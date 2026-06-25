from __future__ import annotations

import argparse
import base64
import math
import statistics
import datetime
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

HTTP_METHOD_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
)

PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SUSPICIOUS_UA = (
    "python-requests",
    "go-http-client",
    "curl/",
    "libwww-perl",
    "masscan",
)

BAD_C2_PORTS = {1080, 4444, 6666, 6667, 6668, 6669, 8888, 9001, 31337}

PRIVATE_NETS = (
    ("10.",),
    ("192.168.",),
    ("172.", tuple(str(n) + "." for n in range(16, 32))),
)


def _read_pcap(path: Path) -> tuple[list[dict[str, Any]], str, tuple[int, int]]:
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("Unsupported pcap magic bytes")

        header = handle.read(20)
        if len(header) != 20:
            raise ValueError("Corrupted pcap global header")

        version_major, version_minor, _, _, _, _ = struct.unpack(endian + "HHiIII", header)
        packets: list[dict[str, Any]] = []
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Corrupted pcap packet header")
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            frame = handle.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError("Corrupted pcap packet payload")
            packets.append(
                {
                    "ts_sec": ts_sec,
                    "ts_usec": ts_usec,
                    "incl_len": incl_len,
                    "orig_len": orig_len,
                    "frame": frame,
                }
            )
    return packets, endian, (version_major, version_minor)


def _decode_text(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.decode("latin-1", errors="replace")


def _printable_ratio(payload: bytes) -> float:
    if not payload:
        return 0.0
    printable = 0
    for b in payload:
        if b in {9, 10, 13} or PRINTABLE_MIN <= b <= PRINTABLE_MAX:
            printable += 1
    return printable / len(payload)


def _extract_ascii_runs(payload: bytes, min_len: int) -> list[str]:
    runs: list[str] = []
    current: list[int] = []
    for b in payload:
        if PRINTABLE_MIN <= b <= PRINTABLE_MAX:
            current.append(b)
        else:
            if len(current) >= min_len:
                runs.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        runs.append(bytes(current).decode("ascii"))
    return runs


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    value = 0.0
    for count in counts.values():
        p = count / total
        value -= p * math.log2(p)
    return value


def _contains_private_ip(text: str) -> bool:
    if "10." in text or "192.168." in text:
        return True
    if "172." in text:
        for part in text.split():
            if part.startswith("172."):
                octets = part.split(".")
                if len(octets) > 1 and octets[1].isdigit():
                    second = int(octets[1])
                    if 16 <= second <= 31:
                        return True
    return False


def _tcp_flag_names(flags_byte: int) -> list[str]:
    mapping = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    return [name for bit, name in mapping if flags_byte & bit]


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return False


def _parse_http_payload(payload: bytes) -> tuple[str, str | None]:
    if payload.startswith(b"HTTP/"):
        content_type = "HTTP response"
    else:
        content_type = "HTTP request"
    readable = _decode_text(payload)
    return content_type, readable


TLS_CONTENT_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}

TLS_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0E: "ServerHelloDone",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
}


def _parse_tls_payload(payload: bytes) -> tuple[str, Any, bool, dict[str, Any]]:
    meta: dict[str, Any] = {}
    if not payload:
        return "TLS (no payload)", None, False, meta
    record_type = payload[0]
    record_name = TLS_CONTENT_TYPES.get(record_type, f"Unknown(0x{record_type:02x})")
    if len(payload) >= 3:
        meta["tls_version"] = f"0x{payload[1]:02x}{payload[2]:02x}"
    if record_type == 0x16 and len(payload) > 5:
        handshake_type = payload[5]
        handshake_name = TLS_HANDSHAKE_TYPES.get(handshake_type, f"Handshake(0x{handshake_type:02x})")
        meta["handshake_type"] = handshake_name
        return f"TLS {handshake_name}", None, False, meta
    if record_type == 0x18 and len(payload) > 8:
        hb_type = payload[5]
        claimed_len = struct.unpack(">H", payload[6:8])[0]
        actual_len = len(payload) - 8
        if hb_type == 1 and claimed_len > actual_len:
            overflow = claimed_len - actual_len
            return (
                "HEARTBLEED REQUEST",
                f"Claimed {claimed_len} bytes, actual {actual_len}, overflow {overflow}",
                True,
                meta,
            )
        if hb_type == 2 and len(payload) > 100:
            runs = _extract_ascii_runs(payload[8:], 8)
            return "HEARTBLEED RESPONSE", runs, True, meta
        return "TLS Heartbeat", None, False, meta
    if record_type == 0x17:
        return "TLS ApplicationData (encrypted)", f"[encrypted — {len(payload)} bytes]", False, meta
    return f"TLS {record_name}", None, False, meta


def _decode_dns_name(payload: bytes, offset: int = 12, depth: int = 0) -> tuple[str | None, int]:
    if depth > 10:
        return None, offset
    labels: list[str] = []
    position = offset
    while position < len(payload):
        length = payload[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0:
            if position + 1 >= len(payload):
                return None, position + 1
            pointer = ((length & 0x3F) << 8) | payload[position + 1]
            name, _ = _decode_dns_name(payload, pointer, depth + 1)
            if name:
                labels.append(name)
            position += 2
            break
        position += 1
        end = position + length
        if end > len(payload):
            return None, end
        labels.append(payload[position:end].decode("ascii", errors="replace"))
        position = end
    if not labels:
        return None, position
    return ".".join(labels), position


def _parse_dns(payload: bytes) -> tuple[str, str | None, dict[str, Any]]:
    meta: dict[str, Any] = {}
    if len(payload) < 12:
        return "DNS", None, meta
    flags = struct.unpack(">H", payload[2:4])[0]
    is_response = bool(flags & 0x8000)
    name, position = _decode_dns_name(payload, 12)
    if not name:
        return "DNS Response" if is_response else "DNS Query", None, meta
    if position + 4 > len(payload):
        return "DNS Response" if is_response else "DNS Query", f"Query: {name}", meta
    qtype = struct.unpack(">H", payload[position : position + 2])[0]
    qtype_name = "A" if qtype == 1 else f"TYPE{qtype}"
    if not is_response:
        meta["query_name"] = name
        meta["query_type"] = qtype_name
        return "DNS Query", f"Query: {name} ({qtype_name})", meta
    ancount = struct.unpack(">H", payload[6:8])[0]
    answer_offset = position + 4
    if ancount < 1:
        return "DNS Response", f"Response: {name}", meta
    if answer_offset + 10 > len(payload):
        return "DNS Response", f"Response: {name}", meta
    if payload[answer_offset] & 0xC0:
        answer_offset += 2
    else:
        _, answer_offset = _decode_dns_name(payload, answer_offset)
    if answer_offset + 10 > len(payload):
        return "DNS Response", f"Response: {name}", meta
    atype = struct.unpack(">H", payload[answer_offset : answer_offset + 2])[0]
    rdlength = struct.unpack(">H", payload[answer_offset + 8 : answer_offset + 10])[0]
    rdata_offset = answer_offset + 10
    if atype == 1 and rdata_offset + rdlength <= len(payload):
        ip_bytes = payload[rdata_offset : rdata_offset + 4]
        ip_addr = ".".join(str(b) for b in ip_bytes)
        meta["answer_ip"] = ip_addr
        meta["answer_type"] = "A"
        return "DNS Response", f"Response: {name} → {ip_addr}", meta
    if atype == 16 and rdata_offset + rdlength <= len(payload):
        if rdlength > 1:
            txt_len = payload[rdata_offset]
            txt = payload[rdata_offset + 1 : rdata_offset + 1 + txt_len]
            meta["txt_length"] = len(txt)
    return "DNS Response", f"Response: {name} ({qtype_name})", meta


def _parse_icmp_payload(frame: bytes, icmp_start: int, ttl: int | None) -> dict[str, Any]:
    icmp_type = frame[icmp_start] if len(frame) > icmp_start else None
    icmp_code = frame[icmp_start + 1] if len(frame) > icmp_start + 1 else None
    icmp_id = None
    icmp_seq = None
    if len(frame) >= icmp_start + 8:
        icmp_id = struct.unpack(">H", frame[icmp_start + 4 : icmp_start + 6])[0]
        icmp_seq = struct.unpack(">H", frame[icmp_start + 6 : icmp_start + 8])[0]
    payload_start = icmp_start + 8
    hidden_text = None
    hidden_message = False
    if len(frame) > icmp_start + 16:
        payload = frame[icmp_start + 16 :]
        stripped = payload.rstrip(b"N").rstrip(b"\x00").strip()
        if stripped and all(PRINTABLE_MIN <= b <= PRINTABLE_MAX for b in stripped):
            text = stripped.decode("ascii")
            if all(c in "0123456789abcdefABCDEF" for c in text) and len(text) % 2 == 0:
                try:
                    hidden_text = bytes.fromhex(text).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    hidden_text = text
            else:
                hidden_text = text
    if hidden_text:
        hidden_message = True
    content_type = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else "ICMP"
    return {
        "content_type": content_type,
        "readable": hidden_text,
        "hidden_message": hidden_message,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "icmp_id": icmp_id,
        "icmp_seq": icmp_seq,
        "ttl": ttl,
    }


def _parse_arp(frame: bytes, arp_start: int) -> tuple[str, str | None, str | None, str]:
    if len(frame) < arp_start + 28:
        return "ARP", None, None, "ARP"
    opcode = struct.unpack(">H", frame[arp_start + 6 : arp_start + 8])[0]
    sender_mac = frame[arp_start + 8 : arp_start + 14].hex(":")
    sender_ip = ".".join(str(b) for b in frame[arp_start + 14 : arp_start + 18])
    target_ip = ".".join(str(b) for b in frame[arp_start + 24 : arp_start + 28])
    if opcode == 1:
        return "ARP Request", sender_ip, target_ip, f"Who has {target_ip}? Tell {sender_ip}"
    if opcode == 2:
        return "ARP Reply", sender_ip, target_ip, f"{sender_ip} is at {sender_mac}"
    return "ARP", sender_ip, target_ip, "ARP"


def _app_protocol(src_port: int | None, dst_port: int | None, l4: str) -> str:
    ports = {src_port, dst_port}
    if l4 == "tcp":
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "TLS"
        if 5672 in ports:
            return "AMQP"
        return "TCP"
    if l4 == "udp":
        if 53 in ports:
            return "DNS"
        return "UDP"
    if l4 == "icmp":
        return "ICMP"
    if l4 == "arp":
        return "ARP"
    return l4.upper()


def _format_client_server(src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None, proto: str) -> tuple[str, str]:
    known_ports = {80, 443, 53, 5672}
    if src_port in known_ports and dst_port not in known_ports:
        server = f"{src_ip}:{src_port}"
        client = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
        return client, server
    if dst_port in known_ports and src_port not in known_ports:
        client = f"{src_ip}:{src_port}" if src_port is not None else src_ip
        server = f"{dst_ip}:{dst_port}"
        return client, server
    client = f"{src_ip}:{src_port}" if src_port is not None else src_ip
    server = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
    return client, server


def _parse_packet(frame: bytes) -> dict[str, Any] | None:
    if len(frame) < 14:
        return None
    eth_type = struct.unpack(">H", frame[12:14])[0]
    if eth_type == ETH_TYPE_ARP:
        content_type, src_ip, dst_ip, readable = _parse_arp(frame, 14)
        return {
            "l4": "arp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": None,
            "payload": frame[14:],
            "ttl": None,
            "content_type": content_type,
            "readable": readable,
        }
    if eth_type == 0x8100:
        if len(frame) >= 18 and struct.unpack(">H", frame[16:18])[0] == 0x8100:
            return {"l4": "vlan", "double_vlan": True, "payload": frame}
    if eth_type != ETH_TYPE_IPV4:
        return None
    if len(frame) < 34:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if len(frame) < 14 + ihl:
        return None
    ttl = frame[22]
    proto = frame[23]
    flags_offset = struct.unpack(">H", frame[20:22])[0]
    more_fragments = bool(flags_offset & 0x2000)
    frag_offset = flags_offset & 0x1FFF
    src_ip = ".".join(str(b) for b in frame[26:30])
    dst_ip = ".".join(str(b) for b in frame[30:34])
    ip_header_end = 14 + ihl
    if proto == PROTO_ICMP:
        icmp_start = ip_header_end
        icmp_info = _parse_icmp_payload(frame, icmp_start, ttl)
        return {
            "l4": "icmp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": None,
            "payload": frame[icmp_start:],
            "ttl": ttl,
            "ip_more_fragments": more_fragments,
            "ip_frag_offset": frag_offset,
            **icmp_info,
        }
    if proto == PROTO_TCP:
        if len(frame) < ip_header_end + 20:
            return None
        src_port = struct.unpack(">H", frame[ip_header_end : ip_header_end + 2])[0]
        dst_port = struct.unpack(">H", frame[ip_header_end + 2 : ip_header_end + 4])[0]
        data_offset = (frame[ip_header_end + 12] >> 4) * 4
        flags_byte = frame[ip_header_end + 13]
        payload_start = ip_header_end + data_offset
        if len(frame) < payload_start:
            payload = b""
        else:
            payload = frame[payload_start:]
        return {
            "l4": "tcp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload,
            "ttl": ttl,
            "ip_more_fragments": more_fragments,
            "ip_frag_offset": frag_offset,
            "tcp_flags": _tcp_flag_names(flags_byte),
            "tcp_flags_raw": flags_byte,
            "tcp_window": struct.unpack(">H", frame[ip_header_end + 14 : ip_header_end + 16])[0],
        }
    if proto == PROTO_UDP:
        if len(frame) < ip_header_end + 8:
            return None
        src_port = struct.unpack(">H", frame[ip_header_end : ip_header_end + 2])[0]
        dst_port = struct.unpack(">H", frame[ip_header_end + 2 : ip_header_end + 4])[0]
        payload = frame[ip_header_end + 8 :]
        return {
            "l4": "udp",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload,
            "ttl": ttl,
            "ip_more_fragments": more_fragments,
            "ip_frag_offset": frag_offset,
        }
    if proto in {1, 6, 17}:
        return None
    return None


def _protocol_readable(parsed: dict[str, Any]) -> tuple[str, Any, dict[str, Any]]:
    l4 = parsed.get("l4")
    payload = parsed.get("payload", b"")
    src_port = parsed.get("src_port")
    dst_port = parsed.get("dst_port")
    extras: dict[str, Any] = {}
    extras["raw_length"] = len(payload) if payload is not None else 0
    if l4 == "tcp":
        if 80 in {src_port, dst_port}:
            content_type, readable = _parse_http_payload(payload)
            return content_type, readable, extras
        if 443 in {src_port, dst_port}:
            content_type, readable, heartbleed, tls_meta = _parse_tls_payload(payload)
            extras["heartbleed"] = heartbleed
            extras.update(tls_meta)
            return content_type, readable, extras
        if 5672 in {src_port, dst_port}:
            runs = _extract_ascii_runs(payload, 6)
            readable = " | ".join(runs) if runs else None
            return "AMQP", readable, extras
        port_label = dst_port if dst_port is not None else src_port
        if payload:
            printable_ratio = _printable_ratio(payload)
            if printable_ratio > 0.5:
                return f"TCP port {port_label}", _decode_text(payload), extras
            hex_prefix = payload[:64].hex()
            return f"TCP port {port_label}", f"[binary {len(payload)} bytes] hex: {hex_prefix}", extras
        return f"TCP port {port_label}", None, extras
    if l4 == "udp":
        if 53 in {src_port, dst_port}:
            content_type, readable, dns_meta = _parse_dns(payload)
            extras.update(dns_meta)
            return content_type, readable, extras
        return "UDP", None, extras
    if l4 == "icmp":
        return parsed.get("content_type", "ICMP"), parsed.get("readable"), {
            "hidden_message": parsed.get("hidden_message", False),
        }
    if l4 == "arp":
        return parsed.get("content_type", "ARP"), parsed.get("readable"), extras
    if l4 == "vlan":
        return "VLAN", None, {"double_vlan": parsed.get("double_vlan", False)}
    return (l4.upper() if l4 else "UNKNOWN"), None, extras


def _conversation_key(parsed: dict[str, Any], protocol: str) -> tuple:
    src_ip = parsed.get("src_ip")
    dst_ip = parsed.get("dst_ip")
    src_port = parsed.get("src_port")
    dst_port = parsed.get("dst_port")
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        a, b = left, right
    else:
        a, b = right, left
    return (protocol, a, b)


def _format_direction(src_ip: str, dst_ip: str, client: str, server: str) -> str:
    if client.startswith(src_ip):
        return "client→server"
    if server.startswith(src_ip):
        return "server→client"
    return f"{src_ip}→{dst_ip}"


def _iter_packets(parsed_packets: list[dict[str, Any]], capture_start: float) -> Iterable[dict[str, Any]]:
    for parsed in parsed_packets:
        ts = parsed["timestamp"]
        yield {
            "index": parsed["index"],
            "time": ts - capture_start,
            "timestamp": ts,
            "src_ip": parsed.get("src_ip"),
            "dst_ip": parsed.get("dst_ip"),
            "src_port": parsed.get("src_port"),
            "dst_port": parsed.get("dst_port"),
            "protocol": parsed.get("protocol"),
            "length": parsed.get("length"),
            "ttl": parsed.get("ttl"),
            "tcp_flags": parsed.get("tcp_flags"),
            "tcp_window": parsed.get("tcp_window"),
            "content_type": parsed.get("content_type"),
            "readable": parsed.get("readable"),
            "hidden_message": parsed.get("hidden_message"),
            "icmp_id": parsed.get("icmp_id"),
            "icmp_seq": parsed.get("icmp_seq"),
            "icmp_type": parsed.get("icmp_type"),
            "icmp_code": parsed.get("icmp_code"),
        }


def _make_alert(
    *,
    rule: str,
    severity: str,
    description: str,
    timestamp: float,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    evidence: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    dedup_key: str | None = None,
) -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "description": description,
        "evidence": evidence or {},
        "tags": tags or [],
        "dedup_key": dedup_key or rule,
        "count": 1,
    }


def _dedupe_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        key = alert.get("dedup_key", alert["rule"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = alert
            continue
        existing["count"] += 1
        if alert.get("timestamp", 0) > existing.get("timestamp", 0):
            existing["timestamp"] = alert.get("timestamp")
        if alert.get("evidence"):
            existing["evidence"] = alert["evidence"]
    return list(merged.values())


def detect_tcp_syn_scan(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 10
    PORT_THRESHOLD = 15
    alerts: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        flags = pkt.get("tcp_flags") or []
        if "SYN" in flags and "ACK" not in flags:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip or pkt.get("dst_port") is None:
                continue
            by_key[(src_ip, dst_ip)].append(pkt)
    for (src_ip, dst_ip), items in by_key.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        ports: set[int] = set()
        for end in range(len(items)):
            ports.add(items[end]["dst_port"])
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                ports.discard(items[start]["dst_port"])
                start += 1
            if len(ports) >= PORT_THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_tcp_syn_scan",
                        severity="HIGH",
                        description=f"{src_ip} sent SYN-only packets to {len(ports)} ports on {dst_ip} within {WINDOW_SEC}s",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="TCP",
                        evidence={
                            "ports": sorted(ports),
                            "window_seconds": WINDOW_SEC,
                        },
                        tags=["recon", "scan"],
                        dedup_key=f"tcp_syn_scan|{src_ip}|{dst_ip}",
                    )
                )
                break
    return alerts


def detect_tls_self_signed(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "TLS":
            continue
        if pkt.get("content_type") != "TLS Certificate":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        lower = readable.lower()
        issuer = None
        subject = None
        for line in readable.split("\r\n"):
            if "issuer" in line.lower():
                issuer = line
            if "subject" in line.lower():
                subject = line
        if issuer and subject and issuer.split(":", 1)[-1].strip() == subject.split(":", 1)[-1].strip():
            alerts.append(
                _make_alert(
                    rule="detect_self_signed_cert",
                    severity="MEDIUM",
                    description="Self-signed certificate detected (issuer == subject)",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="TLS",
                    evidence={"issuer": issuer, "subject": subject},
                    tags=["policy"],
                    dedup_key=f"self_signed|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def detect_tcp_connect_scan(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 10
    PORT_THRESHOLD = 15
    alerts: list[dict[str, Any]] = []
    by_flow: dict[tuple[str, str, int], dict[str, Any]] = defaultdict(lambda: {"states": [], "timestamp": 0})
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        if not src_ip or not dst_ip or dst_port is None:
            continue
        flags = pkt.get("tcp_flags") or []
        if "SYN" in flags and "ACK" not in flags:
            by_flow[(src_ip, dst_ip, dst_port)]["states"].append("SYN")
            by_flow[(src_ip, dst_ip, dst_port)]["timestamp"] = pkt["timestamp"]
        if "SYN" in flags and "ACK" in flags:
            by_flow[(dst_ip, src_ip, pkt.get("src_port") or 0)]["states"].append("SYN-ACK")
        if "ACK" in flags and "SYN" not in flags:
            by_flow[(src_ip, dst_ip, dst_port)]["states"].append("ACK")
        if "RST" in flags:
            by_flow[(src_ip, dst_ip, dst_port)]["states"].append("RST")
    by_key: dict[tuple[str, str], list[int]] = defaultdict(list)
    for (src_ip, dst_ip, dst_port), info in by_flow.items():
        states = info["states"]
        if "SYN" in states and "SYN-ACK" in states and "ACK" in states and "RST" in states:
            by_key[(src_ip, dst_ip)].append(dst_port)
    for (src_ip, dst_ip), ports in by_key.items():
        if len(set(ports)) >= PORT_THRESHOLD:
            alerts.append(
                _make_alert(
                    rule="detect_tcp_connect_scan",
                    severity="HIGH",
                    description=f"{src_ip} completed handshakes then reset across {len(set(ports))} ports on {dst_ip}",
                    timestamp=packets[-1]["timestamp"] if packets else 0,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    evidence={"ports": sorted(set(ports)), "window_seconds": WINDOW_SEC},
                    tags=["recon", "scan"],
                    dedup_key=f"tcp_connect_scan|{src_ip}|{dst_ip}",
                )
            )
    return alerts


def detect_tcp_flag_scans(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        flags = pkt.get("tcp_flags") or []
        flag_set = set(flags)
        if flag_set == {"FIN"}:
            kind = "FIN"
        elif not flag_set:
            kind = "NULL"
        elif flag_set == {"FIN", "PSH", "URG"}:
            kind = "XMAS"
        else:
            continue
        alerts.append(
            _make_alert(
                rule="detect_tcp_flag_scan",
                severity="HIGH",
                description=f"TCP {kind} scan-style flags observed",
                timestamp=pkt["timestamp"],
                src_ip=pkt.get("src_ip"),
                dst_ip=pkt.get("dst_ip"),
                protocol="TCP",
                evidence={"flags": flags, "type": kind},
                tags=["recon", "scan"],
                dedup_key=f"tcp_flag_scan|{pkt.get('src_ip')}|{pkt.get('dst_ip')}|{kind}",
            )
        )
    return alerts


def detect_udp_scan(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 10
    PORT_THRESHOLD = 15
    alerts: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "UDP":
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        if not src_ip or not dst_ip or dst_port is None:
            continue
        by_key[(src_ip, dst_ip)].append(pkt)
    for (src_ip, dst_ip), items in by_key.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        ports: set[int] = set()
        for end in range(len(items)):
            ports.add(items[end]["dst_port"])
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                ports.discard(items[start]["dst_port"])
                start += 1
            if len(ports) >= PORT_THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_udp_scan",
                        severity="HIGH",
                        description=f"{src_ip} sent UDP to {len(ports)} ports on {dst_ip} within {WINDOW_SEC}s",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="UDP",
                        evidence={"ports": sorted(ports), "window_seconds": WINDOW_SEC},
                        tags=["recon", "scan"],
                        dedup_key=f"udp_scan|{src_ip}|{dst_ip}",
                    )
                )
                break
    return alerts


def detect_icmp_sweep(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 5
    HOST_THRESHOLD = 5
    alerts: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "ICMP":
            continue
        if pkt.get("icmp_type") != 8:
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        by_src[src_ip].append(pkt)
    for src_ip, items in by_src.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        targets: set[str] = set()
        for end in range(len(items)):
            targets.add(items[end]["dst_ip"])
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                targets.discard(items[start]["dst_ip"])
                start += 1
            if len(targets) >= HOST_THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_icmp_sweep",
                        severity="HIGH",
                        description=f"{src_ip} sent ICMP echo requests to {len(targets)} hosts within {WINDOW_SEC}s",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        protocol="ICMP",
                        evidence={"targets": sorted(targets), "window_seconds": WINDOW_SEC},
                        tags=["recon"],
                        dedup_key=f"icmp_sweep|{src_ip}",
                    )
                )
                break
    return alerts


def detect_os_fingerprinting(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    ttl_values = {64, 128, 255}
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        ttl = pkt.get("ttl")
        window = pkt.get("tcp_window")
        flags = pkt.get("tcp_flags") or []
        readable = (pkt.get("readable") or "").lower() if isinstance(pkt.get("readable"), str) else ""
        if ttl in ttl_values or (window is not None and window in {1024, 2048, 4096, 8192, 16384}):
            alerts.append(
                _make_alert(
                    rule="detect_os_fingerprinting",
                    severity="MEDIUM",
                    description="TCP packet shows OS fingerprinting-like characteristics",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="TCP",
                    evidence={"ttl": ttl, "window": window, "flags": flags},
                    tags=["recon"],
                    dedup_key=f"os_fingerprint|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if any(token in readable for token in ("nmap", "masscan", "zmap", "nessus")):
            alerts.append(
                _make_alert(
                    rule="detect_os_fingerprinting",
                    severity="MEDIUM",
                    description="Fingerprinting tool signature found in payload",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="TCP",
                    evidence={"signature": readable[:120]},
                    tags=["recon"],
                    dedup_key=f"os_fingerprint_sig|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def detect_service_version_probe(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 30
    HOST_THRESHOLD = 10
    alerts: list[dict[str, Any]] = []
    by_src_port: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        if not src_ip or not dst_ip or dst_port is None:
            continue
        by_src_port[(src_ip, dst_port)].append(pkt)
    for (src_ip, dst_port), items in by_src_port.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        targets: set[str] = set()
        for end in range(len(items)):
            targets.add(items[end]["dst_ip"])
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                targets.discard(items[start]["dst_ip"])
                start += 1
            if len(targets) >= HOST_THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_service_version_probe",
                        severity="HIGH",
                        description=f"{src_ip} connected to {len(targets)} hosts on port {dst_port} within {WINDOW_SEC}s",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        protocol="TCP",
                        evidence={"targets": sorted(targets), "port": dst_port, "window_seconds": WINDOW_SEC},
                        tags=["recon"],
                        dedup_key=f"service_probe|{src_ip}|{dst_port}",
                    )
                )
                break
    return alerts


def detect_heartbleed(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "TLS":
            continue
        if pkt.get("content_type") != "HEARTBLEED REQUEST":
            continue
        alerts.append(
            _make_alert(
                rule="detect_heartbleed",
                severity="CRITICAL",
                description="Heartbleed request detected",
                timestamp=pkt["timestamp"],
                src_ip=pkt.get("src_ip"),
                dst_ip=pkt.get("dst_ip"),
                protocol="TLS",
                evidence={"details": pkt.get("readable")},
                tags=["exploit"],
                dedup_key=f"heartbleed|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
            )
        )
    return alerts


def detect_http_exploits(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    sql_patterns = ["' or '1'='1", "union select", "drop table", "'; --", "xp_cmdshell", "information_schema"]
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "alert("]
    traversal_patterns = ["../", "..%2f", "..%5c", "%2e%2e"]
    cmd_patterns = ["; ls", "| cat", "&& wget", "$(", "`"]
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable") or ""
        if not isinstance(readable, str):
            continue
        lowered = readable.lower()
        if "() {" in readable:
            alerts.append(
                _make_alert(
                    rule="detect_shellshock",
                    severity="CRITICAL",
                    description="ShellShock payload detected in HTTP headers",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"shellshock|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if any(pat in lowered for pat in sql_patterns):
            alerts.append(
                _make_alert(
                    rule="detect_sql_injection",
                    severity="CRITICAL",
                    description="SQL injection pattern detected in HTTP payload",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"sql_injection|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if any(pat in lowered for pat in xss_patterns):
            alerts.append(
                _make_alert(
                    rule="detect_xss",
                    severity="CRITICAL",
                    description="XSS pattern detected in HTTP payload",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"xss|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if any(pat in lowered for pat in traversal_patterns):
            alerts.append(
                _make_alert(
                    rule="detect_directory_traversal",
                    severity="HIGH",
                    description="Directory traversal pattern detected in HTTP request",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"traversal|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if any(pat in lowered for pat in cmd_patterns):
            alerts.append(
                _make_alert(
                    rule="detect_command_injection",
                    severity="CRITICAL",
                    description="Command injection pattern detected in HTTP payload",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"cmd_injection|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if "${jndi:" in lowered:
            alerts.append(
                _make_alert(
                    rule="detect_log4shell",
                    severity="CRITICAL",
                    description="Log4Shell pattern detected in payload",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"sample": readable[:120]},
                    tags=["exploit"],
                    dedup_key=f"log4shell|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def _mask_secret(value: str) -> str:
    return "***" if value else "***"


def _find_http_header_value(payload: str, header_name: str) -> str | None:
    for line in payload.split("\r\n"):
        if line.lower().startswith(header_name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def detect_credential_exposure(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        proto = pkt.get("protocol")
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue

        if proto == "HTTP" and pkt.get("dst_port") == 80:
            header_val = _find_http_header_value(readable, "Authorization")
            if header_val and header_val.lower().startswith("basic "):
                token = header_val.split(" ", 1)[1]
                try:
                    decoded = base64.b64decode(token).decode("utf-8", errors="replace")
                except (ValueError, UnicodeDecodeError):
                    decoded = ""
                username = decoded.split(":", 1)[0] if ":" in decoded else decoded
                alerts.append(
                    _make_alert(
                        rule="detect_http_basic_auth",
                        severity="HIGH",
                        description="HTTP Basic Auth credentials sent in cleartext",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="HTTP",
                        evidence={"username": username, "password": _mask_secret("x")},
                        tags=["credential"],
                        dedup_key=f"http_basic|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )

            if "\r\n\r\n" in readable and readable.lower().startswith("post "):
                body = readable.split("\r\n\r\n", 1)[1]
                for field in ["password", "passwd", "pwd", "pass", "secret", "token", "api_key", "auth"]:
                    if f"{field}=" in body.lower():
                        alerts.append(
                            _make_alert(
                                rule="detect_http_form_credentials",
                                severity="HIGH",
                                description="HTTP form contains credential-like fields",
                                timestamp=pkt["timestamp"],
                                src_ip=pkt.get("src_ip"),
                                dst_ip=pkt.get("dst_ip"),
                                protocol="HTTP",
                                evidence={"field": field, "value": _mask_secret("x")},
                                tags=["credential"],
                                dedup_key=f"http_form_cred|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                            )
                        )

            if readable.lower().startswith("get ") and "?" in readable:
                path = readable.split(" ", 2)[1]
                query = path.split("?", 1)[1] if "?" in path else ""
                for key in ["token", "session", "sessionid", "auth", "api_key"]:
                    if f"{key}=" in query.lower():
                        alerts.append(
                            _make_alert(
                                rule="detect_session_token_in_url",
                                severity="MEDIUM",
                                description="Session/token value found in URL query string",
                                timestamp=pkt["timestamp"],
                                src_ip=pkt.get("src_ip"),
                                dst_ip=pkt.get("dst_ip"),
                                protocol="HTTP",
                                evidence={"parameter": key},
                                tags=["credential"],
                                dedup_key=f"token_url|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                            )
                        )

        if proto == "TCP" and pkt.get("dst_port") == 21:
            if readable.upper().startswith("USER "):
                username = readable.split(" ", 1)[1].strip()
                alerts.append(
                    _make_alert(
                        rule="detect_ftp_cleartext_credentials",
                        severity="HIGH",
                        description="FTP USER sent in cleartext",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="FTP",
                        evidence={"username": username, "password": _mask_secret("x")},
                        tags=["credential"],
                        dedup_key=f"ftp_user|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )
            if readable.upper().startswith("PASS "):
                alerts.append(
                    _make_alert(
                        rule="detect_ftp_cleartext_credentials",
                        severity="HIGH",
                        description="FTP PASS sent in cleartext",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="FTP",
                        evidence={"password": _mask_secret("x")},
                        tags=["credential"],
                        dedup_key=f"ftp_pass|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )

        if proto == "TCP" and pkt.get("dst_port") == 23:
            alerts.append(
                _make_alert(
                    rule="detect_telnet_cleartext",
                    severity="MEDIUM",
                    description="Telnet session detected (unencrypted)",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="TELNET",
                    evidence={},
                    tags=["credential", "policy"],
                    dedup_key=f"telnet|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )

        if proto == "TCP" and pkt.get("dst_port") == 25:
            if "AUTH LOGIN" in readable.upper() or "AUTH PLAIN" in readable.upper():
                alerts.append(
                    _make_alert(
                        rule="detect_smtp_auth_cleartext",
                        severity="HIGH",
                        description="SMTP AUTH credentials sent in cleartext",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="SMTP",
                        evidence={},
                        tags=["credential"],
                        dedup_key=f"smtp_auth|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )

        if "BEGIN PRIVATE KEY" in readable or "BEGIN RSA PRIVATE KEY" in readable or "BEGIN EC PRIVATE KEY" in readable:
            alerts.append(
                _make_alert(
                    rule="detect_private_key_material",
                    severity="CRITICAL",
                    description="Private key material observed in traffic",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol=proto,
                    evidence={"sample": readable[:80]},
                    tags=["credential"],
                    dedup_key=f"private_key|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def detect_dns_exfiltration(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    WINDOW_SEC = 60
    QUERY_THRESHOLD = 200
    for pkt in packets:
        if pkt.get("protocol") != "DNS":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str) or "Query:" not in readable:
            continue
        query = readable.split("Query:", 1)[1].strip().split(" ", 1)[0]
        labels = query.split(".")
        if not labels:
            continue
        subdomain = labels[0]
        if len(query) > 0 and (len(subdomain) / len(query) > 0.4 or len(subdomain) > 40):
            entropy = _entropy(subdomain)
            alerts.append(
                _make_alert(
                    rule="detect_dns_tunneling",
                    severity="HIGH",
                    description="DNS query with long/likely-encoded subdomain",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="DNS",
                    evidence={"query": query, "subdomain": subdomain, "entropy": entropy},
                    tags=["exfil"],
                    dedup_key=f"dns_tunnel|{pkt.get('src_ip')}|{query}",
                )
            )
    by_src_domain: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "DNS":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str) or "Query:" not in readable:
            continue
        src_ip = pkt.get("src_ip")
        if not src_ip:
            continue
        query = readable.split("Query:", 1)[1].strip().split(" ", 1)[0]
        labels = query.split(".")
        if len(labels) < 2:
            continue
        parent = ".".join(labels[-2:])
        by_src_domain[(src_ip, parent)].append(pkt)
    for (src_ip, parent), items in by_src_domain.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        subs: set[str] = set()
        for end in range(len(items)):
            query = items[end]["readable"].split("Query:", 1)[1].strip().split(" ", 1)[0]
            subs.add(query)
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                old_query = items[start]["readable"].split("Query:", 1)[1].strip().split(" ", 1)[0]
                subs.discard(old_query)
                start += 1
            if len(subs) > QUERY_THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_dns_exfiltration_volume",
                        severity="HIGH",
                        description="High DNS query volume to many subdomains",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        protocol="DNS",
                        evidence={"parent_domain": parent, "unique_queries": len(subs), "window_seconds": WINDOW_SEC},
                        tags=["exfil"],
                        dedup_key=f"dns_exfil|{src_ip}|{parent}",
                    )
                )
                break
    return alerts


def detect_icmp_exfiltration(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_conv: dict[tuple[str, str], int] = defaultdict(int)
    for pkt in packets:
        if pkt.get("protocol") != "ICMP":
            continue
        if pkt.get("hidden_message"):
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip:
                continue
            by_conv[(src_ip, dst_ip)] += len(pkt.get("readable") or "")
    for (src_ip, dst_ip), total in by_conv.items():
        alerts.append(
            _make_alert(
                rule="detect_icmp_exfiltration",
                severity="HIGH",
                description="ICMP echo requests contain non-standard payload data",
                timestamp=packets[-1]["timestamp"] if packets else 0,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="ICMP",
                evidence={"hidden_bytes": total},
                tags=["exfil"],
                dedup_key=f"icmp_exfil|{src_ip}|{dst_ip}",
            )
        )
    return alerts


def detect_dns_txt_size_from_meta(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "DNS":
            continue
        txt_len = pkt.get("dns_txt_length")
        if txt_len and txt_len > 200:
            alerts.append(
                _make_alert(
                    rule="detect_large_dns_txt",
                    severity="HIGH",
                    description="Large DNS TXT response (possible C2/exfil)",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="DNS",
                    evidence={"txt_length": txt_len},
                    tags=["exfil"],
                    dedup_key=f"dns_txt|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def detect_http_c2_identical_user_agents(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_conv: dict[tuple[str, str], list[str]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        ua = _find_http_header_value(readable, "User-Agent")
        if ua:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip:
                continue
            key = (src_ip, dst_ip)
            by_conv[key].append(ua)
    for (src_ip, dst_ip), uas in by_conv.items():
        if len(uas) >= 3 and len(set(uas)) == 1:
            ua = uas[0]
            if any(token in ua.lower() for token in SUSPICIOUS_UA) or ua.strip().isalnum():
                alerts.append(
                    _make_alert(
                        rule="detect_http_c2_identical_ua",
                        severity="MEDIUM",
                        description="Identical User-Agent across HTTP requests in conversation",
                        timestamp=packets[-1]["timestamp"] if packets else 0,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTP",
                        evidence={"user_agent": ua, "count": len(uas)},
                        tags=["c2"],
                        dedup_key=f"identical_ua|{src_ip}|{dst_ip}",
                    )
                )
    return alerts


def detect_large_http_post(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        if readable.lower().startswith("post ") and "\r\n\r\n" in readable:
            body = readable.split("\r\n\r\n", 1)[1]
            if len(body.encode("utf-8", errors="ignore")) > 1_000_000 and _is_private(pkt.get("src_ip")) and not _is_private(pkt.get("dst_ip")):
                alerts.append(
                    _make_alert(
                        rule="detect_large_http_post",
                        severity="HIGH",
                        description="Large outbound HTTP POST body (possible exfiltration)",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="HTTP",
                        evidence={"body_bytes": len(body)},
                        tags=["exfil"],
                        dedup_key=f"large_http_post|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )
    return alerts


def detect_large_dns_txt(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return detect_dns_txt_size_from_meta(packets, conversations)


def detect_beaconing(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for pkt in packets:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        if _is_private(src_ip) and not _is_private(dst_ip):
            by_pair[(src_ip, dst_ip)].append(pkt["timestamp"])
    for (src_ip, dst_ip), times in by_pair.items():
        if len(times) < 6:
            continue
        times.sort()
        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
        if len(intervals) < 5:
            continue
        mean = statistics.mean(intervals)
        if mean == 0:
            continue
        stdev = statistics.pstdev(intervals)
        if stdev / mean < 0.15:
            alerts.append(
                _make_alert(
                    rule="detect_beaconing",
                    severity="HIGH",
                    description="Regular outbound connection intervals suggest beaconing",
                    timestamp=times[-1],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=None,
                    evidence={"mean_interval": mean, "stdev": stdev, "count": len(times)},
                    tags=["c2"],
                    dedup_key=f"beacon|{src_ip}|{dst_ip}",
                )
            )
    return alerts


def detect_long_low_volume_connections(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for convo in conversations:
        if convo.get("protocol") != "TCP":
            continue
        duration = convo.get("end_time", 0) - convo.get("start_time", 0)
        if duration > 120 and convo.get("total_bytes", 0) < 1024:
            alerts.append(
                _make_alert(
                    rule="detect_long_low_volume_tcp",
                    severity="MEDIUM",
                    description="Long-lived TCP conversation with very low data volume",
                    timestamp=convo.get("end_time", 0),
                    src_ip=convo.get("client", "").split(":")[0],
                    dst_ip=convo.get("server", "").split(":")[0],
                    protocol="TCP",
                    evidence={"duration": duration, "bytes": convo.get("total_bytes")},
                    tags=["c2"],
                    dedup_key=f"low_volume|{convo.get('client')}|{convo.get('server')}",
                )
            )
    return alerts


def detect_http_c2_patterns(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        ua = _find_http_header_value(readable, "User-Agent")
        if not ua or not ua.strip():
            alerts.append(
                _make_alert(
                    rule="detect_http_c2_user_agent",
                    severity="MEDIUM",
                    description="HTTP request missing User-Agent header",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={},
                    tags=["c2"],
                    dedup_key=f"ua_missing|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
        if ua and any(token in ua.lower() for token in SUSPICIOUS_UA):
            alerts.append(
                _make_alert(
                    rule="detect_http_c2_user_agent",
                    severity="MEDIUM",
                    description="Suspicious HTTP User-Agent detected",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="HTTP",
                    evidence={"user_agent": ua},
                    tags=["c2"],
                    dedup_key=f"ua_suspicious|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    return alerts


def detect_tls_no_sni(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "TLS":
            continue
        if pkt.get("content_type") != "TLS ClientHello":
            continue
        readable = pkt.get("readable")
        if isinstance(readable, str) and "server_name" in readable.lower():
            continue
        alerts.append(
            _make_alert(
                rule="detect_tls_no_sni",
                severity="MEDIUM",
                description="TLS ClientHello without SNI",
                timestamp=pkt["timestamp"],
                src_ip=pkt.get("src_ip"),
                dst_ip=pkt.get("dst_ip"),
                protocol="TLS",
                evidence={},
                tags=["c2"],
                dedup_key=f"tls_no_sni|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
            )
        )
    return alerts


def detect_known_bad_ports(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") not in {"TCP", "UDP"}:
            continue
        if not _is_private(pkt.get("src_ip")):
            continue
        dst_port = pkt.get("dst_port")
        if dst_port in BAD_C2_PORTS:
            alerts.append(
                _make_alert(
                    rule="detect_known_bad_ports",
                    severity="HIGH",
                    description="Outbound connection to known malware/C2 port",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol=pkt.get("protocol"),
                    evidence={"port": dst_port},
                    tags=["c2"],
                    dedup_key=f"bad_port|{pkt.get('src_ip')}|{dst_port}",
                )
            )
    return alerts


def detect_arp_spoofing(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    arp_map: dict[str, set[str]] = defaultdict(set)
    packet_nums: dict[tuple[str, str], list[int]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "ARP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str) or " is at " not in readable:
            continue
        ip = readable.split(" is at ", 1)[0].strip()
        mac = readable.split(" is at ", 1)[1].strip()
        arp_map[ip].add(mac)
        packet_nums[(ip, mac)].append(pkt.get("index", 0))
    for ip, macs in arp_map.items():
        if len(macs) > 1:
            packets_for_ip = []
            for mac in macs:
                packets_for_ip.extend(packet_nums.get((ip, mac), []))
            alerts.append(
                _make_alert(
                    rule="detect_arp_spoofing",
                    severity="HIGH",
                    description="Multiple MAC addresses observed for same IP in ARP replies",
                    timestamp=packets[-1]["timestamp"] if packets else 0,
                    src_ip=ip,
                    protocol="ARP",
                    evidence={"macs": sorted(macs), "packet_numbers": sorted(set(packets_for_ip))},
                    tags=["infrastructure"],
                    dedup_key=f"arp_spoof|{ip}",
                )
            )
    return alerts


def detect_arp_flood(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 10
    THRESHOLD = 50
    alerts: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "ARP":
            continue
        src_ip = pkt.get("src_ip")
        if not src_ip:
            continue
        by_src[src_ip].append(pkt)
    for src_ip, items in by_src.items():
        items.sort(key=lambda x: x["timestamp"])
        start = 0
        for end in range(len(items)):
            while items[end]["timestamp"] - items[start]["timestamp"] > WINDOW_SEC:
                start += 1
            if end - start + 1 > THRESHOLD:
                alerts.append(
                    _make_alert(
                        rule="detect_arp_flood",
                        severity="HIGH",
                        description="High rate of ARP packets from single host",
                        timestamp=items[end]["timestamp"],
                        src_ip=src_ip,
                        protocol="ARP",
                        evidence={"count": end - start + 1, "window_seconds": WINDOW_SEC},
                        tags=["infrastructure"],
                        dedup_key=f"arp_flood|{src_ip}",
                    )
                )
                break
    return alerts


def detect_icmp_flood(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    THRESHOLD_PPS = 100
    alerts: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "ICMP" or pkt.get("icmp_type") != 8:
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        by_pair[(src_ip, dst_ip)].append(pkt)
    for (src_ip, dst_ip), items in by_pair.items():
        items.sort(key=lambda x: x["timestamp"])
        if len(items) < THRESHOLD_PPS:
            continue
        duration = items[-1]["timestamp"] - items[0]["timestamp"]
        if duration <= 0:
            continue
        rate = len(items) / duration
        if rate >= THRESHOLD_PPS:
            alerts.append(
                _make_alert(
                    rule="detect_icmp_flood",
                    severity="HIGH",
                    description="ICMP echo request flood",
                    timestamp=items[-1]["timestamp"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="ICMP",
                    evidence={"rate_pps": rate, "count": len(items)},
                    tags=["dos"],
                    dedup_key=f"icmp_flood|{src_ip}|{dst_ip}",
                )
            )
    return alerts


def detect_tcp_syn_flood(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    THRESHOLD_PPS = 200
    alerts: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue
        flags = pkt.get("tcp_flags") or []
        if "SYN" in flags and "ACK" not in flags:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip:
                continue
            by_pair[(src_ip, dst_ip)].append(pkt)
    for (src_ip, dst_ip), items in by_pair.items():
        items.sort(key=lambda x: x["timestamp"])
        if len(items) < THRESHOLD_PPS:
            continue
        duration = items[-1]["timestamp"] - items[0]["timestamp"]
        if duration <= 0:
            continue
        rate = len(items) / duration
        if rate >= THRESHOLD_PPS:
            alerts.append(
                _make_alert(
                    rule="detect_tcp_syn_flood",
                    severity="HIGH",
                    description="TCP SYN flood suspected",
                    timestamp=items[-1]["timestamp"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    evidence={"rate_pps": rate, "count": len(items)},
                    tags=["dos"],
                    dedup_key=f"syn_flood|{src_ip}|{dst_ip}",
                )
            )
    return alerts


def detect_dns_amplification(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for pkt in packets:
        if pkt.get("protocol") != "DNS":
            continue
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        if pkt.get("content_type") == "DNS Query":
            by_pair[(src_ip, dst_ip)] = {"query_len": pkt.get("length", 0), "timestamp": pkt["timestamp"]}
        if pkt.get("content_type") == "DNS Response":
            key = (dst_ip, src_ip)
            query = by_pair.get(key)
            if query and query["query_len"] > 0 and pkt.get("length", 0) > 10 * query["query_len"] and query["query_len"] < 100:
                alerts.append(
                    _make_alert(
                        rule="detect_dns_amplification",
                        severity="HIGH",
                        description="DNS amplification pattern detected",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol="DNS",
                        evidence={"query_size": query["query_len"], "response_size": pkt.get("length")},
                        tags=["dos"],
                        dedup_key=f"dns_amp|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )
    return alerts


def detect_vlan_hopping(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "VLAN":
            continue
        if pkt.get("double_vlan"):
            alerts.append(
                _make_alert(
                    rule="detect_vlan_hopping",
                    severity="MEDIUM",
                    description="Double-tagged VLAN frame observed",
                    timestamp=pkt["timestamp"],
                    protocol="VLAN",
                    evidence={},
                    tags=["infrastructure"],
                    dedup_key="vlan_hopping",
                )
            )
    return alerts


def detect_policy_violations(packets: list[dict[str, Any]], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        proto = pkt.get("protocol")
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        if proto == "HTTP" and pkt.get("dst_port") == 80 and _is_private(src_ip) and _is_private(dst_ip):
            alerts.append(
                _make_alert(
                    rule="detect_unencrypted_internal_http",
                    severity="LOW",
                    description="Internal HTTP observed on port 80",
                    timestamp=pkt["timestamp"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="HTTP",
                    evidence={},
                    tags=["policy"],
                    dedup_key=f"internal_http|{src_ip}|{dst_ip}",
                )
            )
        if proto == "TCP" and pkt.get("dst_port") in {21, 23, 25}:
            alerts.append(
                _make_alert(
                    rule="detect_unencrypted_protocol",
                    severity="MEDIUM",
                    description="Unencrypted legacy protocol observed",
                    timestamp=pkt["timestamp"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    evidence={"port": pkt.get("dst_port")},
                    tags=["policy"],
                    dedup_key=f"unencrypted|{src_ip}|{dst_ip}|{pkt.get('dst_port')}",
                )
            )
        if proto == "TLS":
            tls_version = pkt.get("tls_version")
            if tls_version in {"0x0301", "0x0302"}:
                alerts.append(
                    _make_alert(
                        rule="detect_deprecated_tls",
                        severity="LOW",
                        description="Deprecated TLS version observed",
                        timestamp=pkt["timestamp"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="TLS",
                        evidence={"tls_version": tls_version},
                        tags=["policy"],
                        dedup_key=f"deprecated_tls|{src_ip}|{dst_ip}|{tls_version}",
                    )
                )
        if proto == "HTTP":
            readable = pkt.get("readable")
            if isinstance(readable, str) and pkt.get("content_type") == "HTTP response":
                if any(header in readable for header in ["X-Forwarded-For", "X-Real-IP", "Via"]):
                    if _contains_private_ip(readable):
                        alerts.append(
                            _make_alert(
                                rule="detect_internal_ip_header",
                                severity="LOW",
                                description="Internal IP exposed in HTTP headers",
                                timestamp=pkt["timestamp"],
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                protocol="HTTP",
                                evidence={},
                                tags=["policy"],
                                dedup_key=f"internal_ip_header|{src_ip}|{dst_ip}",
                            )
                        )
        if proto == "AMQP":
            readable = pkt.get("readable")
            if isinstance(readable, str):
                lower = readable.lower()
                if any(token in lower for token in ["flag", "secret", "key", "password", "admin", "token"]):
                    alerts.append(
                        _make_alert(
                            rule="detect_amqp_secret_strings",
                            severity="MEDIUM",
                            description="AMQP payload contains secret-like strings",
                            timestamp=pkt["timestamp"],
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            protocol="AMQP",
                            evidence={"sample": readable[:120]},
                            tags=["policy"],
                            dedup_key=f"amqp_secret|{src_ip}|{dst_ip}",
                        )
                    )
    return alerts


def detect_anomalies(packets: list[dict[str, Any]], conversations: list[dict[str, Any]], total_packets: int) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    if not packets:
        return alerts
    cutoff = int(max(1, total_packets * 0.1))
    early_hosts = {pkt.get("src_ip") for pkt in packets[:cutoff]} | {pkt.get("dst_ip") for pkt in packets[:cutoff]}
    for pkt in packets[cutoff:]:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if src_ip and src_ip not in early_hosts:
            alerts.append(
                _make_alert(
                    rule="detect_new_host_mid_capture",
                    severity="INFO",
                    description="New host appeared after initial capture window",
                    timestamp=pkt["timestamp"],
                    src_ip=src_ip,
                    protocol=pkt.get("protocol"),
                    evidence={},
                    tags=["anomaly"],
                    dedup_key=f"new_host|{src_ip}",
                )
            )
            early_hosts.add(src_ip)
        if dst_ip and dst_ip not in early_hosts:
            alerts.append(
                _make_alert(
                    rule="detect_new_host_mid_capture",
                    severity="INFO",
                    description="New host appeared after initial capture window",
                    timestamp=pkt["timestamp"],
                    src_ip=dst_ip,
                    protocol=pkt.get("protocol"),
                    evidence={},
                    tags=["anomaly"],
                    dedup_key=f"new_host|{dst_ip}",
                )
            )
            early_hosts.add(dst_ip)

    times = [pkt["timestamp"] for pkt in packets]
    start_time = min(times)
    buckets: dict[int, int] = defaultdict(int)
    for pkt in packets:
        bucket = int((pkt["timestamp"] - start_time) / 5)
        buckets[bucket] += 1
    avg = sum(buckets.values()) / max(1, len(buckets))
    for bucket, count in buckets.items():
        if avg > 0 and count > 3 * avg:
            alerts.append(
                _make_alert(
                    rule="detect_traffic_spike",
                    severity="LOW",
                    description="Traffic spike detected in 5-second window",
                    timestamp=start_time + bucket * 5,
                    evidence={"window_start": bucket * 5, "packet_count": count, "average": avg},
                    tags=["anomaly"],
                    dedup_key=f"traffic_spike|{bucket}",
                )
            )

    by_src_port: dict[tuple[str, int], set[str]] = defaultdict(set)
    for pkt in packets:
        if pkt.get("src_ip") and pkt.get("src_port") and pkt.get("dst_ip"):
            by_src_port[(pkt["src_ip"], pkt["src_port"])].add(pkt["dst_ip"])
    for (src_ip, src_port), dst_ips in by_src_port.items():
        if len(dst_ips) > 3:
            alerts.append(
                _make_alert(
                    rule="detect_port_reuse",
                    severity="LOW",
                    description="Source port reused across multiple destination IPs",
                    timestamp=packets[-1]["timestamp"],
                    src_ip=src_ip,
                    protocol=None,
                    evidence={"src_port": src_port, "destinations": sorted(dst_ips)},
                    tags=["anomaly"],
                    dedup_key=f"port_reuse|{src_ip}|{src_port}",
                )
            )

    for convo in conversations:
        if convo.get("protocol") != "TCP":
            continue
        if convo.get("total_bytes", 0) == 0:
            continue
        bytes_a = 0
        bytes_b = 0
        client = convo.get("client", "")
        server = convo.get("server", "")
        for item in convo.get("stream", []):
            direction = item.get("direction")
            length = item.get("length", 0)
            if direction == "client→server":
                bytes_a += length
            elif direction == "server→client":
                bytes_b += length
        if bytes_a > 0 and bytes_b > 0:
            ratio = max(bytes_a, bytes_b) / max(1, min(bytes_a, bytes_b))
        else:
            ratio = 0
        if ratio >= 10:
            alerts.append(
                _make_alert(
                    rule="detect_asymmetric_conversation",
                    severity="LOW",
                    description="TCP conversation appears asymmetric",
                    timestamp=convo.get("end_time", 0),
                    src_ip=client.split(":")[0],
                    dst_ip=server.split(":")[0],
                    protocol="TCP",
                    evidence={"bytes_client_to_server": bytes_a, "bytes_server_to_client": bytes_b, "ratio": ratio},
                    tags=["anomaly"],
                    dedup_key=f"asymmetric|{client}|{server}",
                )
            )

    for pkt in packets:
        ttl = pkt.get("ttl")
        if ttl is not None and ttl <= 5:
            alerts.append(
                _make_alert(
                    rule="detect_ttl_anomaly",
                    severity="LOW",
                    description="TTL very low (possibly traceroute or anomaly)",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol=pkt.get("protocol"),
                    evidence={"ttl": ttl},
                    tags=["anomaly"],
                    dedup_key=f"ttl_low|{pkt.get('src_ip')}|{pkt.get('dst_ip')}|{ttl}",
                )
            )
        if pkt.get("ip_more_fragments") or (pkt.get("ip_frag_offset") or 0) > 0:
            if pkt.get("protocol") in {"TCP", "UDP"}:
                alerts.append(
                    _make_alert(
                        rule="detect_fragmented_ip",
                        severity="LOW",
                        description="Fragmented IP packet observed for TCP/UDP",
                        timestamp=pkt["timestamp"],
                        src_ip=pkt.get("src_ip"),
                        dst_ip=pkt.get("dst_ip"),
                        protocol=pkt.get("protocol"),
                        evidence={
                            "more_fragments": pkt.get("ip_more_fragments"),
                            "fragment_offset": pkt.get("ip_frag_offset"),
                        },
                        tags=["anomaly"],
                        dedup_key=f"fragment|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                    )
                )
    return alerts


def run_detections(packets: list[dict[str, Any]], conversations: list[dict[str, Any]], total_packets: int) -> list[dict[str, Any]]:
    rules = [
        detect_tcp_syn_scan,
        detect_tcp_connect_scan,
        detect_tcp_flag_scans,
        detect_udp_scan,
        detect_icmp_sweep,
        detect_os_fingerprinting,
        detect_service_version_probe,
        detect_heartbleed,
        detect_http_exploits,
        detect_credential_exposure,
        detect_dns_exfiltration,
        detect_icmp_exfiltration,
        detect_large_http_post,
        detect_large_dns_txt,
        detect_beaconing,
        detect_long_low_volume_connections,
        detect_http_c2_patterns,
        detect_http_c2_identical_user_agents,
        detect_tls_no_sni,
        detect_tls_self_signed,
        detect_known_bad_ports,
        detect_arp_spoofing,
        detect_arp_flood,
        detect_icmp_flood,
        detect_tcp_syn_flood,
        detect_dns_amplification,
        detect_vlan_hopping,
        detect_policy_violations,
        lambda pkts, convos: detect_anomalies(pkts, convos, total_packets),
    ]
    alerts: list[dict[str, Any]] = []
    for rule in rules:
        alerts.extend(rule(packets, conversations))
    return _dedupe_alerts(alerts)


def list_rules() -> list[str]:
    return [
        "detect_tcp_syn_scan",
        "detect_tcp_connect_scan",
        "detect_tcp_flag_scan",
        "detect_udp_scan",
        "detect_icmp_sweep",
        "detect_os_fingerprinting",
        "detect_service_version_probe",
        "detect_heartbleed",
        "detect_shellshock",
        "detect_sql_injection",
        "detect_xss",
        "detect_directory_traversal",
        "detect_command_injection",
        "detect_log4shell",
        "detect_http_basic_auth",
        "detect_http_form_credentials",
        "detect_session_token_in_url",
        "detect_ftp_cleartext_credentials",
        "detect_telnet_cleartext",
        "detect_smtp_auth_cleartext",
        "detect_private_key_material",
        "detect_dns_tunneling",
        "detect_dns_exfiltration_volume",
        "detect_icmp_exfiltration",
        "detect_large_http_post",
        "detect_large_dns_txt",
        "detect_beaconing",
        "detect_long_low_volume_tcp",
        "detect_http_c2_user_agent",
        "detect_tls_no_sni",
        "detect_self_signed_cert",
        "detect_known_bad_ports",
        "detect_arp_spoofing",
        "detect_arp_flood",
        "detect_icmp_flood",
        "detect_tcp_syn_flood",
        "detect_dns_amplification",
        "detect_vlan_hopping",
        "detect_unencrypted_internal_http",
        "detect_unencrypted_protocol",
        "detect_deprecated_tls",
        "detect_internal_ip_header",
        "detect_amqp_secret_strings",
        "detect_new_host_mid_capture",
        "detect_traffic_spike",
        "detect_port_reuse",
        "detect_asymmetric_conversation",
        "detect_fragmented_ip",
        "detect_ttl_anomaly",
    ]


def build_output(
    pcap_path: Path,
    *,
    filter_ip: str | None = None,
    filter_proto: str | None = None,
) -> tuple[dict[str, Any], dict[str, int]]:
    packets_raw, _, version = _read_pcap(pcap_path)
    if not packets_raw:
        raise ValueError("No packets in capture")

    capture_start = packets_raw[0]["ts_sec"] + packets_raw[0]["ts_usec"] / 1_000_000
    capture_end = packets_raw[-1]["ts_sec"] + packets_raw[-1]["ts_usec"] / 1_000_000
    duration = max(0.0, capture_end - capture_start)
    capture_start_iso = datetime.datetime.utcfromtimestamp(capture_start).replace(tzinfo=datetime.timezone.utc)

    host_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"packets_sent": 0, "packets_received": 0, "protocols_used": set(), "ports_used": set()}
    )
    protocol_counts: Counter[str] = Counter()
    total_bytes = 0

    parsed_packets: list[dict[str, Any]] = []
    conversations: dict[tuple, dict[str, Any]] = {}
    heartbleed_count = 0
    hidden_message_count = 0
    rsa_key_count = 0

    for index, packet in enumerate(packets_raw, start=1):
        ts = packet["ts_sec"] + packet["ts_usec"] / 1_000_000
        parsed = _parse_packet(packet["frame"])
        if parsed is None:
            continue

        l4 = parsed["l4"]
        app_proto = _app_protocol(parsed.get("src_port"), parsed.get("dst_port"), l4)
        if filter_ip and filter_ip not in {parsed.get("src_ip"), parsed.get("dst_ip")}:
            continue
        if filter_proto and filter_proto.upper() != app_proto.upper():
            continue

        total_bytes += packet["orig_len"]
        protocol_counts[l4.upper()] += 1

        src_ip = parsed.get("src_ip")
        dst_ip = parsed.get("dst_ip")
        src_port = parsed.get("src_port")
        dst_port = parsed.get("dst_port")
        ttl = parsed.get("ttl")
        if src_ip:
            host_stats[src_ip]["packets_sent"] += 1
            host_stats[src_ip]["protocols_used"].add(l4.upper())
            if src_port is not None:
                host_stats[src_ip]["ports_used"].add(src_port)
        if dst_ip:
            host_stats[dst_ip]["packets_received"] += 1
            host_stats[dst_ip]["protocols_used"].add(l4.upper())
            if dst_port is not None:
                host_stats[dst_ip]["ports_used"].add(dst_port)

        content_type, readable, extras = _protocol_readable(parsed)
        if extras.get("heartbleed"):
            heartbleed_count += 1
            if isinstance(readable, list):
                if any("PRIVATE KEY" in item for item in readable):
                    rsa_key_count += 1
            elif isinstance(readable, str) and "PRIVATE KEY" in readable:
                rsa_key_count += 1
        if extras.get("hidden_message"):
            hidden_message_count += 1
        if isinstance(readable, str) and "BEGIN RSA PRIVATE KEY" in readable:
            rsa_key_count += 1

        packet_entry = {
            "index": index,
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": app_proto,
            "length": packet["orig_len"],
            "ttl": ttl,
            "tcp_flags": parsed.get("tcp_flags"),
            "tcp_window": parsed.get("tcp_window"),
            "ip_more_fragments": parsed.get("ip_more_fragments"),
            "ip_frag_offset": parsed.get("ip_frag_offset"),
            "tls_version": extras.get("tls_version"),
            "dns_txt_length": extras.get("txt_length"),
            "content_type": content_type,
            "readable": readable,
            "hidden_message": extras.get("hidden_message"),
            "icmp_id": parsed.get("icmp_id"),
            "icmp_seq": parsed.get("icmp_seq"),
            "icmp_type": parsed.get("icmp_type"),
            "icmp_code": parsed.get("icmp_code"),
        }
        parsed_packets.append(packet_entry)

        conv_key = _conversation_key(parsed, app_proto)
        convo = conversations.get(conv_key)
        if convo is None:
            client, server = _format_client_server(src_ip or "", dst_ip or "", src_port, dst_port, app_proto)
            convo = {
                "protocol": app_proto,
                "client": client,
                "server": server,
                "start_time": ts - capture_start,
                "end_time": ts - capture_start,
                "total_packets": 0,
                "total_bytes": 0,
                "stream": [],
            }
            conversations[conv_key] = convo

        convo["end_time"] = ts - capture_start
        convo["total_packets"] += 1
        convo["total_bytes"] += packet["orig_len"]
        direction = _format_direction(src_ip or "", dst_ip or "", convo["client"], convo["server"])
        convo["stream"].append(
            {
                "direction": direction,
                "time": ts - capture_start,
                "length": extras.get("raw_length", 0),
                "content_type": content_type,
                "readable": readable,
            }
        )

    summary = {
        "file": pcap_path.name,
        "pcap_version": f"{version[0]}.{version[1]}",
        "capture_start": capture_start_iso.isoformat().replace("+00:00", "Z"),
        "duration_seconds": duration,
        "total_packets": len(parsed_packets),
        "total_bytes": total_bytes,
        "protocols": dict(protocol_counts),
    }

    hosts = {
        ip: {
            "packets_sent": stats["packets_sent"],
            "packets_received": stats["packets_received"],
            "protocols_used": sorted(stats["protocols_used"]),
            "ports_used": sorted(stats["ports_used"]),
        }
        for ip, stats in host_stats.items()
    }

    conversations_list = []
    for idx, convo in enumerate(conversations.values(), start=1):
        conversations_list.append({"id": f"conv_{idx:03d}", **convo})

    alerts = run_detections(parsed_packets, conversations_list, total_packets=len(parsed_packets))
    output = {
        "summary": summary,
        "hosts": hosts,
        "conversations": conversations_list,
        "packets": list(_iter_packets(parsed_packets, capture_start)),
        "alerts": alerts,
    }
    notable = {
        "heartbleed": heartbleed_count,
        "icmp_hidden": hidden_message_count,
        "rsa_keys": rsa_key_count,
    }
    return output, notable


def _format_protocol_percentages(protocols: dict[str, int]) -> str:
    total = sum(protocols.values())
    if total == 0:
        return ""
    parts = []
    for proto, count in sorted(protocols.items(), key=lambda item: item[1], reverse=True):
        pct = (count / total) * 100
        if pct < 1:
            parts.append(f"{proto}(<1%)")
        else:
            parts.append(f"{proto}({pct:.0f}%)")
    return " ".join(parts)


def _render_alerts(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "No alerts detected."
    lines = ["Detected alerts:"]
    for alert in alerts:
        severity = alert.get("severity", "INFO")
        rule = alert.get("rule", "unknown")
        src = alert.get("src_ip") or "-"
        dst = alert.get("dst_ip") or "-"
        description = alert.get("description", "")
        count = alert.get("count", 1)
        lines.append(f"- [{severity}] {rule} {src} → {dst} (count={count}) {description}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert a PCAP file to structured JSON")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("-o", "--out", type=Path, default=None, help="Write full JSON output to file")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--conversations-only", action="store_true")
    parser.add_argument("--filter-ip", type=str, default=None)
    parser.add_argument("--filter-proto", type=str, default=None)
    parser.add_argument("--severity", type=str, default=None, help="Filter alerts at or above severity")
    parser.add_argument("--rules", action="store_true", help="List available detection rules and exit")
    args = parser.parse_args()

    if args.rules:
        for name in list_rules():
            print(name)
        return 0

    output, notable = build_output(args.pcap, filter_ip=args.filter_ip, filter_proto=args.filter_proto)
    if args.conversations_only:
        output.pop("packets", None)

    if args.severity:
        threshold = SEVERITY_ORDER.get(args.severity.upper())
        if threshold is None:
            raise SystemExit("Invalid severity. Use one of: CRITICAL, HIGH, MEDIUM, LOW, INFO")
        output["alerts"] = [
            alert for alert in output.get("alerts", []) if SEVERITY_ORDER.get(alert.get("severity", "INFO"), 1) >= threshold
        ]

    print(_render_alerts(output.get("alerts", [])))

    if args.out:
        json_text = json.dumps(output, indent=2 if args.pretty else None)
        args.out.write_text(json_text, encoding="utf-8")
        print(f"✓ Wrote {args.out}")

    summary = output["summary"]
    proto_line = _format_protocol_percentages(summary.get("protocols", {}))
    print(f"  {summary['total_packets']:,} packets → {len(output['conversations']):,} conversations")
    if proto_line:
        print(f"  Protocols: {proto_line}")
    notes = []
    if notable["heartbleed"]:
        notes.append(f"{notable['heartbleed']} HEARTBLEED packets")
    if notable["icmp_hidden"]:
        notes.append(f"{notable['icmp_hidden']} ICMP hidden messages")
    if notable["rsa_keys"]:
        notes.append(f"{notable['rsa_keys']} RSA private key in leaked memory")
    if notes:
        print("  Notable: " + ", ".join(notes))
    return 0


if __name__ == "__main__":
    sys.exit(main())

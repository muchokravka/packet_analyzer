from __future__ import annotations

import base64
import collections
import concurrent.futures
import dataclasses
import ipaddress
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, IO

from . import detections
from .pcapng import parse_pcapng
from .protocols import detect_kerberos, detect_quic, detect_smb, detect_ssh
from .utils import (
    DetectionPacket,
    ProgressCallback,
    decode_payload_text,
    entropy,
    extract_printable,
    find_http_header_value,
    is_private_ip,
    printable_ratio,
    SUSPICIOUS_PORTS,
)


ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN_8021Q = 0x8100
ETH_TYPE_VLAN_8021AD = 0x88A8
LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0
LINKTYPE_PPP = 9
LINKTYPE_PPP_HDLC = 50
LINKTYPE_PPP_ETHER = 51
LINKTYPE_LOOP = 108
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PPP_PROTO_IP = 0x0021
PPP_PROTO_IPV6 = 0x0057

HTTP_METHOD_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
)


@dataclasses.dataclass(slots=True)
class PacketRecord:
    index: int
    timestamp: float
    ts_sec: int
    ts_usec: int
    captured_len: int
    original_len: int
    frame_len: int
    l2: str
    l3: str | None
    l4: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    ttl: int | None
    tcp_flags: list[str]
    direction: str | None
    flow_key: str | None
    app_hints: list[str]
    payload_size: int
    payload_preview: str | None
    payload_b64: str | None
    payload_hex: str | None
    dns_query: str | None
    http_first_line: str | None
    indicators: list[str]
    parse_note: str | None
    icmp_type: int | None
    icmp_code: int | None
    icmp_checksum: int | None
    icmp_id: int | None
    icmp_seq: int | None
    tcp_window: int | None = None
    ip_more_fragments: bool | None = None
    ip_frag_offset: int | None = None


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        a, b = left, right
    else:
        a, b = right, left
    return f"{proto}|{a[0]}:{a[1]}|{b[0]}:{b[1]}"


def _extract_icmp_hidden_text(frame: bytes, icmp_start: int) -> str | None:
    payload_start = icmp_start + 16
    if len(frame) <= payload_start:
        return None
    payload = frame[payload_start:]
    stripped = payload.rstrip(b"N").rstrip(b"\x00").strip()
    if not stripped:
        return None
    if not all(0x20 <= b <= 0x7e for b in stripped):
        return None
    text = stripped.decode("ascii")
    if text and re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
        try:
            return bytes.fromhex(text).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return text
    return text


def _b64(payload: bytes, max_bytes: int) -> str | None:
    if not payload:
        return None
    data = payload[:max_bytes]
    return base64.b64encode(data).decode("ascii")


def _hex(payload: bytes, max_bytes: int) -> str | None:
    if not payload:
        return None
    return payload[:max_bytes].hex()


def _decode_dns_name_at(payload: bytes, offset: int, depth: int = 0) -> tuple[str | None, int]:
    if depth > 10:
        return None, offset
    if offset >= len(payload):
        return None, offset

    labels: list[str] = []
    position = offset
    advanced = False
    while position < len(payload):
        length = payload[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0:
            if position + 1 >= len(payload):
                return None, position + 1
            pointer = ((length & 0x3F) << 8) | payload[position + 1]
            name, _ = _decode_dns_name_at(payload, pointer, depth + 1)
            if name:
                labels.append(name)
            position += 2
            advanced = True
            break

        position += 1
        label_end = position + length
        if label_end > len(payload):
            return None, position
        labels.append(payload[position:label_end].decode("ascii", errors="replace"))
        position = label_end

    if not labels:
        return None, position
    return ".".join(labels), position if not advanced else position


def _decode_dns_name(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount < 1:
        return None
    name, _ = _decode_dns_name_at(payload, 12)
    return name


def _parse_http_first_line(payload: bytes) -> str | None:
    if not payload:
        return None
    if payload.startswith(HTTP_METHOD_PREFIXES) or payload.startswith(b"HTTP/"):
        line = payload.split(b"\r\n", 1)[0]
        return line.decode("utf-8", errors="replace")[:300]
    return None


def _tcp_flags(flags_byte: int) -> list[str]:
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


def _packet_indicators(
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    direction: str | None,
    payload: bytes,
    tcp_flag_names: list[str],
    dns_query: str | None,
    http_first_line: str | None,
) -> list[str]:
    indicators: list[str] = []

    if direction in {"ingress", "egress", "external"} and (src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS):
        indicators.append("suspicious_port")
    if src_ip and dst_ip and (is_private_ip(src_ip) != is_private_ip(dst_ip)):
        indicators.append("cross_boundary_traffic")
    if "SYN" in tcp_flag_names and "ACK" not in tcp_flag_names:
        indicators.append("tcp_syn")
    if "RST" in tcp_flag_names:
        indicators.append("tcp_reset")

    if dns_query:
        if len(dns_query) > 60:
            indicators.append("long_dns_query")
        if re.search(r"[A-Za-z0-9+/]{18,}", dns_query):
            indicators.append("encoded_dns_label")

    if http_first_line and "HTTP/" in http_first_line and " 5" in http_first_line:
        indicators.append("http_server_error")

    if payload:
        payload_entropy = entropy(payload[:256])
        if payload_entropy > 7.4 and len(payload) > 80:
            indicators.append("high_entropy_payload")

    return indicators


def _read_pcap(path: Path) -> tuple[list[tuple[int, int, bytes, int]], str, int]:
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size == 0:
            raise ValueError("Empty pcap file")
        os.lseek(fd, 0, os.SEEK_SET)
        with mmap.mmap(fd, size, access=mmap.ACCESS_READ) as mem:
            magic = mem[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            elif magic == b"\x0a\x0d\x0d\x0a":
                try:
                    return parse_pcapng(path)
                except (ValueError, OSError):
                    return _try_convert_pcapng(path)
            else:
                raise ValueError(f"Unsupported pcap magic bytes: {magic.hex()}")

            if len(mem) < 24:
                raise ValueError("Corrupted pcap global header")

            _, _, _, _, _, link_type = struct.unpack(endian + "HHiIII", mem[4:24])

            packets: list[tuple[int, int, bytes, int]] = []
            offset = 24
            while offset + 16 <= len(mem):
                ts_sec, ts_usec, captured_len, original_len = struct.unpack(endian + "IIII", mem[offset : offset + 16])
                offset += 16
                if offset + captured_len > len(mem):
                    raise ValueError("Corrupted pcap packet payload")
                payload = bytes(mem[offset : offset + captured_len])
                offset += captured_len
                packets.append((ts_sec, ts_usec, payload, original_len))
            return packets, endian, link_type
    finally:
        os.close(fd)


def _try_convert_pcapng(path: Path) -> tuple[list[tuple[int, int, bytes, int]], str, int]:
    for tool in ("editcap", "tshark"):
        exe = shutil.which(tool)
        if exe is None:
            continue
        tmp = Path(tempfile.mktemp(suffix=".pcap"))
        try:
            if tool == "editcap":
                cmd = [exe, str(path), str(tmp)]
            else:
                cmd = [exe, "-F", "pcap", "-r", str(path), str(tmp)]
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            return _read_pcap(tmp)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            tmp.unlink(missing_ok=True)
            continue
        finally:
            tmp.unlink(missing_ok=True)
    raise ValueError(
        "pcapng is not supported. Install Wireshark (editcap/tshark) for auto-conversion, "
        "or convert manually: editcap input.pcapng output.pcap"
    )


def _extract_l3_context(frame: bytes, link_type: int) -> tuple[str, int | None, int | None]:
    if link_type in {LINKTYPE_NULL, LINKTYPE_LOOP}:
        if len(frame) < 4:
            return "loopback", None, None
        af_le = struct.unpack("<I", frame[0:4])[0]
        if af_le in {2}:
            return "loopback", 4, ETH_TYPE_IPV4
        if af_le in {24, 28, 30}:
            return "loopback", 4, ETH_TYPE_IPV6
        af_be = struct.unpack(">I", frame[0:4])[0]
        if af_be in {2}:
            return "loopback", 4, ETH_TYPE_IPV4
        if af_be in {24, 28, 30}:
            return "loopback", 4, ETH_TYPE_IPV6
        return "loopback", None, None

    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return "ethernet", None, None
        eth_type = struct.unpack(">H", frame[12:14])[0]
        return "ethernet", 14, eth_type

    if link_type == LINKTYPE_PPP:
        if len(frame) < 4:
            return "ppp", None, None
        proto = struct.unpack(">H", frame[2:4])[0]
        if proto == PPP_PROTO_IP:
            return "ppp", 4, ETH_TYPE_IPV4
        if proto == PPP_PROTO_IPV6:
            return "ppp", 4, ETH_TYPE_IPV6
        return "ppp", None, None

    if link_type in {LINKTYPE_PPP_HDLC, LINKTYPE_PPP_ETHER}:
        if len(frame) < 2:
            return "ppp", None, None
        proto = struct.unpack(">H", frame[0:2])[0]
        if proto == PPP_PROTO_IP:
            return "ppp", 2, ETH_TYPE_IPV4
        if proto == PPP_PROTO_IPV6:
            return "ppp", 2, ETH_TYPE_IPV6
        return "ppp", None, None

    if link_type == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return "linux_sll2", None, None
        protocol = struct.unpack(">H", frame[0:2])[0]
        return "linux_sll2", 20, protocol

    if link_type == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return "linux_sll", None, None
        protocol = struct.unpack(">H", frame[14:16])[0]
        return "linux_sll", 16, protocol

    if link_type == LINKTYPE_RAW:
        if not frame:
            return "raw", None, None
        version = frame[0] >> 4
        if version == 4:
            return "raw", 0, ETH_TYPE_IPV4
        if version == 6:
            return "raw", 0, ETH_TYPE_IPV6
        return "raw", None, None

    return f"linktype_{link_type}", None, None


def _parse_tls(payload: bytes) -> dict[str, Any]:
    """Parse first TLS record from *payload* and extract metadata."""
    result: dict[str, Any] = {
        "tls_content_type": None,
        "tls_version": None,
        "has_sni": False,
        "is_heartbleed": False,
    }
    if len(payload) < 5:
        return result

    content_type = payload[0]
    version_bytes = payload[1:3]
    record_len = struct.unpack(">H", payload[3:5])[0]

    version_map = {
        b"\x03\x00": "0x0300",
        b"\x03\x01": "0x0301",
        b"\x03\x02": "0x0302",
        b"\x03\x03": "0x0303",
        b"\x03\x04": "0x0304",
    }
    tls_ver = version_map.get(version_bytes)
    result["tls_version"] = tls_ver

    if content_type == 0x15:  # Alert
        result["tls_content_type"] = "TLS Alert"
    elif content_type == 0x16:  # Handshake
        if len(payload) < 6:
            return result
        hs_type = payload[5]
        if hs_type == 0x01:  # ClientHello
            result["tls_content_type"] = "TLS ClientHello"
            _parse_clienthello_sni(payload, result)
        elif hs_type == 0x02:  # ServerHello
            result["tls_content_type"] = "TLS ServerHello"
        elif hs_type == 0x0B:  # Certificate
            result["tls_content_type"] = "TLS Certificate"
        elif hs_type == 0x10:  # CertificateRequest
            result["tls_content_type"] = "TLS CertificateRequest"
        else:
            result["tls_content_type"] = f"TLS Handshake({hs_type})"
    elif content_type == 0x17:  # Application Data
        result["tls_content_type"] = "TLS AppData"
    elif content_type == 0x18:  # Heartbeat
        result["tls_content_type"] = "HEARTBLEED REQUEST"
        # Heartbleed: heartbeat request where payload_length > actual payload
        # TLS record header (5) + HeartbeatMessageType (1) + payload_length (2) = 8 bytes min
        if len(payload) >= 8:
            hb_payload_len = struct.unpack(">H", payload[6:8])[0]
            available = len(payload) - 8
            if hb_payload_len > available + 16:
                result["is_heartbleed"] = True

    return result


def _parse_clienthello_sni(payload: bytes, result: dict[str, Any]) -> None:
    """Extract SNI from TLS ClientHello handshake record, if present."""
    if len(payload) < 43:
        return
    # Skip: record header(5) + hs_type(1) + hs_len(3) + version(2) + random(32) = 43
    offset = 43
    # Skip session_id (1 byte length + data)
    if offset >= len(payload):
        return
    session_id_len = payload[offset]
    offset += 1 + session_id_len
    # Skip cipher suites (2 byte length + data)
    if offset + 1 >= len(payload):
        return
    cs_len = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2 + cs_len
    # Skip compression methods (1 byte length + data)
    if offset >= len(payload):
        return
    comp_len = payload[offset]
    offset += 1 + comp_len
    # Extensions: 2 byte length + data
    if offset + 1 >= len(payload):
        return
    ext_total = struct.unpack(">H", payload[offset : offset + 2])[0]
    offset += 2
    ext_end = offset + ext_total
    while offset + 4 <= ext_end and offset + 4 <= len(payload):
        ext_type = struct.unpack(">H", payload[offset : offset + 2])[0]
        ext_len = struct.unpack(">H", payload[offset + 2 : offset + 4])[0]
        offset += 4
        if ext_type == 0x0000:  # SNI
            if len(payload) >= offset + ext_len:
                sni_data = payload[offset : offset + ext_len]
                if len(sni_data) > 5:
                    name_len = struct.unpack(">H", sni_data[3:5])[0]
                    if len(sni_data) >= 5 + name_len:
                        result["has_sni"] = True
            break
        offset += ext_len


def _parse_dns_txt_length(payload: bytes) -> int | None:
    """Parse DNS response answer section and return first TXT record length."""
    if len(payload) < 12:
        return None
    # Check QR bit (response)
    if not (payload[2] & 0x80):
        return None
    # Parse header counts
    qdcount = struct.unpack(">H", payload[4:6])[0]
    ancount = struct.unpack(">H", payload[6:8])[0]
    if ancount < 1 or qdcount < 1:
        return None
    # Skip question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(payload):
            label_len = payload[offset]
            if label_len == 0:
                offset += 1
                break
            if label_len & 0xC0:
                offset += 2
                break
            offset += 1 + label_len
        offset += 4  # QTYPE + QCLASS
    # Parse answer records
    for _ in range(ancount):
        if offset >= len(payload):
            break
        # Name (might be compressed pointer 2 bytes)
        name_start = offset
        if payload[offset] & 0xC0:
            offset += 2
        else:
            while offset < len(payload):
                label_len = payload[offset]
                if label_len == 0:
                    offset += 1
                    break
                if label_len & 0xC0:
                    offset += 2
                    break
                offset += 1 + label_len
        # TYPE, CLASS, TTL, RDLENGTH
        if offset + 10 > len(payload):
            break
        rrtype = struct.unpack(">H", payload[offset : offset + 2])[0]
        offset += 2
        offset += 2  # CLASS
        offset += 4  # TTL
        rdlength = struct.unpack(">H", payload[offset : offset + 2])[0]
        offset += 2
        if rrtype == 16:  # TXT
            return rdlength
        offset += rdlength
    return None


def _build_detection_dict(
    index: int,
    timestamp: float,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    l4: str | None,
    l3: str | None,
    app_hints: list[str],
    ttl: int | None,
    tcp_flag_names: list[str],
    tcp_window_val: int | None,
    payload: bytes,
    captured_len: int,
    http_first_line: str | None,
    dns_query_val: str | None,
    icmp_type_val: int | None,
    icmp_code_val: int | None,
    icmp_id_val: int | None,
    icmp_seq_val: int | None,
    ip_mf: bool | None,
    ip_fo: int | None,
    icmp_hidden_map: dict[int, str],
    double_vlan_val: bool = False,
) -> DetectionPacket:
    proto: str
    content_type: str | None = None
    readable: str | None = None
    tls_version: str | None = None
    dns_txt_length_val: int | None = None

    if "http" in app_hints:
        proto = "HTTP"
        content_type = "HTTP response" if (http_first_line or "").startswith("HTTP/") else "HTTP request" if http_first_line else None
        readable = decode_payload_text(payload)
    elif "dns" in app_hints:
        proto = "DNS"
        is_dns_response = bool(payload[2] & 0x80) if len(payload) > 2 else False
        content_type = "DNS Response" if is_dns_response else "DNS Query"
        readable = f"Query: {dns_query_val}" if dns_query_val else None
        dns_txt_length_val = _parse_dns_txt_length(payload) if is_dns_response else None
    elif l4 == "tcp":
        if src_port == 443 or dst_port == 443:
            proto = "TLS"
            readable = decode_payload_text(payload)
            tls_info = _parse_tls(payload)
            content_type = tls_info.get("tls_content_type")
            tls_version = tls_info.get("tls_version")
            if tls_info.get("is_heartbleed"):
                content_type = "HEARTBLEED REQUEST"
        else:
            proto = "TCP"
            if payload:
                text = decode_payload_text(payload)
                pr = printable_ratio(payload[:256])
                readable = text[:300] if pr > 0.5 else None
    elif l4 == "udp":
        proto = "UDP"
    elif l4 == "icmp":
        proto = "ICMP"
        if icmp_type_val == 8:
            content_type = "Echo Request"
        elif icmp_type_val == 0:
            content_type = "Echo Reply"
        else:
            content_type = "ICMP"
    elif l4 == "icmpv6":
        proto = "ICMPv6"
        if icmp_type_val == 128:
            content_type = "Echo Request"
        elif icmp_type_val == 129:
            content_type = "Echo Reply"
        else:
            content_type = "ICMPv6"
    elif l3 == "arp":
        proto = "ARP"
        readable = decode_payload_text(payload)
    else:
        proto = (l4 or "UNKNOWN").upper()
        readable = decode_payload_text(payload)[:300] if payload else None

    hidden_message = (icmp_seq_val is not None and icmp_seq_val in icmp_hidden_map)

    return {
        "index": index,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": captured_len,
        "ttl": ttl,
        "tcp_flags": tcp_flag_names,
        "tcp_window": tcp_window_val,
        "content_type": content_type,
        "readable": readable,
        "hidden_message": hidden_message,
        "icmp_id": icmp_id_val,
        "icmp_seq": icmp_seq_val,
        "icmp_type": icmp_type_val,
        "icmp_code": icmp_code_val,
        "ip_more_fragments": ip_mf,
        "ip_frag_offset": ip_fo,
        "tls_version": tls_version,
        "dns_txt_length": dns_txt_length_val,
        "double_vlan": double_vlan_val,
    }


def _flow_to_conversation_dict(flow: dict[str, Any]) -> dict[str, Any]:
    proto = flow.get("protocol", "tcp")
    app = flow.get("app_hints", [])
    if "http" in app:
        app_proto = "HTTP"
    elif "dns" in app:
        app_proto = "DNS"
    elif proto == "tcp":
        app_proto = "TCP"
    elif proto == "udp":
        app_proto = "UDP"
    else:
        app_proto = proto.upper()

    src = flow.get("src", "")
    dst = flow.get("dst", "")

    return {
        "id": flow.get("flow_key", ""),
        "protocol": app_proto,
        "client": src,
        "server": dst,
        "start_time": flow.get("first_seen", 0.0),
        "end_time": flow.get("last_seen", 0.0),
        "duration_sec": flow.get("duration_sec", 0.0),
        "total_packets": flow.get("packets", 0),
        "total_bytes": flow.get("bytes", 0),
        "bytes_a_to_b": flow.get("bytes_a_to_b", 0),
        "bytes_b_to_a": flow.get("bytes_b_to_a", 0),
        "stream": [],
        "tcp_flags": list(flow.get("tcp_flags", [])),
    }


def _process_packet_chunk(
    packets_chunk: list[tuple[int, int, bytes, int]],
    start_index: int,
    link_type: int,
    endian: str,
    include_payload_b64: bool,
    max_payload_b64_bytes: int,
) -> dict[str, Any]:
    """Process a chunk of raw packets. Returns dict with all collected data."""
    packet_records: list[PacketRecord] = []
    detection_packets: list[DetectionPacket] = []
    protocol_counts: collections.Counter[str] = collections.Counter()
    source_ip_counts: collections.Counter[str] = collections.Counter()
    destination_ip_counts: collections.Counter[str] = collections.Counter()
    tcp_port_counts: collections.Counter[int] = collections.Counter()
    udp_port_counts: collections.Counter[int] = collections.Counter()
    flows: dict[str, dict[str, Any]] = {}
    indicator_counts: collections.Counter[str] = collections.Counter()
    dns_queries: collections.Counter[str] = collections.Counter()
    http_lines: list[str] = []
    payload_bytes_total = 0
    icmp_hidden_texts: dict[int, str] = {}

    for index, (ts_sec, ts_usec, frame, original_len) in enumerate(packets_chunk, start=start_index):
        timestamp = ts_sec + ts_usec / 1_000_000
        l2: str = "unknown"
        l3: str | None = None
        l4: str | None = None
        src_ip: str | None = None
        dst_ip: str | None = None
        src_port: int | None = None
        dst_port: int | None = None
        ttl: int | None = None
        payload: bytes = b""
        dns_query: str | None = None
        http_first_line: str | None = None
        tcp_flag_names: list[str] = []
        app_hints: list[str] = []
        flow_key: str | None = None
        parse_note: str | None = None
        icmp_type: int | None = None
        icmp_code: int | None = None
        icmp_checksum: int | None = None
        icmp_id: int | None = None
        icmp_seq: int | None = None
        tcp_window: int | None = None
        ip_more_fragments: bool | None = None
        ip_frag_offset: int | None = None

        l2, l3_offset, eth_type = _extract_l3_context(frame, link_type)
        vlan_count = 0
        if l3_offset is not None and eth_type is not None:
            while eth_type in {ETH_TYPE_VLAN_8021Q, ETH_TYPE_VLAN_8021AD} and len(frame) >= l3_offset + 4:
                eth_type = struct.unpack(">H", frame[l3_offset + 2 : l3_offset + 4])[0]
                l3_offset += 4
                vlan_count += 1

            if eth_type == ETH_TYPE_ARP:
                protocol_counts["ARP"] += 1
                l3 = "arp"
                if len(frame) > l3_offset:
                    payload = frame[l3_offset:]
            elif eth_type == ETH_TYPE_IPV4:
                l3 = "ipv4"
                protocol_counts["IPv4"] += 1
                if len(frame) >= l3_offset + 20:
                    ihl = (frame[l3_offset] & 0x0F) * 4
                    ip_header_start = l3_offset
                    ip_header_end = ip_header_start + ihl
                    if ihl >= 20 and len(frame) >= ip_header_end:
                        proto = frame[ip_header_start + 9]
                        ttl = frame[ip_header_start + 8]
                        src_ip = ".".join(str(b) for b in frame[ip_header_start + 12 : ip_header_start + 16])
                        dst_ip = ".".join(str(b) for b in frame[ip_header_start + 16 : ip_header_start + 20])
                        source_ip_counts[src_ip] += 1
                        destination_ip_counts[dst_ip] += 1
                        flags_offset_val = struct.unpack(">H", frame[ip_header_start + 6 : ip_header_start + 8])[0]
                        ip_more_fragments = bool(flags_offset_val & 0x2000)
                        ip_frag_offset = flags_offset_val & 0x1FFF

                        if proto == PROTO_ICMP:
                            l4 = "icmp"
                            protocol_counts["ICMP"] += 1
                            icmp_start = ip_header_end
                            if len(frame) >= icmp_start + 4:
                                icmp_type = frame[icmp_start]
                                icmp_code = frame[icmp_start + 1]
                                icmp_checksum = struct.unpack(">H", frame[icmp_start + 2 : icmp_start + 4])[0]
                                if icmp_type in {0, 8} and len(frame) >= icmp_start + 8:
                                    icmp_id = struct.unpack(">H", frame[icmp_start + 4 : icmp_start + 6])[0]
                                    icmp_seq = struct.unpack(">H", frame[icmp_start + 6 : icmp_start + 8])[0]
                            payload_start = icmp_start + 8 if len(frame) >= icmp_start + 8 else icmp_start + 4
                            payload = frame[payload_start:] if len(frame) > payload_start else b""
                            if icmp_seq is not None:
                                hidden_text = _extract_icmp_hidden_text(frame, icmp_start)
                                if hidden_text:
                                    icmp_hidden_texts[icmp_seq] = hidden_text
                        elif proto == PROTO_TCP:
                            l4 = "tcp"
                            protocol_counts["TCP"] += 1
                            if len(frame) >= ip_header_end + 20:
                                src_port = struct.unpack(">H", frame[ip_header_end : ip_header_end + 2])[0]
                                dst_port = struct.unpack(">H", frame[ip_header_end + 2 : ip_header_end + 4])[0]
                                data_offset = (frame[ip_header_end + 12] >> 4) * 4
                                flags_byte = frame[ip_header_end + 13]
                                tcp_flag_names = _tcp_flags(flags_byte)
                                tcp_window = struct.unpack(">H", frame[ip_header_end + 14 : ip_header_end + 16])[0]
                                payload_start = ip_header_end + data_offset
                                payload = frame[payload_start:] if len(frame) >= payload_start else b""
                                if src_port is not None:
                                    tcp_port_counts[src_port] += 1
                                if dst_port is not None:
                                    tcp_port_counts[dst_port] += 1
                                http_first_line = _parse_http_first_line(payload)
                                if http_first_line:
                                    app_hints.append("http")
                                    http_lines.append(http_first_line)
                                if src_port == 22 or dst_port == 22:
                                    if detect_ssh(payload).get("app_hint"):
                                        app_hints.append("ssh")
                                elif src_port in {139, 445} or dst_port in {139, 445}:
                                    if detect_smb(payload).get("app_hint"):
                                        app_hints.append("smb")
                                elif src_port == 88 or dst_port == 88:
                                    if detect_kerberos(payload).get("app_hint"):
                                        app_hints.append("kerberos")
                        elif proto == PROTO_UDP:
                            l4 = "udp"
                            protocol_counts["UDP"] += 1
                            if len(frame) >= ip_header_end + 8:
                                src_port = struct.unpack(">H", frame[ip_header_end : ip_header_end + 2])[0]
                                dst_port = struct.unpack(">H", frame[ip_header_end + 2 : ip_header_end + 4])[0]
                                payload = frame[ip_header_end + 8 :]
                                if src_port is not None:
                                    udp_port_counts[src_port] += 1
                                if dst_port is not None:
                                    udp_port_counts[dst_port] += 1
                                if src_port == 53 or dst_port == 53:
                                    dns_query = _decode_dns_name(payload)
                                    if dns_query:
                                        app_hints.append("dns")
                                        dns_queries[dns_query] += 1
                                elif src_port == 88 or dst_port == 88:
                                    if detect_kerberos(payload).get("app_hint"):
                                        app_hints.append("kerberos")
                                elif src_port == 443 or dst_port == 443:
                                    if detect_quic(payload).get("app_hint"):
                                        app_hints.append("quic")
                        else:
                            l4 = f"ip_proto_{proto}"
                            protocol_counts[l4] += 1
                            payload = frame[ip_header_end:] if len(frame) > ip_header_end else b""
            elif eth_type == ETH_TYPE_IPV6:
                l3 = "ipv6"
                protocol_counts["IPv6"] += 1
                ip_header_start = l3_offset
                if len(frame) >= ip_header_start + 40:
                    proto = frame[ip_header_start + 6]
                    ttl = frame[ip_header_start + 7]
                    src_ip = str(ipaddress.IPv6Address(frame[ip_header_start + 8 : ip_header_start + 24]))
                    dst_ip = str(ipaddress.IPv6Address(frame[ip_header_start + 24 : ip_header_start + 40]))
                    source_ip_counts[src_ip] += 1
                    destination_ip_counts[dst_ip] += 1
                    l4_start = ip_header_start + 40

                    if proto == PROTO_TCP:
                        l4 = "tcp"
                        protocol_counts["TCP"] += 1
                        if len(frame) >= l4_start + 20:
                            src_port = struct.unpack(">H", frame[l4_start : l4_start + 2])[0]
                            dst_port = struct.unpack(">H", frame[l4_start + 2 : l4_start + 4])[0]
                            data_offset = (frame[l4_start + 12] >> 4) * 4
                            flags_byte = frame[l4_start + 13]
                            tcp_flag_names = _tcp_flags(flags_byte)
                            payload_start = l4_start + data_offset
                            payload = frame[payload_start:] if len(frame) >= payload_start else b""
                            tcp_port_counts[src_port] += 1
                            tcp_port_counts[dst_port] += 1
                            http_first_line = _parse_http_first_line(payload)
                            if http_first_line:
                                app_hints.append("http")
                                http_lines.append(http_first_line)
                            if src_port == 22 or dst_port == 22:
                                if detect_ssh(payload).get("app_hint"):
                                    app_hints.append("ssh")
                            elif src_port in {139, 445} or dst_port in {139, 445}:
                                if detect_smb(payload).get("app_hint"):
                                    app_hints.append("smb")
                            elif src_port == 88 or dst_port == 88:
                                if detect_kerberos(payload).get("app_hint"):
                                    app_hints.append("kerberos")
                    elif proto == PROTO_UDP:
                        l4 = "udp"
                        protocol_counts["UDP"] += 1
                        if len(frame) >= l4_start + 8:
                            src_port = struct.unpack(">H", frame[l4_start : l4_start + 2])[0]
                            dst_port = struct.unpack(">H", frame[l4_start + 2 : l4_start + 4])[0]
                            payload = frame[l4_start + 8 :]
                            udp_port_counts[src_port] += 1
                            udp_port_counts[dst_port] += 1
                            if src_port == 53 or dst_port == 53:
                                dns_query = _decode_dns_name(payload)
                                if dns_query:
                                    app_hints.append("dns")
                                    dns_queries[dns_query] += 1
                            elif src_port == 88 or dst_port == 88:
                                if detect_kerberos(payload).get("app_hint"):
                                    app_hints.append("kerberos")
                            elif src_port == 443 or dst_port == 443:
                                if detect_quic(payload).get("app_hint"):
                                    app_hints.append("quic")
                    elif proto == 58:
                        l4 = "icmpv6"
                        protocol_counts["ICMPv6"] += 1
                        icmp_start = l4_start
                        if len(frame) >= icmp_start + 4:
                            icmp_type = frame[icmp_start]
                            icmp_code = frame[icmp_start + 1]
                            icmp_checksum = struct.unpack(">H", frame[icmp_start + 2 : icmp_start + 4])[0]
                            if icmp_type in {128, 129} and len(frame) >= icmp_start + 8:
                                icmp_id = struct.unpack(">H", frame[icmp_start + 4 : icmp_start + 6])[0]
                                icmp_seq = struct.unpack(">H", frame[icmp_start + 6 : icmp_start + 8])[0]
                        payload_start = icmp_start + 8 if len(frame) >= icmp_start + 8 else icmp_start + 4
                        payload = frame[payload_start:] if len(frame) > payload_start else b""
                    else:
                        l4 = f"ipv6_next_{proto}"
                        protocol_counts[l4] += 1
                        payload = frame[l4_start:] if len(frame) > l4_start else b""
            else:
                parse_note = "unsupported_or_truncated_l3"
                payload = frame[l3_offset:] if l3_offset is not None and len(frame) > l3_offset else b""
        else:
            parse_note = "unsupported_or_truncated_link_layer"

        if src_ip and dst_ip and src_port is not None and dst_port is not None and l4 in {"tcp", "udp"}:
            flow_key = _flow_key(src_ip, dst_ip, src_port, dst_port, l4)
            flow = flows.setdefault(
                flow_key,
                {
                    "flow_key": flow_key,
                    "protocol": l4,
                    "src": f"{src_ip}:{src_port}",
                    "dst": f"{dst_ip}:{dst_port}",
                    "endpoint_a": min((src_ip, src_port), (dst_ip, dst_port)),
                    "endpoint_b": max((src_ip, src_port), (dst_ip, dst_port)),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "packets": 0,
                    "bytes": 0,
                    "bytes_a_to_b": 0,
                    "bytes_b_to_a": 0,
                    "tcp_flags": set(),
                    "app_hints": set(),
                    "indicators": collections.Counter(),
                },
            )
            flow["last_seen"] = timestamp
            flow["packets"] += 1
            flow["bytes"] += len(frame)
            if (src_ip, src_port) == flow["endpoint_a"]:
                flow["bytes_a_to_b"] += len(frame)
            else:
                flow["bytes_b_to_a"] += len(frame)
            if l4 == "tcp":
                for name in tcp_flag_names:
                    flow["tcp_flags"].add(name)

        direction = None
        if src_ip and dst_ip:
            src_private = is_private_ip(src_ip)
            dst_private = is_private_ip(dst_ip)
            if src_private and not dst_private:
                direction = "egress"
            elif not src_private and dst_private:
                direction = "ingress"
            elif src_private and dst_private:
                direction = "internal"
            else:
                direction = "external"

        payload_preview = extract_printable(payload)
        payload_b64 = _b64(payload, max_payload_b64_bytes) if include_payload_b64 else None
        payload_hex = _hex(payload, max_payload_b64_bytes)
        indicators = _packet_indicators(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            direction,
            payload,
            tcp_flag_names,
            dns_query,
            http_first_line,
        )
        for indicator in indicators:
            indicator_counts[indicator] += 1
            if flow_key:
                flow = flows[flow_key]
                flow["indicators"][indicator] += 1
        if flow_key and app_hints:
            flow = flows[flow_key]
            for hint in app_hints:
                flow["app_hints"].add(hint)

        payload_bytes_total += len(payload)
        packet_records.append(
            PacketRecord(
                index=index,
                timestamp=timestamp,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                captured_len=len(frame),
                original_len=original_len,
                frame_len=len(frame),
                l2=l2,
                l3=l3,
                l4=l4,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ttl=ttl,
                tcp_flags=tcp_flag_names,
                direction=direction,
                flow_key=flow_key,
                app_hints=app_hints,
                payload_size=len(payload),
                payload_preview=payload_preview,
                payload_b64=payload_b64,
                payload_hex=payload_hex,
                dns_query=dns_query,
                http_first_line=http_first_line,
                indicators=indicators,
                parse_note=parse_note,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                icmp_checksum=icmp_checksum,
                icmp_id=icmp_id,
                icmp_seq=icmp_seq,
                tcp_window=tcp_window,
                ip_more_fragments=ip_more_fragments,
                ip_frag_offset=ip_frag_offset,
            )
        )

        double_vlan = vlan_count >= 2
        detection_packets.append(
            _build_detection_dict(
                index=index,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                l4=l4,
                l3=l3,
                app_hints=app_hints,
                ttl=ttl,
                tcp_flag_names=tcp_flag_names,
                tcp_window_val=tcp_window,
                payload=payload,
                captured_len=len(frame),
                http_first_line=http_first_line,
                dns_query_val=dns_query,
                icmp_type_val=icmp_type,
                icmp_code_val=icmp_code,
                icmp_id_val=icmp_id,
                icmp_seq_val=icmp_seq,
                ip_mf=ip_more_fragments,
                ip_fo=ip_frag_offset,
                icmp_hidden_map={},
                double_vlan_val=double_vlan,
            )
        )

    return {
        "packet_records": packet_records,
        "detection_packets": detection_packets,
        "protocol_counts": protocol_counts,
        "source_ip_counts": source_ip_counts,
        "destination_ip_counts": destination_ip_counts,
        "tcp_port_counts": tcp_port_counts,
        "udp_port_counts": udp_port_counts,
        "flows": flows,
        "indicator_counts": indicator_counts,
        "dns_queries": dns_queries,
        "http_lines": http_lines,
        "payload_bytes_total": payload_bytes_total,
        "icmp_hidden_texts": icmp_hidden_texts,
    }


def _merge_chunk_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge results from multiple _process_packet_chunk calls."""
    merged: dict[str, Any] = {
        "packet_records": [],
        "detection_packets": [],
        "protocol_counts": collections.Counter(),
        "source_ip_counts": collections.Counter(),
        "destination_ip_counts": collections.Counter(),
        "tcp_port_counts": collections.Counter(),
        "udp_port_counts": collections.Counter(),
        "flows": {},
        "indicator_counts": collections.Counter(),
        "dns_queries": collections.Counter(),
        "http_lines": [],
        "payload_bytes_total": 0,
        "icmp_hidden_texts": {},
    }
    for r in results:
        merged["packet_records"].extend(r["packet_records"])
        merged["detection_packets"].extend(r["detection_packets"])
        merged["protocol_counts"] += r["protocol_counts"]
        merged["source_ip_counts"] += r["source_ip_counts"]
        merged["destination_ip_counts"] += r["destination_ip_counts"]
        merged["tcp_port_counts"] += r["tcp_port_counts"]
        merged["udp_port_counts"] += r["udp_port_counts"]
        merged["indicator_counts"] += r["indicator_counts"]
        merged["dns_queries"] += r["dns_queries"]
        merged["http_lines"].extend(r["http_lines"])
        merged["payload_bytes_total"] += r["payload_bytes_total"]
        merged["icmp_hidden_texts"].update(r["icmp_hidden_texts"])
        # Merge flows
        for flow_key, flow in r["flows"].items():
            existing = merged["flows"].get(flow_key)
            if existing is None:
                merged["flows"][flow_key] = flow
            else:
                existing["first_seen"] = min(existing["first_seen"], flow["first_seen"])
                existing["last_seen"] = max(existing["last_seen"], flow["last_seen"])
                existing["packets"] += flow["packets"]
                existing["bytes"] += flow["bytes"]
                existing["bytes_a_to_b"] += flow["bytes_a_to_b"]
                existing["bytes_b_to_a"] += flow["bytes_b_to_a"]
                existing["tcp_flags"].update(flow["tcp_flags"])
                existing["app_hints"].update(flow["app_hints"])
                existing["indicators"] += flow["indicators"]
    return merged


def _build_result(
    packets_raw: list[tuple[int, int, bytes, int]],
    endian: str,
    link_type: int,
    path: Path,
    *,
    include_payload_b64: bool = True,
    max_payload_b64_bytes: int = 256,
    packet_output_limit: int | None = 5000,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Build full analysis result from raw parsed packet data (shared by file + live)."""
    total_packets = len(packets_raw)
    # Decide sequential vs parallel
    if total_packets < 1000:
        if progress:
            progress("analyzing", 0, total_packets)
        result = _process_packet_chunk(packets_raw, 1, link_type, endian, include_payload_b64, max_payload_b64_bytes)
        merged = _merge_chunk_results([result])
        if progress:
            progress("analyzing", total_packets, total_packets)
    else:
        num_workers = min(32, (os.cpu_count() or 1) + 4)
        chunk_size = max(num_workers * 10, 100)
        chunks: list[list[tuple[int, int, bytes, int]]] = []
        for i in range(0, total_packets, chunk_size):
            chunks.append(packets_raw[i:i + chunk_size])

        if progress:
            progress("analyzing", 0, total_packets)

        completed = 0
        results: list[dict[str, Any]] = [{} for _ in range(len(chunks))]
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures: dict[concurrent.futures.Future, int] = {}
            start = 1
            for idx, chunk in enumerate(chunks):
                future = pool.submit(_process_packet_chunk, chunk, start, link_type, endian, include_payload_b64, max_payload_b64_bytes)
                futures[future] = idx
                start += len(chunk)

            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                results[idx] = future.result()
                completed += len(chunks[idx])
                if progress:
                    progress("analyzing", min(completed, total_packets), total_packets)

        merged = _merge_chunk_results(results)

    packet_records = merged["packet_records"]
    detection_packets = merged["detection_packets"]
    protocol_counts = merged["protocol_counts"]
    source_ip_counts = merged["source_ip_counts"]
    destination_ip_counts = merged["destination_ip_counts"]
    tcp_port_counts = merged["tcp_port_counts"]
    udp_port_counts = merged["udp_port_counts"]
    flows = merged["flows"]
    indicator_counts = merged["indicator_counts"]
    dns_queries = merged["dns_queries"]
    http_lines = merged["http_lines"]
    payload_bytes_total = merged["payload_bytes_total"]
    icmp_hidden_texts = merged["icmp_hidden_texts"]

    start_ts = packets_raw[0][0] + packets_raw[0][1] / 1_000_000 if packets_raw else 0.0
    end_ts = packets_raw[-1][0] + packets_raw[-1][1] / 1_000_000 if packets_raw else 0.0

    serialized_flows: list[dict[str, Any]] = []
    for flow in flows.values():
        serialized_flows.append(
            {
                "flow_key": flow["flow_key"],
                "protocol": flow["protocol"],
                "src": flow["src"],
                "dst": flow["dst"],
                "first_seen": flow["first_seen"],
                "last_seen": flow["last_seen"],
                "duration_sec": flow["last_seen"] - flow["first_seen"],
                "packets": flow["packets"],
                "bytes": flow["bytes"],
                "bytes_a_to_b": flow["bytes_a_to_b"],
                "bytes_b_to_a": flow["bytes_b_to_a"],
                "tcp_flags": sorted(flow["tcp_flags"]),
                "app_hints": sorted(flow["app_hints"]),
                "indicators": dict(flow["indicators"]),
            }
        )

    serialized_flows.sort(key=lambda item: (item["packets"], item["bytes"]), reverse=True)

    top_talkers = [
        {"ip": ip, "packets": count}
        for ip, count in source_ip_counts.most_common(15)
    ]

    top_destinations = [
        {"ip": ip, "packets": count}
        for ip, count in destination_ip_counts.most_common(15)
    ]

    top_tcp_ports = [
        {"port": port, "hits": count}
        for port, count in tcp_port_counts.most_common(15)
    ]

    top_udp_ports = [
        {"port": port, "hits": count}
        for port, count in udp_port_counts.most_common(15)
    ]

    packets_json_full = [dataclasses.asdict(packet) for packet in packet_records]
    packets_json = packets_json_full
    packets_truncated = False
    if packet_output_limit is not None and packet_output_limit >= 0 and len(packets_json_full) > packet_output_limit:
        notable = sorted(
            packets_json_full,
            key=lambda item: (
                len(item["indicators"]),
                item["payload_size"],
                1 if item["dns_query"] else 0,
                1 if item["http_first_line"] else 0,
            ),
            reverse=True,
        )
        packets_json = sorted(notable[:packet_output_limit], key=lambda item: item["index"])
        packets_truncated = True
    duration = max(0.0, end_ts - start_ts)

    summary: dict[str, Any] = {
        "file": str(path),
        "file_name": path.name,
        "packet_count": len(packet_records),
        "duration_sec": duration,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "captured_frame_bytes": sum(packet.frame_len for packet in packet_records),
        "payload_bytes": payload_bytes_total,
        "packets_per_sec": (len(packet_records) / duration) if duration > 0 else len(packet_records),
        "protocol_counts": dict(protocol_counts),
        "unique_sources": len(source_ip_counts),
        "unique_destinations": len(destination_ip_counts),
        "unique_flows": len(serialized_flows),
        "packets_output_count": len(packets_json),
        "packets_truncated": packets_truncated,
        "top_talkers": top_talkers,
        "top_destinations": top_destinations,
        "top_tcp_ports": top_tcp_ports,
        "top_udp_ports": top_udp_ports,
        "dns_top_queries": [
            {"query": query, "count": count} for query, count in dns_queries.most_common(20)
        ],
        "http_first_lines_sample": http_lines[:30],
        "indicator_counts": dict(indicator_counts),
        "pcap_format": {
            "byte_order": "little-endian" if endian == "<" else "big-endian",
            "link_type": link_type,
            "link_layer": packet_records[0].l2 if packet_records else "unknown",
            "supported_linktype": link_type
            in {
                LINKTYPE_ETHERNET,
                LINKTYPE_NULL,
                LINKTYPE_LOOP,
                LINKTYPE_PPP,
                LINKTYPE_PPP_HDLC,
                LINKTYPE_PPP_ETHER,
                LINKTYPE_RAW,
                LINKTYPE_LINUX_SLL,
                LINKTYPE_LINUX_SLL2,
            },
        },
        "unsupported_or_truncated_packets": sum(1 for p in packet_records if p.parse_note is not None),
        "icmp_hidden_texts": dict(sorted(icmp_hidden_texts.items())),
    }

    # ── Run detection engine ─────────────────────────────────────────────
    if progress:
        progress("detections", None, None)
    icmp_hidden_map: dict[int, str] = dict(sorted(icmp_hidden_texts.items()))
    for d in detection_packets:
        icmp_seq = d.get("icmp_seq")
        if icmp_seq is not None and icmp_seq in icmp_hidden_map:
            d["hidden_message"] = True
    detection_conversations = [_flow_to_conversation_dict(f) for f in serialized_flows]
    alerts = detections.run_detections(detection_packets, detection_conversations, total_packets=len(packet_records))

    if icmp_hidden_map:
        print("ICMP hidden text:")
        for seq, text in icmp_hidden_map.items():
            print(f"{seq}: {text}")

    ai_prep: dict[str, Any] = {
        "alerts": alerts,
        "prompt_guidance": {
            "task": "Analyze this network capture for notable behavior, anomalies, and likely activity.",
            "focus_areas": [
                "traffic profile",
                "protocol anomalies",
                "dns behavior",
                "suspicious ports",
                "lateral movement indicators",
                "possible exfiltration patterns",
            ],
            "safety_context": "This dataset is for legitimate network forensics and defensive analysis.",
        },
        "summary": summary,
        "flows": serialized_flows,
        "packets": packets_json,
    }

    return ai_prep


def analyze_pcap(
    pcap_path: str | Path,
    *,
    max_packets: int | None = None,
    include_payload_b64: bool = True,
    max_payload_b64_bytes: int = 256,
    packet_output_limit: int | None = 5000,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    path = Path(pcap_path)
    if progress:
        progress("reading", None, None)
    packets_raw, endian, link_type = _read_pcap(path)
    if max_packets is not None:
        packets_raw = packets_raw[:max_packets]
        if progress:
            progress("reading", len(packets_raw), len(packets_raw))
    return _build_result(
        packets_raw, endian, link_type, path,
        include_payload_b64=include_payload_b64,
        max_payload_b64_bytes=max_payload_b64_bytes,
        packet_output_limit=packet_output_limit,
        progress=progress,
    )


def render_json(result: dict[str, Any], *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(result, indent=2, sort_keys=False)
    return json.dumps(result, separators=(",", ":"), sort_keys=False)


def render_jsonl(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(json.dumps({"type": "summary", "data": result["summary"]}, separators=(",", ":")))
    for alert in result.get("alerts", []):
        lines.append(json.dumps({"type": "alert", "data": alert}, separators=(",", ":")))
    for flow in result["flows"]:
        lines.append(json.dumps({"type": "flow", "data": flow}, separators=(",", ":")))
    for packet in result["packets"]:
        lines.append(json.dumps({"type": "packet", "data": packet}, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def stream_jsonl(result: dict[str, Any], output: IO[str]) -> None:
    """Write JSONL records to *output* as a stream, flushing after each."""
    output.write(json.dumps({"type": "summary", "data": result["summary"]}, separators=(",", ":")) + "\n")
    output.flush()
    for alert in result.get("alerts", []):
        output.write(json.dumps({"type": "alert", "data": alert}, separators=(",", ":")) + "\n")
        output.flush()
    for flow in result["flows"]:
        output.write(json.dumps({"type": "flow", "data": flow}, separators=(",", ":")) + "\n")
        output.flush()
    for packet in result["packets"]:
        output.write(json.dumps({"type": "packet", "data": packet}, separators=(",", ":")) + "\n")
        output.flush()


def render_ai_prompt(
    result: dict[str, Any],
    *,
    max_flows: int = 20,
    max_packets: int = 30,
) -> str:
    summary = result["summary"]
    flows = result.get("flows", [])[:max_flows]
    packets = result.get("packets", [])[:max_packets]

    lines: list[str] = []
    lines.append("You are a network forensics assistant. Analyze the following PCAP-derived telemetry.")
    lines.append("Return: executive summary, prioritized findings, confidence, and recommended triage next steps.")
    lines.append("")
    lines.append("=== Capture Summary ===")
    lines.append(f"File: {summary.get('file_name')}")
    lines.append(f"Packets: {summary.get('packet_count')} (included in output: {summary.get('packets_output_count')})")
    lines.append(f"Duration(sec): {summary.get('duration_sec')}")
    lines.append(f"Unique flows: {summary.get('unique_flows')}")
    lines.append(f"Protocol counts: {json.dumps(summary.get('protocol_counts', {}), separators=(',', ':'))}")
    lines.append(f"Indicator counts: {json.dumps(summary.get('indicator_counts', {}), separators=(',', ':'))}")
    lines.append("Top talkers: " + json.dumps(summary.get("top_talkers", [])[:10], separators=(",", ":")))
    lines.append("Top TCP ports: " + json.dumps(summary.get("top_tcp_ports", [])[:10], separators=(",", ":")))
    lines.append("Top UDP ports: " + json.dumps(summary.get("top_udp_ports", [])[:10], separators=(",", ":")))
    lines.append("Top DNS queries: " + json.dumps(summary.get("dns_top_queries", [])[:10], separators=(",", ":")))
    lines.append("")
    alerts = result.get("alerts", [])
    if alerts:
        lines.append("=== Alerts ===")
        for alert in alerts[:20]:
            lines.append(
                json.dumps(
                    {
                        "rule": alert.get("rule"),
                        "severity": alert.get("severity"),
                        "src_ip": alert.get("src_ip"),
                        "dst_ip": alert.get("dst_ip"),
                        "description": alert.get("description"),
                        "count": alert.get("count"),
                    },
                    separators=(",", ":"),
                )
            )
        lines.append("")

    lines.append("=== Flow Samples ===")
    for flow in flows:
        lines.append(
            json.dumps(
                {
                    "flow_key": flow.get("flow_key"),
                    "protocol": flow.get("protocol"),
                    "src": flow.get("src"),
                    "dst": flow.get("dst"),
                    "packets": flow.get("packets"),
                    "bytes": flow.get("bytes"),
                    "bytes_a_to_b": flow.get("bytes_a_to_b"),
                    "bytes_b_to_a": flow.get("bytes_b_to_a"),
                    "tcp_flags": flow.get("tcp_flags"),
                    "app_hints": flow.get("app_hints"),
                    "indicators": flow.get("indicators"),
                },
                separators=(",", ":"),
            )
        )
    lines.append("")
    lines.append("=== Packet Samples ===")
    for packet in packets:
        lines.append(
            json.dumps(
                {
                    "index": packet.get("index"),
                    "timestamp": packet.get("timestamp"),
                    "l3": packet.get("l3"),
                    "l4": packet.get("l4"),
                    "src_ip": packet.get("src_ip"),
                    "dst_ip": packet.get("dst_ip"),
                    "src_port": packet.get("src_port"),
                    "dst_port": packet.get("dst_port"),
                    "direction": packet.get("direction"),
                    "dns_query": packet.get("dns_query"),
                    "http_first_line": packet.get("http_first_line"),
                    "payload_preview": packet.get("payload_preview"),
                    "payload_hex": packet.get("payload_hex"),
                    "indicators": packet.get("indicators"),
                },
                separators=(",", ":"),
            )
        )

    lines.append("")
    lines.append("=== Instructions ===")
    lines.append("1) Identify likely benign baseline vs suspicious behavior.")
    lines.append("2) Highlight possible scanning, C2, lateral movement, exfiltration, or misconfiguration.")
    lines.append("3) Reference exact flow_key/packet index for each finding.")
    lines.append("4) Provide prioritized next investigation steps and data gaps.")

    return "\n".join(lines) + "\n"

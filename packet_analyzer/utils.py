from __future__ import annotations

import collections
import ipaddress
import math
from typing import Any, NotRequired, TypedDict

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_ip(ip: str | None) -> bool:
    if ip is None:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(parsed in network for network in _PRIVATE_NETS)


def contains_private_ip(text: str) -> bool:
    if "10." not in text and "192.168." not in text and "172." not in text:
        return False
    for part in text.split():
        if part.startswith("172."):
            octets = part.split(".")
            if len(octets) > 1 and octets[1].isdigit():
                second = int(octets[1])
                if 16 <= second <= 31:
                    return True
            continue
        if part.startswith("10.") or part.startswith("192.168."):
            return True
    return False


def decode_payload_text(payload: bytes, max_len: int = 4096) -> str:
    truncated = payload[:max_len]
    try:
        return truncated.decode("utf-8")
    except UnicodeDecodeError:
        return truncated.decode("latin-1", errors="replace")


def extract_printable(payload: bytes, max_chars: int = 200) -> str | None:
    if not payload:
        return None
    cleaned = payload[:max_chars]
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in cleaned)
    if not text.strip("."):
        return None
    return text


def printable_ratio(payload: bytes) -> float:
    if not payload:
        return 0.0
    printable = 0
    for b in payload:
        if b in {9, 10, 13} or 0x20 <= b <= 0x7E:
            printable += 1
    return printable / len(payload)


def extract_ascii_runs(payload: bytes, min_len: int) -> list[str]:
    runs: list[str] = []
    current: list[int] = []
    for b in payload:
        if 0x20 <= b <= 0x7E:
            current.append(b)
        else:
            if len(current) >= min_len:
                runs.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        runs.append(bytes(current).decode("ascii"))
    return runs


def find_http_header_value(payload: str, header_name: str) -> str | None:
    for line in payload.split("\r\n"):
        if line.lower().startswith(header_name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def mask_secret(value: str) -> str:
    return "***" if value else "***"


def entropy(data: bytes | str) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    value = 0.0
    for count in counts.values():
        p = count / total
        value -= p * math.log2(p)
    return value


SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    445,
    3389,
    4444,
    5555,
    6667,
    31337,
}

BAD_C2_PORTS = {1080, 4444, 6666, 6667, 6668, 6669, 8888, 9001, 31337}


class DetectionPacket(TypedDict, total=False):
    index: int
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    ttl: int | None
    tcp_flags: list[str]
    tcp_window: int | None
    content_type: str | None
    readable: str | None
    hidden_message: bool
    icmp_id: int | None
    icmp_seq: int | None
    icmp_type: int | None
    icmp_code: int | None
    ip_more_fragments: bool | None
    ip_frag_offset: int | None
    tls_version: str | None
    dns_txt_length: int | None
    double_vlan: bool

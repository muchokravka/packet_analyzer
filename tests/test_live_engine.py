from __future__ import annotations

import struct
import time
from typing import Any

import pytest

from packet_analyzer.live_engine import (
    LiveConfig,
    LiveEngine,
    OnlineStats,
    RateTracker,
    SlidingWindowTracker,
    TTLDict,
    _decode_tcp_flags,
    _detect_link_type,
    _parse_raw_packet,
)
from packet_analyzer.utils import DetectionPacket


# ── SlidingWindowTracker Tests ───────────────────────────────────────────────


class TestSlidingWindowTracker:
    def test_add_and_count(self) -> None:
        t = SlidingWindowTracker(window_sec=10.0)
        t.add(100.0, "a")
        t.add(101.0, "b")
        t.add(102.0, "a")
        assert t.unique_count(105.0) == 2
        assert t.item_count(105.0) == 3

    def test_expiry(self) -> None:
        t = SlidingWindowTracker(window_sec=10.0)
        t.add(0.0, "old")
        t.add(15.0, "new")
        assert t.unique_count(15.0) == 1
        assert t.unique_keys(15.0) == {"new"}

    def test_all_expired(self) -> None:
        t = SlidingWindowTracker(window_sec=10.0)
        t.add(0.0, "gone")
        assert t.unique_count(20.0) == 0
        assert t.unique_keys(20.0) == set()

    def test_clear(self) -> None:
        t = SlidingWindowTracker(window_sec=10.0)
        t.add(100.0, "a")
        t.add(101.0, "b")
        t.clear()
        assert t.unique_count(102.0) == 0

    def test_empty_initial(self) -> None:
        t = SlidingWindowTracker(window_sec=10.0)
        assert t.unique_count() == 0
        assert t.item_count() == 0


# ── RateTracker Tests ────────────────────────────────────────────────────────


class TestRateTracker:
    def test_rate(self) -> None:
        rt = RateTracker(window_sec=1.0)
        now = 1000.0
        for _ in range(5):
            rt.tick(now)
        assert rt.rate(now) == pytest.approx(5.0)

    def test_rate_decays(self) -> None:
        rt = RateTracker(window_sec=1.0)
        rt.tick(0.0)
        assert rt.rate(2.0) < 1.0  # expired

    def test_clear(self) -> None:
        rt = RateTracker(window_sec=1.0)
        rt.tick(100.0)
        rt.clear()
        assert rt.rate(101.0) == 0.0


# ── TTLDict Tests ────────────────────────────────────────────────────────────


class TestTTLDict:
    def test_set_get(self) -> None:
        d = TTLDict(ttl_sec=60.0)
        d.set("k1", "v1")
        assert d.get("k1") == "v1"

    def test_get_missing(self) -> None:
        d = TTLDict(ttl_sec=60.0)
        assert d.get("nope") is None

    def test_expiry(self) -> None:
        d = TTLDict(ttl_sec=0.01)
        d.set("k1", "v1")
        time.sleep(0.02)
        assert d.prune() >= 1
        assert d.get("k1") is None

    def test_setdefault(self) -> None:
        d = TTLDict(ttl_sec=60.0)
        assert d.setdefault("k1", "default") == "default"
        assert d.setdefault("k1", "other") == "default"

    def test_items(self) -> None:
        d = TTLDict(ttl_sec=60.0)
        d.set("a", 1)
        d.set("b", 2)
        assert set(d.items()) == {("a", 1), ("b", 2)}

    def test_len(self) -> None:
        d = TTLDict(ttl_sec=60.0)
        d.set("a", 1)
        assert len(d) == 1


# ── OnlineStats Tests ────────────────────────────────────────────────────────


class TestOnlineStats:
    def test_single_value(self) -> None:
        s = OnlineStats()
        s.add(5.0)
        assert s.count == 1
        assert s.mean == 5.0
        assert s.variance == 0.0

    def test_known_values(self) -> None:
        s = OnlineStats()
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.add(v)
        assert s.mean == pytest.approx(3.0)
        assert s.variance == pytest.approx(2.0)

    def test_cov(self) -> None:
        s = OnlineStats()
        for v in [10.0, 10.0, 10.0]:
            s.add(v)
        assert s.cov == 0.0

    def test_cov_high(self) -> None:
        s = OnlineStats()
        for v in [1.0, 100.0, 1.0, 100.0]:
            s.add(v)
        assert s.cov > 0.5


# ── _decode_tcp_flags Tests ─────────────────────────────────────────────────


class TestDecodeTcpFlags:
    def test_syn(self) -> None:
        assert _decode_tcp_flags(0x02) == ["SYN"]

    def test_syn_ack(self) -> None:
        assert set(_decode_tcp_flags(0x12)) == {"SYN", "ACK"}

    def test_fin_psh_urg(self) -> None:
        flags = _decode_tcp_flags(0x29)  # FIN + PSH + URG
        assert set(flags) == {"FIN", "PSH", "URG"}

    def test_rst(self) -> None:
        assert _decode_tcp_flags(0x04) == ["RST"]

    def test_no_flags(self) -> None:
        assert _decode_tcp_flags(0x00) == []


# ── _parse_raw_packet Tests ─────────────────────────────────────────────────


def _eth_tcp_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    flags_byte: int = 0x02,
) -> bytes:
    """Build a minimal Ethernet + IPv4 + TCP frame."""
    eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0800)
    ver_ihl = 0x45
    tos = 0
    total_len = 40 + 20  # ip(20) + tcp(20)
    ip_id = 0
    ip_flags = 0x4000
    ttl = 64
    proto = 6  # TCP
    ip_checksum = 0
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ip_id, ip_flags,
        ttl, proto, ip_checksum,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    seq = 1000
    ack = 0
    data_offset = 0x50  # 5 words = 20 bytes
    window = 65535
    checksum = 0
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset, flags_byte, window, checksum, 0)
    return eth + ip_hdr + tcp_hdr


def _eth_udp_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 40000,
    dst_port: int = 53,
) -> bytes:
    """Build a minimal Ethernet + IPv4 + UDP frame."""
    eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0800)
    ver_ihl = 0x45
    total_len = 20 + 8  # ip(20) + udp(8)
    ip_id = 0
    ip_flags = 0x4000
    ttl = 64
    proto = 17  # UDP
    ip_checksum = 0
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, ip_id, ip_flags,
        ttl, proto, ip_checksum,
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, 8, 0)
    return eth + ip_hdr + udp_hdr


def _eth_icmp_echo(payload: bytes, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2") -> bytes:
    """Build a minimal Ethernet + IPv4 + ICMP Echo frame."""
    eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0800)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 0, 0x4000, 64, 1, 0,  # proto=1 ICMP
        bytes(int(x) for x in src_ip.split(".")),
        bytes(int(x) for x in dst_ip.split(".")),
    )
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0, 1)  # type=8 echo
    return eth + ip_hdr + icmp


class TestParseRawPacket:
    def test_tcp_packet(self) -> None:
        frame = _eth_tcp_packet()
        pkt = _parse_raw_packet(1000.0, frame)
        assert pkt is not None
        assert pkt["protocol"] == "TCP"
        assert pkt["src_ip"] == "10.0.0.1"
        assert pkt["dst_ip"] == "10.0.0.2"
        assert pkt["src_port"] == 12345
        assert pkt["dst_port"] == 80
        assert "SYN" in (pkt.get("tcp_flags") or [])

    def test_udp_packet(self) -> None:
        frame = _eth_udp_packet()
        pkt = _parse_raw_packet(1000.0, frame)
        assert pkt is not None
        assert pkt["protocol"] == "UDP"
        assert pkt["src_port"] == 40000
        assert pkt["dst_port"] == 53

    def test_icmp_packet(self) -> None:
        frame = _eth_icmp_echo(b"")
        pkt = _parse_raw_packet(1000.0, frame)
        assert pkt is not None
        assert pkt["protocol"] == "ICMP"
        assert pkt["icmp_type"] == 8

    def test_truncated_frame(self) -> None:
        pkt = _parse_raw_packet(1000.0, b"\x00" * 10)
        assert pkt is None

    def test_non_ip_frame(self) -> None:
        eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0806)
        eth += b"\x00" * 30  # ARP
        pkt = _parse_raw_packet(1000.0, eth)
        assert pkt is not None
        assert pkt["protocol"] == "ARP"

    def test_vlan_tagged(self) -> None:
        eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x8100)
        eth += struct.pack(">H", 0x002A)  # VLAN tag
        eth += struct.pack(">H", 0x0800)  # inner EtherType = IPv4
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 40, 0, 0x4000, 64, 6, 0,
            bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
        )
        tcp = struct.pack("!HHIIBBHHH", 12345, 80, 0, 0, 0x50, 0x02, 65535, 0, 0)
        pkt = _parse_raw_packet(1000.0, eth + ip_hdr + tcp)
        assert pkt is not None
        assert pkt["protocol"] == "TCP"
        assert pkt["src_ip"] == "10.0.0.1"

    def test_bad_ihl_too_small(self) -> None:
        frame = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0800)
        frame += bytes([0x45]) + b"\x00" * 4  # IHL=5 but only 5 bytes total
        pkt = _parse_raw_packet(1000.0, frame)
        assert pkt is not None
        assert pkt["protocol"] == "UNKNOWN"

    def test_rst_flag(self) -> None:
        frame = _eth_tcp_packet(flags_byte=0x04)
        pkt = _parse_raw_packet(1000.0, frame)
        assert pkt is not None
        assert "RST" in (pkt.get("tcp_flags") or [])

    def test_icmp_no_echo(self) -> None:
        eth = bytes.fromhex("001122334455" + "667788990011") + struct.pack(">H", 0x0800)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 28, 0, 0x4000, 64, 1, 0,
            bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
        )
        icmp = struct.pack("!BBHHH", 3, 0, 0, 0, 1)  # type=3 (unreach), not echo
        pkt = _parse_raw_packet(1000.0, eth + ip_hdr + icmp)
        assert pkt is not None
        assert pkt["protocol"] == "ICMP"
        assert pkt.get("icmp_type") == 3


# ── _detect_link_type Tests ─────────────────────────────────────────────────────


class TestDetectLinkType:
    def test_ethernet(self) -> None:
        pkt = _make_fake_packet("Ether")
        assert _detect_link_type(pkt) == 1

    def test_sll(self) -> None:
        pkt = _make_fake_packet("SLL")
        assert _detect_link_type(pkt) == 113

    def test_cooked_linux(self) -> None:
        pkt = _make_fake_packet("CookedLinux")
        assert _detect_link_type(pkt) == 113

    def test_loopback(self) -> None:
        pkt = _make_fake_packet("Loopback")
        assert _detect_link_type(pkt) == 0

    def test_ipnull(self) -> None:
        pkt = _make_fake_packet("IPnull")
        assert _detect_link_type(pkt) == 0

    def test_raw_ip(self) -> None:
        pkt = _make_fake_packet("IP")
        assert _detect_link_type(pkt) == 101

    def test_unknown_defaults_to_ethernet(self) -> None:
        pkt = _make_fake_packet("UnknownLayer")
        assert _detect_link_type(pkt) == 1


def _make_fake_packet(class_name: str) -> Any:
    cls = type(class_name, (object,), {})
    obj = cls()
    return obj


# ── Loopback / SLL Parsing + Rules Tests ──────────────────────────────────────


def _sll_tcp_syn(
    dst_port: int,
    src: str = "127.0.0.1",
    dst: str = "127.0.0.1",
    timestamp: float = 1000.0,
) -> DetectionPacket | None:
    sll = struct.pack("!HHH", 0, 0x0010, 0) + b"\x00" * 8  # sll_pkttype, sll_hatype, sll_halen, sll_addr
    sll += struct.pack(">H", 0x0800)  # sll_protocol = IPv4 (bytes 14-15)
    src_bytes = bytes(int(x) for x in src.split("."))
    dst_bytes = bytes(int(x) for x in dst.split("."))
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 0, 0x4000, 64, 6, 0,
        src_bytes, dst_bytes,
    )
    tcp = struct.pack("!HHIIBBHHH", 40000, dst_port, 0, 0, 0x50, 0x02, 65535, 0, 0)
    frame = sll + ip + tcp
    return _parse_raw_packet(timestamp, frame, link_type=113)


class TestSllParsing:
    def test_sll_parse_tcp_syn(self) -> None:
        pkt = _sll_tcp_syn(dst_port=80)
        assert pkt is not None
        assert pkt["protocol"] == "TCP"
        assert pkt["src_ip"] == "127.0.0.1"
        assert pkt["dst_ip"] == "127.0.0.1"
        assert "SYN" in (pkt.get("tcp_flags") or [])
        assert "ACK" not in (pkt.get("tcp_flags") or [])

    def test_sll_parse_tcp_syn_ack(self) -> None:
        sll = struct.pack("!HHH", 0, 0x0010, 0) + b"\x00" * 8
        sll += struct.pack(">H", 0x0800)
        src = bytes([127, 0, 0, 1])
        dst = bytes([127, 0, 0, 2])
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, src, dst,
        )
        tcp = struct.pack("!HHIIBBHHH", 80, 40000, 100, 200, 0x50, 0x12, 65535, 0, 0)
        frame = sll + ip + tcp
        pkt = _parse_raw_packet(1000.0, frame, link_type=113)
        assert pkt is not None
        assert pkt["protocol"] == "TCP"
        assert "SYN" in (pkt.get("tcp_flags") or [])
        assert "ACK" in (pkt.get("tcp_flags") or [])

    def test_sll_syn_scan_triggers_via_engine(self) -> None:
        cfg = LiveConfig(syn_scan_threshold=3)
        eng = LiveEngine(config=cfg)
        alerts: list[dict] = []
        eng.on_alert = alerts.append

        for port in [80, 443, 8080]:
            pkt = _sll_tcp_syn(dst_port=port, timestamp=1000.0 + port * 0.001)
            assert pkt is not None, f"SLL parse failed for port {port}"
            eng._run_incremental_rules(pkt)

        assert len(alerts) == 1
        assert alerts[0]["rule"] == "detect_tcp_syn_scan"
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["src_ip"] == "127.0.0.1"
        assert alerts[0]["dst_ip"] == "127.0.0.1"

    def test_sll_syn_scan_below_threshold(self) -> None:
        cfg = LiveConfig(syn_scan_threshold=3)
        eng = LiveEngine(config=cfg)
        alerts: list[dict] = []
        eng.on_alert = alerts.append

        for port in [80, 443]:
            pkt = _sll_tcp_syn(dst_port=port, timestamp=1000.0 + port * 0.001)
            assert pkt is not None
            eng._run_incremental_rules(pkt)

        assert len(alerts) == 0


# ── LiveConfig Tests ─────────────────────────────────────────────────────────


class TestLiveConfig:
    def test_defaults(self) -> None:
        cfg = LiveConfig()
        assert cfg.interface is None
        assert cfg.count == 0
        assert cfg.timeout == 30
        assert cfg.bpf_filter == ""
        assert cfg.queue_maxsize == 10000
        assert cfg.syn_scan_threshold == 15
        assert cfg.icmp_flood_threshold == 100.0

    def test_custom_values(self) -> None:
        cfg = LiveConfig(
            interface="eth1",
            count=500,
            timeout=60,
            bpf_filter="tcp or udp",
            syn_scan_threshold=5,
            syn_flood_threshold=500,
        )
        assert cfg.interface == "eth1"
        assert cfg.count == 500
        assert cfg.timeout == 60
        assert cfg.bpf_filter == "tcp or udp"
        assert cfg.syn_scan_threshold == 5
        assert cfg.syn_flood_threshold == 500


# ── LiveEngine Incremental Rule Tests (in isolation, no scapy) ────────────────


def _pkt(
    proto: str = "TCP",
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 40000,
    dst_port: int = 80,
    tcp_flags: list[str] | None = None,
    icmp_type: int | None = None,
    timestamp: float = 1000.0,
) -> DetectionPacket:
    return DetectionPacket(
        index=0,
        timestamp=timestamp,
        src_ip=src,
        dst_ip=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        length=64,
        tcp_flags=tcp_flags or [],
        icmp_type=icmp_type,
    )


class TestLiveEngineRules:
    """Test _run_incremental_rules in isolation by constructing a stopped engine."""

    @pytest.fixture
    def engine(self) -> LiveEngine:
        """A LiveEngine with lowered thresholds for easier testing."""
        cfg = LiveConfig(
            syn_scan_threshold=3,
            udp_scan_threshold=3,
            icmp_sweep_threshold=2,
            icmp_flood_threshold=5,
            syn_flood_threshold=5,
            beacon_min_samples=3,
            beacon_cov_threshold=0.20,
        )
        return LiveEngine(config=cfg)

    @pytest.fixture
    def recording_engine(self, engine: LiveEngine) -> LiveEngine:
        """Engine that records emitted alerts in a list."""
        engine._emitted: list[dict[str, Any]] = []  # type: ignore[attr-defined]

        def _record(a: dict[str, Any]) -> None:
            engine._emitted.append(a)  # type: ignore[attr-defined]

        engine.on_alert = _record
        return engine

    # ── SYN Scan ──

    def test_syn_scan_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        for port in [80, 443, 8080]:
            eng._run_incremental_rules(_pkt(dst_port=port, tcp_flags=["SYN"]))
        assert len(eng._emitted) == 1  # type: ignore[attr-defined]
        alert = eng._emitted[0]  # type: ignore[attr-defined]
        assert alert["rule"] == "detect_tcp_syn_scan"
        assert alert["src_ip"] == "10.0.0.1"
        assert alert["dst_ip"] == "10.0.0.2"

    def test_syn_scan_below_threshold(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        for port in [80, 443]:
            eng._run_incremental_rules(_pkt(dst_port=port, tcp_flags=["SYN"]))
        assert len(eng._emitted) == 0  # type: ignore[attr-defined]

    def test_syn_scan_not_syn_ignored(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        eng._run_incremental_rules(_pkt(dst_port=80, tcp_flags=["SYN", "ACK"]))
        assert len(eng._emitted) == 0  # type: ignore[attr-defined]

    def test_syn_scan_different_dst_separate(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        eng._run_incremental_rules(_pkt(dst_port=80, dst="10.0.0.2", tcp_flags=["SYN"]))
        eng._run_incremental_rules(_pkt(dst_port=443, dst="10.0.0.2", tcp_flags=["SYN"]))
        eng._run_incremental_rules(_pkt(dst_port=8080, dst="10.0.0.2", tcp_flags=["SYN"]))
        eng._run_incremental_rules(_pkt(dst_port=80, dst="10.0.0.3", tcp_flags=["SYN"]))
        eng._run_incremental_rules(_pkt(dst_port=443, dst="10.0.0.3", tcp_flags=["SYN"]))
        # 3 ports to .2, 2 to .3 — only .2 should trigger
        assert len(eng._emitted) == 1  # type: ignore[attr-defined]
        assert eng._emitted[0]["dst_ip"] == "10.0.0.2"  # type: ignore[attr-defined]

    # ── UDP Scan ──

    def test_udp_scan_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        for port in [53, 123, 161]:
            eng._run_incremental_rules(_pkt(proto="UDP", dst_port=port))
        assert len(eng._emitted) == 1  # type: ignore[attr-defined]
        assert eng._emitted[0]["rule"] == "detect_udp_scan"  # type: ignore[attr-defined]

    def test_udp_scan_below_threshold(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        for port in [53, 123]:
            eng._run_incremental_rules(_pkt(proto="UDP", dst_port=port))
        assert len(eng._emitted) == 0  # type: ignore[attr-defined]

    # ── ICMP Sweep ──

    def test_icmp_sweep_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        for target in ["10.0.0.2", "10.0.0.3"]:
            eng._run_incremental_rules(_pkt(proto="ICMP", dst=target, icmp_type=8))
        assert len(eng._emitted) == 1  # type: ignore[attr-defined]
        assert eng._emitted[0]["rule"] == "detect_icmp_sweep"  # type: ignore[attr-defined]

    def test_icmp_sweep_non_echo_ignored(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        eng._run_incremental_rules(_pkt(proto="ICMP", dst="10.0.0.2", icmp_type=3))
        eng._run_incremental_rules(_pkt(proto="ICMP", dst="10.0.0.3", icmp_type=3))
        assert len(eng._emitted) == 0  # type: ignore[attr-defined]

    # ── ICMP Flood ──

    def test_icmp_flood_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        now = 1000.0
        for i in range(6):
            eng._run_incremental_rules(
                _pkt(proto="ICMP", dst="10.0.0.2", icmp_type=8, timestamp=now + i * 0.1)
            )
        alerts = [a for a in eng._emitted if a["rule"] == "detect_icmp_flood"]  # type: ignore[attr-defined]
        assert len(alerts) >= 1

    # ── TCP SYN Flood ──

    def test_syn_flood_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        now = 1000.0
        for i in range(6):
            eng._run_incremental_rules(
                _pkt(dst_port=80, tcp_flags=["SYN"], timestamp=now + i * 0.1)
            )
        alerts = [a for a in eng._emitted if a["rule"] == "detect_tcp_syn_flood"]  # type: ignore[attr-defined]
        assert len(alerts) >= 1

    # ── Beaconing ──

    def test_beaconing_triggers(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        now = 1000.0
        for i in range(4):
            eng._run_incremental_rules(
                _pkt(src="192.168.1.1", dst="8.8.8.8", timestamp=now + i * 10.0)
            )
        alerts = [a for a in eng._emitted if a["rule"] == "detect_beaconing"]  # type: ignore[attr-defined]
        assert len(alerts) >= 1
        assert alerts[0]["evidence"]["cov"] < 0.20

    def test_beaconing_below_min_samples(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8"))
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8"))
        alerts = [a for a in eng._emitted if a["rule"] == "detect_beaconing"]  # type: ignore[attr-defined]
        assert len(alerts) == 0

    def test_beaconing_irregular_no_alert(self, recording_engine: LiveEngine) -> None:
        eng = recording_engine
        now = 1000.0
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8", timestamp=now))
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8", timestamp=now + 1.0))
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8", timestamp=now + 30.0))
        eng._run_incremental_rules(_pkt(src="192.168.1.1", dst="8.8.8.8", timestamp=now + 60.0))
        alerts = [a for a in eng._emitted if a["rule"] == "detect_beaconing"]  # type: ignore[attr-defined]
        assert len(alerts) == 0

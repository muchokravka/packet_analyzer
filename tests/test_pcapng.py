from __future__ import annotations

import struct
from pathlib import Path

import pytest

from packet_analyzer.pcapng import parse_pcapng


def _pcapng_block(block_type: int, body: bytes, endian: str) -> bytes:
    """Wrap *body* in a PCAPNG block header/footer."""
    padding = (4 - (len(body) % 4)) % 4
    padded_body = body + b"\x00" * padding
    total_len = 8 + len(padded_body) + 4
    header = struct.pack(endian + "II", block_type, total_len)
    trailer = struct.pack(endian + "I", total_len)
    return header + padded_body + trailer


def _shb(endian: str) -> bytes:
    """Build Section Header Block."""
    bom_bytes = struct.pack(endian + "I", 0x1A2B3C4D)
    body = bom_bytes  # BOM (4)
    body += struct.pack(endian + "HH", 1, 0)  # version major=1, minor=0
    body += struct.pack(endian + "q", -1)  # section length = unspecified (-1)
    return _pcapng_block(0x0A0D0D0A, body, endian)


def _idb(link_type: int, endian: str, ts_resol: int | None = None) -> bytes:
    """Build Interface Description Block."""
    body = struct.pack(endian + "HHI", link_type, 0, 65535)
    if ts_resol is not None:
        # option: if_tsresol (code 9)
        opt_body = bytes([ts_resol])
        opt_len = len(opt_body)
        opt_code = 9
        option = struct.pack(endian + "HH", opt_code, opt_len) + opt_body
        # Pad option to 32-bit
        if len(option) % 4:
            option += b"\x00" * (4 - (len(option) % 4))
        body += option
    # End-of-options
    body += struct.pack(endian + "HH", 0, 0)
    return _pcapng_block(0x00000001, body, endian)


def _epb(packet_data: bytes, ts_high: int, ts_low: int, endian: str) -> bytes:
    """Build Enhanced Packet Block."""
    body = struct.pack(endian + "I", 0)  # interface_id = 0
    body += struct.pack(endian + "II", ts_high, ts_low)
    body += struct.pack(endian + "II", len(packet_data), len(packet_data))
    body += packet_data
    return _pcapng_block(0x00000006, body, endian)


def _write_pcapng(path: Path, blocks: list[bytes]) -> None:
    with path.open("wb") as f:
        for block in blocks:
            f.write(block)


def _make_pcap(ts_sec: int, ts_usec: int, payload: bytes, link_type: int = 1, endian: str = "<") -> bytes:
    """Build a minimal valid pcapng file with one EPB."""
    ts_total = ts_sec * 1_000_000 + ts_usec
    ts_high = ts_total >> 32
    ts_low = ts_total & 0xFFFFFFFF
    blocks = [
        _shb(endian),
        _idb(link_type, endian),
        _epb(payload, ts_high, ts_low, endian),
    ]
    return b"".join(blocks)


# ── Tests ──────────────────────────────────────────────────────────────────


def test_parse_single_epb(tmp_path: Path) -> None:
    data = _make_pcap(1_700_000_000, 500_000, b"hello pcapng")
    p = tmp_path / "test.pcapng"
    p.write_bytes(data)

    packets, endian, link_type = parse_pcapng(p)
    assert len(packets) == 1
    ts_sec, ts_usec, payload, orig_len = packets[0]
    assert ts_sec == 1_700_000_000
    assert ts_usec == 500_000
    assert payload == b"hello pcapng"
    assert orig_len == len(b"hello pcapng")
    assert link_type == 1  # Ethernet
    assert endian == "<"


def test_parse_big_endian(tmp_path: Path) -> None:
    data = _make_pcap(1_700_000_001, 0, b"big-endian test", endian=">")
    p = tmp_path / "big.pcapng"
    p.write_bytes(data)

    packets, endian, link_type = parse_pcapng(p)
    assert len(packets) == 1
    assert packets[0][0] == 1_700_000_001
    assert packets[0][2] == b"big-endian test"
    assert endian == ">"


def test_parse_multi_epb(tmp_path: Path) -> None:
    blocks = [
        _shb("<"),
        _idb(1, "<"),
        _epb(b"packet1", 0, 0, "<"),
        _epb(b"packet2", 0, 1, "<"),
        _epb(b"packet3", 0, 2, "<"),
    ]
    p = tmp_path / "multi.pcapng"
    _write_pcapng(p, blocks)

    packets, _, _ = parse_pcapng(p)
    assert len(packets) == 3
    assert [pkt[2] for pkt in packets] == [b"packet1", b"packet2", b"packet3"]


def test_parse_nondefault_linktype(tmp_path: Path) -> None:
    data = _make_pcap(0, 0, b"\x45\x00\x00\x14", link_type=101)  # RAW
    p = tmp_path / "raw.pcapng"
    p.write_bytes(data)

    _, _, link_type = parse_pcapng(p)
    assert link_type == 101


def test_truncated_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "truncated.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a")  # just the magic

    with pytest.raises(ValueError, match="No packets found"):
        parse_pcapng(p)


def test_empty_file_raises(tmp_path: Path) -> None:
    p = tmp_path / "empty.pcapng"
    p.write_bytes(b"")

    with pytest.raises(ValueError, match="Empty pcapng file"):
        parse_pcapng(p)


def test_epb_with_options_preserves_data(tmp_path: Path) -> None:
    """EPB with trailing options should still parse payload correctly."""
    body = struct.pack("<I", 0)  # interface_id
    body += struct.pack("<II", 0, 1000)  # ts_high, ts_low
    body += struct.pack("<II", 4, 4)  # cap_len, orig_len
    body += b"DATA"
    # option: end of options
    body += struct.pack("<HH", 0, 0)
    block = _pcapng_block(0x00000006, body, "<")
    blocks = [_shb("<"), _idb(1, "<"), block]
    p = tmp_path / "opts.pcapng"
    _write_pcapng(p, blocks)

    packets, _, _ = parse_pcapng(p)
    assert len(packets) == 1
    assert packets[0][2] == b"DATA"

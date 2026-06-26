from __future__ import annotations

import os
import struct
from pathlib import Path

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
SHB_BLOCK_TYPE = 0x0A0D0D0A
IDB_BLOCK_TYPE = 0x00000001
EPB_BLOCK_TYPE = 0x00000006
SPB_BLOCK_TYPE = 0x00000003
BOM_CANONICAL = 0x1A2B3C4D


def _detect_endian(data: bytes) -> str:
    """Detect endianness from SHB Byte-Order Magic at offset 8."""
    bom_le = struct.unpack("<I", data[8:12])[0]
    return "<" if bom_le == BOM_CANONICAL else ">"


def _block_type_raw(block_type: int, endian: str) -> bytes:
    return struct.pack(endian + "I", block_type)


def parse_pcapng(path: Path) -> tuple[list[tuple[int, int, bytes, int]], str, int]:
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size == 0:
            raise ValueError("Empty pcapng file")
        os.lseek(fd, 0, os.SEEK_SET)
        import mmap

        with mmap.mmap(fd, size, access=mmap.ACCESS_READ) as mem:
            return _parse_pcapng_mem(mem)
    finally:
        os.close(fd)


def _parse_pcapng_mem(mem) -> tuple[list[tuple[int, int, bytes, int]], str, int]:
    packets: list[tuple[int, int, bytes, int]] = []
    endian = "<"
    link_type = 1
    ts_resol = 6
    offset = 0

    while offset + 8 <= len(mem):
        block_type_raw = bytes(mem[offset : offset + 4])

        if block_type_raw == PCAPNG_MAGIC:
            # ── Section Header Block ──────────────────────────────────────
            if offset + 12 > len(mem):
                break
            # Detect endianness before reading further
            endian = _detect_endian(mem[offset : offset + 12])
            block_len = struct.unpack(endian + "I", mem[offset + 4 : offset + 8])[0]
            if block_len < 28 or block_len > len(mem) - offset:
                raise ValueError(f"Invalid SHB block length at offset {offset}")
            # Verify BOM matches detected endianness
            bom = struct.unpack(endian + "I", mem[offset + 8 : offset + 12])[0]
            if bom != BOM_CANONICAL:
                raise ValueError("PCAPNG byte order magic mismatch")
            offset += block_len
            continue

        end = offset + 8
        if end > len(mem):
            break

        # Try reading block_total_len with current endianness
        block_len = struct.unpack(endian + "I", mem[offset + 4 : offset + 8])[0]
        if block_len < 12 or block_len > len(mem) - offset:
            # Invalid length — try other endianness
            other_endian = ">" if endian == "<" else "<"
            block_len = struct.unpack(other_endian + "I", mem[offset + 4 : offset + 8])[0]
            if 12 <= block_len <= len(mem) - offset:
                endian = other_endian

        # ── Interface Description Block ───────────────────────────────────
        if block_type_raw == _block_type_raw(IDB_BLOCK_TYPE, endian):
            if block_len < 20:
                offset += block_len
                continue
            link_type = struct.unpack(endian + "H", mem[offset + 8 : offset + 10])[0]
            _snap_len = struct.unpack(endian + "I", mem[offset + 12 : offset + 16])[0]
            # Parse IDB options for timestamp resolution
            opt_offset = offset + 16
            opt_end = offset + block_len - 4
            while opt_offset + 4 <= opt_end:
                opt_code = struct.unpack(endian + "H", mem[opt_offset : opt_offset + 2])[0]
                opt_len = struct.unpack(endian + "H", mem[opt_offset + 2 : opt_offset + 4])[0]
                if opt_code == 0:
                    break
                if opt_code == 9 and opt_len >= 1:
                    ts_val = mem[opt_offset + 4]
                    if ts_val & 0x80:
                        ts_resol = -(ts_val & 0x7F)
                    else:
                        ts_resol = ts_val & 0x7F
                aligned = 4 + ((opt_len + 3) & ~3)
                opt_offset += aligned
            offset += block_len
            continue

        # ── Enhanced Packet Block ─────────────────────────────────────────
        if block_type_raw == _block_type_raw(EPB_BLOCK_TYPE, endian):
            if block_len < 32:
                offset += block_len
                continue
            _intf_id = struct.unpack(endian + "I", mem[offset + 8 : offset + 12])[0]
            ts_high = struct.unpack(endian + "I", mem[offset + 12 : offset + 16])[0]
            ts_low = struct.unpack(endian + "I", mem[offset + 16 : offset + 20])[0]
            cap_len = struct.unpack(endian + "I", mem[offset + 20 : offset + 24])[0]
            orig_len = struct.unpack(endian + "I", mem[offset + 24 : offset + 28])[0]

            ts_sec, ts_usec = _epb_timestamp(ts_high, ts_low, ts_resol)

            data_start = offset + 28
            if data_start + cap_len > len(mem):
                break
            packet_data = bytes(mem[data_start : data_start + cap_len])
            packets.append((ts_sec, ts_usec, packet_data, orig_len))
            offset += block_len
            continue

        # ── Simple Packet Block ────────────────────────────────────────────
        if block_type_raw == _block_type_raw(SPB_BLOCK_TYPE, endian):
            if block_len < 16:
                offset += block_len
                continue
            orig_len = struct.unpack(endian + "I", mem[offset + 8 : offset + 12])[0]
            cap_len = block_len - 16
            data_start = offset + 12
            if cap_len > 0 and data_start + cap_len <= len(mem):
                packet_data = bytes(mem[data_start : data_start + cap_len])
                packets.append((0, 0, packet_data, orig_len))
            offset += block_len
            continue

        # ── Unknown block: skip ────────────────────────────────────────────
        if block_len <= 0:
            break
        offset += block_len

    if not packets:
        raise ValueError("No packets found in pcapng file")

    return packets, endian, link_type


def _epb_timestamp(ts_high: int, ts_low: int, ts_resol: int) -> tuple[int, int]:
    total = (ts_high << 32) | ts_low
    if ts_resol > 0:
        factor = 10**ts_resol
        sec = total // factor
        rem = total % factor
        usec = rem * 1_000_000 // factor
    else:
        factor = 2 ** (-ts_resol)
        sec = total // factor
        rem = total % factor
        usec = rem * 1_000_000 // factor
    return sec, usec

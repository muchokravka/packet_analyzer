from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packet_analyzer import live as live_module


def _make_mock_packet(data: bytes, time_val: float | None = None) -> MagicMock:
    pkt = MagicMock()
    pkt.__bytes__ = MagicMock(return_value=data)
    pkt.time = time_val or time.time()
    return pkt


def test_capture_live_empty() -> None:
    """No packets captured returns an empty result (not a crash)."""
    with patch.object(live_module, "_import_scapy") as mock_import:
        scapy_mock = MagicMock()
        scapy_mock.sniff = MagicMock()
        mock_import.return_value = scapy_mock

        result = live_module.capture_live(count=0, timeout=1)
        assert result["summary"]["packet_count"] == 0
        assert result["flows"] == []
        assert result["packets"] == []


def test_capture_live_calls_sniff() -> None:
    with patch.object(live_module, "_import_scapy") as mock_import:
        scapy_mock = MagicMock()

        collected: list[bytes] = []

        def fake_sniff(iface=None, prn=None, count=100, timeout=30, store=False):
            for _ in range(3):
                pkt = _make_mock_packet(b"\x00" * 64)
                prn(pkt)

        scapy_mock.sniff = fake_sniff
        mock_import.return_value = scapy_mock
        collected = []

        orig_build = live_module._build_result

        def fake_build(packets_raw, endian, link_type, path, **kw):
            nonlocal collected
            collected = packets_raw
            return orig_build(packets_raw, endian, link_type, path, **kw)

        with patch.object(live_module, "_build_result", fake_build):
            result = live_module.capture_live(count=3, timeout=2)

        assert result["summary"]["packet_count"] == 3
        assert len(collected) == 3


def test_capture_live_passes_interface() -> None:
    with patch.object(live_module, "_import_scapy") as mock_import:
        scapy_mock = MagicMock()
        captured_iface: list[str | None] = []

        def fake_sniff(iface=None, prn=None, count=100, timeout=30, store=False):
            captured_iface.append(iface)
            for _ in range(2):
                prn(_make_mock_packet(b"\x00" * 64))

        scapy_mock.sniff = fake_sniff
        mock_import.return_value = scapy_mock

        with patch.object(live_module, "_build_result") as mock_build:
            mock_build.return_value = {
                "alerts": [],
                "prompt_guidance": {},
                "summary": {"packet_count": 2, "duration_sec": 1.0},
                "flows": [],
                "packets": [],
            }
            live_module.capture_live(interface="eth0", count=2, timeout=1)

        assert captured_iface == ["eth0"]


def test_list_interfaces() -> None:
    with patch.object(live_module, "_import_scapy") as mock_import:
        scapy_mock = MagicMock()
        scapy_mock.get_if_list = MagicMock(return_value=["eth0", "lo", "wlan0"])
        mock_import.return_value = scapy_mock

        ifaces = live_module.list_interfaces()
        assert ifaces == ["eth0", "lo", "wlan0"]


def test_import_scapy_missing() -> None:
    with patch("builtins.__import__", side_effect=ImportError("no scapy")):
        # Force reimport by clearing cache
        if "packet_analyzer.live" in list(live_module.__dict__.keys()):
            pass
        with pytest.raises(ImportError, match="scapy is required"):
            live_module._import_scapy()

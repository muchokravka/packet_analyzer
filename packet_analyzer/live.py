from __future__ import annotations

import time
from typing import Any

from .analyzer import _build_result

LINKTYPE_ETHERNET = 1


def capture_live(
    *,
    interface: str | None = None,
    count: int = 100,
    timeout: int | None = 30,
    packet_output_limit: int | None = 5000,
) -> dict[str, Any]:
    """Capture live packets from a network interface and analyze them.

    Parameters
    ----------
    interface : str or None
        Network interface name (e.g. "eth0", "lo"). None = default.
    count : int
        Number of packets to capture (0 = unlimited until timeout).
    timeout : int or None
        Capture duration in seconds (None = no timeout).
    packet_output_limit : int or None
        Max packet records in output.

    Returns
    -------
    Same dict shape as analyze_pcap().
    """
    scapy = _import_scapy()

    captured: list[bytes] = []
    start_time = time.time()

    def _sniff_callback(pkt: Any) -> None:
        captured.append(bytes(pkt))

    scapy.sniff(
        iface=interface,
        prn=_sniff_callback,
        count=count,
        timeout=timeout,
        store=False,
    )

    elapsed = time.time() - start_time

    if not captured:
        return {
            "alerts": [],
            "prompt_guidance": {
                "task": "Analyze this network capture",
                "focus_areas": [],
                "safety_context": "",
            },
            "summary": {
                "file": f"live:{interface or 'default'}",
                "file_name": f"live-{interface or 'default'}",
                "packet_count": 0,
                "duration_sec": elapsed,
                "start_ts": start_time,
                "end_ts": time.time(),
                "captured_frame_bytes": 0,
                "payload_bytes": 0,
                "packets_per_sec": 0.0,
                "protocol_counts": {},
                "unique_sources": 0,
                "unique_destinations": 0,
                "unique_flows": 0,
                "packets_output_count": 0,
                "packets_truncated": False,
                "top_talkers": [],
                "top_destinations": [],
                "top_tcp_ports": [],
                "top_udp_ports": [],
                "dns_top_queries": [],
                "http_first_lines_sample": [],
                "indicator_counts": {},
                "pcap_format": {
                    "byte_order": "native",
                    "link_type": LINKTYPE_ETHERNET,
                    "link_layer": "Ethernet",
                    "supported_linktype": True,
                },
                "unsupported_or_truncated_packets": 0,
                "icmp_hidden_texts": {},
            },
            "flows": [],
            "packets": [],
        }

    now = int(time.time())
    packets_raw = [(now, 0, raw, LINKTYPE_ETHERNET) for raw in captured]

    from pathlib import Path
    path = Path(f"live:{interface or 'default'}")

    return _build_result(
        packets_raw, "<", LINKTYPE_ETHERNET, path,
        include_payload_b64=True,
        max_payload_b64_bytes=256,
        packet_output_limit=packet_output_limit,
    )


def list_interfaces() -> list[str]:
    """List available network interfaces (requires scapy)."""
    scapy = _import_scapy()
    return scapy.get_if_list()


def _import_scapy():
    """Lazy-import scapy with a helpful error message."""
    try:
        import scapy.all as scapy
        return scapy
    except ImportError:
        raise ImportError(
            "scapy is required for live capture. Install it with: pip install scapy"
        )

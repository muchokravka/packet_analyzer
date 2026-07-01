from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .analyzer import _build_result
from .utils import ProgressCallback

LINKTYPE_ETHERNET = 1


def capture_live(
    *,
    interface: str | None = None,
    count: int = 100,
    timeout: int | None = 30,
    packet_output_limit: int | None = 5000,
    engine: str = "scapy",
    bpf_filter: str = "",
    progress: ProgressCallback | None = None,
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
    engine : str
        Capture backend: "scapy" (default), "tcpdump", or "producer-consumer".
    bpf_filter : str
        BPF filter expression for kernel-level filtering.
    progress : ProgressCallback or None
        Optional progress callback for stages during analysis.

    Returns
    -------
    Same dict shape as analyze_pcap().
    """
    if interface is None:
        import scapy.all as _scapy
        default = _scapy.conf.iface.name
        import sys
        print(
            f"[live] no --interface specified; using \"{default}\". "
            f"Use --interface lo to capture localhost traffic.",
            file=sys.stderr,
        )

    if engine == "tcpdump":
        return _capture_tcpdump(interface=interface, count=count, timeout=timeout, packet_output_limit=packet_output_limit, progress=progress)

    if engine == "producer-consumer":
        return _capture_producer_consumer(
            interface=interface, count=count, timeout=timeout,
            packet_output_limit=packet_output_limit, bpf_filter=bpf_filter,
        )

    return _capture_scapy(interface=interface, count=count, timeout=timeout, packet_output_limit=packet_output_limit, progress=progress)


def _capture_scapy(
    *,
    interface: str | None = None,
    count: int = 100,
    timeout: int | None = 30,
    packet_output_limit: int | None = 5000,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    scapy = _import_scapy()
    scapy_count: int | None = count if count > 0 else None
    captured: list[bytes] = []
    link_type: int = LINKTYPE_ETHERNET
    start_time = time.time()

    def _sniff_callback(pkt: Any) -> None:
        nonlocal link_type
        if len(captured) == 0:
            from .live_engine import _detect_link_type
            link_type = _detect_link_type(pkt)
        captured.append(bytes(pkt))

    scapy.sniff(
        iface=interface,
        prn=_sniff_callback,
        count=scapy_count,
        timeout=timeout,
        store=False,
    )

    elapsed = time.time() - start_time

    if not captured:
        return _empty_result(interface, elapsed)

    now = int(time.time())
    packets_raw = [(now, 0, raw, link_type) for raw in captured]
    path = Path(f"live:{interface or 'default'}")

    return _build_result(
        packets_raw, "<", link_type, path,
        include_payload_b64=True,
        max_payload_b64_bytes=256,
        packet_output_limit=packet_output_limit,
        progress=progress,
    )


def _capture_tcpdump(
    *,
    interface: str | None = None,
    count: int = 100,
    timeout: int | None = 30,
    packet_output_limit: int | None = 5000,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Capture live packets using tcpdump (more portable, no scapy dep)."""
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump not found. Install it or use --live-engine scapy.")

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    tmp_path = Path(tmp.name)

    try:
        cmd = ["tcpdump", "-i", interface or "any", "-w", str(tmp_path), "-nn"]
        if count > 0:
            cmd += ["-c", str(count)]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()

        if not tmp_path.exists() or tmp_path.stat().st_size == 0:
            return _empty_result(interface, timeout or 0)

        from .analyzer import analyze_pcap as _analyze_file
        result = _analyze_file(
            tmp_path,
            include_payload_b64=True,
            max_payload_b64_bytes=256,
            packet_output_limit=packet_output_limit,
            progress=progress,
        )
        result["summary"]["file"] = f"live:{interface or 'default'}"
        result["summary"]["file_name"] = f"live-{interface or 'default'}"
        return result
    finally:
        tmp_path.unlink(missing_ok=True)


def _empty_result(interface: str | None, elapsed: float) -> dict[str, Any]:
    return {
        "alerts": [],
        "prompt_guidance": {"task": "Analyze this network capture", "focus_areas": [], "safety_context": ""},
        "summary": {
            "file": f"live:{interface or 'default'}",
            "file_name": f"live-{interface or 'default'}",
            "packet_count": 0,
            "duration_sec": elapsed,
            "start_ts": time.time() - elapsed,
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
            "pcap_format": {"byte_order": "native", "link_type": LINKTYPE_ETHERNET, "link_layer": "Ethernet", "supported_linktype": True},
            "unsupported_or_truncated_packets": 0,
            "icmp_hidden_texts": {},
        },
        "flows": [],
        "packets": [],
    }


def list_interfaces() -> list[str]:
    """List available network interfaces (requires scapy)."""
    scapy = _import_scapy()
    return scapy.get_if_list()


def _capture_producer_consumer(
    *,
    interface: str | None = None,
    count: int = 0,
    timeout: float | None = 30,
    packet_output_limit: int | None = 5000,
    bpf_filter: str = "",
) -> dict[str, Any]:
    """Capture using the producer-consumer engine with sliding-window rules.

    This engine uses two threads:
      - Producer: scapy.sniff(store=False, prn=enqueue) — lightweight
      - Consumer: parses L2-L4, runs incremental detection rules, emits alerts

    Returns a result dict compatible with analyze_pcap().
    """
    from .live_engine import LiveConfig, LiveEngine

    alerts: list[dict[str, Any]] = []
    config = LiveConfig(
        interface=interface,
        count=count,
        timeout=timeout,
        bpf_filter=bpf_filter,
        packet_output_limit=packet_output_limit,
    )
    engine = LiveEngine(config=config, on_alert=lambda a: alerts.append(a))
    start_ts = time.time()
    engine.start()

    # Block until the capture finishes (timeout, count, or interrupt)
    try:
        if engine._producer:
            engine._producer.join()
    except KeyboardInterrupt:
        pass
    finally:
        stats = engine.stop()
    elapsed = time.time() - start_ts

    result = {
        "alerts": alerts,
        "prompt_guidance": {
            "task": "Analyze this live network capture",
            "focus_areas": ["Real-time detection", "Live alert correlation"],
            "safety_context": "",
        },
        "summary": {
            "file": f"live:{interface or 'default'}",
            "file_name": f"live-{interface or 'default'}",
            "packet_count": stats["packets_consumed"],
            "duration_sec": round(elapsed, 3),
            "start_ts": start_ts,
            "end_ts": time.time(),
            "captured_frame_bytes": 0,
            "payload_bytes": 0,
            "packets_per_sec": stats["packets_per_sec"],
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
                "link_type": 1,
                "link_layer": "Ethernet",
                "supported_linktype": True,
            },
            "unsupported_or_truncated_packets": 0,
            "icmp_hidden_texts": {},
        },
        "flows": [],
        "packets": [],
    }

    if alerts:
        severity_counts: dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        result["summary"]["indicator_counts"] = severity_counts

    return result


def _import_scapy():
    """Lazy-import scapy with a helpful error message."""
    try:
        import scapy.all as scapy
        return scapy
    except ImportError:
        raise ImportError("scapy is required for live capture. Install it with: pip install scapy")

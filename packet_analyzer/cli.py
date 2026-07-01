from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import detections
from .analyzer import analyze_pcap, render_ai_prompt, render_json, render_jsonl, stream_jsonl
from .compare import compare_pcaps, render_diff_text
from .detections import build_incident_timelines
from .formats import render_csv, render_csv_flows
from .utils import ProgressCallback, add_local_network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packet-analyzer", description="Parse PCAP and export AI-ready structured data")
    parser.add_argument("pcap", type=Path, nargs="?", help="Path to input .pcap file")
    parser.add_argument("-o", "--output", type=Path, default=Path("analysis.json"), help="Output file path")
    parser.add_argument(
        "--format",
        choices=("json", "jsonl", "csv"),
        default="json",
        help="Output format (json, jsonl, csv)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Optional hard cap of packets to process",
    )
    parser.add_argument(
        "--no-payload-b64",
        action="store_true",
        help="Skip base64 payload excerpts in packet records",
    )
    parser.add_argument(
        "--payload-b64-bytes",
        type=int,
        default=256,
        help="Maximum payload bytes to base64 encode per packet",
    )
    parser.add_argument(
        "--packet-output-limit",
        type=int,
        default=5000,
        help="Maximum number of packet records to include in JSON/JSONL output",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact JSON output (no pretty indentation)",
    )
    parser.add_argument(
        "--conversations-only",
        action="store_true",
        help="Only output flow/conversation records (omit per-packet details)",
    )
    parser.add_argument(
        "--prompt-output",
        type=Path,
        default=None,
        help="Optional path to write an LLM-ready analysis prompt text",
    )
    parser.add_argument(
        "--prompt-max-flows",
        type=int,
        default=20,
        help="Maximum number of flow records embedded in generated prompt",
    )
    parser.add_argument(
        "--prompt-max-packets",
        type=int,
        default=30,
        help="Maximum number of packet records embedded in generated prompt",
    )
    parser.add_argument(
        "--wireshark-export",
        type=Path,
        default=None,
        help="Optional path to write a full Wireshark decode (tshark -T json)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        help="Minimum alert severity to include: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )
    parser.add_argument(
        "--rules",
        action="store_true",
        help="List available detection rules and exit",
    )
    parser.add_argument(
        "--filter-ip",
        type=str,
        default=None,
        help="Only include packets matching this IP (source or destination)",
    )
    parser.add_argument(
        "--filter-proto",
        type=str,
        default=None,
        help="Only include packets matching this protocol (e.g. HTTP, DNS, TLS, TCP, UDP, ICMP)",
    )
    parser.add_argument(
        "--diff",
        type=Path,
        default=None,
        help="Compare with a second PCAP file and show differences",
    )
    parser.add_argument(
        "--diff-output",
        type=Path,
        default=None,
        help="Write structured diff JSON to this file",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream JSONL output to stdout (requires --format jsonl)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live from a network interface instead of reading a PCAP file",
    )
    parser.add_argument(
        "--live-engine",
        choices=("scapy", "tcpdump", "producer-consumer"),
        default="scapy",
        help="Capture backend for --live (default: scapy). producer-consumer uses "
             "a threaded producer-consumer pipeline with streaming sliding-window rules",
    )
    parser.add_argument(
        "--bpf-filter",
        type=str,
        default="",
        help="BPF filter expression for kernel-level filtering (e.g. 'tcp or udp'). "
             "Packets not matching are dropped at the NIC level before Python touches them.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit (requires scapy)",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface for live capture (e.g. eth0, lo). Default: scapy chooses",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to capture in live mode (0 = unlimited)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Live capture duration in seconds",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress and summary output to stderr/stdout",
    )
    parser.add_argument(
        "--local-net",
        action="append",
        default=[],
        dest="local_nets",
        help="Additional local network CIDR (repeatable, e.g. --local-net 192.168.63.0/24). "
             "Traffic within these ranges is classified as internal/lateral.",
    )
    return parser


def _filter_alerts(alerts: list[dict[str, Any]], severity: str | None) -> list[dict[str, Any]]:
    if severity is None:
        return alerts
    threshold = detections.SEVERITY_ORDER.get(severity.upper())
    if threshold is None:
        raise SystemExit("Invalid severity. Use one of: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    return [
        alert for alert in alerts
        if detections.SEVERITY_ORDER.get(alert.get("severity", "INFO"), 1) >= threshold
    ]


def _filter_packets(packets: list[dict[str, Any]], *, filter_ip: str | None, filter_proto: str | None) -> list[dict[str, Any]]:
    filtered = packets
    if filter_ip:
        filtered = [p for p in filtered if p.get("src_ip") == filter_ip or p.get("dst_ip") == filter_ip]
    if filter_proto:
        filtered = [p for p in filtered if (p.get("protocol") or "").upper() == filter_proto.upper()]
    return filtered


def _make_progress_callback(quiet: bool) -> ProgressCallback | None:
    """Return a progress callback if *quiet* is False, else None."""
    if quiet:
        return None

    last_stage: list[str] = [""]
    def _cb(stage: str, current: int | None, total: int | None) -> None:
        if stage == "reading":
            if last_stage[0] != "reading":
                last_stage[0] = "reading"
                print("[*] Reading PCAP file...", file=sys.stderr)
        elif stage == "analyzing" and current is not None and total is not None:
            if last_stage[0] != "analyzing":
                last_stage[0] = "analyzing"
                print(f"[*] Analyzing packets: 0/{total} (0%)", file=sys.stderr, end="")
            pct = current / total * 100 if total > 0 else 0
            print(f"\r[*] Analyzing packets: {current}/{total} ({pct:.0f}%)", file=sys.stderr, end="")
            if current == total:
                print(file=sys.stderr)
        elif stage == "detections":
            if last_stage[0] != "detections":
                last_stage[0] = "detections"
                print("[*] Running detection rules...", file=sys.stderr)
        elif stage == "writing":
            if last_stage[0] != "writing":
                last_stage[0] = "writing"
                print("[*] Writing output...", file=sys.stderr)
    return _cb


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    progress = _make_progress_callback(args.quiet)

    for net in args.local_nets:
        add_local_network(net)

    if args.rules:
        for name in detections.list_rules():
            print(name)
        return 0

    if args.list_interfaces:
        from .live import list_interfaces
        for iface in list_interfaces():
            print(iface)
        return 0

    if args.live:
        if args.pcap is not None:
            print("warning: --live ignores the PCAP positional argument", file=sys.stderr)
        from .live import capture_live
        result = capture_live(
            interface=args.interface,
            count=args.count,
            timeout=args.timeout,
            engine=args.live_engine,
            bpf_filter=args.bpf_filter,
            packet_output_limit=args.packet_output_limit,
            progress=progress,
        )
    elif args.pcap is None:
        parser.print_help()
        return 1
    else:
        result = analyze_pcap(
        args.pcap,
        max_packets=args.max_packets,
        include_payload_b64=not args.no_payload_b64,
        max_payload_b64_bytes=args.payload_b64_bytes,
        packet_output_limit=args.packet_output_limit,
        progress=progress,
    )

    # Apply CLI-level filters
    if args.filter_ip or args.filter_proto:
        result["packets"] = _filter_packets(result["packets"], filter_ip=args.filter_ip, filter_proto=args.filter_proto)
        result["alerts"] = _filter_alerts(result["alerts"], args.severity)
    else:
        result["alerts"] = _filter_alerts(result["alerts"], args.severity)

    if args.conversations_only:
        result.pop("packets", None)

    # Incident timeline correlation
    incidents = build_incident_timelines(result.get("alerts", []))
    result["incident_timelines"] = incidents

    # Diff mode
    if args.diff is not None:
        result_b = analyze_pcap(
            args.diff,
            max_packets=args.max_packets,
            include_payload_b64=not args.no_payload_b64,
            max_payload_b64_bytes=args.payload_b64_bytes,
            packet_output_limit=args.packet_output_limit,
            progress=progress,
        )
        diff = compare_pcaps(result, result_b)
        diff_text = render_diff_text(diff)
        print(diff_text)
        if args.diff_output is not None:
            import json
            args.diff_output.write_text(
                json.dumps(diff, indent=2, default=str), encoding="utf-8"
            )
            print(f"Wrote structured diff to {args.diff_output}")
        return 0

    # Stream mode
    if args.stream:
        if args.format != "jsonl":
            raise SystemExit("--stream requires --format jsonl")
        import sys
        stream_jsonl(result, sys.stdout)
        # Still print summary to stderr so streaming output is clean
        import sys
        print(detections.render_alerts(result.get("alerts", [])), file=sys.stderr)
        sm = result["summary"]
        print(
            f"Streamed {args.format.upper()} to stdout "
            f"(packets={sm['packet_count']}, flows={sm['unique_flows']}, duration={sm['duration_sec']:.3f}s)",
            file=sys.stderr,
        )
        return 0

    # Render output
    if progress:
        progress("writing", None, None)

    if args.format == "jsonl":
        rendered = render_jsonl(result)
    elif args.format == "csv":
        if args.conversations_only:
            rendered = render_csv_flows(result)
        else:
            rendered = render_csv(result)
    else:
        rendered = render_json(result, pretty=not args.compact)

    args.output.write_text(rendered, encoding="utf-8")

    # Optional prompt export
    if args.prompt_output is not None:
        prompt = render_ai_prompt(result, max_flows=args.prompt_max_flows, max_packets=args.prompt_max_packets)
        args.prompt_output.write_text(prompt, encoding="utf-8")

    # Optional Wireshark export
    if args.wireshark_export is not None:
        tshark = shutil.which("tshark")
        if tshark is None:
            raise SystemExit("tshark not found. Install Wireshark or tshark to enable --wireshark-export.")
        command = [tshark, "-r", str(args.pcap), "-T", "json"]
        try:
            with args.wireshark_export.open("wb") as handle:
                subprocess.run(command, check=True, stdout=handle, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            message = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else "tshark failed"
            raise SystemExit(message) from exc

    if args.quiet:
        return 0

    # Print summary to stdout
    alerts = result.get("alerts", [])
    print(detections.render_alerts(alerts))

    incidents = result.get("incident_timelines", [])
    if incidents:
        print(f"Incident timelines: {len(incidents)} multi-stage incident(s) detected")
        for inc in incidents:
            print(f"  {inc['incident_id']}: {inc['description']}")

    summary = result["summary"]
    print(
        f"Wrote {args.format.upper()} analysis to {args.output} "
        f"(packets={summary['packet_count']}, flows={summary['unique_flows']}, duration={summary['duration_sec']:.3f}s)"
    )

    # Protocol distribution
    protocols = summary.get("protocol_counts", {})
    total = sum(protocols.values())
    if total:
        parts: list[str] = []
        for proto, count in sorted(protocols.items(), key=lambda item: item[1], reverse=True):
            pct = (count / total) * 100
            parts.append(f"{proto}(<1%)" if pct < 1 else f"{proto}({pct:.0f}%)")
        print(f"  Protocols: {' '.join(parts)}")

    if args.prompt_output is not None:
        print(f"Wrote prompt file to {args.prompt_output}")
    if args.wireshark_export is not None:
        print(f"Wrote Wireshark decode to {args.wireshark_export}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

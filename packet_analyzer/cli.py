from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from .analyzer import analyze_pcap, render_ai_prompt, render_json, render_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packet-analyzer", description="Parse PCAP and export AI-ready structured data")
    parser.add_argument("pcap", type=Path, help="Path to input .pcap file")
    parser.add_argument("-o", "--output", type=Path, default=Path("analysis.json"), help="Output file path")
    parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
        help="Output format for AI ingestion",
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    result = analyze_pcap(
        args.pcap,
        max_packets=args.max_packets,
        include_payload_b64=not args.no_payload_b64,
        max_payload_b64_bytes=args.payload_b64_bytes,
        packet_output_limit=args.packet_output_limit,
    )

    if args.format == "jsonl":
        rendered = render_jsonl(result)
    else:
        rendered = render_json(result, pretty=not args.compact)

    args.output.write_text(rendered, encoding="utf-8")

    if args.prompt_output is not None:
        prompt = render_ai_prompt(result, max_flows=args.prompt_max_flows, max_packets=args.prompt_max_packets)
        args.prompt_output.write_text(prompt, encoding="utf-8")

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

    summary = result["summary"]
    print(
        f"Wrote {args.format.upper()} analysis to {args.output} "
        f"(packets={summary['packet_count']}, flows={summary['unique_flows']}, duration={summary['duration_sec']:.3f}s)"
    )
    if args.prompt_output is not None:
        print(f"Wrote prompt file to {args.prompt_output}")
    if args.wireshark_export is not None:
        print(f"Wrote Wireshark decode to {args.wireshark_export}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

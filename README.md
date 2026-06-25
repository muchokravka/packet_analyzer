# packet-analyzer

`packet-analyzer` parses `.pcap` files and exports structured network telemetry ready to pass into an AI model for defensive forensics analysis.

It supports multiple common link-layer capture types (Ethernet, Linux cooked v1/v2, raw IP, loopback/null, PPP). For unsupported or truncated frames it still emits packet records with `parse_note`, and summary includes `unsupported_or_truncated_packets` so partial-analysis confidence is explicit.

## What it produces

- **Summary block**: packet count, duration, protocol distribution, top talkers/ports, indicators.
- **Flow records**: bidirectional TCP/UDP flow grouping with packet/byte counts and timing.
- **Packet records**: normalized per-packet schema with L2/L3/L4, addressing, payload preview, optional payload base64 excerpt, app hints (DNS/HTTP), and indicators.
- **AI guidance block**: prompt hints and focus areas so downstream models get consistent context.
- **Prompt export**: optional `.txt` prompt purpose-built for LLM investigation workflows.

Output can be `JSON` (single document) or `JSONL` (summary + flow + packet records).
To protect model context windows, packet output is capped by default (`--packet-output-limit 5000`).

If you need a Wireshark-grade decode, the CLI can optionally call `tshark` to export full JSON decoding.

## Install

From repository root:

```bash
python -m pip install -e .
```

## Usage

```bash
packet-analyzer capture.pcap -o analysis.json
```

JSONL export:

```bash
packet-analyzer capture.pcap --format jsonl -o analysis.jsonl
```

Faster/smaller run for huge captures:

```bash
packet-analyzer capture.pcap --max-packets 100000 --no-payload-b64 --compact -o analysis.json
```

Adjust packet output size for LLM context budget:

```bash
packet-analyzer capture.pcap --packet-output-limit 2000 -o analysis.json
```

Generate a ready-to-paste AI prompt file:

```bash
packet-analyzer capture.pcap -o analysis.json --prompt-output analysis_prompt.txt
```

Control how much context is embedded in prompt:

```bash
packet-analyzer capture.pcap -o analysis.json --prompt-output analysis_prompt.txt --prompt-max-flows 30 --prompt-max-packets 50
```

Export full Wireshark decode (requires tshark):

```bash
packet-analyzer capture.pcap --wireshark-export wireshark.json
```

## Output schema highlights

- `summary.protocol_counts`
- `summary.indicator_counts`
- `flows[].flow_key`, `flows[].duration_sec`, `flows[].indicators`
- `packets[].direction`, `packets[].app_hints`, `packets[].indicators`
- `packets[].payload_preview`, `packets[].payload_hex`, and optional `packets[].payload_b64`
- `packets[].icmp_type`, `packets[].icmp_code`, `packets[].icmp_id`, `packets[].icmp_seq` when ICMP is present
- `packets[].parse_note` when decoding is partial/unsupported
- `summary.unsupported_or_truncated_packets` and `summary.pcap_format.supported_linktype`

## Security and use context

This tool is intended for legitimate incident response, blue-team analysis, and network troubleshooting.

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
packet-analyzer <pcap_file> [options]
```

Or run directly from the project root:

```bash
python3 packet_analyzer.py <pcap_file> [options]
```

### Basic options

| Flag | Description |
|------|-------------|
| `<pcap_file>` | Path to input `.pcap` or `.pcapng` file |
| `-o, --output <file>` | Output file path (default: `analysis.json`) |
| `--format <fmt>` | Output format: `json` (default), `jsonl`, or `csv` |
| `--quiet` | Suppress progress and summary output (for scripting) |

### Analysis scope

| Flag | Description |
|------|-------------|
| `--max-packets <n>` | Hard cap on packets to process (no limit by default) |
| `--packet-output-limit <n>` | Max packet records in output (default: `5000`) |
| `--compact` | Compact JSON output (no pretty indentation) |
| `--conversations-only` | Output flow records only, omit per-packet details |
| `--local-net <cidr>` | Treat CIDR as local network (repeatable, e.g. `--local-net 192.168.63.0/24`) |
| `--no-payload-b64` | Skip base64 payload excerpts in packet records |
| `--payload-b64-bytes <n>` | Max payload bytes to base64 per packet (default: `256`) |

### Filtering

| Flag | Description |
|------|-------------|
| `--severity <level>` | Min alert severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--filter-ip <ip>` | Only include packets matching this IP (source or destination) |
| `--filter-proto <proto>` | Only include packets matching protocol (e.g. `HTTP`, `DNS`, `TLS`, `TCP`) |
| `--rules` | List all available detection rules and exit |

### AI prompt export

| Flag | Description |
|------|-------------|
| `--prompt-output <file>` | Write an LLM-ready analysis prompt to a `.txt` file |
| `--prompt-max-flows <n>` | Max flow records embedded in prompt (default: `20`) |
| `--prompt-max-packets <n>` | Max packet records embedded in prompt (default: `30`) |

### Diff mode

| Flag | Description |
|------|-------------|
| `--diff <pcap_file>` | Compare with a second PCAP file and show differences |
| `--diff-output <file>` | Write structured diff as JSON to a file |

### Live capture

| Flag | Description |
|------|-------------|
| `--live` | Capture live from a network interface instead of reading a file |
| `--live-engine <engine>` | Capture backend: `scapy` (default) or `tcpdump` |
| `--interface <name>` | Network interface (e.g. `eth0`, `lo`). Default: system chooses |
| `--count <n>` | Number of packets to capture (default: `100`, `0` = unlimited) |
| `--timeout <sec>` | Capture duration in seconds (default: `30`) |
| `--list-interfaces` | List available network interfaces and exit |
| `--stream` | Stream JSONL output to stdout while capturing (requires `--format jsonl`) |

### Advanced

| Flag | Description |
|------|-------------|
| `--wireshark-export <file>` | Export full Wireshark decode as JSON (requires `tshark`) |

### Examples

Quick analysis:
```bash
packet-analyzer capture.pcap -o analysis.json
```

JSONL format:
```bash
packet-analyzer capture.pcap --format jsonl -o analysis.jsonl
```

Fast run for huge captures (no payload, compact output):
```bash
packet-analyzer capture.pcap --max-packets 100000 --no-payload-b64 --compact
```

LLM workflow with context control:
```bash
packet-analyzer capture.pcap -o analysis.json \
  --prompt-output analysis_prompt.txt \
  --prompt-max-flows 30 \
  --prompt-max-packets 50
```

Wireshark-grade decode (requires tshark):
```bash
packet-analyzer capture.pcap --wireshark-export wireshark.json
```

Live capture with tcpdump backend:
```bash
packet-analyzer --live --live-engine tcpdump --interface eth0 --count 500 -o live.json
```

Diff two captures:
```bash
packet-analyzer capture_before.pcap --diff capture_after.pcap
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

## Detection Rules

The built-in detection engine analyzes parsed traffic for suspicious patterns. Rules are grouped by category:

### Recon & Scanning
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_tcp_syn_scan` | HIGH | SYN-only packets to 15+ ports on same host within 10s |
| `detect_tcp_connect_scan` | HIGH | Full handshake + RST across 15+ ports |
| `detect_tcp_flag_scan` | HIGH | FIN, NULL, or XMAS scan-style TCP flags |
| `detect_udp_scan` | HIGH | UDP packets to 15+ ports on same host within 10s |
| `detect_icmp_sweep` | HIGH | ICMP Echo Requests to 5+ hosts within 5s |
| `detect_os_fingerprinting` | MEDIUM | Unusual TTL/window combinations or scanner signatures |
| `detect_service_version_probe` | HIGH | Same port connections to 10+ hosts within 30s |

### Exploits
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_heartbleed` | CRITICAL | TLS Heartbleed heartbeat request |
| `detect_shellshock` | CRITICAL | ShellShock payload in HTTP headers |
| `detect_sql_injection` | CRITICAL | SQL injection patterns in HTTP |
| `detect_xss` | CRITICAL | XSS patterns in HTTP |
| `detect_directory_traversal` | HIGH | Directory traversal in HTTP request |
| `detect_command_injection` | CRITICAL | Command injection in HTTP |
| `detect_log4shell` | CRITICAL | Log4Shell JNDI pattern |

### Credential Exposure
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_http_basic_auth` | HIGH | Cleartext Basic Auth credentials |
| `detect_http_form_credentials` | HIGH | Password fields in HTTP POST body |
| `detect_session_token_in_url` | MEDIUM | Session/token in URL query string |
| `detect_ftp_cleartext_credentials` | HIGH | Cleartext FTP USER/PASS |
| `detect_telnet_cleartext` | MEDIUM | Telnet session detected |
| `detect_smtp_auth_cleartext` | HIGH | SMTP AUTH in cleartext |
| `detect_private_key_material` | CRITICAL | Private key material in traffic |

### Exfiltration & C2
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_dns_tunneling` | HIGH | Long/encoded DNS subdomains |
| `detect_dns_exfiltration_volume` | HIGH | High DNS query volume to many subdomains |
| `detect_icmp_exfiltration` | HIGH | ICMP payloads with hidden text |
| `detect_large_http_post` | HIGH | Large outbound HTTP POST (>1MB) |
| `detect_large_dns_txt` | HIGH | Oversized DNS TXT records (>200 bytes) |
| `detect_beaconing` | HIGH | Regular outbound connection intervals (CoV <15%) |
| `detect_long_low_volume_tcp` | MEDIUM | Long-lived TCP with minimal data |
| `detect_http_c2_user_agent` | MEDIUM | Missing or suspicious User-Agent header |
| `detect_http_c2_identical_ua` | MEDIUM | Identical UA across 3+ requests |
| `detect_known_bad_ports` | HIGH | Outbound to known C2 ports (4444, 6667, 31337, ...) |

### TLS
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_tls_no_sni` | MEDIUM | TLS ClientHello without SNI |
| `detect_self_signed_cert` | MEDIUM | Self-signed certificate (issuer == subject) |

### Infrastructure
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_arp_spoofing` | HIGH | Multiple MACs for same IP in ARP replies |
| `detect_arp_flood` | HIGH | High rate of ARP packets from single host |

### DoS
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_icmp_flood` | HIGH | ICMP Echo Request flood (100+ pps) |
| `detect_tcp_syn_flood` | HIGH | TCP SYN flood (200+ pps) |
| `detect_dns_amplification` | HIGH | DNS response >10x query size |

### Anomalies
| Rule | Severity | Description |
|------|----------|-------------|
| `detect_new_host_mid_capture` | INFO | Host unseen in first 10% of capture |
| `detect_traffic_spike` | LOW | 5s window exceeds 3x average |
| `detect_port_reuse` | LOW | Source port reused across 4+ destinations |
| `detect_asymmetric_conversation` | LOW | TCP ratio >10:1 one direction |
| `detect_ttl_anomaly` | LOW | TTL <=5 (traceroute) |
| `detect_fragmented_ip` | LOW | IP fragments for TCP/UDP |
| `detect_vlan_hopping` | MEDIUM | Double-tagged VLAN frame |
| `detect_unencrypted_internal_http` | LOW | Internal HTTP on port 80 |
| `detect_unencrypted_protocol` | MEDIUM | FTP/Telnet/SMTP in use |
| `detect_deprecated_tls` | LOW | TLS 1.0 or 1.1 observed |
| `detect_internal_ip_header` | LOW | Internal IP leaked in HTTP headers |
| `detect_amqp_secret_strings` | MEDIUM | AMQP payload with secret-like strings |

### CLI control

Use `--rules` to list all available rules, `--severity` to filter
(CRITICAL/HIGH/MEDIUM/LOW/INFO), and `--filter-ip` / `--filter-proto` to scope
analysis.

## Security and use context

This tool is intended for legitimate incident response, blue-team analysis, and network troubleshooting.

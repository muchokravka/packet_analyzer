# Packet Analyzer Enhancement Plan

## Scope
Implement all 7 major feature areas across 3 phases.

## Phase 1 — Foundational (no deps)

### 1.1 Native PCAPNG Support
**File**: `packet_analyzer/pcapng.py`
- Parse Section Header Block (SHB) — detect endianness per section
- Parse Interface Description Block (IDB) — link type, snap length
- Parse Enhanced Packet Block (EPB) — actual packet data
- Block TLV walking (options)
- Return same `[(ts_sec, ts_usec, payload, original_len)]` format as PCAP reader
- **DO NOT** add dependencies — pure `struct` parsing
- Integrate into `_read_pcap():` try PCAP, then PCAPNG, then pcapng conversion fallback
- Tests: synthetic pcapng EPB frames, endianness, multiple sections

### 1.2 CSV Output Format
**File**: `packet_analyzer/formats.py`
- `render_csv(result)` — flat table of packet records
- `render_csv_summary(result)` — summary-only CSV
- Flows CSV output
- Add `--format csv` to CLI
- Tests: check CSV header + rows

### 1.3 ThreadPoolExecutor for Parallel Parsing
**File**: `packet_analyzer/analyzer.py`
- Split raw frames into chunks
- Process each chunk in `ThreadPoolExecutor(max_workers=os.cpu_count())`
- Merge flow dictionaries after processing (thread-safe counter merges)
- Benchmark: N/A, just correctness verified by existing tests
- Tests: same results as sequential (existing tests verify)

## Phase 2 — Protocol Parsers + Detections

### 2.1 Lightweight Protocol Parsers
**File**: `packet_analyzer/protocols.py`

#### SMB (445, 139)
- Detect SMB2 protocol using NetBIOS session + SMB2 magic (`\xfe\x53\x4d\x42`)
- Parse SMB2 dialect from negotiate response
- Detect SMBv1 (EternalBlue) via `\xff\x53\x4d\x42` magic
- Extract fields: dialect, command, NT status

#### SSH (22)
- Parse SSH banner exchange
- Detect SSH version (major.minor)
- Extract key exchange algorithms from KEX_INIT

#### Kerberos (88)
- ASN.1 length parsing for Kerberos
- Detect AS-REQ, TGS-REQ, AS-REP message types
- Extract realm and service principal

#### QUIC (443/UDP + other ports)
- Detect QUIC Initial packet via leading byte `0xc0` (fixed bit)
- Parse QUIC version
- Detect QUIC v1 vs v2

**Integration**: Add app_hints ("smb", "ssh", "kerberos", "quic") in `analyze_pcap()` for matching port/protocol. Lightweight — detect presence, don't parse deeply.

### 2.2 New Detection Rules
**File**: `packet_analyzer/detections.py`

| Rule | Severity | Description |
|------|----------|-------------|
| `detect_smb_exploit` | CRITICAL | SMBv1 (EternalBlue) dialect detected |
| `detect_ssh_bruteforce` | HIGH | Multiple SSH connections from same IP within window |
| `detect_kerberos_roasting` | HIGH | Kerberos AS-REP w/ RC4 encryption |
| `detect_doh_traffic` | LOW | TLS to port 443 with known DoH provider SNI |
| `detect_quic_usage` | LOW | QUIC traffic detected |
| `detect_port_scan_enhanced` | HIGH | Combined TCP+UDP port scan detection |

## Phase 3 — CLI + Remaining

### 3.1 CLI: Diff Mode
**File**: `packet_analyzer/cli.py`
- `--diff PCAP2` — compare two captures
- Output: summary diff (packet count delta, new IPs, new protocols, new alerts)
- Show alerts unique to each capture

### 3.2 CLI: Live Capture
**File**: `packet_analyzer/live.py` (NEW — optional scapy dependency)
- `--live` flag with interface + count + filter
- Live capture via `scapy.sniff()` with fallback to raw socket
- Feed captured frames through existing parser
- Pipe results to stdout in real-time

### 3.3 CLI: Interactive Mode
**File**: `packet_analyzer/interactive.py` (NEW)
- `--interactive` flag
- Basic REPL: `summary`, `flows`, `alerts`, `packets [filter]`, `export json/csv`, `quit`
- Uses existing result dictionary

### 3.4 Parquet Output
**File**: `packet_analyzer/formats.py`
- Optional dependency `pyarrow`
- `--format parquet`
- Write packets table as Parquet file
- Graceful degrade if pyarrow not installed

### 3.5 NDJSON Streaming
**File**: `packet_analyzer/formats.py`
- Already have JSONL (`render_jsonl`) — this is about streaming during capture
- For live capture: output NDJSON to stdout as packets arrive
- Add `--stream` flag to JSONL mode

## File Map

| File | Purpose | New/Existing |
|------|---------|-------------|
| `pcapng.py` | PCAPNG block parser | NEW |
| `formats.py` | CSV, Parquet output | NEW |
| `protocols.py` | SMB, SSH, Kerberos, QUIC light parsers | NEW |
| `live.py` | Live capture (scapy-based) | NEW |
| `interactive.py` | Interactive REPL | NEW |
| `analyzer.py` | PCAPNG integration, thread pool | EXISTING |
| `detections.py` | New detection rules | EXISTING |
| `cli.py` | CLI enhancements, diff mode | EXISTING |
| `utils.py` | No changes expected | EXISTING |

## Test Plan

- All existing 99 tests must pass at every phase
- `test_pcapng.py` — synthetic PCAPNG frames
- `test_protocols.py` — SMB, SSH, Kerberos, QUIC detection
- `test_formats.py` — CSV header/rows, Parquet roundtrip
- `test_live.py` — mock scapy capture
- `test_cli.py` — diff mode, interactive test
- `test_detections.py` — new rules with synthetic packets

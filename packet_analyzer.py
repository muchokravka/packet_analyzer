#!/usr/bin/env python3
"""
packet-analyzer — PCAP parser and AI-ready network analysis exporter.

Direct entry point for running from the project root without pip-installing.
Usage:  python run.py <pcap_file> [options]
"""
import sys
from pathlib import Path

# Ensure the project root is on sys.path so `packet_analyzer` is importable
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from packet_analyzer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

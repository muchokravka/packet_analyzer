from __future__ import annotations

import csv
import io
import json
from typing import Any


def render_csv(result: dict[str, Any]) -> str:
    """Render packet records as CSV."""
    packets = result.get("packets", [])
    if not packets:
        return ""

    fields = [
        "index", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "l3", "l4", "direction", "app_hints", "dns_query", "http_first_line",
        "payload_preview", "indicators", "parse_note", "payload_size",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(fields)

    for pkt in packets:
        row: list[str] = []
        for field in fields:
            val = pkt.get(field)
            if val is None:
                row.append("")
            elif isinstance(val, (list, dict)):
                row.append(json.dumps(val, separators=(",", ":"), sort_keys=True))
            else:
                row.append(str(val))
        writer.writerow(row)

    return buf.getvalue()


def render_csv_summary(result: dict[str, Any]) -> str:
    """Render summary block as key-value CSV."""
    summary = result.get("summary", {})
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["key", "value"])

    for key, val in summary.items():
        if isinstance(val, (list, dict)):
            val = json.dumps(val, separators=(",", ":"), sort_keys=True)
        else:
            val = str(val)
        writer.writerow([key, val])

    return buf.getvalue()


def render_csv_flows(result: dict[str, Any]) -> str:
    """Render flow/conversation records as CSV."""
    flows = result.get("flows", [])
    if not flows:
        return ""

    fields = [
        "flow_key", "protocol", "src", "dst", "packets", "bytes",
        "duration_sec", "app_hints",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(fields)

    for flow in flows:
        row: list[str] = []
        for field in fields:
            val = flow.get(field)
            if val is None:
                row.append("")
            elif isinstance(val, (list, dict)):
                row.append(json.dumps(val, separators=(",", ":"), sort_keys=True))
            else:
                row.append(str(val))
        writer.writerow(row)

    return buf.getvalue()

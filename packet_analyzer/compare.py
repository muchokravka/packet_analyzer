from __future__ import annotations

from typing import Any


def compare_pcaps(result_a: dict[str, Any], result_b: dict[str, Any]) -> dict[str, Any]:
    """Diff two analysis result dicts and produce a structured comparison."""
    sm_a = result_a.get("summary", {})
    sm_b = result_b.get("summary", {})

    # Summary-level diff
    duration_a = sm_a.get("duration_sec", 0.0)
    duration_b = sm_b.get("duration_sec", 0.0)
    pkt_a = sm_a.get("packet_count", 0)
    pkt_b = sm_b.get("packet_count", 0)
    flow_a = sm_a.get("unique_flows", 0)
    flow_b = sm_b.get("unique_flows", 0)

    # Protocol distribution diff
    proto_a = sm_a.get("protocol_counts", {})
    proto_b = sm_b.get("protocol_counts", {})
    all_protos = sorted(set(list(proto_a.keys()) + list(proto_b.keys())))
    proto_diff: list[dict[str, Any]] = []
    for p in all_protos:
        ca = proto_a.get(p, 0)
        cb = proto_b.get(p, 0)
        if ca != cb:
            proto_diff.append({"protocol": p, "a": ca, "b": cb, "delta": cb - ca})

    # Flow diff
    flows_a = _flow_set(result_a.get("flows", []))
    flows_b = _flow_set(result_b.get("flows", []))
    new_flows = sorted(flows_b - flows_a)
    missing_flows = sorted(flows_a - flows_b)

    # Alert diff
    alerts_a = {(a.get("rule", ""), a.get("src_ip", ""), a.get("dst_ip", "")) for a in result_a.get("alerts", [])}
    alerts_b = {(a.get("rule", ""), a.get("src_ip", ""), a.get("dst_ip", "")) for a in result_b.get("alerts", [])}
    new_alerts_raw: list[dict[str, Any]] = []
    for a in result_b.get("alerts", []):
        key = (a.get("rule", ""), a.get("src_ip", ""), a.get("dst_ip", ""))
        if key not in alerts_a:
            new_alerts_raw.append(a)

    suppressed_alerts_raw: list[dict[str, Any]] = []
    for a in result_a.get("alerts", []):
        key = (a.get("rule", ""), a.get("src_ip", ""), a.get("dst_ip", ""))
        if key not in alerts_b:
            suppressed_alerts_raw.append(a)

    return {
        "summary": {
            "duration_sec_a": duration_a,
            "duration_sec_b": duration_b,
            "duration_diff_sec": round(duration_b - duration_a, 3),
            "packets_a": pkt_a,
            "packets_b": pkt_b,
            "packets_delta": pkt_b - pkt_a,
            "flows_a": flow_a,
            "flows_b": flow_b,
            "flows_delta": flow_b - flow_a,
            "protocol_diffs": proto_diff,
        },
        "new_flows": new_flows,
        "missing_flows": missing_flows,
        "new_alerts": new_alerts_raw,
        "suppressed_alerts": suppressed_alerts_raw,
    }


def _flow_set(flows: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for f in flows:
        key = f.get("flow_key") or f.get("id") or ""
        if key:
            out.add(key)
    return out


def render_diff_text(diff: dict[str, Any]) -> str:
    """Render a human-readable text diff."""
    lines: list[str] = ["=== PCAP Comparison ===\n"]

    sm = diff["summary"]
    lines.append(f"  Duration: {sm['duration_sec_a']:.3f}s -> {sm['duration_sec_b']:.3f}s ({sm['duration_diff_sec']:+.3f}s)")
    lines.append(f"  Packets:  {sm['packets_a']} -> {sm['packets_b']} ({sm['packets_delta']:+d})")
    lines.append(f"  Flows:    {sm['flows_a']} -> {sm['flows_b']} ({sm['flows_delta']:+d})")

    if sm["protocol_diffs"]:
        lines.append("\n  Protocol changes:")
        for pd in sm["protocol_diffs"]:
            lines.append(f"    {pd['protocol']}: {pd['a']} -> {pd['b']} ({pd['delta']:+d})")

    if diff["new_flows"]:
        lines.append(f"\n  New flows ({len(diff['new_flows'])}):")
        for f in diff["new_flows"][:20]:
            lines.append(f"    + {f}")
        if len(diff["new_flows"]) > 20:
            lines.append(f"    ... and {len(diff['new_flows']) - 20} more")

    if diff["missing_flows"]:
        lines.append(f"\n  Missing flows ({len(diff['missing_flows'])}):")
        for f in diff["missing_flows"][:20]:
            lines.append(f"    - {f}")
        if len(diff["missing_flows"]) > 20:
            lines.append(f"    ... and {len(diff['missing_flows']) - 20} more")

    if diff["new_alerts"]:
        lines.append(f"\n  New alerts ({len(diff['new_alerts'])}):")
        for a in diff["new_alerts"]:
            lines.append(f"    [{a.get('severity','?')}] {a.get('rule','?')} {a.get('src_ip','?')} -> {a.get('dst_ip','?')}")

    if diff["suppressed_alerts"]:
        lines.append(f"\n  Suppressed alerts ({len(diff['suppressed_alerts'])}):")
        for a in diff["suppressed_alerts"]:
            lines.append(f"    [{a.get('severity','?')}] {a.get('rule','?')} {a.get('src_ip','?')} -> {a.get('dst_ip','?')}")

    return "\n".join(lines)

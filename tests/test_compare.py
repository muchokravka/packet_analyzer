from __future__ import annotations

from packet_analyzer.compare import compare_pcaps, render_diff_text


def _result(
    packets: int = 0,
    flows: int = 0,
    duration: float = 0.0,
    protocols: dict | None = None,
    alerts: list | None = None,
    flow_keys: list[str] | None = None,
) -> dict:
    if flow_keys is None:
        flow_keys = []
    return {
        "summary": {
            "packet_count": packets,
            "unique_flows": flows,
            "duration_sec": duration,
            "protocol_counts": protocols or {},
        },
        "flows": [{"flow_key": k} for k in flow_keys],
        "alerts": alerts or [],
    }


def test_compare_identical() -> None:
    r = _result(packets=100, flows=10, duration=30.0, protocols={"TCP": 80, "UDP": 20})
    diff = compare_pcaps(r, r)
    assert diff["summary"]["packets_delta"] == 0
    assert diff["summary"]["flows_delta"] == 0
    assert diff["summary"]["duration_diff_sec"] == 0.0
    assert diff["new_flows"] == []
    assert diff["missing_flows"] == []
    assert diff["new_alerts"] == []
    assert diff["suppressed_alerts"] == []


def test_compare_more_packets() -> None:
    a = _result(packets=100, flows=10, duration=30.0)
    b = _result(packets=200, flows=15, duration=35.0)
    diff = compare_pcaps(a, b)
    assert diff["summary"]["packets_delta"] == 100
    assert diff["summary"]["flows_delta"] == 5
    assert diff["summary"]["duration_diff_sec"] == 5.0


def test_compare_new_flows() -> None:
    a = _result(flow_keys=["flow1", "flow2"])
    b = _result(flow_keys=["flow1", "flow2", "flow3"])
    diff = compare_pcaps(a, b)
    assert diff["new_flows"] == ["flow3"]
    assert diff["missing_flows"] == []


def test_compare_missing_flows() -> None:
    a = _result(flow_keys=["flow1", "flow2"])
    b = _result(flow_keys=["flow1"])
    diff = compare_pcaps(a, b)
    assert diff["new_flows"] == []
    assert diff["missing_flows"] == ["flow2"]


def test_compare_alerts_new() -> None:
    a = _result(alerts=[{"rule": "detect_xss", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
    b = _result(
        alerts=[
            {"rule": "detect_xss", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            {"rule": "detect_smb_exploit", "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"},
        ]
    )
    diff = compare_pcaps(a, b)
    assert len(diff["new_alerts"]) == 1
    assert diff["new_alerts"][0]["rule"] == "detect_smb_exploit"
    assert len(diff["suppressed_alerts"]) == 0


def test_compare_alerts_suppressed() -> None:
    a = _result(
        alerts=[
            {"rule": "detect_xss", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            {"rule": "detect_smb_exploit", "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"},
        ]
    )
    b = _result(alerts=[{"rule": "detect_xss", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
    diff = compare_pcaps(a, b)
    assert len(diff["new_alerts"]) == 0
    assert len(diff["suppressed_alerts"]) == 1
    assert diff["suppressed_alerts"][0]["rule"] == "detect_smb_exploit"


def test_compare_protocol_diffs() -> None:
    a = _result(packets=100, protocols={"TCP": 80, "UDP": 20})
    b = _result(packets=100, protocols={"TCP": 70, "UDP": 20, "QUIC": 10})
    diff = compare_pcaps(a, b)
    proto_names = {p["protocol"] for p in diff["summary"]["protocol_diffs"]}
    assert "TCP" in proto_names
    assert "QUIC" in proto_names
    for pd in diff["summary"]["protocol_diffs"]:
        if pd["protocol"] == "TCP":
            assert pd["delta"] == -10
        elif pd["protocol"] == "QUIC":
            assert pd["delta"] == 10


def test_render_diff_text_basic() -> None:
    a = _result(packets=100, flows=10, duration=30.0)
    b = _result(packets=200, flows=10, duration=30.0)
    diff = compare_pcaps(a, b)
    text = render_diff_text(diff)
    assert "PCAP Comparison" in text
    assert "100 -> 200" in text


def test_render_diff_text_with_alerts() -> None:
    a = _result(alerts=[])
    b = _result(alerts=[{"rule": "detect_smb_exploit", "severity": "CRITICAL", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
    diff = compare_pcaps(a, b)
    text = render_diff_text(diff)
    assert "New alerts" in text
    assert "detect_smb_exploit" in text

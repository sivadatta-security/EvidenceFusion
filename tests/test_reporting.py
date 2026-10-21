"""Tests for evidence-aware incident report exports."""

from src.api.reporting import build_report_payload, render_markdown_report


def test_report_payload_only_includes_events_in_incident():
    incident = {
        "incident_id": "INC-TEST",
        "event_ids": ["EV-1"],
        "event_count": 1,
        "severity": "Low",
        "sources": ["network"],
        "summary": "One test event",
    }
    events = [
        {"event_id": "EV-1", "timestamp": "2026-01-01T00:00:00Z"},
        {"event_id": "EV-2", "timestamp": "2026-01-01T00:01:00Z"},
    ]

    payload = build_report_payload(incident, events, [])

    assert payload["incident"]["incident_id"] == "INC-TEST"
    assert [event["event_id"] for event in payload["events"]] == ["EV-1"]
    assert payload["report_version"] == "1.0"
    assert "not proof of malicious activity" in payload["interpretation_notice"]


def test_markdown_report_includes_incident_event_and_evidence_details():
    payload = build_report_payload(
        {
            "incident_id": "INC-42",
            "event_ids": ["EV-42"],
            "event_count": 1,
            "severity": "High",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z",
            "sources": ["network"],
            "summary": "Suspicious outbound connection",
        },
        [
            {
                "event_id": "EV-42",
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "network",
                "event_type": "connection",
                "host": "WS-01",
                "user": "analyst-test",
                "description": "Connection to a test destination",
            }
        ],
        [
            {
                "evidence_id": "E-42",
                "filename": "capture.pcap",
                "sha256": "abc123",
            }
        ],
    )

    report = render_markdown_report(payload)

    assert "# EvidenceFusion Incident Report" in report
    assert "INC-42" in report
    assert "EV-42" in report
    assert "Suspicious outbound connection" in report
    assert "capture.pcap" in report
    assert "abc123" in report
    assert "Analyst Caution" in report


def test_markdown_report_handles_empty_events_and_evidence():
    payload = build_report_payload(
        {"incident_id": "INC-EMPTY", "event_ids": [], "sources": []},
        [],
        [],
    )

    report = render_markdown_report(payload)

    assert "No event records were included." in report
    assert "No linked evidence records were found." in report

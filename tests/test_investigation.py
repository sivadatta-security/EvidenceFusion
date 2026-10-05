from src.api.investigation import build_investigation


def test_build_investigation_creates_incident_summary():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "source": "system",
            "event_type": "powershell_execution",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
            "description": "PowerShell execution detected",
            "confidence": 0.9,
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:02Z",
            "source": "network",
            "event_type": "web_c2_connection",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
            "description": "Connection to suspicious domain",
            "confidence": 0.85,
        },
    ]

    investigations = build_investigation(events)

    assert len(investigations) == 1

    incident = investigations[0]

    assert incident["incident_id"] == "INC001"

    assert set(incident["event_ids"]) == {
        "EVT001",
        "EVT002",
    }

    assert incident["event_count"] == 2

    assert incident["severity"] == "High"

    assert incident["sources"] == [
        "network",
        "system",
    ]

    assert incident["relationship_count"] == 1

    assert incident["max_correlation_score"] == 7

    assert incident["mitre_techniques"] == [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "event_ids": ["EVT001"],
        },
        {
            "technique_id": "T1071.001",
            "technique_name": "Web Protocols",
            "event_ids": ["EVT002"],
        },
    ]


def test_build_investigation_keeps_unrelated_events_separate():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "source": "system",
            "event_type": "powershell_execution",
            "user": "user01",
            "host": "WORKSTATION01",
            "description": "PowerShell execution",
            "confidence": 0.9,
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T12:00:00Z",
            "source": "system",
            "event_type": "process_discovery",
            "user": "user99",
            "host": "WORKSTATION99",
            "description": "Process discovery",
            "confidence": 0.8,
        },
    ]

    investigations = build_investigation(events)

    assert len(investigations) == 2

    assert investigations[0]["incident_id"] == "INC001"
    assert investigations[0]["event_ids"] == ["EVT001"]

    assert investigations[1]["incident_id"] == "INC002"
    assert investigations[1]["event_ids"] == ["EVT002"]


def test_build_investigation_handles_empty_events():
    investigations = build_investigation([])

    assert investigations == []
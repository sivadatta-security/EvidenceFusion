from src.correlation.engine import (
    compare_events,
    correlate_events,
    build_incident_clusters,
    create_incidents,
    summarize_incident,
    classify_severity,
)


def test_events_correlate_by_user_host_domain_and_time():
    event_a = {
        "event_id": "EVT001",
        "timestamp": "2026-09-01T10:30:00Z",
        "user": "user01",
        "host": "WORKSTATION01",
        "domain": "malicious.test",
    }

    event_b = {
        "event_id": "EVT002",
        "timestamp": "2026-09-01T10:31:02Z",
        "user": "user01",
        "host": "WORKSTATION01",
        "domain": "malicious.test",
    }

    result = compare_events(event_a, event_b)

    assert result["score"] == 7

    assert result["reasons"] == [
        "same_user",
        "same_host",
        "same_domain",
        "close_in_time",
    ]


def test_events_with_no_matching_attributes_only_get_time_score():
    event_a = {
        "event_id": "EVT001",
        "timestamp": "2026-09-01T10:30:00Z",
        "user": "user01",
        "host": "WORKSTATION01",
    }

    event_b = {
        "event_id": "EVT002",
        "timestamp": "2026-09-01T10:32:00Z",
        "user": "user02",
        "host": "WORKSTATION02",
    }

    result = compare_events(event_a, event_b)

    assert result["score"] == 1
    assert result["reasons"] == ["close_in_time"]


def test_events_outside_time_window_do_not_get_time_score():
    event_a = {
        "event_id": "EVT001",
        "timestamp": "2026-09-01T10:30:00Z",
        "user": "user01",
    }

    event_b = {
        "event_id": "EVT002",
        "timestamp": "2026-09-01T10:36:00Z",
        "user": "user02",
    }

    result = compare_events(event_a, event_b)

    assert result["score"] == 0
    assert result["reasons"] == []


def test_correlate_events_returns_only_related_pairs():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT003",
            "timestamp": "2026-09-01T10:40:00Z",
            "user": "user02",
            "host": "WORKSTATION02",
            "domain": "safe.test",
        },
    ]

    relationships = correlate_events(events)

    assert len(relationships) == 1
    assert relationships[0]["event_a"] == "EVT001"
    assert relationships[0]["event_b"] == "EVT002"
    assert relationships[0]["score"] == 7


def test_correlate_events_does_not_create_relationship_for_time_only():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "user": "user01",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:32:00Z",
            "user": "user02",
        },
    ]

    relationships = correlate_events(events)

    assert relationships == []


def test_build_incident_clusters_groups_connected_events():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT003",
            "timestamp": "2026-09-01T10:32:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "source_ip": "192.0.2.10",
        },
        {
            "event_id": "EVT004",
            "timestamp": "2026-09-01T10:33:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "source_ip": "192.0.2.10",
        },
        {
            "event_id": "EVT005",
            "timestamp": "2026-09-01T12:00:00Z",
            "user": "user99",
            "host": "WORKSTATION99",
            "domain": "unrelated.test",
        },
    ]

    clusters = build_incident_clusters(events)

    assert len(clusters) == 2

    cluster_event_ids = [
        set(cluster)
        for cluster in clusters
    ]

    assert {
        "EVT001",
        "EVT002",
        "EVT003",
        "EVT004",
    } in cluster_event_ids

    assert {"EVT005"} in cluster_event_ids


def test_create_incidents_assigns_incident_ids():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:00Z",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT003",
            "timestamp": "2026-09-01T12:00:00Z",
            "user": "user99",
            "host": "WORKSTATION99",
        },
    ]

    incidents = create_incidents(events)

    assert len(incidents) == 2

    assert incidents[0]["incident_id"] == "INC001"
    assert set(incidents[0]["event_ids"]) == {
        "EVT001",
        "EVT002",
    }

    assert incidents[1]["incident_id"] == "INC002"
    assert incidents[1]["event_ids"] == ["EVT003"]


def test_summarize_incident():
    events = [
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
            "source": "system",
            "event_type": "powershell_execution",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:00Z",
            "source": "network",
            "event_type": "network",
            "user": "user01",
            "host": "WORKSTATION01",
            "domain": "malicious.test",
        },
    ]

    incidents = create_incidents(events)

    summary = summarize_incident(
        incidents[0],
        events,
    )

    assert summary["event_count"] == 2
    assert summary["first_seen"] == "2026-09-01T10:30:00+00:00"
    assert summary["last_seen"] == "2026-09-01T10:31:00+00:00"
    assert summary["sources"] == ["network", "system"]
    assert summary["relationship_count"] == 1
    assert summary["max_correlation_score"] == 7
    assert summary["severity"] == "High"

    assert summary["mitre_techniques"] == [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "event_ids": ["EVT001"],
        }
    ]


def test_classify_severity():
    assert classify_severity(0) == "Low"
    assert classify_severity(1) == "Low"
    assert classify_severity(2) == "Low"

    assert classify_severity(3) == "Medium"
    assert classify_severity(5) == "Medium"

    assert classify_severity(6) == "High"
    assert classify_severity(7) == "High"
    assert classify_severity(10) == "High"
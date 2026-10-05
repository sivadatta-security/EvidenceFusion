from src.mitre.mapping import (
    map_event_to_mitre,
    map_incident_to_mitre,
)


def test_powershell_event_maps_to_mitre():
    event = {
        "event_id": "EVT001",
        "event_type": "powershell_execution",
    }

    result = map_event_to_mitre(event)

    assert result == {
        "event_id": "EVT001",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
    }


def test_process_discovery_maps_to_mitre():
    event = {
        "event_id": "EVT002",
        "event_type": "process_discovery",
    }

    result = map_event_to_mitre(event)

    assert result == {
        "event_id": "EVT002",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
    }


def test_unknown_event_type_returns_none():
    event = {
        "event_id": "EVT003",
        "event_type": "unknown_activity",
    }

    result = map_event_to_mitre(event)

    assert result is None

def test_incident_maps_multiple_events_to_mitre():
    incident = {
        "incident_id": "INC001",
        "event_ids": [
            "EVT001",
            "EVT002",
            "EVT003",
        ],
    }

    events = [
        {
            "event_id": "EVT001",
            "event_type": "powershell_execution",
        },
        {
            "event_id": "EVT002",
            "event_type": "process_discovery",
        },
        {
            "event_id": "EVT003",
            "event_type": "web_c2_connection",
        },
    ]

    result = map_incident_to_mitre(
        incident,
        events,
    )

    assert result["incident_id"] == "INC001"
    assert len(result["techniques"]) == 3

    technique_ids = {
        technique["technique_id"]
        for technique in result["techniques"]
    }

    assert technique_ids == {
        "T1059.001",
        "T1057",
        "T1071.001",
    }


def test_incident_deduplicates_same_technique():
    incident = {
        "incident_id": "INC001",
        "event_ids": [
            "EVT001",
            "EVT002",
        ],
    }

    events = [
        {
            "event_id": "EVT001",
            "event_type": "process_discovery",
        },
        {
            "event_id": "EVT002",
            "event_type": "process_discovery",
        },
    ]

    result = map_incident_to_mitre(
        incident,
        events,
    )

    assert len(result["techniques"]) == 1

    technique = result["techniques"][0]

    assert technique["technique_id"] == "T1057"
    assert technique["technique_name"] == "Process Discovery"

    assert technique["event_ids"] == [
        "EVT001",
        "EVT002",
    ]
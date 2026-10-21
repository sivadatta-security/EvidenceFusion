
from src.mitre.mapping import (
    assess_event_for_mitre,
    assess_incident_for_mitre,
    map_event_to_mitre,
    map_incident_to_mitre,
)


def test_powershell_event_maps_to_mitre():
    event = {
        "event_id": "EVT001",
        "event_type": "powershell_execution",
    }

    assert map_event_to_mitre(event) == {
        "event_id": "EVT001",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
    }


def test_process_discovery_maps_to_mitre():
    event = {
        "event_id": "EVT002",
        "event_type": "process_discovery",
    }

    assert map_event_to_mitre(event) == {
        "event_id": "EVT002",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
    }


def test_unknown_event_type_returns_none():
    assert map_event_to_mitre({
        "event_id": "EVT003",
        "event_type": "unknown_activity",
    }) is None


def test_email_receipt_alone_does_not_claim_phishing():
    result = assess_event_for_mitre({
        "event_id": "EVT004",
        "event_type": "email_received",
        "description": "Email received",
        "artifact": "email_attachment",
    })

    assert result["status"] == "no_assessment"
    assert result["technique_id"] is None


def test_domain_access_alone_does_not_claim_command_and_control():
    result = assess_event_for_mitre({
        "event_id": "EVT005",
        "event_type": "domain_access",
        "domain": "unknown.example",
        "description": "User accessed a domain",
    })

    assert result["status"] == "no_assessment"
    assert result["technique_id"] is None



def test_suspicious_email_is_review_only_not_confirmed_phishing():
    result = assess_event_for_mitre({
        "event_id": "EVT006",
        "event_type": "email_received",
        "description": "Suspicious email received",
        "artifact": "suspicious_url",
    })

    assert result["status"] == "needs_review"
    assert result["technique_id"] is None
    assert "suspicious" in result["indicators"]
    assert "phishing" not in result["indicators"]
    assert "corroborating evidence" in result["recommended_action"]



def test_explicit_mapping_is_reported_as_mapped_not_confirmed():
    result = assess_event_for_mitre({
        "event_id": "EVT007",
        "event_type": "powershell_execution",
        "description": "PowerShell process started",
    })

    assert result["status"] == "mapped"
    assert result["technique_id"] == "T1059.001"
    assert "Validate" in result["reason"]


def test_api_test_events_are_excluded():
    result = assess_event_for_mitre({
        "event_id": "API_TEST_EVENT_123",
        "event_type": "email_received",
        "description": "Suspicious email received",
        "artifact": "phishing payload",
    })

    assert result["status"] == "excluded"
    assert result["technique_id"] is None


def test_incident_maps_multiple_events_to_mitre():
    incident = {
        "incident_id": "INC001",
        "event_ids": ["EVT001", "EVT002", "EVT003"],
    }
    events = [
        {"event_id": "EVT001", "event_type": "powershell_execution"},
        {"event_id": "EVT002", "event_type": "process_discovery"},
        {"event_id": "EVT003", "event_type": "web_c2_connection"},
    ]

    result = map_incident_to_mitre(incident, events)

    assert result["incident_id"] == "INC001"
    assert {
        item["technique_id"] for item in result["techniques"]
    } == {"T1059.001", "T1057", "T1071.001"}


def test_incident_deduplicates_same_technique():
    incident = {
        "incident_id": "INC001",
        "event_ids": ["EVT001", "EVT002"],
    }
    events = [
        {"event_id": "EVT001", "event_type": "process_discovery"},
        {"event_id": "EVT002", "event_type": "process_discovery"},
    ]

    result = map_incident_to_mitre(incident, events)

    assert len(result["techniques"]) == 1
    assert result["techniques"][0]["technique_id"] == "T1057"
    assert result["techniques"][0]["event_ids"] == ["EVT001", "EVT002"]


def test_incident_with_only_unmapped_events_has_no_techniques():
    incident = {
        "incident_id": "INC002",
        "event_ids": ["EVT010"],
    }
    events = [
        {"event_id": "EVT010", "event_type": "email_received"},
    ]

    result = map_incident_to_mitre(incident, events)

    assert result["techniques"] == []


def test_incident_assessment_excludes_test_events():
    incident = {
        "incident_id": "INC003",
        "event_ids": ["EVT011", "API_TEST_EVENT_1"],
    }
    events = [
        {
            "event_id": "EVT011",
            "event_type": "email_received",
            "description": "Suspicious email received",
        },
        {
            "event_id": "API_TEST_EVENT_1",
            "event_type": "email_received",
            "description": "Suspicious email received",
        },
    ]

    result = assess_incident_for_mitre(incident, events)

    assert len(result["assessments"]) == 1
    assert result["assessments"][0]["event_id"] == "EVT011"
    assert result["assessment_counts"]["needs_review"] == 1


MITRE_MAPPINGS = {
    "command_execution": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    "powershell_execution": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
    },
    "process_discovery": {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
    },
    "account_discovery": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
    },
    "scheduled_task_created": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
    },
    "web_c2_connection": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
    },
}

REVIEW_INDICATORS = (
    "suspicious",
    "phishing",
    "malicious",
    "credential theft",
    "credential harvesting",
    "payload",
)


def _is_test_event(event):
    """Identify obvious test fixtures that must not create assessments."""
    event_id = str(event.get("event_id") or "").strip().upper()

    if event_id.startswith("API_TEST_EVENT"):
        return True

    if event.get("is_test") is True:
        return True

    return False


def map_event_to_mitre(event):
    """
    Map a normalized event when an explicit event-type mapping exists.

    This is a deterministic mapping, not proof that the behavior was
    malicious. Existing return fields are preserved for compatibility.
    """
    event_type = event.get("event_type")
    mapping = MITRE_MAPPINGS.get(event_type)

    if mapping is None:
        return None

    return {
        "event_id": event["event_id"],
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
    }


def assess_event_for_mitre(event):
    """
    Produce a conservative triage assessment for an event.

    Explicit mappings remain separate from review candidates. Textual
    indicators only trigger review; they do not establish an ATT&CK
    technique or confirm malicious activity.
    """
    if _is_test_event(event):
        return {
            "event_id": event.get("event_id"),
            "status": "excluded",
            "technique_id": None,
            "technique_name": None,
            "reason": "Test event excluded from security assessment.",
            "indicators": [],
            "recommended_action": "No action; this is a test record.",
        }

    mapping = map_event_to_mitre(event)

    if mapping is not None:
        return {
            "event_id": event["event_id"],
            "status": "mapped",
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"],
            "reason": (
                "The normalized event type has an explicit ATT&CK mapping. "
                "Validate the underlying evidence before drawing conclusions."
            ),
            "indicators": [event.get("event_type")],
            "recommended_action": (
                "Review the source evidence and validate the observed behavior."
            ),
        }

    searchable_fields = (
        "description",
        "artifact",
        "event_type",
    )
    text = " ".join(
        str(event.get(field) or "")
        for field in searchable_fields
    ).casefold()

    indicators = [
        indicator
        for indicator in REVIEW_INDICATORS
        if indicator in text
    ]

    if not indicators:
        return {
            "event_id": event.get("event_id"),
            "status": "no_assessment",
            "technique_id": None,
            "technique_name": None,
            "reason": (
                "No explicit ATT&CK mapping or supported review indicator "
                "was found in the available event fields."
            ),
            "indicators": [],
            "recommended_action": (
                "Collect additional event context if this event is relevant "
                "to the investigation."
            ),
        }

    return {
        "event_id": event.get("event_id"),
        "status": "needs_review",
        "technique_id": None,
        "technique_name": None,
        "reason": (
            "Review indicators were found in event text, but they are "
            "insufficient to assign an ATT&CK technique or confirm an attack."
        ),
        "indicators": indicators,
        "recommended_action": (
            "Inspect the original artifact, validate the indicator, and "
            "collect corroborating evidence before assigning a technique."
        ),
    }


def map_incident_to_mitre(incident, events):
    """
    Map events belonging to an incident to explicit ATT&CK techniques.

    Duplicate techniques are returned once. This preserves the existing
    incident mapping contract; candidate assessments are separate.
    """
    event_map = {
        event["event_id"]: event
        for event in events
    }

    techniques = {}

    for event_id in incident["event_ids"]:
        event = event_map.get(event_id)

        if event is None:
            continue

        mapping = map_event_to_mitre(event)

        if mapping is None:
            continue

        technique_id = mapping["technique_id"]

        if technique_id not in techniques:
            techniques[technique_id] = {
                "technique_id": technique_id,
                "technique_name": mapping["technique_name"],
                "event_ids": [],
            }

        techniques[technique_id]["event_ids"].append(event_id)

    return {
        "incident_id": incident["incident_id"],
        "techniques": list(techniques.values()),
    }


def assess_incident_for_mitre(incident, events):
    """
    Assess an incident's events and return non-test assessments.

    This does not alter incident severity, correlation, or existing mappings.
    """
    event_map = {
        event["event_id"]: event
        for event in events
    }

    assessments = []

    for event_id in incident.get("event_ids", []):
        event = event_map.get(event_id)

        if event is None:
            continue

        assessment = assess_event_for_mitre(event)

        if assessment["status"] != "excluded":
            assessments.append(assessment)

    return {
        "incident_id": incident["incident_id"],
        "assessments": assessments,
        "assessment_counts": {
            "mapped": sum(
                item["status"] == "mapped" for item in assessments
            ),
            "needs_review": sum(
                item["status"] == "needs_review" for item in assessments
            ),
            "no_assessment": sum(
                item["status"] == "no_assessment" for item in assessments
            ),
        },
    }

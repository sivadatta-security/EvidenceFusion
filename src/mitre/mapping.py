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


def map_event_to_mitre(event):
    """
    Map a normalized EvidenceFusion event to an
    ATT&CK technique when an explicit mapping exists.
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

def map_incident_to_mitre(incident, events):
    """
    Map all events belonging to an incident to ATT&CK techniques.

    Duplicate techniques are returned only once.
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

        techniques[technique_id]["event_ids"].append(
            event_id
        )

    return {
        "incident_id": incident["incident_id"],
        "techniques": list(techniques.values()),
    }
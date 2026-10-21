"""Utilities for generating portable, evidence-aware incident reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_report_payload(
    incident: dict[str, Any],
    events: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a JSON-serializable report snapshot without changing stored data."""
    event_ids = set(incident.get("event_ids", []))
    incident_events = [
        dict(event) for event in events if event.get("event_id") in event_ids
    ]
    return {
        "report_type": "EvidenceFusion incident report",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": dict(incident),
        "events": incident_events,
        "evidence": [dict(item) for item in evidence],
        "interpretation_notice": (
            "Correlation, severity, MITRE ATT&CK assessments, and external "
            "intelligence are investigative aids, not proof of malicious "
            "activity. Validate conclusions against the underlying evidence."
        ),
    }


def render_markdown_report(payload: dict[str, Any]) -> str:
    """Render a readable Markdown report from a report payload."""
    incident = payload["incident"]
    lines = [
        "# EvidenceFusion Incident Report",
        "",
        f"- **Report version:** {payload['report_version']}",
        f"- **Generated at (UTC):** {payload['generated_at']}",
        f"- **Incident ID:** {incident.get('incident_id', 'Unknown')}",
        f"- **Severity:** {incident.get('severity', 'Unclassified')}",
        f"- **Event count:** {incident.get('event_count', len(payload['events']))}",
        f"- **First seen:** {incident.get('first_seen', 'Unknown')}",
        f"- **Last seen:** {incident.get('last_seen', 'Unknown')}",
        "",
        "## Summary",
        "",
        str(incident.get("summary", "No summary was supplied.")),
        "",
        "## Correlation",
        "",
        f"- **Sources:** {', '.join(map(str, incident.get('sources', []))) or 'None recorded'}",
        f"- **Event IDs:** {', '.join(map(str, incident.get('event_ids', []))) or 'None recorded'}",
        "",
        "## Events",
        "",
    ]

    if payload["events"]:
        for event in payload["events"]:
            lines.extend([
                f"### {event.get('event_id', 'Unknown event')}",
                f"- **Timestamp:** {event.get('timestamp', 'Unknown')}",
                f"- **Source / type:** {event.get('source', 'Unknown')} / {event.get('event_type', 'Unknown')}",
                f"- **Host / user:** {event.get('host') or 'Unknown'} / {event.get('user') or 'Unknown'}",
                f"- **Description:** {event.get('description', 'No description supplied.')}",
                "",
            ])
    else:
        lines.extend(["No event records were included.", ""])

    lines.extend(["## Linked Evidence", ""])
    if payload["evidence"]:
        for item in payload["evidence"]:
            lines.extend([
                f"- **{item.get('evidence_id', 'Unknown evidence')}** — "
                f"{item.get('filename') or item.get('original_filename') or item.get('artifact_type') or 'Evidence artifact'}; "
                f"SHA-256: {item.get('sha256') or item.get('hash') or 'Not recorded'}",
            ])
    else:
        lines.append("No linked evidence records were found.")
    lines.extend([
        "",
        "## Analyst Caution",
        "",
        payload["interpretation_notice"],
        "",
    ])
    return "\n".join(lines)

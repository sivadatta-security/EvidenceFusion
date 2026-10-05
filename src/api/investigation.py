from src.correlation.engine import (
    create_incidents,
    summarize_incident,
)


def build_investigation(events):
    """
    Build structured investigation results from normalized events.

    The investigation process:
    1. Creates incident clusters from correlated events.
    2. Generates an investigation summary for each incident.
    3. Returns the summaries as a list.
    """
    incidents = create_incidents(events)

    return [
        summarize_incident(
            incident,
            events,
        )
        for incident in incidents
    ]
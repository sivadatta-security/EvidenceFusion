from datetime import datetime, timedelta


# Initial correlation configuration.
TIME_WINDOW_MINUTES = 5
CORRELATION_THRESHOLD = 3

CORRELATION_WEIGHTS = {
    "same_user": 2,
    "same_host": 2,
    "same_source_ip": 2,
    "same_destination_ip": 2,
    "same_domain": 2,
    "same_hash": 3,
    "close_in_time": 1,
}


def parse_timestamp(timestamp):
    """Convert an ISO 8601 timestamp into a timezone-aware datetime."""
    return datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )


def compare_events(event_a, event_b):
    """
    Compare two normalized events and calculate their correlation score.

    Returns the score and the reasons that contributed to it.
    """
    score = 0
    reasons = []

    if (
        event_a.get("user")
        and event_a.get("user") == event_b.get("user")
    ):
        score += CORRELATION_WEIGHTS["same_user"]
        reasons.append("same_user")

    if (
        event_a.get("host")
        and event_a.get("host") == event_b.get("host")
    ):
        score += CORRELATION_WEIGHTS["same_host"]
        reasons.append("same_host")

    if (
        event_a.get("source_ip")
        and event_a.get("source_ip") == event_b.get("source_ip")
    ):
        score += CORRELATION_WEIGHTS["same_source_ip"]
        reasons.append("same_source_ip")

    if (
        event_a.get("destination_ip")
        and event_a.get("destination_ip")
        == event_b.get("destination_ip")
    ):
        score += CORRELATION_WEIGHTS["same_destination_ip"]
        reasons.append("same_destination_ip")

    if (
        event_a.get("domain")
        and event_a.get("domain") == event_b.get("domain")
    ):
        score += CORRELATION_WEIGHTS["same_domain"]
        reasons.append("same_domain")

    if (
        event_a.get("hash")
        and event_a.get("hash") == event_b.get("hash")
    ):
        score += CORRELATION_WEIGHTS["same_hash"]
        reasons.append("same_hash")

    timestamp_a = parse_timestamp(event_a["timestamp"])
    timestamp_b = parse_timestamp(event_b["timestamp"])

    time_difference = abs(timestamp_a - timestamp_b)

    if time_difference <= timedelta(
        minutes=TIME_WINDOW_MINUTES
    ):
        score += CORRELATION_WEIGHTS["close_in_time"]
        reasons.append("close_in_time")

    return {
        "event_a": event_a["event_id"],
        "event_b": event_b["event_id"],
        "score": score,
        "reasons": reasons,
    }


def correlate_events(events):
    """
    Compare all event pairs and return relationships
    that meet the correlation threshold.
    """
    relationships = []

    for index, event_a in enumerate(events):
        for event_b in events[index + 1:]:
            result = compare_events(event_a, event_b)

            if result["score"] >= CORRELATION_THRESHOLD:
                relationships.append(result)

    return relationships


def build_incident_clusters(events):
    """
    Build incident clusters from correlated event relationships.

    Events connected through qualifying relationships are grouped
    into the same incident cluster.
    """
    relationships = correlate_events(events)

    adjacency = {}

    for event in events:
        adjacency[event["event_id"]] = set()

    for relationship in relationships:
        event_a = relationship["event_a"]
        event_b = relationship["event_b"]

        adjacency[event_a].add(event_b)
        adjacency[event_b].add(event_a)

    visited = set()
    clusters = []

    for event in events:
        event_id = event["event_id"]

        if event_id in visited:
            continue

        cluster = []
        stack = [event_id]

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)
            cluster.append(current)

            for neighbor in adjacency[current]:
                if neighbor not in visited:
                    stack.append(neighbor)

        clusters.append(cluster)

    return clusters


def create_incidents(events):
    """
    Convert incident clusters into structured incident records.
    """
    clusters = build_incident_clusters(events)

    incidents = []

    for index, cluster in enumerate(clusters, start=1):
        incidents.append(
            {
                "incident_id": f"INC{index:03d}",
                "event_ids": sorted(cluster),
            }
        )

    return incidents


def summarize_incident(incident, events):
    """
    Add investigation-focused summary information to an incident.
    """
    event_map = {
        event["event_id"]: event
        for event in events
    }

    incident_events = [
        event_map[event_id]
        for event_id in incident["event_ids"]
        if event_id in event_map
    ]

    timestamps = [
        parse_timestamp(event["timestamp"])
        for event in incident_events
    ]

    sources = sorted(
        {
            event["source"]
            for event in incident_events
            if event.get("source")
        }
    )

    relationships = correlate_events(incident_events)

    max_correlation_score = max(
        (
            relationship["score"]
            for relationship in relationships
        ),
        default=0,
    )

    return {
        **incident,
        "event_count": len(incident_events),
        "first_seen": min(timestamps).isoformat()
        if timestamps
        else None,
        "last_seen": max(timestamps).isoformat()
        if timestamps
        else None,
        "sources": sources,
        "relationship_count": len(relationships),
        "max_correlation_score": max_correlation_score,
        "severity": classify_severity(
            max_correlation_score
        ),
    }


def classify_severity(max_correlation_score):
    """
    Classify incident severity using the project's
    initial correlation-score thresholds.
    """
    if max_correlation_score >= 6:
        return "High"

    if max_correlation_score >= 3:
        return "Medium"

    return "Low"
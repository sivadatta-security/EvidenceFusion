
from datetime import datetime, timezone


def parse_event_timestamp(value):
    """Parse a timestamp into UTC, returning None if it is invalid."""
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def sort_events_by_time(events):
    """Sort chronologically, putting invalid timestamps at the end."""
    def sort_key(event):
        timestamp = parse_event_timestamp(event.get("timestamp"))

        if timestamp is None:
            return (1, datetime.max.replace(tzinfo=timezone.utc))

        return (0, timestamp)

    return sorted(events, key=sort_key)

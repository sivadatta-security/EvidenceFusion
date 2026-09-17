from datetime import datetime


def sort_events_by_time(events):
    """Return events sorted chronologically by timestamp."""
    return sorted(
        events,
        key=lambda event: datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        ),
    )
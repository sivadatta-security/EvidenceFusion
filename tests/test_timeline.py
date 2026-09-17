from src.api.timeline import sort_events_by_time


def test_sort_events_by_time():
    events = [
        {
            "event_id": "EVT003",
            "timestamp": "2026-09-01T10:32:00Z",
        },
        {
            "event_id": "EVT001",
            "timestamp": "2026-09-01T10:30:00Z",
        },
        {
            "event_id": "EVT002",
            "timestamp": "2026-09-01T10:31:00Z",
        },
    ]

    result = sort_events_by_time(events)

    assert [event["event_id"] for event in result] == [
        "EVT001",
        "EVT002",
        "EVT003",
    ]
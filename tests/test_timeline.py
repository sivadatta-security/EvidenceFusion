
from src.api.timeline import parse_event_timestamp, sort_events_by_time


def test_sort_events_by_time():
    events = [
        {"event_id": "EVT003", "timestamp": "2026-09-01T10:32:00Z"},
        {"event_id": "EVT001", "timestamp": "2026-09-01T10:30:00Z"},
        {"event_id": "EVT002", "timestamp": "2026-09-01T10:31:00Z"},
    ]

    result = sort_events_by_time(events)

    assert [event["event_id"] for event in result] == [
        "EVT001",
        "EVT002",
        "EVT003",
    ]


def test_sort_events_with_different_timezones():
    events = [
        {"event_id": "LATER", "timestamp": "2026-09-01T12:00:00+02:00"},
        {"event_id": "EARLIER", "timestamp": "2026-09-01T09:30:00Z"},
    ]

    result = sort_events_by_time(events)

    assert [event["event_id"] for event in result] == [
        "EARLIER",
        "LATER",
    ]


def test_invalid_timestamps_are_placed_last():
    events = [
        {"event_id": "INVALID", "timestamp": "not-a-timestamp"},
        {"event_id": "VALID", "timestamp": "2026-09-01T10:30:00Z"},
        {"event_id": "MISSING"},
    ]

    result = sort_events_by_time(events)

    assert [event["event_id"] for event in result] == [
        "VALID",
        "INVALID",
        "MISSING",
    ]


def test_naive_timestamp_is_treated_as_utc():
    parsed = parse_event_timestamp("2026-09-01T10:30:00")

    assert parsed is not None
    assert parsed.isoformat() == "2026-09-01T10:30:00+00:00"


def test_parse_invalid_timestamp_returns_none():
    assert parse_event_timestamp("not-a-timestamp") is None
    assert parse_event_timestamp(None) is None
    assert parse_event_timestamp("") is None

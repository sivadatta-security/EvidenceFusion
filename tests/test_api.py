from uuid import uuid4

from fastapi.testclient import TestClient

from src.api.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200

    assert response.json() == {
        "project": "EvidenceFusion",
        "message": "EvidenceFusion API is running",
        "version": "0.1.0",
    }


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_get_events():
    response = client.get("/events")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_event():
    event = {
        "event_id": f"API_TEST_EVENT_{uuid4().hex}",
        "timestamp": "2026-09-01T10:40:00Z",
        "source": "email",
        "event_type": "email_received",
        "user": "api_user",
        "host": "API_HOST",
        "source_ip": None,
        "destination_ip": None,
        "domain": "example.test",
        "artifact": "test_artifact",
        "hash": None,
        "description": "API test event",
        "confidence": 0.8,
    }

    response = client.post("/events", json=event)

    assert response.status_code == 201
    assert response.json()["event_id"] == event["event_id"]


def test_duplicate_event_returns_conflict():
    event = {
        "event_id": f"API_DUPLICATE_EVENT_{uuid4().hex}",
        "timestamp": "2026-09-01T10:41:00Z",
        "source": "email",
        "event_type": "email_received",
        "description": "Duplicate test event",
        "confidence": 0.8,
    }

    first_response = client.post(
        "/events",
        json=event,
    )

    second_response = client.post(
        "/events",
        json=event,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409


def test_invalid_timestamp_returns_validation_error():
    event = {
        "event_id": f"INVALID_TIMESTAMP_{uuid4().hex}",
        "timestamp": "not-a-timestamp",
        "source": "email",
        "event_type": "email_received",
        "description": "Invalid timestamp test",
        "confidence": 0.8,
    }

    response = client.post(
        "/events",
        json=event,
    )

    assert response.status_code == 422


def test_invalid_source_returns_validation_error():
    event = {
        "event_id": f"INVALID_SOURCE_{uuid4().hex}",
        "timestamp": "2026-09-01T10:42:00Z",
        "source": "unknown_source",
        "event_type": "email_received",
        "description": "Invalid source test",
        "confidence": 0.8,
    }

    response = client.post(
        "/events",
        json=event,
    )

    assert response.status_code == 422


def test_invalid_confidence_returns_validation_error():
    event = {
        "event_id": f"INVALID_CONFIDENCE_{uuid4().hex}",
        "timestamp": "2026-09-01T10:43:00Z",
        "source": "email",
        "event_type": "email_received",
        "description": "Invalid confidence test",
        "confidence": 1.5,
    }

    response = client.post(
        "/events",
        json=event,
    )

    assert response.status_code == 422


def test_timeline_returns_events_in_chronological_order():
    response = client.get("/timeline")

    assert response.status_code == 200

    events = response.json()

    timestamps = [
        event["timestamp"]
        for event in events
    ]

    assert timestamps == sorted(timestamps)


def test_incidents_returns_investigation_results():
    response = client.get("/incidents")

    assert response.status_code == 200

    incidents = response.json()

    assert isinstance(incidents, list)

    if incidents:
        incident = incidents[0]

        assert "incident_id" in incident
        assert "event_ids" in incident
        assert "event_count" in incident
        assert "first_seen" in incident
        assert "last_seen" in incident
        assert "sources" in incident
        assert "relationship_count" in incident
        assert "max_correlation_score" in incident
        assert "severity" in incident
        assert "mitre_techniques" in incident
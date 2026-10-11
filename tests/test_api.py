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

def test_get_incident_by_id():
    incidents_response = client.get("/incidents")

    assert incidents_response.status_code == 200

    incidents = incidents_response.json()

    if not incidents:
        return

    incident_id = incidents[0]["incident_id"]

    response = client.get(
        f"/incidents/{incident_id}"
    )

    assert response.status_code == 200

    incident = response.json()

    assert incident["incident_id"] == incident_id
    assert "event_ids" in incident
    assert "severity" in incident
    assert "mitre_techniques" in incident


def test_get_unknown_incident_returns_not_found():
    response = client.get(
        "/incidents/INC999999"
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Incident 'INC999999' not found."
    }


def make_api_event():
    return {
        "event_id": f"EVIDENCE_API_EVENT_{uuid4().hex}",
        "timestamp": "2026-09-01T10:40:00Z",
        "source": "email",
        "event_type": "email_received",
        "description": "Evidence API integration test",
        "confidence": 0.8,
    }


def make_api_evidence():
    return {
        "evidence_id": f"EVD_{uuid4().hex}",
        "artifact_type": "email",
        "source_reference": "case-files/email-001.eml",
        "sha256": "a" * 64,
        "hash_algorithm": "SHA-256",
        "acquisition_method": "mailbox_export",
        "acquired_at": "2026-09-01T10:35:00Z",
        "acquired_by": "analyst-01",
        "verification_status": "not_verified",
        "metadata": {"case_id": "CASE001"},
    }


def test_create_and_get_evidence():
    evidence = make_api_evidence()

    created = client.post("/evidence", json=evidence)

    assert created.status_code == 201
    assert created.json()["evidence_id"] == evidence["evidence_id"]
    assert created.json()["metadata"] == {"case_id": "CASE001"}

    fetched = client.get(f"/evidence/{evidence['evidence_id']}")

    assert fetched.status_code == 200
    assert fetched.json()["sha256"] == evidence["sha256"]


def test_duplicate_evidence_returns_conflict():
    evidence = make_api_evidence()

    first = client.post("/evidence", json=evidence)
    second = client.post("/evidence", json=evidence)

    assert first.status_code == 201
    assert second.status_code == 409


def test_invalid_sha256_returns_validation_error():
    evidence = make_api_evidence()
    evidence["sha256"] = "not-a-valid-sha256"

    response = client.post("/evidence", json=evidence)

    assert response.status_code == 422


def test_event_evidence_link_and_retrieval():
    event = make_api_event()
    evidence = make_api_evidence()

    event_response = client.post("/events", json=event)
    evidence_response = client.post("/evidence", json=evidence)

    assert event_response.status_code == 201
    assert evidence_response.status_code == 201

    linked = client.post(
        f"/events/{event['event_id']}/evidence/{evidence['evidence_id']}",
        json={"relationship": "supports"},
    )

    assert linked.status_code == 201
    assert linked.json()["relationship"] == "supports"

    retrieved = client.get(
        f"/events/{event['event_id']}/evidence"
    )

    assert retrieved.status_code == 200
    assert len(retrieved.json()) == 1
    assert retrieved.json()[0]["evidence_id"] == evidence["evidence_id"]


def test_unknown_evidence_returns_not_found():
    response = client.get("/evidence/UNKNOWN_EVIDENCE_ID")

    assert response.status_code == 404


def test_incident_evidence_returns_linked_evidence():
    suffix = uuid4().hex

    event_one = make_api_event()
    event_one.update({
        "event_id": f"INC_EVIDENCE_A_{suffix}",
        "user": f"incident_user_{suffix}",
        "timestamp": "2026-09-01T10:40:00Z",
    })

    event_two = make_api_event()
    event_two.update({
        "event_id": f"INC_EVIDENCE_B_{suffix}",
        "user": f"incident_user_{suffix}",
        "timestamp": "2026-09-01T10:41:00Z",
    })

    evidence = make_api_evidence()

    assert client.post("/events", json=event_one).status_code == 201
    assert client.post("/events", json=event_two).status_code == 201
    assert client.post("/evidence", json=evidence).status_code == 201

    for event in (event_one, event_two):
        response = client.post(
            f"/events/{event['event_id']}/evidence/"
            f"{evidence['evidence_id']}",
            json={"relationship": "supports"},
        )
        assert response.status_code == 201

    incidents_response = client.get("/incidents")
    assert incidents_response.status_code == 200

    incident = next(
        (
            item for item in incidents_response.json()
            if event_one["event_id"] in item["event_ids"]
            and event_two["event_id"] in item["event_ids"]
        ),
        None,
    )
    assert incident is not None

    response = client.get(
        f"/incidents/{incident['incident_id']}/evidence"
    )

    assert response.status_code == 200
    result = response.json()
    assert result["incident_id"] == incident["incident_id"]

    matching = [
        item for item in result["evidence"]
        if item["evidence_id"] == evidence["evidence_id"]
    ]
    assert len(matching) == 1

    linked_event_ids = {
        link["event_id"]
        for link in matching[0]["event_links"]
    }
    assert linked_event_ids == {
        event_one["event_id"],
        event_two["event_id"],
    }


def test_incident_evidence_unknown_incident_returns_not_found():
    response = client.get(
        "/incidents/INC_DOES_NOT_EXIST/evidence"
    )

    assert response.status_code == 404

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api import database
from src.api import main


@pytest.fixture
def client(monkeypatch):
    """Create a temporary database for each API test."""
    with tempfile.TemporaryDirectory() as temp_directory:
        temp_path = Path(temp_directory)

        monkeypatch.setattr(database, "DATA_DIR", temp_path)
        monkeypatch.setattr(
            database,
            "DATABASE_PATH",
            temp_path / "test_evidencefusion.db"
        )

        database.initialize_database()

        monkeypatch.setattr(main, "get_events", database.get_events)
        monkeypatch.setattr(main, "insert_event", database.insert_event)

        with TestClient(main.app) as test_client:
            yield test_client

        connection = database.get_connection()
        connection.close()


def test_root(client):
    """Verify the root endpoint."""
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["project"] == "EvidenceFusion"


def test_health_check(client):
    """Verify the health endpoint."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_get_events(client):
    """Verify that events can be retrieved."""
    response = client.get("/events")

    assert response.status_code == 200
    assert response.json() == []


def test_create_event(client):
    """Verify that a new event can be created."""
    event = {
        "event_id": "TEST_API_001",
        "timestamp": "2026-09-01T10:40:00Z",
        "source": "system",
        "event_type": "process_created",
        "user": "test_user",
        "host": "TEST-PC",
        "source_ip": None,
        "destination_ip": None,
        "domain": None,
        "artifact": "test_process.exe",
        "hash": None,
        "description": "Test process creation event",
        "confidence": 0.95
    }

    response = client.post("/events", json=event)

    assert response.status_code == 201

    data = response.json()

    assert data["event_id"] == "TEST_API_001"
    assert data["source"] == "system"
    assert data["event_type"] == "process_created"
    assert data["confidence"] == 0.95


def test_duplicate_event(client):
    """Verify that duplicate event IDs are rejected."""
    event = {
        "event_id": "TEST_API_DUPLICATE",
        "timestamp": "2026-09-01T10:45:00Z",
        "source": "system",
        "event_type": "login",
        "user": "test_user",
        "host": "TEST-PC",
        "source_ip": None,
        "destination_ip": None,
        "domain": None,
        "artifact": None,
        "hash": None,
        "description": "Test duplicate event",
        "confidence": 0.80
    }

    first_response = client.post("/events", json=event)
    second_response = client.post("/events", json=event)

    assert first_response.status_code == 201
    assert second_response.status_code == 409
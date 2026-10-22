from fastapi.testclient import TestClient

from src.api import main


client = TestClient(main.app)


def test_import_dataset_records_are_idempotent_and_keep_provenance(monkeypatch):
    sample = {
        "read_only": True,
        "dataset": "CICIDS2017",
        "total_records": 1,
        "limit": 1,
        "offset": 0,
        "records": [{
            "event_id": "external-row-7",
            "dataset": "CICIDS2017",
            "source": "network",
            "event_type": "benchmark_network_record",
            "original_label": "BENIGN",
            "label_semantics": "network traffic label",
            "source_row_number": 7,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "metadata": {"flow_id": "flow-7"},
        }],
    }
    monkeypatch.setattr(main, "get_dataset_records", lambda **kwargs: sample)

    first = client.post(
        "/datasets/import-to-events?dataset=CICIDS2017&limit=1"
    )
    assert first.status_code == 200
    body = first.json()
    assert body["created_count"] == 1
    assert body["skipped_existing_count"] == 0

    second = client.post(
        "/datasets/import-to-events?dataset=CICIDS2017&limit=1"
    )
    assert second.status_code == 200
    assert second.json()["created_count"] == 0
    assert second.json()["skipped_existing_count"] == 1

    events = client.get("/events").json()
    imported = [event for event in events if event["event_id"] == "DATA-CICIDS2017-000007"]
    assert len(imported) == 1
    assert imported[0]["source"] == "network"
    assert "BENCHMARK REVIEW CASE" in imported[0]["description"]
    assert "original_label" in imported[0]["artifact"]
    assert "flow-7" in imported[0]["artifact"]

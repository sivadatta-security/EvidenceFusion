import sqlite3

import pytest

from src.ingestion.dataset_query import (
    DatasetDatabaseUnavailable,
    get_dataset_records,
    get_dataset_summary,
)


def make_database(path):
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE imported_records (
                event_id TEXT PRIMARY KEY, dataset TEXT NOT NULL, source TEXT NOT NULL,
                event_type TEXT NOT NULL, original_label TEXT NOT NULL,
                label_semantics TEXT NOT NULL, source_row_number INTEGER NOT NULL,
                timestamp TEXT, metadata_json TEXT NOT NULL, imported_at TEXT NOT NULL
            );
            CREATE TABLE import_manifest (
                dataset TEXT PRIMARY KEY, source_filename TEXT NOT NULL,
                selected_count INTEGER NOT NULL, sample_seed INTEGER NOT NULL,
                imported_at TEXT NOT NULL
            );
            INSERT INTO imported_records VALUES
                ('CIC-1','CICIDS2017','network','BENIGN','BENIGN','traffic label',2,
                 '2017-01-01T00:00:00','{"source_ip":"192.0.2.1"}','2026-01-01T00:00:00+00:00'),
                ('FERB-1','FERB','email','email_dataset_record','1','unverified',3,
                 NULL,'{"url_count":"1"}','2026-01-01T00:00:00+00:00');
            INSERT INTO import_manifest VALUES
                ('CICIDS2017','network.csv',1,123,'2026-01-01T00:00:00+00:00'),
                ('FERB','ferb.csv',1,456,'2026-01-01T00:00:00+00:00');
            """
        )


def test_summary_reports_counts_and_keeps_benchmark_isolated(tmp_path):
    path = tmp_path / "sample.db"
    make_database(path)

    result = get_dataset_summary(path)

    assert result["read_only"] is True
    assert result["total_records"] == 2
    assert {item["dataset"]: item["record_count"] for item in result["datasets"]} == {
        "CICIDS2017": 1, "FERB": 1
    }
    assert "not automatically treated as confirmed incidents" in result["note"]


def test_records_are_paginated_and_metadata_is_decoded(tmp_path):
    path = tmp_path / "sample.db"
    make_database(path)

    result = get_dataset_records(dataset="cicids2017", limit=1, offset=0, database_path=path)

    assert result["total_records"] == 1
    assert result["records"][0]["metadata"]["source_ip"] == "192.0.2.1"
    assert result["read_only"] is True


def test_invalid_dataset_is_rejected(tmp_path):
    path = tmp_path / "sample.db"
    make_database(path)
    with pytest.raises(ValueError):
        get_dataset_records(dataset="unknown", database_path=path)


def test_missing_dataset_database_is_reported(tmp_path):
    with pytest.raises(DatasetDatabaseUnavailable):
        get_dataset_summary(tmp_path / "missing.db")

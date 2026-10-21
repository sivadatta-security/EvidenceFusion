"""Tests for LANL authentication benchmark ingestion."""

import csv
import sqlite3

import pytest

from src.ingestion.dataset_importer import (
    create_database,
    sample_lanl_authentication,
)
from src.ingestion.dataset_query import get_dataset_records, get_dataset_summary


def write_rows(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)


def test_lanl_sampling_preserves_relative_time_and_matches_reference(tmp_path):
    auth_path = tmp_path / "auth.txt"
    redteam_path = tmp_path / "redteam.txt"
    write_rows(auth_path, [
        ["10", "U1", "U2", "C1", "C2", "Kerberos", "Network", "LogOn", "Success"],
        ["20", "U3", "U4", "C3", "C4", "NTLM", "Network", "LogOn", "Failure"],
    ])
    write_rows(redteam_path, [["10", "U1", "C1", "C2"]])

    rows = sample_lanl_authentication(auth_path, redteam_path, limit=10)

    assert len(rows) == 2
    matched = next(item for item in rows if item["row"]["time_seconds"] == "10")
    unmatched = next(item for item in rows if item["row"]["time_seconds"] == "20")
    assert matched["redteam_match"] is True
    assert unmatched["redteam_match"] is False
    assert matched["row"]["time_seconds"] == "10"


def test_lanl_empty_or_invalid_auth_file_fails_closed(tmp_path):
    auth_path = tmp_path / "auth.txt"
    redteam_path = tmp_path / "redteam.txt"
    write_rows(auth_path, [["not", "a", "valid", "nine", "column", "row"]])
    write_rows(redteam_path, [])

    with pytest.raises(ValueError, match="no valid 9-column"):
        sample_lanl_authentication(auth_path, redteam_path)


def test_dataset_query_reads_lanl_when_present_in_manifest(tmp_path):
    database_path = tmp_path / "external.db"
    records = [{
        "event_id": "LANL-TEST",
        "dataset": "LANL_AUTH",
        "source": "authentication",
        "event_type": "auth_activity",
        "original_label": "no_exact_redteam_match",
        "label_semantics": "no exact redteam tuple match; NOT a benign label",
        "source_row_number": 1,
        "timestamp": None,
        "metadata_json": '{"time_seconds":"10","redteam_reference_match":false}',
    }]
    create_database(database_path, records)

    summary = get_dataset_summary(database_path)
    page = get_dataset_records("lanl_auth", limit=10, database_path=database_path)

    assert summary["total_records"] == 1
    assert summary["datasets"] == [{"dataset": "LANL_AUTH", "record_count": 1}]
    assert page["records"][0]["metadata"]["time_seconds"] == "10"
    assert page["records"][0]["label_semantics"].endswith("NOT a benign label")

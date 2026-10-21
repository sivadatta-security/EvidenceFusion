
import csv
import sqlite3

import pytest

from src.ingestion.dataset_importer import (
    build_records,
    classify_network_label,
    create_database,
)


def write_csv(path, headers, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def make_network_row(label, index):
    return {
        "Flow ID": f"flow-{index}",
        " Source IP": f"192.0.2.{(index % 250) + 1}",
        " Source Port": str(1000 + index % 50000),
        " Destination IP": "198.51.100.10",
        " Destination Port": "443",
        " Protocol": "6",
        " Timestamp": "2017-07-06 12:00:00",
        " Flow Duration": "1000",
        " Total Fwd Packets": "2",
        " Total Backward Packets": "3",
        " Flow Bytes/s": "100",
        " Flow Packets/s": "5",
        " Label": label,
    }


def make_email_row(label, index):
    return {
        "sender": f"sender-{index}",
        "sender_domain": "sender.example",
        "receiver": f"receiver-{index}",
        "receiver_domain": "receiver.example",
        "date": "2026-01-02",
        "subject": "Test subject",
        "content_types": "text/plain",
        "body": "Do not import the full email body",
        "urls": "https://example.test/",
        "url_count": "1",
        "url_length_max": "22",
        "url_length_avg": "22",
        "url_subdom_max": "1",
        "url_subdom_avg": "1",
        "attachment_count": "0",
        "has_attachments": "false",
        "attachment_types": "",
        "attachment_size_max": "0",
        "attachment_size_avg": "0",
        "language": "en",
        "original_filename": f"mail-{index}.eml",
        "label": str(label),
    }


def create_test_csvs(tmp_path):
    network_path = tmp_path / "network.csv"
    email_path = tmp_path / "ferb.csv"

    network_headers = list(make_network_row("BENIGN", 0))
    network_rows = []
    categories = [
        ("BENIGN", 140),
        ("Web Attack - Brute Force", 20),
        ("Web Attack - XSS", 15),
        ("Web Attack - Sql Injection", 8),
    ]
    index = 0
    for label, count in categories:
        for _ in range(count):
            network_rows.append(make_network_row(label, index))
            index += 1
    write_csv(network_path, network_headers, network_rows)

    email_headers = list(make_email_row(0, 0))
    email_rows = [
        make_email_row(label, index)
        for label in (0, 1)
        for index in range(60)
    ]
    write_csv(email_path, email_headers, email_rows)

    return network_path, email_path


def test_network_label_classification_handles_encoding_variants():
    assert classify_network_label("BENIGN") == "BENIGN"
    assert classify_network_label("Web Attack - Brute Force") == "BRUTE_FORCE"
    assert classify_network_label("Web Attack � XSS") == "XSS"
    assert (
        classify_network_label("Web Attack � Sql Injection")
        == "SQL_INJECTION"
    )
    assert classify_network_label("unknown") is None


def test_build_records_selects_exact_250_and_preserves_labels(tmp_path):
    network_path, email_path = create_test_csvs(tmp_path)

    records = build_records(network_path, email_path)

    assert len(records) == 250
    assert sum(row["dataset"] == "CICIDS2017" for row in records) == 150
    assert sum(row["dataset"] == "FERB" for row in records) == 100

    network_counts = {}
    for row in records:
        if row["dataset"] == "CICIDS2017":
            network_counts[row["event_type"]] = (
                network_counts.get(row["event_type"], 0) + 1
            )

    assert network_counts == {
        "BENIGN": 120,
        "BRUTE_FORCE": 15,
        "XSS": 10,
        "SQL_INJECTION": 5,
    }

    email_labels = [
        row["original_label"]
        for row in records
        if row["dataset"] == "FERB"
    ]
    assert email_labels.count("0") == 50
    assert email_labels.count("1") == 50
    assert all(
        row["label_semantics"].startswith("unverified")
        for row in records
        if row["dataset"] == "FERB"
    )


def test_sampling_is_reproducible(tmp_path):
    network_path, email_path = create_test_csvs(tmp_path)

    first = build_records(network_path, email_path)
    second = build_records(network_path, email_path)

    assert [row["event_id"] for row in first] == [
        row["event_id"] for row in second
    ]


def test_database_is_separate_and_keeps_metadata(tmp_path):
    network_path, email_path = create_test_csvs(tmp_path)
    output_path = tmp_path / "external_dataset_demo.db"
    records = build_records(network_path, email_path)

    create_database(output_path, records)

    with sqlite3.connect(output_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM imported_records"
        ).fetchone()[0]
        datasets = dict(connection.execute(
            "SELECT dataset, selected_count FROM import_manifest"
        ).fetchall())
        email_record = connection.execute(
            """
            SELECT original_label, label_semantics, metadata_json
            FROM imported_records
            WHERE dataset = 'FERB'
            LIMIT 1
            """
        ).fetchone()

    assert count == 250
    assert datasets == {"CICIDS2017": 150, "FERB": 100}
    assert email_record[0] in {"0", "1"}
    assert "unverified" in email_record[1]
    assert "Do not import the full email body" not in email_record[2]
    assert "sender-0" not in email_record[2]


def test_database_creation_refuses_to_overwrite(tmp_path):
    output_path = tmp_path / "existing.db"
    output_path.write_bytes(b"keep this file unchanged")

    with pytest.raises(FileExistsError):
        create_database(output_path, [])

    assert output_path.read_bytes() == b"keep this file unchanged"

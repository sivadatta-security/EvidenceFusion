import sqlite3

import pytest

from src.demo.seed_demo import (
    TARGET_CASES,
    build_demo_events,
    create_demo_database,
)


def _row(dataset, row_number, label, semantics, event_type, metadata=None):
    return {
        "event_id": f"{dataset}-{row_number}",
        "dataset": dataset,
        "source": "network" if dataset == "CICIDS2017" else "email",
        "event_type": event_type,
        "original_label": label,
        "label_semantics": semantics,
        "source_row_number": row_number,
        "timestamp": None,
        "metadata": metadata or {},
    }


def test_demo_builder_creates_exactly_100_cases_and_marks_provenance():
    rows = {
        "CICIDS2017": [
            _row("CICIDS2017", i, "Brute Force", "CICIDS2017 traffic label", "BRUTE_FORCE")
            for i in range(1, 36)
        ],
        "FERB": [
            _row("FERB", i, str(i % 2), "unverified; original dataset label retained", "email_dataset_record")
            for i in range(1, 26)
        ],
        "LANL_AUTH": [
            _row("LANL_AUTH", i, "no_exact_redteam_match", "no exact redteam tuple match; NOT a benign label", "auth_activity")
            for i in range(1, 26)
        ],
    }

    events, summary = build_demo_events(rows)

    assert summary["target_cases"] == TARGET_CASES
    assert len(summary["cases"]) == 100
    assert summary["benchmark_case_count"] == 70
    assert summary["synthetic_case_count"] == 30
    assert len(events) == 70 + 30 * 2
    assert all("not a confirmed real-world incident" in e["description"].lower()
               for e in events if e["event_id"].startswith("DEMO-BENCH-"))
    assert all("SYNTHETIC" in e["description"] for e in events if e["event_id"].startswith("DEMO-SYN-"))


def test_demo_builder_fills_missing_datasets_with_synthetic_cases():
    events, summary = build_demo_events({
        "CICIDS2017": [
            _row("CICIDS2017", i, "XSS", "CICIDS2017 traffic label", "XSS")
            for i in range(1, 4)
        ]
    })

    assert len(summary["cases"]) == 100
    assert summary["benchmark_case_count"] == 3
    assert summary["synthetic_case_count"] == 97
    assert len(events) == 3 + 97 * 2


def test_demo_database_refuses_to_overwrite_existing_file(tmp_path):
    dataset_db = tmp_path / "datasets.db"
    output_db = tmp_path / "demo.db"
    connection = sqlite3.connect(dataset_db)
    connection.executescript(
        """
        CREATE TABLE import_manifest (
            dataset TEXT PRIMARY KEY,
            source_filename TEXT NOT NULL,
            selected_count INTEGER NOT NULL,
            sample_seed INTEGER NOT NULL,
            imported_at TEXT NOT NULL
        );
        CREATE TABLE imported_records (
            event_id TEXT PRIMARY KEY,
            dataset TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            original_label TEXT NOT NULL,
            label_semantics TEXT NOT NULL,
            source_row_number INTEGER NOT NULL,
            timestamp TEXT,
            metadata_json TEXT NOT NULL
        );
        INSERT INTO import_manifest VALUES ('CICIDS2017','test.csv',1,1,'now');
        INSERT INTO imported_records VALUES (
            'CIC-1','CICIDS2017','network','XSS','XSS',
            'CICIDS2017 traffic label',1,NULL,'{}'
        );
        """
    )
    connection.commit()
    connection.close()

    first = create_demo_database(dataset_db, output_db)
    assert first["target_cases"] == 100
    assert output_db.is_file()
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        create_demo_database(dataset_db, output_db)


def test_synthetic_events_form_separate_correlated_clusters():
    from src.correlation.engine import build_incident_clusters

    events, summary = build_demo_events({})
    synthetic_events = [e for e in events if e["event_id"].startswith("DEMO-SYN-")]
    clusters = build_incident_clusters(synthetic_events)

    assert len(clusters) == summary["synthetic_case_count"]
    assert all(len(cluster) == 2 for cluster in clusters)

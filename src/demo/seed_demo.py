"""Build a reproducible, isolated 100-case EvidenceFusion demo database.

Benchmark rows remain labelled as review cases, not confirmed incidents.
Synthetic cases are explicitly identified and are designed to exercise correlation.
The script refuses to overwrite an existing output database.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DB = PROJECT_ROOT / "data" / "external_dataset_demo.db"
DEFAULT_OUTPUT_DB = PROJECT_ROOT / "data" / "evidencefusion_demo.db"
TARGET_CASES = 100
MAX_CICIDS_CASES = 30
MAX_FERB_CASES = 20
MAX_LANL_CASES = 20
DEMO_START = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)

SYNTHETIC_SCENARIOS = [
    ("phishing_email", "email", "Suspicious email followed by endpoint command activity", "needs_review"),
    ("powershell_execution", "system", "PowerShell execution requires analyst review", "needs_review"),
    ("process_discovery", "system", "Unexpected process discovery on a workstation", "needs_review"),
    ("account_discovery", "system", "Unusual account enumeration activity", "needs_review"),
    ("scheduled_task_created", "system", "Unexpected scheduled task creation", "needs_review"),
    ("web_c2_connection", "network", "Suspicious outbound web connection", "needs_review"),
    ("command_execution", "system", "Command execution observed after suspicious access", "needs_review"),
    ("brute_force_review", "network", "Repeated authentication failures require review", "synthetic_scenario"),
    ("possible_data_exfiltration", "network", "Unusual outbound data transfer requires validation", "synthetic_scenario"),
    ("suspicious_download", "email", "Email attachment download requires evidence review", "synthetic_scenario"),
]


def _load_benchmark_rows(database_path: str | Path) -> dict[str, list[dict[str, Any]]]:
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(
            f"Benchmark database not found: {path}. Run src.ingestion.dataset_importer "
            "first, using the downloaded CICIDS2017 and FERB CSVs (and optional LANL pair)."
        )

    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        datasets = {
            row["dataset"]
            for row in connection.execute("SELECT dataset FROM import_manifest")
        }
        rows_by_dataset: dict[str, list[dict[str, Any]]] = {}
        for dataset in ("CICIDS2017", "FERB", "LANL_AUTH"):
            if dataset not in datasets:
                continue
            rows = connection.execute(
                """SELECT event_id, dataset, source, event_type, original_label,
                          label_semantics, source_row_number, timestamp, metadata_json
                   FROM imported_records WHERE dataset = ?
                   ORDER BY source_row_number""",
                (dataset,),
            ).fetchall()
            rows_by_dataset[dataset] = [
                {
                    **dict(row),
                    "metadata": json.loads(row["metadata_json"]),
                }
                for row in rows
            ]
        return rows_by_dataset
    finally:
        connection.close()


def _select_benchmark_cases(rows_by_dataset: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Prefer labelled CICIDS attack rows; preserve uncertain labels for review."""
    selected: list[dict[str, Any]] = []
    cicids_attacks = [
        row for row in rows_by_dataset.get("CICIDS2017", [])
        if str(row["original_label"]).strip().casefold() != "benign"
    ]
    selected.extend(cicids_attacks[:MAX_CICIDS_CASES])
    selected.extend(rows_by_dataset.get("FERB", [])[:MAX_FERB_CASES])
    selected.extend(rows_by_dataset.get("LANL_AUTH", [])[:MAX_LANL_CASES])
    return selected[:70]


def _demo_timestamp(index: int, event_offset_minutes: int = 0) -> str:
    """Create an explicitly synthetic presentation timeline for demo records."""
    return (DEMO_START + timedelta(minutes=index * 20 + event_offset_minutes)).isoformat()


def _benchmark_event(row: dict[str, Any], case_number: int) -> dict[str, Any]:
    dataset = row["dataset"]
    original_label = str(row["original_label"])
    metadata = row["metadata"]
    original_timestamp = row.get("timestamp")
    provenance = {
        "demo_case": case_number,
        "record_kind": "benchmark_review_case",
        "dataset": dataset,
        "source_row_number": row["source_row_number"],
        "original_label": original_label,
        "label_semantics": row["label_semantics"],
        "original_timestamp": original_timestamp,
        "metadata": metadata,
    }
    description = (
        "BENCHMARK REVIEW CASE — not a confirmed real-world incident. "
        f"Dataset={dataset}; source row={row['source_row_number']}; "
        f"original label={original_label!r}; label semantics={row['label_semantics']}. "
        "The timestamp below is a synthetic dashboard presentation time; "
        "the original timestamp, if present, is preserved in the artifact provenance JSON."
    )
    if dataset == "CICIDS2017":
        source = "network"
        event_type = row["event_type"] or "benchmark_network_record"
        confidence = 0.65 if original_label.strip().casefold() != "benign" else 0.35
    elif dataset == "FERB":
        source = "email"
        event_type = "email_dataset_review"
        confidence = 0.4
    else:
        source = "system"
        event_type = "authentication_dataset_review"
        confidence = 0.45

    return {
        "event_id": f"DEMO-BENCH-{case_number:03d}",
        "timestamp": _demo_timestamp(case_number),
        "source": source,
        "event_type": event_type,
        "user": None,
        "host": None,
        # Benchmark rows are intentionally not correlated by guessed identifiers.
        "source_ip": None,
        "destination_ip": None,
        "domain": None,
        "artifact": f"benchmark://{dataset}/row/{row['source_row_number']}#"
                    + json.dumps(provenance, sort_keys=True, ensure_ascii=False),
        "hash": None,
        "description": description,
        "confidence": confidence,
    }


def _synthetic_case_events(case_number: int, synthetic_index: int) -> list[dict[str, Any]]:
    scenario_type, first_source, scenario_description, _kind = SYNTHETIC_SCENARIOS[
        synthetic_index % len(SYNTHETIC_SCENARIOS)
    ]
    suffix = f"{case_number:03d}"
    user = f"demo-user-{suffix}"
    host = f"demo-host-{suffix}"
    source_ip = f"198.51.100.{(synthetic_index % 200) + 1}"
    destination_ip = f"203.0.113.{(synthetic_index % 200) + 1}"
    common = {
        "user": user,
        "host": host,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "domain": f"demo-indicator-{suffix}.invalid",
        "hash": None,
        "confidence": 0.6,
    }
    first = {
        **common,
        "event_id": f"DEMO-SYN-{case_number:03d}-A",
        "timestamp": _demo_timestamp(case_number, 0),
        "source": first_source,
        "event_type": scenario_type,
        "artifact": f"synthetic://scenario/{scenario_type}/{suffix}/event-a",
        "description": (
            f"SYNTHETIC TRAINING DATA — case {case_number:03d}. "
            f"{scenario_description}. No real user, host, or indicator is represented."
        ),
    }
    second = {
        **common,
        "event_id": f"DEMO-SYN-{case_number:03d}-B",
        "timestamp": _demo_timestamp(case_number, 2),
        "source": "incident_response",
        "event_type": "incident_response_review",
        "artifact": f"synthetic://scenario/{scenario_type}/{suffix}/event-b",
        "description": (
            f"SYNTHETIC CORROBORATING EVENT — case {case_number:03d}. "
            "Analyst review and evidence validation are required; this is not a real incident."
        ),
    }
    return [first, second]


def build_demo_events(rows_by_dataset: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build exactly 100 demo cases, with all provenance and synthetic status explicit."""
    benchmark_rows = _select_benchmark_cases(rows_by_dataset)
    events: list[dict[str, Any]] = []
    case_manifest: list[dict[str, Any]] = []

    for case_number, row in enumerate(benchmark_rows, start=1):
        events.append(_benchmark_event(row, case_number))
        case_manifest.append({
            "case_number": case_number,
            "kind": "benchmark_review_case",
            "dataset": row["dataset"],
            "source_row_number": row["source_row_number"],
        })

    synthetic_count = TARGET_CASES - len(benchmark_rows)
    for synthetic_index in range(synthetic_count):
        case_number = len(benchmark_rows) + synthetic_index + 1
        events.extend(_synthetic_case_events(case_number, synthetic_index))
        case_manifest.append({
            "case_number": case_number,
            "kind": "synthetic_scenario",
            "scenario": SYNTHETIC_SCENARIOS[synthetic_index % len(SYNTHETIC_SCENARIOS)][0],
        })

    summary = {
        "target_cases": TARGET_CASES,
        "benchmark_case_count": len(benchmark_rows),
        "synthetic_case_count": synthetic_count,
        "cases": case_manifest,
    }
    return events, summary


def create_demo_database(
    dataset_database_path: str | Path = DEFAULT_DATASET_DB,
    output_path: str | Path = DEFAULT_OUTPUT_DB,
) -> dict[str, Any]:
    """Create a separate operational-schema database for the demo; never overwrite."""
    output = Path(output_path).expanduser().resolve()
    if output.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing demo database: {output}. "
            "Choose a new --output path; do not delete databases to retry."
        )

    rows_by_dataset = _load_benchmark_rows(dataset_database_path)
    events, summary = build_demo_events(rows_by_dataset)
    output.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(output)
    try:
        connection.executescript(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user TEXT,
                host TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                domain TEXT,
                artifact TEXT,
                hash TEXT,
                description TEXT NOT NULL,
                confidence REAL NOT NULL
            );
            """
        )
        connection.executemany(
            """INSERT INTO events (
                event_id, timestamp, source, event_type, user, host,
                source_ip, destination_ip, domain, artifact, hash,
                description, confidence
            ) VALUES (
                :event_id, :timestamp, :source, :event_type, :user, :host,
                :source_ip, :destination_ip, :domain, :artifact, :hash,
                :description, :confidence
            )""",
            events,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        raise
    else:
        connection.close()

    source_counts = dict(Counter(event["source"] for event in events))
    summary.update({
        "output_database": str(output),
        "event_count": len(events),
        "event_source_counts": source_counts,
        "dataset_case_counts": dict(Counter(
            case["dataset"] for case in summary["cases"] if "dataset" in case
        )),
        "note": (
            "Benchmark records are review cases, not confirmed real-world incidents. "
            "Synthetic cases use reserved example IP ranges and .invalid domains. "
            "Use this database only as a demo profile."
        ),
    })
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create an isolated EvidenceFusion database with 100 demo investigation cases."
    )
    parser.add_argument("--dataset-db", default=str(DEFAULT_DATASET_DB),
                        help=f"Existing isolated benchmark database (default: {DEFAULT_DATASET_DB})")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_DB),
                        help=f"New demo database; never overwritten (default: {DEFAULT_OUTPUT_DB})")
    args = parser.parse_args(argv)
    summary = create_demo_database(args.dataset_db, args.output)
    print(json.dumps({key: value for key, value in summary.items() if key != "cases"}, indent=2))
    print("Demo case manifest written to the output database event provenance; case list follows.")
    print(json.dumps(summary["cases"], indent=2))
    print("\nStart the dashboard against this isolated database with:")
    print(f'$env:EVIDENCEFUSION_DB_PATH = "{summary["output_database"]}"')
    print("python -m uvicorn src.api.main:app --reload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

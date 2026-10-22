"""Build a reproducible, isolated 100-case EvidenceFusion demo database.

The database is compatible with the app's EVIDENCEFUSION_DB_PATH setting.
Benchmark rows are source observations, not confirmed real-world incidents.
Synthetic companion events are explicitly identified in their descriptions.
"""
import argparse
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "evidencefusion_demo.db"
DEFAULT_DATASET_DB = PROJECT_ROOT / "data" / "external_dataset_demo.db"
SEED = 20261022
CASE_COUNT = 100
SOURCE_TARGETS = (("CICIDS2017", 35), ("FERB", 20), ("LANL_AUTH", 15))


def _load_benchmark_rows(dataset_db: Path) -> dict[str, list[dict]]:
    """Load rows read-only from the isolated importer database if available."""
    result = {name: [] for name, _ in SOURCE_TARGETS}
    if not dataset_db.is_file():
        return result

    connection = sqlite3.connect(dataset_db.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"imported_records", "import_manifest"}.issubset(tables):
            raise ValueError(f"{dataset_db} is not an EvidenceFusion dataset-import database")
        for dataset, _ in SOURCE_TARGETS:
            rows = connection.execute(
                """SELECT event_id, source, event_type, original_label,
                          label_semantics, source_row_number, timestamp, metadata_json
                   FROM imported_records WHERE dataset = ?
                   ORDER BY source_row_number""",
                (dataset,),
            ).fetchall()
            result[dataset] = [
                {
                    "event_id": row[0], "source": row[1], "event_type": row[2],
                    "original_label": row[3], "label_semantics": row[4],
                    "source_row_number": row[5], "timestamp": row[6],
                    "metadata": json.loads(row[7]),
                }
                for row in rows
            ]
    finally:
        connection.close()
    return result


def _schema(connection: sqlite3.Connection) -> None:
    """Create the compatible application schema in a new isolated database."""
    connection.executescript(
        """
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
            source TEXT NOT NULL, event_type TEXT NOT NULL, user TEXT,
            host TEXT, source_ip TEXT, destination_ip TEXT, domain TEXT,
            artifact TEXT, hash TEXT, description TEXT NOT NULL,
            confidence REAL NOT NULL
        );
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY, artifact_type TEXT NOT NULL,
            source_reference TEXT NOT NULL, sha256 TEXT, hash_algorithm TEXT,
            acquisition_method TEXT, acquired_at TEXT, acquired_by TEXT,
            verification_status TEXT NOT NULL DEFAULT 'not_verified',
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE event_evidence (
            event_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
            relationship TEXT NOT NULL DEFAULT 'supports',
            PRIMARY KEY (event_id, evidence_id),
            FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
        );
        CREATE TABLE custody_audit (
            audit_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL,
            action TEXT NOT NULL, actor TEXT NOT NULL, occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE RESTRICT
        );
        CREATE TABLE demo_case_manifest (
            case_id TEXT PRIMARY KEY, case_kind TEXT NOT NULL,
            source_dataset TEXT NOT NULL, source_row_number INTEGER,
            source_event_id TEXT, provenance_json TEXT NOT NULL,
            seed INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        """
    )


def build_demo_events(dataset_db: Path | None = None) -> tuple[list[dict], list[dict]]:
    """Create exactly 100 isolated two-event cases with transparent provenance."""
    benchmark = _load_benchmark_rows(dataset_db or DEFAULT_DATASET_DB)
    rng = random.Random(SEED)
    now = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
    events: list[dict] = []
    manifest: list[dict] = []

    selected: list[tuple[str, dict]] = []
    for dataset, target in SOURCE_TARGETS:
        rows = benchmark.get(dataset, [])
        rng.shuffle(rows)
        selected.extend((dataset, row) for row in rows[:target])

    # If an input dataset was not imported, its allocation becomes synthetic.
    # This keeps the demo runnable without pretending missing datasets were used.
    for case_number in range(1, CASE_COUNT + 1):
        case_id = f"DEMO{case_number:03d}"
        if case_number <= len(selected):
            dataset, row = selected[case_number - 1]
            case_kind = "benchmark_observation_with_synthetic_context"
            source = {"CICIDS2017": "network", "FERB": "email", "LANL_AUTH": "system"}[dataset]
            original_type = row["event_type"]
            original_label = row["original_label"]
            row_number = row["source_row_number"]
            source_event_id = row["event_id"]
            provenance = {
                "dataset": dataset,
                "source_row_number": row_number,
                "source_event_id": source_event_id,
                "original_label": original_label,
                "label_semantics": row["label_semantics"],
                "benchmark_is_confirmed_incident": False,
            }
            primary_description = (
                f"DEMO BENCHMARK OBSERVATION from {dataset}, source row {row_number}. "
                f"Original label: {original_label!r}. This observation is not by itself "
                "a confirmed incident; synthetic companion context is added for demo correlation."
            )
            primary_type = {
                "CICIDS2017": "network_benchmark_observation",
                "FERB": "email_benchmark_observation",
                "LANL_AUTH": "authentication_benchmark_observation",
            }[dataset]
            primary_artifact = f"benchmark:{dataset}:row:{row_number}"
        else:
            dataset = "SYNTHETIC"
            source = "system"
            original_type = "synthetic_scenario"
            original_label = "synthetic_demo_only"
            row_number = None
            source_event_id = None
            case_kind = "synthetic_scenario"
            provenance = {
                "dataset": "SYNTHETIC",
                "synthetic": True,
                "scenario": "multi-source demo correlation",
                "benchmark_is_confirmed_incident": False,
            }
            primary_description = (
                f"SYNTHETIC DEMO CASE {case_id}: simulated suspicious activity for "
                "testing correlation, triage and reporting only; not a real incident."
            )
            primary_type = "powershell_execution" if case_number % 3 == 0 else "synthetic_suspicious_activity"
            primary_artifact = f"synthetic:{case_id}:event-1"

        # Distinct entities and a 10-minute gap between cases prevent accidental
        # cross-case joins under the current 5-minute correlation window.
        base_time = now + timedelta(minutes=10 * case_number)
        user = f"demo_user_{case_number:03d}"
        host = f"DEMO_HOST_{case_number:03d}"
        source_ip = f"198.51.{(case_number - 1) // 254}.{((case_number - 1) % 254) + 1}"
        domain = f"case-{case_number:03d}.demo.invalid"
        first_id = f"DEMO-{case_id}-E1"
        second_id = f"DEMO-{case_id}-E2"

        events.append({
            "event_id": first_id,
            "timestamp": base_time.isoformat(),
            "source": source,
            "event_type": primary_type,
            "user": user,
            "host": host,
            "source_ip": source_ip,
            "destination_ip": None,
            "domain": domain,
            "artifact": primary_artifact,
            "hash": None,
            "description": primary_description,
            "confidence": 0.55 if dataset != "SYNTHETIC" else 0.35,
        })

        companion_source = "network" if source != "network" else "incident_response"
        companion_type = "web_c2_connection" if case_number % 2 == 0 else "suspicious_network_activity"
        companion_description = (
            f"SYNTHETIC COMPANION for {case_id}: generated context linked by the "
            "demo fixture's user/host/IP and time window. This is simulated evidence, "
            "not an observation from the benchmark dataset."
        )
        events.append({
            "event_id": second_id,
            "timestamp": (base_time + timedelta(minutes=1)).isoformat(),
            "source": companion_source,
            "event_type": companion_type,
            "user": user,
            "host": host,
            "source_ip": source_ip,
            "destination_ip": f"203.0.{(case_number - 1) // 254}.{((case_number - 1) % 254) + 1}",
            "domain": domain,
            "artifact": f"synthetic:{case_id}:companion",
            "hash": None,
            "description": companion_description,
            "confidence": 0.35,
        })
        manifest.append({
            "case_id": case_id,
            "case_kind": case_kind,
            "source_dataset": dataset,
            "source_row_number": row_number,
            "source_event_id": source_event_id,
            "provenance_json": json.dumps(provenance, sort_keys=True),
            "seed": SEED,
        })

    return events, manifest


def create_demo_database(output_path: Path, dataset_db: Path | None = None) -> dict:
    """Create a new compatible demo database; never overwrite any existing file."""
    output_path = Path(output_path).expanduser().resolve()
    if output_path.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing database: {output_path}. Choose a new filename."
        )
    events, manifest = build_demo_events(dataset_db)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(output_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        _schema(connection)
        created_at = datetime.now(timezone.utc).isoformat()
        connection.executemany(
            """INSERT INTO events (
                event_id, timestamp, source, event_type, user, host, source_ip,
                destination_ip, domain, artifact, hash, description, confidence
            ) VALUES (
                :event_id, :timestamp, :source, :event_type, :user, :host,
                :source_ip, :destination_ip, :domain, :artifact, :hash,
                :description, :confidence
            )""",
            events,
        )
        connection.executemany(
            """INSERT INTO demo_case_manifest (
                case_id, case_kind, source_dataset, source_row_number,
                source_event_id, provenance_json, seed, created_at
            ) VALUES (
                :case_id, :case_kind, :source_dataset, :source_row_number,
                :source_event_id, :provenance_json, :seed, :created_at
            )""",
            [{**item, "created_at": created_at} for item in manifest],
        )
        connection.commit()
    except Exception:
        connection.rollback()
        # Deliberately do not delete a partially created DB; preserve it for inspection.
        raise
    finally:
        connection.close()

    return {
        "database": str(output_path),
        "cases": len(manifest),
        "events": len(events),
        "source_counts": {
            name: sum(item["source_dataset"] == name for item in manifest)
            for name in sorted({item["source_dataset"] for item in manifest})
        },
        "synthetic_cases": sum(item["source_dataset"] == "SYNTHETIC" for item in manifest),
        "seed": SEED,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-db", type=Path, default=DEFAULT_DATASET_DB,
                        help="Existing isolated importer DB; read-only and optional.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="New demo DB path; existing files are never overwritten.")
    args = parser.parse_args(argv)
    summary = create_demo_database(args.output, args.dataset_db)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""Safely import a reproducible sample from public network and email datasets.

The output is a standalone SQLite database. This module never connects to
EvidenceFusion's production database and refuses to overwrite an existing file.
"""

import argparse
import csv
import hashlib
import json
import random
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "external_dataset_demo.db"
RANDOM_SEED = 20261018

NETWORK_QUOTAS = {
    "BENIGN": 120,
    "BRUTE_FORCE": 15,
    "XSS": 10,
    "SQL_INJECTION": 5,
}
EMAIL_QUOTAS = {"0": 50, "1": 50}
LANL_SAMPLE_SIZE = 1000
LANL_RANDOM_SEED = RANDOM_SEED + 2


def clean_row(row):
    """Trim CSV header names and normalize missing values."""
    return {
        str(key).strip(): (value.strip() if value is not None else "")
        for key, value in row.items()
        if key is not None
    }


def classify_network_label(label):
    """Map known CICIDS2017 labels to sample categories."""
    value = " ".join((label or "").strip().casefold().split())

    if value == "benign":
        return "BENIGN"
    if "brute force" in value:
        return "BRUTE_FORCE"
    if "xss" in value:
        return "XSS"
    if "sql injection" in value:
        return "SQL_INJECTION"

    return None


def parse_timestamp(value):
    """Return an ISO timestamp when parseable; otherwise preserve raw text."""
    value = (value or "").strip()
    if not value:
        return None

    candidates = [value, value.replace("/", "-")]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                # Preserve unknown timezone semantics instead of claiming UTC.
                return parsed.isoformat()
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue

    return value


def reservoir_sample(path, quotas, classify, seed, encoding="utf-8-sig"):
    """Choose deterministic, bounded-memory samples from each category."""
    rng = random.Random(seed)
    samples = {category: [] for category in quotas}
    seen = Counter()

    with Path(path).open(
        "r", encoding=encoding, errors="replace", newline=""
    ) as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")

        for row_number, raw_row in enumerate(reader, start=2):
            row = clean_row(raw_row)
            category = classify(row)

            if category not in quotas:
                continue

            seen[category] += 1
            quota = quotas[category]
            if quota == 0:
                continue

            bucket = samples[category]
            item = {"row_number": row_number, "row": row}

            if len(bucket) < quota:
                bucket.append(item)
            else:
                replacement = rng.randrange(seen[category])
                if replacement < quota:
                    bucket[replacement] = item

    missing = {
        category: {"required": quota, "found": seen[category]}
        for category, quota in quotas.items()
        if seen[category] < quota
    }
    if missing:
        raise ValueError(
            f"Dataset does not contain enough records for the requested "
            f"sample: {missing}"
        )

    return [
        item
        for category in quotas
        for item in samples[category]
    ]


def network_category(row):
    return classify_network_label(row.get("Label", ""))


def email_category(row):
    # Preserve the dataset's label without assuming what 0 or 1 means.
    label = (row.get("label") or "").strip()
    return label if label in EMAIL_QUOTAS else None


def selected_metadata(dataset, row):
    """Keep useful fields while avoiding full message bodies and addresses."""
    if dataset == "CICIDS2017":
        wanted = [
            "Flow ID",
            " Source IP",
            " Source Port",
            " Destination IP",
            " Destination Port",
            " Protocol",
            " Timestamp",
            " Flow Duration",
            " Total Fwd Packets",
            " Total Backward Packets",
            " Flow Bytes/s",
            " Flow Packets/s",
            " Label",
        ]
        # Header whitespace differs across copies of this dataset.
        normalized = {key.strip(): value for key, value in row.items()}
        return {
            key.strip(): normalized[key.strip()]
            for key in wanted
            if key.strip() in normalized
        }

    # FERB email: do not store sender/receiver addresses or full body content.
    wanted = [
        "sender_domain",
        "receiver_domain",
        "date",
        "content_types",
        "url_count",
        "url_length_max",
        "url_length_avg",
        "attachment_count",
        "has_attachments",
        "attachment_types",
        "attachment_size_max",
        "attachment_size_avg",
        "language",
        "label",
    ]
    return {key: row[key] for key in wanted if key in row}


def stable_event_id(dataset, row_number, row):
    """Generate a stable identifier for this dataset row."""
    identity = json.dumps(
        {"dataset": dataset, "row_number": row_number, "row": row},
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    prefix = {"CICIDS2017": "CIC", "FERB": "FERB", "LANL_AUTH": "LANL"}[dataset]
    return f"{prefix}-{digest.upper()}"



def load_lanl_redteam_keys(path):
    """Load documented LANL red-team tuples for cautious label matching."""
    keys = set()
    with Path(path).open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 4:
                continue
            time_value, user, source_computer, destination_computer = [
                value.strip() for value in row[:4]
            ]
            if time_value and user and source_computer and destination_computer:
                keys.add((time_value, user, source_computer, destination_computer))
    return keys


def sample_lanl_authentication(auth_path, redteam_path, limit=LANL_SAMPLE_SIZE):
    """Reservoir-sample LANL auth rows; preserve relative time, not fake UTC."""
    if limit < 1:
        raise ValueError("LANL sample limit must be at least 1")
    redteam_keys = load_lanl_redteam_keys(redteam_path)
    rng = random.Random(LANL_RANDOM_SEED)
    reservoir = []
    seen = 0
    with Path(auth_path).open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, fields in enumerate(csv.reader(handle), start=1):
            if len(fields) < 9:
                continue
            fields = [value.strip() for value in fields[:9]]
            if not fields[0].isdigit():
                continue
            seen += 1
            row = {
                "time_seconds": fields[0],
                "source_user": fields[1],
                "destination_user": fields[2],
                "source_computer": fields[3],
                "destination_computer": fields[4],
                "authentication_type": fields[5],
                "logon_type": fields[6],
                "authentication_orientation": fields[7],
                "outcome": fields[8],
            }
            key = (fields[0], fields[1], fields[3], fields[4])
            item = {"row_number": row_number, "row": row, "redteam_match": key in redteam_keys}
            if len(reservoir) < limit:
                reservoir.append(item)
            else:
                replacement = rng.randrange(seen)
                if replacement < limit:
                    reservoir[replacement] = item
    if seen == 0:
        raise ValueError("LANL authentication file contains no valid 9-column records")
    return reservoir


def build_records(network_path, email_path, lanl_auth_path=None, lanl_redteam_path=None):
    network = reservoir_sample(
        network_path,
        NETWORK_QUOTAS,
        network_category,
        RANDOM_SEED,
    )
    email = reservoir_sample(
        email_path,
        EMAIL_QUOTAS,
        email_category,
        RANDOM_SEED + 1,
    )

    records = []

    if bool(lanl_auth_path) != bool(lanl_redteam_path):
        raise ValueError("--lanl-auth-csv and --lanl-redteam-csv must be supplied together")

    for item in network:
        row = item["row"]
        label = row.get("Label", "")
        category = network_category(row)
        metadata = selected_metadata("CICIDS2017", row)
        records.append({
            "event_id": stable_event_id(
                "CICIDS2017", item["row_number"], row
            ),
            "dataset": "CICIDS2017",
            "source": "network",
            "event_type": category,
            "original_label": label,
            "label_semantics": "CICIDS2017 traffic label",
            "source_row_number": item["row_number"],
            "timestamp": parse_timestamp(row.get("Timestamp", "")),
            "metadata_json": json.dumps(
                metadata, sort_keys=True, ensure_ascii=False
            ),
        })

    for item in email:
        row = item["row"]
        label = (row.get("label") or "").strip()
        metadata = selected_metadata("FERB", row)
        records.append({
            "event_id": stable_event_id("FERB", item["row_number"], row),
            "dataset": "FERB",
            "source": "email",
            "event_type": "email_dataset_record",
            "original_label": label,
            "label_semantics": "unverified; original dataset label retained",
            "source_row_number": item["row_number"],
            "timestamp": parse_timestamp(row.get("date", "")),
            "metadata_json": json.dumps(
                metadata, sort_keys=True, ensure_ascii=False
            ),
        })


    if lanl_auth_path and lanl_redteam_path:
        for item in sample_lanl_authentication(lanl_auth_path, lanl_redteam_path):
            row = item["row"]
            redteam_match = item["redteam_match"]
            metadata = dict(row)
            metadata["redteam_reference_match"] = redteam_match
            records.append({
                "event_id": stable_event_id("LANL_AUTH", item["row_number"], row),
                "dataset": "LANL_AUTH",
                "source": "authentication",
                "event_type": "auth_activity",
                "original_label": "redteam_reference_match" if redteam_match else "no_exact_redteam_match",
                "label_semantics": (
                    "exact tuple match against LANL redteam reference; analyst validation required"
                    if redteam_match
                    else "no exact redteam tuple match; NOT a benign label"
                ),
                "source_row_number": item["row_number"],
                "timestamp": None,
                "metadata_json": json.dumps(metadata, sort_keys=True, ensure_ascii=False),
            })

    return records


def create_database(output_path, records):
    """Create a new standalone database; never overwrite an existing file."""
    output_path = Path(output_path).expanduser().resolve()

    if output_path.exists():
        raise FileExistsError(
            f"Output already exists; refusing to overwrite it: {output_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    connection = None

    try:
        connection = sqlite3.connect(output_path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE imported_records (
                event_id TEXT PRIMARY KEY,
                dataset TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                original_label TEXT NOT NULL,
                label_semantics TEXT NOT NULL,
                source_row_number INTEGER NOT NULL,
                timestamp TEXT,
                metadata_json TEXT NOT NULL,
                imported_at TEXT NOT NULL
            );

            CREATE TABLE import_manifest (
                dataset TEXT PRIMARY KEY,
                source_filename TEXT NOT NULL,
                selected_count INTEGER NOT NULL,
                sample_seed INTEGER NOT NULL,
                imported_at TEXT NOT NULL
            );
            """
        )

        imported_at = datetime.now(timezone.utc).isoformat()
        connection.executemany(
            """
            INSERT INTO imported_records (
                event_id, dataset, source, event_type, original_label,
                label_semantics, source_row_number, timestamp,
                metadata_json, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record["event_id"],
                    record["dataset"],
                    record["source"],
                    record["event_type"],
                    record["original_label"],
                    record["label_semantics"],
                    record["source_row_number"],
                    record["timestamp"],
                    record["metadata_json"],
                    imported_at,
                )
                for record in records
            ],
        )

        counts = Counter(record["dataset"] for record in records)
        manifest_details = {
            "CICIDS2017": ("CICIDS2017-thursday.pcap_ISCX.csv", RANDOM_SEED),
            "FERB": ("ferb.csv", RANDOM_SEED + 1),
            "LANL_AUTH": ("auth.txt + redteam.txt", LANL_RANDOM_SEED),
        }
        connection.executemany(
            """
            INSERT INTO import_manifest (
                dataset, source_filename, selected_count, sample_seed,
                imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (dataset, manifest_details[dataset][0], count,
                 manifest_details[dataset][1], imported_at)
                for dataset, count in sorted(counts.items())
            ],
        )
        connection.commit()
    except Exception:
        if connection is not None:
            connection.rollback()
        # Leave a partial database visible for investigation rather than
        # silently deleting a file. The user can inspect it before retrying.
        raise
    finally:
        if connection is not None:
            connection.close()

    return output_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create an isolated, reproducible security dataset sample."
    )
    parser.add_argument(
        "--network-csv",
        required=True,
        help="Path to CICIDS2017-thursday.pcap_ISCX.csv",
    )
    parser.add_argument(
        "--email-csv",
        required=True,
        help="Path to ferb.csv",
    )
    parser.add_argument(
        "--lanl-auth-csv",
        help="Optional headerless LANL auth.txt file",
    )
    parser.add_argument(
        "--lanl-redteam-csv",
        help="Optional headerless LANL redteam.txt reference file",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"New output database (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args(argv)

    try:
        records = build_records(args.network_csv, args.email_csv, args.lanl_auth_csv, args.lanl_redteam_csv)
        output = create_database(args.output, records)
    except (OSError, csv.Error, ValueError, sqlite3.Error) as exc:
        print(f"IMPORT FAILED: {exc}", file=sys.stderr)
        return 1

    counts = Counter(
        (record["dataset"], record["event_type"], record["original_label"])
        for record in records
    )
    print(f"Created isolated sample database: {output}")
    print(f"Total records: {len(records)}")
    for dataset, count in sorted(Counter(record["dataset"] for record in records).items()):
        print(f"{dataset} records: {count}")
    print("Network category counts:")
    for category, quota in NETWORK_QUOTAS.items():
        print(f"  {category}: {quota}")
    print("FERB raw label counts:")
    for label, quota in EMAIL_QUOTAS.items():
        print(f"  label {label}: {quota}")
    print("FERB labels remain uninterpreted until their documentation is verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

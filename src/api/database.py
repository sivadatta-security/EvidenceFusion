
import json
import sqlite3
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "evidencefusion.db"


def get_connection():
    """Create a database connection with foreign-key enforcement."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    """Create the event and evidence tables if they do not exist."""
    connection = get_connection()

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
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

            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                artifact_type TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                sha256 TEXT,
                hash_algorithm TEXT,
                acquisition_method TEXT,
                acquired_at TEXT,
                acquired_by TEXT,
                verification_status TEXT NOT NULL
                    DEFAULT 'not_verified',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS event_evidence (
                event_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                relationship TEXT NOT NULL DEFAULT 'supports',
                PRIMARY KEY (event_id, evidence_id),
                FOREIGN KEY (event_id)
                    REFERENCES events(event_id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(evidence_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS custody_audit (
                audit_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(evidence_id) ON DELETE RESTRICT
            );
             """
        )
    finally:
        connection.close()

    print("DATABASE INITIALIZED")
    print("Database:", DATABASE_PATH)


def insert_event(event):
    """Insert a normalized event into the SQLite database."""
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO events (
                event_id, timestamp, source, event_type,
                user, host, source_ip, destination_ip,
                domain, artifact, hash, description, confidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                event["timestamp"],
                event["source"],
                event["event_type"],
                event.get("user"),
                event.get("host"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("domain"),
                event.get("artifact"),
                event.get("hash"),
                event["description"],
                event["confidence"],
            ),
        )
        connection.commit()

        print("EVENT INSERTED")
        print("Event ID:", event["event_id"])
    finally:
        connection.close()


def get_events():
    """Retrieve normalized events as tuples, ordered by timestamp."""
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            SELECT
                event_id, timestamp, source, event_type,
                user, host, source_ip, destination_ip,
                domain, artifact, hash, description, confidence
            FROM events
            ORDER BY timestamp
            """
        )
        return cursor.fetchall()
    finally:
        connection.close()


def insert_evidence(evidence):
    """Register metadata for an original evidence artifact.

    source_reference should identify a managed artifact or its location;
    do not put the artifact's contents into this metadata record.
    """
    metadata_json = json.dumps(
        evidence.get("metadata", {}),
        sort_keys=True,
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id, artifact_type, source_reference,
                sha256, hash_algorithm, acquisition_method,
                acquired_at, acquired_by, verification_status,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence["evidence_id"],
                evidence["artifact_type"],
                evidence["source_reference"],
                evidence.get("sha256"),
                evidence.get("hash_algorithm"),
                evidence.get("acquisition_method"),
                evidence.get("acquired_at"),
                evidence.get("acquired_by"),
                evidence.get("verification_status", "not_verified"),
                metadata_json,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _evidence_row_to_dict(row):
    """Convert an evidence database row to an API-friendly dictionary."""
    if row is None:
        return None

    return {
        "evidence_id": row[0],
        "artifact_type": row[1],
        "source_reference": row[2],
        "sha256": row[3],
        "hash_algorithm": row[4],
        "acquisition_method": row[5],
        "acquired_at": row[6],
        "acquired_by": row[7],
        "verification_status": row[8],
        "metadata": json.loads(row[9]),
    }


def get_evidence(evidence_id):
    """Retrieve one evidence record, or None if it does not exist."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                evidence_id, artifact_type, source_reference,
                sha256, hash_algorithm, acquisition_method,
                acquired_at, acquired_by, verification_status,
                metadata_json
            FROM evidence
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()

        return _evidence_row_to_dict(row)
    finally:
        connection.close()


def link_event_evidence(
    event_id,
    evidence_id,
    relationship="supports",
):
    """Link an existing event to an existing evidence record.

    SQLite foreign-key enforcement rejects missing event/evidence IDs.
    """
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO event_evidence (
                event_id, evidence_id, relationship
            )
            VALUES (?, ?, ?)
            """,
            (event_id, evidence_id, relationship),
        )
        connection.commit()
    finally:
        connection.close()


def get_evidence_for_event(event_id):
    """Retrieve evidence linked to an event, including link relationships."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                e.evidence_id, e.artifact_type, e.source_reference,
                e.sha256, e.hash_algorithm, e.acquisition_method,
                e.acquired_at, e.acquired_by, e.verification_status,
                e.metadata_json, ee.relationship
            FROM event_evidence AS ee
            JOIN evidence AS e
                ON e.evidence_id = ee.evidence_id
            WHERE ee.event_id = ?
            ORDER BY e.evidence_id
            """,
            (event_id,),
        ).fetchall()

        results = []

        for row in rows:
            evidence = _evidence_row_to_dict(row[:10])
            evidence["relationship"] = row[10]
            results.append(evidence)

        return results
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    print("EVENTS FOUND:", len(get_events()))


def register_acquired_evidence(evidence):
    """
    Save acquired evidence and its initial custody audit entry atomically.

    Either both records are committed, or neither is.
    """
    connection = get_connection()

    audit_id = f"AUD-{uuid4().hex[:12].upper()}"
    acquired_at = evidence["acquired_at"]

    details = {
        "source_reference": evidence["source_reference"],
        "sha256": evidence["sha256"],
        "hash_algorithm": evidence["hash_algorithm"],
        "verification_status": evidence["verification_status"],
        "acquisition_method": evidence["acquisition_method"],
    }

    try:
        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id, artifact_type, source_reference,
                sha256, hash_algorithm, acquisition_method,
                acquired_at, acquired_by, verification_status,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence["evidence_id"],
                evidence["artifact_type"],
                evidence["source_reference"],
                evidence["sha256"],
                evidence["hash_algorithm"],
                evidence["acquisition_method"],
                acquired_at,
                evidence["acquired_by"],
                evidence["verification_status"],
                json.dumps(evidence.get("metadata", {}), sort_keys=True),
            ),
        )

        connection.execute(
            """
            INSERT INTO custody_audit (
                audit_id, evidence_id, action, actor,
                occurred_at, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                evidence["evidence_id"],
                "acquisition_completed",
                evidence["acquired_by"],
                acquired_at,
                json.dumps(details, sort_keys=True),
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_evidence(evidence["evidence_id"])


def get_chain_of_custody(evidence_id):
    """Return the recorded custody audit history for one evidence item."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                audit_id, evidence_id, action, actor,
                occurred_at, details_json
            FROM custody_audit
            WHERE evidence_id = ?
            ORDER BY occurred_at, audit_id
            """,
            (evidence_id,),
        ).fetchall()

        return [
            {
                "audit_id": row[0],
                "evidence_id": row[1],
                "action": row[2],
                "actor": row[3],
                "occurred_at": row[4],
                "details": json.loads(row[5]),
            }
            for row in rows
        ]

    finally:
        connection.close()

def record_evidence_verification(evidence_id, actor, result):
    """
    Update the current verification status and append a custody
    audit entry in one database transaction.
    """
    occurred_at = datetime.now(timezone.utc).isoformat()
    audit_id = f"AUD-{uuid4().hex[:12].upper()}"

    details = {
        "expected_sha256": result.get("expected_sha256"),
        "calculated_sha256": result.get("calculated_sha256"),
        "verification_status": result["verification_status"],
        "reason": result.get("reason"),
    }

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE evidence
            SET verification_status = ?
            WHERE evidence_id = ?
            """,
            (result["verification_status"], evidence_id),
        )

        if cursor.rowcount == 0:
            raise ValueError("Evidence record does not exist.")

        connection.execute(
            """
            INSERT INTO custody_audit (
                audit_id, evidence_id, action, actor,
                occurred_at, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                evidence_id,
                "integrity_verification",
                actor,
                occurred_at,
                json.dumps(details, sort_keys=True),
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_evidence(evidence_id)
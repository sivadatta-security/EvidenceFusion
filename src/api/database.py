import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "evidencefusion.db"


def get_connection():
    """Create and return a connection to the EvidenceFusion database."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    return connection


def initialize_database():
    """Create the events table if it does not already exist."""
    connection = get_connection()

    connection.execute(
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
        )
        """
    )

    connection.commit()
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
                event_id,
                timestamp,
                source,
                event_type,
                user,
                host,
                source_ip,
                destination_ip,
                domain,
                artifact,
                hash,
                description,
                confidence
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
    """Retrieve all normalized events from the database."""
    connection = get_connection()

    cursor = connection.execute(
        """
        SELECT
            event_id,
            timestamp,
            source,
            event_type,
            user,
            host,
            source_ip,
            destination_ip,
            domain,
            artifact,
            hash,
            description,
            confidence
        FROM events
        ORDER BY timestamp
        """
    )

    events = cursor.fetchall()

    connection.close()

    return events


if __name__ == "__main__":
    initialize_database()

    events = get_events()

    print("EVENTS FOUND:", len(events))

    for event in events:
        print(event)
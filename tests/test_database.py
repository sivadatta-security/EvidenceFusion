import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.api import database


class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Create an isolated temporary database for each test."""
        self.temp_directory = tempfile.TemporaryDirectory()

        self.original_data_dir = database.DATA_DIR
        self.original_database_path = database.DATABASE_PATH

        database.DATA_DIR = Path(self.temp_directory.name)
        database.DATABASE_PATH = (
            database.DATA_DIR / "test_evidencefusion.db"
        )

        database.initialize_database()

    def tearDown(self):
        """Restore database paths and clean up temporary files."""
        database.DATA_DIR = self.original_data_dir
        database.DATABASE_PATH = self.original_database_path

        self.temp_directory.cleanup()

    def sample_event(self, event_id="TEST001"):
        return {
            "event_id": event_id,
            "timestamp": "2026-09-01T10:30:00Z",
            "source": "email",
            "event_type": "email_received",
            "user": "test_user",
            "host": "TEST-PC",
            "source_ip": None,
            "destination_ip": None,
            "domain": "example.test",
            "artifact": "suspicious_url",
            "hash": None,
            "description": "Test suspicious email",
            "confidence": 0.90,
        }

    def sample_evidence(self, evidence_id="EVD001"):
        return {
            "evidence_id": evidence_id,
            "artifact_type": "email",
            "source_reference": "case-files/email-001.eml",
            "sha256": "a" * 64,
            "hash_algorithm": "SHA-256",
            "acquisition_method": "mailbox_export",
            "acquired_at": "2026-09-01T10:35:00Z",
            "acquired_by": "analyst-01",
            "verification_status": "verified",
            "metadata": {"case_id": "CASE001"},
        }

    def test_empty_database(self):
        """A new database initially contains no events."""
        self.assertEqual(database.get_events(), [])

    def test_insert_and_retrieve_event(self):
        """Existing event storage remains compatible."""
        database.insert_event(self.sample_event())

        events = database.get_events()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "TEST001")
        self.assertEqual(events[0][2], "email")
        self.assertEqual(events[0][3], "email_received")
        self.assertEqual(events[0][4], "test_user")
        self.assertEqual(events[0][5], "TEST-PC")
        self.assertEqual(events[0][8], "example.test")
        self.assertEqual(events[0][12], 0.90)

    def test_insert_and_retrieve_evidence(self):
        """Evidence metadata and JSON metadata are preserved."""
        evidence = self.sample_evidence()

        database.insert_evidence(evidence)
        result = database.get_evidence("EVD001")

        self.assertIsNotNone(result)
        self.assertEqual(result["artifact_type"], "email")
        self.assertEqual(
            result["source_reference"],
            "case-files/email-001.eml",
        )
        self.assertEqual(result["hash_algorithm"], "SHA-256")
        self.assertEqual(result["metadata"], {"case_id": "CASE001"})

    def test_missing_evidence_returns_none(self):
        self.assertIsNone(database.get_evidence("DOES_NOT_EXIST"))

    def test_link_event_to_evidence(self):
        """An event can reference its supporting evidence."""
        database.insert_event(self.sample_event())
        database.insert_evidence(self.sample_evidence())

        database.link_event_evidence("TEST001", "EVD001")

        linked = database.get_evidence_for_event("TEST001")

        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["evidence_id"], "EVD001")
        self.assertEqual(linked[0]["relationship"], "supports")

    def test_event_can_reference_multiple_evidence_records(self):
        database.insert_event(self.sample_event())
        database.insert_evidence(self.sample_evidence("EVD001"))
        database.insert_evidence(self.sample_evidence("EVD002"))

        database.link_event_evidence("TEST001", "EVD001")
        database.link_event_evidence(
            "TEST001",
            "EVD002",
            relationship="corroborates",
        )

        linked = database.get_evidence_for_event("TEST001")

        self.assertEqual(len(linked), 2)
        relationships = {
            item["evidence_id"]: item["relationship"]
            for item in linked
        }
        self.assertEqual(relationships["EVD001"], "supports")
        self.assertEqual(relationships["EVD002"], "corroborates")

    def test_duplicate_evidence_id_is_rejected(self):
        database.insert_evidence(self.sample_evidence())

        with self.assertRaises(sqlite3.IntegrityError):
            database.insert_evidence(self.sample_evidence())

    def test_link_to_missing_event_is_rejected(self):
        database.insert_evidence(self.sample_evidence())

        with self.assertRaises(sqlite3.IntegrityError):
            database.link_event_evidence("MISSING_EVENT", "EVD001")

    def test_link_to_missing_evidence_is_rejected(self):
        database.insert_event(self.sample_event())

        with self.assertRaises(sqlite3.IntegrityError):
            database.link_event_evidence("TEST001", "MISSING_EVIDENCE")


if __name__ == "__main__":
    unittest.main()

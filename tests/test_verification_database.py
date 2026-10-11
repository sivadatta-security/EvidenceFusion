
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from src.api import database


class TestEvidenceVerificationDatabase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "test_evidencefusion.db"

        self.data_patch = patch.object(database, "DATA_DIR", self.data_dir)
        self.db_patch = patch.object(database, "DATABASE_PATH", self.db_path)
        self.data_patch.start()
        self.db_patch.start()
        self.addCleanup(self.data_patch.stop)
        self.addCleanup(self.db_patch.stop)

        database.initialize_database()

        evidence = {
            "evidence_id": "EVD-DB-VERIFY-001",
            "artifact_type": "test_file",
            "source_reference": "data/evidence/sample.txt",
            "sha256": "a" * 64,
            "hash_algorithm": "SHA-256",
            "acquisition_method": "local_file_copy",
            "acquired_at": "2026-10-12T00:00:00+00:00",
            "acquired_by": "test-analyst",
            "verification_status": "not_verified",
            "metadata": {},
        }
        database.register_acquired_evidence(evidence)
                # Ensure the acquisition entry predates verification.
        connection = database.get_connection()
        try:
            connection.execute(
                """
                UPDATE custody_audit
                SET occurred_at = ?
                WHERE evidence_id = ?
                  AND action = 'acquisition_completed'
                """,
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat(),
                    "EVD-DB-VERIFY-001",
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verification_updates_status_and_appends_audit(self):
        result = {
            "expected_sha256": "a" * 64,
            "calculated_sha256": "a" * 64,
            "verification_status": "verified",
            "reason": "Hashes match.",
        }

        updated = database.record_evidence_verification(
            "EVD-DB-VERIFY-001", "analyst-02", result
        )

        self.assertEqual(updated["verification_status"], "verified")

        entries = database.get_chain_of_custody("EVD-DB-VERIFY-001")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[-1]["action"], "integrity_verification")
        self.assertEqual(entries[-1]["actor"], "analyst-02")
        self.assertEqual(
            entries[-1]["details"]["calculated_sha256"], "a" * 64
        )

    def test_failed_verification_is_recorded(self):
        result = {
            "expected_sha256": "a" * 64,
            "calculated_sha256": "b" * 64,
            "verification_status": "failed",
            "reason": "Hashes differ.",
        }

        updated = database.record_evidence_verification(
            "EVD-DB-VERIFY-001", "analyst-02", result
        )

        self.assertEqual(updated["verification_status"], "failed")

        entries = database.get_chain_of_custody("EVD-DB-VERIFY-001")
        self.assertEqual(entries[-1]["details"]["verification_status"], "failed")

    def test_unknown_evidence_cannot_be_recorded(self):
        result = {
            "expected_sha256": "a" * 64,
            "calculated_sha256": "a" * 64,
            "verification_status": "verified",
            "reason": "Hashes match.",
        }

        with self.assertRaises(ValueError):
            database.record_evidence_verification(
                "EVD-UNKNOWN", "analyst-02", result
            )


if __name__ == "__main__":
    unittest.main()
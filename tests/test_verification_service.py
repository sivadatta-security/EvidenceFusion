
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.acquisition.service import (
    sha256_file,
    verify_evidence_integrity,
)


class TestEvidenceVerificationService(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.evidence_dir = self.root / "data" / "evidence"
        self.evidence_dir.mkdir(parents=True)

        self.file_path = self.evidence_dir / "sample.txt"
        self.file_path.write_text("original evidence", encoding="utf-8")

        self.evidence = {
            "evidence_id": "EVD-SERVICE-001",
            "source_reference": "data/evidence/sample.txt",
            "sha256": sha256_file(self.file_path),
            "hash_algorithm": "SHA-256",
        }

        self.root_patch = patch(
            "src.acquisition.service.PROJECT_ROOT", self.root
        )
        self.dir_patch = patch(
            "src.acquisition.service.EVIDENCE_DIR", self.evidence_dir
        )
        self.root_patch.start()
        self.dir_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.dir_patch.stop)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_matching_hash_is_verified(self):
        result = verify_evidence_integrity(self.evidence)

        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(
            result["calculated_sha256"], self.evidence["sha256"]
        )

    def test_modified_file_fails_verification(self):
        self.file_path.write_text("modified evidence", encoding="utf-8")

        result = verify_evidence_integrity(self.evidence)

        self.assertEqual(result["verification_status"], "failed")
        self.assertNotEqual(
            result["calculated_sha256"], self.evidence["sha256"]
        )

    def test_missing_file_is_unavailable(self):
        self.file_path.unlink()

        result = verify_evidence_integrity(self.evidence)

        self.assertEqual(result["verification_status"], "unavailable")
        self.assertIsNone(result["calculated_sha256"])

    def test_path_outside_evidence_directory_is_rejected(self):
        outside_file = self.root / "outside.txt"
        outside_file.write_text("not managed evidence", encoding="utf-8")
        self.evidence["source_reference"] = "outside.txt"

        result = verify_evidence_integrity(self.evidence)

        self.assertEqual(result["verification_status"], "failed")
        self.assertIn("outside managed storage", result["reason"])

    def test_missing_hash_baseline_is_unavailable(self):
        self.evidence["sha256"] = None

        result = verify_evidence_integrity(self.evidence)

        self.assertEqual(result["verification_status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
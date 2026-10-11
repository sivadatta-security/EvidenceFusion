
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.acquisition import service


class TestEvidenceAcquisition(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.incoming = self.root / "incoming"
        self.evidence = self.root / "evidence"

        self.incoming.mkdir()
        self.evidence.mkdir()

        self.source = self.incoming / "sample.txt"
        self.source.write_bytes(b"EvidenceFusion test artifact")

        # Redirect acquisition paths to temporary folders.
        # This prevents tests from modifying the real project evidence folder.
        self.incoming_patch = patch.object(
            service, "INCOMING_DIR", self.incoming
        )
        self.evidence_patch = patch.object(
            service, "EVIDENCE_DIR", self.evidence
        )
        self.root_patch = patch.object(
            service, "PROJECT_ROOT", self.root
        )

        self.incoming_patch.start()
        self.evidence_patch.start()
        self.root_patch.start()

        self.addCleanup(self.incoming_patch.stop)
        self.addCleanup(self.evidence_patch.stop)
        self.addCleanup(self.root_patch.stop)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_acquires_and_hashes_file(self):
        """A copied file should match its source and expected SHA-256."""
        original_bytes = self.source.read_bytes()
        expected_hash = hashlib.sha256(original_bytes).hexdigest()

        result = service.acquire_file(
            self.source,
            acquired_by="test-analyst",
            expected_sha256=expected_hash,
        )

        # The result contains a project-relative evidence reference.
        # Find the actual file in the temporary evidence directory.
        copied_file = self.evidence / Path(
            result["source_reference"]
        ).name

        self.assertTrue(copied_file.is_file())
        self.assertEqual(copied_file.read_bytes(), original_bytes)
        self.assertEqual(result["sha256"], expected_hash)
        self.assertEqual(result["hash_algorithm"], "SHA-256")
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(
            result["acquired_by"], "test-analyst"
        )

        # Confirm that the source file remains unchanged.
        self.assertEqual(self.source.read_bytes(), original_bytes)

    def test_without_expected_hash_is_not_verified(self):
        """Without an independently supplied hash, do not claim verification."""
        result = service.acquire_file(
            self.source,
            acquired_by="test-analyst",
        )

        self.assertEqual(
            result["verification_status"], "not_verified"
        )
        self.assertEqual(result["hash_algorithm"], "SHA-256")
        self.assertTrue(result["sha256"])

    def test_wrong_expected_hash_fails_verification(self):
        """A different expected hash should produce a failed status."""
        result = service.acquire_file(
            self.source,
            acquired_by="test-analyst",
            expected_sha256="0" * 64,
        )

        self.assertEqual(result["verification_status"], "failed")

    def test_rejects_path_outside_incoming_directory(self):
        """Reject a file that is outside the allowed incoming directory."""
        outside = self.root / "outside.txt"
        outside.write_text("not allowed", encoding="utf-8")

        with self.assertRaises(service.AcquisitionError):
            service.acquire_file(
                outside,
                acquired_by="test-analyst",
            )

    def test_rejects_missing_source(self):
        """Reject a source file that does not exist."""
        with self.assertRaises(service.AcquisitionError):
            service.acquire_file(
                self.incoming / "missing.txt",
                acquired_by="test-analyst",
            )

    def test_rejects_invalid_expected_hash(self):
        """Reject an expected hash that is not 64 hexadecimal characters."""
        with self.assertRaises(service.AcquisitionError):
            service.acquire_file(
                self.source,
                acquired_by="test-analyst",
                expected_sha256="invalid",
            )


if __name__ == "__main__":
    unittest.main()
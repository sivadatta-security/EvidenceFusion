
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.main import app


class TestEvidenceVerificationAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.evidence = {
            "evidence_id": "EVD-VERIFY-001",
            "artifact_type": "test_file",
            "source_reference": "data/evidence/sample.txt",
            "sha256": "a" * 64,
            "hash_algorithm": "SHA-256",
            "acquisition_method": "local_file_copy",
            "acquired_at": "2026-10-11T19:00:00+00:00",
            "acquired_by": "test-analyst",
            "verification_status": "not_verified",
            "metadata": {},
        }

    @patch("src.api.main.record_evidence_verification")
    @patch("src.api.main.verify_evidence_integrity")
    @patch("src.api.main.get_evidence")
    def test_successful_verification_is_recorded(
        self, mock_get, mock_verify, mock_record
    ):
        result = {
            "evidence_id": "EVD-VERIFY-001",
            "expected_sha256": "a" * 64,
            "calculated_sha256": "a" * 64,
            "verification_status": "verified",
            "reason": "Current hash matches the stored acquisition hash.",
        }
        mock_get.return_value = self.evidence
        mock_verify.return_value = result
        mock_record.return_value = {
            **self.evidence,
            "verification_status": "verified",
        }

        response = self.client.post(
            "/evidence/EVD-VERIFY-001/verify",
            params={"verified_by": "analyst-01"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["verification"]["verification_status"],
            "verified",
        )
        mock_record.assert_called_once_with(
            "EVD-VERIFY-001", "analyst-01", result
        )

    @patch("src.api.main.record_evidence_verification")
    @patch("src.api.main.verify_evidence_integrity")
    @patch("src.api.main.get_evidence")
    def test_modified_file_is_recorded_as_failed(
        self, mock_get, mock_verify, mock_record
    ):
        result = {
            "evidence_id": "EVD-VERIFY-001",
            "expected_sha256": "a" * 64,
            "calculated_sha256": "b" * 64,
            "verification_status": "failed",
            "reason": "Current hash differs from the stored acquisition hash.",
        }
        mock_get.return_value = self.evidence
        mock_verify.return_value = result
        mock_record.return_value = {
            **self.evidence,
            "verification_status": "failed",
        }

        response = self.client.post(
            "/evidence/EVD-VERIFY-001/verify",
            params={"verified_by": "analyst-01"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["verification"]["verification_status"],
            "failed",
        )
        mock_record.assert_called_once()

    @patch("src.api.main.record_evidence_verification")
    @patch("src.api.main.verify_evidence_integrity")
    @patch("src.api.main.get_evidence")
    def test_missing_file_is_recorded_as_unavailable(
        self, mock_get, mock_verify, mock_record
    ):
        result = {
            "evidence_id": "EVD-VERIFY-001",
            "expected_sha256": "a" * 64,
            "calculated_sha256": None,
            "verification_status": "unavailable",
            "reason": "Evidence file is missing.",
        }
        mock_get.return_value = self.evidence
        mock_verify.return_value = result
        mock_record.return_value = {
            **self.evidence,
            "verification_status": "unavailable",
        }

        response = self.client.post(
            "/evidence/EVD-VERIFY-001/verify",
            params={"verified_by": "analyst-01"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["verification"]["verification_status"],
            "unavailable",
        )
        mock_record.assert_called_once()

    @patch("src.api.main.get_evidence")
    def test_unknown_evidence_returns_404(self, mock_get):
        mock_get.return_value = None

        response = self.client.post(
            "/evidence/EVD-UNKNOWN/verify",
            params={"verified_by": "analyst-01"},
        )

        self.assertEqual(response.status_code, 404)

    def test_blank_investigator_is_rejected(self):
        response = self.client.post(
            "/evidence/EVD-VERIFY-001/verify",
            params={"verified_by": "   "},
        )

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
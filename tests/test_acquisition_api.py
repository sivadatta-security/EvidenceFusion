
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.main import app
from src.acquisition.service import AcquisitionError


class TestEvidenceAcquisitionAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch("src.api.main.register_acquired_evidence")
    @patch("src.api.main.acquire_file")
    def test_acquisition_endpoint_returns_saved_evidence(
        self, mock_acquire, mock_register
    ):
        evidence = {
            "evidence_id": "EVD-API-TEST-001",
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

        mock_acquire.return_value = evidence
        mock_register.return_value = evidence

        response = self.client.post(
            "/evidence/acquire",
            json={
                "filename": "sample.txt",
                "acquired_by": "test-analyst",
                "artifact_type": "test_file",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["evidence_id"], "EVD-API-TEST-001")
        self.assertEqual(
            response.json()["verification_status"], "not_verified"
        )
        mock_acquire.assert_called_once()
        mock_register.assert_called_once_with(evidence)

    @patch("src.api.main.acquire_file")
    def test_acquisition_rejects_missing_source(
        self, mock_acquire
    ):
        mock_acquire.side_effect = AcquisitionError(
            "The source must be an existing file inside data/incoming."
        )

        response = self.client.post(
            "/evidence/acquire",
            json={
                "filename": "missing.txt",
                "acquired_by": "test-analyst",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("existing file", response.json()["detail"])

    @patch("src.api.main.get_chain_of_custody")
    @patch("src.api.main.get_evidence")
    def test_custody_endpoint_returns_audit_entries(
        self, mock_get_evidence, mock_get_custody
    ):
        mock_get_evidence.return_value = {
            "evidence_id": "EVD-API-TEST-002"
        }
        mock_get_custody.return_value = [
            {
                "audit_id": "AUD-API-TEST-001",
                "evidence_id": "EVD-API-TEST-002",
                "action": "acquisition_completed",
                "actor": "test-analyst",
                "occurred_at": "2026-10-11T19:00:00+00:00",
                "details": {"hash_algorithm": "SHA-256"},
            }
        ]

        response = self.client.get(
            "/evidence/EVD-API-TEST-002/custody"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["evidence_id"], "EVD-API-TEST-002"
        )
        self.assertEqual(len(response.json()["audit_entries"]), 1)
        self.assertEqual(
            response.json()["audit_entries"][0]["action"],
            "acquisition_completed",
        )

    @patch("src.api.main.get_evidence")
    def test_custody_endpoint_returns_404_for_unknown_evidence(
        self, mock_get_evidence
    ):
        mock_get_evidence.return_value = None

        response = self.client.get(
            "/evidence/EVD-DOES-NOT-EXIST/custody"
        )

        self.assertEqual(response.status_code, 404)

    @patch("src.api.main.remove_acquired_file")
    @patch("src.api.main.register_acquired_evidence")
    @patch("src.api.main.acquire_file")
    def test_database_failure_triggers_copy_cleanup(
        self, mock_acquire, mock_register, mock_cleanup
    ):
        evidence = {
            "evidence_id": "EVD-API-CLEANUP-001",
            "source_reference": (
                "data/evidence/EVD-API-CLEANUP-001_sample.txt"
            ),
        }

        mock_acquire.return_value = evidence
        mock_register.side_effect = RuntimeError("Database unavailable")

        response = self.client.post(
            "/evidence/acquire",
            json={
                "filename": "sample.txt",
                "acquired_by": "test-analyst",
                "artifact_type": "test_file",
            },
        )

        self.assertEqual(response.status_code, 500)
        mock_cleanup.assert_called_once_with(evidence)



if __name__ == "__main__":
    unittest.main()

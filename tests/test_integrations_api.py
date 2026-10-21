from fastapi.testclient import TestClient

import src.api.main as api_main


client = TestClient(api_main.app)


def test_virustotal_endpoint_returns_existing_report(monkeypatch):
    monkeypatch.setattr(
        api_main,
        "lookup_indicator",
        lambda kind, indicator: {
            "provider": "VirusTotal",
            "indicator_type": kind,
            "indicator": indicator,
            "analysis_stats": {"malicious": 0},
        },
    )

    response = client.get("/threat-intel/domain/example.com")

    assert response.status_code == 200
    assert response.json()["provider"] == "VirusTotal"
    assert response.json()["indicator"] == "example.com"


def test_virustotal_endpoint_rejects_invalid_indicator(monkeypatch):
    def reject(kind, indicator):
        raise ValueError("indicator must be a valid domain name")

    monkeypatch.setattr(api_main, "lookup_indicator", reject)
    response = client.get("/threat-intel/domain/not-a-domain")

    assert response.status_code == 422


def test_virustotal_endpoint_reports_missing_key(monkeypatch):
    from src.threat_intel.virustotal import VirusTotalNotConfigured

    def not_configured(kind, indicator):
        raise VirusTotalNotConfigured("VirusTotal API key is not configured.")

    monkeypatch.setattr(api_main, "lookup_indicator", not_configured)
    response = client.get("/threat-intel/domain/example.com")

    assert response.status_code == 503

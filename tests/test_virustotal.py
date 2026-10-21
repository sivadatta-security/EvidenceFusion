import io
import json
from urllib.error import HTTPError

import pytest

from src.threat_intel import virustotal


def test_validate_sha256_normalizes_case():
    digest = "A" * 64
    assert virustotal.validate_indicator("file", digest) == digest.lower()


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", "not-an-ip"),
        ("domain", "not a domain"),
        ("url", "ftp://example.com/file"),
        ("file", "abc"),
        ("unknown", "example.com"),
    ],
)
def test_rejects_invalid_indicators(kind, value):
    with pytest.raises(ValueError):
        virustotal.validate_indicator(kind, value)


def test_missing_api_key_fails_without_network(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(virustotal.VirusTotalNotConfigured):
        virustotal.lookup_indicator("domain", "example.com")


def test_lookup_summarizes_existing_report(monkeypatch):
    payload = {
        "data": {
            "id": "example.com",
            "attributes": {
                "reputation": -2,
                "last_analysis_stats": {
                    "malicious": 2, "suspicious": 1, "harmless": 10,
                    "undetected": 5, "timeout": 0,
                },
                "last_analysis_date": 1760000000,
                "names": ["example.com"],
                "categories": {"Example": "Technology"},
            },
        },
    }
    seen = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["key"] = request.get_header("X-apikey")
        seen["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(virustotal, "urlopen", fake_urlopen)
    result = virustotal.lookup_indicator("domain", "EXAMPLE.COM", api_key="test-key")

    assert seen["url"].endswith("/domains/example.com")
    assert seen["method"] == "GET"
    assert seen["key"] == "test-key"
    assert result["indicator"] == "example.com"
    assert result["analysis_stats"]["malicious"] == 2
    assert "contextual evidence" in result["disclaimer"]


def test_rate_limit_is_reported(monkeypatch):
    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, 429, "rate limit", {}, io.BytesIO(b""))

    monkeypatch.setattr(virustotal, "urlopen", fake_urlopen)
    with pytest.raises(virustotal.VirusTotalRateLimited):
        virustotal.lookup_indicator("domain", "example.com", api_key="test-key")

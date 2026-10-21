"""Read-only VirusTotal API v3 lookups for existing indicators.

This integration never uploads files or submits URLs. Configure VT_API_KEY in
the process environment; do not commit API keys to the repository.
"""
import base64
import ipaddress
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalError(RuntimeError):
    """Base exception for VirusTotal lookup failures."""


class VirusTotalNotConfigured(VirusTotalError):
    """Raised when no API key is configured."""


class VirusTotalRateLimited(VirusTotalError):
    """Raised when VirusTotal reports a rate limit."""


class VirusTotalRequestError(VirusTotalError):
    """Raised for provider or transport errors."""


def validate_indicator(indicator_type: str, indicator: str) -> str:
    """Validate and normalize a supported indicator."""
    kind = (indicator_type or "").strip().lower()
    value = (indicator or "").strip()
    if not value:
        raise ValueError("indicator must not be blank")

    if kind == "file":
        if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError("file indicators must be a 64-character SHA-256 hash")
        return value.lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("indicator must be a valid IPv4 or IPv6 address") from error
    if kind == "domain":
        domain = value.rstrip(".").lower()
        if len(domain) > 253 or "." not in domain or any(
            not part or len(part) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part) is None
            for part in domain.split(".")
        ):
            raise ValueError("indicator must be a valid domain name")
        return domain
    if kind == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("URL indicators must be absolute HTTP or HTTPS URLs")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs containing credentials are not supported")
        return value
    raise ValueError("indicator_type must be one of: file, ip, domain, url")


def _resource_path(indicator_type: str, indicator: str) -> str:
    kind = indicator_type.lower()
    if kind == "file":
        return "/files/" + quote(indicator, safe="")
    if kind == "ip":
        return "/ip_addresses/" + quote(indicator, safe=":")
    if kind == "domain":
        return "/domains/" + quote(indicator, safe=".-")
    encoded = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
    return "/urls/" + encoded


def _summary(payload: dict, indicator_type: str, indicator: str) -> dict:
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    permalink_id = data.get("id") or indicator
    if indicator_type == "url":
        permalink_id = quote(str(permalink_id), safe="-_")
    return {
        "provider": "VirusTotal",
        "indicator_type": indicator_type,
        "indicator": indicator,
        "reputation": attributes.get("reputation"),
        "analysis_stats": {
            key: int(stats.get(key, 0) or 0)
            for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
        },
        "last_analysis_date": attributes.get("last_analysis_date"),
        "names": attributes.get("names", [])[:10] if isinstance(attributes.get("names"), list) else [],
        "categories": attributes.get("categories", {}),
        "permalink": f"https://www.virustotal.com/gui/{indicator_type}/{permalink_id}",
        "disclaimer": "Third-party intelligence is contextual evidence, not a verdict.",
    }


def lookup_indicator(indicator_type: str, indicator: str, api_key: str | None = None, timeout: float = 10) -> dict:
    """Fetch an existing report from VirusTotal without submitting artifacts."""
    kind = (indicator_type or "").strip().lower()
    normalized = validate_indicator(kind, indicator)
    key = (api_key or os.environ.get("VT_API_KEY", "")).strip()
    if not key:
        raise VirusTotalNotConfigured("VirusTotal API key is not configured; set VT_API_KEY.")

    request = Request(
        API_BASE + _resource_path(kind, normalized),
        headers={"x-apikey": key, "accept": "application/json", "user-agent": "EvidenceFusion/1.0"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 404:
            raise VirusTotalRequestError("VirusTotal has no report for this indicator.") from error
        if error.code == 429:
            raise VirusTotalRateLimited("VirusTotal rate limit reached; retry later.") from error
        if error.code in {401, 403}:
            raise VirusTotalRequestError("VirusTotal rejected the API key or its permissions.") from error
        raise VirusTotalRequestError(f"VirusTotal returned HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise VirusTotalRequestError("Could not reach VirusTotal; check network connectivity.") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VirusTotalRequestError("VirusTotal returned an invalid JSON response.") from error

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise VirusTotalRequestError("VirusTotal response did not contain a report.")
    return _summary(payload, kind, normalized)

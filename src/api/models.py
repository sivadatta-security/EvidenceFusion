from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


def validate_timestamp(value: str) -> str:
    """Validate that a timestamp is ISO 8601 and timezone-aware."""
    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "timestamp must be a valid ISO 8601 datetime"
        ) from error

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "timestamp must include a timezone"
        )

    return value


class EventCreate(BaseModel):
    """Data accepted when creating a new EvidenceFusion event."""

    event_id: str
    timestamp: str
    source: Literal[
        "system",
        "network",
        "email",
        "incident_response",
    ]
    event_type: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    artifact: str | None = None
    hash: str | None = None
    description: str
    confidence: float = Field(ge=0.0, le=1.0)

    _validate_timestamp = field_validator("timestamp")(
        validate_timestamp
    )


class Event(BaseModel):
    """API representation of a normalized EvidenceFusion event."""

    event_id: str
    timestamp: str
    source: Literal[
        "system",
        "network",
        "email",
        "incident_response",
    ]
    event_type: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    artifact: str | None = None
    hash: str | None = None
    description: str
    confidence: float = Field(ge=0.0, le=1.0)

    _validate_timestamp = field_validator("timestamp")(
        validate_timestamp
    )


from typing import Literal as EvidenceLiteral

from pydantic import ConfigDict, model_validator


class EvidenceCreate(BaseModel):
    """Validated metadata for a digital evidence artifact."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    artifact_type: str = Field(min_length=1, max_length=100)
    source_reference: str = Field(min_length=1, max_length=2048)
    sha256: str | None = None
    hash_algorithm: str | None = None
    acquisition_method: str | None = None
    acquired_at: str | None = None
    acquired_by: str | None = None
    verification_status: EvidenceLiteral[
        "not_verified",
        "verified",
        "failed",
        "unavailable",
    ] = "not_verified"
    metadata: dict = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value):
        if value is not None:
            import re

            if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
                raise ValueError("sha256 must contain exactly 64 hexadecimal characters")

        return value

    @field_validator("acquired_at")
    @classmethod
    def validate_acquired_at(cls, value):
        if value is not None:
            return validate_timestamp(value)
        return value

    @model_validator(mode="after")
    def validate_hash_metadata(self):
        if self.sha256 is not None and self.hash_algorithm not in (
            None,
            "SHA-256",
            "sha256",
        ):
            raise ValueError("sha256 must use the SHA-256 algorithm")
        return self


class EvidenceLinkCreate(BaseModel):
    """Describe the relationship between an event and evidence."""

    model_config = ConfigDict(extra="forbid")

    relationship: EvidenceLiteral[
        "supports",
        "corroborates",
        "derived_from",
        "mentions",
    ] = "supports"


class EvidenceAcquisitionRequest(BaseModel):
    """Request to acquire a file already placed in data/incoming."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255)
    acquired_by: str = Field(min_length=1, max_length=128)
    artifact_type: str = Field(default="file", min_length=1, max_length=100)
    expected_sha256: str | None = None

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value):
        value = value.strip()

        if (
            not value
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
        ):
            raise ValueError(
                "filename must be a filename, not a path."
            )

        return value

    @field_validator("acquired_by", "artifact_type")
    @classmethod
    def validate_nonblank_fields(cls, value):
        if not value.strip():
            raise ValueError("This field must not be blank.")
        return value.strip()

    @field_validator("expected_sha256")
    @classmethod
    def validate_expected_sha256(cls, value):
        if value is not None:
            value = value.strip().lower()

            if (
                len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError(
                    "expected_sha256 must contain 64 hexadecimal characters."
                )

        return value

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
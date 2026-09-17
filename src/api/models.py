from pydantic import BaseModel


class EventCreate(BaseModel):
    """Data accepted when creating a new EvidenceFusion event."""

    event_id: str
    timestamp: str
    source: str
    event_type: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    artifact: str | None = None
    hash: str | None = None
    description: str
    confidence: float


class Event(BaseModel):
    """API representation of a normalized EvidenceFusion event."""

    event_id: str
    timestamp: str
    source: str
    event_type: str
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    domain: str | None = None
    artifact: str | None = None
    hash: str | None = None
    description: str
    confidence: float
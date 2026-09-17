from fastapi import FastAPI, HTTPException

from src.api.database import get_events, insert_event
from src.api.models import Event, EventCreate


app = FastAPI(
    title="EvidenceFusion API",
    description="Backend API for the EvidenceFusion DFIR investigation platform.",
    version="0.1.0",
)


@app.get("/")
def root():
    """Return basic information about the EvidenceFusion API."""
    return {
        "project": "EvidenceFusion",
        "message": "EvidenceFusion API is running",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    """Check whether the API is healthy."""
    return {
        "status": "healthy"
    }


@app.get("/events", response_model=list[Event])
def read_events():
    """Return all normalized events stored in the database."""
    rows = get_events()

    events = []

    for row in rows:
        events.append(
            Event(
                event_id=row[0],
                timestamp=row[1],
                source=row[2],
                event_type=row[3],
                user=row[4],
                host=row[5],
                source_ip=row[6],
                destination_ip=row[7],
                domain=row[8],
                artifact=row[9],
                hash=row[10],
                description=row[11],
                confidence=row[12],
            )
        )

    return events


@app.post("/events", response_model=Event, status_code=201)
def create_event(event: EventCreate):
    """Create and store a new normalized event."""
    try:
        insert_event(event.model_dump())
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(
                status_code=409,
                detail=f"Event with ID '{event.event_id}' already exists.",
            )

        raise HTTPException(
            status_code=500,
            detail="Failed to store event.",
        )

    return Event(**event.model_dump())
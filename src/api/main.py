from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import sqlite3

from src.api.database import (
    get_events,
    insert_event,
    insert_evidence,
    get_evidence,
    link_event_evidence,
    get_evidence_for_event,
    initialize_database,
    register_acquired_evidence,
    get_chain_of_custody,
    record_evidence_verification,
)
from src.api.models import (
    Event,
    EventCreate,
    EvidenceCreate,
    EvidenceLinkCreate,
    EvidenceAcquisitionRequest,
)
from src.acquisition.service import (
    acquire_file,
    AcquisitionError,
    INCOMING_DIR,
    remove_acquired_file,
    verify_evidence_integrity,
)
from src.api.timeline import sort_events_by_time
from src.api.investigation import build_investigation


app = FastAPI(
    title="EvidenceFusion API",
    description="Backend API for the EvidenceFusion DFIR investigation platform.",
    version="0.1.0",
)

initialize_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

@app.get("/timeline", response_model=list[Event])
def read_timeline():
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

    return sort_events_by_time(
        [event.model_dump() for event in events]
    )

@app.get("/incidents")
def read_incidents():
    """
    Return structured investigation results.

    Events are loaded from the database and processed through
    the investigation pipeline.
    """
    rows = get_events()

    events = []

    for row in rows:
        events.append(
            {
                "event_id": row[0],
                "timestamp": row[1],
                "source": row[2],
                "event_type": row[3],
                "user": row[4],
                "host": row[5],
                "source_ip": row[6],
                "destination_ip": row[7],
                "domain": row[8],
                "artifact": row[9],
                "hash": row[10],
                "description": row[11],
                "confidence": row[12],
            }
        )

    return build_investigation(events)

@app.get("/incidents/{incident_id}")
def read_incident(incident_id: str):
    """
    Return a single investigation by incident ID.
    """
    rows = get_events()

    events = []

    for row in rows:
        events.append(
            {
                "event_id": row[0],
                "timestamp": row[1],
                "source": row[2],
                "event_type": row[3],
                "user": row[4],
                "host": row[5],
                "source_ip": row[6],
                "destination_ip": row[7],
                "domain": row[8],
                "artifact": row[9],
                "hash": row[10],
                "description": row[11],
                "confidence": row[12],
            }
        )

    investigations = build_investigation(events)

    for incident in investigations:
        if incident["incident_id"] == incident_id:
            return incident

    raise HTTPException(
        status_code=404,
        detail=f"Incident '{incident_id}' not found.",
    )


@app.post("/evidence", status_code=201)
def create_evidence(evidence: EvidenceCreate):
    """Register metadata for a digital evidence artifact."""
    try:
        insert_evidence(evidence.model_dump())
    except sqlite3.IntegrityError as error:
        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(
                status_code=409,
                detail=f"Evidence with ID '{evidence.evidence_id}' already exists.",
            ) from error
        raise HTTPException(
            status_code=400,
            detail="Evidence record violates a database constraint.",
        ) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=422,
            detail="Evidence metadata could not be serialized.",
        ) from error

    return get_evidence(evidence.evidence_id)


@app.get("/evidence/{evidence_id}")
def read_evidence(evidence_id: str):
    """Retrieve one evidence record."""
    evidence = get_evidence(evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence '{evidence_id}' not found.",
        )

    return evidence


@app.post(
    "/events/{event_id}/evidence/{evidence_id}",
    status_code=201,
)
def create_event_evidence_link(
    event_id: str,
    evidence_id: str,
    link: EvidenceLinkCreate | None = None,
):
    """Link existing evidence metadata to an existing event."""
    event_exists = any(
        row[0] == event_id
        for row in get_events()
    )

    if not event_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_id}' not found.",
        )

    if get_evidence(evidence_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence '{evidence_id}' not found.",
        )

    relationship = link.relationship if link else "supports"

    try:
        link_event_evidence(
            event_id,
            evidence_id,
            relationship=relationship,
        )
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=409,
            detail="This event-evidence link already exists or is invalid.",
        ) from error

    return {
        "event_id": event_id,
        "evidence_id": evidence_id,
        "relationship": relationship,
    }


@app.get("/events/{event_id}/evidence")
def read_event_evidence(event_id: str):
    """Retrieve all evidence linked to an event."""
    event_exists = any(
        row[0] == event_id
        for row in get_events()
    )

    if not event_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_id}' not found.",
        )

    return get_evidence_for_event(event_id)


@app.get("/incidents/{incident_id}/evidence")
def read_incident_evidence(incident_id: str):
    """Return unique evidence records linked to an incident's events."""
    rows = get_events()

    events = [
        {
            "event_id": row[0],
            "timestamp": row[1],
            "source": row[2],
            "event_type": row[3],
            "user": row[4],
            "host": row[5],
            "source_ip": row[6],
            "destination_ip": row[7],
            "domain": row[8],
            "artifact": row[9],
            "hash": row[10],
            "description": row[11],
            "confidence": row[12],
        }
        for row in rows
    ]

    incidents = build_investigation(events)

    incident = next(
        (
            item for item in incidents
            if item["incident_id"] == incident_id
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' not found.",
        )

    evidence_by_id = {}

    for event_id in incident["event_ids"]:
        linked_evidence = get_evidence_for_event(event_id)

        for record in linked_evidence:
            evidence_id = record["evidence_id"]

            if evidence_id not in evidence_by_id:
                evidence_by_id[evidence_id] = {
                    key: value
                    for key, value in record.items()
                    if key != "relationship"
                }
                evidence_by_id[evidence_id]["event_links"] = []

            evidence_by_id[evidence_id]["event_links"].append(
                {
                    "event_id": event_id,
                    "relationship": record.get(
                        "relationship", "supports"
                    ),
                }
            )

    return {
        "incident_id": incident_id,
        "evidence": list(evidence_by_id.values()),
         }



@app.post("/evidence/acquire", status_code=201)
def acquire_evidence(request: EvidenceAcquisitionRequest):
    """Acquire a file and register its metadata and custody record."""
    evidence = None

    try:
        evidence = acquire_file(
            source_path=INCOMING_DIR / request.filename,
            acquired_by=request.acquired_by,
            artifact_type=request.artifact_type,
            expected_sha256=request.expected_sha256,
        )

        try:
            return register_acquired_evidence(evidence)

        except Exception:
            # The database registration did not complete.
            # Remove only the managed copy, never the original source.
            try:
                remove_acquired_file(evidence)
            except OSError:
                # Preserve the original registration error.
                pass

            raise

    except AcquisitionError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except sqlite3.IntegrityError as error:
        if "UNIQUE constraint failed" in str(error):
            raise HTTPException(
                status_code=409,
                detail="An evidence record with this ID already exists.",
            ) from error

        raise HTTPException(
            status_code=500,
            detail="The evidence record could not be saved.",
        ) from error

    except OSError as error:
        raise HTTPException(
            status_code=500,
            detail="The evidence file could not be acquired or cleaned up.",
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="The evidence record could not be saved.",
        ) from error



@app.get("/evidence/{evidence_id}/custody")
def read_evidence_custody(evidence_id: str):
    """Return the recorded chain-of-custody history for an evidence item."""
    evidence = get_evidence(evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence '{evidence_id}' not found.",
        )

    return {
        "evidence_id": evidence_id,
        "audit_entries": get_chain_of_custody(evidence_id),
    }

@app.post("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str, verified_by: str):
    """Verify an acquired file and record the result in custody history."""

    actor = verified_by.strip()

    if not actor or len(actor) > 128:
        raise HTTPException(
            status_code=422,
            detail="verified_by must contain 1–128 characters.",
        )

    evidence = get_evidence(evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence '{evidence_id}' not found.",
        )

    result = verify_evidence_integrity(evidence)

    try:
        updated_evidence = record_evidence_verification(
            evidence_id,
            actor,
            result,
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="The verification result could not be recorded.",
        ) from error

    return {
        "evidence": updated_evidence,
        "verification": result,
    }
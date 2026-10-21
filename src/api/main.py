
import sqlite3
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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
from src.api.timeline import sort_events_by_time, parse_event_timestamp
from src.api.investigation import build_investigation
from src.mitre.mapping import (
    assess_incident_for_mitre,
    map_incident_to_mitre,
)

from src.threat_intel.virustotal import (
    VirusTotalNotConfigured,
    VirusTotalRateLimited,
    VirusTotalRequestError,
    lookup_indicator,
)



@app.get("/threat-intel/{indicator_type}/{indicator:path}")
def get_threat_intelligence(indicator_type: str, indicator: str):
    """Look up an existing VirusTotal report; never upload evidence or submit URLs."""
    try:
        return lookup_indicator(indicator_type, indicator)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except VirusTotalNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except VirusTotalRateLimited as error:
        raise HTTPException(status_code=429, detail=str(error)) from error
    except VirusTotalRequestError as error:
        message = str(error)
        status_code = 404 if "no report" in message.lower() else 502
        raise HTTPException(status_code=status_code, detail=message) from error


app = FastAPI(
    title="EvidenceFusion API",
    description="Backend API for the EvidenceFusion DFIR investigation platform.",
    version="0.1.0",
)

initialize_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "null",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the EvidenceFusion dashboard frontend.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"

app.mount(
    "/dashboard/static",
    StaticFiles(directory=str(DASHBOARD_DIR)),
    name="dashboard-static",
)


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
def serve_dashboard():
    """Serve the EvidenceFusion investigation dashboard."""
    return FileResponse(str(DASHBOARD_DIR / "index.html"))

def _event_from_row(row):
    """Convert a database event row to the API event model."""
    return Event(
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


def _event_dict_from_row(row):
    """Convert a database event row to an investigation dictionary."""
    return {
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



def _enrich_incident_with_mitre(incident, events):
    """Add ATT&CK mappings and conservative assessments to an incident."""
    enriched = dict(incident)

    enriched["mitre_techniques"] = map_incident_to_mitre(
        incident, events
    )["techniques"]

    enriched["mitre_assessment"] = assess_incident_for_mitre(
        incident, events
    )

    return enriched


def _parse_filter_timestamp(value, parameter_name):
    """Validate and parse an ISO 8601 filter timestamp."""
    if value is None:
        return None

    parsed = parse_event_timestamp(value)

    if parsed is None or not value.strip():
        raise HTTPException(
            status_code=422,
            detail=f"{parameter_name} must be a valid ISO 8601 timestamp.",
        )

    # Filter timestamps must include an explicit timezone.
    try:
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        original = datetime.fromisoformat(raw)
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=f"{parameter_name} must be a valid ISO 8601 timestamp.",
        ) from error

    if original.tzinfo is None or original.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=f"{parameter_name} must include a timezone.",
        )

    return parsed


def _get_timeline_events(
    user=None,
    host=None,
    source=None,
    start_time=None,
    end_time=None,
):
    """Filter and sort events without changing the database."""
    events = [_event_from_row(row).model_dump() for row in get_events()]

    start = _parse_filter_timestamp(start_time, "start_time")
    end = _parse_filter_timestamp(end_time, "end_time")

    if start is not None and end is not None and start > end:
        raise HTTPException(
            status_code=422,
            detail="start_time must be earlier than or equal to end_time.",
        )

    filtered = []

    for event in events:
        if user is not None and event.get("user") != user:
            continue

        if host is not None and event.get("host") != host:
            continue

        if source is not None and event.get("source") != source:
            continue

        timestamp = parse_event_timestamp(event.get("timestamp"))

        if start is not None:
            if timestamp is None or timestamp < start:
                continue

        if end is not None:
            if timestamp is None or timestamp > end:
                continue

        filtered.append(event)

    return sort_events_by_time(filtered)


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
    return {"status": "healthy"}


@app.get("/events", response_model=list[Event])
def read_events():
    """Return all normalized events stored in the database."""
    return [_event_from_row(row) for row in get_events()]


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
            ) from error

        raise HTTPException(
            status_code=500,
            detail="Failed to store event.",
        ) from error

    return Event(**event.model_dump())


@app.get("/timeline", response_model=list[Event])
def read_timeline(
    user: str | None = Query(default=None, min_length=1),
    host: str | None = Query(default=None, min_length=1),
    source: str | None = Query(
        default=None,
        pattern="^(system|network|email|incident_response)$",
    ),
    start_time: str | None = Query(default=None, min_length=1),
    end_time: str | None = Query(default=None, min_length=1),
):
    """Return chronologically sorted events with optional filters."""
    return _get_timeline_events(
        user=user,
        host=host,
        source=source,
        start_time=start_time,
        end_time=end_time,
    )



@app.get("/incidents")
def read_incidents(
    severity: str | None = Query(
        default=None,
        pattern="^(High|Medium|Low)$",
    ),
    source: str | None = Query(default=None, min_length=1),
    min_events: int = Query(default=1, ge=1),
):
    """Return investigation results with optional filters."""
    events = [_event_dict_from_row(row) for row in get_events()]
    incidents = build_investigation(events)

    filtered_incidents = []

    for incident in incidents:
        if severity is not None and incident["severity"] != severity:
            continue

        if source is not None and source not in incident["sources"]:
            continue

        if incident["event_count"] < min_events:
            continue

        filtered_incidents.append(_enrich_incident_with_mitre(incident, events))

    return filtered_incidents


@app.get("/dashboard/summary")
def read_dashboard_summary():
    """Return high-level incident and event metrics for a dashboard."""
    events = [_event_dict_from_row(row) for row in get_events()]
    incidents = build_investigation(events)

    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    source_counts = {}

    for incident in incidents:
        severity = incident.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

        for source in incident.get("sources", []):
            source_counts[source] = source_counts.get(source, 0) + 1

    return {
        "total_incidents": len(incidents),
        "total_events": len(events),
        "severity_counts": severity_counts,
        "source_counts": dict(sorted(source_counts.items())),
    }

@app.get("/incidents/{incident_id}")
def read_incident(incident_id: str):
    """Return a single investigation by incident ID."""
    events = [_event_dict_from_row(row) for row in get_events()]
    investigations = build_investigation(events)

    for incident in investigations:
        if incident["incident_id"] == incident_id:
            return _enrich_incident_with_mitre(incident, events)

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
    event_exists = any(row[0] == event_id for row in get_events())

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
    event_exists = any(row[0] == event_id for row in get_events())

    if not event_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_id}' not found.",
        )

    return get_evidence_for_event(event_id)


@app.get("/incidents/{incident_id}/evidence")
def read_incident_evidence(incident_id: str):
    """Return unique evidence records linked to an incident's events."""
    events = [_event_dict_from_row(row) for row in get_events()]
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
                    "relationship": record.get("relationship", "supports"),
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
            # Remove only the managed copy, never the original source.
            try:
                remove_acquired_file(evidence)
            except OSError:
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
            detail="verified_by must contain 1-128 characters.",
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

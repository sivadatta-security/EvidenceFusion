# EvidenceFusion

**Automated Multi-Source Digital Evidence Correlation for DFIR Investigations**

EvidenceFusion is an academic Digital Forensics and Incident Response (DFIR) platform designed to organize digital evidence, correlate security events from multiple sources, and help analysts investigate related activity through a unified dashboard.

## 1. Project Objectives

- Collect and register digital evidence artifacts.
- Calculate SHA-256 hashes to support evidence integrity checks.
- Maintain evidence acquisition and chain-of-custody records.
- Store normalized security events from different sources.
- Correlate related events using shared attributes and timestamps.
- Group related events into incidents and assign initial severity.
- Display investigation summaries and supporting evidence.
- Provide evidence-based MITRE ATT&CK assessment information.

## 2. Main Features

### Digital Evidence Acquisition

Evidence files can be acquired from the project's incoming directory into managed evidence storage. The acquisition workflow calculates SHA-256 hashes and checks the acquired copy against the source.

An independently supplied expected hash can also be used during acquisition.

### Evidence Integrity Verification

The verification service recalculates the hash of a managed evidence file and compares it with the recorded acquisition hash.

A matching hash supports integrity verification against the recorded baseline. It does not independently establish authorship or authenticity.

### Chain of Custody

Evidence records include acquisition metadata, such as the analyst, timestamp, acquisition method, hash algorithm, and verification status. The API exposes recorded chain-of-custody entries.

### Event Correlation and Incident Investigation

Normalized events may include:

- Timestamp and event source
- User and host
- Source and destination IP addresses
- Domain and file hash
- Event type, description, and confidence

The correlation engine evaluates matching attributes and temporal proximity. Qualifying relationships can be grouped into incident clusters.

Incident information includes event counts, time ranges, sources, severity, correlation details, and available MITRE ATT&CK assessment information.

Correlation scores and severity labels are investigative aids, not proof that malicious activity occurred.

### Investigation Workbench

The dashboard provides a unified interface for reviewing investigation information, event timelines, incident details, filtering options, and MITRE ATT&CK assessments.

MITRE assessment results must be interpreted using their evidence, confidence, and review status. A result requiring analyst review should not be treated as a confirmed technique mapping.

### Dataset Import

The project includes a dataset-importing module for bringing supported security datasets into the investigation workflow. Imported data should retain its provenance and original labels wherever supported.

Dataset samples are not automatically proof of real-world incidents. Synthetic or benchmark records should be interpreted according to their source and context.

## 3. Technology Stack

- **Python** — application logic and event processing
- **FastAPI** — REST API and dashboard delivery
- **SQLite** — local application data storage
- **HTML, CSS, JavaScript** — web dashboard
- **SHA-256** — evidence integrity checking
- **pytest** — automated testing

## 4. Project Structure

```text
EvidenceFusion/
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── data/
│   ├── incoming/
│   └── evidence/
├── src/
│   ├── acquisition/
│   ├── api/
│   ├── correlation/
│   ├── ingestion/
│   └── mitre/
└── tests/
```

The project may contain additional modules and data files beyond this overview.

- `dashboard/` contains the web interface.
- `data/incoming/` is used for files awaiting acquisition.
- `data/evidence/` stores managed evidence copies.
- `src/api/` contains the API application.
- `src/ingestion/` contains dataset-importing functionality.
- `src/mitre/` contains MITRE ATT&CK assessment logic.
- `tests/` contains automated tests.

## 5. Requirements

- Python and the project's required Python packages
- Git
- A modern web browser

Use a Python version compatible with the installed project dependencies. Run commands from the repository root.

The repository does not currently include a `requirements.txt` file. Use the project's existing environment or its documented dependency configuration rather than assuming a dependency list.

## 6. Setup and Startup

### Step 1: Open the repository

Open a terminal in the EvidenceFusion repository root.

If you use a virtual environment, activate it before starting the application.

### Step 2: Install or verify dependencies

Install the packages required by the project in the active Python environment. Ensure FastAPI, Uvicorn, and the application's other dependencies are available.

### Step 3: Start the API and dashboard

Run:

```powershell
python -m uvicorn src.api.main:app --reload
```

Open the following addresses in your browser:

- **Investigation dashboard:** http://127.0.0.1:8000/dashboard/
- **Interactive API documentation:** http://127.0.0.1:8000/docs
- **API base URL:** http://127.0.0.1:8000

Keep the terminal running while using the application.

The dashboard is served by the FastAPI application, so a separate Live Server instance is not required for the normal workflow.

## 7. Evidence Acquisition and Verification Workflow

1. Place a suitable test artifact in `data/incoming/`.
2. Open the interactive API documentation at `/docs`.
3. Locate `POST /evidence/acquire`.
4. Supply the required filename, analyst identifier, and artifact type.
5. Supply an independently calculated expected SHA-256 hash when appropriate.
6. Record the returned evidence ID and acquisition result.
7. Use `POST /evidence/{evidence_id}/verify` to verify the stored file against its recorded hash.
8. Use `GET /evidence/{evidence_id}/custody` to inspect the recorded chain-of-custody history.

Use test artifacts for demonstrations. Preserve original investigative evidence and follow approved evidence-handling procedures.

## 8. Event and Incident Investigation Workflow

1. Load or submit supported normalized security events.
2. Retrieve events using `GET /events`.
3. Review event timelines and available filters.
4. Retrieve incident summaries using `GET /incidents`.
5. Open an incident to inspect its correlated events, summary, and supporting evidence.
6. Review the associated MITRE ATT&CK assessment, including any items requiring analyst review.
7. Use the dashboard summary to understand the investigation data currently available.

Correlation outcomes depend on the supplied data, available event attributes, and implemented rules.

## 9. API Reference

The following endpoints are documented by the project:

| Endpoint | Purpose |
|---|---|
| `GET /events` | Retrieve events and supported filters |
| `GET /incidents` | Retrieve incident summaries and supported filters |
| `GET /incidents/{incident_id}` | Retrieve a single incident |
| `GET /dashboard/summary` | Retrieve dashboard metrics |
| `POST /evidence` | Register evidence metadata |
| `GET /evidence/{evidence_id}` | Retrieve evidence metadata |
| `POST /evidence/acquire` | Acquire a file and register its metadata |
| `POST /events/{event_id}/evidence/{evidence_id}` | Link evidence to an event |
| `GET /events/{event_id}/evidence` | Retrieve evidence linked to an event |
| `GET /incidents/{incident_id}/evidence` | Retrieve evidence associated with an incident |
| `GET /evidence/{evidence_id}/custody` | Retrieve chain-of-custody records |
| `POST /evidence/{evidence_id}/verify` | Verify evidence integrity and record the result |

For current parameters, validation rules, and response schemas, consult the running application's interactive documentation at `/docs`.

## 10. Running Tests

Run the test suite from the repository root:

```powershell
python -m pytest -q
```

The latest confirmed project test result before this documentation update was **95 passed, with 2 warnings**.

The warnings were dependency deprecation warnings and were not test failures. Rerun the suite after code changes and investigate failures before committing.

## 11. Current Limitations

- Automated correlation depends on configured rules and available event fields.
- Severity is an initial rule-based classification that requires analyst interpretation.
- MITRE ATT&CK assessments depend on implemented mapping rules and the evidence available.
- Hash verification compares a file with its recorded baseline; it does not prove authorship or authenticity.
- Local file acquisition should not be described as complete physical disk or memory acquisition.
- Benchmark and synthetic datasets require appropriate provenance and contextual interpretation.
- The application requires additional validation and security hardening before operational deployment.

## 12. Future Improvements

Potential improvements include:

- Additional source-specific event parsers
- Broader forensic artifact ingestion
- More end-to-end integration tests
- Investigation export and reporting
- Additional correlation rules and analyst feedback
- Authentication and role-based access control
- Deployment hardening

These items should be treated as future work until implemented and tested.

## 13. Project Purpose

EvidenceFusion brings evidence handling, event correlation, incident investigation, and forensic context into a unified DFIR workflow.

The project is intended as an academic investigation platform. Its findings should be interpreted by an analyst and validated against the available evidence.

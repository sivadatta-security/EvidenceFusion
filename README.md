# EvidenceFusion

**Automated Multi-Source Digital Evidence Correlation for DFIR Investigations**

EvidenceFusion is a digital forensics and incident response (DFIR) investigation platform designed to organize digital evidence, correlate security events from multiple sources, and help analysts investigate related activity through a unified dashboard.

## 1. Project Objectives

- Collect and register digital evidence artifacts.
- Calculate SHA-256 hashes to support evidence integrity checks.
- Maintain evidence acquisition and chain-of-custody records.
- Store normalized security events from different sources.
- Correlate related events using shared attributes and timestamps.
- Group related events into incidents and assign an initial severity.
- Display investigation summaries and supporting evidence.
- Map relevant event types to MITRE ATT&CK techniques.

## 2. Main Features

### Digital Evidence Acquisition

Evidence files are acquired from the project's incoming directory into managed evidence storage. The acquisition service calculates SHA-256 hashes, checks that the source remains unchanged during copying, and compares the acquired copy with the source.

An independently supplied expected hash can also be used during acquisition.

### Evidence Integrity Verification

The verification service recalculates the hash of a managed evidence file and compares it with the recorded acquisition hash. Results distinguish verified, failed, and unavailable checks.

A matching hash supports integrity verification against the recorded baseline; it does not independently establish who created the evidence.

### Chain of Custody

Evidence records include acquisition metadata such as the analyst, timestamp, acquisition method, hash algorithm, and verification status. The API also exposes recorded chain-of-custody entries.

### Event Correlation and Incident Investigation

Normalized events can contain information such as:

- Timestamp and event source
- User and host
- Source and destination IP addresses
- Domain and file hash
- Event type, description, and confidence

The correlation engine assigns weighted scores to matching attributes and temporal proximity. Qualifying relationships are grouped into incident clusters. Investigation summaries include event counts, time ranges, sources, severity, correlation information, and available MITRE ATT&CK mappings.

Correlation scores and severity labels are investigative aids, not proof that malicious activity occurred.

### Investigation Dashboard

The web dashboard provides access to investigation information, including event timelines, incident details, supporting evidence, and MITRE ATT&CK mappings. The API also supports timeline and incident filtering.

## 3. Technology Stack

- **Python** — application logic and correlation
- **FastAPI** — REST API
- **SQLite** — event and evidence metadata storage
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
│   └── mitre/
└── tests/
```

The `data/incoming/` directory is used for files awaiting acquisition, while `data/evidence/` stores managed evidence copies. The API database module manages application records.

## 5. Requirements

- Python 3.14 or a compatible Python version supported by the installed dependencies
- Git
- A modern web browser
- A local static web server for the dashboard, such as the VS Code Live Server extension
- The Python packages required by the application

Run commands from the repository root.

## 6. Setup and Startup

### Step 1: Install dependencies

Activate your existing virtual environment if you use one. Install the project's required packages according to the dependency files provided by your team.

If Uvicorn is not installed, install it in your active Python environment:

```powershell
python -m pip install uvicorn
```

### Step 2: Start the API

```powershell
python -m uvicorn src.api.main:app --reload
```

The local API should be available at:

- API base URL: `http://127.0.0.1:8000`
- Interactive API documentation: `http://127.0.0.1:8000/docs`

Keep this terminal running while using the application.

### Step 3: Start the dashboard

Open the `dashboard` folder in Visual Studio Code and launch `index.html` using Live Server. Configure the server to use port `5500`, which is included in the API's current CORS configuration.

Open the local URL displayed by Live Server.

If the dashboard cannot reach the API, check that the API is running and that the dashboard origin matches the configured CORS origins.

## 7. Evidence Acquisition and Verification Workflow

1. Place a test artifact in `data/incoming/`.
2. Open the interactive API documentation at `/docs`.
3. Find `POST /evidence/acquire`.
4. Supply the filename, analyst identifier, and artifact type. An independently calculated expected SHA-256 hash can be supplied when available.
5. Record the returned evidence ID and acquisition result.
6. Use `POST /evidence/{evidence_id}/verify` to check the stored evidence against its recorded hash.
7. Use `GET /evidence/{evidence_id}/custody` to inspect the recorded chain-of-custody history.
8. Review the evidence metadata and verification result.

**Important:** Use test artifacts for demonstrations. Do not place original investigative evidence in a test workflow unless the handling procedure has been approved. Preserve original files and maintain appropriate access controls.

## 8. Event and Incident Investigation Workflow

1. Submit or load normalized security events through the available event API.
2. Retrieve events using `GET /events`.
3. Inspect the timeline and apply supported filters.
4. Retrieve incidents using `GET /incidents`.
5. Open an incident to review its correlated events, summary, supporting evidence, and available MITRE ATT&CK mappings.
6. Review the dashboard summary and recorded evidence history when needed.

The exact correlation outcome depends on the available event attributes and the configured correlation rules.

## 9. API Reference

The following endpoints are implemented in the API:

| Endpoint | Purpose |
|---|---|
| `GET /events` | Retrieve events, with supported filters |
| `GET /incidents` | Retrieve incident summaries, with supported filters |
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

For request parameters, validation rules, and response schemas, use the interactive API documentation at `/docs`.

## 10. Running Tests

From the repository root:

```powershell
python -m pytest -q
```

The current baseline before this documentation update is **82 passing tests**.

Tests should be run again after changes. Do not commit a change if the suite fails without investigating the failure.

## 11. Current Limitations

- Automated correlation is based on configured rules and available event fields.
- Severity is an initial rule-based classification and requires analyst interpretation.
- MITRE ATT&CK mappings depend on the project's implemented mapping rules.
- Hash verification compares the current evidence file with the recorded acquisition baseline; it does not prove authorship or authenticity.
- Evidence acquisition currently copies local files from the incoming directory. It should not be described as a complete physical disk or memory acquisition capability.
- The platform should be validated with representative end-to-end test data before being used in a real investigation.

## 12. Future Improvements

Potential improvements include:

- Additional source-specific event parsers
- Broader forensic artifact ingestion
- More end-to-end integration tests
- Improved investigation export and reporting
- Additional correlation rules and analyst feedback
- Deployment hardening, authentication, and role-based access control

These improvements should be treated as future work until implemented and tested.

## 13. Project Purpose

EvidenceFusion aims to bring evidence handling, event correlation, incident investigation, and supporting forensic context into one accessible DFIR workflow. It is an academic investigation platform and should be validated and secured appropriately before operational deployment.

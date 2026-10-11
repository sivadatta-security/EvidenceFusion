const API_BASE_URL = "http://127.0.0.1:8000";


/* =========================
   API REQUEST HELPER
   ========================= */

async function fetchApi(endpoint) {
    const response = await fetch(
        `${API_BASE_URL}${endpoint}`
    );

    if (!response.ok) {
        throw new Error(
            `API request failed: ${response.status}`
        );
    }

    return response.json();
}


/* =========================
   LOAD EVENTS
   ========================= */

async function loadEvents() {
    return fetchApi("/events");
}


/* =========================
   LOAD TIMELINE
   ========================= */

async function loadTimeline() {
    return fetchApi("/timeline");
}


/* =========================
   LOAD INCIDENTS
   ========================= */

async function loadIncidents() {
    return fetchApi("/incidents");
}


/* =========================
   SUMMARY CARDS
   ========================= */

function updateSummary(
    events,
    incidents
) {
    const incidentCount =
        incidents.length;

    const highCount =
        incidents.filter(
            incident =>
                incident.severity === "High"
        ).length;

    const techniqueIds =
        new Set();

    incidents.forEach(
        incident => {
            incident.mitre_techniques.forEach(
                technique => {
                    techniqueIds.add(
                        technique.technique_id
                    );
                }
            );
        }
    );

    document.getElementById(
        "incident-count"
    ).textContent = incidentCount;

    document.getElementById(
        "high-count"
    ).textContent = highCount;

    document.getElementById(
        "event-count"
    ).textContent = events.length;

    document.getElementById(
        "technique-count"
    ).textContent =
        techniqueIds.size;
}


/* =========================
   RENDER TIMELINE
   ========================= */

function renderTimeline(events) {
    const container =
        document.getElementById(
            "timeline"
        );

    if (events.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No investigation events found.
            </div>
        `;

        return;
    }

    container.innerHTML =
        events.map(event => {

            const timestamp =
                new Date(
                    event.timestamp
                ).toLocaleString();

            return `
                <div class="timeline-item">

                    <div class="timeline-time">
                        ${timestamp}
                    </div>

                    <div class="timeline-event">

                        <strong>
                            ${event.event_type}
                        </strong>

                        <span>
                            ${event.description}
                        </span>

                    </div>

                </div>
            `;

        }).join("");
}


/* =========================
   RENDER INCIDENTS
   ========================= */

function renderIncidents(incidents) {
    const container =
        document.getElementById(
            "incidents"
        );

    if (incidents.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No incidents detected.
            </div>
        `;

        return;
    }

    container.innerHTML =
        incidents.map(
            incident => {

                const severity =
                    incident.severity.toLowerCase();

                return `
                    <div
                        class="incident-card"
                        onclick="openIncident('${incident.incident_id}')"
                    >

                        <div class="incident-id">
                            ${incident.incident_id}
                        </div>

                        <div>
                            <span
                                class="severity severity-${severity}"
                            >
                                ${incident.severity}
                            </span>
                        </div>

                        <div class="incident-description">

                            ${incident.event_count}
                            correlated events

                            <br>

                            Sources:
                            ${incident.sources.join(", ")}

                        </div>

                        <div class="incident-score">

                            Score:
                            ${incident.max_correlation_score}

                        </div>

                    </div>
                `;

            }
        ).join("");
}


/* =========================
   RENDER MITRE TECHNIQUES
   ========================= */

function renderMitreTechniques(
    incidents
) {
    const container =
        document.getElementById(
            "mitre-techniques"
        );

    const techniques = [];

    const seen =
        new Set();

    incidents.forEach(
        incident => {

            incident.mitre_techniques.forEach(
                technique => {

                    if (
                        !seen.has(
                            technique.technique_id
                        )
                    ) {
                        seen.add(
                            technique.technique_id
                        );

                        techniques.push(
                            technique
                        );
                    }

                }
            );

        }
    );

    if (techniques.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No MITRE ATT&CK techniques identified.
            </div>
        `;

        return;
    }

    container.innerHTML =
        techniques.map(
            technique => `
                <div class="technique-card">

                    <div class="technique-id">
                        ${technique.technique_id}
                    </div>

                    <div class="technique-name">
                        ${technique.technique_name}
                    </div>

                    <div class="technique-events">
                        Supporting events:
                        ${technique.event_ids.join(", ")}
                    </div>

                </div>
            `
        ).join("");
}


/* =========================
   LOAD DASHBOARD
   ========================= */

async function loadDashboard() {

    try {

        const [
            events,
            timeline,
            incidents
        ] = await Promise.all([
            loadEvents(),
            loadTimeline(),
            loadIncidents()
        ]);

        updateSummary(
            events,
            incidents
        );

        renderTimeline(
            timeline
        );

        renderIncidents(
            incidents
        );

        renderMitreTechniques(
            incidents
        );

    } catch (error) {

        console.error(
            "Failed to load dashboard:",
            error
        );

        document.getElementById(
            "timeline"
        ).innerHTML = `
            <div class="empty-state">
                Unable to connect to
                EvidenceFusion API.
            </div>
        `;

        document.getElementById(
            "incidents"
        ).innerHTML = `
            <div class="empty-state">
                Backend API unavailable.
            </div>
        `;

        document.getElementById(
            "mitre-techniques"
        ).innerHTML = `
            <div class="empty-state">
                Backend API unavailable.
            </div>
        `;
    }
}


/* =========================
   INITIALIZE DASHBOARD
   ========================= */

async function openIncident(incidentId) {

    try {

        const incident =
            await fetchApi(
                `/incidents/${incidentId}`
            );

        showIncidentDetails(
            incident
        );

    } catch (error) {

        console.error(
            "Failed to load incident:",
            error
        );

        alert(
            "Unable to load incident details."
        );
    }
}


function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function formatField(label, value) {
    return `
        <div class="event-field">
            <span class="event-field-label">
                ${escapeHtml(label)}
            </span>
            <strong class="event-field-value">
                ${escapeHtml(value ?? "Not available")}
            </strong>
        </div>
    `;
}

async function showIncidentDetails(incident) {
    const existingPanel =
        document.getElementById("incident-detail-panel");

    if (existingPanel) {
        existingPanel.remove();
    }

    const panel = document.createElement("section");
    panel.id = "incident-detail-panel";
    panel.className = "panel";

    const dashboard = document.querySelector(".dashboard");

    if (!dashboard) {
        console.error("Dashboard container was not found.");
        return;
    }

    dashboard.prepend(panel);

    const severity = String(incident.severity ?? "unknown")
        .toLowerCase();

    const techniques = incident.mitre_techniques ?? [];

    const techniquesHtml = techniques.length
        ? techniques.map(technique => `
            <div class="technique-card">
                <div class="technique-id">
                    ${escapeHtml(technique.technique_id)}
                </div>
                <div class="technique-name">
                    ${escapeHtml(technique.technique_name)}
                </div>
                <div class="technique-events">
                    Supporting events:
                    ${escapeHtml(
                        (technique.event_ids ?? []).join(", ")
                    )}
                </div>
            </div>
        `).join("")
        : `<div class="empty-state">
            No MITRE ATT&CK techniques identified.
        </div>`;

    panel.innerHTML = `
        <div class="panel-header">
            <div>
                <h2>Incident ${escapeHtml(incident.incident_id)}</h2>
                <p>Detailed investigation view</p>
            </div>
            <button class="close-button"
                onclick="closeIncidentDetails()">
                Close
            </button>
        </div>

        <div class="incident-detail-content">
            <div class="detail-summary">
                <div class="detail-box">
                    <span>Severity</span>
                    <strong class="severity severity-${escapeHtml(severity)}">
                        ${escapeHtml(incident.severity)}
                    </strong>
                </div>
                <div class="detail-box">
                    <span>Correlation Score</span>
                    <strong>${escapeHtml(incident.max_correlation_score)}</strong>
                </div>
                <div class="detail-box">
                    <span>Event Count</span>
                    <strong>${escapeHtml(incident.event_count)}</strong>
                </div>
                <div class="detail-box">
                    <span>Sources</span>
                    <strong>${escapeHtml((incident.sources ?? []).join(", "))}</strong>
                </div>
            </div>

            <div class="detail-section">
                <h3>Investigation Window</h3>
                <p>First seen: ${escapeHtml(
                    incident.first_seen
                        ? new Date(incident.first_seen).toLocaleString()
                        : "Not available"
                )}</p>
                <p>Last seen: ${escapeHtml(
                    incident.last_seen
                        ? new Date(incident.last_seen).toLocaleString()
                        : "Not available"
                )}</p>
            </div>

            <div class="detail-section">
                <h3>Correlated Events</h3>
                <div id="incident-events-content">
                    <p>Loading event records...</p>
                </div>
            </div>

            <div class="detail-section">
                <h3>MITRE ATT&CK</h3>
                <div class="technique-list">${techniquesHtml}</div>
            </div>
        </div>
    `;

    panel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

    try {
        const response = await fetchApi("/events");
        const events = Array.isArray(response)
            ? response
            : response.events ?? [];

        const incidentEventIds = new Set(incident.event_ids ?? []);

        const matchedEvents = events.filter(event =>
            incidentEventIds.has(event.event_id)
        );

        const eventsContainer =
            document.getElementById("incident-events-content");

        if (!eventsContainer) return;

        if (matchedEvents.length === 0) {
            eventsContainer.innerHTML = `
                <div class="empty-state">
                    No matching event records were returned by the API.
                </div>
            `;
            return;
        }

        eventsContainer.innerHTML = matchedEvents.map(event => `
            <article class="detail-event">
                <h4>${escapeHtml(event.event_id)}</h4>

                <div class="event-fields">
                    ${formatField("Timestamp", event.timestamp)}
                    ${formatField("Source", event.source)}
                    ${formatField("Event Type", event.event_type)}
                    ${formatField("User", event.user)}
                    ${formatField("Host", event.host)}
                    ${formatField("Source IP", event.source_ip)}
                    ${formatField("Destination IP", event.destination_ip)}
                    ${formatField("Domain", event.domain)}
                    ${formatField("Artifact", event.artifact)}
                    ${formatField("Hash", event.hash)}
                    ${formatField("Description", event.description)}
                    ${formatField("Confidence", event.confidence)}
                </div>
            </article>
        `).join("");
    } catch (error) {
        console.error("Failed to load incident event records:", error);

        const eventsContainer =
            document.getElementById("incident-events-content");

        if (eventsContainer) {
            eventsContainer.innerHTML = `
                <div class="empty-state">
                    Unable to load event records. Check that the API is running.
                </div>
            `;
        }
    }
}



function closeIncidentDetails() {

    const panel =
        document.getElementById(
            "incident-detail-panel"
        );

    if (panel) {
        panel.remove();
    }
}

loadDashboard();
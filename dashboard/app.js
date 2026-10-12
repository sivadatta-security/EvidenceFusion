const API_BASE_URL = "http://127.0.0.1:8000";

/* =========================
   API REQUEST HELPER
   ========================= */

async function fetchApi(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);

    if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
    }

    return response.json();
}

/* =========================
   LOAD DATA
   ========================= */

async function loadEvents() {
    return fetchApi("/events");
}

async function loadTimeline() {
    return fetchApi("/timeline");
}

async function loadIncidents(filters = {}) {
    const params = new URLSearchParams();

    if (filters.severity) params.set("severity", filters.severity);
    if (filters.source) params.set("source", filters.source);
    if (filters.min_events) params.set("min_events", filters.min_events);

    const query = params.toString();
    return fetchApi(`/incidents${query ? `?${query}` : ""}`);
}

/* =========================
   SUMMARY CARDS
   ========================= */

function updateSummary(events, incidents, summary = null) {
    const incidentCount = summary?.total_incidents ?? incidents.length;

    const highCount = summary?.severity_counts?.High ??
        incidents.filter(incident => incident.severity === "High").length;

    const techniqueIds = new Set();

    incidents.forEach(incident => {
        (incident.mitre_techniques ?? []).forEach(technique => {
            if (technique.technique_id) {
                techniqueIds.add(technique.technique_id);
            }
        });
    });

    document.getElementById("incident-count").textContent =
        incidentCount;

    document.getElementById("high-count").textContent =
        highCount;

    document.getElementById("event-count").textContent =
        summary?.total_events ?? events.length;

    document.getElementById("technique-count").textContent =
        techniqueIds.size;
}

/* =========================
   HTML ESCAPING
   ========================= */

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

/* =========================
   RENDER TIMELINE
   ========================= */

function renderTimeline(events) {
    const container = document.getElementById("timeline");

    if (!events.length) {
        container.innerHTML = `
            <div class="empty-state">
                No investigation events found.
            </div>
        `;
        return;
    }

    container.innerHTML = events.map(event => {
        const timestamp = event.timestamp
            ? new Date(event.timestamp).toLocaleString()
            : "Time unavailable";

        return `
            <article class="timeline-item">
                <div class="timeline-time">
                    ${escapeHtml(timestamp)}
                </div>

                <div class="timeline-event">
                    <strong>${escapeHtml(event.event_type)}</strong>
                    <span>${escapeHtml(event.description)}</span>
                    <small>
                        Event ID: ${escapeHtml(event.event_id)}
                    </small>
                </div>
            </article>
        `;
    }).join("");
}

/* =========================
   RENDER INCIDENTS
   ========================= */

function renderIncidents(incidents) {
    const container = document.getElementById("incidents");

    if (!incidents.length) {
        container.innerHTML = `
            <div class="empty-state">
                No incidents detected.
            </div>
        `;
        return;
    }

    container.innerHTML = incidents.map(incident => {
        const severity = String(
            incident.severity ?? "unknown"
        ).toLowerCase();

        return `
            <button
                type="button"
                class="incident-card"
                onclick="openIncident('${escapeHtml(incident.incident_id)}')"
                aria-label="Open incident ${escapeHtml(incident.incident_id)}"
            >
                <span class="incident-id">
                    ${escapeHtml(incident.incident_id)}
                </span>

                <span>
                    <span class="severity severity-${escapeHtml(severity)}">
                        ${escapeHtml(incident.severity)}
                    </span>
                </span>

                <span class="incident-description">
                    ${escapeHtml(incident.event_count)} correlated events
                    <br>
                    Sources: ${escapeHtml(
                        (incident.sources ?? []).join(", ") || "Unknown"
                    )}
                </span>

                <span class="incident-score">
                    Score: ${escapeHtml(incident.max_correlation_score)}
                </span>
            </button>
        `;
    }).join("");
}

/* =========================
   RENDER MITRE TECHNIQUES
   ========================= */

function renderMitreTechniques(incidents) {
    const container = document.getElementById("mitre-techniques");

    const techniques = [];
    const seen = new Set();

    incidents.forEach(incident => {
        (incident.mitre_techniques ?? []).forEach(technique => {
            if (
                technique.technique_id &&
                !seen.has(technique.technique_id)
            ) {
                seen.add(technique.technique_id);
                techniques.push(technique);
            }
        });
    });

    if (!techniques.length) {
        container.innerHTML = `
            <div class="empty-state">
                No MITRE ATT&CK techniques identified.
            </div>
        `;
        return;
    }

    container.innerHTML = techniques.map(technique => `
        <article class="technique-card">
            <div class="technique-id">
                ${escapeHtml(technique.technique_id)}
            </div>

            <div class="technique-name">
                ${escapeHtml(technique.technique_name)}
            </div>

            <div class="technique-events">
                Supporting events:
                ${escapeHtml((technique.event_ids ?? []).join(", "))}
            </div>
        </article>
    `).join("");
}

/* =========================
   INCIDENT EVIDENCE
   ========================= */


function renderIncidentEvidence(evidence) {
    const container = document.getElementById(
        "incident-evidence-content"
    );

    if (!container) return;

    if (!evidence.length) {
        container.innerHTML = `
            <div class="empty-state">
                No evidence has been linked to this incident yet.
                Link evidence to one of the incident's events through
                the API to display it here.
            </div>
        `;
        return;
    }

    container.innerHTML = evidence.map(record => {
        const links = record.event_links ?? [];
        const metadata = record.metadata ?? {};

        const verification = String(
            record.verification_status ?? "not_verified"
        ).toLowerCase();

        const allowedStatuses = [
            "verified",
            "failed",
            "not_verified",
            "unavailable"
        ];

        const statusClass = allowedStatuses.includes(verification)
            ? verification
            : "unknown";

        return `
            <article class="evidence-card"
                     data-evidence-card="${escapeHtml(record.evidence_id)}">

                <div class="evidence-card-header">
                    <div class="evidence-heading">
                        <h4>${escapeHtml(record.evidence_id)}</h4>
                        <p>${escapeHtml(record.artifact_type)}</p>
                    </div>

                    <span class="verification verification-${statusClass}"
                          data-verification-status>
                        ${escapeHtml(verification.replace(/_/g, " "))}
                    </span>
                </div>

                <div class="event-fields">
                    ${formatField("Source Reference", record.source_reference)}
                    ${formatField("Hash Algorithm", record.hash_algorithm)}
                    ${formatField("SHA-256", record.sha256)}
                    ${formatField("Acquisition Method", record.acquisition_method)}
                    ${formatField("Acquired At", record.acquired_at)}
                    ${formatField("Acquired By", record.acquired_by)}
                </div>

                <div class="evidence-actions">
                    <button type="button"
                            class="evidence-action-button"
                            data-action="verify"
                            data-evidence-id="${escapeHtml(record.evidence_id)}">
                        Verify Integrity
                    </button>

                    <button type="button"
                            class="evidence-action-button"
                            data-action="custody"
                            data-evidence-id="${escapeHtml(record.evidence_id)}">
                        View Chain of Custody
                    </button>
                </div>

                <p class="evidence-action-message"
                   data-verification-message
                   aria-live="polite"></p>

                <details class="evidence-custody"
                         data-custody-panel>
                    <summary>Chain of custody history</summary>
                    <div data-custody-content>
                        Select "View Chain of Custody" to load audit entries.
                    </div>
                </details>

                <div class="evidence-links">
                    <strong>Linked Events (${links.length})</strong>
                    ${
                        links.length
                            ? `
                                <ul>
                                    ${links.map(link => `
                                        <li>
                                            <code>${escapeHtml(link.event_id)}</code>
                                            <span class="relationship">
                                                ${escapeHtml(link.relationship)}
                                            </span>
                                        </li>
                                    `).join("")}
                                </ul>
                            `
                            : `<p>No event associations returned.</p>`
                    }
                </div>

                <details class="evidence-metadata">
                    <summary>Additional metadata</summary>
                    <pre>${escapeHtml(JSON.stringify(metadata, null, 2))}</pre>
                </details>
            </article>
        `;
    }).join("");

    container.querySelectorAll('[data-action="verify"]').forEach(button => {
        button.addEventListener("click", async () => {
            await verifyEvidenceIntegrity(
                button.dataset.evidenceId,
                button
            );
        });
    });

    container.querySelectorAll('[data-action="custody"]').forEach(button => {
        button.addEventListener("click", async () => {
            await loadEvidenceCustody(
                button.dataset.evidenceId,
                button
            );
        });
    });
}


/* =========================
   VERIFY EVIDENCE INTEGRITY
   ========================= */

async function verifyEvidenceIntegrity(evidenceId, button) {
    const card = button.closest("[data-evidence-card]");
    if (!card) return;

    const message = card.querySelector("[data-verification-message]");
    const statusElement = card.querySelector("[data-verification-status]");

    const verifiedBy = prompt(
        "Enter the investigator ID or name performing verification:"
    );

    if (verifiedBy === null) return;

    if (!verifiedBy.trim() || verifiedBy.trim().length > 128) {
        message.textContent =
            "Enter an investigator name between 1 and 128 characters.";
        return;
    }

    button.disabled = true;
    message.textContent = "Verifying evidence integrity...";

    try {
        const response = await fetch(
            `${API_BASE_URL}/evidence/${encodeURIComponent(evidenceId)}/verify` +
            `?verified_by=${encodeURIComponent(verifiedBy.trim())}`,
            { method: "POST" }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail ?? `Verification failed: HTTP ${response.status}`
            );
        }

        const result = data.verification;
        const status = String(
            result.verification_status ?? "unavailable"
        ).toLowerCase();

        const allowedStatuses = [
            "verified",
            "failed",
            "not_verified",
            "unavailable"
        ];

        const safeStatus = allowedStatuses.includes(status)
            ? status
            : "unknown";

        statusElement.className =
            `verification verification-${safeStatus}`;

        statusElement.textContent = safeStatus.replace(/_/g, " ");

        message.textContent =
            `${result.reason ?? "Verification completed."} ` +
            `Expected SHA-256: ${result.expected_sha256 ?? "Unavailable"}. ` +
            `Calculated SHA-256: ${result.calculated_sha256 ?? "Unavailable"}.`;

        // Refresh custody history so the new attempt appears immediately.
        const custodyButton = card.querySelector('[data-action="custody"]');

        if (custodyButton) {
            await loadEvidenceCustody(evidenceId, custodyButton);
        }
    } catch (error) {
        console.error("Evidence verification failed:", error);
        message.textContent =
            `Could not complete verification: ${error.message}`;
    } finally {
        button.disabled = false;
    }
}


/* =========================
   LOAD CHAIN OF CUSTODY
   ========================= */

async function loadEvidenceCustody(evidenceId, button) {
    const card = button.closest("[data-evidence-card]");
    if (!card) return;

    const panel = card.querySelector("[data-custody-panel]");
    const content = card.querySelector("[data-custody-content]");

    panel.open = true;
    content.textContent = "Loading custody history...";
    button.disabled = true;

    try {
        const result = await fetchApi(
            `/evidence/${encodeURIComponent(evidenceId)}/custody`
        );

        const entries = result.audit_entries ?? [];

        if (!entries.length) {
            content.innerHTML = `
                <p class="empty-state">No custody audit entries found.</p>
            `;
            return;
        }

        content.innerHTML = entries.map(entry => `
            <article class="custody-entry">
                <h4>${escapeHtml(entry.action)}</h4>
                <div class="event-fields">
                    ${formatField("Audit ID", entry.audit_id)}
                    ${formatField("Investigator", entry.actor)}
                    ${formatField(
                        "Recorded At",
                        new Date(entry.occurred_at).toLocaleString()
                    )}
                </div>
                <details>
                    <summary>Audit details</summary>
                    <pre>${escapeHtml(
                        JSON.stringify(entry.details ?? {}, null, 2)
                    )}</pre>
                </details>
            </article>
        `).join("");
    } catch (error) {
        console.error("Failed to load custody history:", error);
        content.textContent =
            `Could not load custody history: ${error.message}`;
    } finally {
        button.disabled = false;
    }
}


async function loadDashboard() {
    const status = document.querySelector(".status span:last-child");

    try {
        const [events, timeline, incidents, summary] = await Promise.all([
            loadEvents(),
            loadTimeline(),
            loadIncidents(),
            fetchApi("/dashboard/summary")
        ]);

        updateSummary(events, incidents, summary);
        renderTimeline(timeline);
        renderIncidents(incidents);
        renderMitreTechniques(incidents);

        if (status) {
            status.textContent = "System Connected";
        }
    } catch (error) {
        console.error("Failed to load dashboard:", error);

        if (status) {
            status.textContent = "API Unavailable";
        }

        document.getElementById("timeline").innerHTML = `
            <div class="empty-state">
                Unable to connect to EvidenceFusion API.
                Make sure the backend is running.
            </div>
        `;

        document.getElementById("incidents").innerHTML = `
            <div class="empty-state">
                Incident data could not be loaded.
            </div>
        `;

        document.getElementById("mitre-techniques").innerHTML = `
            <div class="empty-state">
                Threat analysis data could not be loaded.
            </div>
        `;
    }
}

/* =========================
   OPEN INCIDENT DETAILS
   ========================= */

async function openIncident(incidentId) {
    try {
        const incident = await fetchApi(
            `/incidents/${encodeURIComponent(incidentId)}`
        );

        await showIncidentDetails(incident);
    } catch (error) {
        console.error("Failed to load incident:", error);
        alert("Unable to load incident details. Check the API.");
    }
}

/* =========================
   INCIDENT DETAIL VIEW
   ========================= */

async function showIncidentDetails(incident) {
    const existingPanel = document.getElementById(
        "incident-detail-panel"
    );

    if (existingPanel) {
        existingPanel.remove();
    }

    const dashboard = document.querySelector(".dashboard");

    if (!dashboard) {
        console.error("Dashboard container was not found.");
        return;
    }

    const panel = document.createElement("section");
    panel.id = "incident-detail-panel";
    panel.className = "panel incident-detail-panel";

    dashboard.prepend(panel);

    const severity = String(
        incident.severity ?? "unknown"
    ).toLowerCase();

    const techniques = incident.mitre_techniques ?? [];

    const techniquesHtml = techniques.length
        ? techniques.map(technique => `
            <article class="technique-card">
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
            </article>
        `).join("")
        : `
            <div class="empty-state">
                No MITRE ATT&CK techniques identified.
            </div>
        `;

    panel.innerHTML = `
        <div class="panel-header">
            <div>
                <h2>Incident ${escapeHtml(incident.incident_id)}</h2>
                <p>Detailed investigation and evidence view</p>
            </div>

            <button
                type="button"
                class="close-button"
                onclick="closeIncidentDetails()"
            >
                Close
            </button>
        </div>

        <div class="incident-detail-content">
            <div class="detail-summary">
                <div class="detail-box">
                    <span>Severity</span>
                    <strong>
                        <span class="severity severity-${escapeHtml(severity)}">
                            ${escapeHtml(incident.severity)}
                        </span>
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
                    <strong>
                        ${escapeHtml((incident.sources ?? []).join(", "))}
                    </strong>
                </div>
            </div>

            <div class="detail-section">
                <h3>Investigation Window</h3>
                <p>
                    First seen:
                    ${escapeHtml(
                        incident.first_seen
                            ? new Date(incident.first_seen).toLocaleString()
                            : "Not available"
                    )}
                </p>
                <p>
                    Last seen:
                    ${escapeHtml(
                        incident.last_seen
                            ? new Date(incident.last_seen).toLocaleString()
                            : "Not available"
                    )}
                </p>
            </div>

            <div class="detail-section">
                <h3>Correlated Events</h3>
                <div id="incident-events-content">
                    <p>Loading event records...</p>
                </div>
            </div>

            <div class="detail-section">
                <h3>Supporting Digital Evidence</h3>
                <p class="section-description">
                    Artifacts associated with the events in this incident.
                </p>
                <div id="incident-evidence-content">
                    <p>Loading evidence records...</p>
                </div>
            </div>

            <div class="detail-section">
                <h3>MITRE ATT&CK</h3>
                <div class="technique-list">
                    ${techniquesHtml}
                </div>
            </div>
        </div>
    `;

    panel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

    const eventsContainer = document.getElementById(
        "incident-events-content"
    );

    const evidenceContainer = document.getElementById(
        "incident-evidence-content"
    );

    try {
        const [events, evidenceResult] = await Promise.all([
            fetchApi("/events"),
            fetchApi(
                `/incidents/${encodeURIComponent(incident.incident_id)}/evidence`
            )
        ]);

        const incidentEventIds = new Set(incident.event_ids ?? []);

        const matchedEvents = events.filter(event =>
            incidentEventIds.has(event.event_id)
        );

        if (eventsContainer) {
            eventsContainer.innerHTML = matchedEvents.length
                ? matchedEvents.map(event => `
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
                `).join("")
                : `
                    <div class="empty-state">
                        No matching event records were found.
                    </div>
                `;
        }

        renderIncidentEvidence(evidenceResult.evidence ?? []);
    } catch (error) {
        console.error(
            "Failed to load incident events or evidence:",
            error
        );

        if (eventsContainer) {
            eventsContainer.innerHTML = `
                <div class="empty-state">
                    Unable to load event records.
                </div>
            `;
        }

        if (evidenceContainer) {
            evidenceContainer.innerHTML = `
                <div class="empty-state">
                    Unable to load incident evidence.
                    Check the API and its incident evidence endpoint.
                </div>
            `;
        }
    }
}

/* =========================
   CLOSE INCIDENT DETAILS
   ========================= */

function closeIncidentDetails() {
    const panel = document.getElementById("incident-detail-panel");

    if (panel) {
        panel.remove();
    }
}

/* =========================
   INCIDENT FILTERS
   ========================= */

function readIncidentFilters() {
    const severity = document.getElementById("filter-severity").value;
    const source = document.getElementById("filter-source").value.trim();
    const minEvents = document.getElementById("filter-min-events").value;

    return {
        severity,
        source,
        min_events: minEvents || "1"
    };
}

async function applyIncidentFilters() {
    const container = document.getElementById("incidents");
    const filterStatus = document.getElementById("incident-filter-status");

    container.innerHTML = '<div class="empty-state">Loading filtered incidents...</div>';
    filterStatus.textContent = "Applying filters...";

    try {
        const incidents = await loadIncidents(readIncidentFilters());
        renderIncidents(incidents);
        filterStatus.textContent = `${incidents.length} incident(s) match the selected filters.`;
    } catch (error) {
        console.error("Failed to filter incidents:", error);
        container.innerHTML = `
            <div class="empty-state">
                Could not load filtered incidents. Check the API connection and try again.
            </div>
        `;
        filterStatus.textContent = `Filter request failed: ${error.message}`;
    }
}

function setupIncidentFilters() {
    const form = document.getElementById("incident-filters");
    const resetButton = document.getElementById("reset-incident-filters");

    if (!form || !resetButton) return;

    form.addEventListener("submit", async event => {
        event.preventDefault();

        const minEvents = Number(document.getElementById("filter-min-events").value);
        if (!Number.isInteger(minEvents) || minEvents < 1) {
            document.getElementById("incident-filter-status").textContent =
                "Minimum events must be a whole number greater than or equal to 1.";
            return;
        }

        await applyIncidentFilters();
    });

    resetButton.addEventListener("click", async () => {
        form.reset();
        document.getElementById("filter-min-events").value = "1";
        await applyIncidentFilters();
    });
}

/* =========================
   INITIALIZE DASHBOARD
   ========================= */

setupIncidentFilters();
loadDashboard();
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

async function loadTimeline(filters = {}) {
    const params = new URLSearchParams();

    if (filters.user) params.set("user", filters.user);
    if (filters.host) params.set("host", filters.host);
    if (filters.source) params.set("source", filters.source);
    if (filters.start_time) params.set("start_time", filters.start_time);
    if (filters.end_time) params.set("end_time", filters.end_time);

    const query = params.toString();
    return fetchApi(`/timeline${query ? `?${query}` : ""}`);
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
   RENDER MITRE ASSESSMENTS
   ========================= */

function renderMitreAssessments(incidents) {
    const container = document.getElementById("mitre-assessments");
    if (!container) return;

    const assessments = [];
    const seen = new Set();

    (incidents ?? []).forEach(incident => {
        const result = incident.mitre_assessment ?? {};

        (result.assessments ?? []).forEach(assessment => {
            const key = `${incident.incident_id}:${assessment.event_id ?? "unknown"}`;
            if (seen.has(key)) return;
            seen.add(key);
            assessments.push({
                ...assessment,
                incident_id: incident.incident_id
            });
        });
    });

    const counts = assessments.reduce((totals, item) => {
        const status = item.status ?? "no_assessment";
        totals[status] = (totals[status] ?? 0) + 1;
        return totals;
    }, {});

    const summary = `
        <div class="assessment-summary" aria-label="Assessment counts">
            <span>Mapped: ${counts.mapped ?? 0}</span>
            <span>Needs review: ${counts.needs_review ?? 0}</span>
            <span>No assessment: ${counts.no_assessment ?? 0}</span>
        </div>
    `;

    if (!assessments.length) {
        container.innerHTML = summary + `
            <div class="empty-state">
                No event assessments are available for the displayed incidents.
            </div>
        `;
        return;
    }

    container.innerHTML = summary + assessments.map(item => {
        const status = String(item.status ?? "unknown");
        const statusLabels = {
            mapped: "Explicit mapping",
            needs_review: "Needs review",
            no_assessment: "No assessment",
            excluded: "Excluded"
        };
        const statusLabel = statusLabels[status] ?? status.replace(/_/g, " ");
        const indicators = (item.indicators ?? []).length
            ? item.indicators.map(value => `
                <span class="assessment-indicator">${escapeHtml(value)}</span>
            `).join("")
            : '<span class="muted-text">None recorded</span>';
        const technique = item.technique_id
            ? `<p><strong>Technique:</strong> ${escapeHtml(item.technique_id)} — ${escapeHtml(item.technique_name ?? "Name unavailable")}</p>`
            : '<p><strong>Technique:</strong> Not assigned</p>';
                    return `
            <article class="assessment-card">
                <div class="assessment-card-header">
                    <div>
                        <h3>${escapeHtml(item.event_id ?? "Unknown event")}</h3>
                        <p>Incident ${escapeHtml(item.incident_id ?? "Unknown")}</p>
                    </div>

                    <span class="assessment-status assessment-status-${escapeHtml(status)}">
                        ${escapeHtml(statusLabel)}
                    </span>
                </div>

                ${technique}

                <p><strong>Reason</strong></p>
                <p>${escapeHtml(item.reason ?? "No reason supplied.")}</p>

                <p><strong>Indicators</strong></p>
                <div class="assessment-indicators">${indicators}</div>

                <p><strong>Recommended action</strong></p>
                <p>${escapeHtml(item.recommended_action ?? "Review the source evidence.")}</p>
            </article>
        `;
    }).join("");
}

/* =========================
   INCIDENT ASSESSMENT DETAILS
   ========================= */

function renderIncidentAssessmentDetails(incident) {
    const result = incident.mitre_assessment ?? {};
    const assessments = result.assessments ?? [];

    if (!assessments.length) {
        return `
            <div class="empty-state">
                No assessment details are available for this incident.
            </div>
        `;
    }

    return assessments.map(item => {
        const status = String(item.status ?? "unknown");

        const statusLabels = {
            mapped: "Explicit mapping",
            needs_review: "Needs review",
            no_assessment: "No assessment",
            excluded: "Excluded"
        };

        const indicators = (item.indicators ?? []).length
            ? item.indicators.map(value => `
                <span class="assessment-indicator">
                    ${escapeHtml(value)}
                </span>
            `).join("")
            : '<span class="muted-text">None recorded</span>';

        return `
            <article class="assessment-card">
                <div class="assessment-card-header">
                    <div>
                        <h4>${escapeHtml(item.event_id ?? "Unknown event")}</h4>
                    </div>

                    <span class="assessment-status assessment-status-${escapeHtml(status)}">
                        ${escapeHtml(
                            statusLabels[status] ?? status.replace(/_/g, " ")
                        )}
                    </span>
                </div>

                <p>
                    <strong>Technique:</strong>
                    ${
                        item.technique_id
                            ? `${escapeHtml(item.technique_id)} — ${escapeHtml(item.technique_name ?? "Name unavailable")}`
                            : "Not assigned"
                    }
                </p>

                <p><strong>Reason:</strong> ${escapeHtml(item.reason ?? "No reason supplied.")}</p>

                <p><strong>Indicators:</strong></p>
                <div class="assessment-indicators">${indicators}</div>

                <p><strong>Recommended action:</strong> ${escapeHtml(item.recommended_action ?? "Review the source evidence.")}</p>
            </article>
        `;
    }).join("");
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

        const result = data.verification ?? {};
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

    if (!panel || !content) return;

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
                <p class="empty-state">
                    No custody audit entries found.
                </p>
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
                        entry.occurred_at
                            ? new Date(entry.occurred_at).toLocaleString()
                            : "Unavailable"
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


    /* =========================
    INCIDENT DETAILS
    ========================= */

    async function openIncident(incidentId) {
        const modal = document.getElementById("incident-modal");
        const content = document.getElementById("incident-details");

        if (!modal || !content) {
            console.error("Incident detail modal elements were not found.");
            return;
        }

    modal.classList.add("open");
    content.innerHTML = `
        <div class="loading-state">Loading incident details...</div>
    `;

    try {
        const incident = await fetchApi(
            `/incidents/${encodeURIComponent(incidentId)}`
        );

        const events = incident.events ?? [];
        const techniques = incident.mitre_techniques ?? [];

        content.innerHTML = `
            <div class="incident-detail-header">
                <h2>${escapeHtml(incident.incident_id)}</h2>
                <span class="severity severity-${escapeHtml(
                    String(incident.severity ?? "unknown").toLowerCase()
                )}">
                    ${escapeHtml(incident.severity ?? "Unknown")}
                </span>
            </div>

            <p>${escapeHtml(
                incident.description ?? "No description available."
            )}</p>

            <div class="event-fields">
                ${formatField("Incident ID", incident.incident_id)}
                ${formatField("Severity", incident.severity)}
                ${formatField("Event Count", events.length)}
                ${formatField("Sources", (incident.sources ?? []).join(", "))}
                ${formatField("Correlation Score", incident.max_correlation_score)}
            </div>

            <section class="incident-detail-section">
                <h3>Correlated Events</h3>
                ${
                    events.length
                        ? events.map(event => `
                            <article class="event-detail-card">
                                <h4>${escapeHtml(event.event_id)}</h4>
                                <div class="event-fields">
                                    ${formatField("Type", event.event_type)}
                                    ${formatField("Timestamp", event.timestamp)}
                                    ${formatField("Source", event.source)}
                                    ${formatField("User", event.user)}
                                    ${formatField("Host", event.host)}
                                    ${formatField("Source IP", event.source_ip)}
                                    ${formatField("Destination IP", event.destination_ip)}
                                    ${formatField("Domain", event.domain)}
                                </div>
                                <p>${escapeHtml(event.description)}</p>
                            </article>
                        `).join("")
                        : `<p class="empty-state">No event details returned.</p>`
                }
            </section>

            <section class="incident-detail-section">
                <h3>MITRE ATT&amp;CK Techniques</h3>
                ${
                    techniques.length
                        ? techniques.map(technique => `
                            <article class="technique-card">
                                <h4>
                                    ${escapeHtml(technique.technique_id)}
                                    — ${escapeHtml(technique.technique_name)}
                                </h4>
                                <p>${escapeHtml(
                                    technique.description ?? ""
                                )}</p>
                                <p>
                                    Supporting events:
                                    ${escapeHtml(
                                        (technique.event_ids ?? []).join(", ")
                                    )}
                                </p>
                            </article>
                        `).join("")
                        : `<p class="empty-state">
                            No ATT&amp;CK techniques have been assigned.
                        </p>`
                }
            </section>

            <section class="incident-detail-section">
                <h3>MITRE Assessment Review</h3>
                <p class="muted-text">
                    Assessment indicators are investigative leads, not proof
                    of malicious activity. Validate them against original
                    evidence and corroborating sources.
                </p>
                ${renderIncidentAssessmentDetails(incident)}
            </section>
        `;

        await loadIncidentEvidence(incidentId);
    } catch (error) {
        console.error("Failed to load incident details:", error);

        content.innerHTML = `
            <div class="error-message">
                Could not load incident details:
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}


/* =========================
   INCIDENT EVIDENCE LOADING
   ========================= */

async function loadIncidentEvidence(incidentId) {
    const container = document.getElementById(
        "incident-evidence-content"
    );

    if (!container) return;

    container.innerHTML = `
        <div class="loading-state">Loading linked evidence...</div>
    `;

    try {
        const result = await fetchApi(
            `/incidents/${encodeURIComponent(incidentId)}/evidence`
        );

        renderIncidentEvidence(result.evidence ?? []);
    } catch (error) {
        // The incident details remain available even if the evidence
        // endpoint has not been implemented or returns an error.
        console.warn("Incident evidence could not be loaded:", error);

        container.innerHTML = `
            <div class="empty-state">
                Evidence could not be loaded for this incident.
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}


/* =========================
   CLOSE INCIDENT MODAL
   ========================= */

function closeIncidentModal() {
    const modal = document.getElementById("incident-modal");

    if (modal) {
        modal.classList.remove("open");
    }
}


/* =========================
   APPLY INCIDENT FILTERS
   ========================= */

async function applyIncidentFilters() {
    const severityElement = document.getElementById("severity-filter");
    const sourceElement = document.getElementById("source-filter");
    const minEventsElement = document.getElementById("min-events-filter");

    const filters = {
        severity: severityElement?.value || "",
        source: sourceElement?.value || "",
        min_events: minEventsElement?.value || ""
    };

    try {
        const incidents = await loadIncidents(filters);

        renderIncidents(incidents);
        renderMitreTechniques(incidents);
        renderMitreAssessments(incidents);
    } catch (error) {
        console.error("Failed to apply incident filters:", error);

        const incidentContainer = document.getElementById("incidents");

        if (incidentContainer) {
            incidentContainer.innerHTML = `
                <div class="error-message">
                    Could not filter incidents:
                    ${escapeHtml(error.message)}
                </div>
            `;
        }

        const assessmentContainer = document.getElementById(
            "mitre-assessments"
        );

        if (assessmentContainer) {
            assessmentContainer.innerHTML = `
                <div class="error-message">
                    Assessment results could not be refreshed.
                </div>
            `;
        }
    }
}


/* =========================
   DATASET AND THREAT INTELLIGENCE
   ========================= */

async function loadDatasetSummary() {
    const container = document.getElementById("dataset-summary");
    if (!container) return;

    try {
        const summary = await fetchApi("/datasets/sample/summary");
        const counts = (summary.datasets ?? []).map(item => `
            <div class="integration-stat">
                <span>${escapeHtml(item.dataset)}</span>
                <strong>${escapeHtml(item.record_count)}</strong>
            </div>
        `).join("");

        container.innerHTML = `
            <div class="integration-stats">
                <div class="integration-stat total">
                    <span>Total sample rows</span>
                    <strong>${escapeHtml(summary.total_records ?? 0)}</strong>
                </div>
                ${counts}
            </div>
            <p class="muted-text">${escapeHtml(summary.note ?? "Benchmark data is separate from operational events.")}</p>
        `;
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                Dataset sample is not available yet. Create it with the documented dataset importer.
                <small>${escapeHtml(error.message)}</small>
            </div>
        `;
    }
}

async function loadDatasetRecords(dataset = "") {
    const container = document.getElementById("dataset-records");
    if (!container) return;

    container.innerHTML = '<div class="loading-state">Loading sample records...</div>';
    const params = new URLSearchParams({ limit: "10", offset: "0" });
    if (dataset) params.set("dataset", dataset);

    try {
        const result = await fetchApi(`/datasets/sample/records?${params.toString()}`);
        if (!result.records?.length) {
            container.innerHTML = '<div class="empty-state">No sample records found.</div>';
            return;
        }

        container.innerHTML = `
            <p class="muted-text">Showing ${result.records.length} of ${escapeHtml(result.total_records)} records.</p>
            <div class="integration-record-list">
                ${result.records.map(record => `
                    <article class="integration-record">
                        <div><strong>${escapeHtml(record.dataset)}</strong><span>${escapeHtml(record.event_type)}</span></div>
                        <p>Original label: ${escapeHtml(record.original_label)} · Row ${escapeHtml(record.source_row_number)}</p>
                        <small>${escapeHtml(record.event_id)}</small>
                    </article>
                `).join("")}
            </div>
        `;
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">Could not load benchmark rows. ${escapeHtml(error.message)}</div>
        `;
    }
}

async function lookupThreatIndicator(event) {
    event.preventDefault();
    const type = document.getElementById("threat-indicator-type")?.value;
    const value = document.getElementById("threat-indicator-value")?.value.trim();
    const container = document.getElementById("threat-intel-result");
    if (!container || !type || !value) return;

    container.innerHTML = '<div class="loading-state">Looking up existing VirusTotal report...</div>';
    try {
        const response = await fetchApi(`/threat-intel/${encodeURIComponent(type)}/${encodeURIComponent(value)}`);
        const stats = response.analysis_stats ?? {};
        const statCards = ["malicious", "suspicious", "harmless", "undetected"].map(key => `
            <div class="integration-stat"><span>${escapeHtml(key)}</span><strong>${escapeHtml(stats[key] ?? 0)}</strong></div>
        `).join("");
        const categories = response.categories && typeof response.categories === "object"
            ? Object.entries(response.categories).slice(0, 8).map(([source, category]) =>
                `<li><strong>${escapeHtml(source)}:</strong> ${escapeHtml(category)}</li>`).join("")
            : "";

        container.innerHTML = `
            <div class="threat-result">
                <div class="threat-result-heading">
                    <strong>${escapeHtml(response.provider)} report</strong>
                    <span>Reputation: ${escapeHtml(response.reputation ?? "Not available")}</span>
                </div>
                <p class="threat-indicator">${escapeHtml(response.indicator_type)} · ${escapeHtml(response.indicator)}</p>
                <div class="integration-stats">${statCards}</div>
                ${response.last_analysis_date ? `<p class="muted-text">Last analysis timestamp: ${escapeHtml(response.last_analysis_date)}</p>` : ""}
                ${categories ? `<ul class="threat-categories">${categories}</ul>` : ""}
                <p class="muted-text">${escapeHtml(response.disclaimer ?? "Validate third-party intelligence against original evidence.")}</p>
                <a class="filter-button inline-link" href="${escapeHtml(response.permalink)}" target="_blank" rel="noopener noreferrer">Open provider report</a>
            </div>
        `;
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                Lookup unavailable. Check the API key, rate limit, and indicator.
                <small>${escapeHtml(error.message)}</small>
            </div>
        `;
    }
}

/* =========================
   DASHBOARD REFRESH
   ========================= */

async function loadDashboard() {
    try {
        const [events, incidents] = await Promise.all([
            loadEvents(),
            loadIncidents()
        ]);

        renderTimeline(events);
        renderIncidents(incidents);
        renderMitreTechniques(incidents);
        renderMitreAssessments(incidents);
        updateSummary(events, incidents);
    } catch (error) {
        console.error("Dashboard loading failed:", error);

        const timeline = document.getElementById("timeline");
        const incidents = document.getElementById("incidents");
        const assessments = document.getElementById("mitre-assessments");

        if (timeline) {
            timeline.innerHTML = `
                <div class="error-message">
                    Could not load timeline data.
                    ${escapeHtml(error.message)}
                </div>
            `;
        }

        if (incidents) {
            incidents.innerHTML = `
                <div class="error-message">
                    Could not load incidents.
                </div>
            `;
        }

        if (assessments) {
            assessments.innerHTML = `
                <div class="error-message">
                    MITRE assessments could not be loaded.
                </div>
            `;
        }
    }
}


/* =========================
   INITIALIZE DASHBOARD
   ========================= */

document.addEventListener("DOMContentLoaded", () => {
    const datasetForm = document.getElementById("dataset-records-form");
    if (datasetForm) {
        datasetForm.addEventListener("submit", event => {
            event.preventDefault();
            loadDatasetRecords(document.getElementById("dataset-records-source")?.value || "");
        });
    }

    const threatForm = document.getElementById("threat-intel-form");
    if (threatForm) {
        threatForm.addEventListener("submit", lookupThreatIndicator);
    }

    loadDatasetSummary();

    const refreshButton = document.getElementById("refresh-dashboard");

    if (refreshButton) {
        refreshButton.addEventListener("click", loadDashboard);
    }

    const filterButton = document.getElementById("apply-filters");

    if (filterButton) {
        filterButton.addEventListener("click", applyIncidentFilters);
    }

    const closeButton = document.getElementById("close-incident-modal");

    if (closeButton) {
        closeButton.addEventListener("click", closeIncidentModal);
    }

    const modal = document.getElementById("incident-modal");

    if (modal) {
        modal.addEventListener("click", event => {
            if (event.target === modal) {
                closeIncidentModal();
            }
        });
    }

    document.addEventListener("keydown", event => {
        if (event.key === "Escape") {
            closeIncidentModal();
        }
    });

    loadDashboard();
});
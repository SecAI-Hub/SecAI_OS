package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ---------- integration configuration ----------

// IntegrationConfig defines connections to external SecAI services.
type IntegrationConfig struct {
	IncidentRecorderURL string `yaml:"incident_recorder_url"` // e.g. http://127.0.0.1:8515
	RuntimeAttestorURL  string `yaml:"runtime_attestor_url"`  // e.g. http://127.0.0.1:8505
}

// ---------- GPU attestation state (for runtime-attestor) ----------

// GPUAttestState summarises GPU integrity for inclusion in the runtime
// attestation bundle.  Exported via /v1/attest-state.
type GPUAttestState struct {
	Timestamp      time.Time              `json:"timestamp"`
	Verdict        Verdict                `json:"verdict"`
	CompositeScore float64                `json:"composite_score"`
	ProbeStatuses  map[string]ProbeStatus `json:"probe_statuses"`
	ProbeScores    map[string]float64     `json:"probe_scores"`
	DriverVersion  string                 `json:"driver_version,omitempty"`
	DeviceNodes    []string               `json:"device_nodes,omitempty"`
	Trend          float64                `json:"trend"`
}

// buildAttestState creates an attestation summary from the current scoring
// engine state.  The caller is responsible for obtaining any needed locks
// on latestResults beforehand.
func buildAttestState(scorer *ScoringEngine, latestResults []ProbeResult) GPUAttestState {
	latest := scorer.Latest()

	state := GPUAttestState{
		Timestamp:     time.Now().UTC(),
		Verdict:       VerdictUnknown,
		ProbeStatuses: make(map[string]ProbeStatus),
		ProbeScores:   make(map[string]float64),
		Trend:         scorer.Trend(10),
	}

	if latest != nil {
		state.Verdict = latest.Verdict
		state.CompositeScore = latest.CompositeScore
		state.ProbeStatuses = latest.ProbeStatuses
		state.ProbeScores = latest.ProbeScores
	}

	// Extract driver version and device nodes from latest probe results.
	for _, r := range latestResults {
		if r.Type == ProbeDriverFingerprint {
			for _, f := range r.Findings {
				if strings.Contains(f.Description, "driver version") {
					state.DriverVersion = f.Detail
				}
			}
		}
		if r.Type == ProbeDeviceAllowlist {
			for _, f := range r.Findings {
				if strings.Contains(f.Description, "device nodes detected") {
					state.DeviceNodes = strings.Split(f.Detail, ", ")
				}
			}
		}
	}

	return state
}

// ---------- incident reporting ----------

// IncidentReport is the JSON payload POSTed to the incident-recorder
// when GPU integrity degrades.
type IncidentReport struct {
	Class       string                 `json:"class"`
	Source      string                 `json:"source"`
	Description string                `json:"description"`
	Severity    string                `json:"severity,omitempty"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
}

// reportIncident sends an incident to the incident-recorder service.
// Errors are logged but never fatal; GPU monitoring continues even if
// reporting fails (fail-open on telemetry, fail-closed on integrity).
func reportIncident(recorderURL, token string, entry ScoreEntry, results []ProbeResult) {
	if recorderURL == "" {
		return
	}

	// Only report warning or critical verdicts.
	if entry.Verdict != VerdictWarning && entry.Verdict != VerdictCritical {
		return
	}

	incidentClass := "model_behavior_anomaly"
	severity := "high"
	description := fmt.Sprintf("GPU integrity %s: composite score %.2f", entry.Verdict, entry.CompositeScore)

	// Classify the incident based on what probes triggered.
	for _, r := range results {
		switch {
		case r.Type == ProbeTensorHash && r.Status == StatusFail:
			incidentClass = "manifest_mismatch"
			severity = "critical"
			description = "GPU model file hash mismatch detected"
		case r.Type == ProbeECCStatus && r.Status == StatusFail:
			incidentClass = "integrity_violation"
			severity = "critical"
			description = "GPU uncorrected ECC memory errors detected"
		case r.Type == ProbeDriverFingerprint && r.Status == StatusFail:
			incidentClass = "integrity_violation"
			severity = "high"
			description = "GPU driver fingerprint changed unexpectedly"
		case r.Type == ProbeDeviceAllowlist && r.Status == StatusFail:
			incidentClass = "integrity_violation"
			severity = "high"
			description = "Unexpected GPU device nodes detected"
		}
	}

	// Build evidence from probe findings.
	evidence := map[string]interface{}{
		"verdict":         string(entry.Verdict),
		"composite_score": entry.CompositeScore,
		"probe_statuses":  entry.ProbeStatuses,
	}

	failedProbes := []string{}
	for _, r := range results {
		if r.Status == StatusFail || r.Status == StatusDrift {
			failedProbes = append(failedProbes, r.Probe)
		}
	}
	evidence["failed_probes"] = failedProbes

	report := IncidentReport{
		Class:       incidentClass,
		Source:      "gpu-integrity-watch",
		Description: description,
		Severity:    severity,
		Evidence:    evidence,
	}

	body, err := json.Marshal(report)
	if err != nil {
		log.Printf("warning: failed to marshal incident report: %v", err)
		return
	}

	url := strings.TrimSuffix(recorderURL, "/") + "/api/v1/incidents/report"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("warning: failed to create incident request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("warning: failed to report incident to %s: %v", recorderURL, err)
		return
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("incident reported: class=%s severity=%s", incidentClass, severity)
		auditLog("incident_reported", map[string]interface{}{
			"class":    incidentClass,
			"severity": severity,
			"verdict":  string(entry.Verdict),
		})
	} else {
		log.Printf("warning: incident-recorder returned %d", resp.StatusCode)
	}
}

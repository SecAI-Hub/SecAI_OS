package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------- integration configuration ----------

// IntegrationConfig defines connections to external SecAI services.
type IntegrationConfig struct {
	IncidentRecorderURL string `yaml:"incident_recorder_url"` // e.g. http://127.0.0.1:8515
	RuntimeAttestorURL  string `yaml:"runtime_attestor_url"`  // e.g. http://127.0.0.1:8505
}

// ---------- incident reporting ----------

// IncidentReport is the JSON payload POSTed to the incident-recorder
// when GPU integrity degrades.
type IncidentReport struct {
	Class       string            `json:"class"`
	Source      string            `json:"source"`
	Description string            `json:"description"`
	Severity    string            `json:"severity,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

// reportIncident sends an incident to the incident-recorder service.
// Errors are logged but never fatal; GPU monitoring continues even if
// reporting fails (fail-open on telemetry, fail-closed on integrity).
func reportIncident(recorderURL, token string, entry ScoreEntry, results []ProbeResult) {
	if recorderURL == "" {
		return
	}

	// Unavailable required evidence must also reach the containment authority.
	if entry.Verdict == VerdictHealthy {
		return
	}

	incidentClass := "model_behavior_anomaly"
	severity := "high"
	description := fmt.Sprintf("GPU integrity %s: composite score %.2f", entry.Verdict, entry.CompositeScore)
	if entry.Verdict == VerdictUnknown {
		incidentClass = "integrity_violation"
		description = "Required GPU integrity evidence is unavailable"
	}

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
	statuses, _ := json.Marshal(entry.ProbeStatuses)
	evidence := map[string]string{
		"schema_version":  "1",
		"verdict":         string(entry.Verdict),
		"composite_score": fmt.Sprintf("%.6f", entry.CompositeScore),
		"probe_statuses":  string(statuses),
	}

	failedProbes := []string{}
	for _, r := range results {
		if r.Status == StatusFail || r.Status == StatusDrift {
			failedProbes = append(failedProbes, r.Probe)
		}
	}
	failed, _ := json.Marshal(failedProbes)
	evidence["failed_probes"] = string(failed)

	report := IncidentReport{
		Class:       incidentClass,
		Source:      "gpu-integrity-watch",
		Description: description,
		Severity:    severity,
		Evidence:    evidence,
	}
	// Report each concrete changed artifact separately so the recorder can
	// execute its existing single-model containment contract without guessing.
	paths := map[string]bool{}
	for _, result := range results {
		for _, path := range result.ModelPaths {
			if filepath.IsAbs(path) && filepath.Clean(path) == path {
				paths[path] = true
			}
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	if len(ordered) == 0 {
		// An unidentified/global integrity fault requires appliance containment,
		// rather than claiming a model quarantine with an empty target.
		if report.Class == "manifest_mismatch" || report.Class == "model_behavior_anomaly" {
			report.Class = "integrity_violation"
		}
		sendIncidentReport(recorderURL, token, report)
		return
	}
	for _, path := range ordered {
		report.Evidence["model_path"] = path
		sendIncidentReport(recorderURL, token, report)
	}
}

func sendIncidentReport(recorderURL, token string, report IncidentReport) {

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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("incident reported: class=%s severity=%s", report.Class, report.Severity)
		auditLog("incident_reported", map[string]interface{}{
			"class":    report.Class,
			"severity": report.Severity,
			"verdict":  report.Evidence["verdict"],
		})
	} else {
		log.Printf("warning: incident-recorder returned %d", resp.StatusCode)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// =========================================================================
// Incident-recorder integration
// =========================================================================

// incidentRecorderURL returns the configured incident-recorder URL.
func incidentRecorderURL() string {
	u := os.Getenv("INCIDENT_RECORDER_URL")
	if u == "" {
		u = "http://127.0.0.1:8515"
	}
	return u
}

// incidentReportPayload is the JSON body sent to the incident-recorder.
type incidentReportPayload struct {
	Class       string            `json:"class"`
	Source      string            `json:"source"`
	Description string           `json:"description"`
	Severity    string            `json:"severity,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

// reportViolations sends integrity violations to the incident-recorder
// service.  Errors are logged but never fatal; monitoring continues even
// if reporting fails (fail-open on telemetry, fail-closed on integrity).
func reportViolations(state IntegrityState, violations []IntegrityViolation, token string) {
	recorderURL := incidentRecorderURL()
	if recorderURL == "" {
		return
	}

	// Only report when degraded or worse.
	if state == StateTrusted {
		return
	}

	// Classify the incident based on violation types.
	incidentClass := "integrity_violation"
	severity := "high"
	if state == StateRecoveryRequired {
		severity = "critical"
	}

	// Build description from violations.
	var violationDescs []string
	for _, v := range violations {
		violationDescs = append(violationDescs, fmt.Sprintf("%s: %s (%s→%s)",
			v.Category, v.Path, truncHash(v.ExpectedHash), truncHash(v.ActualHash)))
	}
	description := fmt.Sprintf("Integrity monitor detected %d violation(s): state=%s",
		len(violations), state)

	// Check if any violations are model files → manifest_mismatch class.
	for _, v := range violations {
		if v.Category == CatModelFile {
			incidentClass = "manifest_mismatch"
			description = fmt.Sprintf("Model file integrity violation: %s", v.Path)
			break
		}
	}

	// Build evidence.
	evidence := map[string]string{
		"state":            string(state),
		"violation_count":  fmt.Sprintf("%d", len(violations)),
		"scan_count":       fmt.Sprintf("%d", scanCount.Load()),
		"violations":       strings.Join(violationDescs, "; "),
	}

	// Add first few violation paths.
	for i, v := range violations {
		if i >= 5 {
			break
		}
		evidence[fmt.Sprintf("violation_%d_path", i)] = v.Path
		evidence[fmt.Sprintf("violation_%d_category", i)] = string(v.Category)
		evidence[fmt.Sprintf("violation_%d_action", i)] = v.Action
	}

	report := incidentReportPayload{
		Class:       incidentClass,
		Source:      "integrity-monitor",
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
		log.Printf("incident reported to recorder: class=%s severity=%s violations=%d",
			incidentClass, severity, len(violations))
	} else {
		log.Printf("warning: incident-recorder returned %d", resp.StatusCode)
	}
}

// truncHash shortens a hash for display.  Special values like "missing"
// and "removed" are returned as-is.
func truncHash(h string) string {
	if h == "missing" || h == "removed" {
		return h
	}
	if len(h) > 8 {
		return h[:8] + "…"
	}
	return h
}

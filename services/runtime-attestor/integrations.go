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

// reportAttestationFailure sends a degraded/failed attestation to the
// incident-recorder service.  Errors are logged but never fatal; the
// attestor continues operating even if reporting fails.
func reportAttestationFailure(bundle RuntimeStateBundle, token string) {
	recorderURL := incidentRecorderURL()
	if recorderURL == "" {
		return
	}

	// Only report degraded or failed states.
	if bundle.State == StateAttested || bundle.State == StatePending {
		return
	}

	severity := "high"
	if bundle.State == StateFailed {
		severity = "critical"
	}

	description := fmt.Sprintf("Runtime attestation %s: %d failure(s) detected",
		bundle.State, len(bundle.Failures))
	if len(bundle.Failures) > 0 {
		description += " — " + bundle.Failures[0]
	}

	evidence := map[string]string{
		"state":              string(bundle.State),
		"failure_count":      fmt.Sprintf("%d", len(bundle.Failures)),
		"tpm_available":      fmt.Sprintf("%t", bundle.TPMAvailable),
		"tpm_quote_verified": fmt.Sprintf("%t", bundle.TPMQuoteVerified),
		"secure_boot":        fmt.Sprintf("%t", bundle.BootMeasurements.SecureBootEnabled),
		"deployment_digest":  bundle.DeploymentDigest,
		"policy_digest":      bundle.PolicyDigest,
		"bundle_hmac":        bundle.BundleHMAC,
	}

	// Include all failures in evidence.
	for i, f := range bundle.Failures {
		if i >= 10 {
			break
		}
		evidence[fmt.Sprintf("failure_%d", i)] = f
	}

	// Include service binary digest mismatches.
	for name, digest := range bundle.ServiceDigests {
		if digest == "missing" {
			evidence["missing_binary_"+name] = "true"
		}
	}

	report := incidentReportPayload{
		Class:       "attestation_failure",
		Source:      "runtime-attestor",
		Description: description,
		Severity:    severity,
		Evidence:    evidence,
	}

	body, err := json.Marshal(report)
	if err != nil {
		log.Printf("warning: failed to marshal attestation incident: %v", err)
		return
	}

	url := strings.TrimSuffix(recorderURL, "/") + "/api/v1/incidents/report"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("warning: failed to create attestation incident request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("warning: failed to report attestation incident to %s: %v", recorderURL, err)
		return
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("attestation incident reported: state=%s severity=%s failures=%d",
			bundle.State, severity, len(bundle.Failures))
	} else {
		log.Printf("warning: incident-recorder returned %d", resp.StatusCode)
	}
}

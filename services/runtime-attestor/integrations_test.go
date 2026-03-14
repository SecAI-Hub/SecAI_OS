package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =========================================================================
// Attestation failure reporting tests
// =========================================================================

func TestReportAttestationFailure_SkipsAttested(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	bundle := RuntimeStateBundle{State: StateAttested}
	reportAttestationFailure(bundle, "")
	if called {
		t.Error("should not report when attested")
	}
}

func TestReportAttestationFailure_SkipsPending(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	bundle := RuntimeStateBundle{State: StatePending}
	reportAttestationFailure(bundle, "")
	if called {
		t.Error("should not report when pending")
	}
}

func TestReportAttestationFailure_ReportsDegraded(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-ATT-001"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)
	serviceToken = ""

	bundle := RuntimeStateBundle{
		State:        StateDegraded,
		Failures:     []string{"service binary missing: registry"},
		TPMAvailable: false,
	}
	reportAttestationFailure(bundle, "")

	if received.Source != "runtime-attestor" {
		t.Errorf("expected source runtime-attestor, got %s", received.Source)
	}
	if received.Class != "attestation_failure" {
		t.Errorf("expected class attestation_failure, got %s", received.Class)
	}
	if received.Severity != "high" {
		t.Errorf("expected severity high for degraded, got %s", received.Severity)
	}
}

func TestReportAttestationFailure_CriticalForFailed(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-ATT-002"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	bundle := RuntimeStateBundle{
		State:    StateFailed,
		Failures: []string{"TPM2 not available"},
	}
	reportAttestationFailure(bundle, "")

	if received.Severity != "critical" {
		t.Errorf("expected severity critical for failed, got %s", received.Severity)
	}
}

func TestReportAttestationFailure_IncludesEvidence(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-ATT-003"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	bundle := RuntimeStateBundle{
		State:            StateDegraded,
		Failures:         []string{"service binary missing: registry"},
		TPMAvailable:     true,
		TPMQuoteVerified: false,
		PolicyDigest:     "abc123",
		DeploymentDigest: "def456",
		BundleHMAC:       "hmac789",
		ServiceDigests:   map[string]string{"registry": "missing"},
		BootMeasurements: BootMeasurements{SecureBootEnabled: true},
	}
	reportAttestationFailure(bundle, "")

	if received.Evidence["tpm_available"] != "true" {
		t.Errorf("expected tpm_available=true, got %s", received.Evidence["tpm_available"])
	}
	if received.Evidence["failure_0"] != "service binary missing: registry" {
		t.Errorf("expected failure_0, got %s", received.Evidence["failure_0"])
	}
	if received.Evidence["missing_binary_registry"] != "true" {
		t.Errorf("expected missing_binary_registry=true, got %s", received.Evidence["missing_binary_registry"])
	}
	if received.Evidence["policy_digest"] != "abc123" {
		t.Errorf("expected policy_digest=abc123, got %s", received.Evidence["policy_digest"])
	}
}

func TestReportAttestationFailure_BearerToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-ATT-004"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	bundle := RuntimeStateBundle{
		State:    StateDegraded,
		Failures: []string{"test failure"},
	}
	reportAttestationFailure(bundle, "attest-secret")

	if authHeader != "Bearer attest-secret" {
		t.Errorf("expected Bearer token, got %q", authHeader)
	}
}

func TestReportAttestationFailure_EmptyURL_NoCall(t *testing.T) {
	t.Setenv("INCIDENT_RECORDER_URL", "")
	bundle := RuntimeStateBundle{State: StateDegraded, Failures: []string{"test"}}
	// Should not panic.
	reportAttestationFailure(bundle, "")
}

func TestReportAttestationFailure_ServerDown_NoFatal(t *testing.T) {
	t.Setenv("INCIDENT_RECORDER_URL", "http://127.0.0.1:1")
	bundle := RuntimeStateBundle{State: StateFailed, Failures: []string{"test"}}
	// Should not panic.
	reportAttestationFailure(bundle, "")
}

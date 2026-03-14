package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =========================================================================
// Incident reporting tests
// =========================================================================

func TestReportViolations_SkipsTrusted(t *testing.T) {
	// Should not make any HTTP call when state is trusted.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	reportViolations(StateTrusted, nil, "")
	if called {
		t.Error("should not report when state is trusted")
	}
}

func TestReportViolations_ReportsDegraded(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-001"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)
	serviceToken = ""

	violations := []IntegrityViolation{
		{
			Category:     CatServiceBinary,
			Path:         "/usr/libexec/secure-ai/registry",
			ExpectedHash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			ActualHash:   "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Action:       "degrade_appliance",
		},
	}

	reportViolations(StateDegraded, violations, "")

	if received.Source != "integrity-monitor" {
		t.Errorf("expected source integrity-monitor, got %s", received.Source)
	}
	if received.Class != "integrity_violation" {
		t.Errorf("expected class integrity_violation, got %s", received.Class)
	}
	if received.Severity != "high" {
		t.Errorf("expected severity high for degraded, got %s", received.Severity)
	}
}

func TestReportViolations_CriticalForRecoveryRequired(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-002"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	violations := []IntegrityViolation{
		{Category: CatServiceBinary, Path: "/a", ExpectedHash: "abcdef12", ActualHash: "12345678"},
		{Category: CatPolicyFile, Path: "/b", ExpectedHash: "abcdef12", ActualHash: "12345678"},
		{Category: CatTrustMaterial, Path: "/c", ExpectedHash: "abcdef12", ActualHash: "12345678"},
	}

	reportViolations(StateRecoveryRequired, violations, "")

	if received.Severity != "critical" {
		t.Errorf("expected severity critical for recovery_required, got %s", received.Severity)
	}
}

func TestReportViolations_ModelViolation_ManifestMismatch(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-003"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	violations := []IntegrityViolation{
		{Category: CatModelFile, Path: "/var/lib/secure-ai/registry/model.gguf",
			ExpectedHash: "abcdef12", ActualHash: "12345678"},
	}

	reportViolations(StateDegraded, violations, "")

	if received.Class != "manifest_mismatch" {
		t.Errorf("model violations should use manifest_mismatch class, got %s", received.Class)
	}
}

func TestReportViolations_IncludesEvidence(t *testing.T) {
	var received incidentReportPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-004"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	violations := []IntegrityViolation{
		{Category: CatServiceBinary, Path: "/usr/bin/test",
			ExpectedHash: "abcdef1234567890", ActualHash: "1234567890abcdef", Action: "degrade_appliance"},
	}

	reportViolations(StateDegraded, violations, "")

	if received.Evidence["violation_count"] != "1" {
		t.Errorf("expected violation_count=1, got %s", received.Evidence["violation_count"])
	}
	if received.Evidence["violation_0_path"] != "/usr/bin/test" {
		t.Errorf("expected violation path, got %s", received.Evidence["violation_0_path"])
	}
	if received.Evidence["state"] != "degraded" {
		t.Errorf("expected state=degraded, got %s", received.Evidence["state"])
	}
}

func TestReportViolations_BearerToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "INC-005"})
	}))
	defer srv.Close()
	t.Setenv("INCIDENT_RECORDER_URL", srv.URL)

	violations := []IntegrityViolation{
		{Category: CatServiceBinary, Path: "/a", ExpectedHash: "abcdef12", ActualHash: "12345678"},
	}
	reportViolations(StateDegraded, violations, "test-secret-token")

	if authHeader != "Bearer test-secret-token" {
		t.Errorf("expected Bearer token, got %q", authHeader)
	}
}

func TestReportViolations_EmptyURL_NoCall(t *testing.T) {
	t.Setenv("INCIDENT_RECORDER_URL", "")
	// Should not panic or make any call.
	reportViolations(StateDegraded, []IntegrityViolation{
		{Category: CatServiceBinary, Path: "/a", ExpectedHash: "abc", ActualHash: "def"},
	}, "")
}

func TestReportViolations_ServerDown_NoFatal(t *testing.T) {
	t.Setenv("INCIDENT_RECORDER_URL", "http://127.0.0.1:1") // closed port
	// Should not panic; error is logged.
	reportViolations(StateDegraded, []IntegrityViolation{
		{Category: CatServiceBinary, Path: "/a", ExpectedHash: "abc", ActualHash: "def"},
	}, "")
}

// =========================================================================
// TruncHash tests
// =========================================================================

func TestTruncHash_Long(t *testing.T) {
	result := truncHash("abcdef1234567890")
	if result != "abcdef12…" {
		t.Errorf("expected truncated hash, got %s", result)
	}
}

func TestTruncHash_Special(t *testing.T) {
	if truncHash("missing") != "missing" {
		t.Error("missing should pass through")
	}
	if truncHash("removed") != "removed" {
		t.Error("removed should pass through")
	}
}

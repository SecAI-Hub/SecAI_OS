package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =========================================================================
// Test helpers
// =========================================================================

func resetGlobalState(t *testing.T) {
	t.Helper()
	incidentsMu.Lock()
	incidents = nil
	incidentsMu.Unlock()
	readToken = ""
	operatorToken = ""
	recoveryAdminToken = ""
	forensicToken = ""
	canaryReporterToken = ""
	gpuReporterToken = ""
	integrityReporterToken = ""
	attestorReporterToken = ""
	containmentTokens = ContainmentTokens{}
	forensicHMACKey = []byte("0123456789abcdef0123456789abcdef")
	incidentCount.Store(0)
	containedCount.Store(0)
	resolvedCount.Store(0)
	idCounter.Store(0)
	auditMu.Lock()
	if auditFile != nil {
		_ = auditFile.Close()
	}
	auditFile = nil
	auditMu.Unlock()
	incidentStorePath = ""
	containmentExecutor = func(inc Incident, _ ServiceEndpoints, _ string) ([]ContainmentResult, bool) {
		results := make([]ContainmentResult, 0, len(inc.ContainmentActions))
		for _, action := range inc.ContainmentActions {
			results = append(results, ContainmentResult{
				Action:      action,
				Success:     true,
				CompletedAt: "2026-07-27T00:00:00Z",
			})
		}
		return results, true
	}
	t.Cleanup(func() {
		containmentExecutor = executeContainment
	})

	// Load default containment policy
	containmentPolicyMu.Lock()
	containmentPolicy = defaultContainmentPolicy()
	containmentPolicyMu.Unlock()

	// Unit tests use the deterministic executor above. Contract/integration
	// tests opt back into executeContainment explicitly.
	endpoints = ServiceEndpoints{
		AgentURL:    "http://127.0.0.1:1",
		AgentSocket: "",
		AirlockURL:  "http://127.0.0.1:1",
		RegistryURL: "http://127.0.0.1:1",
	}
}

func reportIncidentHTTP(t *testing.T, report IncidentReport) (*httptest.ResponseRecorder, Incident) {
	t.Helper()
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)
	var inc Incident
	if w.Code == http.StatusCreated {
		json.Unmarshal(w.Body.Bytes(), &inc)
	}
	return w, inc
}

// =========================================================================
// Policy loading tests
// =========================================================================

func TestLoadPolicy_Defaults(t *testing.T) {
	resetGlobalState(t)
	t.Setenv("CONTAINMENT_POLICY_PATH", "/nonexistent/policy.yaml")
	if err := loadContainmentPolicy(); err != nil {
		t.Fatalf("loadContainmentPolicy: %v", err)
	}
	pol := getContainmentPolicy()
	if pol.Version != 1 {
		t.Errorf("expected version 1, got %d", pol.Version)
	}
	if len(pol.Rules) == 0 {
		t.Error("should have default rules")
	}
}

func TestLoadPolicy_FromFile(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	content := `
version: 2
rules:
  attestation_failure:
    auto_contain: true
    actions: ["freeze_agent"]
    default_severity: critical
`
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(content), 0644)
	t.Setenv("CONTAINMENT_POLICY_PATH", path)
	if err := loadContainmentPolicy(); err != nil {
		t.Fatalf("loadContainmentPolicy: %v", err)
	}
	pol := getContainmentPolicy()
	if pol.Version != 2 {
		t.Errorf("expected version 2, got %d", pol.Version)
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644)
	t.Setenv("CONTAINMENT_POLICY_PATH", path)
	err := loadContainmentPolicy()
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// =========================================================================
// Incident creation tests
// =========================================================================

func TestCreateIncident_Basic(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassPolicyBypass,
		Source:      "tool-firewall",
		Description: "Attempted tool call to system.exec",
	})
	if inc.ID == "" {
		t.Error("incident should have an ID")
	}
	if inc.CreatedAt == "" {
		t.Error("incident should have created_at")
	}
	if inc.Class != ClassPolicyBypass {
		t.Errorf("expected class policy_bypass_attempt, got %s", inc.Class)
	}
	if inc.Hash == "" {
		t.Error("incident should have hash")
	}
}

func TestCreateIncident_AutoContainment(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassAttestationFailure,
		Source:      "runtime-attestor",
		Description: "TPM2 quote verification failed",
	})
	if inc.State != StateContained {
		t.Errorf("expected contained state for auto-contain, got %s", inc.State)
	}
	if len(inc.ContainmentActions) == 0 {
		t.Error("should have containment actions")
	}
	if len(inc.ContainmentResults) != len(inc.ContainmentActions) {
		t.Fatalf("expected per-action results, got %+v", inc.ContainmentResults)
	}
}

func TestCreateIncident_DoesNotClaimFailedContainment(t *testing.T) {
	resetGlobalState(t)
	containmentExecutor = func(inc Incident, _ ServiceEndpoints, _ string) ([]ContainmentResult, bool) {
		return []ContainmentResult{{
			Action:      inc.ContainmentActions[0],
			Success:     false,
			Error:       "target unavailable",
			CompletedAt: "2026-07-27T00:00:00Z",
		}}, false
	}
	inc := createIncident(IncidentReport{
		Class:       ClassPromptInjection,
		Source:      "agent",
		Description: "containment target unavailable",
	})
	if inc.State != StateContainmentFailed {
		t.Fatalf("failed actions must not be represented as contained, got %s", inc.State)
	}
	if containedCount.Load() != 0 {
		t.Fatal("failed containment must not increment contained_count")
	}
	if len(inc.ContainmentResults) != 1 || inc.ContainmentResults[0].Error == "" {
		t.Fatalf("failure evidence was not recorded: %+v", inc.ContainmentResults)
	}
}

func TestCreateIncident_NoAutoContainment(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassForbiddenAirlock,
		Source:      "airlock",
		Description: "Request to blocked destination",
	})
	if inc.State != StateOpen {
		t.Errorf("expected open state (no auto-contain), got %s", inc.State)
	}
}

func TestCreateIncident_DefaultSeverity(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassAttestationFailure,
		Source:      "test",
		Description: "test",
	})
	if inc.Severity != SeverityCritical {
		t.Errorf("expected critical severity from policy default, got %s", inc.Severity)
	}
}

func TestCreateIncident_OverrideSeverity(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassForbiddenAirlock,
		Severity:    SeverityLow,
		Source:      "test",
		Description: "test",
	})
	if inc.Severity != SeverityLow {
		t.Errorf("expected low severity (overridden), got %s", inc.Severity)
	}
}

func TestCreateIncident_CounterIncremented(t *testing.T) {
	resetGlobalState(t)
	before := incidentCount.Load()
	createIncident(IncidentReport{
		Class:       ClassPromptInjection,
		Source:      "test",
		Description: "test",
	})
	after := incidentCount.Load()
	if after != before+1 {
		t.Errorf("incident count should increment: %d -> %d", before, after)
	}
}

func TestCreateIncident_ContainedCountIncremented(t *testing.T) {
	resetGlobalState(t)
	before := containedCount.Load()
	createIncident(IncidentReport{
		Class:       ClassAttestationFailure,
		Source:      "test",
		Description: "test",
	})
	after := containedCount.Load()
	if after != before+1 {
		t.Errorf("contained count should increment: %d -> %d", before, after)
	}
}

func TestCreateIncident_UniqueIDs(t *testing.T) {
	resetGlobalState(t)
	inc1 := createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "a", Description: "a"})
	inc2 := createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "b", Description: "b"})
	if inc1.ID == inc2.ID {
		t.Error("incidents should have unique IDs")
	}
}

func TestCreateIncident_WithEvidence(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class:       ClassManifestMismatch,
		Source:      "integrity-monitor",
		Description: "Model hash mismatch",
		Evidence: map[string]string{
			"expected_hash": "abc123",
			"actual_hash":   "def456",
			"model_path":    "/var/lib/secure-ai/registry/model.gguf",
		},
	})
	if len(inc.Evidence) != 3 {
		t.Errorf("expected 3 evidence fields, got %d", len(inc.Evidence))
	}
}

// =========================================================================
// Incident lifecycle tests
// =========================================================================

func TestResolveIncident(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class: ClassToolCallBurst, Source: "agent", Description: "burst",
	})
	completeRecoveryCeremony(t, recoveryMgr, inc.ID)
	resolved, found := resolveIncident(inc.ID)
	if !found {
		t.Fatal("incident should be found")
	}
	if resolved.State != StateResolved {
		t.Errorf("expected resolved state, got %s", resolved.State)
	}
	if resolved.ResolvedAt == "" {
		t.Error("should have resolved_at timestamp")
	}
}

func TestResolveIncident_NotFound(t *testing.T) {
	resetGlobalState(t)
	_, found := resolveIncident("nonexistent")
	if found {
		t.Error("should not find nonexistent incident")
	}
}

func TestAcknowledgeIncident(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class: ClassForbiddenAirlock, Source: "airlock", Description: "blocked",
	})
	ack, found := acknowledgeIncident(inc.ID)
	if !found {
		t.Fatal("incident should be found")
	}
	if ack.State != StateAcknowledged {
		t.Errorf("expected acknowledged state, got %s", ack.State)
	}
}

func TestGetOpenIncidents(t *testing.T) {
	resetGlobalState(t)
	createIncident(IncidentReport{Class: ClassForbiddenAirlock, Source: "a", Description: "a"})
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "b"})
	inc3 := createIncident(IncidentReport{Class: ClassToolCallBurst, Source: "c", Description: "c"})
	completeRecoveryCeremony(t, recoveryMgr, inc3.ID)
	resolveIncident(inc3.ID)

	open := getOpenIncidents()
	if len(open) != 2 {
		t.Errorf("expected 2 open incidents, got %d", len(open))
	}
}

// =========================================================================
// Validation tests
// =========================================================================

func TestIsValidClass(t *testing.T) {
	if !isValidClass(ClassAttestationFailure) {
		t.Error("attestation_failure should be valid")
	}
	if isValidClass("made_up_class") {
		t.Error("made_up_class should be invalid")
	}
}

func TestIsValidSeverity(t *testing.T) {
	if !isValidSeverity(SeverityCritical) {
		t.Error("critical should be valid")
	}
	if !isValidSeverity("") {
		t.Error("empty should be valid (uses default)")
	}
	if isValidSeverity("extreme") {
		t.Error("extreme should be invalid")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SeverityCritical) <= severityRank(SeverityHigh) {
		t.Error("critical > high")
	}
	if severityRank(SeverityHigh) <= severityRank(SeverityMedium) {
		t.Error("high > medium")
	}
	if severityRank(SeverityMedium) <= severityRank(SeverityLow) {
		t.Error("medium > low")
	}
}

// =========================================================================
// HTTP endpoint tests
// =========================================================================

func TestHTTP_Health(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("health returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("health status = %v", body["status"])
	}
}

func TestHTTP_Report_CreatesIncident(t *testing.T) {
	resetGlobalState(t)
	w, inc := reportIncidentHTTP(t, IncidentReport{
		Class:       ClassPolicyBypass,
		Source:      "tool-firewall",
		Description: "Blocked system.exec call",
	})
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if inc.ID == "" {
		t.Error("should return incident with ID")
	}
}

func TestHTTP_Report_MissingFields(t *testing.T) {
	resetGlobalState(t)
	body, _ := json.Marshal(IncidentReport{Class: ClassPolicyBypass})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestHTTP_Report_InvalidClass(t *testing.T) {
	resetGlobalState(t)
	body, _ := json.Marshal(map[string]string{
		"class": "invalid_class", "source": "test", "description": "test",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid class, got %d", w.Code)
	}
}

func TestHTTP_Report_InvalidSeverity(t *testing.T) {
	resetGlobalState(t)
	body, _ := json.Marshal(map[string]string{
		"class": "policy_bypass_attempt", "severity": "extreme",
		"source": "test", "description": "test",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid severity, got %d", w.Code)
	}
}

func TestHTTP_Report_BadJSON(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	handleReport(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestHTTP_Report_MethodNotAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/report", nil)
	w := httptest.NewRecorder()
	handleReport(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_List(t *testing.T) {
	resetGlobalState(t)
	createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "a", Description: "a"})
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "b"})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	w := httptest.NewRecorder()
	handleList(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("list returned %d", w.Code)
	}
	var incs []Incident
	json.Unmarshal(w.Body.Bytes(), &incs)
	if len(incs) != 2 {
		t.Errorf("expected 2 incidents, got %d", len(incs))
	}
	// Should be sorted by severity (critical first)
	if incs[0].Severity != SeverityCritical {
		t.Errorf("first incident should be critical, got %s", incs[0].Severity)
	}
}

func TestHTTP_List_FilterByClass(t *testing.T) {
	resetGlobalState(t)
	createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "a", Description: "a"})
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "b"})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?class=policy_bypass_attempt", nil)
	w := httptest.NewRecorder()
	handleList(w, r)

	var incs []Incident
	json.Unmarshal(w.Body.Bytes(), &incs)
	if len(incs) != 1 {
		t.Errorf("expected 1 filtered incident, got %d", len(incs))
	}
}

func TestHTTP_List_FilterByState(t *testing.T) {
	resetGlobalState(t)
	createIncident(IncidentReport{Class: ClassForbiddenAirlock, Source: "a", Description: "a"})   // open
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "b"}) // contained

	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?state=open", nil)
	w := httptest.NewRecorder()
	handleList(w, r)

	var incs []Incident
	json.Unmarshal(w.Body.Bytes(), &incs)
	if len(incs) != 1 {
		t.Errorf("expected 1 open incident, got %d", len(incs))
	}
}

func TestHTTP_Get_Found(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{Class: ClassToolCallBurst, Source: "agent", Description: "burst"})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/get?id="+inc.ID, nil)
	w := httptest.NewRecorder()
	handleGet(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("get returned %d", w.Code)
	}
}

func TestHTTP_Get_NotFound(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/get?id=nonexistent", nil)
	w := httptest.NewRecorder()
	handleGet(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_Get_MissingID(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/get", nil)
	w := httptest.NewRecorder()
	handleGet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing id, got %d", w.Code)
	}
}

func TestHTTP_Resolve(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{Class: ClassToolCallBurst, Source: "agent", Description: "burst"})
	completeRecoveryCeremony(t, recoveryMgr, inc.ID)

	body, _ := json.Marshal(map[string]string{"id": inc.ID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/resolve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleResolve(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("resolve returned %d", w.Code)
	}
	var resolved Incident
	json.Unmarshal(w.Body.Bytes(), &resolved)
	if resolved.State != StateResolved {
		t.Errorf("expected resolved, got %s", resolved.State)
	}
}

func TestHTTP_Resolve_NotFound(t *testing.T) {
	resetGlobalState(t)
	body, _ := json.Marshal(map[string]string{"id": "nonexistent"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/resolve", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleResolve(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHTTP_Acknowledge(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{Class: ClassForbiddenAirlock, Source: "airlock", Description: "blocked"})

	body, _ := json.Marshal(map[string]string{"id": inc.ID})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/acknowledge", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleAcknowledge(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("acknowledge returned %d", w.Code)
	}
}

func TestHTTP_Stats(t *testing.T) {
	resetGlobalState(t)
	createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "a", Description: "a"})
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "b"})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	handleStats(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("stats returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["total_incidents"].(float64) != 2 {
		t.Errorf("expected 2 total incidents, got %v", body["total_incidents"])
	}
}

func TestHTTP_Reload(t *testing.T) {
	resetGlobalState(t)
	t.Setenv("CONTAINMENT_POLICY_PATH", "/nonexistent/policy.yaml")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("reload returned %d", w.Code)
	}
}

func TestHTTP_Reload_MethodNotAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// =========================================================================
// Token auth tests
// =========================================================================

func TestToken_NoTokenConfigured(t *testing.T) {
	resetGlobalState(t)
	called := false
	handler := requireReadToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if called {
		t.Error("must fail closed without token")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without token, got %d", w.Code)
	}
}

func TestToken_RequiresBearer(t *testing.T) {
	resetGlobalState(t)
	readToken = "test-token"
	handler := requireReadToken(func(w http.ResponseWriter, r *http.Request) {})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestToken_ValidToken(t *testing.T) {
	resetGlobalState(t)
	readToken = "valid"
	called := false
	handler := requireReadToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("should call handler with valid token")
	}
}

func TestIncidentEndpointScopesAreIndependent(t *testing.T) {
	resetGlobalState(t)
	readToken = "read-token"
	operatorToken = "operator-token"
	recoveryAdminToken = "recovery-token"
	forensicToken = "forensic-token"
	canaryReporterToken = "canary-token"
	gpuReporterToken = "gpu-token"
	integrityReporterToken = "integrity-token"
	attestorReporterToken = "attestor-token"

	assertStatus := func(method, path, token, body string, expected int) {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		newIncidentMux().ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("%s %s with %q: expected %d, got %d: %s",
				method, path, token, expected, w.Code, w.Body.String())
		}
	}

	assertStatus(http.MethodGet, "/api/v1/stats", "read-token", "", http.StatusOK)
	assertStatus(http.MethodGet, "/api/v1/stats", "operator-token", "", http.StatusForbidden)
	assertStatus(http.MethodPost, "/api/v1/reload", "operator-token", "", http.StatusOK)
	assertStatus(http.MethodPost, "/api/v1/reload", "read-token", "", http.StatusForbidden)
	assertStatus(http.MethodGet, "/api/v1/recovery/status", "recovery-token", "", http.StatusOK)
	assertStatus(http.MethodGet, "/api/v1/recovery/status", "operator-token", "", http.StatusForbidden)
	assertStatus(http.MethodGet, "/api/v1/forensic/export", "forensic-token", "", http.StatusOK)
	assertStatus(http.MethodGet, "/api/v1/forensic/export", "recovery-token", "", http.StatusForbidden)

	reportBody := `{"class":"integrity_violation","severity":"critical","source":"canary-tripwire","description":"canary changed"}`
	assertStatus(http.MethodPost, "/api/v1/incidents/report", "canary-token", reportBody, http.StatusCreated)
	assertStatus(http.MethodPost, "/api/v1/incidents/report", "read-token", reportBody, http.StatusForbidden)
	assertStatus(http.MethodGet, "/api/v1/stats", "canary-token", "", http.StatusForbidden)
}

func TestReporterCredentialCannotForgeSourceOrClass(t *testing.T) {
	resetGlobalState(t)
	canaryReporterToken = "canary-token"
	gpuReporterToken = "gpu-token"
	integrityReporterToken = "integrity-token"
	attestorReporterToken = "attestor-token"

	assertForbidden := func(body string) {
		t.Helper()
		r := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/incidents/report",
			bytes.NewBufferString(body),
		)
		r.Header.Set("Authorization", "Bearer canary-token")
		w := httptest.NewRecorder()
		requireReporterToken(handleReport)(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected reporter forgery to be forbidden, got %d: %s", w.Code, w.Body.String())
		}
	}
	assertForbidden(`{"class":"integrity_violation","source":"runtime-attestor","description":"forged source"}`)
	assertForbidden(`{"class":"attestation_failure","source":"canary-tripwire","description":"forged class"}`)
	if incidentCount.Load() != 0 {
		t.Fatal("forged reports must not create incidents")
	}
}

func TestLoadAuthorizationTokensRequiresDistinctScopedCredentials(t *testing.T) {
	resetGlobalState(t)
	temp := t.TempDir()
	credentials := []struct {
		env   string
		name  string
		value string
	}{
		{"INCIDENT_READ_TOKEN_PATH", "read", strings.Repeat("1", 64)},
		{"INCIDENT_OPERATOR_TOKEN_PATH", "operator", strings.Repeat("2", 64)},
		{"INCIDENT_RECOVERY_ADMIN_TOKEN_PATH", "recovery", strings.Repeat("3", 64)},
		{"INCIDENT_FORENSIC_TOKEN_PATH", "forensic", strings.Repeat("4", 64)},
		{"INCIDENT_REPORTER_CANARY_TOKEN_PATH", "canary", strings.Repeat("5", 64)},
		{"INCIDENT_REPORTER_GPU_INTEGRITY_TOKEN_PATH", "gpu", strings.Repeat("6", 64)},
		{"INCIDENT_REPORTER_INTEGRITY_MONITOR_TOKEN_PATH", "integrity", strings.Repeat("7", 64)},
		{"INCIDENT_REPORTER_RUNTIME_ATTESTOR_TOKEN_PATH", "attestor", strings.Repeat("8", 64)},
	}
	for _, credential := range credentials {
		path := filepath.Join(temp, credential.name+".token")
		if err := os.WriteFile(path, []byte(credential.value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(credential.env, path)
	}
	if err := loadAuthorizationTokens(); err != nil {
		t.Fatalf("expected scoped credentials to load: %v", err)
	}
	if readToken != credentials[0].value || attestorReporterToken != credentials[7].value {
		t.Fatal("scoped credentials were not loaded into the expected authorities")
	}

	duplicatePath := os.Getenv("INCIDENT_READ_TOKEN_PATH")
	t.Setenv("INCIDENT_OPERATOR_TOKEN_PATH", duplicatePath)
	if err := loadAuthorizationTokens(); err == nil ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("expected duplicate scope credentials to fail closed, got %v", err)
	}
}

func TestReportRejectsUnknownFieldsAndTrailingObjects(t *testing.T) {
	resetGlobalState(t)
	for _, body := range []string{
		`{"class":"integrity_violation","source":"canary-tripwire","description":"x","unexpected":true}`,
		`{"class":"integrity_violation","source":"canary-tripwire","description":"x"} {}`,
	} {
		r := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/incidents/report",
			bytes.NewBufferString(body),
		)
		w := httptest.NewRecorder()
		handleReport(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected strict report decoder to reject %q, got %d", body, w.Code)
		}
	}
}

// =========================================================================
// Audit logging tests
// =========================================================================

func TestAuditLog_WritesOnIncident(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", logPath)
	initAuditLog()
	defer func() {
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
	}()

	createIncident(IncidentReport{
		Class: ClassPolicyBypass, Source: "test", Description: "test",
	})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log should have entries")
	}
}

// =========================================================================
// Persistence durability tests
// =========================================================================

func TestPersistIncidents_RoundTrip(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	incidentStorePath = filepath.Join(dir, "incidents.jsonl")

	// Create several incidents
	createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "a", Description: "first"})
	createIncident(IncidentReport{Class: ClassAttestationFailure, Source: "b", Description: "second"})
	createIncident(IncidentReport{Class: ClassForbiddenAirlock, Source: "c", Description: "third"})

	// Verify the file was written and is non-empty
	data, err := os.ReadFile(incidentStorePath)
	if err != nil {
		t.Fatalf("failed to read persisted incidents: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("incident store should not be empty")
	}

	// Clear in-memory state and reload from disk
	incidentsMu.Lock()
	incidents = nil
	incidentsMu.Unlock()
	incidentCount.Store(0)

	loadIncidentsFromDisk()

	loaded := getIncidents()
	if len(loaded) != 3 {
		t.Errorf("expected 3 incidents after reload, got %d", len(loaded))
	}
}

func TestPersistIncidents_AtomicRename(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	incidentStorePath = filepath.Join(dir, "incidents.jsonl")

	createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "test", Description: "test"})

	// The temp file should not exist after persistence (renamed to final path)
	tmpPath := incidentStorePath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temporary file should not exist after atomic rename")
	}

	// The final file should exist
	if _, err := os.Stat(incidentStorePath); os.IsNotExist(err) {
		t.Error("incident store file should exist after persistence")
	}
}

func TestAuditLog_SyncedToDisk(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", logPath)
	initAuditLog()
	defer func() {
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
	}()

	// Create an incident — triggers writeAudit which now includes Sync
	createIncident(IncidentReport{
		Class: ClassIntegrityViolation, Source: "integrity-monitor", Description: "hash mismatch",
	})

	// Open the file independently and verify content is readable
	// (if Sync worked, data should be on disk, not just in kernel buffer)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("audit log should contain the incident entry")
	}

	// Creation and containment completion are separate durable audit records.
	// Every record must be valid JSON, and the final record must reflect the
	// authoritative post-containment state.
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) == 0 {
		t.Fatal("audit log should contain at least one JSONL record")
	}
	for i, line := range lines {
		var entry Incident
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("audit entry %d should be valid JSON: %v", i, err)
		}
		if entry.Class != ClassIntegrityViolation {
			t.Fatalf("audit entry %d class should be integrity_violation, got %s", i, entry.Class)
		}
	}
}

// =========================================================================
// Containment action tests
// =========================================================================

func TestContainmentActions_AttestationFailure(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class: ClassAttestationFailure, Source: "attestor", Description: "failed",
	})
	expected := []string{"freeze_agent", "disable_airlock", "force_vault_relock"}
	if len(inc.ContainmentActions) != len(expected) {
		t.Errorf("expected %d actions, got %d: %v", len(expected), len(inc.ContainmentActions), inc.ContainmentActions)
	}
}

func TestContainmentActions_PromptInjection(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class: ClassPromptInjection, Source: "agent", Description: "injection detected",
	})
	if len(inc.ContainmentActions) == 0 {
		t.Error("prompt injection should trigger containment")
	}
}

func TestContainmentActions_ModelAnomaly(t *testing.T) {
	resetGlobalState(t)
	inc := createIncident(IncidentReport{
		Class: ClassModelAnomaly, Source: "gpu-watch", Description: "model regression",
	})
	found := false
	for _, a := range inc.ContainmentActions {
		if a == "quarantine_model" {
			found = true
		}
	}
	if !found {
		t.Error("model anomaly should include quarantine_model action")
	}
}

// =========================================================================
// Forensic export tests (M51)
// =========================================================================

func TestHTTP_ForensicExport(t *testing.T) {
	resetGlobalState(t)
	// Create an incident so the bundle is non-empty
	createIncident(IncidentReport{
		Class: ClassPolicyBypass, Source: "test", Description: "test incident for forensic export",
	})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/forensic/export", nil)
	w := httptest.NewRecorder()
	handleForensicExport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("forensic export returned %d: %s", w.Code, w.Body.String())
	}

	var bundle ForensicBundle
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("invalid JSON in forensic bundle: %v", err)
	}
	if bundle.BundleHash == "" {
		t.Error("bundle should have a hash")
	}
	if bundle.ExportedAt == "" {
		t.Error("bundle should have an exported_at timestamp")
	}
	if len(bundle.Incidents) != 1 {
		t.Errorf("expected 1 incident in bundle, got %d", len(bundle.Incidents))
	}
	if bundle.PolicyDigest == "" {
		t.Error("bundle should have a policy digest")
	}
}

func TestHTTP_ForensicExport_MethodNotAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/forensic/export", nil)
	w := httptest.NewRecorder()
	handleForensicExport(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_RecoveryStatus(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/recovery/status", nil)
	w := httptest.NewRecorder()
	handleRecoveryStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("recovery status returned %d: %s", w.Code, w.Body.String())
	}

	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := data["pending_recoveries"]; !ok {
		t.Error("response should have pending_recoveries field")
	}
	if _, ok := data["count"]; !ok {
		t.Error("response should have count field")
	}
}

// =========================================================================
// Audit log tail reader tests (M51)
// =========================================================================

func TestReadAuditLogTail(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	auditPath = path

	// Write 5 lines
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		f.WriteString("{\"line\":" + string(rune('0'+i)) + "}\n")
	}
	f.Close()

	lines := readAuditLogTail(3)
	if len(lines) != 3 {
		t.Errorf("expected 3 tail lines, got %d", len(lines))
	}

	all := readAuditLogTail(100)
	if len(all) != 5 {
		t.Errorf("expected 5 total lines, got %d", len(all))
	}
}

func TestReadAuditLogTail_NoFile(t *testing.T) {
	resetGlobalState(t)
	auditPath = "/nonexistent/audit.jsonl"
	lines := readAuditLogTail(10)
	if lines != nil {
		t.Errorf("expected nil for nonexistent file, got %v", lines)
	}
}

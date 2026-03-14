package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	serviceToken = ""
	incidentCount.Store(0)
	containedCount.Store(0)
	resolvedCount.Store(0)
	idCounter.Store(0)
	auditFile = nil

	// Load default containment policy
	containmentPolicyMu.Lock()
	containmentPolicy = defaultContainmentPolicy()
	containmentPolicyMu.Unlock()

	// Set endpoints to unreachable addresses to prevent async containment
	// goroutines from racing with subsequent test state resets.
	endpoints = ServiceEndpoints{
		AgentURL:   "http://127.0.0.1:1",
		AirlockURL: "http://127.0.0.1:1",
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
	createIncident(IncidentReport{Class: ClassForbiddenAirlock, Source: "a", Description: "a"}) // open
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
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("should pass through without token")
	}
}

func TestToken_RequiresBearer(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "test-token"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestToken_ValidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "valid"
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
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

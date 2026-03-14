package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// =========================================================================
// End-to-end enforcement chain integration tests
//
// These tests verify the full path:
//   1. External service reports a security event via HTTP
//   2. Incident recorder creates an incident with correct classification
//   3. Containment policy is evaluated and actions assigned
//   4. Containment actions are dispatched to target services
// =========================================================================

// TestChain_IntegrityViolation_FreezeAndDisable verifies the complete
// enforcement chain for an integrity violation:
//   integrity-monitor → incident-recorder → freeze_agent + disable_airlock + force_vault_relock
func TestChain_IntegrityViolation_FreezeAndDisable(t *testing.T) {
	resetGlobalState(t)

	// Set up mock target services to receive containment actions.
	var mu sync.Mutex
	var containmentCalls []struct {
		Path   string
		Action string
	}

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		containmentCalls = append(containmentCalls, struct {
			Path   string
			Action string
		}{Path: r.URL.Path, Action: payload["action"]})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	// Point containment endpoints to our mock.
	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	// Simulate integrity-monitor reporting a violation via HTTP.
	report := IncidentReport{
		Class:       ClassIntegrityViolation,
		Severity:    SeverityCritical,
		Source:      "integrity-monitor",
		Description: "Binary hash mismatch detected: /usr/lib/secure-ai/bin/registry",
		Evidence: map[string]string{
			"path":          "/usr/lib/secure-ai/bin/registry",
			"expected_hash": "abc123def456",
			"actual_hash":   "789xyz000000",
			"category":      "binary",
			"state":         "recovery_required",
		},
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)

	// Verify incident was created with correct state.
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)

	if inc.Class != ClassIntegrityViolation {
		t.Errorf("expected class integrity_violation, got %s", inc.Class)
	}
	if inc.State != StateContained {
		t.Errorf("expected contained state (auto-containment), got %s", inc.State)
	}
	if inc.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", inc.Severity)
	}

	// Verify containment actions were assigned.
	expectedActions := []string{"freeze_agent", "disable_airlock", "force_vault_relock"}
	if len(inc.ContainmentActions) != len(expectedActions) {
		t.Fatalf("expected %d containment actions, got %d: %v",
			len(expectedActions), len(inc.ContainmentActions), inc.ContainmentActions)
	}
	for i, expected := range expectedActions {
		if inc.ContainmentActions[i] != expected {
			t.Errorf("action[%d]: expected %s, got %s", i, expected, inc.ContainmentActions[i])
		}
	}

	// Give the async containment goroutine time to dispatch.
	time.Sleep(200 * time.Millisecond)

	// Verify containment calls reached the target services.
	mu.Lock()
	defer mu.Unlock()

	if len(containmentCalls) != 3 {
		t.Fatalf("expected 3 containment calls, got %d: %+v", len(containmentCalls), containmentCalls)
	}

	// Check each call.
	callMap := make(map[string]string)
	for _, c := range containmentCalls {
		callMap[c.Path] = c.Action
	}
	if callMap["/api/v1/freeze"] != "freeze" {
		t.Errorf("expected freeze action at /api/v1/freeze, got %s", callMap["/api/v1/freeze"])
	}
	if callMap["/api/v1/disable"] != "disable" {
		t.Errorf("expected disable action at /api/v1/disable, got %s", callMap["/api/v1/disable"])
	}
	if callMap["/api/v1/vault/relock"] != "relock" {
		t.Errorf("expected relock action at /api/v1/vault/relock, got %s", callMap["/api/v1/vault/relock"])
	}
}

// TestChain_AttestationFailure_ContainmentDispatched verifies the enforcement
// chain for an attestation failure reported by the runtime attestor:
//   runtime-attestor → incident-recorder → freeze_agent + disable_airlock + force_vault_relock
func TestChain_AttestationFailure_ContainmentDispatched(t *testing.T) {
	resetGlobalState(t)

	var mu sync.Mutex
	receivedPaths := []string{}

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedPaths = append(receivedPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	// Simulate runtime-attestor reporting an attestation failure.
	report := IncidentReport{
		Class:       ClassAttestationFailure,
		Severity:    SeverityCritical,
		Source:      "runtime-attestor",
		Description: "TPM2 quote verification failed: PCR mismatch",
		Evidence: map[string]string{
			"tpm_available":    "true",
			"quote_verified":   "false",
			"state":            "failed",
			"failure_0":        "PCR 7 mismatch",
			"secure_boot":      "true",
			"policy_digest":    "abc123",
			"deployment_digest": "def456",
		},
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)

	if inc.State != StateContained {
		t.Errorf("expected contained, got %s", inc.State)
	}
	if inc.Evidence["tpm_available"] != "true" {
		t.Errorf("evidence should be preserved: tpm_available=%s", inc.Evidence["tpm_available"])
	}

	// Wait for async containment.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedPaths) < 2 {
		t.Errorf("expected at least 2 containment calls, got %d", len(receivedPaths))
	}
}

// TestChain_ManifestMismatch_QuarantinesModel verifies that a manifest
// mismatch triggers model quarantine containment:
//   integrity-monitor (model) → incident-recorder → quarantine_model + freeze_agent
func TestChain_ManifestMismatch_QuarantinesModel(t *testing.T) {
	resetGlobalState(t)

	var mu sync.Mutex
	receivedActions := make(map[string]string)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		receivedActions[r.URL.Path] = payload["action"]
		if payload["model_path"] != "" {
			receivedActions["quarantine_model_path"] = payload["model_path"]
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	report := IncidentReport{
		Class:       ClassManifestMismatch,
		Severity:    SeverityHigh,
		Source:      "integrity-monitor",
		Description: "Model file hash does not match signed baseline",
		Evidence: map[string]string{
			"model_path":    "/var/lib/secure-ai/registry/promoted/llama-3.2-3b.gguf",
			"expected_hash": "sha256:aabbccdd",
			"actual_hash":   "sha256:11223344",
		},
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)

	// Manifest mismatch should trigger quarantine_model + freeze_agent.
	hasQuarantine := false
	hasFreeze := false
	for _, a := range inc.ContainmentActions {
		if a == "quarantine_model" {
			hasQuarantine = true
		}
		if a == "freeze_agent" {
			hasFreeze = true
		}
	}
	if !hasQuarantine {
		t.Error("manifest_mismatch should trigger quarantine_model")
	}
	if !hasFreeze {
		t.Error("manifest_mismatch should trigger freeze_agent")
	}

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if receivedActions["/api/v1/quarantine"] != "quarantine" {
		t.Errorf("expected quarantine action, got %s", receivedActions["/api/v1/quarantine"])
	}
	if receivedActions["quarantine_model_path"] != "/var/lib/secure-ai/registry/promoted/llama-3.2-3b.gguf" {
		t.Errorf("expected model path in quarantine payload, got %s", receivedActions["quarantine_model_path"])
	}
}

// TestChain_BearerToken_PropagatedToContainment verifies that the service
// token is correctly propagated through the entire chain.
func TestChain_BearerToken_PropagatedToContainment(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "chain-test-secret"

	var mu sync.Mutex
	receivedAuth := []string{}

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = append(receivedAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	// Report via authenticated HTTP handler.
	report := IncidentReport{
		Class:       ClassPromptInjection,
		Source:      "agent",
		Description: "Prompt injection detected in user input",
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer chain-test-secret")
	w := httptest.NewRecorder()
	requireServiceToken(handleReport)(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// All containment calls should carry the bearer token.
	for i, auth := range receivedAuth {
		if auth != "Bearer chain-test-secret" {
			t.Errorf("containment call %d: expected Bearer token, got %q", i, auth)
		}
	}
	if len(receivedAuth) == 0 {
		t.Error("expected at least one containment call with auth")
	}
}

// TestChain_NoAutoContain_NoDispatched verifies that incident classes
// without auto-containment do NOT dispatch containment actions.
func TestChain_NoAutoContain_NoDispatched(t *testing.T) {
	resetGlobalState(t)

	called := false
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	// forbidden_airlock_request has auto_contain: false in default policy.
	report := IncidentReport{
		Class:       ClassForbiddenAirlock,
		Source:      "airlock",
		Description: "Request to blocked destination: example.com",
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)

	if inc.State != StateOpen {
		t.Errorf("expected open state (no auto-contain), got %s", inc.State)
	}
	if len(inc.ContainmentActions) != 0 {
		t.Errorf("expected 0 containment actions, got %d", len(inc.ContainmentActions))
	}

	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("containment should not be dispatched for no-auto-contain incidents")
	}
}

// TestChain_IncidentLifecycle_FullCycle verifies the complete incident
// lifecycle: report → auto-contain → resolve → acknowledge.
func TestChain_IncidentLifecycle_FullCycle(t *testing.T) {
	resetGlobalState(t)

	// Use unreachable endpoints to avoid async containment calls.
	endpoints = ServiceEndpoints{
		AgentURL:    "http://127.0.0.1:1",
		AirlockURL:  "http://127.0.0.1:1",
		RegistryURL: "http://127.0.0.1:1",
	}

	// Step 1: Report an incident.
	report := IncidentReport{
		Class:       ClassToolCallBurst,
		Severity:    SeverityMedium,
		Source:      "agent",
		Description: "50 tool calls in 10 seconds",
	}
	w, inc := reportIncidentHTTP(t, report)
	if w.Code != http.StatusCreated {
		t.Fatalf("report: expected 201, got %d", w.Code)
	}
	if inc.State != StateContained {
		t.Errorf("expected contained (tool_call_burst has auto_contain), got %s", inc.State)
	}

	// Step 2: Verify incident appears in list.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	listW := httptest.NewRecorder()
	handleList(listW, listReq)
	var listed []Incident
	json.Unmarshal(listW.Body.Bytes(), &listed)
	if len(listed) != 1 {
		t.Fatalf("expected 1 incident in list, got %d", len(listed))
	}

	// Step 3: Resolve the incident.
	resolveBody, _ := json.Marshal(map[string]string{"id": inc.ID})
	resolveReq := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/resolve", bytes.NewReader(resolveBody))
	resolveW := httptest.NewRecorder()
	handleResolve(resolveW, resolveReq)
	if resolveW.Code != http.StatusOK {
		t.Fatalf("resolve: expected 200, got %d", resolveW.Code)
	}
	var resolved Incident
	json.Unmarshal(resolveW.Body.Bytes(), &resolved)
	if resolved.State != StateResolved {
		t.Errorf("expected resolved, got %s", resolved.State)
	}

	// Step 4: Acknowledge.
	ackBody, _ := json.Marshal(map[string]string{"id": inc.ID})
	ackReq := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/acknowledge", bytes.NewReader(ackBody))
	ackW := httptest.NewRecorder()
	handleAcknowledge(ackW, ackReq)
	if ackW.Code != http.StatusOK {
		t.Fatalf("acknowledge: expected 200, got %d", ackW.Code)
	}
	var acked Incident
	json.Unmarshal(ackW.Body.Bytes(), &acked)
	if acked.State != StateAcknowledged {
		t.Errorf("expected acknowledged, got %s", acked.State)
	}

	// Step 5: Stats should reflect the lifecycle.
	statsReq := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	statsW := httptest.NewRecorder()
	handleStats(statsW, statsReq)
	var stats map[string]interface{}
	json.Unmarshal(statsW.Body.Bytes(), &stats)
	if stats["total_incidents"].(float64) != 1 {
		t.Errorf("expected 1 total incident, got %v", stats["total_incidents"])
	}
}

// TestChain_GPUAnomaly_IncidentAndQuarantine verifies the chain for
// GPU integrity watch anomalies that report model behavior anomalies.
func TestChain_GPUAnomaly_IncidentAndQuarantine(t *testing.T) {
	resetGlobalState(t)

	var mu sync.Mutex
	quarantineCalled := false

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "quarantine") {
			mu.Lock()
			quarantineCalled = true
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	endpoints = ServiceEndpoints{
		AgentURL:    targetSrv.URL,
		AirlockURL:  targetSrv.URL,
		RegistryURL: targetSrv.URL,
	}

	report := IncidentReport{
		Class:       ClassModelAnomaly,
		Source:      "gpu-integrity-watch",
		Description: "Model behavior regression detected: output entropy spike",
		Evidence: map[string]string{
			"model_path":      "/var/lib/secure-ai/registry/promoted/model.gguf",
			"entropy_score":   "0.98",
			"baseline_score":  "0.42",
			"gpu_device":      "0000:01:00.0",
		},
	}
	body, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleReport(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)

	// model_behavior_anomaly should trigger quarantine_model.
	hasQuarantine := false
	for _, a := range inc.ContainmentActions {
		if a == "quarantine_model" {
			hasQuarantine = true
		}
	}
	if !hasQuarantine {
		t.Error("model anomaly should trigger quarantine_model containment")
	}

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if !quarantineCalled {
		t.Error("quarantine endpoint should have been called")
	}
}

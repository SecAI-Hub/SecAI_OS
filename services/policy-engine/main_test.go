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

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempAgentPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const testPolicyYAML = `
defaults:
  network:
    runtime_egress: deny
tools:
  default: deny
  allow:
    - name: filesystem.read
      paths_allowlist:
        - /var/lib/secure-ai/vault/**
    - name: filesystem.write
      paths_allowlist:
        - /var/lib/secure-ai/vault/outputs/**
      paths_denylist:
        - /var/lib/secure-ai/vault/outputs/secrets/**
    - name: web.search
  deny:
    - name: system.exec
  rate_limit:
    requests_per_minute: 120
    burst_size: 20
airlock:
  enabled: false
  destination_allowlist:
    - huggingface.co
    - cdn.example.com
models:
  allowed_formats:
    - gguf
    - safetensors
  deny_formats:
    - pickle
    - pt
`

const testAgentPolicyYAML = `
agent:
  default_mode: standard
  always_deny:
    - change_security
  hard_approval:
    - outbound_request
    - export_data
    - trust_change
  allowed_tools:
    - filesystem.read
    - filesystem.list
    - filesystem.write
  workspace:
    readable:
      - /var/lib/secure-ai/vault/user_docs/**
    writable:
      - /var/lib/secure-ai/vault/outputs/**
  budgets:
    standard:
      max_steps: 30
      max_tool_calls: 80
      max_tokens: 32000
      max_wall_clock_seconds: 600
`

func setupTestPolicies(t *testing.T) {
	t.Helper()
	pPath := writeTempPolicy(t, testPolicyYAML)
	aPath := writeTempAgentPolicy(t, testAgentPolicyYAML)
	t.Setenv("POLICY_PATH", pPath)
	t.Setenv("AGENT_POLICY_PATH", aPath)
	if err := loadPolicies(); err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}
}

func decideRequest(t *testing.T, req DecisionRequest) DecisionResponse {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleDecide(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp DecisionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

// =========================================================================
// Tool access tests
// =========================================================================

func TestToolAccess_AllowedTool(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "filesystem.read",
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestToolAccess_DeniedTool(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "system.exec",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestToolAccess_UnknownToolDefaultDeny(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "unknown.tool",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestToolAccess_PathAllowed(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "filesystem.read",
		Params:  map[string]string{"path": "/var/lib/secure-ai/vault/model.gguf"},
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestToolAccess_PathDenied(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "filesystem.write",
		Params:  map[string]string{"path": "/var/lib/secure-ai/vault/outputs/secrets/key.pem"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestToolAccess_PathOutsideScope(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "filesystem.read",
		Params:  map[string]string{"path": "/etc/shadow"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

// =========================================================================
// Path access tests (agent workspace)
// =========================================================================

func TestPathAccess_ReadAllowed(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainPathAccess,
		Subject: "/var/lib/secure-ai/vault/user_docs/report.txt",
		Action:  "read",
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestPathAccess_ReadOutsideScope(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainPathAccess,
		Subject: "/etc/passwd",
		Action:  "read",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestPathAccess_WriteAllowed(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainPathAccess,
		Subject: "/var/lib/secure-ai/vault/outputs/result.txt",
		Action:  "write",
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestPathAccess_WriteOutsideScope(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainPathAccess,
		Subject: "/var/lib/secure-ai/vault/user_docs/hack.txt",
		Action:  "write",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

// =========================================================================
// Egress tests
// =========================================================================

func TestEgress_DenyByDefault(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainEgress,
		Subject: "https://evil.com/exfiltrate",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestEgress_AirlockDisabled(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainEgress,
		Subject: "https://huggingface.co/api",
	})
	// Airlock is disabled in our test policy, so even allowlisted destinations are denied
	if resp.Decision != "deny" {
		t.Errorf("expected deny (airlock disabled), got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestDestinationAllowedRejectsLookalikeHost(t *testing.T) {
	if destinationAllowed("https://evil-huggingface.co.example/download", "huggingface.co") {
		t.Fatal("expected lookalike hostname to be rejected")
	}
	if destinationAllowed("https://huggingface.co.example/download", "https://huggingface.co/") {
		t.Fatal("expected lookalike URL prefix to be rejected")
	}
}

// =========================================================================
// Agent risk tests
// =========================================================================

func TestAgentRisk_AlwaysDeny(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "change_security",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestAgentRisk_HardApproval(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "outbound_request",
	})
	if resp.Decision != "ask" {
		t.Errorf("expected ask, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestAgentRisk_ExportDataNeedsApproval(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "export_data",
	})
	if resp.Decision != "ask" {
		t.Errorf("expected ask, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestAgentRisk_AllowedTool(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "filesystem.read",
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestAgentRisk_UnknownAction(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "launch_missiles",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

// =========================================================================
// Sensitivity tests
// =========================================================================

func TestSensitivity_WithinCeiling(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainSensitivity,
		Subject: "low",
		Params:  map[string]string{"ceiling": "medium"},
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSensitivity_ExceedsCeiling(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainSensitivity,
		Subject: "high",
		Params:  map[string]string{"ceiling": "medium"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSensitivity_EqualCeiling(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainSensitivity,
		Subject: "medium",
		Params:  map[string]string{"ceiling": "medium"},
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSensitivity_InvalidLevel(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainSensitivity,
		Subject: "extreme",
		Params:  map[string]string{"ceiling": "medium"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny for invalid level, got %s", resp.Decision)
	}
}

// =========================================================================
// Model promotion tests
// =========================================================================

func TestModelPromotion_AllowedFormat(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainModelPromotion,
		Subject: "my-model",
		Params:  map[string]string{"format": "gguf"},
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestModelPromotion_DeniedFormat(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainModelPromotion,
		Subject: "my-model",
		Params:  map[string]string{"format": "pickle"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestModelPromotion_UnknownFormatDenied(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainModelPromotion,
		Subject: "my-model",
		Params:  map[string]string{"format": "unknown_fmt"},
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny for unknown format, got %s: %s", resp.Decision, resp.Reason)
	}
}

// =========================================================================
// Decision evidence tests
// =========================================================================

func TestEvidence_HasAllFields(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "filesystem.read",
	})
	ev := resp.Evidence
	if ev.Timestamp == "" {
		t.Error("evidence missing timestamp")
	}
	if ev.Domain != "tool_access" {
		t.Errorf("evidence domain = %q, want tool_access", ev.Domain)
	}
	if ev.PolicyDigest == "" {
		t.Error("evidence missing policy_digest")
	}
	if ev.RuleID == "" {
		t.Error("evidence missing rule_id")
	}
	if ev.InputHash == "" {
		t.Error("evidence missing input_hash")
	}
}

func TestEvidence_PolicyDigestConsistent(t *testing.T) {
	setupTestPolicies(t)
	r1 := decideRequest(t, DecisionRequest{Domain: DomainToolAccess, Subject: "filesystem.read"})
	r2 := decideRequest(t, DecisionRequest{Domain: DomainAgentRisk, Subject: "filesystem.read"})
	if r1.Evidence.PolicyDigest != r2.Evidence.PolicyDigest {
		t.Error("policy digest should be the same across domains")
	}
}

// =========================================================================
// Unknown domain test
// =========================================================================

func TestUnknownDomain_Denied(t *testing.T) {
	setupTestPolicies(t)
	resp := decideRequest(t, DecisionRequest{
		Domain:  "made_up_domain",
		Subject: "anything",
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny for unknown domain, got %s", resp.Decision)
	}
}

// =========================================================================
// HTTP endpoint tests
// =========================================================================

func TestHTTP_HealthEndpoint(t *testing.T) {
	setupTestPolicies(t)
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
	if body["policy_digest"] == nil || body["policy_digest"] == "" {
		t.Error("health missing policy_digest")
	}
}

func TestHTTP_StatsEndpoint(t *testing.T) {
	setupTestPolicies(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	handleStats(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("stats returned %d", w.Code)
	}
}

func TestHTTP_DigestEndpoint(t *testing.T) {
	setupTestPolicies(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/digest", nil)
	w := httptest.NewRecorder()
	handleDigest(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("digest returned %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["policy_digest"] == "" {
		t.Error("digest endpoint returned empty digest")
	}
}

func TestHTTP_DecideMethodNotAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/decide", nil)
	w := httptest.NewRecorder()
	handleDecide(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_DecideBadBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	handleDecide(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_DecideMissingFields(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"domain": "tool_access"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleDecide(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHTTP_ReloadRequiresToken(t *testing.T) {
	old := serviceToken
	serviceToken = "test-secret-token"
	defer func() { serviceToken = old }()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	w := httptest.NewRecorder()
	requireServiceToken(handleReload)(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without token, got %d", w.Code)
	}
}

func TestHTTP_ReloadWithValidToken(t *testing.T) {
	setupTestPolicies(t)
	old := serviceToken
	serviceToken = "test-secret-token"
	defer func() { serviceToken = old }()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	r.Header.Set("Authorization", "Bearer test-secret-token")
	w := httptest.NewRecorder()
	requireServiceToken(handleReload)(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHTTP_ReloadMethodNotAllowed(t *testing.T) {
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

func TestCheckToken_Empty(t *testing.T) {
	old := serviceToken
	serviceToken = ""
	defer func() { serviceToken = old }()

	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("handler should be called when no token configured")
	}
}

func TestCheckToken_Invalid(t *testing.T) {
	old := serviceToken
	serviceToken = "correct"
	defer func() { serviceToken = old }()

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong token, got %d", w.Code)
	}
}

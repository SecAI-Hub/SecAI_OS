package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticatedServiceHandlerProtectsEverythingButHealth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := authenticatedCredentialHandler(next, testCredentialSet(t, strings.Repeat("t", 32), strings.Repeat("a", 32)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/policy", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected authenticated request to pass, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("health should remain credentialless, got %d", w.Code)
	}
}

func testCredentialSet(t *testing.T, service, admin string) *credentialSet {
	t.Helper()
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "service", tokenDigest: sha256.Sum256([]byte(service)), roles: roleMap(roleEvaluator, roleObserver)},
		{identity: "admin", tokenDigest: sha256.Sum256([]byte(admin)), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func TestLoadPolicyRejectsUnknownAndDefaultAllow(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown.yaml":  "version: 1\ndefault_action: deny\nunknown: true\naudit:\n  enabled: true\n  log_path: /tmp/audit\n",
		"allow.yaml":    "version: 1\ndefault_action: allow\naudit:\n  enabled: true\n  log_path: /tmp/audit\n",
		"unsigned.yaml": "version: 1\ndefault_action: deny\naudit:\n  enabled: true\n  log_path: /tmp/audit\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil {
			t.Fatalf("expected %s to be rejected", name)
		}
	}
}

func TestLoadPolicyRejectsGroupWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `version: 1
default_action: deny
audit:
  enabled: true
  log_path: /tmp/audit.jsonl
  sign_reports: true
  key_path: /tmp/signing.key
  receipt_audience: test:mcp-firewall
  receipt_ttl_seconds: 120
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("group-writable policy was accepted")
	}
}

func TestLoadServiceTokenRejectsSymlinkAndWeakToken(t *testing.T) {
	dir := trustedCredentialTestDir(t)
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", weak)
	if _, err := loadServiceToken(); err == nil {
		t.Fatal("expected weak token to be rejected")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(weak, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", link)
	if _, err := loadServiceToken(); err == nil {
		t.Fatal("expected token symlink to be rejected")
	}
}

func TestLoadServiceTokenRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(trustedCredentialTestDir(t), "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", path)
	if _, err := loadServiceToken(); err == nil {
		t.Fatal("expected group/other-readable token to be rejected")
	}
}

func TestPolicyEngineEnforcesServerRateLimit(t *testing.T) {
	policy := &FirewallPolicy{
		Version: 1, DefaultAction: "deny",
		Servers: []ServerPolicy{{
			Name: "server", TrustLevel: "trusted", RateLimit: 1,
			AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow"}},
		}},
	}
	engine := NewPolicyEngine(policy)
	state := NewTaintState()
	req := EvalRequest{Server: "server", Method: "tools/call", Tool: "tool", SessionID: "session"}
	if got := engine.Evaluate(req, state); got.Action != "allow" {
		t.Fatalf("first request unexpectedly denied: %#v", got)
	}
	if got := engine.Evaluate(req, state); got.Action != "deny" || got.Rule != "builtin:server-rate-limit" {
		t.Fatalf("rate limit not enforced: %#v", got)
	}
}

func TestGlobalRuleServerTrustPredicateIsEnforced(t *testing.T) {
	policy := &FirewallPolicy{
		Version: 1, DefaultAction: "deny",
		Servers: []ServerPolicy{
			{Name: "trusted", TrustLevel: "trusted", AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow"}}},
			{Name: "untrusted", TrustLevel: "untrusted", AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow"}}},
		},
		GlobalRules: []GlobalRule{{
			Name: "deny-untrusted", Match: Match{ServerTrust: []string{"untrusted"}},
			Action: "deny", Reason: "untrusted server",
		}},
	}
	engine := NewPolicyEngine(policy)
	state := NewTaintState()
	trusted := engine.Evaluate(EvalRequest{Server: "trusted", Method: "tools/call", Tool: "tool", SessionID: "s1"}, state)
	untrusted := engine.Evaluate(EvalRequest{Server: "untrusted", Method: "tools/call", Tool: "tool", SessionID: "s2"}, state)
	if trusted.Action != "allow" || untrusted.Rule != "deny-untrusted" {
		t.Fatalf("trust predicate mismatch: trusted=%#v untrusted=%#v", trusted, untrusted)
	}
}

func TestPolicyEngineEnforcesConfiguredServerFingerprint(t *testing.T) {
	policy := &FirewallPolicy{
		Version: 1, DefaultAction: "deny",
		Servers: []ServerPolicy{{
			Name: "server", Fingerprint: "sha256:expected", TrustLevel: "trusted",
			AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow"}},
		}},
	}
	engine := NewPolicyEngine(policy)
	state := NewTaintState()
	request := EvalRequest{
		Server: "server", ServerFingerprint: "sha256:wrong", Method: "tools/call", Tool: "tool", SessionID: "session",
	}
	if decision := engine.Evaluate(request, state); decision.Action != "deny" || decision.Rule != "builtin:server-fingerprint" {
		t.Fatalf("fingerprint mismatch was not denied: %#v", decision)
	}
	request.ServerFingerprint = "sha256:expected"
	if decision := engine.Evaluate(request, state); decision.Action != "allow" {
		t.Fatalf("matching fingerprint was not allowed: %#v", decision)
	}
}

func TestPolicyEngineRejectsUndeclaredArguments(t *testing.T) {
	policy := &FirewallPolicy{
		Version: 1, DefaultAction: "deny",
		Servers: []ServerPolicy{{
			Name: "server", TrustLevel: "trusted",
			AllowedTools: []ToolPolicy{{
				Name: "tool", Action: "allow", ArgRules: []ArgRule{{Name: "path"}},
			}},
		}},
	}
	decision := NewPolicyEngine(policy).Evaluate(EvalRequest{
		Server: "server", Method: "tools/call", Tool: "tool", SessionID: "session",
		Arguments: map[string]string{"path": "/approved", "command": "unexpected"},
	}, NewTaintState())
	if decision.Action != "deny" || !strings.Contains(decision.Reason, "argument validation") {
		t.Fatalf("undeclared argument was not denied: %#v", decision)
	}
}

func TestArgumentRuleForcesRedaction(t *testing.T) {
	policy := &FirewallPolicy{
		Version: 1, DefaultAction: "deny",
		Servers: []ServerPolicy{{
			Name: "server", TrustLevel: "trusted",
			AllowedTools: []ToolPolicy{{
				Name: "tool", Action: "allow", ArgRules: []ArgRule{{Name: "value", Redact: true}},
			}},
		}},
	}
	decision := NewPolicyEngine(policy).Evaluate(EvalRequest{
		Server: "server", Method: "tools/call", Tool: "tool", SessionID: "session",
		Arguments: map[string]string{"value": "sensitive"},
	}, NewTaintState())
	if decision.RedactedArgs["value"] != "[REDACTED:policy]" {
		t.Fatalf("policy redaction was not applied: %#v", decision.RedactedArgs)
	}
}

func TestSanitizeRequestForAuditRemovesPayloads(t *testing.T) {
	req := EvalRequest{
		Server: "server", Method: "tools/call", Tool: "tool", SessionID: "customer-session",
		Resource:  "file:///sensitive/customer/path",
		Arguments: map[string]string{"content": "customer secret"},
	}
	clean := sanitizeRequestForAudit(req)
	if clean.SessionID == req.SessionID || clean.Resource == req.Resource ||
		strings.Contains(clean.Arguments["content"], "customer secret") {
		t.Fatalf("audit request retained sensitive data: %#v", clean)
	}
}

func TestTaintStateBoundsSessions(t *testing.T) {
	state := NewTaintState()
	state.maxSessions = 2
	state.Add("one", "label", "source")
	state.Add("two", "label", "source")
	state.Add("three", "label", "source")
	if len(state.sessions) != 2 {
		t.Fatalf("expected bounded state, got %d sessions", len(state.sessions))
	}
}

func TestValidateBindAddressRequiresExplicitRemoteOptIn(t *testing.T) {
	t.Setenv("ALLOW_REMOTE_BIND", "")
	if err := validateBindAddress("0.0.0.0:8510"); err == nil {
		t.Fatal("expected wildcard bind to be rejected")
	}
	if err := validateBindAddress("127.0.0.1:8510"); err != nil {
		t.Fatalf("loopback bind rejected: %v", err)
	}
}

func TestAuditLoaderRejectsUnknownFieldsAndIncompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLog(path, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := al.Record("test", nil, nil, "detail")
	if err != nil {
		t.Fatal(err)
	}
	if err := al.Close(); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
	withUnknown = append(withUnknown, '\n')
	if err := os.WriteFile(path, withUnknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadAuditEntries(path, 10); err == nil {
		t.Fatal("audit entry with unknown fields was accepted")
	}

	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadAuditEntries(path, 10); err == nil {
		t.Fatal("audit log with incomplete final line was accepted")
	}
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalResourceContainmentAndDenyPrecedence(t *testing.T) {
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", Servers: []ServerPolicy{{
		Name: "files", TrustLevel: "trusted", AllowedResources: []ResourcePolicy{
			{Pattern: "file:///home/user/**", Action: "allow"},
			{Pattern: "file:///home/user/private/**", Action: "deny"},
		},
	}}}
	engine := NewPolicyEngine(policy)
	state := NewTaintState()
	for name, resource := range map[string]string{
		"double_encoded_traversal": "file:///home/user/%252e%252e/etc/passwd",
		"encoded_separator_escape": "file:///home/user%2f..%2fetc/passwd",
		"deny_overrides_allow":     "file:///home/user/private/secrets.txt",
		"prefix_lookalike":         "file:///home/user-evil/report.txt",
	} {
		t.Run(name, func(t *testing.T) {
			decision := engine.Evaluate(EvalRequest{Server: "files", Method: "resources/read", Resource: resource, SessionID: "session"}, state)
			if decision.Action != "deny" {
				t.Fatalf("unsafe resource was not denied: %#v", decision)
			}
		})
	}
	allowed := engine.Evaluate(EvalRequest{Server: "files", Method: "resources/read", Resource: "file:///home/user/reports/one.txt", SessionID: "session"}, state)
	if allowed.Action != "allow" {
		t.Fatalf("contained resource unexpectedly denied: %#v", allowed)
	}
}

func TestGlobalApprovalCannotElevateDefaultDeny(t *testing.T) {
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", GlobalRules: []GlobalRule{{
		Name: "approval", Match: Match{Methods: []string{"tools/call"}}, Action: "require-approval", Reason: "review",
	}}}
	decision := NewPolicyEngine(policy).Evaluate(EvalRequest{Server: "unknown", Method: "tools/call", Tool: "unknown", SessionID: "session"}, NewTaintState())
	if decision.Action != "deny" || decision.Rule != "default:server-not-found" {
		t.Fatalf("global approval elevated default deny: %#v", decision)
	}
}

func TestGlobalDenyOverridesEarlierApproval(t *testing.T) {
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", Servers: []ServerPolicy{{
		Name: "server", TrustLevel: "trusted", AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow"}},
	}}, GlobalRules: []GlobalRule{
		{Name: "approval-first", Match: Match{Methods: []string{"tools/call"}}, Action: "require-approval", Reason: "review"},
		{Name: "deny-second", Match: Match{Methods: []string{"tools/call"}}, Action: "deny", Reason: "blocked"},
	}}
	decision := NewPolicyEngine(policy).Evaluate(EvalRequest{Server: "server", Method: "tools/call", Tool: "tool", SessionID: "session"}, NewTaintState())
	if decision.Action != "deny" || decision.Rule != "deny-second" {
		t.Fatalf("earlier approval shadowed global deny: %#v", decision)
	}
}

func TestMethodSpecificFieldsCannotBeConfused(t *testing.T) {
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", Servers: []ServerPolicy{{
		Name: "server", TrustLevel: "trusted", AllowedTools: []ToolPolicy{{Name: "tool", Action: "allow", ArgRules: []ArgRule{{Name: "value"}}}},
		AllowedResources: []ResourcePolicy{{Pattern: "mcp://server/data/**", Action: "allow"}},
	}}}
	engine := NewPolicyEngine(policy)
	requests := []EvalRequest{
		{Server: "server", Method: "tools/call", Tool: "tool", Resource: "mcp://server/data/secret", Arguments: map[string]string{"value": "ok"}, SessionID: "session"},
		{Server: "server", Method: "resources/read", Resource: "mcp://server/data/one", Arguments: map[string]string{"value": "smuggled"}, SessionID: "session"},
		{Server: "server", Method: "tools/list", Tool: "tool", SessionID: "session"},
	}
	for _, request := range requests {
		if decision := engine.Evaluate(request, NewTaintState()); decision.Action != "deny" || decision.Rule != "builtin:invalid-request" {
			t.Fatalf("method-confused request was not rejected: request=%#v decision=%#v", request, decision)
		}
	}
}

func TestReceiptClaimsReplayAndBatchBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := NewAuditLog("", priv, 10)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Action: "allow", Server: "server", Tool: "tool", Rule: "allow", Reason: "test", SessionID: "session"}
	request := EvalRequest{Server: "server", Method: "tools/call", Tool: "tool", SessionID: "session", SessionToken: "must-not-be-signed"}
	entry, err := al.Record("evaluate", &decision, &request, "")
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := "sha256:" + strings.Repeat("a", 64)
	receipt, err := al.SignReceipt(decision, request, entry, ReceiptOptions{
		Audience: "secai:test", PolicyDigest: policyDigest, TTL: time.Minute,
		BatchID: "batch", BatchIndex: 1, BatchSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(receipt.RequestDigest, "must-not-be-signed") || receipt.AuditHash != entry.Hash || receipt.KeyID == "" {
		t.Fatalf("receipt context binding incomplete: %#v", receipt)
	}
	expectedRequestDigest, err := ComputeRequestDigest(request)
	if err != nil || receipt.RequestDigest != expectedRequestDigest {
		t.Fatalf("receipt request digest mismatch: got=%q want=%q err=%v", receipt.RequestDigest, expectedRequestDigest, err)
	}
	mutated := request
	mutated.Tool = "other-tool"
	mutatedDigest, _ := ComputeRequestDigest(mutated)
	if mutatedDigest == receipt.RequestDigest {
		t.Fatal("request substitution did not change the execution digest")
	}
	verifier, err := NewReceiptVerifier(pub, "secai:test", policyDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyAndConsume(receipt); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if err := verifier.VerifyAndConsume(receipt); err == nil {
		t.Fatal("replayed receipt was accepted")
	}
	tampered := receipt
	tampered.BatchIndex = 0
	if VerifyReceipt(tampered, pub) {
		t.Fatal("tampered batch binding was accepted")
	}
}

func TestReceiptReservationCanRetryAfterAuditFailure(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := NewAuditLog("", priv, 10)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Action: "allow", Server: "server", Rule: "allow", Reason: "ok", SessionID: "session"}
	request := EvalRequest{Server: "server", Method: "tools/list", SessionID: "session"}
	entry, err := al.Record("evaluate", &decision, &request, "")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	receipt, err := al.SignReceipt(decision, request, entry, ReceiptOptions{Audience: "secai:test", PolicyDigest: digest, TTL: time.Minute, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewReceiptVerifier(pub, "secai:test", digest)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := verifier.ReserveForPolicy(receipt, digest)
	if err != nil {
		t.Fatal(err)
	}
	// The completion handler releases this reservation when durable audit fails.
	verifier.Release(reservation)
	retry, err := verifier.ReserveForPolicy(receipt, digest)
	if err != nil {
		t.Fatalf("receipt could not be retried after failed audit persistence: %v", err)
	}
	verifier.Commit(retry)
	if _, err := verifier.ReserveForPolicy(receipt, digest); err == nil {
		t.Fatal("receipt remained reusable after committed completion")
	}
}

func TestExecutionCompletionAuditFailureDoesNotBurnReceiptOrApplyTaint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := NewAuditLog("", priv, 10)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewSessionBindingManager([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Create("server", 2, 60)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Action: "allow", Server: "server", Tool: "source", Rule: "allow", Reason: "ok", SessionID: binding.SessionID, TaintApplied: []string{"external"}}
	request := EvalRequest{Server: "server", Method: "tools/call", Tool: "source", SessionID: binding.SessionID, SessionToken: binding.BindingToken}
	entry, err := al.Record("evaluate", &decision, &request, "")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	receipt, err := al.SignReceipt(decision, request, entry, ReceiptOptions{Audience: "secai:test", PolicyDigest: digest, TTL: time.Minute, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewReceiptVerifier(pub, "secai:test", digest)
	if err != nil {
		t.Fatal(err)
	}
	taint := NewTaintState()
	al.mu.Lock()
	al.writeErr = errors.New("synthetic durable audit failure")
	al.mu.Unlock()
	if _, err := completeExecution(receipt, binding.BindingToken, true, digest, manager, verifier, al, taint); !errors.Is(err, errCompletionAudit) {
		t.Fatalf("expected audit failure, got %v", err)
	}
	if taint.HasTaint(binding.SessionID, "external") {
		t.Fatal("taint was applied before completion audit became durable")
	}
	al.mu.Lock()
	al.writeErr = nil // models operator recovery/restart while the receipt remains unexpired
	al.mu.Unlock()
	if applied, err := completeExecution(receipt, binding.BindingToken, true, digest, manager, verifier, al, taint); err != nil || len(applied) != 1 {
		t.Fatalf("unexpired receipt was not safely retryable after audit recovery: applied=%v err=%v", applied, err)
	}
	if !taint.HasTaint(binding.SessionID, "external") {
		t.Fatal("successful durable completion did not propagate taint")
	}
	if _, err := completeExecution(receipt, binding.BindingToken, true, digest, manager, verifier, al, taint); !errors.Is(err, errCompletionReceipt) {
		t.Fatalf("completed receipt replay was not denied: %v", err)
	}
}

func TestConsumedReceiptReplayStateRecoversFromAudit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLog(path, priv, 10)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{Action: "allow", Server: "server", Rule: "allow", Reason: "ok", SessionID: "session"}
	request := EvalRequest{Server: "server", Method: "tools/list", SessionID: "session"}
	entry, err := al.Record("evaluate", &decision, &request, "")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	receipt, err := al.SignReceipt(decision, request, entry, ReceiptOptions{Audience: "secai:test", PolicyDigest: digest, TTL: time.Minute, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := al.RecordCompletion(receipt, true); err != nil {
		t.Fatal(err)
	}
	if err := al.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewAuditLog(path, priv, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	verifier, err := NewReceiptVerifier(pub, "secai:test", digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.SeedConsumed(recovered.ConsumedReceipts()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.ReserveForPolicy(receipt, digest); err == nil {
		t.Fatal("receipt consumed before restart became replayable after audit recovery")
	}
	entries := recovered.Entries(0)
	entries[len(entries)-1].ReceiptUse.Success = false
	if valid, _ := VerifyChain(entries); valid {
		t.Fatal("tampered durable receipt-use claim was not covered by the audit hash")
	}
}

func TestServerIssuedSessionAndSeparateAdminRole(t *testing.T) {
	manager, err := NewSessionBindingManager([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	one, err := manager.Create("server", 2, 60)
	if err != nil {
		t.Fatal(err)
	}
	two, err := manager.Create("server", 2, 60)
	if err != nil {
		t.Fatal(err)
	}
	if one.SessionID == two.SessionID || one.BindingToken == two.BindingToken || len(one.SessionID) < 32 {
		t.Fatal("server-issued sessions were not independently unpredictable")
	}
	if ok, _ := manager.Validate(one.SessionID, "server", one.BindingToken); !ok {
		t.Fatal("issued session did not authorize evaluation")
	}
	if ok, _ := manager.Check(one.SessionID, "server", one.BindingToken); !ok {
		t.Fatal("issued session did not authenticate completion")
	}

	service := strings.Repeat("s", 32)
	admin := strings.Repeat("a", 32)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authenticatedCredentialHandler(next, testCredentialSet(t, service, admin))
	for token, want := range map[string]int{service: http.StatusForbidden, admin: http.StatusNoContent} {
		req := httptest.NewRequest(http.MethodDelete, "/v1/taint/session", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != want {
			t.Fatalf("role separation failed for expected status %d: got %d", want, response.Code)
		}
	}
}

func TestBatchSessionAuthorizationIsAtomic(t *testing.T) {
	manager, err := NewSessionBindingManager([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Create("server", 2, 60)
	if err != nil {
		t.Fatal(err)
	}
	requests := []EvalRequest{
		{Server: "server", SessionID: binding.SessionID, SessionToken: binding.BindingToken},
		{Server: "server", SessionID: binding.SessionID, SessionToken: "invalid"},
	}
	if ok, _ := manager.ValidateBatch(requests); ok {
		t.Fatal("invalid batch session was accepted")
	}
	if ok, reason := manager.Validate(binding.SessionID, "server", binding.BindingToken); !ok {
		t.Fatalf("failed batch partially consumed valid allowance: %s", reason)
	}
}

func TestAuditRuntimeIdentityLinksModeAndBoundaryRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	al, err := NewAuditLog(path, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	request := EvalRequest{Server: "server", Method: "tools/call", SessionID: "customer-session", SessionToken: "secret-token", Arguments: map[string]string{"content": "password=hunter2"}}
	decision := Decision{Action: "deny", Server: "server", Rule: "test", Reason: "Bearer abcdefghijklmnopqrstuvwxyz123456", SessionID: "customer-session", RedactedArgs: map[string]string{"nested": "api_key=abcdefghijklmnopqrstuv"}}
	if _, err := al.Record("evaluate", &decision, &request, "password=supersecret"); err != nil {
		t.Fatal(err)
	}
	entry := al.Entries(1)[0]
	encoded := entry.Detail + entry.Decision.Reason + entry.Decision.RedactedArgs["nested"] + entry.Request.Arguments["content"] + entry.Request.SessionToken
	if strings.Contains(encoded, "hunter2") || strings.Contains(encoded, "supersecret") || strings.Contains(encoded, "abcdefghijklmnopqrstuv") || strings.Contains(encoded, "customer-session") {
		t.Fatalf("audit boundary retained sensitive content: %#v", entry)
	}
	link := filepath.Join(dir, "audit-link.jsonl")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := al.Record("evaluate", nil, nil, ""); err == nil {
		t.Fatal("live audit hard-link change was not rejected")
	}
	_ = al.Close()

	broad := filepath.Join(dir, "broad.jsonl")
	if err := os.WriteFile(broad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(broad, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditLog(broad, nil, 10); err == nil {
		t.Fatal("broad audit permissions were accepted")
	}
}

func TestAuditIdentityAttributionIsStructuredAndNotRedacted(t *testing.T) {
	al, err := NewAuditLog("", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	entry, err := al.RecordContext("evaluate", nil, nil, "password=do-not-retain", AuditContext{
		Identity: "password:operator", PolicyDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Identity != "password:operator" {
		t.Fatalf("structured identity was altered by detail redaction: %q", entry.Identity)
	}
	if entry.PolicyDigest != digest {
		t.Fatalf("policy digest attribution was lost: %q", entry.PolicyDigest)
	}
	if strings.Contains(entry.Detail, "do-not-retain") {
		t.Fatalf("free-form audit detail was not redacted: %q", entry.Detail)
	}
}

func TestEvaluationDoesNotApplyTaintBeforeCompletion(t *testing.T) {
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", Servers: []ServerPolicy{{
		Name: "server", TrustLevel: "trusted", AllowedTools: []ToolPolicy{{Name: "source", Action: "allow", TaintLabel: "external"}},
	}}}
	state := NewTaintState()
	decision := NewPolicyEngine(policy).Evaluate(EvalRequest{Server: "server", Method: "tools/call", Tool: "source", SessionID: "session"}, state)
	if decision.Action != "allow" || len(decision.TaintApplied) != 1 || state.HasTaint("session", "external") {
		t.Fatalf("taint was not deferred to successful completion: decision=%#v state=%#v", decision, state.Entries("session"))
	}
}

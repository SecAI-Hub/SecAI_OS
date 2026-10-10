package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type remediationGateway struct {
	handler http.Handler
	audit   *AuditLog
	taint   *TaintState
}

func newRemediationGateway(t *testing.T, path string, key ed25519.PrivateKey) *remediationGateway {
	t.Helper()
	policy := &FirewallPolicy{Version: 1, DefaultAction: "deny", Servers: []ServerPolicy{
		{Name: "web", TrustLevel: "untrusted", AllowedTools: []ToolPolicy{{Name: "search", Action: "allow", TaintLabel: "external-data"}}},
		{Name: "calculator", TrustLevel: "trusted", AllowedTools: []ToolPolicy{{Name: "evaluate", Action: "allow"}}},
	}, TaintRules: []TaintRule{{Name: "no-external-eval", Match: TaintMatch{SourceTaint: []string{"external-data"}, TargetTools: []string{"evaluate"}}, Action: "deny", Reason: "untrusted data cannot execute"}},
		Audit: AuditConfig{Enabled: true, SignReports: true, LogPath: path, KeyPath: "/unused", ReceiptAudience: "test:mcp", ReceiptTTLSeconds: 120}}
	digest, err := computePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	var runtime atomic.Pointer[firewallRuntime]
	runtime.Store(&firewallRuntime{policy: policy, engine: NewPolicyEngine(policy), digest: digest})
	al, err := NewAuditLog(path, key, 10)
	if err != nil {
		t.Fatal(err)
	}
	taint := NewTaintState()
	if err := al.RestoreTaint(taint); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSessionBindingManager([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewReceiptVerifier(key.Public().(ed25519.PublicKey), policy.Audit.ReceiptAudience, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.SeedConsumed(al.ConsumedReceipts()); err != nil {
		t.Fatal(err)
	}
	principals := []credentialPrincipal{}
	for _, identity := range []string{"alice", "bob"} {
		principals = append(principals, credentialPrincipal{identity: identity, tokenDigest: sha256.Sum256([]byte(strings.Repeat(identity, 16))), roles: roleMap(roleEvaluator, roleObserver)})
	}
	principals = append(principals, credentialPrincipal{identity: "admin", tokenDigest: sha256.Sum256([]byte(strings.Repeat("admin", 16))), roles: roleMap(roleAdministrator)})
	credentials, err := newCredentialSet(principals)
	if err != nil {
		t.Fatal(err)
	}
	mux := newMCPFirewallMux(mcpHTTPDependencies{runtime: &runtime, policyTxnMu: &sync.RWMutex{}, taintState: taint, privateKey: key, sessions: sessions, receiptVerifier: verifier, auditLog: al})
	return &remediationGateway{authenticatedCredentialHandler(mux, credentials), al, taint}
}

func (g *remediationGateway) call(t *testing.T, identity, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(data)))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat(identity, 16))
	response := httptest.NewRecorder()
	g.handler.ServeHTTP(response, request)
	return response
}

func (g *remediationGateway) request(t *testing.T, identity, server, tool string) EvalRequest {
	t.Helper()
	r := g.call(t, identity, http.MethodPost, "/v1/sessions", map[string]any{"server": server})
	if r.Code != http.StatusCreated {
		t.Fatalf("session: %d %s", r.Code, r.Body.String())
	}
	var binding SessionBinding
	if err := json.Unmarshal(r.Body.Bytes(), &binding); err != nil {
		t.Fatal(err)
	}
	return EvalRequest{Server: server, Method: "tools/call", Tool: tool, SessionID: binding.SessionID, SessionToken: binding.BindingToken}
}

func TestDurablePrincipalTaintAndCompletionRecovery(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	g := newRemediationGateway(t, path, key)
	request := g.request(t, "alice", "web", "search")
	response := g.call(t, "alice", http.MethodPost, "/v1/evaluate", request)
	var result struct {
		Decision Decision        `json:"decision"`
		Receipt  DecisionReceipt `json:"receipt"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Decision.Action != "allow" {
		t.Fatalf("evaluation: %s", response.Body.String())
	}
	// No completion is needed to constrain an in-flight or unresolved effect.
	for _, identity := range []string{"alice", "bob"} {
		r := g.call(t, identity, http.MethodPost, "/v1/evaluate", g.request(t, identity, "calculator", "evaluate"))
		var verdict struct {
			Decision Decision `json:"decision"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &verdict)
		want := "deny"
		if identity == "bob" {
			want = "allow"
		}
		if r.Code != 200 || verdict.Decision.Action != want {
			t.Fatalf("%s cross-server verdict: %s", identity, r.Body.String())
		}
	}
	if r := g.call(t, "alice", http.MethodDelete, "/v1/taint/anything", nil); r.Code != 403 {
		t.Fatal("evaluator can clear taint")
	}
	if r := g.call(t, "admin", http.MethodDelete, "/v1/taint/anything", nil); r.Code != 409 {
		t.Fatal("in-flight context can be cleared")
	}
	if r := g.call(t, "bob", http.MethodGet, "/v1/taint/"+request.SessionID, nil); strings.Contains(r.Body.String(), "external-data") {
		t.Fatal("another identity can read taint")
	}
	for i := 0; i < 15; i++ {
		if _, err := g.audit.Record("heartbeat", nil, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(g.audit.Entries(0)) != 10 || !g.audit.ContainsDecision(result.Receipt.AuditSequence, result.Receipt.AuditHash) {
		t.Fatal("display eviction lost completion evidence")
	}
	if err := g.audit.Close(); err != nil {
		t.Fatal(err)
	}
	// Build a valid large historical fixture in one flush. Production append
	// durability is tested above and by the separate audit fault tests; 1,100
	// synchronous fixture flushes are not necessary to test index recovery.
	journal, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	previous, sequence := g.audit.prevHash, g.audit.seq
	for i := 0; i < 1100; i++ {
		entry := AuditEntry{Sequence: sequence + 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), PrevHash: previous, Event: "heartbeat"}
		entry.Hash = computeAuditHash(entry)
		if err := json.NewEncoder(journal).Encode(entry); err != nil {
			journal.Close()
			t.Fatal(err)
		}
		previous, sequence = entry.Hash, entry.Sequence
	}
	if err := journal.Sync(); err != nil {
		journal.Close()
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	g = newRemediationGateway(t, path, key)
	r := g.call(t, "alice", http.MethodPost, "/v1/evaluate", g.request(t, "alice", "calculator", "evaluate"))
	if !strings.Contains(r.Body.String(), `"action":"deny"`) {
		t.Fatalf("restart lost taint: %s", r.Body.String())
	}
	completion := map[string]any{"receipt": result.Receipt, "session_token": request.SessionToken, "success": true}
	if r := g.call(t, "bob", http.MethodPost, "/v1/executions/complete", completion); r.Code != 401 {
		t.Fatalf("wrong identity completion: %d", r.Code)
	}
	if r := g.call(t, "alice", http.MethodPost, "/v1/executions/complete", completion); r.Code != 200 {
		t.Fatalf("restart completion: %d %s", r.Code, r.Body.String())
	}
	if err := g.audit.Close(); err != nil {
		t.Fatal(err)
	}
	g = newRemediationGateway(t, path, key)
	defer g.audit.Close()
	if r := g.call(t, "alice", http.MethodPost, "/v1/executions/complete", completion); r.Code != 403 {
		t.Fatalf("restart replay: %d", r.Code)
	}
}

func TestBatchAndAuditFailureCannotIssueUnsafeAllow(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	g := newRemediationGateway(t, filepath.Join(t.TempDir(), "audit.jsonl"), key)
	requests := []EvalRequest{g.request(t, "alice", "web", "search"), g.request(t, "alice", "calculator", "evaluate")}
	r := g.call(t, "alice", http.MethodPost, "/v1/evaluate/batch", requests)
	var result struct {
		Decisions []Decision `json:"decisions"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &result)
	if r.Code != 200 || len(result.Decisions) != 2 || result.Decisions[0].Action != "allow" || result.Decisions[1].Action != "deny" {
		t.Fatalf("batch: %s", r.Body.String())
	}
	request := g.request(t, "bob", "web", "search")
	if err := g.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if r := g.call(t, "bob", http.MethodPost, "/v1/evaluate", request); r.Code != 503 || strings.Contains(r.Body.String(), `"receipt"`) {
		t.Fatalf("failed audit issued decision: %s", r.Body.String())
	}
	if r := g.call(t, "bob", http.MethodGet, "/ready", nil); r.Code != 503 {
		t.Fatal("failed audit reported ready")
	}
}

func TestAuditMinimizesUnknownSecretsAndPreventsConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLog(path, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	if other, err := NewAuditLog(path, nil, 10); err == nil {
		other.Close()
		t.Fatal("multiple audit writers accepted")
	}
	secret := "opaqueSyntheticBusinessSecret42"
	request := EvalRequest{Server: secret, Method: secret, Tool: secret, Arguments: map[string]string{secret: secret}, SessionID: secret}
	decision := Decision{Action: "deny", Server: secret, Tool: secret, Rule: secret, Reason: secret, Evidence: []string{secret}, RedactedArgs: map[string]string{secret: secret}}
	if _, err := al.Record("evaluate", &decision, &request, secret); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(al.Entries(0))
	if strings.Contains(string(encoded), secret) {
		t.Fatal("opaque secret retained in audit")
	}
	if ok, _ := VerifyChain(al.Entries(0)); !ok {
		t.Fatal("minimized audit chain invalid")
	}
}

func TestPrincipalTaintDoesNotExpireOrEvict(t *testing.T) {
	state := NewTaintState()
	state.maxSessions = 2
	for i := 0; i < 2; i++ {
		if !state.Add(principalTaintContext(fmt.Sprint(i)), "external-data", "test") {
			t.Fatal("premature capacity failure")
		}
	}
	if state.Add(principalTaintContext("third"), "external-data", "test") || state.Available() {
		t.Fatal("capacity did not fail closed")
	}
	if !state.HasTaint(principalTaintContext("0"), "external-data") {
		t.Fatal("capacity evicted protected context")
	}
}

func TestCanonicalPathRejectsSymlinkParentAmbiguityAndDanglingLinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root + "/outside/../private", root + "/dangling/file", root + "/outside/file", root + "/safe\nfile"} {
		if violation := checkPathRestrictions([]string{root}, map[string]string{"path": path}); violation == "" {
			t.Fatalf("ambiguous or escaped path permitted: %q", path)
		}
	}
	if violation := checkPathRestrictions([]string{root}, map[string]string{"path": root + "/new-parent/file"}); violation != "" {
		t.Fatalf("safe missing parent rejected: %s", violation)
	}
}

func TestNativeSigningSeedCredential(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(trustedCredentialTestDir(t), "signing.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := loadSigningKey(path)
	if err != nil || !key.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatalf("native seed credential: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigningKey(path); err == nil {
		t.Fatal("publicly readable seed was accepted")
	}
}

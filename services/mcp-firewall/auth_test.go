package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

func trustedCredentialTestDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".mcp-firewall-credentials-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestScopedCredentialsEnforceExactRoles(t *testing.T) {
	evaluator := strings.Repeat("e", 32)
	observer := strings.Repeat("o", 32)
	admin := strings.Repeat("a", 32)
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "runtime-a", tokenDigest: sha256.Sum256([]byte(evaluator)), roles: roleMap(roleEvaluator)},
		{identity: "monitor", tokenDigest: sha256.Sum256([]byte(observer)), roles: roleMap(roleObserver)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(admin)), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, roleEvaluator) {
			return
		}
		if authenticatedIdentity(r) != "runtime-a" {
			t.Fatal("authenticated identity was not bound to the request")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/observe", func(w http.ResponseWriter, r *http.Request) {
		if requireRole(w, r, roleObserver) {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r) {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	handler := authenticatedCredentialHandler(mux, credentials)

	for _, test := range []struct {
		path, token string
		want        int
	}{
		{"/evaluate", evaluator, http.StatusNoContent},
		{"/evaluate", observer, http.StatusForbidden},
		{"/evaluate", admin, http.StatusForbidden},
		{"/observe", observer, http.StatusNoContent},
		{"/admin", admin, http.StatusNoContent},
		{"/admin", evaluator, http.StatusForbidden},
		{"/evaluate", "wrong", http.StatusUnauthorized},
		{"/evaluate", strings.Repeat("z", maxCredentialTokenSize+1), http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, test.path, nil)
		req.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != test.want {
			t.Fatalf("%s returned %d, want %d", test.path, response.Code, test.want)
		}
	}
}

func TestCredentialConfigurationLoadsIdentityAndRejectsUnsafeRoleSets(t *testing.T) {
	if _, err := loadCredentialSetFile("relative-credentials.yaml"); err == nil {
		t.Fatal("relative credential configuration path was accepted")
	}
	dir := trustedCredentialTestDir(t)
	paths := make([]string, 3)
	for i, value := range []string{strings.Repeat("e", 32), strings.Repeat("o", 32), strings.Repeat("a", 32)} {
		paths[i] = filepath.Join(dir, fmt.Sprintf("token-%d", i))
		if err := os.WriteFile(paths[i], []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(dir, "credentials.yaml")
	body := fmt.Sprintf("version: 1\ncredentials:\n  - identity: runtime-a\n    token_path: %s\n    roles: [evaluator]\n  - identity: monitor\n    token_path: %s\n    roles: [observer]\n  - identity: operator\n    token_path: %s\n    roles: [administrator]\n", paths[0], paths[1], paths[2])
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := loadCredentialSetFile(config)
	if err != nil || len(credentials.principals) != 3 {
		t.Fatalf("valid credential configuration rejected: %v", err)
	}

	principals := []credentialPrincipal{
		{identity: "combined-admin", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleAdministrator, roleObserver)},
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(strings.Repeat("y", 32))), roles: roleMap(roleEvaluator)},
	}
	if _, err := newCredentialSet(principals); err == nil {
		t.Fatal("administrator combined with another role was accepted")
	}
	principals = []credentialPrincipal{
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleEvaluator)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(strings.Repeat("x", 32))), roles: roleMap(roleAdministrator)},
	}
	if _, err := newCredentialSet(principals); err == nil {
		t.Fatal("duplicate token values were accepted for different identities")
	}
}

func TestCredentialSourcesRequireTrustedOwnersAndParentChain(t *testing.T) {
	dir := trustedCredentialTestDir(t)
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenCredentialPath(token, "test token"); err != nil {
		t.Fatalf("trusted token rejected: %v", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenCredentialPath(token, "test token"); err == nil {
		t.Fatal("token beneath a group-writable parent was accepted")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	expectedUID := os.Geteuid() + 1
	if os.Geteuid() == 0 {
		expectedUID = 0
		if err := os.Chown(token, 65534, -1); err != nil {
			t.Skipf("cannot create mismatched-owner fixture: %v", err)
		}
	}
	identities, err := inspectTrustedCredentialPath(token, 0o077, expectedUID)
	if err == nil || identities != nil {
		t.Fatal("credential path owned by neither root nor the expected effective uid was accepted")
	}
	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(token, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := loadTokenCredentialPath(link, "test token"); err == nil {
		t.Fatal("credential token symlink was accepted")
	}
}

func TestProductionMuxEnforcesFullRoleMatrix(t *testing.T) {
	policy := testPolicy()
	policy.Audit = AuditConfig{
		Enabled: true, SignReports: true, LogPath: "", KeyPath: "/unused",
		ReceiptAudience: "test:mcp-firewall", ReceiptTTLSeconds: 120,
	}
	digest, err := computePolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	var runtimeState atomic.Pointer[firewallRuntime]
	runtimeState.Store(&firewallRuntime{policy: policy, engine: NewPolicyEngine(policy), digest: digest})

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := NewAuditLog("", privateKey, 100)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSessionBindingManager(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	receiptVerifier, err := NewReceiptVerifier(privateKey.Public().(ed25519.PublicKey), policy.Audit.ReceiptAudience, digest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sessions.Create("filesystem", 100, 900)
	if err != nil {
		t.Fatal(err)
	}

	completionBinding, err := sessions.Create("filesystem", 10, 900)
	if err != nil {
		t.Fatal(err)
	}
	completionRequest := EvalRequest{
		Server: "filesystem", Method: "tools/call", Tool: "read_file",
		Arguments: map[string]string{"path": "/home/user/completion.txt"},
		SessionID: completionBinding.SessionID, SessionToken: completionBinding.BindingToken,
	}
	completionDecision := runtimeState.Load().engine.Evaluate(completionRequest, NewTaintState())
	auditRequest := sanitizeRequestForAudit(completionRequest)
	auditEntry, err := auditLog.RecordContext("evaluate", &completionDecision, &auditRequest, "", AuditContext{PolicyDigest: digest, Identity: "runtime"})
	if err != nil {
		t.Fatal(err)
	}
	completionReceipt, err := auditLog.SignReceipt(completionDecision, completionRequest, auditEntry, ReceiptOptions{
		Audience: policy.Audit.ReceiptAudience, PolicyDigest: digest, TTL: 2 * time.Minute, BatchSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	completionBody, err := json.Marshal(map[string]any{
		"receipt": completionReceipt, "session_token": completionBinding.BindingToken, "success": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tokens := map[gatewayRole]string{
		roleEvaluator:     strings.Repeat("e", 32),
		roleObserver:      strings.Repeat("o", 32),
		roleAdministrator: strings.Repeat("a", 32),
	}
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(tokens[roleEvaluator])), roles: roleMap(roleEvaluator)},
		{identity: "monitor", tokenDigest: sha256.Sum256([]byte(tokens[roleObserver])), roles: roleMap(roleObserver)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(tokens[roleAdministrator])), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	dependencies := mcpHTTPDependencies{
		runtime: &runtimeState, policyTxnMu: &sync.RWMutex{}, taintState: NewTaintState(),
		privateKey: privateKey, sessions: sessions, receiptVerifier: receiptVerifier, auditLog: auditLog,
		loadPolicy: func() (*FirewallPolicy, error) { return policy, nil },
	}
	handler := authenticatedCredentialHandler(newMCPFirewallMux(dependencies), credentials)

	evaluateBody := fmt.Sprintf(`{"server":"filesystem","method":"tools/call","tool":"read_file","arguments":{"path":"/home/user/test.txt"},"session_id":%q,"session_token":%q}`, binding.SessionID, binding.BindingToken)
	batchBody := "[" + evaluateBody + "]"
	endpoints := []struct {
		name, method, path, body string
		role                     gatewayRole
		allowedStatus            int
	}{
		{"evaluate", http.MethodPost, "/v1/evaluate", evaluateBody, roleEvaluator, http.StatusOK},
		{"evaluate-batch", http.MethodPost, "/v1/evaluate/batch", batchBody, roleEvaluator, http.StatusOK},
		{"session-create", http.MethodPost, "/v1/sessions", `{"server":"filesystem"}`, roleEvaluator, http.StatusCreated},
		{"execution-complete", http.MethodPost, "/v1/executions/complete", string(completionBody), roleEvaluator, http.StatusOK},
		{"servers", http.MethodGet, "/v1/servers", "", roleObserver, http.StatusOK},
		{"policy", http.MethodGet, "/v1/policy", "", roleObserver, http.StatusOK},
		{"taint-read", http.MethodGet, "/v1/taint/session", "", roleObserver, http.StatusOK},
		{"audit", http.MethodGet, "/v1/audit", "", roleObserver, http.StatusOK},
		{"audit-verify", http.MethodGet, "/v1/audit/verify", "", roleObserver, http.StatusOK},
		{"metrics", http.MethodGet, "/v1/metrics", "", roleObserver, http.StatusOK},
		{"session-revoke", http.MethodDelete, "/v1/sessions/session", "", roleAdministrator, http.StatusOK},
		{"taint-clear", http.MethodDelete, "/v1/taint/session", "", roleAdministrator, http.StatusConflict},
		{"reload", http.MethodPost, "/v1/reload", "", roleAdministrator, http.StatusOK},
	}
	roles := []gatewayRole{roleEvaluator, roleObserver, roleAdministrator}
	for _, endpoint := range endpoints {
		for _, role := range roles {
			t.Run(endpoint.name+"/"+string(role), func(t *testing.T) {
				request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
				request.Header.Set("Authorization", "Bearer "+tokens[role])
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				want := http.StatusForbidden
				if role == endpoint.role {
					want = endpoint.allowedStatus
				}
				if response.Code != want {
					t.Fatalf("got %d, want %d: %s", response.Code, want, response.Body.String())
				}
			})
		}
		t.Run(endpoint.name+"/unauthenticated", func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body)))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", response.Code)
			}
		})
	}
}

func TestProductionMuxSerializesReloadAndEvaluationAuditDigests(t *testing.T) {
	oldPolicy := testPolicy()
	newPolicy := testPolicy()
	newPolicy.Redaction.Enabled = !oldPolicy.Redaction.Enabled
	oldDigest, err := computePolicyDigest(oldPolicy)
	if err != nil {
		t.Fatal(err)
	}
	newDigest, err := computePolicyDigest(newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if oldDigest == newDigest {
		t.Fatal("test policies produced the same digest")
	}
	var runtimeState atomic.Pointer[firewallRuntime]
	runtimeState.Store(&firewallRuntime{policy: oldPolicy, engine: NewPolicyEngine(oldPolicy), digest: oldDigest})
	auditLog, err := NewAuditLog("", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSessionBindingManager(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sessions.Create("filesystem", 100, 900)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorToken := strings.Repeat("e", 32)
	adminToken := strings.Repeat("a", 32)
	credentials, err := newCredentialSet([]credentialPrincipal{
		{identity: "runtime", tokenDigest: sha256.Sum256([]byte(evaluatorToken)), roles: roleMap(roleEvaluator)},
		{identity: "operator", tokenDigest: sha256.Sum256([]byte(adminToken)), roles: roleMap(roleAdministrator)},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := authenticatedCredentialHandler(newMCPFirewallMux(mcpHTTPDependencies{
		runtime: &runtimeState, policyTxnMu: &sync.RWMutex{}, taintState: NewTaintState(),
		sessions: sessions, auditLog: auditLog, loadPolicy: func() (*FirewallPolicy, error) { return newPolicy, nil },
	}), credentials)
	evaluateBody := fmt.Sprintf(`{"server":"filesystem","method":"tools/call","tool":"read_file","arguments":{"path":"/home/user/test.txt"},"session_id":%q,"session_token":%q}`, binding.SessionID, binding.BindingToken)

	start := make(chan struct{})
	statuses := make(chan int, 25)
	var wait sync.WaitGroup
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(evaluateBody))
			request.Header.Set("Authorization", "Bearer "+evaluatorToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		request := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
		request.Header.Set("Authorization", "Bearer "+adminToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		statuses <- response.Code
	}()
	close(start)
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent request returned %d", status)
		}
	}

	activeDigest := oldDigest
	reloads, evaluations := 0, 0
	for _, entry := range auditLog.Entries(0) {
		switch entry.Event {
		case "reload":
			reloads++
			if entry.OldPolicyDigest != activeDigest || entry.NewPolicyDigest != newDigest {
				t.Fatalf("invalid reload transition: %#v", entry)
			}
			activeDigest = entry.NewPolicyDigest
		case "evaluate":
			evaluations++
			if entry.PolicyDigest != activeDigest {
				t.Fatalf("evaluation digest %q does not match audit-ordered digest %q", entry.PolicyDigest, activeDigest)
			}
		}
	}
	if reloads != 1 || evaluations != 24 {
		t.Fatalf("got %d reload and %d evaluation records", reloads, evaluations)
	}
}

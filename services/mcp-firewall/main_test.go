package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- policy engine tests ----------

func testPolicy() *FirewallPolicy {
	return &FirewallPolicy{
		Version:       1,
		DefaultAction: "deny",
		Servers: []ServerPolicy{
			{
				Name:       "filesystem",
				TrustLevel: "trusted",
				AllowedTools: []ToolPolicy{
					{
						Name:   "read_file",
						Action: "allow",
						ArgRules: []ArgRule{
							{Name: "path", Required: true, Pattern: `^/home/`, MaxLen: 256},
						},
						PathRules:  []string{"/home/user"},
						TaintLabel: "fs-read",
					},
					{
						Name:   "write_file",
						Action: "require-approval",
						ArgRules: []ArgRule{
							{Name: "path", Required: true},
							{Name: "content", MaxLen: 10000},
						},
						PathRules: []string{"/home/user"},
					},
					{
						Name:   "delete_file",
						Action: "deny",
					},
				},
				AllowedResources: []ResourcePolicy{
					{Pattern: "file:///home/user/*", Action: "allow"},
					{Pattern: "file:///etc/*", Action: "deny"},
				},
			},
			{
				Name:       "web-search",
				TrustLevel: "untrusted",
				AllowedTools: []ToolPolicy{
					{
						Name:       "search",
						Action:     "allow",
						TaintLabel: "external-data",
					},
				},
			},
		},
		GlobalRules: []GlobalRule{
			{
				Name:        "block-shell-injection",
				Description: "Block arguments with shell metacharacters",
				Match:       Match{ArgPatterns: []string{`[;&|` + "`" + `$]`}},
				Action:      "deny",
				Reason:      "shell metacharacters detected in arguments",
			},
		},
		TaintRules: []TaintRule{
			{
				Name:        "no-external-to-write",
				Description: "External data cannot be written to filesystem",
				Match: TaintMatch{
					SourceTaint: []string{"external-data"},
					TargetTools: []string{"write_file"},
				},
				Action: "deny",
				Reason: "tainted external data cannot be used in file writes",
			},
		},
		Redaction: RedactionConfig{
			Enabled:  true,
			Patterns: []string{"api_key", "bearer_token", "email"},
		},
	}
}

func TestPolicy_AllowTool(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: map[string]string{"path": "/home/user/doc.txt"},
		SessionID: "s1",
	}, ts)

	if d.Action != "allow" {
		t.Errorf("expected allow, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPolicy_DenyDefault(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "unknown-server",
		Method:    "tools/call",
		Tool:      "anything",
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for unknown server, got %s", d.Action)
	}
}

func TestPolicy_DenyUnknownTool(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "execute_command",
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for unlisted tool, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "not in allowlist") {
		t.Errorf("expected allowlist reason, got %s", d.Reason)
	}
}

func TestPolicy_DenyExplicit(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "delete_file",
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected explicit deny, got %s", d.Action)
	}
}

func TestPolicy_RequireApproval(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "write_file",
		Arguments: map[string]string{"path": "/home/user/file.txt", "content": "hello"},
		SessionID: "s1",
	}, ts)

	if d.Action != "require-approval" {
		t.Errorf("expected require-approval, got %s", d.Action)
	}
}

func TestPolicy_ArgValidation_Required(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	// Missing required "path" argument
	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: map[string]string{},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for missing required arg, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "validation") {
		t.Errorf("expected validation reason, got %s", d.Reason)
	}
}

func TestPolicy_ArgValidation_Pattern(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	// Path doesn't match required pattern ^/home/
	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: map[string]string{"path": "/etc/passwd"},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for pattern violation, got %s", d.Action)
	}
}

func TestPolicy_ArgValidation_MaxLen(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	longPath := "/home/user/" + strings.Repeat("a", 300)
	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: map[string]string{"path": longPath},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for max_len violation, got %s", d.Action)
	}
}

func TestPolicy_PathRestriction(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "write_file",
		Arguments: map[string]string{"path": "/tmp/evil.sh", "content": "rm -rf /"},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for path outside restriction, got %s", d.Action)
	}
}

func TestPolicy_PathTraversal(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "write_file",
		Arguments: map[string]string{"path": "/home/user/../../etc/passwd", "content": "x"},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for path traversal, got %s", d.Action)
	}
}

func TestPolicy_GlobalRule_ShellInjection(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: map[string]string{"path": "/home/user/file; rm -rf /"},
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for shell injection, got %s", d.Action)
	}
	if d.Rule != "block-shell-injection" {
		t.Errorf("expected block-shell-injection rule, got %s", d.Rule)
	}
}

func TestPolicy_ListMethodsAllowed(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	for _, method := range []string{"tools/list", "resources/list", "prompts/list"} {
		d := engine.Evaluate(EvalRequest{
			Server:    "filesystem",
			Method:    method,
			SessionID: "s1",
		}, ts)

		if d.Action != "allow" {
			t.Errorf("expected allow for %s, got %s", method, d.Action)
		}
	}
}

func TestPolicy_ResourceAllow(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "resources/read",
		Resource:  "file:///home/user/readme.md",
		SessionID: "s1",
	}, ts)

	if d.Action != "allow" {
		t.Errorf("expected allow for home resource, got %s", d.Action)
	}
}

func TestPolicy_ResourceDeny(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	d := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "resources/read",
		Resource:  "file:///etc/shadow",
		SessionID: "s1",
	}, ts)

	if d.Action != "deny" {
		t.Errorf("expected deny for /etc resource, got %s", d.Action)
	}
}

// ---------- taint tracking tests ----------

func TestTaint_PropagationAndBlock(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	// Step 1: web search adds "external-data" taint
	d1 := engine.Evaluate(EvalRequest{
		Server:    "web-search",
		Method:    "tools/call",
		Tool:      "search",
		Arguments: map[string]string{"query": "test"},
		SessionID: "s1",
	}, ts)

	if d1.Action != "allow" {
		t.Fatalf("search should be allowed, got %s", d1.Action)
	}
	if len(d1.TaintApplied) == 0 || d1.TaintApplied[0] != "external-data" {
		t.Error("expected external-data taint applied")
	}

	// Step 2: write_file should be blocked due to taint
	d2 := engine.Evaluate(EvalRequest{
		Server:    "filesystem",
		Method:    "tools/call",
		Tool:      "write_file",
		Arguments: map[string]string{"path": "/home/user/result.txt", "content": "search result"},
		SessionID: "s1",
	}, ts)

	if d2.Action != "deny" {
		t.Errorf("expected deny due to taint rule, got %s", d2.Action)
	}
	if d2.Rule != "no-external-to-write" {
		t.Errorf("expected taint rule match, got %s", d2.Rule)
	}
}

func TestTaint_DifferentSessions(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()

	// Taint session s1
	engine.Evaluate(EvalRequest{
		Server: "web-search", Method: "tools/call", Tool: "search",
		Arguments: map[string]string{"query": "test"}, SessionID: "s1",
	}, ts)

	// Session s2 should be unaffected
	d := engine.Evaluate(EvalRequest{
		Server: "filesystem", Method: "tools/call", Tool: "write_file",
		Arguments: map[string]string{"path": "/home/user/file.txt", "content": "clean"},
		SessionID: "s2",
	}, ts)

	if d.Action == "deny" && d.Rule == "no-external-to-write" {
		t.Error("taint from s1 should not affect s2")
	}
}

func TestTaint_Clear(t *testing.T) {
	ts := NewTaintState()
	ts.Add("s1", "external-data", "web-search/search")

	if !ts.HasTaint("s1", "external-data") {
		t.Error("expected taint to exist")
	}

	ts.Clear("s1")

	if ts.HasTaint("s1", "external-data") {
		t.Error("expected taint to be cleared")
	}
}

func TestTaint_NoDuplicates(t *testing.T) {
	ts := NewTaintState()
	ts.Add("s1", "label-a", "source1")
	ts.Add("s1", "label-a", "source2")

	labels := ts.Labels("s1")
	if len(labels) != 1 {
		t.Errorf("expected 1 label (no duplicates), got %d", len(labels))
	}
}

// ---------- redaction tests ----------

func TestRedact_APIKey(t *testing.T) {
	input := `config: api_key=sk-1234567890abcdef1234567890`
	result := redactString(input, []string{"api_key"})
	if !strings.Contains(result, "[REDACTED:api_key]") {
		t.Errorf("expected redacted api_key, got %s", result)
	}
}

func TestRedact_BearerToken(t *testing.T) {
	input := `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test`
	result := redactString(input, []string{"bearer_token"})
	if !strings.Contains(result, "[REDACTED:bearer_token]") {
		t.Errorf("expected redacted bearer token, got %s", result)
	}
}

func TestRedact_Email(t *testing.T) {
	input := "contact admin@example.com for help"
	result := redactString(input, []string{"email"})
	if !strings.Contains(result, "[REDACTED:email]") {
		t.Errorf("expected redacted email, got %s", result)
	}
}

func TestRedact_Arguments(t *testing.T) {
	args := map[string]string{
		"content": "send to admin@corp.com with api_key=sk-abcdef1234567890123456",
		"path":    "/home/user/safe.txt",
	}

	redacted := redactArguments(args, []string{"email", "api_key"})
	if redacted == nil {
		t.Fatal("expected redacted arguments")
	}
	if _, ok := redacted["content"]; !ok {
		t.Error("content should have been redacted")
	}
	if _, ok := redacted["path"]; ok {
		t.Error("path should not have been redacted")
	}
}

func TestRedact_AllPattern(t *testing.T) {
	input := "bearer test_tok_abcdefghijklmnop and admin@test.com"
	result := redactString(input, []string{"all"})
	if strings.Contains(result, "admin@test.com") {
		t.Error("email should be redacted with 'all' pattern")
	}
}

func TestRedact_ConnectionString(t *testing.T) {
	input := "db: postgres://user:pass@localhost/mydb"
	result := redactString(input, []string{"connection_string"})
	if !strings.Contains(result, "[REDACTED:connection_string]") {
		t.Errorf("expected redacted connection string, got %s", result)
	}
}

// ---------- audit tests ----------

func TestAudit_HashChain(t *testing.T) {
	al, err := NewAuditLog("", nil, 100)
	if err != nil {
		t.Fatal(err)
	}

	al.Record("test1", nil, nil, "first")
	al.Record("test2", nil, nil, "second")
	al.Record("test3", nil, nil, "third")

	entries := al.Entries(0)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	valid, failIdx := VerifyChain(entries)
	if !valid {
		t.Errorf("chain should be valid, failed at %d", failIdx)
	}
}

func TestAudit_TamperDetection(t *testing.T) {
	al, _ := NewAuditLog("", nil, 100)

	al.Record("test1", nil, nil, "first")
	al.Record("test2", nil, nil, "second")

	entries := al.Entries(0)
	// Tamper with the first entry
	entries[0].Detail = "tampered"

	valid, failIdx := VerifyChain(entries)
	if valid {
		t.Error("tampered chain should be detected")
	}
	if failIdx != 0 {
		t.Errorf("expected failure at index 0, got %d", failIdx)
	}
}

func TestAudit_SignedReceipt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, _ := NewAuditLog("", priv, 100)

	decision := Decision{Action: "deny", Rule: "test", Reason: "test"}
	request := EvalRequest{Server: "test", Method: "tools/call", Tool: "test", SessionID: "s1"}

	receipt := al.SignReceipt(decision, request)

	if receipt.Signature == "" {
		t.Error("expected signed receipt")
	}
	if receipt.Hash == "" {
		t.Error("expected receipt hash")
	}

	if !VerifyReceipt(receipt, pub) {
		t.Error("receipt verification should pass")
	}
}

func TestAudit_ReceiptTamperDetection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, _ := NewAuditLog("", priv, 100)

	decision := Decision{Action: "allow", Rule: "test", Reason: "test"}
	request := EvalRequest{Server: "test", Method: "tools/call", SessionID: "s1"}

	receipt := al.SignReceipt(decision, request)

	// Tamper with the decision
	receipt.Decision.Action = "deny"

	if VerifyReceipt(receipt, pub) {
		t.Error("tampered receipt should fail verification")
	}
}

func TestAudit_MaxHistory(t *testing.T) {
	al, _ := NewAuditLog("", nil, 5)

	for i := 0; i < 10; i++ {
		al.Record("test", nil, nil, "")
	}

	entries := al.Entries(0)
	if len(entries) != 5 {
		t.Errorf("expected max 5 entries, got %d", len(entries))
	}
}

// ---------- HTTP handler tests ----------

func buildTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	return buildTestMuxWithToken(t, "")
}

func buildTestMuxWithToken(t *testing.T, token string) *http.ServeMux {
	t.Helper()

	policy := testPolicy()
	engine := NewPolicyEngine(policy)
	taintState := NewTaintState()
	al, _ := NewAuditLog("", nil, 100)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req EvalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		d := engine.Evaluate(req, taintState)
		al.Record("evaluate", &d, &req, "")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"decision": d})
	})

	mux.HandleFunc("/v1/evaluate/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var reqs []EvalRequest
		json.NewDecoder(r.Body).Decode(&reqs)
		var decisions []Decision
		for _, req := range reqs {
			decisions = append(decisions, engine.Evaluate(req, taintState))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"decisions": decisions})
	})

	mux.HandleFunc("/v1/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(policy.Servers)
	})

	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": policy.Version, "default_action": policy.DefaultAction,
		})
	})

	mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(al.Entries(100))
	})

	mux.HandleFunc("/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		entries := al.Entries(0)
		valid, failIdx := VerifyChain(entries)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": valid, "fail_index": failIdx})
	})

	mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"evaluations_total": metricEvals.Load(),
		})
	})

	mux.HandleFunc("/v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
	})

	return mux
}

func TestHTTP_Health(t *testing.T) {
	mux := buildTestMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHTTP_Evaluate(t *testing.T) {
	mux := buildTestMux(t)
	body := `{"server":"filesystem","method":"tools/call","tool":"read_file","arguments":{"path":"/home/user/doc.txt"},"session_id":"s1"}`
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/evaluate", strings.NewReader(body)))

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	decision := resp["decision"].(map[string]interface{})
	if decision["action"] != "allow" {
		t.Errorf("expected allow, got %s", decision["action"])
	}
}

func TestHTTP_EvaluateDeny(t *testing.T) {
	mux := buildTestMux(t)
	body := `{"server":"unknown","method":"tools/call","tool":"bad","session_id":"s1"}`
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/evaluate", strings.NewReader(body)))

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	decision := resp["decision"].(map[string]interface{})
	if decision["action"] != "deny" {
		t.Errorf("expected deny, got %s", decision["action"])
	}
}

func TestHTTP_EvaluateBatch(t *testing.T) {
	mux := buildTestMux(t)
	body := `[
		{"server":"filesystem","method":"tools/call","tool":"read_file","arguments":{"path":"/home/user/a.txt"},"session_id":"s1"},
		{"server":"unknown","method":"tools/call","tool":"x","session_id":"s1"}
	]`
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/evaluate/batch", strings.NewReader(body)))

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	decisions := resp["decisions"].([]interface{})
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
}

func TestHTTP_EvaluateMethodNotAllowed(t *testing.T) {
	mux := buildTestMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/evaluate", nil))
	if w.Code != 405 {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Servers(t *testing.T) {
	mux := buildTestMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/servers", nil))
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHTTP_AuditVerify(t *testing.T) {
	mux := buildTestMux(t)

	// Make some evaluations to create audit entries
	body := `{"server":"filesystem","method":"tools/call","tool":"read_file","arguments":{"path":"/home/user/f.txt"},"session_id":"s1"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/evaluate", strings.NewReader(body)))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/audit/verify", nil))

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != true {
		t.Error("audit chain should be valid")
	}
}

func TestHTTP_Metrics(t *testing.T) {
	mux := buildTestMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/metrics", nil))
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHTTP_ReloadRequiresToken(t *testing.T) {
	mux := buildTestMuxWithToken(t, "secret-token")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/reload", nil))
	if w.Code != 401 {
		t.Errorf("expected 401 without token, got %d", w.Code)
	}

	req := httptest.NewRequest("POST", "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("expected 200 with valid token, got %d", w.Code)
	}
}

// ---------- token auth ----------

func TestCheckToken_Empty(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if !checkToken(r, "") {
		t.Error("empty token should allow all")
	}
}

func TestCheckToken_Valid(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer my-token")
	if !checkToken(r, "my-token") {
		t.Error("valid token should pass")
	}
}

func TestCheckToken_Invalid(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	if checkToken(r, "correct") {
		t.Error("invalid token should fail")
	}
}

// ---------- policy validation ----------

func TestValidatePolicy_Warnings(t *testing.T) {
	policy := &FirewallPolicy{
		DefaultAction: "allow",
	}

	issues := validatePolicy(policy)
	if len(issues) == 0 {
		t.Error("expected warnings for default_action=allow")
	}

	hasAllowWarning := false
	for _, issue := range issues {
		if strings.Contains(issue, "deny-by-default") {
			hasAllowWarning = true
		}
	}
	if !hasAllowWarning {
		t.Error("expected deny-by-default warning")
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "test-policy.yaml")
	os.WriteFile(policyFile, []byte(`
version: 1
default_action: deny
servers:
  - name: test-server
    trust_level: trusted
    allowed_tools:
      - name: test-tool
        action: allow
`), 0o644)

	policy, err := LoadPolicy(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DefaultAction != "deny" {
		t.Errorf("expected deny, got %s", policy.DefaultAction)
	}
	if len(policy.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(policy.Servers))
	}
}

// ---------- integration test ----------

func TestIntegration_FullWorkflow(t *testing.T) {
	engine := NewPolicyEngine(testPolicy())
	ts := NewTaintState()
	al, _ := NewAuditLog("", nil, 100)

	// 1. List tools (should always work for known servers)
	d := engine.Evaluate(EvalRequest{
		Server: "filesystem", Method: "tools/list", SessionID: "s1",
	}, ts)
	al.Record("evaluate", &d, nil, "")
	if d.Action != "allow" {
		t.Errorf("tools/list should be allowed, got %s", d.Action)
	}

	// 2. Read a file (allowed)
	d = engine.Evaluate(EvalRequest{
		Server: "filesystem", Method: "tools/call", Tool: "read_file",
		Arguments: map[string]string{"path": "/home/user/readme.md"}, SessionID: "s1",
	}, ts)
	al.Record("evaluate", &d, nil, "")
	if d.Action != "allow" {
		t.Errorf("read_file should be allowed, got %s", d.Action)
	}

	// 3. Web search taints the session
	d = engine.Evaluate(EvalRequest{
		Server: "web-search", Method: "tools/call", Tool: "search",
		Arguments: map[string]string{"query": "test"}, SessionID: "s1",
	}, ts)
	al.Record("evaluate", &d, nil, "")
	if !ts.HasTaint("s1", "external-data") {
		t.Error("session should have external-data taint")
	}

	// 4. Write file now blocked by taint
	d = engine.Evaluate(EvalRequest{
		Server: "filesystem", Method: "tools/call", Tool: "write_file",
		Arguments: map[string]string{"path": "/home/user/out.txt", "content": "data"}, SessionID: "s1",
	}, ts)
	al.Record("evaluate", &d, nil, "")
	if d.Action != "deny" {
		t.Errorf("write should be denied due to taint, got %s", d.Action)
	}

	// 5. Verify audit chain
	entries := al.Entries(0)
	valid, _ := VerifyChain(entries)
	if !valid {
		t.Error("audit chain should be valid")
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 audit entries, got %d", len(entries))
	}
}

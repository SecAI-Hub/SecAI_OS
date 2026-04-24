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

func setupTestPolicy() {
	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default: "deny",
			Allow: []ToolEntry{
				{
					Name:           "filesystem.read",
					PathsAllowlist: []string{"/vault/user_docs/**"},
					PathsDenylist:  []string{"/etc/shadow"},
					MaxArgLength:   4096,
				},
			},
			Deny: []ToolEntry{
				{Name: "shell.exec"},
			},
		},
	}
	policyMu.Unlock()
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDenyUnlisted(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{Tool: "unknown.tool", Params: map[string]string{}})
	if resp.Allowed {
		t.Fatal("expected deny for unlisted tool")
	}
	if resp.Reason != "tool not in allowlist" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestDenyExplicit(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{Tool: "shell.exec", Params: map[string]string{}})
	if resp.Allowed {
		t.Fatal("expected deny for explicitly denied tool")
	}
	if resp.Reason != "tool is explicitly denied" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestAllowListedTool(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/vault/user_docs/readme.txt"},
	})
	if !resp.Allowed {
		t.Fatalf("expected allow, got deny: %s", resp.Reason)
	}
}

func TestDenyPathOutsideAllowlist(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/etc/passwd"},
	})
	if resp.Allowed {
		t.Fatal("expected deny for path outside allowlist")
	}
}

func TestDenyPathTraversal(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/vault/user_docs/../../etc/shadow"},
	})
	if resp.Allowed {
		t.Fatal("expected deny for path traversal")
	}
}

func TestDenyNullBytePath(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/vault/user_docs/file\x00.txt"},
	})
	if resp.Allowed {
		t.Fatal("expected deny for null byte in path")
	}
}

func TestArgLengthLimit(t *testing.T) {
	setupTestPolicy()
	longArg := strings.Repeat("a", 5000)
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": longArg},
	})
	if resp.Allowed {
		t.Fatal("expected deny for oversized argument")
	}
}

func TestEvaluateEndpointMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/evaluate", nil)
	w := httptest.NewRecorder()
	handleEvaluate(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestEvaluateEndpointPost(t *testing.T) {
	setupTestPolicy()
	body := `{"tool":"filesystem.read","params":{"path":"/vault/user_docs/test.txt"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleEvaluate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp ToolCallResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Reason)
	}
}

func TestEvaluateEndpointAcceptsLegacyArgsAlias(t *testing.T) {
	setupTestPolicy()
	body := `{"tool":"filesystem.read","args":{"path":"/vault/user_docs/test.txt"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleEvaluate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp ToolCallResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Reason)
	}
}

func TestEvaluateEndpointRejectsOversizedBody(t *testing.T) {
	setupTestPolicy()
	oversized := `{"tool":"filesystem.read","params":{"prompt":"` + strings.Repeat("x", maxRequestBodySize) + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewBufferString(oversized))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestDenyPrefixLookalikePath(t *testing.T) {
	setupTestPolicy()
	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": "/vault/user_docs_evil/readme.txt"},
	})
	if resp.Allowed {
		t.Fatal("expected deny for prefix lookalike path")
	}
}

func TestDenySymlinkEscape(t *testing.T) {
	tmp := t.TempDir()
	allowedDir := filepath.Join(tmp, "vault", "user_docs")
	if err := os.MkdirAll(allowedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(allowedDir, "linked-secret.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	policyMu.Lock()
	policy = Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default: "deny",
			Allow: []ToolEntry{
				{
					Name:           "filesystem.read",
					PathsAllowlist: []string{allowedDir + "/**"},
				},
			},
		},
	}
	policyMu.Unlock()

	resp := evaluateTool(ToolCallRequest{
		Tool:   "filesystem.read",
		Params: map[string]string{"path": link},
	})
	if resp.Allowed {
		t.Fatal("expected deny for symlink escape outside allowlist")
	}
}

func TestSanitizeAuditParamsRedactsSensitivePayloads(t *testing.T) {
	pol := Policy{}
	params := map[string]string{
		"path":   "/vault/user_docs/report.txt",
		"prompt": "Summarize the attached tax return and bank statement",
		"body":   strings.Repeat("x", 64),
	}

	got := sanitizeAuditParams(params, pol)
	if got["path"] != params["path"] {
		t.Fatalf("expected path to remain readable, got %q", got["path"])
	}
	if !strings.HasPrefix(got["prompt"], "[redacted len=") {
		t.Fatalf("expected prompt to be redacted, got %q", got["prompt"])
	}
	if !strings.HasPrefix(got["body"], "[redacted len=") {
		t.Fatalf("expected body to be redacted, got %q", got["body"])
	}
}

func TestSanitizeAuditParamsAllowsRawWhenConfigured(t *testing.T) {
	pol := Policy{}
	pol.Defaults.Logging.StoreRawPrompts = true

	params := map[string]string{
		"prompt": "safe short prompt",
	}

	got := sanitizeAuditParams(params, pol)
	if got["prompt"] != params["prompt"] {
		t.Fatalf("expected prompt to remain raw, got %q", got["prompt"])
	}
}

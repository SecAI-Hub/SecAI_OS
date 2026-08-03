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
	"time"
)

func TestSanitizeAuditParamsRecursivelyRedactsCredentialAliases(t *testing.T) {
	pol := Policy{}
	pol.Defaults.Logging.StoreRawPrompts = true
	pol.Defaults.Logging.StoreRawResponses = true
	got := sanitizeAuditParams(map[string]any{
		"outer": map[string]any{
			"privateKey": "never-record-this",
			"safe":       "visible",
			"nested": []any{map[string]any{
				"api-token": "also-secret",
			}},
		},
	}, pol)

	outer, ok := got["outer"].(map[string]any)
	if !ok {
		t.Fatalf("nested object was not retained: %#v", got)
	}
	if outer["privateKey"] != "[redacted credential]" {
		t.Fatalf("credential alias was not redacted: %#v", outer)
	}
	if outer["safe"] != "visible" {
		t.Fatalf("safe nested value changed: %#v", outer)
	}
	nested, ok := outer["nested"].([]any)
	if !ok || len(nested) != 1 {
		t.Fatalf("nested array changed: %#v", outer["nested"])
	}
	nestedMap, ok := nested[0].(map[string]any)
	if !ok || nestedMap["api-token"] != "[redacted credential]" {
		t.Fatalf("nested credential was not redacted: %#v", nested)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "never-record-this") ||
		strings.Contains(string(encoded), "also-secret") || strings.Contains(string(encoded), "sha256") {
		t.Fatalf("audit output retained credential verifier material: %s", encoded)
	}
}

func TestTypedRuleCanForceAuditRedaction(t *testing.T) {
	pol := Policy{Tools: ToolsPolicy{Allow: []ToolEntry{{
		Name: "filesystem.write",
		ArgRules: []ToolArgRule{
			{Name: "path", Type: "string"},
			{Name: "content", Type: "string", Redact: true},
		},
	}}}}
	pol.Defaults.Logging.StoreRawPrompts = true
	got := sanitizeToolAuditParams(map[string]any{
		"path":    "/vault/outputs/report.txt",
		"content": "confidential report",
	}, pol, "filesystem.write")
	if got["path"] != "/vault/outputs/report.txt" || got["content"] != "[redacted credential]" {
		t.Fatalf("typed audit redaction was not enforced: %#v", got)
	}
}

func TestArgsBlocklistInspectsRawNestedValuesAndKeys(t *testing.T) {
	entry := ToolEntry{ArgsBlacklist: []string{"&&", "<script>", ">"}}
	cases := []any{
		"printf safe && id",
		"<script>run()</script>",
		map[string]any{"items": []any{"safe", "nested && command"}},
		map[string]any{"<script>": "value"},
	}
	for _, value := range cases {
		req := ToolCallRequest{TypedParams: map[string]any{"note": value}}
		if ok, reason := validateArgs(req, entry); ok || !strings.Contains(reason, "blocked pattern") {
			t.Fatalf("blocklisted nested value was accepted: ok=%t reason=%q value=%#v", ok, reason, value)
		}
	}
	clean := ToolCallRequest{TypedParams: map[string]any{
		"note": map[string]any{"items": []any{"safe", "still safe"}},
	}}
	if ok, reason := validateArgs(clean, entry); !ok {
		t.Fatalf("clean nested value was rejected: %s", reason)
	}
}

func TestTypedArgumentsRejectWrongTypesAndDangerousUndeclaredFields(t *testing.T) {
	entry := ToolEntry{ArgRules: []ToolArgRule{{Name: "count", Type: "integer", Required: true}}}
	if ok, reason := validateArgs(ToolCallRequest{
		TypedParams: map[string]any{"count": json.Number("2")},
	}, entry); !ok {
		t.Fatalf("valid typed argument denied: %s", reason)
	}
	if ok, _ := validateArgs(ToolCallRequest{
		TypedParams: map[string]any{"count": "2"},
	}, entry); ok {
		t.Fatal("string bypassed integer argument rule")
	}
	for _, name := range []string{"command", "shell-command", "privateKey", "request-url"} {
		if ok, _ := validateArgs(ToolCallRequest{
			TypedParams: map[string]any{name: "unsafe"},
		}, ToolEntry{}); ok {
			t.Fatalf("undeclared dangerous argument %q was accepted", name)
		}
	}
	if ok, _ := validateArgs(ToolCallRequest{
		TypedParams: map[string]any{"label": "unexpected"},
	}, ToolEntry{ArgRules: []ToolArgRule{}}); ok {
		t.Fatal("explicitly empty typed contract accepted an argument")
	}
}

func TestArgumentTreeLimitsFailClosed(t *testing.T) {
	value := any("leaf")
	for i := 0; i < maxArgumentDepth+2; i++ {
		value = map[string]any{"nested": value}
	}
	req := ToolCallRequest{Tool: "filesystem.read", TypedParams: map[string]any{"metadata": value}}
	if ok, _ := validateToolCall(req); ok {
		t.Fatal("excessively deep argument tree was accepted")
	}
}

func TestValidatePolicyRejectsUnsafeDefaultsAndMalformedArgRules(t *testing.T) {
	valid := Policy{
		Version: 1,
		Tools: ToolsPolicy{
			Default: "deny",
			Allow: []ToolEntry{{
				Name: "test",
				ArgRules: []ToolArgRule{{
					Name: "value", Type: "string", MaxLength: 32, Pattern: "^[a-z]+$",
				}},
			}},
		},
	}
	if err := validatePolicy(valid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	invalid := []Policy{
		{Version: 1, Tools: ToolsPolicy{Default: "allow"}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", RateLimit: RateConfig{RequestsPerMinute: -1}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", RateLimit: RateConfig{BurstSize: 1_000_001}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "x", Type: "string"}, {Name: "x", Type: "string"}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "", Type: "string"}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "x", Type: "bytes"}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "x", Type: "integer", Pattern: "[0-9]+"}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "x", Type: "string", Pattern: "["}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "x", Type: "string", MaxLength: maxRequestBodySize + 1}},
		}}}},
		{Version: 1, Tools: ToolsPolicy{Default: "deny", Allow: []ToolEntry{{
			Name: "test", ArgRules: []ToolArgRule{{Name: "path", Type: "object"}},
		}}}},
	}
	for i, pol := range invalid {
		if err := validatePolicy(pol); err == nil {
			t.Fatalf("invalid policy case %d was accepted", i)
		}
	}
}

func TestLoadPolicyRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	original := getPolicy()
	t.Cleanup(func() {
		policyMu.Lock()
		policy = original
		policyMu.Unlock()
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	t.Setenv("POLICY_PATH", path)
	cases := []string{
		"version: 1\ntools:\n  default: deny\nunknown: true\n",
		"version: 1\ntools:\n  default: deny\n  allow:\n    - name: test\n      max_arg_lenght: 10\n",
		"version: 1\ntools:\n  default: deny\n---\nversion: 1\ntools:\n  default: deny\n",
	}
	for _, content := range cases {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := loadPolicy(); err == nil {
			t.Fatalf("malformed policy was accepted: %q", content)
		}
	}
	validSharedPolicy := "version: 1\nmodels:\n  allowed_formats: [gguf]\ntools:\n  default: deny\n"
	if err := os.WriteFile(path, []byte(validSharedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadPolicy(); err != nil {
		t.Fatalf("recognized shared-policy section was rejected: %v", err)
	}
}

func TestShippedPolicyLoadsUnderStrictParser(t *testing.T) {
	path := filepath.Join("..", "..", "files", "system", "etc", "secure-ai", "policy", "policy.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("shipped appliance policy is not present in the standalone service tree")
	} else if err != nil {
		t.Fatal(err)
	}
	original := getPolicy()
	t.Cleanup(func() {
		policyMu.Lock()
		policy = original
		policyMu.Unlock()
	})
	t.Setenv("POLICY_PATH", path)
	if err := loadPolicy(); err != nil {
		t.Fatalf("shipped policy failed strict parsing: %v", err)
	}
}

func TestRateLimiterHonorsBurstSize(t *testing.T) {
	rateMu.Lock()
	oldTokens, oldLast, oldRPM, oldBurst := rateTokens, rateLast, rateRPM, rateBurst
	rateTokens, rateLast, rateRPM, rateBurst = 0, time.Time{}, 0, 0
	rateMu.Unlock()
	t.Cleanup(func() {
		rateMu.Lock()
		rateTokens, rateLast, rateRPM, rateBurst = oldTokens, oldLast, oldRPM, oldBurst
		rateMu.Unlock()
	})
	pol := Policy{Tools: ToolsPolicy{RateLimit: RateConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
	}}}
	if !checkRateLimit(pol) || !checkRateLimit(pol) {
		t.Fatal("configured burst was not available")
	}
	if checkRateLimit(pol) {
		t.Fatal("request exceeded the configured burst")
	}
}

func TestFilesystemWriteAllowsOutputAndDeniesTraversal(t *testing.T) {
	original := getPolicy()
	t.Cleanup(func() {
		policyMu.Lock()
		policy = original
		policyMu.Unlock()
	})
	policyMu.Lock()
	policy = Policy{Version: 1, Tools: ToolsPolicy{
		Default: "deny",
		RateLimit: RateConfig{
			RequestsPerMinute: 10_000,
			BurstSize:         10_000,
		},
		Allow: []ToolEntry{{
			Name: "filesystem.write",
			ArgRules: []ToolArgRule{
				{Name: "path", Type: "string", Required: true, MaxLength: 4096},
				{Name: "content", Type: "string", Required: true, MaxLength: 4096, Redact: true},
			},
			PathsAllowlist: []string{"/vault/outputs/**"},
			ArgsBlacklist:  []string{"../", "/etc/", "/usr/"},
			MaxArgLength:   4096,
		}},
	}}
	policyMu.Unlock()
	allowed := evaluateTool(ToolCallRequest{
		Tool: "filesystem.write",
		TypedParams: map[string]any{
			"path":    "/vault/outputs/report.txt",
			"content": "safe report",
		},
	})
	if !allowed.Allowed {
		t.Fatalf("valid output write was denied: %s", allowed.Reason)
	}
	traversal := evaluateTool(ToolCallRequest{
		Tool: "filesystem.write",
		TypedParams: map[string]any{
			"path":    "/vault/outputs/../private/report.txt",
			"content": "unsafe target",
		},
	})
	if traversal.Allowed {
		t.Fatal("output traversal escaped the allowlist")
	}
}

func TestEvaluateRequestRejectsTrailingUnknownAndConflictingFields(t *testing.T) {
	setupTestPolicy()
	cases := []string{
		`{"tool":"filesystem.read","params":{"path":"/vault/user_docs/test.txt"}} {}`,
		`{"tool":"filesystem.read","params":{"path":"/vault/user_docs/test.txt"},"bypass":true}`,
		`{"tool":"filesystem.read","params":{"path":"/vault/user_docs/test.txt"},"args":{}}`,
	}
	for _, body := range cases {
		w := httptest.NewRecorder()
		handleEvaluate(w, httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d for %s", w.Code, body)
		}
	}
}

func TestAllowedDecisionFailsClosedWhenAuditUnavailable(t *testing.T) {
	setupTestPolicy()
	auditMu.Lock()
	previous := auditFile
	auditFile = nil
	auditMu.Unlock()
	t.Cleanup(func() {
		auditMu.Lock()
		auditFile = previous
		auditMu.Unlock()
	})

	allowed := httptest.NewRecorder()
	handleEvaluate(allowed, httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(
		`{"tool":"filesystem.read","params":{"path":"/vault/user_docs/test.txt"}}`,
	)))
	if allowed.Code != http.StatusServiceUnavailable {
		t.Fatalf("allowed decision did not fail closed without audit: %d", allowed.Code)
	}

	denied := httptest.NewRecorder()
	handleEvaluate(denied, httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(
		`{"tool":"unknown.tool","params":{}}`,
	)))
	if denied.Code != http.StatusOK {
		t.Fatalf("denied decision changed status after audit failure: %d", denied.Code)
	}
	var response ToolCallResponse
	if err := json.Unmarshal(denied.Body.Bytes(), &response); err != nil || response.Allowed {
		t.Fatalf("denied response was not preserved: err=%v response=%#v", err, response)
	}
}

func TestBoundedRegularFileRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(path, 4); err == nil {
		t.Fatal("oversized credential file was accepted")
	}
	link := filepath.Join(dir, "credential-link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readRegularFile(link, maxTokenSize); err == nil {
		t.Fatal("symlink credential file was accepted")
	}
}

func TestPolicyAndCredentialFileTrustRequirements(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(policyPath, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(policyPath, maxPolicySize); err == nil {
		t.Fatal("group-writable policy was accepted")
	}
	if err := os.Chmod(policyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(policyPath, maxPolicySize); err != nil {
		t.Fatalf("trusted read-only policy was rejected: %v", err)
	}

	tokenPath := filepath.Join(dir, "service.token")
	validToken := strings.Repeat("a", minTokenSize)
	if err := os.WriteFile(tokenPath, []byte(validToken), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(tokenPath, maxTokenSize); err == nil {
		t.Fatal("group-readable credential was accepted")
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(tokenPath, maxTokenSize); err != nil {
		t.Fatalf("owner-only credential was rejected: %v", err)
	}

	if os.Geteuid() == 0 {
		if err := os.Chown(policyPath, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := readRegularFile(policyPath, maxPolicySize); err == nil {
			t.Fatal("policy owned by an untrusted account was accepted")
		}
	}
}

func TestServiceTokenUsesBoundedOwnerOnlyDigestAuthentication(t *testing.T) {
	oldDigest, oldLoaded := serviceTokenDigest, serviceTokenLoaded
	t.Cleanup(func() {
		serviceTokenDigest, serviceTokenLoaded = oldDigest, oldLoaded
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "service.token")
	t.Setenv("SERVICE_TOKEN_PATH", path)

	if err := os.WriteFile(path, []byte(strings.Repeat("a", minTokenSize-1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err == nil {
		t.Fatal("undersized token was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("a", maxTokenSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err == nil {
		t.Fatal("oversized token was accepted")
	}

	token := strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	if serviceTokenDigest != sha256.Sum256([]byte(token)) || !serviceTokenLoaded {
		t.Fatal("service token was not stored as a fixed-length digest")
	}
	handler := requireServiceToken(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	validRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	validRequest.Header.Set("Authorization", "Bearer "+token)
	validResponse := httptest.NewRecorder()
	handler(validResponse, validRequest)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid digest authentication failed: %d", validResponse.Code)
	}
	invalidRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	invalidRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 64))
	invalidResponse := httptest.NewRecorder()
	handler(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusForbidden {
		t.Fatalf("invalid digest authentication was accepted: %d", invalidResponse.Code)
	}
}

func TestAuditFileEnforcesTypeIdentityPermissionsAndSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o646); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditLog(path); err == nil {
		t.Fatal("world-accessible audit file was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit-link.jsonl")
	if err := os.Link(path, link); err == nil {
		if _, openErr := openAuditLog(path); openErr == nil {
			t.Fatal("hard-linked audit file was accepted")
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}

	f, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := auditFile
	auditFile = f
	t.Cleanup(func() {
		auditFile = previous
		_ = f.Close()
	})
	if err := f.Truncate(maxAuditSize); err != nil {
		t.Fatal(err)
	}
	if err := writeAudit(AuditEntry{Tool: "test", Allowed: false}); err == nil {
		t.Fatal("audit append exceeded the size cap")
	}
}

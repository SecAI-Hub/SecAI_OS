package main

import (
	"crypto/sha256"
	"encoding/hex"
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

func writeTempMonitorPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "integrity-monitor.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func createTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func resetGlobalState(t *testing.T) {
	t.Helper()
	stateMu.Lock()
	currentState = StateTrusted
	activeViolations = nil
	lastScanAt = ""
	stateMu.Unlock()
	baselineMu.Lock()
	baseline = SignedBaseline{}
	baselineMu.Unlock()
	serviceToken = ""
	hmacKey = nil
	scanCount.Store(0)
	degradedCount.Store(0)
	recoveryCount.Store(0)
	auditFile = nil
}

func setupTestEnvironment(t *testing.T) (binDir string, polDir string) {
	t.Helper()
	binDir = t.TempDir()
	polDir = t.TempDir()

	createTempFile(t, binDir, "registry", "registry-binary-v1")
	createTempFile(t, binDir, "tool-firewall", "firewall-binary-v1")
	createTempFile(t, polDir, "policy.yaml", "tools:\n  default: deny\n")
	createTempFile(t, polDir, "agent.yaml", "agent:\n  default_mode: standard\n")

	policyYAML := `
version: 1
scan_interval: "1s"
service_binaries:
  - ` + filepath.Join(binDir, "registry") + `
  - ` + filepath.Join(binDir, "tool-firewall") + `
policy_files:
  - ` + filepath.Join(polDir, "policy.yaml") + `
  - ` + filepath.Join(polDir, "agent.yaml") + `
model_dirs: []
systemd_units: []
trust_material: []
degradation_threshold: 3
`
	path := writeTempMonitorPolicy(t, policyYAML)
	t.Setenv("MONITOR_POLICY_PATH", path)
	if err := loadMonitorPolicy(); err != nil {
		t.Fatalf("loadMonitorPolicy: %v", err)
	}

	return binDir, polDir
}

// =========================================================================
// Policy loading tests
// =========================================================================

func TestLoadPolicy_Defaults(t *testing.T) {
	resetGlobalState(t)
	t.Setenv("MONITOR_POLICY_PATH", "/nonexistent/monitor-policy.yaml")
	if err := loadMonitorPolicy(); err != nil {
		t.Fatalf("loadMonitorPolicy: %v", err)
	}
	pol := getMonitorPolicy()
	if pol.Version != 1 {
		t.Errorf("expected version 1, got %d", pol.Version)
	}
	if len(pol.ServiceBinaries) == 0 {
		t.Error("defaults should have service binaries")
	}
	if pol.ScanInterval != "30s" {
		t.Errorf("expected default interval 30s, got %s", pol.ScanInterval)
	}
	if pol.DegradationThreshold != 3 {
		t.Errorf("expected threshold 3, got %d", pol.DegradationThreshold)
	}
}

func TestLoadPolicy_FromFile(t *testing.T) {
	resetGlobalState(t)
	policy := `
version: 2
scan_interval: "10s"
service_binaries:
  - /usr/bin/test1
  - /usr/bin/test2
policy_files:
  - /etc/test/policy.yaml
degradation_threshold: 5
`
	path := writeTempMonitorPolicy(t, policy)
	t.Setenv("MONITOR_POLICY_PATH", path)
	if err := loadMonitorPolicy(); err != nil {
		t.Fatalf("loadMonitorPolicy: %v", err)
	}
	pol := getMonitorPolicy()
	if pol.Version != 2 {
		t.Errorf("expected version 2, got %d", pol.Version)
	}
	if len(pol.ServiceBinaries) != 2 {
		t.Errorf("expected 2 binaries, got %d", len(pol.ServiceBinaries))
	}
	if pol.ScanInterval != "10s" {
		t.Errorf("expected 10s, got %s", pol.ScanInterval)
	}
	if pol.DegradationThreshold != 5 {
		t.Errorf("expected threshold 5, got %d", pol.DegradationThreshold)
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	resetGlobalState(t)
	path := writeTempMonitorPolicy(t, "not: [valid: yaml: {{")
	t.Setenv("MONITOR_POLICY_PATH", path)
	err := loadMonitorPolicy()
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadPolicy_DefaultsForMissing(t *testing.T) {
	resetGlobalState(t)
	policy := `
version: 1
service_binaries: []
`
	path := writeTempMonitorPolicy(t, policy)
	t.Setenv("MONITOR_POLICY_PATH", path)
	if err := loadMonitorPolicy(); err != nil {
		t.Fatalf("loadMonitorPolicy: %v", err)
	}
	pol := getMonitorPolicy()
	// scan_interval should default to 30s
	if pol.ScanInterval != "30s" {
		t.Errorf("expected default 30s, got %s", pol.ScanInterval)
	}
	// threshold should default to 3
	if pol.DegradationThreshold != 3 {
		t.Errorf("expected threshold 3, got %d", pol.DegradationThreshold)
	}
}

// =========================================================================
// File hashing tests
// =========================================================================

func TestHashFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := createTempFile(t, dir, "test.bin", "test-content")
	hash, size, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if size != 12 {
		t.Errorf("expected size 12, got %d", size)
	}
	// Verify hash
	expected := sha256.Sum256([]byte("test-content"))
	if hash != hex.EncodeToString(expected[:]) {
		t.Error("hash mismatch")
	}
}

func TestHashFile_Missing(t *testing.T) {
	_, _, err := hashFile("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path := createTempFile(t, dir, "test.bin", "same-content")
	h1, _, _ := hashFile(path)
	h2, _, _ := hashFile(path)
	if h1 != h2 {
		t.Error("same file should produce same hash")
	}
}

// =========================================================================
// Baseline tests
// =========================================================================

func TestComputeBaseline_WithFiles(t *testing.T) {
	resetGlobalState(t)
	binDir, _ := setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	if len(bl.Entries) < 2 {
		t.Errorf("expected at least 2 entries (binaries), got %d", len(bl.Entries))
	}
	if bl.CreatedAt == "" {
		t.Error("baseline should have created_at")
	}

	// Check that entries include the binaries
	found := false
	for _, e := range bl.Entries {
		if e.Path == filepath.Join(binDir, "registry") {
			found = true
			if e.Category != CatServiceBinary {
				t.Errorf("expected category service_binary, got %s", e.Category)
			}
		}
	}
	if !found {
		t.Error("baseline should include registry binary")
	}
}

func TestComputeBaseline_Sorted(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	for i := 1; i < len(bl.Entries); i++ {
		if bl.Entries[i].Path < bl.Entries[i-1].Path {
			t.Error("baseline entries should be sorted by path")
		}
	}
}

func TestComputeBaseline_HMAC_NoKey(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)
	hmacKey = nil

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	if bl.HMAC != "unsigned" {
		t.Errorf("expected 'unsigned' without key, got %s", bl.HMAC)
	}
}

func TestComputeBaseline_HMAC_WithKey(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)
	hmacKey = []byte("test-hmac-key")

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	if bl.HMAC == "unsigned" {
		t.Error("should be signed with key")
	}
	if len(bl.HMAC) != 64 {
		t.Errorf("HMAC should be 64 hex chars, got %d", len(bl.HMAC))
	}
}

func TestVerifyBaselineHMAC_Valid(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)
	hmacKey = []byte("verify-key")

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	if !verifyBaselineHMAC(bl) {
		t.Error("valid baseline HMAC should verify")
	}
}

func TestVerifyBaselineHMAC_Tampered(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)
	hmacKey = []byte("verify-key")

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)

	// Tamper with baseline
	bl.CreatedAt = "tampered"
	if verifyBaselineHMAC(bl) {
		t.Error("tampered baseline should not verify")
	}
}

func TestVerifyBaselineHMAC_UnsignedNoKey(t *testing.T) {
	resetGlobalState(t)
	hmacKey = nil
	bl := SignedBaseline{HMAC: "unsigned"}
	if !verifyBaselineHMAC(bl) {
		t.Error("unsigned baseline should verify when no key configured")
	}
}

// =========================================================================
// Scan tests
// =========================================================================

func TestPerformScan_NoViolations(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	state, violations := performScan()
	if state != StateTrusted {
		t.Errorf("expected trusted, got %s", state)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestPerformScan_ModifiedFile(t *testing.T) {
	resetGlobalState(t)
	binDir, _ := setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Modify a binary
	regPath := filepath.Join(binDir, "registry")
	os.WriteFile(regPath, []byte("TAMPERED-binary"), 0755)

	state, violations := performScan()
	if state != StateDegraded {
		t.Errorf("expected degraded after modification, got %s", state)
	}
	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Category != CatServiceBinary {
		t.Errorf("expected service_binary category, got %s", violations[0].Category)
	}
	if violations[0].ActualHash == violations[0].ExpectedHash {
		t.Error("actual and expected hash should differ")
	}
}

func TestPerformScan_DeletedFile(t *testing.T) {
	resetGlobalState(t)
	binDir, _ := setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Delete a binary
	os.Remove(filepath.Join(binDir, "registry"))

	state, violations := performScan()
	if state != StateDegraded {
		t.Errorf("expected degraded after deletion, got %s", state)
	}
	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].ActualHash != "missing" {
		t.Errorf("expected 'missing' actual hash, got %s", violations[0].ActualHash)
	}
}

func TestPerformScan_ManyViolations_RecoveryRequired(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	polDir := t.TempDir()

	// Create 4 files (more than threshold of 3)
	bin1 := createTempFile(t, dir, "svc1", "content-1")
	bin2 := createTempFile(t, dir, "svc2", "content-2")
	bin3 := createTempFile(t, dir, "svc3", "content-3")
	pol1 := createTempFile(t, polDir, "p1.yaml", "policy: 1")

	policyYAML := `
version: 1
scan_interval: "1s"
service_binaries:
  - ` + bin1 + `
  - ` + bin2 + `
  - ` + bin3 + `
policy_files:
  - ` + pol1 + `
degradation_threshold: 3
`
	path := writeTempMonitorPolicy(t, policyYAML)
	t.Setenv("MONITOR_POLICY_PATH", path)
	loadMonitorPolicy()

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Tamper all 4 files
	os.WriteFile(bin1, []byte("TAMPERED-1"), 0755)
	os.WriteFile(bin2, []byte("TAMPERED-2"), 0755)
	os.WriteFile(bin3, []byte("TAMPERED-3"), 0755)

	state, violations := performScan()
	if state != StateRecoveryRequired {
		t.Errorf("expected recovery_required with 3+ violations, got %s", state)
	}
	if len(violations) < 3 {
		t.Errorf("expected at least 3 violations, got %d", len(violations))
	}
}

func TestPerformScan_CountsIncremented(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	before := scanCount.Load()
	performScan()
	after := scanCount.Load()
	if after != before+1 {
		t.Errorf("scan count should increment: %d -> %d", before, after)
	}
}

func TestPerformScan_UnchangedFilesTrusted(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Scan multiple times — should stay trusted
	for i := 0; i < 3; i++ {
		state, _ := performScan()
		if state != StateTrusted {
			t.Errorf("scan %d: expected trusted, got %s", i, state)
		}
	}
}

// =========================================================================
// Action determination tests
// =========================================================================

func TestActionForCategory(t *testing.T) {
	tests := []struct {
		cat    WatchCategory
		action string
	}{
		{CatServiceBinary, "degrade_appliance"},
		{CatPolicyFile, "reload_policy"},
		{CatModelFile, "quarantine_model"},
		{CatSystemdUnit, "degrade_appliance"},
		{CatTrustMaterial, "degrade_appliance"},
		{"unknown", "log_alert"},
	}
	for _, tt := range tests {
		got := actionForCategory(tt.cat)
		if got != tt.action {
			t.Errorf("actionForCategory(%s) = %s, want %s", tt.cat, got, tt.action)
		}
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
	if body["state"] != "trusted" {
		t.Errorf("initial state should be trusted, got %v", body["state"])
	}
}

func TestHTTP_Status(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)
	performScan()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handleStatus(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status returned %d", w.Code)
	}
	var status StatusResponse
	json.Unmarshal(w.Body.Bytes(), &status)
	if status.State != StateTrusted {
		t.Errorf("expected trusted state, got %s", status.State)
	}
	if status.WatchedFiles == 0 {
		t.Error("should have watched files")
	}
	if status.ScanCount == 0 {
		t.Error("should have scan count > 0")
	}
}

func TestHTTP_Baseline(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/baseline", nil)
	w := httptest.NewRecorder()
	handleBaseline(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("baseline returned %d", w.Code)
	}
	var result SignedBaseline
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Entries) == 0 {
		t.Error("baseline should have entries")
	}
}

func TestHTTP_Baseline_MethodNotAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/baseline", nil)
	w := httptest.NewRecorder()
	handleBaseline(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Scan_PostOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Scan_Post(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("scan returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["state"] != "trusted" {
		t.Errorf("expected trusted state, got %v", body["state"])
	}
}

func TestHTTP_Rebaseline(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/rebaseline", nil)
	w := httptest.NewRecorder()
	handleRebaseline(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("rebaseline returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "rebaselined" {
		t.Errorf("expected 'rebaselined', got %v", body["status"])
	}

	// After rebaseline, state should be trusted
	stateMu.RLock()
	state := currentState
	stateMu.RUnlock()
	if state != StateTrusted {
		t.Errorf("state should be trusted after rebaseline, got %s", state)
	}
}

func TestHTTP_Rebaseline_PostOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/rebaseline", nil)
	w := httptest.NewRecorder()
	handleRebaseline(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Reload(t *testing.T) {
	resetGlobalState(t)
	setupTestEnvironment(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("reload returned %d", w.Code)
	}
}

func TestHTTP_Reload_PostOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Verify_Trusted(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when trusted, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["trusted"] != true {
		t.Error("should be trusted")
	}
}

func TestHTTP_Verify_Degraded(t *testing.T) {
	resetGlobalState(t)
	stateMu.Lock()
	currentState = StateDegraded
	stateMu.Unlock()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when degraded, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["trusted"] != false {
		t.Error("should not be trusted when degraded")
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
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without Bearer, got %d", w.Code)
	}
}

func TestToken_InvalidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "correct"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong token, got %d", w.Code)
	}
}

func TestToken_ValidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "valid-token"
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("should call handler with valid token")
	}
}

// =========================================================================
// Audit logging tests
// =========================================================================

func TestAuditLog_WritesViolations(t *testing.T) {
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

	binDir, _ := setupTestEnvironment(t)
	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Tamper a file
	os.WriteFile(filepath.Join(binDir, "registry"), []byte("TAMPERED"), 0755)
	performScan()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log should have violation entries")
	}
}

// =========================================================================
// Model directory watching tests
// =========================================================================

func TestScan_ModelDirectory(t *testing.T) {
	resetGlobalState(t)
	modelDir := t.TempDir()
	createTempFile(t, modelDir, "model-a.gguf", "model-a-content")
	createTempFile(t, modelDir, "model-b.gguf", "model-b-content")

	policyYAML := `
version: 1
scan_interval: "1s"
service_binaries: []
policy_files: []
model_dirs:
  - ` + modelDir + `
degradation_threshold: 3
`
	path := writeTempMonitorPolicy(t, policyYAML)
	t.Setenv("MONITOR_POLICY_PATH", path)
	loadMonitorPolicy()

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	if len(bl.Entries) != 2 {
		t.Errorf("expected 2 model entries, got %d", len(bl.Entries))
	}

	// Tamper one model
	os.WriteFile(filepath.Join(modelDir, "model-a.gguf"), []byte("TAMPERED"), 0644)
	state, violations := performScan()
	if state != StateDegraded {
		t.Errorf("expected degraded after model tamper, got %s", state)
	}
	if len(violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Category != CatModelFile {
		t.Errorf("expected model_file category, got %s", violations[0].Category)
	}
	if violations[0].Action != "quarantine_model" {
		t.Errorf("expected quarantine_model action, got %s", violations[0].Action)
	}
}

// =========================================================================
// Rebaseline after tampering tests
// =========================================================================

func TestRebaseline_ClearsViolations(t *testing.T) {
	resetGlobalState(t)
	binDir, _ := setupTestEnvironment(t)

	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)

	// Tamper and scan → degraded
	os.WriteFile(filepath.Join(binDir, "registry"), []byte("TAMPERED"), 0755)
	state1, _ := performScan()
	if state1 != StateDegraded {
		t.Fatalf("expected degraded, got %s", state1)
	}

	// Rebaseline → trusted
	bl2 := computeBaseline(pol)
	setBaseline(bl2)
	stateMu.Lock()
	currentState = StateTrusted
	activeViolations = nil
	stateMu.Unlock()

	state2, violations2 := performScan()
	if state2 != StateTrusted {
		t.Errorf("expected trusted after rebaseline, got %s", state2)
	}
	if len(violations2) != 0 {
		t.Errorf("expected no violations after rebaseline, got %d", len(violations2))
	}
}

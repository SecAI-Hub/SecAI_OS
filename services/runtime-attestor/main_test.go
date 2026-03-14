package main

import (
	"crypto/hmac"
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

func writeTempAttestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "attestation.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempBinary(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempPolicyFile(t *testing.T, name string, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// resetGlobalState resets the global state for tests.
func resetGlobalState(t *testing.T) {
	t.Helper()
	stateMu.Lock()
	currentState = StatePending
	currentBundle = RuntimeStateBundle{}
	stateMu.Unlock()
	serviceToken = ""
	hmacKey = nil
	attestCount.Store(0)
	degradeCount.Store(0)
	failCount.Store(0)
}

const testAttestPolicyYAML = `
version: 1
require_tpm: false
require_secure_boot: false
expected_pcrs: {}
service_binaries: {}
policy_files: []
refresh_interval: "1m"
hmac_key_path: ""
`

const testAttestPolicyRequireTPM = `
version: 1
require_tpm: true
require_secure_boot: false
expected_pcrs:
  "0": "0x0000000000000000000000000000000000000000000000000000000000000000"
service_binaries: {}
policy_files: []
refresh_interval: "5m"
hmac_key_path: ""
`

const testAttestPolicyRequireSB = `
version: 1
require_tpm: false
require_secure_boot: true
expected_pcrs: {}
service_binaries: {}
policy_files: []
refresh_interval: "5m"
hmac_key_path: ""
`

// =========================================================================
// Policy loading tests
// =========================================================================

func TestLoadAttestPolicy_Defaults(t *testing.T) {
	resetGlobalState(t)
	// Point to a non-existent file → should use defaults
	t.Setenv("ATTESTATION_POLICY_PATH", "/tmp/nonexistent-attestation-policy-12345.yaml")
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if pol.RequireTPM {
		t.Error("default policy should not require TPM")
	}
	if pol.RequireSecureBoot {
		t.Error("default policy should not require Secure Boot")
	}
	if len(pol.ServiceBinaries) == 0 {
		t.Error("default policy should have service binaries")
	}
	if len(pol.PolicyFiles) == 0 {
		t.Error("default policy should have policy files")
	}
}

func TestLoadAttestPolicy_FromFile(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if pol.Version != 1 {
		t.Errorf("expected version 1, got %d", pol.Version)
	}
	if pol.RequireTPM {
		t.Error("should not require TPM")
	}
	if pol.RefreshInterval != "1m" {
		t.Errorf("expected refresh interval 1m, got %s", pol.RefreshInterval)
	}
}

func TestLoadAttestPolicy_RequireTPM(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyRequireTPM)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if !pol.RequireTPM {
		t.Error("should require TPM")
	}
	if len(pol.ExpectedPCRs) == 0 {
		t.Error("should have expected PCRs")
	}
}

func TestLoadAttestPolicy_InvalidYAML(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, "not: [valid: yaml: {{")
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	err := loadAttestPolicy()
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// =========================================================================
// Service digest tests
// =========================================================================

func TestCollectServiceDigests_AllPresent(t *testing.T) {
	resetGlobalState(t)
	bin1 := writeTempBinary(t, "svc1", []byte("binary-content-1"))
	bin2 := writeTempBinary(t, "svc2", []byte("binary-content-2"))

	binaries := map[string]string{
		"svc1": bin1,
		"svc2": bin2,
	}
	digests, failures := collectServiceDigests(binaries)
	if len(failures) != 0 {
		t.Errorf("expected no failures, got %v", failures)
	}
	if len(digests) != 2 {
		t.Errorf("expected 2 digests, got %d", len(digests))
	}
	// Verify digest is a valid hex SHA-256
	for name, d := range digests {
		if d == "missing" {
			t.Errorf("service %s should not be missing", name)
		}
		if len(d) != 64 {
			t.Errorf("digest for %s should be 64 hex chars, got %d", name, len(d))
		}
	}
}

func TestCollectServiceDigests_MissingBinary(t *testing.T) {
	resetGlobalState(t)
	binaries := map[string]string{
		"missing-svc": "/tmp/nonexistent-binary-12345",
	}
	digests, failures := collectServiceDigests(binaries)
	if len(failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(failures))
	}
	if digests["missing-svc"] != "missing" {
		t.Errorf("expected 'missing', got %s", digests["missing-svc"])
	}
}

func TestCollectServiceDigests_DeterministicHash(t *testing.T) {
	resetGlobalState(t)
	bin := writeTempBinary(t, "test-bin", []byte("deterministic-content"))
	binaries := map[string]string{"test": bin}

	d1, _ := collectServiceDigests(binaries)
	d2, _ := collectServiceDigests(binaries)
	if d1["test"] != d2["test"] {
		t.Error("same binary should produce same digest")
	}
}

func TestCollectServiceDigests_DifferentContent(t *testing.T) {
	resetGlobalState(t)
	bin1 := writeTempBinary(t, "a", []byte("content-a"))
	bin2 := writeTempBinary(t, "b", []byte("content-b"))

	d1, _ := collectServiceDigests(map[string]string{"s": bin1})
	d2, _ := collectServiceDigests(map[string]string{"s": bin2})
	if d1["s"] == d2["s"] {
		t.Error("different binaries should produce different digests")
	}
}

// =========================================================================
// Policy digest tests
// =========================================================================

func TestCollectPolicyDigest_ValidFiles(t *testing.T) {
	resetGlobalState(t)
	f1 := writeTempPolicyFile(t, "policy.yaml", "policy: content: 1")
	f2 := writeTempPolicyFile(t, "agent.yaml", "agent: content: 2")

	digest := collectPolicyDigest([]string{f1, f2})
	if digest == "" {
		t.Error("policy digest should not be empty")
	}
	if len(digest) != 64 {
		t.Errorf("policy digest should be 64 hex chars, got %d", len(digest))
	}
}

func TestCollectPolicyDigest_MissingFiles(t *testing.T) {
	resetGlobalState(t)
	digest := collectPolicyDigest([]string{"/nonexistent/a.yaml", "/nonexistent/b.yaml"})
	// Should still return a digest (of empty data)
	if digest == "" {
		t.Error("policy digest should not be empty even with missing files")
	}
}

func TestCollectPolicyDigest_Deterministic(t *testing.T) {
	resetGlobalState(t)
	f := writeTempPolicyFile(t, "policy.yaml", "same-content")
	d1 := collectPolicyDigest([]string{f})
	d2 := collectPolicyDigest([]string{f})
	if d1 != d2 {
		t.Error("same policy file should produce same digest")
	}
}

func TestCollectPolicyDigest_OrderMatters(t *testing.T) {
	resetGlobalState(t)
	f1 := writeTempPolicyFile(t, "a.yaml", "content-a")
	f2 := writeTempPolicyFile(t, "b.yaml", "content-b")

	d1 := collectPolicyDigest([]string{f1, f2})
	d2 := collectPolicyDigest([]string{f2, f1})
	if d1 == d2 {
		t.Error("order of policy files should affect digest")
	}
}

// =========================================================================
// Bundle HMAC tests
// =========================================================================

func TestComputeBundleHMAC_NoKey(t *testing.T) {
	resetGlobalState(t)
	hmacKey = nil
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}
	result := computeBundleHMAC(bundle)
	if result != "unsigned" {
		t.Errorf("expected 'unsigned' without key, got %s", result)
	}
}

func TestComputeBundleHMAC_WithKey(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte("test-secret-key")
	bundle := RuntimeStateBundle{
		Timestamp:            "2026-01-01T00:00:00Z",
		State:                StateAttested,
		DeploymentDigest:     "abc123",
		PolicyDigest:         "def456",
		RegistryManifestHash: "ghi789",
		TPMAvailable:         false,
		TPMQuoteVerified:     false,
	}
	result := computeBundleHMAC(bundle)
	if result == "unsigned" {
		t.Error("should not be unsigned with key")
	}
	if len(result) != 64 {
		t.Errorf("HMAC should be 64 hex chars, got %d", len(result))
	}
	// Verify it's a valid HMAC
	_, err := hex.DecodeString(result)
	if err != nil {
		t.Errorf("HMAC is not valid hex: %v", err)
	}
}

func TestComputeBundleHMAC_Deterministic(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte("test-key")
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}
	h1 := computeBundleHMAC(bundle)
	h2 := computeBundleHMAC(bundle)
	if h1 != h2 {
		t.Error("same input should produce same HMAC")
	}
}

func TestComputeBundleHMAC_DifferentKeys(t *testing.T) {
	resetGlobalState(t)
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}

	hmacKey = []byte("key-1")
	h1 := computeBundleHMAC(bundle)
	hmacKey = []byte("key-2")
	h2 := computeBundleHMAC(bundle)
	if h1 == h2 {
		t.Error("different keys should produce different HMACs")
	}
}

func TestComputeBundleHMAC_VerifyCorrectness(t *testing.T) {
	resetGlobalState(t)
	key := []byte("verification-key")
	hmacKey = key
	bundle := RuntimeStateBundle{
		Timestamp:            "2026-01-01T00:00:00Z",
		State:                StateAttested,
		DeploymentDigest:     "deploy-abc",
		PolicyDigest:         "policy-def",
		RegistryManifestHash: "registry-ghi",
		TPMAvailable:         true,
		TPMQuoteVerified:     false,
	}
	result := computeBundleHMAC(bundle)

	// Independently compute expected HMAC
	data := "2026-01-01T00:00:00Z|attested|deploy-abc|policy-def|registry-ghi|true|false"
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))

	if result != expected {
		t.Errorf("HMAC mismatch: got %s, want %s", result, expected)
	}
}

// =========================================================================
// Attestation state machine tests
// =========================================================================

func TestPerformAttestation_NoRequirements(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	bundle := performAttestation()
	// With no TPM/SB requirements and no service binaries, should be attested
	if bundle.State != StateAttested {
		t.Errorf("expected attested state, got %s (failures: %v)", bundle.State, bundle.Failures)
	}
	if bundle.Timestamp == "" {
		t.Error("bundle should have a timestamp")
	}
}

func TestPerformAttestation_MissingBinary_Degrades(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  nonexistent-svc: /tmp/nonexistent-binary-for-test-12345
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	bundle := performAttestation()
	if bundle.State != StateDegraded {
		t.Errorf("expected degraded state for missing binary, got %s", bundle.State)
	}
	if len(bundle.Failures) == 0 {
		t.Error("should have failures for missing binary")
	}
}

func TestPerformAttestation_ValidBinaries_Attested(t *testing.T) {
	resetGlobalState(t)
	bin := writeTempBinary(t, "test-service", []byte("test-binary-content"))
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  test-service: ` + bin + `
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	bundle := performAttestation()
	if bundle.State != StateAttested {
		t.Errorf("expected attested with valid binary, got %s (failures: %v)", bundle.State, bundle.Failures)
	}
	if bundle.ServiceDigests["test-service"] == "missing" {
		t.Error("service digest should not be 'missing'")
	}
}

func TestPerformAttestation_RequireTPM_FailsInCI(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyRequireTPM)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	bundle := performAttestation()
	// In CI/dev environments, TPM is not available → should fail
	if bundle.State != StateFailed {
		t.Errorf("expected failed state when TPM required but unavailable, got %s", bundle.State)
	}
	if len(bundle.Failures) == 0 {
		t.Error("should have failure messages")
	}
}

func TestPerformAttestation_AttestCountIncremented(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	before := attestCount.Load()
	performAttestation()
	after := attestCount.Load()
	if after != before+1 {
		t.Errorf("attest count should increment: before=%d after=%d", before, after)
	}
}

func TestPerformAttestation_DegradeCountIncremented(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  missing: /tmp/no-such-binary-99999
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}

	before := degradeCount.Load()
	performAttestation()
	after := degradeCount.Load()
	if after <= before {
		t.Errorf("degrade count should increment: before=%d after=%d", before, after)
	}
}

func TestGetCurrentState_Default(t *testing.T) {
	resetGlobalState(t)
	state, bundle := getCurrentState()
	if state != StatePending {
		t.Errorf("initial state should be pending, got %s", state)
	}
	if bundle.Timestamp != "" {
		t.Error("initial bundle should have no timestamp")
	}
}

func TestGetCurrentState_AfterAttestation(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()

	performAttestation()
	state, bundle := getCurrentState()
	if state == StatePending {
		t.Error("state should not be pending after attestation")
	}
	if bundle.Timestamp == "" {
		t.Error("bundle should have a timestamp after attestation")
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
	if body["state"] == nil {
		t.Error("health should include state")
	}
}

func TestHTTP_Attest_Get(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attest returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["state"] == nil {
		t.Error("attest response missing state")
	}
	if body["bundle"] == nil {
		t.Error("attest response missing bundle")
	}
}

func TestHTTP_Attest_Post(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attest POST returned %d", w.Code)
	}
}

func TestHTTP_Attest_MethodNotAllowed(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Verify_Attested(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("verify returned %d when attested", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["verified"] != true {
		t.Error("should be verified when attested")
	}
}

func TestHTTP_Verify_NotAttested(t *testing.T) {
	resetGlobalState(t)
	// State is pending (not attested)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("verify should return 503 when not attested, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["verified"] != false {
		t.Error("should not be verified when pending")
	}
}

func TestHTTP_Verify_Degraded(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  missing: /tmp/no-such-binary-verify-test
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("verify should return 503 when degraded, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["verified"] != false {
		t.Error("should not be verified when degraded")
	}
}

func TestHTTP_Refresh_PostOnly(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handleRefresh(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET refresh, got %d", w.Code)
	}
}

func TestHTTP_Refresh_Post(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handleRefresh(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("refresh returned %d", w.Code)
	}
	var bundle RuntimeStateBundle
	json.Unmarshal(w.Body.Bytes(), &bundle)
	if bundle.Timestamp == "" {
		t.Error("refresh should return bundle with timestamp")
	}
}

func TestHTTP_SecurityStatus(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/security/status", nil)
	w := httptest.NewRecorder()
	handleSecurityStatus(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("security status returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)

	// Check required fields
	requiredFields := []string{
		"attestation_state", "tpm_available", "tpm_quote_verified",
		"secure_boot", "policy_digest", "deployment_digest",
		"service_count", "failure_count", "last_attested",
		"attest_count", "degrade_count", "fail_count",
	}
	for _, field := range requiredFields {
		if _, ok := body[field]; !ok {
			t.Errorf("security status missing field: %s", field)
		}
	}
}

func TestHTTP_SecurityStatus_CountsTracked(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()

	// Run attestation twice
	performAttestation()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/security/status", nil)
	w := httptest.NewRecorder()
	handleSecurityStatus(w, r)

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	count := body["attest_count"].(float64)
	if count < 2 {
		t.Errorf("attest_count should be >= 2, got %v", count)
	}
}

// =========================================================================
// Token auth tests
// =========================================================================

func TestToken_NoTokenConfigured(t *testing.T) {
	resetGlobalState(t)
	serviceToken = ""

	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("handler should pass through when no token configured")
	}
}

func TestToken_RequiresBearer(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "test-token-123"

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without Bearer header, got %d", w.Code)
	}
}

func TestToken_InvalidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "correct-token"

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong token, got %d", w.Code)
	}
}

func TestToken_ValidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "valid-secret-token"

	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r.Header.Set("Authorization", "Bearer valid-secret-token")
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("handler should be called with valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", w.Code)
	}
}

func TestToken_RefreshRequiresToken(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()

	serviceToken = "refresh-secret"
	handler := requireServiceToken(handleRefresh)

	// Without token
	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("refresh without token: expected 403, got %d", w.Code)
	}

	// With valid token
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r2.Header.Set("Authorization", "Bearer refresh-secret")
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("refresh with token: expected 200, got %d", w2.Code)
	}
}

// =========================================================================
// Audit logging tests
// =========================================================================

func TestAuditLog_WritesOnAttestation(t *testing.T) {
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

	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()

	performAttestation()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log should not be empty after attestation")
	}
	// Verify it's valid JSON
	var bundle RuntimeStateBundle
	if err := json.Unmarshal(data[:len(data)-1], &bundle); err != nil {
		t.Errorf("audit log entry is not valid JSON: %v", err)
	}
	if bundle.Timestamp == "" {
		t.Error("audit log entry should have timestamp")
	}
}

// =========================================================================
// Kernel state tests (graceful degradation)
// =========================================================================

func TestCollectKernelState_NoError(t *testing.T) {
	// collectKernelState should not panic even if files don't exist
	cmdline, lockdown := collectKernelState()
	// On macOS CI, /proc/cmdline won't exist
	_ = cmdline
	_ = lockdown
}

// =========================================================================
// Deployment digest tests (graceful degradation)
// =========================================================================

func TestCollectDeploymentDigest_Unavailable(t *testing.T) {
	// rpm-ostree likely not available in CI
	result := collectDeploymentDigest()
	if result != "unavailable" && len(result) == 0 {
		t.Error("deployment digest should be 'unavailable' or a valid hash")
	}
}

// =========================================================================
// Registry manifest tests (graceful degradation)
// =========================================================================

func TestCollectRegistryManifestHash_Unavailable(t *testing.T) {
	result := collectRegistryManifestHash()
	if result != "unavailable" {
		t.Errorf("expected 'unavailable' when manifest missing, got %s", result)
	}
}

// =========================================================================
// Boot measurements tests (graceful degradation)
// =========================================================================

func TestCollectBootMeasurements_NoTPM(t *testing.T) {
	pol := AttestationPolicy{
		RequireTPM:        false,
		RequireSecureBoot: false,
	}
	m, tpmAvail, failures := collectBootMeasurements(pol)
	// In CI, TPM and Secure Boot are not available
	if tpmAvail {
		t.Log("TPM unexpectedly available in test environment")
	}
	if len(failures) != 0 {
		t.Errorf("should have no failures when TPM not required, got %v", failures)
	}
	if m.MeasuredAt == "" {
		t.Error("measured_at timestamp should be set")
	}
}

func TestCollectBootMeasurements_TPMRequired_FailsGracefully(t *testing.T) {
	pol := AttestationPolicy{
		RequireTPM:        true,
		RequireSecureBoot: false,
	}
	_, _, failures := collectBootMeasurements(pol)
	// In CI, TPM is not available → should report failure
	if len(failures) == 0 {
		t.Log("no TPM failure reported — TPM may be available in this environment")
	}
}

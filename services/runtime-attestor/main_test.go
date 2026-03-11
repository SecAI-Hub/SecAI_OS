package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestPolicy() {
	policyMu.Lock()
	policy = AttestationPolicy{
		Version: 1,
		Attestation: AttestConfig{
			Collectors: CollectorToggle{
				Model:     true,
				Container: true,
				Network:   true,
				Mount:     true,
				GPU:       true,
				Policy:    true,
			},
			Model: ModelConfig{
				VaultDir:       "/nonexistent",
				AllowedFormats: []string{"gguf"},
			},
			Network: NetworkConfig{
				AllowedListeners:        []string{"127.0.0.1:8470"},
				DenyUnexpectedListeners: true,
			},
			RateLimit: RateLimitConfig{RequestsPerMinute: 100},
		},
	}
	policyMu.Unlock()
	serviceToken = ""
}

// writeTestFile creates a temp file with given content and returns its path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Health endpoint tests
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["service"] != "runtime-attestor" {
		t.Fatalf("unexpected service: %s", resp["service"])
	}
}

func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	serviceToken = "secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Errorf("health should not require auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Model collector tests
// ---------------------------------------------------------------------------

func TestModelCollector_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	cfg := ModelConfig{
		VaultDir:       dir,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass for empty vault, got %s", result.Status)
	}
}

func TestModelCollector_NoVaultDir(t *testing.T) {
	cfg := ModelConfig{VaultDir: ""}
	result := collectModelState(cfg)
	if result.Status != "skipped" {
		t.Fatalf("expected skipped, got %s", result.Status)
	}
}

func TestModelCollector_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test-model.gguf", "model-data-here")

	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{
					"name":     "test-model",
					"format":   "gguf",
					"filename": "test-model.gguf",
					"sha256":   "0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status == "pass" {
		t.Fatal("expected drift or fail for hash mismatch, got pass")
	}

	found := false
	for _, f := range result.Findings {
		if f.Key == "test-model.gguf" && (f.Status == "fail" || f.Status == "drift") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for test-model.gguf hash mismatch")
	}
}

func TestModelCollector_HashMatch(t *testing.T) {
	dir := t.TempDir()
	content := "trusted-model-content"
	writeTestFile(t, dir, "good-model.gguf", content)

	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{
					"name":     "good-model",
					"format":   "gguf",
					"filename": "good-model.gguf",
					"sha256":   expected,
				},
			},
		})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass, got %s", result.Status)
	}
}

func TestModelCollector_UnknownModel(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "rogue-model.gguf", "rogue-data")

	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []map[string]string{}})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "drift" {
		t.Fatalf("expected drift for unknown model, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Filesystem hardening tests
// ---------------------------------------------------------------------------

func TestHashModelFiles_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := writeTestFile(t, dir, "real.gguf", "data")
	os.Symlink(real, filepath.Join(dir, "link.gguf"))

	results, err := hashModelFiles(dir, []string{"gguf"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := results["link.gguf"]; ok {
		t.Error("symlink should be skipped")
	}
	if _, ok := results["real.gguf"]; !ok {
		t.Error("real file should be hashed")
	}
}

func TestHashModelFiles_SkipsOversized(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "small.gguf", "ok")
	writeTestFile(t, dir, "big.gguf", strings.Repeat("x", 200))

	results, err := hashModelFiles(dir, []string{"gguf"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := results["big.gguf"]; ok {
		t.Error("oversized file should be skipped")
	}
	if _, ok := results["small.gguf"]; !ok {
		t.Error("small file should be hashed")
	}
}

// ---------------------------------------------------------------------------
// Registry hardening tests
// ---------------------------------------------------------------------------

func TestFetchRegistry_InvalidScheme(t *testing.T) {
	_, err := fetchRegistryManifest("ftp://evil.host", "")
	if err == nil {
		t.Fatal("expected error for non-http scheme")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchRegistry_AuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []interface{}{}})
	}))
	defer srv.Close()

	os.Setenv("TEST_REG_TOKEN", "my-secret")
	defer os.Unsetenv("TEST_REG_TOKEN")

	_, err := fetchRegistryManifest(srv.URL, "TEST_REG_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer my-secret" {
		t.Errorf("expected auth header, got %q", gotAuth)
	}
}

// ---------------------------------------------------------------------------
// Policy collector tests
// ---------------------------------------------------------------------------

func TestPolicyCollector_HashMatch(t *testing.T) {
	dir := t.TempDir()
	content := "version: 1\ntools:\n  default: deny\n"
	path := writeTestFile(t, dir, "fw.yaml", content)

	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"tool-firewall": path},
		ApprovedHashes: map[string]string{"tool-firewall": expected},
	}

	result := collectPolicyState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass, got %s", result.Status)
	}
}

func TestPolicyCollector_HashDrift(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "fw.yaml", "changed-content")

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"tool-firewall": filepath.Join(dir, "fw.yaml")},
		ApprovedHashes: map[string]string{"tool-firewall": "wrong-hash"},
	}

	result := collectPolicyState(cfg)
	if result.Status != "drift" {
		t.Fatalf("expected drift, got %s", result.Status)
	}
}

func TestPolicyCollector_MissingFile(t *testing.T) {
	cfg := PolicyFilesConfig{
		Files:          map[string]string{"missing": "/nonexistent/policy.yaml"},
		ApprovedHashes: map[string]string{},
	}

	result := collectPolicyState(cfg)
	found := false
	for _, f := range result.Findings {
		if f.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected error finding for missing file")
	}
}

func TestPolicyCollector_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := writeTestFile(t, dir, "real.yaml", "content")
	link := filepath.Join(dir, "link.yaml")
	os.Symlink(real, link)

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"linked": link},
		ApprovedHashes: map[string]string{},
	}

	result := collectPolicyState(cfg)
	found := false
	for _, f := range result.Findings {
		if f.Key == "linked" && f.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected fail finding for symlink policy file")
	}
}

// ---------------------------------------------------------------------------
// Comparison engine tests
// ---------------------------------------------------------------------------

func TestCompare_AllPass(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "pass" {
		t.Fatalf("expected pass, got %s", att.Verdict)
	}
	if att.Score != 1.0 {
		t.Fatalf("expected score 1.0, got %.2f", att.Score)
	}
}

func TestCompare_Drift(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "drift"},
	}

	att := compare(results)
	if att.Verdict != "drift" {
		t.Fatalf("expected drift, got %s", att.Verdict)
	}
	if att.Score != 0.75 {
		t.Fatalf("expected score 0.75, got %.2f", att.Score)
	}
}

func TestCompare_Fail(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass", Findings: []Finding{{Status: "fail"}}},
		{Name: "b", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail, got %s", att.Verdict)
	}
}

func TestCompare_SkippedIgnored(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "skipped"},
	}

	att := compare(results)
	if att.Verdict != "pass" {
		t.Fatalf("expected pass (skipped ignored), got %s", att.Verdict)
	}
	if att.Score != 1.0 {
		t.Fatalf("expected score 1.0, got %.2f", att.Score)
	}
}

func TestCompare_AllSkipped(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "skipped"},
	}

	att := compare(results)
	if att.Score != 1.0 {
		t.Fatalf("expected 1.0 for all-skipped, got %.2f", att.Score)
	}
}

func TestCompare_CriticalCollectorError_IsFail(t *testing.T) {
	results := []CollectorResult{
		{Name: "model", Status: "error", Error: "vault missing"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for critical collector error, got %s", att.Verdict)
	}
}

func TestCompare_NonCriticalError_IsDrift(t *testing.T) {
	results := []CollectorResult{
		{Name: "container", Status: "error", Error: "podman missing"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "drift" {
		t.Fatalf("expected drift for non-critical error, got %s", att.Verdict)
	}
}

func TestCompare_PolicyError_IsFail(t *testing.T) {
	results := []CollectorResult{
		{Name: "policy", Status: "error", Error: "cannot hash"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for policy collector error, got %s", att.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Redaction tests
// ---------------------------------------------------------------------------

func TestRedactReport_Hostname(t *testing.T) {
	report := TrustReport{
		Hostname:    "build-server-01",
		Attestation: AttestationResult{Verdict: "pass"},
	}

	redacted := redactReport(report, PrivacyProfile{StripHostname: true})
	if redacted.Hostname != "[REDACTED]" {
		t.Errorf("expected hostname redacted, got %s", redacted.Hostname)
	}
}

func TestRedactReport_Paths(t *testing.T) {
	report := TrustReport{
		Attestation: AttestationResult{
			Collectors: []CollectorResult{{
				Name:   "policy",
				Status: "drift",
				Findings: []Finding{{
					Key:    "/etc/secure-ai/policy/fw.yaml",
					Detail: "file at /home/user/policies/fw.yaml changed",
					Status: "drift",
				}},
			}},
		},
	}

	redacted := redactReport(report, PrivacyProfile{StripPaths: true})
	f := redacted.Attestation.Collectors[0].Findings[0]
	if strings.Contains(f.Detail, "/home/user") {
		t.Error("path should be redacted from detail")
	}
}

func TestRedactReport_Listeners(t *testing.T) {
	report := TrustReport{
		Attestation: AttestationResult{
			Collectors: []CollectorResult{{
				Name:   "network",
				Status: "pass",
				Findings: []Finding{{
					Key:    "127.0.0.1:8470",
					Status: "pass",
					Detail: "expected listener",
				}},
			}},
		},
	}

	redacted := redactReport(report, PrivacyProfile{StripListeners: true})
	f := redacted.Attestation.Collectors[0].Findings[0]
	if f.Key != "[REDACTED:listener]" {
		t.Errorf("listener key should be redacted, got %s", f.Key)
	}
}

func TestRedactReport_DoesNotMutateOriginal(t *testing.T) {
	report := TrustReport{
		Hostname:    "original-host",
		Attestation: AttestationResult{Verdict: "pass"},
	}

	redactReport(report, PrivacyProfile{StripHostname: true})
	if report.Hostname != "original-host" {
		t.Error("original report should not be mutated")
	}
}

// ---------------------------------------------------------------------------
// Report generation and signing tests
// ---------------------------------------------------------------------------

func TestGenerateReport(t *testing.T) {
	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)

	if report.Version != "1" {
		t.Fatalf("expected version 1, got %s", report.Version)
	}
	if report.Attestation.Verdict != "pass" {
		t.Fatalf("expected pass, got %s", report.Attestation.Verdict)
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	if err := generateKeypair(privPath, pubPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)

	signed, err := signReport(report, privPath)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if signed.Signature == "" {
		t.Fatal("expected signature")
	}
	if signed.PublicKey == "" {
		t.Fatal("expected public key")
	}

	if err := verifyReport(signed, ""); err != nil {
		t.Fatalf("verify with embedded key: %v", err)
	}

	if err := verifyReport(signed, pubPath); err != nil {
		t.Fatalf("verify with key file: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)
	signed, _ := signReport(report, privPath)

	signed.Attestation.Verdict = "fail"

	err := verifyReport(signed, pubPath)
	if err == nil {
		t.Fatal("expected verification to fail on tampered report")
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests
// ---------------------------------------------------------------------------

func TestAttestEndpoint(t *testing.T) {
	setupTestPolicy()

	req := httptest.NewRequest(http.MethodGet, "/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var report TrustReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Version != "1" {
		t.Fatalf("expected version 1, got %s", report.Version)
	}
}

func TestAttestEndpoint_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestLatestReport_Empty(t *testing.T) {
	latestReportMu.Lock()
	latestReport = nil
	latestReportMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/report/latest", nil)
	w := httptest.NewRecorder()
	handleLatestReport(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestReloadEndpoint_RequiresPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metrics map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestAllEndpointsRequireAuth(t *testing.T) {
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/v1/attest"},
		{"GET", "/v1/report/latest"},
		{"POST", "/v1/reload"},
		{"GET", "/v1/metrics"},
	}

	for _, ep := range endpoints {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(ep.method, ep.path, nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 without token, got %d", ep.method, ep.path, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Service token auth tests
// ---------------------------------------------------------------------------

func TestServiceToken_DevMode(t *testing.T) {
	serviceToken = ""
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called in dev mode")
	}
}

func TestServiceToken_ValidToken(t *testing.T) {
	serviceToken = "test-secret-token"
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer test-secret-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called with valid token")
	}
	serviceToken = ""
}

func TestServiceToken_InvalidToken(t *testing.T) {
	serviceToken = "test-secret-token"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	serviceToken = ""
}

// ---------------------------------------------------------------------------
// Mount collector tests
// ---------------------------------------------------------------------------

func TestMountCollector_NoExpected(t *testing.T) {
	cfg := MountConfig{Expected: nil}
	result := collectMountState(cfg)
	if result.Status != "skipped" {
		t.Fatalf("expected skipped, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// GPU collector tests
// ---------------------------------------------------------------------------

func TestGPUCollector_NoDevices(t *testing.T) {
	cfg := GPUConfig{
		AllowedDevices:        []string{"/dev/nvidia0"},
		DenyUnexpectedDevices: true,
	}
	result := collectGPUState(cfg)
	if result.Status != "pass" && result.Status != "drift" {
		t.Fatalf("expected pass or drift, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// SHA256 helper test
// ---------------------------------------------------------------------------

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "test.bin", "hello world")

	hash, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := sha256.Sum256([]byte("hello world"))
	expectedHex := hex.EncodeToString(expected[:])

	if hash != expectedHex {
		t.Fatalf("expected %s, got %s", expectedHex, hash)
	}
}

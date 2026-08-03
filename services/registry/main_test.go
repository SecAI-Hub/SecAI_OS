package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGGUFGuardUsesImmutableImagePath(t *testing.T) {
	if ggufGuardBin != "/usr/bin/gguf-guard" {
		t.Fatalf("unexpected gguf-guard path: %q", ggufGuardBin)
	}
}

func installTestPolicyBundle(t *testing.T, diffusionLock string) *PolicyBundleEvidence {
	t.Helper()
	policyDir := t.TempDir()
	if diffusionLock == "" {
		diffusionLock = "version: 1\ndirectory_models: []\n"
	}
	contents := map[string]string{
		"policy.yaml":                "version: 1\n",
		"models.lock.yaml":           "version: 1\nmodels: []\n",
		"diffusion-models.lock.yaml": diffusionLock,
		"sources.allowlist.yaml":     "version: 1\nmodels: []\n",
		"yara/secure_ai_default.yar": "rule harmless_test { condition: false }\n",
	}
	components := make(map[string]string, len(contents))
	for name, content := range contents {
		sum := sha256.Sum256([]byte(content))
		components[name] = fmt.Sprintf("%x", sum)
		target := filepath.Join(policyDir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REGISTRY_POLICY_DIR", policyDir)
	t.Setenv("REGISTRY_YARA_RULES_DIR", filepath.Join(policyDir, "yara"))
	t.Setenv(
		"DIFFUSION_MODELS_LOCK_PATH",
		filepath.Join(policyDir, "diffusion-models.lock.yaml"),
	)

	ordered := []string{
		"policy.yaml",
		"models.lock.yaml",
		"diffusion-models.lock.yaml",
		"sources.allowlist.yaml",
		"yara/secure_ai_default.yar",
	}
	bundleHash := sha256.New()
	_, _ = bundleHash.Write([]byte("SecAI-Policy-Bundle-v1\x00"))
	for _, name := range ordered {
		nameBytes := []byte(name)
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(nameBytes)))
		_, _ = bundleHash.Write(length[:])
		_, _ = bundleHash.Write(nameBytes)
		componentBytes, _ := hex.DecodeString(components[name])
		_, _ = bundleHash.Write(componentBytes)
	}
	return &PolicyBundleEvidence{
		Version: 1, SHA256: hex.EncodeToString(bundleHash.Sum(nil)), Components: components,
	}
}

func promoteRequestBody(t *testing.T, request PromoteRequest) *strings.Reader {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(body))
}

func writeTinyDiffusionModel(t *testing.T, root, name string) string {
	t.Helper()
	modelDir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(modelDir, "unet"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(modelDir, "model_index.json"),
		[]byte(`{"_class_name":"StableDiffusionXLPipeline"}`),
		0o644,
	); err != nil {
		t.Fatalf("write model_index: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(modelDir, "unet", "diffusion_pytorch_model.safetensors"),
		[]byte("tiny diffusion weights"),
		0o644,
	); err != nil {
		t.Fatalf("write weights: %v", err)
	}
	return modelDir
}

func TestHealthEndpoint(t *testing.T) {
	source := filepath.Join(t.TempDir(), "manifest.json")
	data := []byte("{\"version\":1,\"models\":[]}\n")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldManifest, oldSource, oldDigest := manifest, manifestSource, manifestDigest
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestSource = source
	manifestDigest = sha256.Sum256(data)
	t.Cleanup(func() {
		manifest, manifestSource, manifestDigest = oldManifest, oldSource, oldDigest
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestHealthDegradesWhenManifestSourceChanges(t *testing.T) {
	source := filepath.Join(t.TempDir(), "manifest.json")
	data := []byte("{\"version\":1,\"models\":[]}\n")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldManifest, oldSource, oldDigest := manifest, manifestSource, manifestDigest
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestSource = source
	manifestDigest = sha256.Sum256(data)
	t.Cleanup(func() {
		manifest, manifestSource, manifestDigest = oldManifest, oldSource, oldDigest
	})
	if err := os.WriteFile(source, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handleHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected changed manifest source to degrade health, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"degraded"`) {
		t.Fatalf("expected degraded response, got %s", w.Body.String())
	}
}

func TestLoadManifestRejectsExistingCorruptionInsteadOfFallingBack(t *testing.T) {
	temp := t.TempDir()
	oldManifestPath, oldSource, oldDigest := manifestPath, manifestSource, manifestDigest
	manifestPath = filepath.Join(temp, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(temp, "models.lock.yaml")
	if err := os.WriteFile(lockPath, []byte("version: 1\nmodels: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_LOCK_PATH", lockPath)
	t.Cleanup(func() {
		manifestPath, manifestSource, manifestDigest = oldManifestPath, oldSource, oldDigest
	})

	if err := loadManifest(); err == nil || !strings.Contains(err.Error(), "runtime manifest") {
		t.Fatalf("expected existing corrupt runtime manifest to fail closed, got %v", err)
	}
}

func TestLoadManifestFallsBackOnlyWhenRuntimeManifestIsAbsent(t *testing.T) {
	temp := t.TempDir()
	oldManifest, oldManifestPath := manifest, manifestPath
	oldSource, oldDigest := manifestSource, manifestDigest
	manifestPath = filepath.Join(temp, "missing-manifest.json")
	lockPath := filepath.Join(temp, "models.lock.yaml")
	lockData := []byte("version: 1\nmodels: []\n")
	if err := os.WriteFile(lockPath, lockData, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_LOCK_PATH", lockPath)
	t.Cleanup(func() {
		manifest, manifestPath = oldManifest, oldManifestPath
		manifestSource, manifestDigest = oldSource, oldDigest
	})

	if err := loadManifest(); err != nil {
		t.Fatalf("expected ENOENT runtime manifest to use the baked lock: %v", err)
	}
	if manifest.Version != 1 || manifestSource != lockPath {
		t.Fatalf("unexpected fallback manifest state: %#v source=%q", manifest, manifestSource)
	}
}

func TestBakedModelsLockMatchesStrictRegistrySchema(t *testing.T) {
	lockPath := filepath.Join(
		"..", "..", "files", "system", "etc", "secure-ai", "policy", "models.lock.yaml",
	)
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := decodeModelsLock(data)
	if err != nil {
		t.Fatalf("production models lock must satisfy strict registry schema: %v", err)
	}
	if candidate.Version != 1 || len(candidate.Models) == 0 {
		t.Fatalf("unexpected production models lock: version=%d models=%d",
			candidate.Version, len(candidate.Models))
	}
}

func TestLoadManifestRejectsUnsafeExistingManifestFile(t *testing.T) {
	temp := t.TempDir()
	oldManifestPath := manifestPath
	manifestPath = filepath.Join(temp, "manifest.json")
	target := filepath.Join(temp, "target.json")
	if err := os.WriteFile(target, []byte("{\"version\":1,\"models\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, manifestPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { manifestPath = oldManifestPath })

	if err := loadManifest(); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("expected symlink manifest to be rejected, got %v", err)
	}
}

func TestListModelsEmpty(t *testing.T) {
	// Reset manifest
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	handleListModels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var models []Artifact
	json.Unmarshal(w.Body.Bytes(), &models)
	if len(models) != 0 {
		t.Fatalf("expected empty list, got %d models", len(models))
	}
}

func TestPromoteInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPromoteMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/model/promote", nil)
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRegistryPathRejectsEscapes(t *testing.T) {
	tmp := t.TempDir()
	oldRegistryDir := registryDir
	registryDir = tmp
	t.Cleanup(func() { registryDir = oldRegistryDir })

	badNames := []string{
		"../escape.gguf",
		filepath.Join("..", "escape.gguf"),
		filepath.Join(tmp, "..", "escape.gguf"),
		filepath.Join(tmp, "model.gguf"),
		"bad\x00name.gguf",
	}
	for _, name := range badNames {
		if path, err := registryPath(name); err == nil {
			t.Fatalf("expected %q to be rejected, got %q", name, path)
		}
	}

	relative, err := registryPath("nested/model.gguf")
	if err != nil {
		t.Fatalf("expected relative registry path to be accepted: %v", err)
	}
	if !strings.HasPrefix(relative, tmp) {
		t.Fatalf("expected %q to stay under %q", relative, tmp)
	}
}

func TestPromoteDirectModelRejected(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	// Reset manifest
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	// Create a fake model file
	fakeModel := filepath.Join(tmp, "test-model.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	body := `{
		"name": "test-model",
		"filename": "test-model.gguf",
		"sha256": "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		"size_bytes": 15,
		"scan_results": {}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected direct promotion to be rejected, got %d: %s", w.Code, w.Body.String())
	}

	// Verify model is in manifest
	manifestMu.RLock()
	count := len(manifest.Models)
	manifestMu.RUnlock()
	if count != 0 {
		t.Fatalf("direct promotion must not change the manifest, got %d entries", count)
	}
}

func TestPromoteStagedModelTransaction(t *testing.T) {
	registry := t.TempDir()
	staging := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("PROMOTION_STAGING_DIR", staging)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	const content = "transactional model data"
	if err := os.WriteFile(filepath.Join(staging, "scan-123.gguf"), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	policyEvidence := installTestPolicyBundle(t, "")
	body := promoteRequestBody(t, PromoteRequest{
		Name: "transactional-model", Filename: "transactional-model.gguf",
		StagedFilename: "scan-123.gguf", SHA256: digest, SizeBytes: int64(len(content)),
		ScanResults:   map[string]string{"malware": "clean"},
		PolicyVersion: policyEvidence.SHA256, PolicyBundle: policyEvidence,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", body)
	w := httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(staging, "scan-123.gguf")); !os.IsNotExist(err) {
		t.Fatalf("staged input should be removed after commit, got %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(registry, "transactional-model.gguf")); err != nil || string(data) != content {
		t.Fatalf("committed artifact mismatch: err=%v data=%q", err, data)
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil || !strings.Contains(string(data), `"transactional-model.gguf"`) {
		t.Fatalf("manifest did not commit promoted artifact: err=%v data=%s", err, data)
	}
}

func TestPromoteStagedHashMismatchLeavesNoFinalArtifact(t *testing.T) {
	registry := t.TempDir()
	staging := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("PROMOTION_STAGING_DIR", staging)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()
	if err := os.WriteFile(filepath.Join(staging, "scan.gguf"), []byte("content"), 0o640); err != nil {
		t.Fatal(err)
	}
	policyEvidence := installTestPolicyBundle(t, "")
	body := promoteRequestBody(t, PromoteRequest{
		Name: "bad-hash", Filename: "bad-hash.gguf", StagedFilename: "scan.gguf",
		SHA256: strings.Repeat("0", 64), SizeBytes: int64(len("content")),
		PolicyVersion: policyEvidence.SHA256, PolicyBundle: policyEvidence,
	})
	w := httptest.NewRecorder()
	handlePromote(w, httptest.NewRequest(http.MethodPost, "/v1/model/promote", body))
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(registry, "bad-hash.gguf")); !os.IsNotExist(err) {
		t.Fatalf("unverified final artifact must not exist, got %v", err)
	}
}

func TestQuarantineModelMovesArtifactAndCommitsManifest(t *testing.T) {
	registry := t.TempDir()
	contained := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("REGISTRY_CONTAINMENT_DIR", contained)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})

	const filename = "suspect.gguf"
	if err := os.WriteFile(filepath.Join(registry, filename), []byte("weights"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "suspect",
		Filename: filename,
		SHA256:   fmt.Sprintf("%x", sha256.Sum256([]byte("weights"))),
	}}}
	manifestMu.Unlock()
	if err := saveManifest(); err != nil {
		t.Fatal(err)
	}

	body := `{
		"action":"quarantine",
		"incident_id":"INC-20260727-0001",
		"model_path":"` + filepath.Join(registry, filename) + `",
		"reason":"runtime anomaly"
	}`
	w := httptest.NewRecorder()
	handleQuarantine(
		w,
		httptest.NewRequest(http.MethodPost, "/api/v1/quarantine", strings.NewReader(body)),
	)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(registry, filename)); !os.IsNotExist(err) {
		t.Fatalf("registry artifact should be removed, got %v", err)
	}
	entries, err := os.ReadDir(contained)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one contained artifact: entries=%v err=%v", entries, err)
	}
	if data, err := os.ReadFile(filepath.Join(contained, entries[0].Name())); err != nil || string(data) != "weights" {
		t.Fatalf("contained artifact mismatch: data=%q err=%v", data, err)
	}
	manifestMu.RLock()
	modelCount := len(manifest.Models)
	manifestMu.RUnlock()
	if modelCount != 0 {
		t.Fatalf("contained model must be removed from manifest, got %d entries", modelCount)
	}
}

func TestQuarantineRejectsArbitraryPath(t *testing.T) {
	registry := t.TempDir()
	contained := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("REGISTRY_CONTAINMENT_DIR", contained)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})
	if err := os.WriteFile(filepath.Join(registry, "known.gguf"), []byte("known"), 0o640); err != nil {
		t.Fatal(err)
	}
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name: "known", Filename: "known.gguf",
	}}}
	manifestMu.Unlock()

	body := `{
		"action":"quarantine",
		"incident_id":"INC-1",
		"model_path":"/etc/passwd"
	}`
	w := httptest.NewRecorder()
	handleQuarantine(
		w,
		httptest.NewRequest(http.MethodPost, "/api/v1/quarantine", strings.NewReader(body)),
	)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-manifest path, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(registry, "known.gguf")); err != nil {
		t.Fatalf("known model must remain in place: %v", err)
	}
}

func TestRegistryMuxProtectsQuarantineEndpoint(t *testing.T) {
	oldToken := serviceToken
	oldContainmentToken := containmentToken
	serviceToken = "registry-test-token"
	containmentToken = "registry-containment-test-token"
	t.Cleanup(func() {
		serviceToken = oldToken
		containmentToken = oldContainmentToken
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/quarantine",
		strings.NewReader(`{"action":"quarantine","incident_id":"INC-1","model_name":"x"}`),
	)
	w := httptest.NewRecorder()
	newRegistryMux().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected unauthenticated quarantine request to be forbidden, got %d", w.Code)
	}
}

func TestRegistryGeneralCredentialCannotQuarantine(t *testing.T) {
	oldToken := serviceToken
	oldContainmentToken := containmentToken
	serviceToken = "registry-general-token"
	containmentToken = "registry-containment-token"
	t.Cleanup(func() {
		serviceToken = oldToken
		containmentToken = oldContainmentToken
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/quarantine",
		strings.NewReader(`{"action":"quarantine","incident_id":"INC-1","model_name":"x"}`),
	)
	req.Header.Set("Authorization", "Bearer registry-general-token")
	w := httptest.NewRecorder()
	newRegistryMux().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("general registry token must not authorize quarantine, got %d", w.Code)
	}
}

func TestRegistryEndpointScopesAreIndependent(t *testing.T) {
	oldRead, oldVerify := readToken, verifyToken
	oldPromote, oldAdmin := promoteToken, adminToken
	oldContainment := containmentToken
	readToken = "read-scope-token"
	verifyToken = "verify-scope-token"
	promoteToken = "promote-scope-token"
	adminToken = "admin-scope-token"
	containmentToken = "containment-scope-token"
	t.Cleanup(func() {
		readToken, verifyToken = oldRead, oldVerify
		promoteToken, adminToken = oldPromote, oldAdmin
		containmentToken = oldContainment
	})
	manifestMu.Lock()
	oldManifest := manifest
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()
	t.Cleanup(func() {
		manifestMu.Lock()
		manifest = oldManifest
		manifestMu.Unlock()
	})
	t.Setenv("INTEGRITY_RESULT_PATH", filepath.Join(t.TempDir(), "integrity.json"))

	assertStatus := func(method, path, token string, expected int) {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		newRegistryMux().ServeHTTP(response, request)
		if response.Code != expected {
			t.Fatalf("%s %s with %q: expected %d, got %d: %s",
				method, path, token, expected, response.Code, response.Body.String())
		}
	}

	// Read is available to the read credential and the UI's administrator
	// credential, but not to verification or promotion workers.
	assertStatus(http.MethodGet, "/v1/models", "read-scope-token", http.StatusOK)
	assertStatus(http.MethodGet, "/v1/models", "admin-scope-token", http.StatusOK)
	assertStatus(http.MethodGet, "/v1/models", "verify-scope-token", http.StatusForbidden)
	assertStatus(http.MethodGet, "/v1/models", "promote-scope-token", http.StatusForbidden)

	// Verification is available to the verifier and administrator only.
	assertStatus(http.MethodPost, "/v1/models/verify-all", "verify-scope-token", http.StatusOK)
	assertStatus(http.MethodPost, "/v1/models/verify-all", "admin-scope-token", http.StatusOK)
	assertStatus(http.MethodPost, "/v1/models/verify-all", "read-scope-token", http.StatusForbidden)
	assertStatus(http.MethodPost, "/v1/models/verify-all", "promote-scope-token", http.StatusForbidden)

	// Promotion deliberately excludes the administrator credential so the UI
	// cannot bypass the quarantine watcher's staged promotion boundary.
	assertStatus(http.MethodPost, "/v1/model/promote", "promote-scope-token", http.StatusBadRequest)
	assertStatus(http.MethodPost, "/v1/model/promote", "admin-scope-token", http.StatusForbidden)
	assertStatus(http.MethodPost, "/v1/model/promote", "read-scope-token", http.StatusForbidden)

	// Deletion is administrator-only and containment remains a fifth,
	// independent authority.
	assertStatus(http.MethodDelete, "/v1/model/delete", "admin-scope-token", http.StatusBadRequest)
	assertStatus(http.MethodDelete, "/v1/model/delete", "promote-scope-token", http.StatusForbidden)
	assertStatus(http.MethodPost, "/api/v1/quarantine", "admin-scope-token", http.StatusForbidden)
	assertStatus(http.MethodPost, "/api/v1/quarantine", "containment-scope-token", http.StatusBadRequest)
}

func TestRegistryLegacyTokenFallbackRequiresExplicitSandboxMode(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "registry.token")
	if err := os.WriteFile(tokenPath, []byte("sandbox-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", tokenPath)
	t.Setenv("REGISTRY_READ_TOKEN_PATH", "")
	t.Setenv("REGISTRY_VERIFY_TOKEN_PATH", "")
	t.Setenv("REGISTRY_PROMOTE_TOKEN_PATH", "")
	t.Setenv("REGISTRY_ADMIN_TOKEN_PATH", "")

	t.Setenv("SECURE_AI_DEPLOYMENT_MODE", "")
	if err := loadEndpointTokens(); err == nil {
		t.Fatal("legacy shared credential must be rejected outside explicit sandbox mode")
	}
	t.Setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")
	if err := loadEndpointTokens(); err != nil {
		t.Fatalf("expected explicit sandbox fallback to load: %v", err)
	}
	if readToken != "sandbox-token" || verifyToken != "sandbox-token" ||
		promoteToken != "sandbox-token" || adminToken != "sandbox-token" {
		t.Fatal("sandbox fallback did not initialize all compatibility scopes")
	}
}

func TestPromoteValidDiffusionDirectory(t *testing.T) {
	registry := t.TempDir()
	staging := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("PROMOTION_STAGING_DIR", staging)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	writeTinyDiffusionModel(t, staging, "scan-directory")
	root, err := os.OpenRoot(staging)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	hash, files, size, err := computeDirectoryHashStats(root, "scan-directory")
	if err != nil {
		t.Fatalf("computeDirectoryHash: %v", err)
	}
	revision := strings.Repeat("a", 40)
	manifestDigest := strings.Repeat("b", 64)
	lock := fmt.Sprintf(`version: 1
directory_models:
  - name: "Test Diffusion"
    filename: "tiny-diffusion"
    source: "https://huggingface.co/test-org/test-model"
    repo_id: "test-org/test-model"
    revision: %q
    variant: null
    file_count: %d
    total_size_bytes: %d
    manifest_sha256: %q
`, revision, files, size, manifestDigest)
	policyEvidence := installTestPolicyBundle(t, lock)
	provenance := &DirectoryProvenance{
		Trust: "image-owned-manifest-pin", ManifestSHA256: manifestDigest,
		Revision: revision, RepoID: "test-org/test-model", Variant: nil,
		FilesChecked: files, TotalSizeBytes: size,
		SHA256FilesChecked: files, GitBlobFilesChecked: 0,
	}
	body := promoteRequestBody(t, PromoteRequest{
		Name: "tiny-diffusion", Filename: "tiny-diffusion",
		StagedFilename: "scan-directory", SHA256: hash, SizeBytes: size,
		Source:        "https://huggingface.co/test-org/test-model",
		ScanResults:   map[string]string{"model_type": "diffusion"},
		PolicyVersion: policyEvidence.SHA256, PolicyBundle: policyEvidence,
		SourceRevision: revision, DirectoryProvenance: provenance,
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	if len(manifest.Models) != 1 {
		t.Fatalf("expected 1 model in manifest, got %d", len(manifest.Models))
	}
	if manifest.Models[0].Format != "diffusion-directory" {
		t.Fatalf("expected diffusion-directory format, got %q", manifest.Models[0].Format)
	}
	if manifest.Models[0].DirectoryProvenance == nil ||
		manifest.Models[0].DirectoryProvenance.Revision != revision {
		t.Fatal("typed directory provenance was not committed")
	}
}

func TestPromoteDirectoryProvenanceMismatchRollsBack(t *testing.T) {
	registry := t.TempDir()
	staging := t.TempDir()
	oldRegistryDir, oldManifestPath := registryDir, manifestPath
	registryDir = registry
	manifestPath = filepath.Join(registry, "manifest.json")
	t.Setenv("PROMOTION_STAGING_DIR", staging)
	t.Cleanup(func() {
		registryDir = oldRegistryDir
		manifestPath = oldManifestPath
	})
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	writeTinyDiffusionModel(t, staging, "scan-directory")
	root, err := os.OpenRoot(staging)
	if err != nil {
		t.Fatal(err)
	}
	hash, files, size, err := computeDirectoryHashStats(root, "scan-directory")
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("c", 40)
	manifestDigest := strings.Repeat("d", 64)
	lock := fmt.Sprintf(`version: 1
directory_models:
  - filename: "rejected-directory"
    source: "https://huggingface.co/test-org/rejected"
    repo_id: "test-org/rejected"
    revision: %q
    variant: null
    file_count: %d
    total_size_bytes: %d
    manifest_sha256: %q
`, revision, files, size, manifestDigest)
	policyEvidence := installTestPolicyBundle(t, lock)
	provenance := &DirectoryProvenance{
		Trust: "image-owned-manifest-pin", ManifestSHA256: manifestDigest,
		Revision: revision, RepoID: "test-org/rejected",
		FilesChecked: files + 1, TotalSizeBytes: size,
		SHA256FilesChecked: files + 1,
	}
	request := PromoteRequest{
		Name: "rejected-directory", Filename: "rejected-directory",
		StagedFilename: "scan-directory", SHA256: hash, SizeBytes: size,
		Source:         "https://huggingface.co/test-org/rejected",
		SourceRevision: revision, DirectoryProvenance: provenance,
		PolicyVersion: policyEvidence.SHA256, PolicyBundle: policyEvidence,
	}
	w := httptest.NewRecorder()
	handlePromote(
		w,
		httptest.NewRequest(
			http.MethodPost,
			"/v1/model/promote",
			promoteRequestBody(t, request),
		),
	)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected mismatched provenance rejection, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(registry, "rejected-directory")); !os.IsNotExist(err) {
		t.Fatalf("rejected directory must not be committed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "scan-directory")); err != nil {
		t.Fatalf("source must remain staged after rejection: %v", err)
	}
}

func TestPromoteDirectoryMissingModelIndexRejected(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	if err := os.MkdirAll(filepath.Join(tmp, "bad-diffusion"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "bad-diffusion", "weights.safetensors"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write weights: %v", err)
	}

	body := `{
		"name": "bad-diffusion",
		"filename": "bad-diffusion",
		"sha256": "deadbeef",
		"size_bytes": 1,
		"scan_results": {"model_type":"diffusion"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteNonexistent(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=nonexistent", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestVerifyAllEmpty(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestVerifyAllWithValidModel(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	resultPath := filepath.Join(tmp, "integrity-last.json")
	t.Setenv("INTEGRITY_RESULT_PATH", resultPath)

	fakeModel := filepath.Join(tmp, "test.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "test",
		Filename: "test.gguf",
		SHA256:   "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected ok, got %v", body["status"])
	}
	if _, err := os.Stat(resultPath); err != nil {
		t.Fatalf("expected integrity result file, got %v", err)
	}
}

func TestVerifyAllWithValidDiffusionDirectory(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	modelDir := writeTinyDiffusionModel(t, tmp, "diffusion-ok")
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	hash, err := computeDirectoryHash(root, filepath.Base(modelDir))
	if err != nil {
		t.Fatalf("computeDirectoryHash: %v", err)
	}

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "diffusion-ok",
		Format:   "diffusion-directory",
		Filename: "diffusion-ok",
		SHA256:   hash,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected ok, got %v", body["status"])
	}
}

func TestVerifyAllDetectsTampered(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	resultPath := filepath.Join(tmp, "integrity-last.json")
	t.Setenv("INTEGRITY_RESULT_PATH", resultPath)

	fakeModel := filepath.Join(tmp, "tampered.gguf")
	os.WriteFile(fakeModel, []byte("tampered data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "tampered",
		Filename: "tampered.gguf",
		SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "failed" {
		t.Fatalf("expected failed, got %v", body["status"])
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("expected integrity result file, got %v", err)
	}
	if !strings.Contains(string(data), "\"status\": \"failed\"") {
		t.Fatalf("expected persisted failed status, got %s", string(data))
	}
}

func TestVerifyAllMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestVerifyModelWithSafeToUse(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "safe.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "safe-model",
		Filename: "safe.gguf",
		SHA256:   "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=safe-model", nil)
	w := httptest.NewRecorder()
	handleVerifyModel(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["safe_to_use"] != "true" {
		t.Fatalf("expected safe_to_use=true, got %v", body["safe_to_use"])
	}
}

func TestVerifyModelTamperedNotSafe(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "bad.gguf")
	os.WriteFile(fakeModel, []byte("tampered"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "bad-model",
		Filename: "bad.gguf",
		SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=bad-model", nil)
	w := httptest.NewRecorder()
	handleVerifyModel(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["safe_to_use"] != "false" {
		t.Fatalf("expected safe_to_use=false, got %v", body["safe_to_use"])
	}
}

func TestDeleteRemovesDiffusionDirectory(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	writeTinyDiffusionModel(t, tmp, "diffusion-delete")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "diffusion-delete",
		Format:   "diffusion-directory",
		Filename: "diffusion-delete",
		SHA256:   "unused",
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=diffusion-delete", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "diffusion-delete")); !os.IsNotExist(err) {
		t.Fatalf("expected diffusion directory to be removed, stat err=%v", err)
	}
}

func TestIntegrityStatusNoFile(t *testing.T) {
	os.Setenv("INTEGRITY_RESULT_PATH", "/tmp/nonexistent-integrity-result.json")
	defer os.Unsetenv("INTEGRITY_RESULT_PATH")

	req := httptest.NewRequest(http.MethodGet, "/v1/integrity/status", nil)
	w := httptest.NewRecorder()
	handleIntegrityStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "unknown" {
		t.Fatalf("expected unknown, got %v", body["status"])
	}
}

func TestIntegrityStatusWithFile(t *testing.T) {
	tmp := t.TempDir()
	resultFile := filepath.Join(tmp, "integrity-last.json")
	os.WriteFile(resultFile, []byte(`{"status":"ok","models_checked":2,"failures":0}`), 0644)
	os.Setenv("INTEGRITY_RESULT_PATH", resultFile)
	defer os.Unsetenv("INTEGRITY_RESULT_PATH")

	req := httptest.NewRequest(http.MethodGet, "/v1/integrity/status", nil)
	w := httptest.NewRecorder()
	handleIntegrityStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected ok, got %v", body["status"])
	}
	if body["models_checked"] != float64(2) {
		t.Fatalf("expected 2, got %v", body["models_checked"])
	}
}

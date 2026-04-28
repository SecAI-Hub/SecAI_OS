package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestPromoteValidModel(t *testing.T) {
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

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify model is in manifest
	manifestMu.RLock()
	count := len(manifest.Models)
	manifestMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 model in manifest, got %d", count)
	}
}

func TestPromoteValidDiffusionDirectory(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	writeTinyDiffusionModel(t, tmp, "tiny-diffusion")
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	hash, err := computeDirectoryHash(root, "tiny-diffusion")
	if err != nil {
		t.Fatalf("computeDirectoryHash: %v", err)
	}
	size, err := artifactSize(root, "tiny-diffusion")
	if err != nil {
		t.Fatalf("artifactSize: %v", err)
	}

	body := fmt.Sprintf(`{
		"name": "tiny-diffusion",
		"filename": "tiny-diffusion",
		"sha256": %q,
		"size_bytes": %d,
		"scan_results": {"model_type":"diffusion"}
	}`, hash, size)

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
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

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
}

func TestVerifyAllDetectsTampered(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

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

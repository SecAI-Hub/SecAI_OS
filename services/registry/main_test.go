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

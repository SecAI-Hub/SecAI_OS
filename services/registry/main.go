package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Artifact represents a promoted model in the trusted registry.
type Artifact struct {
	Name        string            `json:"name" yaml:"name"`
	Format      string            `json:"format" yaml:"format"`
	Filename    string            `json:"filename" yaml:"filename"`
	SHA256      string            `json:"sha256" yaml:"sha256"`
	SizeBytes   int64             `json:"size_bytes" yaml:"size_bytes"`
	Source      string            `json:"source,omitempty" yaml:"source,omitempty"`
	PromotedAt  string            `json:"promoted_at" yaml:"promoted_at"`
	ScanResults map[string]string `json:"scan_results,omitempty" yaml:"scan_results,omitempty"`
}

// Manifest is the runtime registry manifest (stored as JSON on the vault).
type Manifest struct {
	Version int        `json:"version"`
	Models  []Artifact `json:"models"`
}

// ModelsLock is the baked-in models.lock.yaml from /etc/secure-ai.
type ModelsLock struct {
	Version int        `yaml:"version"`
	Models  []Artifact `yaml:"models"`
}

// PromoteRequest is sent by the quarantine pipeline to promote an artifact.
type PromoteRequest struct {
	Name        string            `json:"name"`
	Filename    string            `json:"filename"`
	SHA256      string            `json:"sha256"`
	SizeBytes   int64             `json:"size_bytes"`
	Source      string            `json:"source,omitempty"`
	ScanResults map[string]string `json:"scan_results,omitempty"`
}

var (
	manifest     Manifest
	manifestMu   sync.RWMutex
	registryDir  string
	manifestPath string
	allowedFmts  = map[string]bool{"gguf": true, "safetensors": true}
)

func loadManifest() error {
	// Try runtime manifest first (writable, on vault)
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		return json.Unmarshal(data, &manifest)
	}

	// Fall back to baked-in models.lock.yaml
	lockPath := os.Getenv("REGISTRY_LOCK_PATH")
	if lockPath == "" {
		lockPath = "/etc/secure-ai/policy/models.lock.yaml"
	}
	data, err = os.ReadFile(lockPath)
	if err != nil {
		manifest = Manifest{Version: 1, Models: []Artifact{}}
		return nil
	}
	var lock ModelsLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return err
	}
	manifest = Manifest{Version: lock.Version, Models: lock.Models}
	return nil
}

func saveManifest() error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, data, 0644)
}

func formatFromFilename(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".gguf":
		return "gguf"
	case ".safetensors":
		return "safetensors"
	default:
		return ext
	}
}

// verifyFileHash computes sha256 of a file and compares to expected.
func verifyFileHash(path, expected string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return actual, fmt.Errorf("hash mismatch: expected %s, got %s", expected, actual)
	}
	return actual, nil
}

func handleListModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest.Models)
}

func handleGetModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m)
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleModelPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			path := filepath.Join(registryDir, m.Filename)
			if _, err := os.Stat(path); err != nil {
				http.Error(w, "model file not found on disk", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"path": path})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handlePromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PromoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Filename == "" || req.SHA256 == "" {
		http.Error(w, "name, filename, and sha256 are required", http.StatusBadRequest)
		return
	}

	// Validate format
	format := formatFromFilename(req.Filename)
	if !allowedFmts[format] {
		http.Error(w, fmt.Sprintf("format %q not allowed; permitted: gguf, safetensors", format), http.StatusForbidden)
		return
	}

	// Verify the file exists in the registry directory and hash matches
	filePath := filepath.Join(registryDir, req.Filename)
	actualHash, err := verifyFileHash(filePath, req.SHA256)
	if err != nil {
		http.Error(w, fmt.Sprintf("hash verification failed: %v", err), http.StatusConflict)
		return
	}

	// Get file size
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "cannot stat model file", http.StatusInternalServerError)
		return
	}

	artifact := Artifact{
		Name:        req.Name,
		Format:      format,
		Filename:    req.Filename,
		SHA256:      actualHash,
		SizeBytes:   info.Size(),
		Source:      req.Source,
		PromotedAt:  time.Now().UTC().Format(time.RFC3339),
		ScanResults: req.ScanResults,
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

	// Replace existing entry with same name, or append
	replaced := false
	for i, m := range manifest.Models {
		if m.Name == req.Name {
			manifest.Models[i] = artifact
			replaced = true
			break
		}
	}
	if !replaced {
		manifest.Models = append(manifest.Models, artifact)
	}

	if err := saveManifest(); err != nil {
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("PROMOTED: %s (%s) sha256=%s", artifact.Name, artifact.Filename, artifact.SHA256)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(artifact)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

	found := false
	filtered := make([]Artifact, 0, len(manifest.Models))
	for _, m := range manifest.Models {
		if m.Name == name {
			found = true
			// Remove the model file from disk
			filePath := filepath.Join(registryDir, m.Filename)
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				log.Printf("warning: could not remove %s: %v", filePath, err)
			}
			log.Printf("REMOVED: %s (%s)", m.Name, m.Filename)
		} else {
			filtered = append(filtered, m)
		}
	}

	if !found {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}

	manifest.Models = filtered
	if err := saveManifest(); err != nil {
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
}

func handleVerifyAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manifestMu.RLock()
	models := make([]Artifact, len(manifest.Models))
	copy(models, manifest.Models)
	manifestMu.RUnlock()

	results := make([]map[string]string, 0, len(models))
	allOk := true

	for _, m := range models {
		filePath := filepath.Join(registryDir, m.Filename)
		actual, err := verifyFileHash(filePath, m.SHA256)
		if err != nil {
			allOk = false
			results = append(results, map[string]string{
				"name":     m.Name,
				"status":   "failed",
				"expected": m.SHA256,
				"actual":   actual,
				"error":    err.Error(),
			})
		} else {
			results = append(results, map[string]string{
				"name":   m.Name,
				"status": "verified",
				"sha256": actual,
			})
		}
	}

	status := "ok"
	if !allOk {
		status = "failed"
	}

	w.Header().Set("Content-Type", "application/json")
	if !allOk {
		w.WriteHeader(http.StatusConflict)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"models":  results,
		"checked": len(results),
	})
}

func handleIntegrityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resultPath := os.Getenv("INTEGRITY_RESULT_PATH")
	if resultPath == "" {
		resultPath = "/var/lib/secure-ai/logs/integrity-last.json"
	}

	data, err := os.ReadFile(resultPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "unknown",
			"detail":  "no integrity check has run yet",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleVerifyModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()

	for _, m := range manifest.Models {
		if m.Name == name {
			filePath := filepath.Join(registryDir, m.Filename)
			actual, err := verifyFileHash(filePath, m.SHA256)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"status":   "failed",
					"name":     name,
					"expected": m.SHA256,
					"actual":   actual,
					"error":    err.Error(),
					"safe_to_use": "false",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":      "verified",
				"name":        name,
				"sha256":      actual,
				"safe_to_use": "true",
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	manifestMu.RLock()
	count := len(manifest.Models)
	manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"model_count": count,
		"registry_dir": registryDir,
	})
}

func main() {
	registryDir = os.Getenv("REGISTRY_DIR")
	if registryDir == "" {
		registryDir = "/registry"
	}
	manifestPath = filepath.Join(registryDir, "manifest.json")

	if err := loadManifest(); err != nil {
		log.Printf("warning: could not load manifest: %v", err)
		manifest = Manifest{Version: 1, Models: []Artifact{}}
	}
	log.Printf("loaded %d model(s) from manifest", len(manifest.Models))

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "0.0.0.0:8470"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/models", handleListModels)
	mux.HandleFunc("/v1/model", handleGetModel)
	mux.HandleFunc("/v1/model/path", handleModelPath)
	mux.HandleFunc("/v1/model/promote", handlePromote)
	mux.HandleFunc("/v1/model/delete", handleDelete)
	mux.HandleFunc("/v1/model/verify", handleVerifyModel)
	mux.HandleFunc("/v1/models/verify-all", handleVerifyAll)
	mux.HandleFunc("/v1/integrity/status", handleIntegrityStatus)

	log.Printf("secure-ai-registry listening on %s", bind)
	if err := http.ListenAndServe(bind, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

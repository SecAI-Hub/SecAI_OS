package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Types
// =========================================================================

// IntegrityState tracks the appliance filesystem trust state.
type IntegrityState string

const (
	StateTrusted          IntegrityState = "trusted"
	StateDegraded         IntegrityState = "degraded"
	StateRecoveryRequired IntegrityState = "recovery_required"
)

// WatchCategory identifies what class of file changed.
type WatchCategory string

const (
	CatServiceBinary WatchCategory = "service_binary"
	CatPolicyFile    WatchCategory = "policy_file"
	CatModelFile     WatchCategory = "model_file"
	CatSystemdUnit   WatchCategory = "systemd_unit"
	CatTrustMaterial WatchCategory = "trust_material"
)

// IntegrityViolation records a single detected change.
type IntegrityViolation struct {
	DetectedAt   string        `json:"detected_at" yaml:"detected_at"`
	Category     WatchCategory `json:"category" yaml:"category"`
	Path         string        `json:"path" yaml:"path"`
	ExpectedHash string        `json:"expected_hash" yaml:"expected_hash"`
	ActualHash   string        `json:"actual_hash" yaml:"actual_hash"`
	Action       string        `json:"action" yaml:"action"`
}

// BaselineEntry represents a single file in the signed baseline.
type BaselineEntry struct {
	Path     string        `json:"path" yaml:"path"`
	Hash     string        `json:"hash" yaml:"hash"`
	Category WatchCategory `json:"category" yaml:"category"`
	Size     int64         `json:"size" yaml:"size"`
}

// SignedBaseline is the full baseline manifest.
type SignedBaseline struct {
	CreatedAt string          `json:"created_at" yaml:"created_at"`
	Entries   []BaselineEntry `json:"entries" yaml:"entries"`
	HMAC      string          `json:"hmac" yaml:"hmac"`
}

// MonitorPolicy defines what to watch.
type MonitorPolicy struct {
	Version         int      `yaml:"version"`
	ScanInterval    string   `yaml:"scan_interval"`
	ServiceBinaries []string `yaml:"service_binaries"`
	PolicyFiles     []string `yaml:"policy_files"`
	ModelDirs       []string `yaml:"model_dirs"`
	SystemdUnits    []string `yaml:"systemd_units"`
	TrustMaterial   []string `yaml:"trust_material"`
	HMACKeyPath     string   `yaml:"hmac_key_path"`
	// DegradationThreshold: number of violations before recovery_required
	DegradationThreshold int `yaml:"degradation_threshold"`
}

// StatusResponse is returned by /api/security/status
type StatusResponse struct {
	State            IntegrityState       `json:"state"`
	WatchedFiles     int                  `json:"watched_files"`
	ViolationCount   int                  `json:"violation_count"`
	LastScanAt       string               `json:"last_scan_at"`
	ScanCount        int64                `json:"scan_count"`
	DegradedCount    int64                `json:"degraded_count"`
	RecoveryCount    int64                `json:"recovery_count"`
	ActiveViolations []IntegrityViolation `json:"active_violations,omitempty"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	stateMu          sync.RWMutex
	currentState     IntegrityState = StateTrusted
	activeViolations []IntegrityViolation
	lastScanAt       string

	baselineMu sync.RWMutex
	baseline   SignedBaseline

	policyMu      sync.RWMutex
	monitorPolicy MonitorPolicy

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	serviceToken string
	hmacKey      []byte

	scanCount     atomic.Int64
	degradedCount atomic.Int64
	recoveryCount atomic.Int64
)

const maxRequestBodySize = 64 * 1024

// =========================================================================
// Policy loading
// =========================================================================

func monitorPolicyPath() string {
	p := os.Getenv("MONITOR_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/integrity-monitor.yaml"
	}
	return p
}

func loadMonitorPolicy() error {
	data, err := os.ReadFile(monitorPolicyPath())
	if err != nil {
		log.Printf("warning: monitor policy not found (%v) — using defaults", err)
		policyMu.Lock()
		monitorPolicy = MonitorPolicy{
			Version:      1,
			ScanInterval: "30s",
			ServiceBinaries: []string{
				"/usr/libexec/secure-ai/registry",
				"/usr/libexec/secure-ai/tool-firewall",
				"/usr/libexec/secure-ai/airlock",
				"/usr/libexec/secure-ai/policy-engine",
				"/usr/libexec/secure-ai/runtime-attestor",
				"/usr/libexec/secure-ai/gpu-integrity-watch",
				"/usr/libexec/secure-ai/mcp-firewall",
			},
			PolicyFiles: []string{
				"/etc/secure-ai/policy/policy.yaml",
				"/etc/secure-ai/policy/agent.yaml",
				"/etc/secure-ai/policy/attestation.yaml",
				"/etc/secure-ai/policy/landlock.yaml",
			},
			ModelDirs: []string{
				"/var/lib/secure-ai/registry",
			},
			SystemdUnits: []string{},
			TrustMaterial: []string{
				"/etc/secure-ai/cosign/cosign.pub",
			},
			DegradationThreshold: 3,
		}
		policyMu.Unlock()
		return nil
	}

	var pol MonitorPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return fmt.Errorf("cannot parse monitor policy: %w", err)
	}
	if pol.ScanInterval == "" {
		pol.ScanInterval = "30s"
	}
	if pol.DegradationThreshold <= 0 {
		pol.DegradationThreshold = 3
	}
	policyMu.Lock()
	monitorPolicy = pol
	policyMu.Unlock()
	log.Printf("monitor policy loaded: binaries=%d policies=%d model_dirs=%d units=%d trust=%d interval=%s",
		len(pol.ServiceBinaries), len(pol.PolicyFiles), len(pol.ModelDirs),
		len(pol.SystemdUnits), len(pol.TrustMaterial), pol.ScanInterval)
	return nil
}

func getMonitorPolicy() MonitorPolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return monitorPolicy
}

// =========================================================================
// File hashing
// =========================================================================

func hashFile(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), int64(len(data)), nil
}

// collectWatchedFiles gathers all files to monitor with their categories.
func collectWatchedFiles(pol MonitorPolicy) []struct {
	path     string
	category WatchCategory
} {
	var files []struct {
		path     string
		category WatchCategory
	}

	for _, p := range pol.ServiceBinaries {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatServiceBinary})
	}
	for _, p := range pol.PolicyFiles {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatPolicyFile})
	}
	for _, dir := range pol.ModelDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			files = append(files, struct {
				path     string
				category WatchCategory
			}{filepath.Join(dir, e.Name()), CatModelFile})
		}
	}
	for _, p := range pol.SystemdUnits {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatSystemdUnit})
	}
	for _, p := range pol.TrustMaterial {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatTrustMaterial})
	}
	return files
}

// =========================================================================
// Baseline management
// =========================================================================

func computeBaseline(pol MonitorPolicy) SignedBaseline {
	files := collectWatchedFiles(pol)
	var entries []BaselineEntry

	for _, f := range files {
		hash, size, err := hashFile(f.path)
		if err != nil {
			continue // Skip missing files during baseline
		}
		entries = append(entries, BaselineEntry{
			Path:     f.path,
			Hash:     hash,
			Category: f.category,
			Size:     size,
		})
	}

	// Sort for deterministic ordering
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	bl := SignedBaseline{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
	}
	bl.HMAC = computeBaselineHMAC(bl)
	return bl
}

func computeBaselineHMAC(bl SignedBaseline) string {
	if len(hmacKey) == 0 {
		return "unsigned"
	}
	h := hmac.New(sha256.New, hmacKey)
	h.Write([]byte(bl.CreatedAt))
	for _, e := range bl.Entries {
		h.Write([]byte(fmt.Sprintf("|%s:%s:%s", e.Path, e.Hash, e.Category)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func verifyBaselineHMAC(bl SignedBaseline) bool {
	if len(hmacKey) == 0 {
		return bl.HMAC == "unsigned"
	}
	expected := computeBaselineHMAC(bl)
	return subtle.ConstantTimeCompare([]byte(bl.HMAC), []byte(expected)) == 1
}

func getBaseline() SignedBaseline {
	baselineMu.RLock()
	defer baselineMu.RUnlock()
	return baseline
}

func setBaseline(bl SignedBaseline) {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	baseline = bl
}

// =========================================================================
// Integrity scan
// =========================================================================

func performScan() (IntegrityState, []IntegrityViolation) {
	pol := getMonitorPolicy()
	bl := getBaseline()
	files := collectWatchedFiles(pol)

	// Build lookup from baseline
	baselineMap := make(map[string]BaselineEntry)
	for _, e := range bl.Entries {
		baselineMap[e.Path] = e
	}

	var violations []IntegrityViolation
	now := time.Now().UTC().Format(time.RFC3339)

	for _, f := range files {
		baseEntry, inBaseline := baselineMap[f.path]
		hash, _, err := hashFile(f.path)

		if err != nil {
			if inBaseline {
				// File was in baseline but now missing
				violations = append(violations, IntegrityViolation{
					DetectedAt:   now,
					Category:     f.category,
					Path:         f.path,
					ExpectedHash: baseEntry.Hash,
					ActualHash:   "missing",
					Action:       actionForCategory(f.category),
				})
			}
			continue
		}

		if inBaseline && hash != baseEntry.Hash {
			violations = append(violations, IntegrityViolation{
				DetectedAt:   now,
				Category:     f.category,
				Path:         f.path,
				ExpectedHash: baseEntry.Hash,
				ActualHash:   hash,
				Action:       actionForCategory(f.category),
			})
		}
	}

	// Check for files in baseline that are no longer watched (deleted)
	for path, entry := range baselineMap {
		found := false
		for _, f := range files {
			if f.path == path {
				found = true
				break
			}
		}
		if !found {
			// File was removed entirely
			violations = append(violations, IntegrityViolation{
				DetectedAt:   now,
				Category:     entry.Category,
				Path:         path,
				ExpectedHash: entry.Hash,
				ActualHash:   "removed",
				Action:       actionForCategory(entry.Category),
			})
		}
	}

	// Determine state
	state := StateTrusted
	if len(violations) > 0 {
		state = StateDegraded
		degradedCount.Add(1)
	}
	if len(violations) >= pol.DegradationThreshold {
		state = StateRecoveryRequired
		recoveryCount.Add(1)
	}

	scanCount.Add(1)

	// Update global state
	stateMu.Lock()
	currentState = state
	activeViolations = violations
	lastScanAt = now
	stateMu.Unlock()

	// Audit log
	for _, v := range violations {
		writeAudit(v)
	}

	log.Printf("scan complete: state=%s violations=%d watched=%d",
		state, len(violations), len(files))

	// Report violations to the incident-recorder (async, non-blocking).
	// Capture token to avoid race with global state reset.
	if len(violations) > 0 {
		token := serviceToken
		go reportViolations(state, violations, token)
	}

	return state, violations
}

func actionForCategory(cat WatchCategory) string {
	switch cat {
	case CatServiceBinary:
		return "degrade_appliance"
	case CatPolicyFile:
		return "reload_policy"
	case CatModelFile:
		return "quarantine_model"
	case CatSystemdUnit:
		return "degrade_appliance"
	case CatTrustMaterial:
		return "degrade_appliance"
	default:
		return "log_alert"
	}
}

func getCurrentStatus() StatusResponse {
	stateMu.RLock()
	defer stateMu.RUnlock()

	bl := getBaseline()
	return StatusResponse{
		State:            currentState,
		WatchedFiles:     len(bl.Entries),
		ViolationCount:   len(activeViolations),
		LastScanAt:       lastScanAt,
		ScanCount:        scanCount.Load(),
		DegradedCount:    degradedCount.Load(),
		RecoveryCount:    recoveryCount.Load(),
		ActiveViolations: activeViolations,
	}
}

// =========================================================================
// Audit logging
// =========================================================================

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/integrity-monitor-audit.jsonl"
	}
	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("warning: cannot create audit log dir: %v", err)
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

func writeAudit(v IntegrityViolation) {
	if auditFile == nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
}

// =========================================================================
// Service token auth
// =========================================================================

func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("warning: service token not loaded (%v) — running in dev mode", err)
		return
	}
	serviceToken = strings.TrimSpace(string(data))
}

func loadHMACKey() {
	pol := getMonitorPolicy()
	keyPath := pol.HMACKeyPath
	if keyPath == "" {
		keyPath = "/run/secure-ai/integrity-hmac-key"
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		log.Printf("warning: HMAC key not loaded (%v) — baselines will be unsigned", err)
		return
	}
	hmacKey = data
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

// =========================================================================
// HTTP handlers
// =========================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	state := currentState
	stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"state":  state,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := getCurrentStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bl := getBaseline()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bl)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, violations := performScan()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"state":      state,
		"violations": violations,
	})
}

func handleRebaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)
	log.Printf("baseline recomputed: %d entries", len(bl.Entries))

	// Clear violations after rebaseline
	stateMu.Lock()
	currentState = StateTrusted
	activeViolations = nil
	stateMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "rebaselined",
		"entries": len(bl.Entries),
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadMonitorPolicy(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	state := currentState
	stateMu.RUnlock()

	trusted := state == StateTrusted
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if !trusted {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"trusted": trusted,
		"state":   state,
	})
}

// =========================================================================
// Scan loop
// =========================================================================

func startScanLoop() {
	pol := getMonitorPolicy()
	interval := 30 * time.Second
	if pol.ScanInterval != "" {
		if d, err := time.ParseDuration(pol.ScanInterval); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			performScan()
		}
	}()
	log.Printf("continuous scan loop started: interval=%s", interval)
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadMonitorPolicy(); err != nil {
		log.Fatalf("failed to load monitor policy: %v", err)
	}

	initAuditLog()
	loadServiceToken()
	loadHMACKey()

	// Compute initial baseline
	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	setBaseline(bl)
	log.Printf("initial baseline: %d entries", len(bl.Entries))

	// Initial scan
	state, violations := performScan()
	log.Printf("initial scan: state=%s violations=%d", state, len(violations))

	// Start continuous scanning
	startScanLoop()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8510"
	}

	mux := http.NewServeMux()
	// Read-only endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/status", handleStatus)
	mux.HandleFunc("/api/v1/baseline", handleBaseline)
	mux.HandleFunc("/api/v1/verify", handleVerify)
	// Mutating endpoints (token-protected)
	mux.HandleFunc("/api/v1/scan", requireServiceToken(handleScan))
	mux.HandleFunc("/api/v1/rebaseline", requireServiceToken(handleRebaseline))
	mux.HandleFunc("/api/v1/reload", requireServiceToken(handleReload))

	log.Printf("secure-ai-integrity-monitor listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down integrity-monitor...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("integrity-monitor stopped")
}

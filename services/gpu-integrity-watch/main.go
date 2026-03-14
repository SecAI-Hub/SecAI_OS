package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------- profile / config types ----------

// IntegrityProfile is the top-level configuration loaded from YAML.
type IntegrityProfile struct {
	Version      int                    `yaml:"version"`
	ModelDir     string                 `yaml:"model_dir"`
	InferenceURL string                `yaml:"inference_url"`
	Probes       []ProbeConfig          `yaml:"probes"`
	Scoring      ScoringConfig          `yaml:"scoring"`
	Actions      []ActionConfig         `yaml:"actions"`
	Daemon       DaemonConfig           `yaml:"daemon"`
	BaselineFile string                 `yaml:"baseline_file"`
	Integrations IntegrationConfig      `yaml:"integrations"`
}

// ProbeConfig defines a single probe's configuration.
type ProbeConfig struct {
	Name     string            `yaml:"name" json:"name"`
	Type     ProbeType         `yaml:"type" json:"type"`
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Settings map[string]string `yaml:"settings,omitempty" json:"settings,omitempty"`
}

// ScoringConfig defines scoring engine parameters.
type ScoringConfig struct {
	Weights    map[string]float64 `yaml:"weights"`
	MaxHistory int                `yaml:"max_history"`
}

// DaemonConfig defines daemon mode settings.
type DaemonConfig struct {
	BindAddr string `yaml:"bind_addr"`
	Interval string `yaml:"interval"` // e.g. "5m"
}

// ---------- audit log ----------

var (
	auditMu   sync.Mutex
	auditFile *os.File
)

func initAudit(path string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("warning: cannot open audit log %s: %v", path, err)
		return
	}
	auditFile = f
}

func auditLog(event string, data map[string]interface{}) {
	if auditFile == nil {
		return
	}
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"event":     event,
	}
	for k, v := range data {
		entry[k] = v
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	json.NewEncoder(auditFile).Encode(entry)
}

// ---------- metrics ----------

var (
	metricChecks     atomic.Int64
	metricPass       atomic.Int64
	metricDrift      atomic.Int64
	metricFail       atomic.Int64
	metricActions    atomic.Int64
	metricHTTPReqs   atomic.Int64
)

// ---------- main ----------

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "check":
		cmdCheck()
	case "watch":
		cmdWatch()
	case "daemon":
		cmdDaemon()
	case "baseline":
		cmdBaseline()
	case "status":
		cmdStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gpu-integrity-watch — GPU model integrity monitoring

Usage:
  gpu-integrity-watch check     [-profile FILE]              Run probes once
  gpu-integrity-watch watch     [-profile FILE]              Watch continuously (foreground)
  gpu-integrity-watch daemon    [-profile FILE]              Run as HTTP daemon
  gpu-integrity-watch baseline  [-profile FILE] [-out FILE]  Capture baseline hashes
  gpu-integrity-watch status    [-addr ADDR]                 Query daemon status

Environment:
  INTEGRITY_PROFILE     Path to profile YAML (default: profiles/default-profile.yaml)
  SERVICE_TOKEN         Bearer token for protected endpoints
  AUDIT_LOG             Path to JSONL audit log
`)
}

// ---------- profile loading ----------

func loadProfile() *IntegrityProfile {
	path := envOr("INTEGRITY_PROFILE", "profiles/default-profile.yaml")
	for i, arg := range os.Args[2:] {
		if arg == "-profile" && i+1 < len(os.Args[2:])-1 {
			path = os.Args[i+3]
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to load profile %s: %v", path, err)
	}

	var profile IntegrityProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		log.Fatalf("failed to parse profile: %v", err)
	}
	return &profile
}

func loadBaseline(profile *IntegrityProfile) *Baseline {
	path := profile.BaselineFile
	if path == "" {
		path = "baseline.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil // no baseline yet
	}

	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		log.Printf("warning: failed to parse baseline: %v", err)
		return nil
	}
	return &b
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------- CLI commands ----------

func cmdCheck() {
	profile := loadProfile()
	baseline := loadBaseline(profile)
	initAudit(os.Getenv("AUDIT_LOG"))

	runner := NewProbeRunner(profile, baseline)
	results := runner.RunAll()

	weights := convertWeights(profile.Scoring.Weights)
	scorer := NewScoringEngine(weights, profile.Scoring.MaxHistory)
	entry := scorer.Score(results)

	executor := NewActionExecutor(profile.Actions, profile.ModelDir, profile.InferenceURL)
	actions := executor.Evaluate(entry)

	metricChecks.Add(1)
	countStatuses(results)

	output := map[string]interface{}{
		"probes":  results,
		"score":   entry,
		"actions": actions,
	}

	auditLog("check", map[string]interface{}{
		"verdict": entry.Verdict,
		"score":   entry.CompositeScore,
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)

	switch entry.Verdict {
	case VerdictCritical:
		os.Exit(2)
	case VerdictWarning:
		os.Exit(1)
	}
}

func cmdWatch() {
	profile := loadProfile()
	baseline := loadBaseline(profile)
	initAudit(os.Getenv("AUDIT_LOG"))

	interval := 5 * time.Minute
	if profile.Daemon.Interval != "" {
		if d, err := time.ParseDuration(profile.Daemon.Interval); err == nil {
			interval = d
		}
	}

	runner := NewProbeRunner(profile, baseline)
	weights := convertWeights(profile.Scoring.Weights)
	scorer := NewScoringEngine(weights, profile.Scoring.MaxHistory)
	executor := NewActionExecutor(profile.Actions, profile.ModelDir, profile.InferenceURL)

	log.Printf("watching at interval %s", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately
	runCycle(runner, scorer, executor)

	for range ticker.C {
		runCycle(runner, scorer, executor)
	}
}

func runCycle(runner *ProbeRunner, scorer *ScoringEngine, executor *ActionExecutor) {
	runCycleWithIntegrations(runner, scorer, executor, "", "")
}

func runCycleWithIntegrations(runner *ProbeRunner, scorer *ScoringEngine, executor *ActionExecutor, incidentURL, token string) {
	results := runner.RunAll()
	entry := scorer.Score(results)
	actions := executor.Evaluate(entry)

	metricChecks.Add(1)
	countStatuses(results)

	auditLog("cycle", map[string]interface{}{
		"verdict": entry.Verdict,
		"score":   entry.CompositeScore,
	})

	log.Printf("verdict=%s score=%.2f probes=%d actions=%d",
		entry.Verdict, entry.CompositeScore, len(results), len(actions))

	for _, a := range actions {
		if a.Triggered {
			metricActions.Add(1)
			log.Printf("  action=%s success=%v msg=%s", a.Action, a.Success, a.Message)
		}
	}

	// Report to incident-recorder on warning/critical
	reportIncident(incidentURL, token, entry, results)
}

func cmdBaseline() {
	profile := loadProfile()

	outFile := "baseline.yaml"
	for i, arg := range os.Args[2:] {
		if arg == "-out" && i+1 < len(os.Args[2:])-1 {
			outFile = os.Args[i+3]
		}
	}

	if profile.ModelDir == "" {
		log.Fatal("model_dir must be configured in profile to capture baseline")
	}

	patterns := []string{"*.gguf", "*.bin", "*.safetensors"}
	hashes := hashModelFiles(profile.ModelDir, patterns)

	if len(hashes) == 0 {
		log.Fatalf("no model files found in %s", profile.ModelDir)
	}

	baseline := Baseline{
		CapturedAt:   time.Now().UTC(),
		TensorHashes: hashes,
	}

	data, err := yaml.Marshal(&baseline)
	if err != nil {
		log.Fatalf("failed to marshal baseline: %v", err)
	}

	if err := os.WriteFile(outFile, data, 0o600); err != nil {
		log.Fatalf("failed to write baseline: %v", err)
	}

	fmt.Printf("baseline captured: %d files → %s\n", len(hashes), outFile)
}

func cmdStatus() {
	addr := envOr("DAEMON_ADDR", "http://127.0.0.1:8505")
	for i, arg := range os.Args[2:] {
		if arg == "-addr" && i+1 < len(os.Args[2:])-1 {
			addr = os.Args[i+3]
		}
	}

	resp, err := http.Get(addr + "/v1/status")
	if err != nil {
		log.Fatalf("cannot reach daemon: %v", err)
	}
	defer resp.Body.Close()

	var status map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&status)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(status)
}

// ---------- daemon ----------

func cmdDaemon() {
	profile := loadProfile()
	baseline := loadBaseline(profile)
	initAudit(os.Getenv("AUDIT_LOG"))

	runner := NewProbeRunner(profile, baseline)
	weights := convertWeights(profile.Scoring.Weights)
	scorer := NewScoringEngine(weights, profile.Scoring.MaxHistory)
	executor := NewActionExecutor(profile.Actions, profile.ModelDir, profile.InferenceURL)
	token := os.Getenv("SERVICE_TOKEN")

	// Background probe cycle
	interval := 5 * time.Minute
	if profile.Daemon.Interval != "" {
		if d, err := time.ParseDuration(profile.Daemon.Interval); err == nil {
			interval = d
		}
	}

	var latestMu sync.Mutex
	var latestResults []ProbeResult
	var latestActions []ActionResult

	// Integration URLs (incident reporting, attestation)
	incidentURL := profile.Integrations.IncidentRecorderURL
	if v := os.Getenv("INCIDENT_RECORDER_URL"); v != "" {
		incidentURL = v
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			results := runner.RunAll()
			entry := scorer.Score(results)
			actions := executor.Evaluate(entry)

			metricChecks.Add(1)
			countStatuses(results)

			latestMu.Lock()
			latestResults = results
			latestActions = actions
			latestMu.Unlock()

			auditLog("daemon_cycle", map[string]interface{}{
				"verdict": entry.Verdict,
				"score":   entry.CompositeScore,
			})

			log.Printf("cycle: verdict=%s score=%.2f", entry.Verdict, entry.CompositeScore)

			// Report incidents on warning/critical
			reportIncident(incidentURL, token, entry, results)

			<-ticker.C
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/check", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		results := runner.RunAll()
		entry := scorer.Score(results)
		actions := executor.Evaluate(entry)

		metricChecks.Add(1)
		countStatuses(results)

		latestMu.Lock()
		latestResults = results
		latestActions = actions
		latestMu.Unlock()

		auditLog("api_check", map[string]interface{}{
			"verdict": entry.Verdict,
			"score":   entry.CompositeScore,
			"source":  r.RemoteAddr,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"probes":  results,
			"score":   entry,
			"actions": actions,
		})
	})

	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		latest := scorer.Latest()
		trend := scorer.Trend(10)

		latestMu.Lock()
		probes := latestResults
		actions := latestActions
		latestMu.Unlock()

		status := map[string]interface{}{
			"latest":  latest,
			"trend":   trend,
			"probes":  probes,
			"actions": actions,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	mux.HandleFunc("/v1/history", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scorer.History())
	})

	mux.HandleFunc("/v1/baseline", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if profile.ModelDir == "" {
			http.Error(w, `{"error":"model_dir not configured"}`, http.StatusBadRequest)
			return
		}

		patterns := []string{"*.gguf", "*.bin", "*.safetensors"}
		hashes := hashModelFiles(profile.ModelDir, patterns)

		newBaseline := &Baseline{
			CapturedAt:   time.Now().UTC(),
			TensorHashes: hashes,
		}

		runner.baseline = newBaseline

		// Persist baseline
		bPath := profile.BaselineFile
		if bPath == "" {
			bPath = "baseline.yaml"
		}
		data, _ := yaml.Marshal(newBaseline)
		os.WriteFile(bPath, data, 0o600)

		auditLog("baseline_capture", map[string]interface{}{
			"files":  len(hashes),
			"source": r.RemoteAddr,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "baseline captured",
			"files":  len(hashes),
		})
	})

	mux.HandleFunc("/v1/reload", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		newProfile := loadProfile()
		newBaseline := loadBaseline(newProfile)

		*profile = *newProfile
		runner.profile = profile
		runner.baseline = newBaseline

		auditLog("profile_reload", map[string]interface{}{
			"source": r.RemoteAddr,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "profile reloaded"})
	})

	mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"checks_total":    metricChecks.Load(),
			"pass_total":      metricPass.Load(),
			"drift_total":     metricDrift.Load(),
			"fail_total":      metricFail.Load(),
			"actions_total":   metricActions.Load(),
			"http_reqs_total": metricHTTPReqs.Load(),
		})
	})

	// GPU attestation state endpoint — consumed by the runtime-attestor
	// to include GPU integrity in the signed attestation bundle.
	mux.HandleFunc("/v1/attest-state", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		latestMu.Lock()
		results := latestResults
		latestMu.Unlock()

		state := buildAttestState(scorer, results)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})

	addr := profile.Daemon.BindAddr
	if addr == "" {
		addr = "127.0.0.1:8505"
	}

	log.Printf("gpu-integrity-watch daemon listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---------- helpers ----------

func checkToken(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	provided := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func convertWeights(raw map[string]float64) map[ProbeType]float64 {
	if raw == nil {
		return nil
	}
	out := make(map[ProbeType]float64)
	for k, v := range raw {
		out[ProbeType(k)] = v
	}
	return out
}

func countStatuses(results []ProbeResult) {
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			metricPass.Add(1)
		case StatusDrift:
			metricDrift.Add(1)
		case StatusFail:
			metricFail.Add(1)
		}
	}
}

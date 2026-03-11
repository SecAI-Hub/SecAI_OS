package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
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

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type AttestationPolicy struct {
	Version     int          `yaml:"version"`
	Attestation AttestConfig `yaml:"attestation"`
}

type AttestConfig struct {
	Collectors CollectorToggle  `yaml:"collectors"`
	Model      ModelConfig      `yaml:"model"`
	Container  ContainerConfig  `yaml:"container"`
	Network    NetworkConfig    `yaml:"network"`
	Mount      MountConfig      `yaml:"mount"`
	GPU        GPUConfig        `yaml:"gpu"`
	Policy     PolicyFilesConfig `yaml:"policy"`
	Report     ReportConfig     `yaml:"report"`
	Daemon     DaemonConfig     `yaml:"daemon"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	Privacy    PrivacyProfile   `yaml:"privacy"`
}

type CollectorToggle struct {
	Model     bool `yaml:"model"`
	Container bool `yaml:"container"`
	Network   bool `yaml:"network"`
	Mount     bool `yaml:"mount"`
	GPU       bool `yaml:"gpu"`
	Policy    bool `yaml:"policy"`
}

type ModelConfig struct {
	VaultDir         string   `yaml:"vault_dir"`
	RegistryURL      string   `yaml:"registry_url"`
	RegistryTokenEnv string   `yaml:"registry_token_env"`
	AllowedFormats   []string `yaml:"allowed_formats"`
	MaxFileSize      int64    `yaml:"max_file_size"`
}

type ContainerConfig struct {
	Runtime        string   `yaml:"runtime"`
	ExpectedImages []string `yaml:"expected_images"`
}

type NetworkConfig struct {
	AllowedListeners         []string `yaml:"allowed_listeners"`
	DenyUnexpectedListeners  bool     `yaml:"deny_unexpected_listeners"`
}

type MountConfig struct {
	Expected []MountExpectation `yaml:"expected"`
}

type MountExpectation struct {
	Path     string `yaml:"path"`
	FSType   string `yaml:"fstype"`
	ReadOnly bool   `yaml:"readonly"`
}

type GPUConfig struct {
	AllowedDevices        []string `yaml:"allowed_devices"`
	DenyUnexpectedDevices bool     `yaml:"deny_unexpected_devices"`
}

type PolicyFilesConfig struct {
	Files          map[string]string `yaml:"files"`
	ApprovedHashes map[string]string `yaml:"approved_hashes"`
}

type ReportConfig struct {
	SigningKey string `yaml:"signing_key"`
	OutputDir  string `yaml:"output_dir"`
	Format     string `yaml:"format"`
}

type DaemonConfig struct {
	IntervalSeconds  int    `yaml:"interval_seconds"`
	BindAddr         string `yaml:"bind_addr"`
	ReadTimeoutSec   int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec  int    `yaml:"write_timeout_seconds"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// PrivacyProfile controls what gets stripped from audit logs and reports.
type PrivacyProfile struct {
	StripHostname    bool `yaml:"strip_hostname"`
	StripPaths       bool `yaml:"strip_paths"`
	StripListeners   bool `yaml:"strip_listeners"`
	StripPolicyNames bool `yaml:"strip_policy_names"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   AttestationPolicy

	latestReportMu sync.RWMutex
	latestReport   *TrustReport

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests   atomic.Int64
	attestRequests  atomic.Int64

	serviceToken string
)

const (
	defaultPolicyPath  = "/etc/secure-ai/policy/attestor.yaml"
	defaultTokenPath   = "/run/secure-ai/service-token"
	defaultAuditPath   = "/var/lib/secure-ai/logs/attestor-audit.jsonl"
	defaultBindAddr    = "127.0.0.1:8485"
	defaultRPM         = 60
	maxRequestBodySize = 1 << 20 // 1 MiB
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func loadPolicy() error {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p AttestationPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded from %s (version=%d)", policyFilePath(), p.Version)
	return nil
}

func getPolicy() AttestationPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Verdict   string `json:"verdict,omitempty"`
	Score     float64 `json:"score,omitempty"`
	Source    string `json:"source,omitempty"`
	Error     string `json:"error,omitempty"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	if err := os.MkdirAll(auditPath[:strings.LastIndex(auditPath, "/")], 0750); err != nil {
		log.Printf("warning: cannot create audit dir: %v", err)
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

func writeAudit(entry AuditEntry) {
	if auditFile == nil {
		return
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(entry)
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("service token not loaded (dev mode): %v", err)
		return
	}
	serviceToken = strings.TrimSpace(string(data))
	log.Printf("service token loaded")
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
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.Attestation.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

// ---------------------------------------------------------------------------
// Core attestation logic
// ---------------------------------------------------------------------------

// runAttestation executes all enabled collectors and returns a trust report.
func runAttestation() TrustReport {
	pol := getPolicy()
	cfg := pol.Attestation
	var results []CollectorResult

	if cfg.Collectors.Model {
		results = append(results, collectModelState(cfg.Model))
	}
	if cfg.Collectors.Container {
		results = append(results, collectContainerState(cfg.Container))
	}
	if cfg.Collectors.Network {
		results = append(results, collectNetworkState(cfg.Network))
	}
	if cfg.Collectors.Mount {
		results = append(results, collectMountState(cfg.Mount))
	}
	if cfg.Collectors.GPU {
		results = append(results, collectGPUState(cfg.GPU))
	}
	if cfg.Collectors.Policy {
		results = append(results, collectPolicyState(cfg.Policy))
	}

	att := compare(results)
	report := generateReport(att)

	// Apply privacy redaction if configured.
	if cfg.Privacy != (PrivacyProfile{}) {
		report = redactReport(report, cfg.Privacy)
	}

	// Sign if key is available (sign after redaction so signature covers redacted form).
	if cfg.Report.SigningKey != "" {
		signed, err := signReport(report, cfg.Report.SigningKey)
		if err != nil {
			log.Printf("warning: could not sign report: %v", err)
		} else {
			report = signed
		}
	}

	// Store as latest.
	latestReportMu.Lock()
	latestReport = &report
	latestReportMu.Unlock()

	writeAudit(AuditEntry{
		Action:  "attestation",
		Verdict: att.Verdict,
		Score:   att.Score,
	})

	log.Printf("attestation complete: verdict=%s score=%.2f collectors=%d",
		att.Verdict, att.Score, len(results))

	return report
}

// ---------------------------------------------------------------------------
// HTTP handlers (daemon mode)
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "runtime-attestor",
	})
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	attestRequests.Add(1)

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	report := runAttestation()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func handleLatestReport(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	latestReportMu.RLock()
	rpt := latestReport
	latestReportMu.RUnlock()

	if rpt == nil {
		http.Error(w, "no attestation report available yet", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rpt)
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := loadPolicy(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests":  totalRequests.Load(),
		"attest_requests": attestRequests.Load(),
	})
}

// ---------------------------------------------------------------------------
// Daemon mode
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string, interval time.Duration) {
	loadServiceToken()
	initAuditLog()

	mux := buildMux()

	// Run initial attestation.
	runAttestation()

	// Periodic attestation.
	if interval > 0 {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				runAttestation()
			}
		}()
		log.Printf("periodic attestation every %s", interval)
	}

	pol := getPolicy()
	readTimeout := pol.Attestation.Daemon.ReadTimeoutSec
	if readTimeout <= 0 {
		readTimeout = 30
	}
	writeTimeout := pol.Attestation.Daemon.WriteTimeoutSec
	if writeTimeout <= 0 {
		writeTimeout = 60
	}

	srv := &http.Server{
		Addr:         bindAddr,
		Handler:      mux,
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
	}

	log.Printf("runtime-attestor daemon listening on %s", bindAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// buildMux constructs the HTTP handler. Auth required on all non-health endpoints.
func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/attest", requireServiceToken(handleAttest))
	mux.HandleFunc("/v1/report/latest", requireServiceToken(handleLatestReport))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdAttest(policyPath, outputPath, format, keyPath string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Override signing key if provided via flag.
	if keyPath != "" {
		policyMu.Lock()
		policy.Attestation.Report.SigningKey = keyPath
		policyMu.Unlock()
	}

	report := runAttestation()

	var data []byte
	var err error
	if format == "pretty" {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling report: %v\n", err)
		return 1
	}

	if outputPath != "" && outputPath != "-" {
		if err := os.WriteFile(outputPath, append(data, '\n'), 0640); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}

	// Exit code reflects verdict.
	switch report.Attestation.Verdict {
	case "pass":
		return 0
	case "drift":
		return 2
	default:
		return 3
	}
}

func cmdVerify(reportPath, pubKeyPath string) int {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading report: %v\n", err)
		return 1
	}

	var report TrustReport
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing report: %v\n", err)
		return 1
	}

	if report.Signature == "" {
		fmt.Fprintf(os.Stderr, "report is unsigned\n")
		return 1
	}

	if err := verifyReport(report, pubKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
		return 1
	}

	fmt.Printf("signature valid\n")
	fmt.Printf("  verdict:  %s\n", report.Attestation.Verdict)
	fmt.Printf("  score:    %.2f\n", report.Attestation.Score)
	fmt.Printf("  hostname: %s\n", report.Hostname)
	fmt.Printf("  signed:   %s\n", report.SignedAt)
	return 0
}

func cmdKeygen(privPath, pubPath string) int {
	if err := generateKeypair(privPath, pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("keypair generated:\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return 0
}

func cmdDaemon(policyPath, bindAddr string, intervalSec int) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if bindAddr == "" {
		bindAddr = getPolicy().Attestation.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}

	interval := time.Duration(intervalSec) * time.Second
	if intervalSec <= 0 {
		sec := getPolicy().Attestation.Daemon.IntervalSeconds
		if sec <= 0 {
			sec = 300
		}
		interval = time.Duration(sec) * time.Second
	}

	runDaemon(bindAddr, interval)
	return 0
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "attest":
		fs := flag.NewFlagSet("attest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		output := fs.String("output", "-", "output file (- for stdout)")
		format := fs.String("format", "pretty", "output format: json, pretty")
		key := fs.String("key", "", "signing key path (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdAttest(*policyPath, *output, *format, *key))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		reportPath := fs.String("report", "", "path to trust report file")
		pubKey := fs.String("pubkey", "", "path to public key file")
		fs.Parse(os.Args[2:])
		if *reportPath == "" {
			fmt.Fprintf(os.Stderr, "error: -report is required\n")
			os.Exit(1)
		}
		os.Exit(cmdVerify(*reportPath, *pubKey))

	case "daemon":
		fs := flag.NewFlagSet("daemon", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		interval := fs.Int("interval", 0, "attestation interval seconds (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdDaemon(*policyPath, *bind, *interval))

	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		privPath := fs.String("priv", "attestor.key", "private key output path")
		pubPath := fs.String("pub", "attestor.pub", "public key output path")
		fs.Parse(os.Args[2:])
		os.Exit(cmdKeygen(*privPath, *pubPath))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `runtime-attestor — runtime trust verification for SecAI_OS

Usage:
  runtime-attestor <command> [options]

Commands:
  attest    Run attestation and emit a signed trust report
  verify    Verify the signature on a trust report
  daemon    Run as HTTP daemon with periodic attestation
  keygen    Generate ed25519 signing keypair

Exit codes (attest):
  0  All checks passed
  2  Drift detected
  3  Hard failure detected

Use "runtime-attestor <command> -h" for command-specific options.
`)
}

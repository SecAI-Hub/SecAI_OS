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
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Attestation state types
// =========================================================================

// AttestationState tracks the overall appliance trust state.
type AttestationState string

const (
	StateAttested AttestationState = "attested"
	StateDegraded AttestationState = "degraded"
	StateFailed   AttestationState = "failed"
	StatePending  AttestationState = "pending"
)

// RuntimeStateBundle is the signed evidence emitted at boot and periodically.
type RuntimeStateBundle struct {
	Timestamp            string            `json:"timestamp" yaml:"timestamp"`
	State                AttestationState  `json:"state" yaml:"state"`
	BootMeasurements     BootMeasurements  `json:"boot_measurements" yaml:"boot_measurements"`
	DeploymentDigest     string            `json:"deployment_digest" yaml:"deployment_digest"`
	ServiceDigests       map[string]string `json:"service_digests" yaml:"service_digests"`
	PolicyDigest         string            `json:"policy_digest" yaml:"policy_digest"`
	RegistryManifestHash string            `json:"registry_manifest_hash" yaml:"registry_manifest_hash"`
	KernelCmdline        string            `json:"kernel_cmdline" yaml:"kernel_cmdline"`
	KernelLockdown       string            `json:"kernel_lockdown" yaml:"kernel_lockdown"`
	TPMAvailable         bool              `json:"tpm_available" yaml:"tpm_available"`
	TPMQuoteVerified     bool              `json:"tpm_quote_verified" yaml:"tpm_quote_verified"`
	Failures             []string          `json:"failures,omitempty" yaml:"failures,omitempty"`
	BundleHMAC           string            `json:"bundle_hmac" yaml:"bundle_hmac"`
}

// BootMeasurements captures TPM2 PCR values and Secure Boot state.
type BootMeasurements struct {
	SecureBootEnabled bool              `json:"secure_boot_enabled" yaml:"secure_boot_enabled"`
	PCRValues         map[string]string `json:"pcr_values,omitempty" yaml:"pcr_values,omitempty"`
	MeasuredAt        string            `json:"measured_at" yaml:"measured_at"`
}

// AttestationPolicy defines what must be verified.
type AttestationPolicy struct {
	Version           int               `yaml:"version"`
	RequireTPM        bool              `yaml:"require_tpm"`
	RequireSecureBoot bool              `yaml:"require_secure_boot"`
	ExpectedPCRs      map[string]string `yaml:"expected_pcrs"`
	ServiceBinaries   map[string]string `yaml:"service_binaries"`
	PolicyFiles       []string          `yaml:"policy_files"`
	RefreshInterval   string            `yaml:"refresh_interval"`
	HMACKeyPath       string            `yaml:"hmac_key_path"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	stateMu       sync.RWMutex
	currentState  AttestationState = StatePending
	currentBundle RuntimeStateBundle

	attestPolicy   AttestationPolicy
	attestPolicyMu sync.RWMutex

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	serviceToken string
	hmacKey      []byte

	attestCount  atomic.Int64
	degradeCount atomic.Int64
	failCount    atomic.Int64
)

const maxRequestBodySize = 64 * 1024

// =========================================================================
// Policy loading
// =========================================================================

func attestPolicyPath() string {
	p := os.Getenv("ATTESTATION_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/attestation.yaml"
	}
	return p
}

func loadAttestPolicy() error {
	data, err := os.ReadFile(attestPolicyPath())
	if err != nil {
		// Use defaults if no policy file
		log.Printf("warning: attestation policy not found (%v) — using defaults", err)
		attestPolicyMu.Lock()
		attestPolicy = AttestationPolicy{
			Version:           1,
			RequireTPM:        false,
			RequireSecureBoot: false,
			RefreshInterval:   "5m",
			ServiceBinaries: map[string]string{
				"registry":      "/usr/libexec/secure-ai/registry",
				"tool-firewall": "/usr/libexec/secure-ai/tool-firewall",
				"airlock":       "/usr/libexec/secure-ai/airlock",
				"policy-engine": "/usr/libexec/secure-ai/policy-engine",
			},
			PolicyFiles: []string{
				"/etc/secure-ai/policy/policy.yaml",
				"/etc/secure-ai/policy/agent.yaml",
			},
		}
		attestPolicyMu.Unlock()
		return nil
	}

	var pol AttestationPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return fmt.Errorf("cannot parse attestation policy: %w", err)
	}
	attestPolicyMu.Lock()
	attestPolicy = pol
	attestPolicyMu.Unlock()
	log.Printf("attestation policy loaded: require_tpm=%t require_sb=%t services=%d",
		pol.RequireTPM, pol.RequireSecureBoot, len(pol.ServiceBinaries))
	return nil
}

func getAttestPolicy() AttestationPolicy {
	attestPolicyMu.RLock()
	defer attestPolicyMu.RUnlock()
	return attestPolicy
}

// =========================================================================
// Measurement collectors
// =========================================================================

// collectBootMeasurements reads Secure Boot status and TPM2 PCR values.
func collectBootMeasurements(pol AttestationPolicy) (BootMeasurements, bool, []string) {
	m := BootMeasurements{
		MeasuredAt: time.Now().UTC().Format(time.RFC3339),
		PCRValues:  make(map[string]string),
	}
	var failures []string
	tpmAvailable := false

	// Check Secure Boot
	sbData, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err == nil && len(sbData) >= 5 {
		m.SecureBootEnabled = sbData[4] == 1
	}
	if pol.RequireSecureBoot && !m.SecureBootEnabled {
		failures = append(failures, "Secure Boot not enabled (required by policy)")
	}

	// Read TPM2 PCR values
	out, err := exec.Command("tpm2_pcrread", "sha256:0,2,4,7").Output()
	if err != nil {
		if pol.RequireTPM {
			failures = append(failures, fmt.Sprintf("TPM2 not available: %v", err))
		}
	} else {
		tpmAvailable = true
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") && strings.Contains(line, "0x") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					pcr := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					m.PCRValues[pcr] = val
				}
			}
		}

		// Verify expected PCR values
		for pcr, expected := range pol.ExpectedPCRs {
			if actual, ok := m.PCRValues[pcr]; ok {
				if actual != expected {
					failures = append(failures, fmt.Sprintf("PCR %s mismatch: expected=%s actual=%s", pcr, expected, actual))
				}
			}
		}
	}

	return m, tpmAvailable, failures
}

// collectDeploymentDigest reads the current rpm-ostree deployment digest.
func collectDeploymentDigest() string {
	out, err := exec.Command("rpm-ostree", "status", "--json").Output()
	if err != nil {
		return "unavailable"
	}
	h := sha256.Sum256(out)
	return hex.EncodeToString(h[:16])
}

// collectServiceDigests hashes each service binary.
func collectServiceDigests(binaries map[string]string) (map[string]string, []string) {
	digests := make(map[string]string)
	var failures []string

	for name, path := range binaries {
		data, err := os.ReadFile(path)
		if err != nil {
			digests[name] = "missing"
			failures = append(failures, fmt.Sprintf("service binary missing: %s (%s)", name, path))
			continue
		}
		h := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(h[:])
	}
	return digests, failures
}

// collectPolicyDigest hashes all policy files together.
func collectPolicyDigest(files []string) string {
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// collectRegistryManifestHash hashes the registry manifest file.
func collectRegistryManifestHash() string {
	data, err := os.ReadFile("/var/lib/secure-ai/registry/manifest.json")
	if err != nil {
		return "unavailable"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// collectKernelState reads kernel cmdline and lockdown state.
func collectKernelState() (string, string) {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	lockdown, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return strings.TrimSpace(string(cmdline)), "unavailable"
	}
	return strings.TrimSpace(string(cmdline)), strings.TrimSpace(string(lockdown))
}

// =========================================================================
// Attestation engine
// =========================================================================

func computeBundleHMAC(bundle RuntimeStateBundle) string {
	if len(hmacKey) == 0 {
		return "unsigned"
	}
	// HMAC over the deterministic fields
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%t",
		bundle.Timestamp, bundle.State, bundle.DeploymentDigest,
		bundle.PolicyDigest, bundle.RegistryManifestHash,
		bundle.TPMAvailable, bundle.TPMQuoteVerified)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func performAttestation() RuntimeStateBundle {
	pol := getAttestPolicy()

	boot, tpmAvail, bootFailures := collectBootMeasurements(pol)
	svcDigests, svcFailures := collectServiceDigests(pol.ServiceBinaries)
	policyDigest := collectPolicyDigest(pol.PolicyFiles)
	registryHash := collectRegistryManifestHash()
	cmdline, lockdown := collectKernelState()
	deployDigest := collectDeploymentDigest()

	// Combine all failures
	var failures []string
	failures = append(failures, bootFailures...)
	failures = append(failures, svcFailures...)

	// Determine state
	state := StateAttested
	tpmVerified := tpmAvail && len(bootFailures) == 0

	if len(failures) > 0 {
		state = StateDegraded
		degradeCount.Add(1)
	}
	// Critical failures → failed state
	for _, f := range failures {
		if strings.Contains(f, "not available") && pol.RequireTPM {
			state = StateFailed
			failCount.Add(1)
			break
		}
		if strings.Contains(f, "not enabled") && pol.RequireSecureBoot {
			state = StateFailed
			failCount.Add(1)
			break
		}
	}

	attestCount.Add(1)

	bundle := RuntimeStateBundle{
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		State:                state,
		BootMeasurements:     boot,
		DeploymentDigest:     deployDigest,
		ServiceDigests:       svcDigests,
		PolicyDigest:         policyDigest,
		RegistryManifestHash: registryHash,
		KernelCmdline:        cmdline,
		KernelLockdown:       lockdown,
		TPMAvailable:         tpmAvail,
		TPMQuoteVerified:     tpmVerified,
		Failures:             failures,
	}
	bundle.BundleHMAC = computeBundleHMAC(bundle)

	// Store as current state
	stateMu.Lock()
	currentState = state
	currentBundle = bundle
	stateMu.Unlock()

	log.Printf("attestation complete: state=%s tpm=%t sb=%t failures=%d",
		state, tpmAvail, boot.SecureBootEnabled, len(failures))

	// Audit log
	writeAudit(bundle)

	// Report degraded/failed attestation to the incident-recorder (async).
	// Capture token to avoid race with global state reset in tests.
	if state == StateDegraded || state == StateFailed {
		token := serviceToken
		go reportAttestationFailure(bundle, token)
	}

	return bundle
}

func getCurrentState() (AttestationState, RuntimeStateBundle) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return currentState, currentBundle
}

// =========================================================================
// Audit logging
// =========================================================================

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/runtime-attestor-audit.jsonl"
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

func writeAudit(bundle RuntimeStateBundle) {
	if auditFile == nil {
		return
	}
	data, err := json.Marshal(bundle)
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
	pol := getAttestPolicy()
	keyPath := pol.HMACKeyPath
	if keyPath == "" {
		keyPath = "/run/secure-ai/attestation-hmac-key"
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		log.Printf("warning: HMAC key not loaded (%v) — bundles will be unsigned", err)
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
	state, _ := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"state":  state,
	})
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state, bundle := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"state":  state,
		"bundle": bundle,
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle := performAttestation()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	state, bundle := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attestation_state":  state,
		"tpm_available":      bundle.TPMAvailable,
		"tpm_quote_verified": bundle.TPMQuoteVerified,
		"secure_boot":        bundle.BootMeasurements.SecureBootEnabled,
		"policy_digest":      bundle.PolicyDigest,
		"deployment_digest":  bundle.DeploymentDigest,
		"service_count":      len(bundle.ServiceDigests),
		"failure_count":      len(bundle.Failures),
		"last_attested":      bundle.Timestamp,
		"attest_count":       attestCount.Load(),
		"degrade_count":      degradeCount.Load(),
		"fail_count":         failCount.Load(),
	})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	state, _ := getCurrentState()
	verified := state == StateAttested
	w.Header().Set("Content-Type", "application/json")

	status := http.StatusOK
	if !verified {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified": verified,
		"state":    state,
	})
}

// =========================================================================
// Periodic refresh loop
// =========================================================================

func startRefreshLoop() {
	pol := getAttestPolicy()
	interval := 5 * time.Minute
	if pol.RefreshInterval != "" {
		if d, err := time.ParseDuration(pol.RefreshInterval); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			performAttestation()
		}
	}()
	log.Printf("attestation refresh loop started: interval=%s", interval)
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadAttestPolicy(); err != nil {
		log.Fatalf("failed to load attestation policy: %v", err)
	}

	initAuditLog()
	loadServiceToken()
	loadHMACKey()

	// Initial attestation at startup
	bundle := performAttestation()
	log.Printf("initial attestation: state=%s", bundle.State)

	// Start periodic refresh
	startRefreshLoop()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8505"
	}

	mux := http.NewServeMux()
	// Read-only endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/attest", handleAttest)
	mux.HandleFunc("/api/v1/verify", handleVerify)
	mux.HandleFunc("/api/security/status", handleSecurityStatus)
	// Mutating endpoints
	mux.HandleFunc("/api/v1/refresh", requireServiceToken(handleRefresh))

	log.Printf("secure-ai-runtime-attestor listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
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
	log.Println("shutting down runtime-attestor...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	if auditFile != nil {
		auditFile.Close()
	}
	log.Println("runtime-attestor stopped")
}

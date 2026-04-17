package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type PolicyFile struct {
	Airlock AirlockPolicy `yaml:"airlock"`
}

type AirlockPolicy struct {
	Enabled             bool         `yaml:"enabled"`
	AllowedDestinations []string     `yaml:"allowed_destinations"`
	ContentRules        ContentRules `yaml:"content_rules"`
	RateLimit           RateConfig   `yaml:"rate_limit"`
	MaxBodySize         int          `yaml:"max_body_size"`
	AllowedMethods      []string     `yaml:"allowed_methods"`
}

type ContentRules struct {
	BlockIfContains    []string `yaml:"block_if_contains"`
	ScanForPII         bool     `yaml:"scan_for_pii"`
	ScanForCredentials bool     `yaml:"scan_for_credentials"`
}

type RateConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// SourcesAllowlist loaded from sources.allowlist.yaml for model download URLs.
type SourcesAllowlist struct {
	Models []SourceEntry `yaml:"models"`
}

type SourceEntry struct {
	Name      string `yaml:"name"`
	URLPrefix string `yaml:"url_prefix"`
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

type EgressRequest struct {
	Destination string `json:"destination"`
	Method      string `json:"method"`
	Body        string `json:"body"`
}

type EgressResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   AirlockPolicy

	sourcesMu      sync.RWMutex
	sourcePrefixes []string

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	// Rate limiting
	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	// Stats
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	allowedRequests atomic.Int64
)

var serviceToken string // loaded at startup; empty = dev mode (no auth)

const (
	defaultMaxBodySize    = 10 * 1024 * 1024 // 10 MB
	defaultRequestsPerMin = 30
	maxRequestBodySize    = 64 * 1024 // 64 KB for the check request itself
)

// loadServiceToken reads the service-to-service auth token from disk.
// If the file does not exist, token auth is disabled (dev/test mode).
func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("warning: service token not loaded (%v) — running in dev mode (no token auth)", err)
		return
	}
	serviceToken = strings.TrimSpace(string(data))
	if serviceToken == "" {
		log.Printf("warning: service token file is empty — running in dev mode (no token auth)")
		return
	}
	log.Printf("service token loaded from %s", tokenPath)
}

// requireServiceToken wraps a handler to enforce Bearer token auth on mutating endpoints.
// If no token was loaded at startup (dev mode), all requests pass through.
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
// PII / credential patterns
// ---------------------------------------------------------------------------

var piiPatterns = []*regexp.Regexp{
	// SSN (US)
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	// Credit card (Visa, MC, Amex, Discover)
	regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b`),
	// Email
	regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
	// Phone (US/international)
	regexp.MustCompile(`\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b`),
	// IP addresses (private ranges are fine, but flag all for review)
	regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
}

var credentialPatterns = []*regexp.Regexp{
	// Key=value credential patterns
	regexp.MustCompile(`(?i)(password|passwd|secret|api_key|apikey|token|auth_token|access_token|private_key)\s*[:=]\s*\S+`),
	// Bearer tokens
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
	// AWS keys
	regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
	// GitHub tokens
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
	// Base64-encoded secrets (long strings that look like keys)
	regexp.MustCompile(`(?i)(key|secret|token)\s*[:=]\s*[A-Za-z0-9+/]{40,}={0,2}`),
}

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	p := os.Getenv("POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/policy.yaml"
	}
	return p
}

func sourcesFilePath() string {
	p := os.Getenv("SOURCES_ALLOWLIST_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/sources.allowlist.yaml"
	}
	return p
}

func loadPolicy() error {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	policyMu.Lock()
	policy = pf.Airlock
	policyMu.Unlock()
	log.Printf("policy loaded: enabled=%t destinations=%d", pf.Airlock.Enabled, len(pf.Airlock.AllowedDestinations))
	return nil
}

func loadSources() error {
	data, err := os.ReadFile(sourcesFilePath())
	if err != nil {
		// Sources file is optional
		log.Printf("sources.allowlist.yaml not found; using policy destinations only")
		return nil
	}
	var sa SourcesAllowlist
	if err := yaml.Unmarshal(data, &sa); err != nil {
		return fmt.Errorf("parse sources: %w", err)
	}
	var prefixes []string
	for _, s := range sa.Models {
		if s.URLPrefix != "" {
			prefixes = append(prefixes, s.URLPrefix)
		}
	}
	sourcesMu.Lock()
	sourcePrefixes = prefixes
	sourcesMu.Unlock()
	log.Printf("sources loaded: %d URL prefixes", len(prefixes))
	return nil
}

func getPolicy() AirlockPolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policy
}

func getSourcePrefixes() []string {
	sourcesMu.RLock()
	defer sourcesMu.RUnlock()
	return sourcePrefixes
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	Destination string `json:"destination"`
	Method      string `json:"method"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason,omitempty"`
	BodySize    int    `json:"body_size"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/airlock-audit.jsonl"
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

func writeAudit(entry AuditEntry) {
	if auditFile == nil {
		return
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit(pol AirlockPolicy) bool {
	rpm := pol.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRequestsPerMin
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
// Validation
// ---------------------------------------------------------------------------

func validateDestination(dest string) error {
	if dest == "" {
		return fmt.Errorf("empty destination")
	}
	parsed, err := url.Parse(dest)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	// Only HTTPS allowed for egress
	if parsed.Scheme != "https" {
		return fmt.Errorf("only HTTPS allowed, got %q", parsed.Scheme)
	}
	// Block localhost/private IPs in destination
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "172.") {
		return fmt.Errorf("private/localhost destinations not allowed")
	}
	return nil
}

func isDestinationAllowed(dest string, pol AirlockPolicy) bool {
	// Check policy destinations
	for _, allowed := range pol.AllowedDestinations {
		if destinationMatchesAllowlist(dest, allowed) {
			return true
		}
	}
	// Check sources.allowlist.yaml prefixes
	for _, prefix := range getSourcePrefixes() {
		if destinationMatchesAllowlist(dest, prefix) {
			return true
		}
	}
	return false
}

func hasURLPathPrefix(candidate, prefix string) bool {
	prefix = path.Clean(prefix)
	candidate = path.Clean(candidate)
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func destinationMatchesAllowlist(dest, allowed string) bool {
	destURL, destErr := url.Parse(dest)
	allowedURL, allowedErr := url.Parse(allowed)

	if destErr == nil && allowedErr == nil && destURL.Scheme != "" && allowedURL.Scheme != "" && destURL.Host != "" && allowedURL.Host != "" {
		if !strings.EqualFold(destURL.Scheme, allowedURL.Scheme) {
			return false
		}
		if !strings.EqualFold(destURL.Host, allowedURL.Host) {
			return false
		}
		if allowedURL.Path == "" || allowedURL.Path == "/" {
			return true
		}
		return hasURLPathPrefix(destURL.Path, allowedURL.Path)
	}

	if destErr == nil && destURL.Hostname() != "" && !strings.Contains(allowed, "://") && !strings.Contains(allowed, "/") {
		return strings.EqualFold(destURL.Hostname(), allowed)
	}

	return false
}

func isMethodAllowed(method string, pol AirlockPolicy) bool {
	if len(pol.AllowedMethods) == 0 {
		// Default: only GET and POST
		return method == "GET" || method == "POST"
	}
	upper := strings.ToUpper(method)
	for _, m := range pol.AllowedMethods {
		if strings.ToUpper(m) == upper {
			return true
		}
	}
	return false
}

func scanContent(body string, rules ContentRules) (bool, string) {
	// Check explicit block patterns
	bodyLower := strings.ToLower(body)
	for _, pattern := range rules.BlockIfContains {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true, fmt.Sprintf("body contains blocked pattern: %q", pattern)
		}
	}

	// PII scan
	if rules.ScanForPII {
		for _, pat := range piiPatterns {
			if pat.MatchString(body) {
				return true, "detected PII pattern: " + pat.String()
			}
		}
	}

	// Credential scan
	if rules.ScanForCredentials {
		for _, pat := range credentialPatterns {
			if pat.MatchString(body) {
				return true, "detected credential pattern: " + pat.String()
			}
		}
	}

	return false, ""
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleEgressCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pol := getPolicy()

	if !pol.Enabled {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EgressResponse{Allowed: false, Reason: "airlock is disabled"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req EgressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	totalRequests.Add(1)

	respond := func(allowed bool, reason string) {
		if allowed {
			allowedRequests.Add(1)
		} else {
			blockedRequests.Add(1)
		}
		log.Printf("airlock: dest=%s method=%s allowed=%t reason=%q", req.Destination, req.Method, allowed, reason)
		writeAudit(AuditEntry{
			Destination: req.Destination,
			Method:      req.Method,
			Allowed:     allowed,
			Reason:      reason,
			BodySize:    len(req.Body),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EgressResponse{Allowed: allowed, Reason: reason})
	}

	// Rate limit
	if !checkRateLimit(pol) {
		respond(false, "rate limit exceeded")
		return
	}

	// Validate destination URL
	if err := validateDestination(req.Destination); err != nil {
		respond(false, err.Error())
		return
	}

	// Method check
	if !isMethodAllowed(req.Method, pol) {
		respond(false, fmt.Sprintf("method %q not allowed", req.Method))
		return
	}

	// Destination allowlist
	if !isDestinationAllowed(req.Destination, pol) {
		respond(false, "destination not in allowlist")
		return
	}

	// Body size check
	maxBody := pol.MaxBodySize
	if maxBody <= 0 {
		maxBody = defaultMaxBodySize
	}
	if len(req.Body) > maxBody {
		respond(false, fmt.Sprintf("body too large: %d > %d bytes", len(req.Body), maxBody))
		return
	}

	// Content scanning
	if blocked, reason := scanContent(req.Body, pol.ContentRules); blocked {
		respond(false, reason)
		return
	}

	respond(true, "")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"enabled": pol.Enabled,
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":              pol.Enabled,
		"total_requests":       totalRequests.Load(),
		"blocked_requests":     blockedRequests.Load(),
		"allowed_requests":     allowedRequests.Load(),
		"allowed_destinations": len(pol.AllowedDestinations) + len(getSourcePrefixes()),
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var errs []string
	if err := loadPolicy(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := loadSources(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": errs})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if err := loadPolicy(); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}
	if err := loadSources(); err != nil {
		log.Printf("warning: %v", err)
	}

	initAuditLog()
	loadServiceToken()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8490"
	}

	mux := http.NewServeMux()
	// Read-only endpoints — no auth required
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/egress/check", handleEgressCheck)
	mux.HandleFunc("/v1/stats", handleStats)
	// Mutating endpoints — require service token
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))

	log.Printf("secure-ai-airlock listening on %s (enabled=%t)", bind, policy.Enabled)
	server := &http.Server{
		Addr:              bind,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
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
	log.Println("shutting down airlock...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("airlock stopped")
}

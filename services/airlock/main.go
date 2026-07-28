package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
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
	MaxResponseSize     int64        `yaml:"max_response_size"`
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

// FetchRequest describes an outbound request that the airlock itself performs.
// Callers never receive a general-purpose network route.
type FetchRequest struct {
	Destination string            `json:"destination"`
	Method      string            `json:"method"`
	Body        string            `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   AirlockPolicy

	sourcePrefixes []string

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	// Per-caller rate limiting. A single global bucket let one local process
	// deny egress to every other service.
	rateMu      sync.Mutex
	rateBuckets = make(map[string]*rateBucket)

	// Stats
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	allowedRequests atomic.Int64

	// Containment is a sticky, persisted latch. Policy reloads and service
	// restarts must not silently restore egress after an incident.
	containmentDisabled atomic.Bool
	containmentToken    string

	// Bound the number of long-lived upstream streams. Rate limiting alone
	// does not prevent a caller from opening many slow concurrent downloads.
	fetchSlots = make(chan struct{}, maxConcurrentFetches)
)

type airlockSnapshot struct {
	policy         AirlockPolicy
	sourcePrefixes []string
}

var serviceToken string

type containmentState struct {
	Disabled   bool   `json:"disabled"`
	IncidentID string `json:"incident_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	DisabledAt string `json:"disabled_at,omitempty"`
}

const (
	defaultMaxBodySize     = 10 * 1024 * 1024               // 10 MB
	defaultMaxResponseSize = int64(64) * 1024 * 1024 * 1024 // 64 GiB model ceiling
	defaultRequestsPerMin  = 30
	maxRequestBodySize     = 64 * 1024 // 64 KB for the check request itself
	maxPolicyFileSize      = 2 * 1024 * 1024
	maxDestinationSize     = 8192
	maxQuerySize           = 4096
	maxPolicyDestinations  = 2048
	maxBlockPatterns       = 1024
	maxHeaderCount         = 16
	maxHeaderValueSize     = 16 * 1024
	maxConcurrentFetches   = 8
	maxFetchDuration       = 2 * time.Hour
	maxConfiguredBodySize  = 64 * 1024 * 1024
	maxConfiguredResponse  = int64(64) * 1024 * 1024 * 1024
	maxConfiguredRPM       = 10000
)

// loadServiceToken reads the service-to-service auth token from disk.
// Authentication is fail-closed; an explicit loopback-only development
// override is available for local tests.
func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		serviceToken = ""
		return fmt.Errorf("read service token: %w", err)
	}
	serviceToken = strings.TrimSpace(string(data))
	if serviceToken == "" {
		return fmt.Errorf("service token file is empty")
	}
	log.Printf("service token loaded from %s", tokenPath)
	return nil
}

func loadContainmentToken() error {
	containmentToken = ""
	tokenPath := strings.TrimSpace(os.Getenv("CONTAINMENT_TOKEN_PATH"))
	if tokenPath == "" {
		return fmt.Errorf("CONTAINMENT_TOKEN_PATH is not configured")
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("read containment token: %w", err)
	}
	containmentToken = strings.TrimSpace(string(data))
	if containmentToken == "" {
		return fmt.Errorf("containment token file is empty")
	}
	return nil
}

// requireServiceToken enforces Bearer auth on every policy decision and fetch.
func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return serviceToken }, next)
}

func requireContainmentToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return containmentToken }, next)
}

func requireBearerToken(tokenSource func() string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := tokenSource()
		if expected == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "service authentication unavailable"})
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
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

func allowInsecureLoopbackDev(bind string) bool {
	if os.Getenv("SECAI_ALLOW_INSECURE_NO_AUTH") != "1" {
		return false
	}
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func containmentStatePath() string {
	if configured := strings.TrimSpace(os.Getenv("AIRLOCK_CONTAINMENT_STATE_PATH")); configured != "" {
		return configured
	}
	return "/var/lib/secure-ai/airlock/containment.json"
}

func loadContainmentState() error {
	data, err := os.ReadFile(containmentStatePath())
	if os.IsNotExist(err) {
		containmentDisabled.Store(false)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read airlock containment state: %w", err)
	}
	var state containmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse airlock containment state: %w", err)
	}
	containmentDisabled.Store(state.Disabled)
	return nil
}

func persistContainmentState(state containmentState) error {
	statePath := containmentStatePath()
	if err := os.MkdirAll(filepath.Dir(statePath), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(statePath), ".containment-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0640); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, statePath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(statePath))
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	return err
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

func readBoundedConfig(configPath string) ([]byte, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPolicyFileSize {
		return nil, fmt.Errorf("configuration is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicyFileSize {
		return nil, fmt.Errorf("configuration exceeds %d bytes", maxPolicyFileSize)
	}
	return data, nil
}

func parsePolicy() (AirlockPolicy, error) {
	data, err := readBoundedConfig(policyFilePath())
	if err != nil {
		return AirlockPolicy{}, fmt.Errorf("read policy: %w", err)
	}
	var pf PolicyFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&pf); err != nil {
		return AirlockPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return AirlockPolicy{}, fmt.Errorf("parse policy: multiple YAML documents are not allowed")
	}
	if err := validatePolicy(pf.Airlock); err != nil {
		return AirlockPolicy{}, fmt.Errorf("validate policy: %w", err)
	}
	return pf.Airlock, nil
}

func parseSources() ([]string, error) {
	data, err := readBoundedConfig(sourcesFilePath())
	if os.IsNotExist(err) {
		// Optional means absent is an explicit empty source set. This avoids
		// retaining destinations from a deleted allowlist after reload.
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sources: %w", err)
	}
	var sa SourcesAllowlist
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&sa); err != nil {
		return nil, fmt.Errorf("parse sources: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("parse sources: multiple YAML documents are not allowed")
	}
	if len(sa.Models) > maxPolicyDestinations {
		return nil, fmt.Errorf("too many source allowlist entries")
	}
	prefixes := make([]string, 0, len(sa.Models))
	for _, source := range sa.Models {
		prefix := strings.TrimSpace(source.URLPrefix)
		if prefix == "" {
			continue
		}
		if err := validateAllowlistEntry(prefix); err != nil {
			return nil, fmt.Errorf("source %q: %w", source.Name, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func loadConfiguration() error {
	// Stage and validate both files before taking the write lock. Readers see
	// either the complete old snapshot or the complete new snapshot.
	nextPolicy, err := parsePolicy()
	if err != nil {
		return err
	}
	nextSources, err := parseSources()
	if err != nil {
		return err
	}
	policyMu.Lock()
	policy = nextPolicy
	sourcePrefixes = append([]string(nil), nextSources...)
	policyMu.Unlock()
	log.Printf(
		"airlock configuration loaded: enabled=%t destinations=%d sources=%d",
		nextPolicy.Enabled,
		len(nextPolicy.AllowedDestinations),
		len(nextSources),
	)
	return nil
}

func getPolicy() AirlockPolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policy
}

func getSourcePrefixes() []string {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return append([]string(nil), sourcePrefixes...)
}

func getSnapshot() airlockSnapshot {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return airlockSnapshot{
		policy:         policy,
		sourcePrefixes: append([]string(nil), sourcePrefixes...),
	}
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

type rateBucket struct {
	count  int64
	window time.Time
}

func rateLimitKey(r *http.Request) string {
	// Do not trust a caller-supplied service label. RemoteAddr is supplied by
	// the HTTP server after authentication and maps to the calling container.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func checkRateLimit(pol AirlockPolicy, key string) bool {
	rpm := pol.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRequestsPerMin
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	bucket := rateBuckets[key]
	if bucket == nil || now.Sub(bucket.window) > time.Minute {
		bucket = &rateBucket{window: now}
		rateBuckets[key] = bucket
	}
	bucket.count++

	// Bound state retained for callers that disappear.
	if len(rateBuckets) > 2048 {
		for bucketKey, candidate := range rateBuckets {
			if now.Sub(candidate.window) > 2*time.Minute {
				delete(rateBuckets, bucketKey)
			}
		}
	}
	return bucket.count <= int64(rpm)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func validateDestination(dest string) error {
	if dest == "" {
		return fmt.Errorf("empty destination")
	}
	if len(dest) > maxDestinationSize {
		return fmt.Errorf("destination exceeds %d bytes", maxDestinationSize)
	}
	parsed, err := url.Parse(dest)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	// Only HTTPS allowed for egress
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("only HTTPS allowed, got %q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("destination hostname is required")
	}
	if parsed.User != nil {
		return fmt.Errorf("URL userinfo is not allowed")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("URL fragments are not allowed")
	}
	if len(parsed.RawQuery) > maxQuerySize {
		return fmt.Errorf("URL query exceeds %d bytes", maxQuerySize)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("private/localhost destinations not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("private/reserved destinations not allowed")
	}
	return nil
}

func validateAllowlistEntry(entry string) error {
	if entry == "" || entry != strings.TrimSpace(entry) {
		return fmt.Errorf("allowlist entry is empty or contains surrounding whitespace")
	}
	candidate := entry
	if !strings.Contains(candidate, "://") {
		if strings.ContainsAny(candidate, "/?#@") {
			return fmt.Errorf("hostname-only allowlist entries cannot contain URL components")
		}
		candidate = "https://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return fmt.Errorf("invalid allowlist URL: %w", err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("allowlist entries cannot contain query, userinfo, or fragment")
	}
	if err := validateDestination(candidate); err != nil {
		return err
	}
	return nil
}

func validatePolicy(pol AirlockPolicy) error {
	if len(pol.AllowedDestinations) > maxPolicyDestinations {
		return fmt.Errorf("too many allowed destinations")
	}
	for index, destination := range pol.AllowedDestinations {
		if err := validateAllowlistEntry(destination); err != nil {
			return fmt.Errorf("allowed destination %d: %w", index, err)
		}
	}
	if pol.MaxBodySize < 0 || pol.MaxBodySize > maxConfiguredBodySize {
		return fmt.Errorf("max_body_size must be between 0 and %d", maxConfiguredBodySize)
	}
	if pol.MaxResponseSize < 0 || pol.MaxResponseSize > maxConfiguredResponse {
		return fmt.Errorf("max_response_size must be between 0 and %d", maxConfiguredResponse)
	}
	rpm := pol.RateLimit.RequestsPerMinute
	if rpm < 0 || rpm > maxConfiguredRPM {
		return fmt.Errorf("requests_per_minute must be between 0 and %d", maxConfiguredRPM)
	}
	if len(pol.ContentRules.BlockIfContains) > maxBlockPatterns {
		return fmt.Errorf("too many content block patterns")
	}
	for _, pattern := range pol.ContentRules.BlockIfContains {
		if len(pattern) > 1024 {
			return fmt.Errorf("content block pattern exceeds 1024 bytes")
		}
	}
	for _, method := range pol.AllowedMethods {
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case http.MethodGet, http.MethodPost, http.MethodHead:
		default:
			return fmt.Errorf("unsafe or unsupported allowed method %q", method)
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if !ip.IsGlobalUnicast() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedSpecialNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

var blockedSpecialNetworks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",   // carrier-grade NAT
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmark testing
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved
		"2001:2::/48",     // benchmark testing
		"2001:db8::/32",   // documentation
		"2001:10::/28",    // ORCHID
		"ff00::/8",        // multicast
	}
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}()

// publicOnlyDialContext resolves and validates every address immediately
// before connecting. This closes the DNS-rebinding gap between a policy check
// and the actual outbound socket.
func publicOnlyDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream address: %w", err)
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("upstream resolved to no addresses")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		if isBlockedIP(ip) {
			lastErr = fmt.Errorf("upstream resolved to blocked address")
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no public upstream address")
	}
	return nil, lastErr
}

func newFetchClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           publicOnlyDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0, // model bodies are streamed and bounded by policy
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return validateRedirect(req, via, getSnapshot())
	}
	return client
}

func validateRedirect(req *http.Request, via []*http.Request, snapshot airlockSnapshot) error {
	if len(via) >= 8 {
		return fmt.Errorf("too many redirects")
	}
	if err := validateDestination(req.URL.String()); err != nil {
		return err
	}
	if !isDestinationAllowedWithSources(
		req.URL.String(),
		snapshot.policy,
		snapshot.sourcePrefixes,
	) {
		return fmt.Errorf("redirect destination not in allowlist")
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		req.Header.Del("Authorization")
	}
	return nil
}

var fetchClient = newFetchClient()

func isDestinationAllowed(dest string, pol AirlockPolicy) bool {
	return isDestinationAllowedWithSources(dest, pol, getSourcePrefixes())
}

func isDestinationAllowedWithSources(dest string, pol AirlockPolicy, prefixes []string) bool {
	// Check policy destinations
	for _, allowed := range pol.AllowedDestinations {
		if destinationMatchesAllowlist(dest, allowed) {
			return true
		}
	}
	// Check sources.allowlist.yaml prefixes
	for _, prefix := range prefixes {
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

func evaluateEgress(req EgressRequest, pol AirlockPolicy, rateKey string) (bool, string) {
	return evaluateEgressWithSources(req, pol, getSourcePrefixes(), rateKey)
}

func evaluateEgressWithSources(
	req EgressRequest,
	pol AirlockPolicy,
	prefixes []string,
	rateKey string,
) (bool, string) {
	if !pol.Enabled {
		return false, "airlock is disabled"
	}
	if !checkRateLimit(pol, rateKey) {
		return false, "rate limit exceeded"
	}
	if err := validateDestination(req.Destination); err != nil {
		return false, err.Error()
	}
	if !isMethodAllowed(req.Method, pol) {
		return false, fmt.Sprintf("method %q not allowed", req.Method)
	}
	if !isDestinationAllowedWithSources(req.Destination, pol, prefixes) {
		return false, "destination not in allowlist"
	}
	maxBody := pol.MaxBodySize
	if maxBody <= 0 {
		maxBody = defaultMaxBodySize
	}
	if len(req.Body) > maxBody {
		return false, fmt.Sprintf("body too large: %d > %d bytes", len(req.Body), maxBody)
	}
	if blocked, reason := scanContent(req.Body, pol.ContentRules); blocked {
		return false, reason
	}
	return true, ""
}

func safeAuditDestination(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	// Query strings can contain signed download credentials. Keep only the
	// routing information needed for an audit.
	return (&url.URL{
		Scheme:  parsed.Scheme,
		Host:    parsed.Host,
		Path:    parsed.Path,
		RawPath: parsed.RawPath,
	}).String()
}

func recordDecision(req EgressRequest, allowed bool, reason string) {
	if allowed {
		allowedRequests.Add(1)
	} else {
		blockedRequests.Add(1)
	}
	totalRequests.Add(1)
	destination := safeAuditDestination(req.Destination)
	log.Printf("airlock: dest=%s method=%s allowed=%t reason=%q", destination, req.Method, allowed, reason)
	writeAudit(AuditEntry{
		Destination: destination,
		Method:      req.Method,
		Allowed:     allowed,
		Reason:      reason,
		BodySize:    len(req.Body),
	})
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func decodeSingleJSON(body io.Reader, destination interface{}) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func handleEgressCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req EgressRequest
	if err := decodeSingleJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	respond := func(allowed bool, reason string) {
		recordDecision(req, allowed, reason)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EgressResponse{Allowed: allowed, Reason: reason})
	}

	if containmentDisabled.Load() {
		respond(false, "airlock disabled by incident containment")
		return
	}
	snapshot := getSnapshot()
	allowed, reason := evaluateEgressWithSources(
		req,
		snapshot.policy,
		snapshot.sourcePrefixes,
		rateLimitKey(r),
	)
	respond(allowed, reason)
}

var allowedUpstreamHeaders = map[string]bool{
	"Accept":        true,
	"Authorization": true,
	"Range":         true,
}

var copiedResponseHeaders = []string{
	"Content-Type",
	"Content-Range",
	"Accept-Ranges",
	"ETag",
	"Last-Modified",
}

// handleFetch is the enforced data path. It performs the outbound request and
// streams the response, so an application container never needs direct egress.
func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req FetchRequest
	if err := decodeSingleJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	decisionReq := EgressRequest{
		Destination: req.Destination,
		Method:      method,
		Body:        req.Body,
	}
	if containmentDisabled.Load() {
		recordDecision(decisionReq, false, "airlock disabled by incident containment")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(EgressResponse{
			Allowed: false,
			Reason:  "airlock disabled by incident containment",
		})
		return
	}
	snapshot := getSnapshot()
	pol := snapshot.policy
	allowed, reason := evaluateEgressWithSources(
		decisionReq,
		pol,
		snapshot.sourcePrefixes,
		rateLimitKey(r),
	)
	recordDecision(decisionReq, allowed, reason)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(EgressResponse{Allowed: false, Reason: reason})
		return
	}

	if len(req.Headers) > maxHeaderCount {
		http.Error(w, "too many upstream headers", http.StatusBadRequest)
		return
	}
	select {
	case fetchSlots <- struct{}{}:
		defer func() { <-fetchSlots }()
	default:
		http.Error(w, "too many concurrent fetches", http.StatusTooManyRequests)
		return
	}
	fetchContext, cancelFetch := context.WithTimeout(r.Context(), maxFetchDuration)
	defer cancelFetch()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(maxFetchDuration))

	upstreamReq, err := http.NewRequestWithContext(
		fetchContext,
		method,
		req.Destination,
		strings.NewReader(req.Body),
	)
	if err != nil {
		http.Error(w, "invalid upstream request", http.StatusBadRequest)
		return
	}
	for name, value := range req.Headers {
		canonical := http.CanonicalHeaderKey(name)
		if !allowedUpstreamHeaders[canonical] {
			http.Error(w, "unsupported upstream header", http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(value, "\r\n") {
			http.Error(w, "invalid upstream header value", http.StatusBadRequest)
			return
		}
		if len(value) > maxHeaderValueSize {
			http.Error(w, "upstream header value is too large", http.StatusBadRequest)
			return
		}
		upstreamReq.Header.Set(canonical, value)
	}
	upstreamReq.Header.Set("User-Agent", "SecAI-Airlock/1")

	requestClient := *fetchClient
	requestClient.CheckRedirect = func(
		redirected *http.Request,
		via []*http.Request,
	) error {
		return validateRedirect(redirected, via, snapshot)
	}
	resp, err := requestClient.Do(upstreamReq)
	if err != nil {
		log.Printf("airlock upstream request failed for %s: %v", safeAuditDestination(req.Destination), err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	maxResponse := pol.MaxResponseSize
	if maxResponse <= 0 {
		maxResponse = defaultMaxResponseSize
	}
	if resp.ContentLength > maxResponse {
		http.Error(w, "upstream response exceeds policy limit", http.StatusRequestEntityTooLarge)
		return
	}

	for _, name := range copiedResponseHeaders {
		if value := resp.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.Header().Set("X-SecAI-Upstream-URL", safeAuditDestination(resp.Request.URL.String()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Add("Trailer", "X-SecAI-Response-Truncated")
	w.WriteHeader(resp.StatusCode)

	written, copyErr := io.CopyN(w, resp.Body, maxResponse)
	if copyErr != nil && copyErr != io.EOF {
		log.Printf("airlock response stream failed after %d bytes: %v", written, copyErr)
		return
	}
	if written == maxResponse {
		if resp.ContentLength != maxResponse {
			w.Header().Set("X-SecAI-Response-Truncated", "true")
			log.Printf("airlock terminated response at the %d byte policy limit", maxResponse)
		}
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":               "ok",
		"enabled":              pol.Enabled && !containmentDisabled.Load(),
		"containment_disabled": containmentDisabled.Load(),
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":              pol.Enabled && !containmentDisabled.Load(),
		"containment_disabled": containmentDisabled.Load(),
		"total_requests":       totalRequests.Load(),
		"blocked_requests":     blockedRequests.Load(),
		"allowed_requests":     allowedRequests.Load(),
		"allowed_destinations": len(pol.AllowedDestinations) + len(getSourcePrefixes()),
	})
}

func handleDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req struct {
		Action     string `json:"action"`
		IncidentID string `json:"incident_id"`
		Reason     string `json:"reason"`
	}
	if err := decodeSingleJSON(r.Body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Action != "disable" || strings.TrimSpace(req.IncidentID) == "" {
		http.Error(w, "action=disable and incident_id are required", http.StatusBadRequest)
		return
	}
	state := containmentState{
		Disabled:   true,
		IncidentID: strings.TrimSpace(req.IncidentID),
		Reason:     strings.TrimSpace(req.Reason),
		DisabledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := persistContainmentState(state); err != nil {
		http.Error(w, "cannot persist containment latch", http.StatusInternalServerError)
		return
	}
	containmentDisabled.Store(true)
	log.Printf("CONTAINMENT: airlock disabled by incident %s", state.IncidentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "disabled",
		"incident_id": state.IncidentID,
		"persisted":   true,
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadConfiguration(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "configuration reload rejected; previous snapshot remains active",
		})
		log.Printf("airlock configuration reload rejected: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func newAirlockMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Liveness contains no policy details and remains unauthenticated.
	mux.HandleFunc("/health", handleHealth)
	// Policy, usage, containment, and egress endpoints require a service identity.
	mux.HandleFunc("/v1/egress/check", requireServiceToken(handleEgressCheck))
	mux.HandleFunc("/v1/fetch", requireServiceToken(handleFetch))
	mux.HandleFunc("/v1/stats", requireServiceToken(handleStats))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/api/v1/disable", requireContainmentToken(handleDisable))
	return mux
}

func main() {
	if err := loadConfiguration(); err != nil {
		log.Fatalf("failed to load airlock configuration: %v", err)
	}
	if err := loadContainmentState(); err != nil {
		log.Fatalf("containment state unavailable: %v", err)
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8490"
	}

	initAuditLog()
	if err := loadServiceToken(); err != nil {
		if !allowInsecureLoopbackDev(bind) {
			log.Fatalf("service authentication required: %v", err)
		}
		log.Printf("warning: explicit loopback-only insecure development mode: %v", err)
	}
	if err := loadContainmentToken(); err != nil {
		if strings.TrimSpace(os.Getenv("CONTAINMENT_TOKEN_PATH")) != "" {
			log.Fatalf("containment authentication required: %v", err)
		}
		log.Printf("containment endpoint disabled: %v", err)
	}

	log.Printf("secure-ai-airlock listening on %s (enabled=%t)", bind, policy.Enabled)
	server := &http.Server{
		Addr:              bind,
		Handler:           newAirlockMux(),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Fetch responses may stream multi-gigabyte model files. The response
		// size, connect, TLS, and header phases are bounded separately.
		WriteTimeout:   0,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
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

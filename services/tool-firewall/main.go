package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

type Policy struct {
	Version  int            `yaml:"version"`
	Defaults PolicyDefaults `yaml:"defaults"`
	Tools    ToolsPolicy    `yaml:"tools"`
}

type PolicyDefaults struct {
	Network struct {
		RuntimeEgress string `yaml:"runtime_egress"`
	} `yaml:"network"`
	Logging struct {
		StoreRawPrompts   bool `yaml:"store_raw_prompts"`
		StoreRawResponses bool `yaml:"store_raw_responses"`
	} `yaml:"logging"`
}

type ToolsPolicy struct {
	Default    string      `yaml:"default"`
	Allow      []ToolEntry `yaml:"allow"`
	Deny       []ToolEntry `yaml:"deny"`
	RateLimit  RateConfig  `yaml:"rate_limit"`
}

type ToolEntry struct {
	Name           string   `yaml:"name"`
	PathsAllowlist []string `yaml:"paths_allowlist"`
	PathsDenylist  []string `yaml:"paths_denylist"`
	ArgsBlacklist  []string `yaml:"args_blocklist"`
	MaxArgLength   int      `yaml:"max_arg_length"`
}

type RateConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	BurstSize         int `yaml:"burst_size"`
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

type ToolCallRequest struct {
	Tool   string            `json:"tool"`
	Params map[string]string `json:"params"`
}

type ToolCallResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   Policy

	auditFile   *os.File
	auditMu     sync.Mutex
	auditPath   string

	// Rate limiting: simple sliding window counter
	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	// Stats
	totalRequests  atomic.Int64
	deniedRequests atomic.Int64
)

var serviceToken string // loaded at startup; empty = dev mode (no auth)

const (
	defaultMaxArgLength     = 4096
	defaultRequestsPerMin   = 120
	defaultBurstSize        = 20
	maxRequestBodySize      = 64 * 1024 // 64 KB
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
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	p := os.Getenv("POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/policy.yaml"
	}
	return p
}

func loadPolicy() error {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return err
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return err
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded: default=%s allow=%d deny=%d",
		p.Tools.Default, len(p.Tools.Allow), len(p.Tools.Deny))
	return nil
}

func getPolicy() Policy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policy
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Tool      string `json:"tool"`
	Params    map[string]string `json:"params,omitempty"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason,omitempty"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/tool-firewall-audit.jsonl"
	}
	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("warning: cannot create audit log dir %s: %v", dir, err)
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log %s: %v", auditPath, err)
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

func checkRateLimit(pol Policy) bool {
	rpm := pol.Tools.RateLimit.RequestsPerMinute
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
// Path security
// ---------------------------------------------------------------------------

// cleanAndResolvePath canonicalizes a path, catching traversal attempts.
func cleanAndResolvePath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	// Reject null bytes (path injection via null terminator)
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("path contains null byte")
	}
	cleaned := filepath.Clean(raw)
	// Resolve to absolute to catch ../../../etc/shadow style attacks
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	return abs, nil
}

// matchesGlob checks if a path matches an allowlist pattern.
// Supports trailing ** for recursive match (prefix match) and exact prefix match.
func matchesGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = filepath.Clean(prefix)
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.HasSuffix(pattern, "**") {
		prefix := strings.TrimSuffix(pattern, "**")
		prefix = filepath.Clean(prefix)
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, filepath.Clean(pattern))
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

func validateArgs(params map[string]string, entry ToolEntry) (bool, string) {
	maxLen := entry.MaxArgLength
	if maxLen <= 0 {
		maxLen = defaultMaxArgLength
	}

	for key, val := range params {
		// Length check
		if len(val) > maxLen {
			return false, fmt.Sprintf("argument %q exceeds max length (%d > %d)", key, len(val), maxLen)
		}

		// Blocked argument patterns (e.g., shell injection attempts)
		for _, blocked := range entry.ArgsBlacklist {
			if strings.Contains(strings.ToLower(val), strings.ToLower(blocked)) {
				return false, fmt.Sprintf("argument %q contains blocked pattern %q", key, blocked)
			}
		}
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

func evaluateTool(req ToolCallRequest) ToolCallResponse {
	pol := getPolicy()

	// Rate limit check
	if !checkRateLimit(pol) {
		return ToolCallResponse{Allowed: false, Reason: "rate limit exceeded"}
	}

	// Check deny list first (deny always wins)
	for _, denied := range pol.Tools.Deny {
		if denied.Name == req.Tool {
			return ToolCallResponse{Allowed: false, Reason: "tool is explicitly denied"}
		}
	}

	// Default deny mode
	if pol.Tools.Default != "allow" {
		var matched *ToolEntry
		for i, allowed := range pol.Tools.Allow {
			if allowed.Name == req.Tool {
				matched = &pol.Tools.Allow[i]
				break
			}
		}
		if matched == nil {
			return ToolCallResponse{Allowed: false, Reason: "tool not in allowlist"}
		}

		// Validate arguments
		if ok, reason := validateArgs(req.Params, *matched); !ok {
			return ToolCallResponse{Allowed: false, Reason: reason}
		}

		// Check path constraints
		if path, ok := req.Params["path"]; ok && path != "" {
			resolved, err := cleanAndResolvePath(path)
			if err != nil {
				return ToolCallResponse{Allowed: false, Reason: "invalid path: " + err.Error()}
			}

			// Check denylist first
			for _, denied := range matched.PathsDenylist {
				if matchesGlob(resolved, denied) {
					return ToolCallResponse{Allowed: false, Reason: "path matches denylist"}
				}
			}

			// Check allowlist
			if len(matched.PathsAllowlist) > 0 {
				pathAllowed := false
				for _, pattern := range matched.PathsAllowlist {
					if matchesGlob(resolved, pattern) {
						pathAllowed = true
						break
					}
				}
				if !pathAllowed {
					return ToolCallResponse{Allowed: false, Reason: "path not in allowlist"}
				}
			}
		}

		return ToolCallResponse{Allowed: true}
	}

	// Default allow mode (not recommended, but supported)
	return ToolCallResponse{Allowed: true}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req ToolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	totalRequests.Add(1)
	resp := evaluateTool(req)

	if !resp.Allowed {
		deniedRequests.Add(1)
	}

	// Structured logging
	log.Printf("tool-firewall: tool=%s allowed=%t reason=%q", req.Tool, resp.Allowed, resp.Reason)

	// Audit log
	writeAudit(AuditEntry{
		Tool:    req.Tool,
		Params:  req.Params,
		Allowed: resp.Allowed,
		Reason:  resp.Reason,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"total_requests":  totalRequests.Load(),
		"denied_requests": deniedRequests.Load(),
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadPolicy(); err != nil {
		log.Printf("policy reload failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	log.Printf("policy reloaded successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"default_action":  pol.Tools.Default,
		"allowed_tools":   len(pol.Tools.Allow),
		"denied_tools":    len(pol.Tools.Deny),
		"total_requests":  totalRequests.Load(),
		"denied_requests": deniedRequests.Load(),
	})
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if err := loadPolicy(); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	initAuditLog()
	loadServiceToken()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8475"
	}

	mux := http.NewServeMux()
	// Read-only endpoints — no auth required
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/evaluate", handleEvaluate)
	mux.HandleFunc("/v1/stats", handleStats)
	// Mutating endpoints — require service token
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))

	log.Printf("secure-ai-tool-firewall listening on %s", bind)
	server := &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down tool-firewall...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("tool-firewall stopped")
}

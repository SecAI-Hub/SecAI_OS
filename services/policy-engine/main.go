package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Domain types — request / response for the unified decision API
// =========================================================================

// DecisionDomain enumerates the policy domains the engine can evaluate.
type DecisionDomain string

const (
	DomainToolAccess      DecisionDomain = "tool_access"
	DomainPathAccess      DecisionDomain = "path_access"
	DomainEgress          DecisionDomain = "egress"
	DomainAgentRisk       DecisionDomain = "agent_risk"
	DomainSensitivity     DecisionDomain = "sensitivity"
	DomainModelPromotion  DecisionDomain = "model_promotion"
)

// DecisionRequest is sent by any service needing a policy decision.
type DecisionRequest struct {
	Domain      DecisionDomain    `json:"domain"`
	Subject     string            `json:"subject"`               // e.g. tool name, path, destination
	Action      string            `json:"action,omitempty"`       // e.g. "read", "write", "invoke"
	SessionMode string            `json:"session_mode,omitempty"` // "offline_only", "standard", "sensitive"
	Params      map[string]string `json:"params,omitempty"`       // domain-specific context
}

// DecisionResponse is the unified policy decision result.
type DecisionResponse struct {
	Decision string           `json:"decision"` // "allow", "deny", "ask"
	Reason   string           `json:"reason"`
	Evidence DecisionEvidence `json:"evidence"`
}

// DecisionEvidence is a structured provenance object attached to every decision.
type DecisionEvidence struct {
	Timestamp    string `json:"timestamp"`
	Domain       string `json:"domain"`
	PolicyDigest string `json:"policy_digest"` // SHA-256 of loaded policy files
	RuleID       string `json:"rule_id"`       // which rule matched
	InputHash    string `json:"input_hash"`    // SHA-256 of the request
	EvalTimeUs   int64  `json:"eval_time_us"`  // evaluation duration in microseconds
}

// =========================================================================
// Policy types — loaded from YAML
// =========================================================================

// UnifiedPolicy is the top-level structure combining both policy.yaml and agent.yaml.
type UnifiedPolicy struct {
	// From policy.yaml
	Defaults struct {
		Network struct {
			RuntimeEgress string `yaml:"runtime_egress"`
		} `yaml:"network"`
	} `yaml:"defaults"`

	Tools ToolsPolicy `yaml:"tools"`

	Airlock struct {
		Enabled      bool     `yaml:"enabled"`
		Destinations []string `yaml:"destination_allowlist"`
	} `yaml:"airlock"`

	Models struct {
		AllowedFormats []string `yaml:"allowed_formats"`
		DenyFormats    []string `yaml:"deny_formats"`
	} `yaml:"models"`

	// From agent.yaml
	Agent AgentPolicy `yaml:"agent"`
}

// ToolsPolicy defines tool invocation rules.
type ToolsPolicy struct {
	Default   string      `yaml:"default"`
	Allow     []ToolRule  `yaml:"allow"`
	Deny      []ToolRule  `yaml:"deny"`
	RateLimit RateConfig  `yaml:"rate_limit"`
}

// ToolRule defines a single tool allow/deny rule.
type ToolRule struct {
	Name           string   `yaml:"name"`
	PathsAllowlist []string `yaml:"paths_allowlist"`
	PathsDenylist  []string `yaml:"paths_denylist"`
}

// RateConfig defines rate limiting parameters.
type RateConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	BurstSize         int `yaml:"burst_size"`
}

// AgentPolicy defines agent-specific policy rules.
type AgentPolicy struct {
	DefaultMode string            `yaml:"default_mode"`
	AlwaysDeny  []string          `yaml:"always_deny"`
	HardApproval []string         `yaml:"hard_approval"`
	AllowedTools []string         `yaml:"allowed_tools"`
	Workspace    WorkspacePolicy  `yaml:"workspace"`
	Budgets      map[string]Budget `yaml:"budgets"`
}

// WorkspacePolicy defines path scope rules for agent operations.
type WorkspacePolicy struct {
	Readable []string `yaml:"readable"`
	Writable []string `yaml:"writable"`
}

// Budget defines resource limits per session mode.
type Budget struct {
	MaxSteps    int `yaml:"max_steps"`
	MaxTools    int `yaml:"max_tool_calls"`
	MaxTokens   int `yaml:"max_tokens"`
	MaxWallSec  int `yaml:"max_wall_clock_seconds"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	policyMu     sync.RWMutex
	unifiedPolicy UnifiedPolicy
	policyDigest string // SHA-256 of combined policy files

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	serviceToken string

	// Rate limiting
	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	// Stats
	totalRequests  atomic.Int64
	allowedCount   atomic.Int64
	deniedCount    atomic.Int64
	askCount       atomic.Int64
)

const maxRequestBodySize = 64 * 1024 // 64 KB

// =========================================================================
// Policy loading
// =========================================================================

func policyPath() string {
	p := os.Getenv("POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/policy.yaml"
	}
	return p
}

func agentPolicyPath() string {
	p := os.Getenv("AGENT_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/agent.yaml"
	}
	return p
}

func loadPolicies() error {
	var combined UnifiedPolicy
	var hashInput []byte

	// Load main policy
	pData, err := os.ReadFile(policyPath())
	if err != nil {
		return fmt.Errorf("cannot read policy: %w", err)
	}
	if err := yaml.Unmarshal(pData, &combined); err != nil {
		return fmt.Errorf("cannot parse policy: %w", err)
	}
	hashInput = append(hashInput, pData...)

	// Load agent policy (overlay onto combined)
	aData, err := os.ReadFile(agentPolicyPath())
	if err != nil {
		log.Printf("warning: agent policy not found (%v) — using defaults", err)
	} else {
		var agentCfg struct {
			Agent AgentPolicy `yaml:"agent"`
		}
		if err := yaml.Unmarshal(aData, &agentCfg); err != nil {
			return fmt.Errorf("cannot parse agent policy: %w", err)
		}
		combined.Agent = agentCfg.Agent
		hashInput = append(hashInput, aData...)
	}

	// Compute digest of all policy inputs
	h := sha256.Sum256(hashInput)
	digest := hex.EncodeToString(h[:])

	policyMu.Lock()
	unifiedPolicy = combined
	policyDigest = digest
	policyMu.Unlock()

	log.Printf("policies loaded: digest=%s tools_allow=%d tools_deny=%d agent_deny=%d",
		digest[:12], len(combined.Tools.Allow), len(combined.Tools.Deny),
		len(combined.Agent.AlwaysDeny))
	return nil
}

func getPolicy() (UnifiedPolicy, string) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return unifiedPolicy, policyDigest
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
	if serviceToken == "" {
		log.Printf("warning: service token file is empty — running in dev mode")
	}
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
// Audit logging
// =========================================================================

type AuditEntry struct {
	Timestamp string           `json:"timestamp"`
	Domain    string           `json:"domain"`
	Subject   string           `json:"subject"`
	Action    string           `json:"action,omitempty"`
	Decision  string           `json:"decision"`
	Reason    string           `json:"reason"`
	Evidence  DecisionEvidence `json:"evidence"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/policy-engine-audit.jsonl"
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

// =========================================================================
// Decision engine — the core evaluator
// =========================================================================

func evaluate(req DecisionRequest) DecisionResponse {
	start := time.Now()
	pol, digest := getPolicy()

	// Compute input hash for evidence
	reqJSON, _ := json.Marshal(req)
	inputHash := sha256.Sum256(reqJSON)

	makeEvidence := func(ruleID string) DecisionEvidence {
		return DecisionEvidence{
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
			Domain:       string(req.Domain),
			PolicyDigest: digest,
			RuleID:       ruleID,
			InputHash:    hex.EncodeToString(inputHash[:8]),
			EvalTimeUs:   time.Since(start).Microseconds(),
		}
	}

	switch req.Domain {
	case DomainToolAccess:
		return evaluateToolAccess(req, pol, makeEvidence)
	case DomainPathAccess:
		return evaluatePathAccess(req, pol, makeEvidence)
	case DomainEgress:
		return evaluateEgress(req, pol, makeEvidence)
	case DomainAgentRisk:
		return evaluateAgentRisk(req, pol, makeEvidence)
	case DomainSensitivity:
		return evaluateSensitivity(req, pol, makeEvidence)
	case DomainModelPromotion:
		return evaluateModelPromotion(req, pol, makeEvidence)
	default:
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("unknown domain: %s", req.Domain),
			Evidence: makeEvidence("unknown_domain"),
		}
	}
}

// --- Tool access evaluation ---

func evaluateToolAccess(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	tool := req.Subject

	// Check deny list first (deny always wins)
	for _, denied := range pol.Tools.Deny {
		if denied.Name == tool {
			return DecisionResponse{
				Decision: "deny",
				Reason:   fmt.Sprintf("tool '%s' is explicitly denied", tool),
				Evidence: mkEv("tools.deny." + tool),
			}
		}
	}

	// Default deny mode
	if pol.Tools.Default != "allow" {
		for _, allowed := range pol.Tools.Allow {
			if allowed.Name == tool {
				// Check path constraints if provided
				if path := req.Params["path"]; path != "" {
					for _, denied := range allowed.PathsDenylist {
						if matchesPrefix(path, denied) {
							return DecisionResponse{
								Decision: "deny",
								Reason:   "path matches tool denylist",
								Evidence: mkEv("tools.allow." + tool + ".paths_denylist"),
							}
						}
					}
					if len(allowed.PathsAllowlist) > 0 {
						pathOK := false
						for _, pattern := range allowed.PathsAllowlist {
							if matchesPrefix(path, pattern) {
								pathOK = true
								break
							}
						}
						if !pathOK {
							return DecisionResponse{
								Decision: "deny",
								Reason:   "path not in tool allowlist",
								Evidence: mkEv("tools.allow." + tool + ".paths_allowlist"),
							}
						}
					}
				}
				return DecisionResponse{
					Decision: "allow",
					Reason:   fmt.Sprintf("tool '%s' in allowlist", tool),
					Evidence: mkEv("tools.allow." + tool),
				}
			}
		}
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("tool '%s' not in allowlist (default=deny)", tool),
			Evidence: mkEv("tools.default_deny"),
		}
	}

	return DecisionResponse{
		Decision: "allow",
		Reason:   "default=allow",
		Evidence: mkEv("tools.default_allow"),
	}
}

// --- Path access evaluation ---

func evaluatePathAccess(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	path := req.Subject
	action := req.Action // "read" or "write"

	if action == "" {
		action = "read"
	}

	agent := pol.Agent

	if action == "write" {
		for _, pattern := range agent.Workspace.Writable {
			if matchesPrefix(path, pattern) {
				return DecisionResponse{
					Decision: "allow",
					Reason:   "path in writable scope",
					Evidence: mkEv("agent.workspace.writable"),
				}
			}
		}
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("path '%s' not in writable scope", path),
			Evidence: mkEv("agent.workspace.writable_miss"),
		}
	}

	// Read access
	for _, pattern := range agent.Workspace.Readable {
		if matchesPrefix(path, pattern) {
			return DecisionResponse{
				Decision: "allow",
				Reason:   "path in readable scope",
				Evidence: mkEv("agent.workspace.readable"),
			}
		}
	}

	return DecisionResponse{
		Decision: "deny",
		Reason:   fmt.Sprintf("path '%s' not in readable scope", path),
		Evidence: mkEv("agent.workspace.readable_miss"),
	}
}

// --- Egress evaluation ---

func evaluateEgress(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	dest := req.Subject

	// Default: deny all egress
	if pol.Defaults.Network.RuntimeEgress == "deny" {
		if !pol.Airlock.Enabled {
			return DecisionResponse{
				Decision: "deny",
				Reason:   "runtime egress denied and airlock disabled",
				Evidence: mkEv("defaults.network.egress_deny"),
			}
		}
		// Airlock enabled: check destination allowlist
		for _, allowed := range pol.Airlock.Destinations {
			if strings.Contains(dest, allowed) || matchesPrefix(dest, allowed) {
				return DecisionResponse{
					Decision: "allow",
					Reason:   fmt.Sprintf("destination '%s' in airlock allowlist", dest),
					Evidence: mkEv("airlock.destination_allowlist"),
				}
			}
		}
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("destination '%s' not in airlock allowlist", dest),
			Evidence: mkEv("airlock.destination_miss"),
		}
	}

	return DecisionResponse{
		Decision: "allow",
		Reason:   "egress policy is not deny",
		Evidence: mkEv("defaults.network.egress_open"),
	}
}

// --- Agent risk evaluation ---

func evaluateAgentRisk(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	action := req.Subject

	// Always deny list
	for _, denied := range pol.Agent.AlwaysDeny {
		if denied == action {
			return DecisionResponse{
				Decision: "deny",
				Reason:   fmt.Sprintf("action '%s' is always denied", action),
				Evidence: mkEv("agent.always_deny." + action),
			}
		}
	}

	// Hard approval list
	for _, approval := range pol.Agent.HardApproval {
		if approval == action {
			return DecisionResponse{
				Decision: "ask",
				Reason:   fmt.Sprintf("action '%s' requires explicit approval", action),
				Evidence: mkEv("agent.hard_approval." + action),
			}
		}
	}

	// Allowed tools
	if len(pol.Agent.AllowedTools) > 0 {
		for _, t := range pol.Agent.AllowedTools {
			if t == action {
				return DecisionResponse{
					Decision: "allow",
					Reason:   fmt.Sprintf("action '%s' in allowed tools", action),
					Evidence: mkEv("agent.allowed_tools." + action),
				}
			}
		}
	}

	// Default: deny unknown agent actions
	return DecisionResponse{
		Decision: "deny",
		Reason:   fmt.Sprintf("action '%s' not in agent allow list (default=deny)", action),
		Evidence: mkEv("agent.default_deny"),
	}
}

// --- Sensitivity evaluation ---

func evaluateSensitivity(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	level := req.Subject            // e.g. "high"
	ceiling := req.Params["ceiling"] // e.g. "medium"

	levels := map[string]int{"low": 0, "medium": 1, "high": 2}
	lv, ok1 := levels[level]
	cv, ok2 := levels[ceiling]

	if !ok1 || !ok2 {
		return DecisionResponse{
			Decision: "deny",
			Reason:   "invalid sensitivity level or ceiling",
			Evidence: mkEv("sensitivity.invalid"),
		}
	}

	if lv > cv {
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("sensitivity '%s' exceeds ceiling '%s'", level, ceiling),
			Evidence: mkEv("sensitivity.exceeded"),
		}
	}

	return DecisionResponse{
		Decision: "allow",
		Reason:   fmt.Sprintf("sensitivity '%s' within ceiling '%s'", level, ceiling),
		Evidence: mkEv("sensitivity.ok"),
	}
}

// --- Model promotion evaluation ---

func evaluateModelPromotion(req DecisionRequest, pol UnifiedPolicy, mkEv func(string) DecisionEvidence) DecisionResponse {
	format := req.Params["format"]

	// Check deny formats
	for _, denied := range pol.Models.DenyFormats {
		if strings.EqualFold(format, denied) {
			return DecisionResponse{
				Decision: "deny",
				Reason:   fmt.Sprintf("format '%s' is denied", format),
				Evidence: mkEv("models.deny_formats." + format),
			}
		}
	}

	// Check allowed formats
	if len(pol.Models.AllowedFormats) > 0 {
		for _, allowed := range pol.Models.AllowedFormats {
			if strings.EqualFold(format, allowed) {
				return DecisionResponse{
					Decision: "allow",
					Reason:   fmt.Sprintf("format '%s' is allowed", format),
					Evidence: mkEv("models.allowed_formats." + format),
				}
			}
		}
		return DecisionResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("format '%s' not in allowed formats", format),
			Evidence: mkEv("models.allowed_formats_miss"),
		}
	}

	return DecisionResponse{
		Decision: "allow",
		Reason:   "no format restrictions",
		Evidence: mkEv("models.no_restriction"),
	}
}

// =========================================================================
// Helpers
// =========================================================================

func matchesPrefix(path, pattern string) bool {
	pattern = strings.TrimSuffix(pattern, "/**")
	pattern = strings.TrimSuffix(pattern, "**")
	pattern = filepath.Clean(pattern)
	path = filepath.Clean(path)
	return strings.HasPrefix(path, pattern+"/") || path == pattern
}

// =========================================================================
// HTTP handlers
// =========================================================================

func handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Domain == "" || req.Subject == "" {
		http.Error(w, "domain and subject are required", http.StatusBadRequest)
		return
	}

	totalRequests.Add(1)
	resp := evaluate(req)

	switch resp.Decision {
	case "allow":
		allowedCount.Add(1)
	case "deny":
		deniedCount.Add(1)
	case "ask":
		askCount.Add(1)
	}

	log.Printf("policy-engine: domain=%s subject=%s decision=%s reason=%q",
		req.Domain, req.Subject, resp.Decision, resp.Reason)

	writeAudit(AuditEntry{
		Domain:   string(req.Domain),
		Subject:  req.Subject,
		Action:   req.Action,
		Decision: resp.Decision,
		Reason:   resp.Reason,
		Evidence: resp.Evidence,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	_, digest := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"policy_digest": digest,
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadPolicies(); err != nil {
		log.Printf("policy reload failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	pol, digest := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policy_digest":   digest,
		"tools_allow":     len(pol.Tools.Allow),
		"tools_deny":      len(pol.Tools.Deny),
		"total_requests":  totalRequests.Load(),
		"allowed":         allowedCount.Load(),
		"denied":          deniedCount.Load(),
		"ask":             askCount.Load(),
	})
}

func handleDigest(w http.ResponseWriter, r *http.Request) {
	_, digest := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"policy_digest": digest})
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadPolicies(); err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}

	initAuditLog()
	loadServiceToken()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8500"
	}

	mux := http.NewServeMux()
	// Read-only endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/decide", handleDecide)
	mux.HandleFunc("/api/v1/stats", handleStats)
	mux.HandleFunc("/api/v1/digest", handleDigest)
	// Mutating endpoints
	mux.HandleFunc("/api/v1/reload", requireServiceToken(handleReload))

	log.Printf("secure-ai-policy-engine listening on %s", bind)
	server := &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

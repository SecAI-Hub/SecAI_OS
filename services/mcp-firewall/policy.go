package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ---------- policy types ----------

// FirewallPolicy is the top-level policy configuration.
type FirewallPolicy struct {
	Version       int             `yaml:"version" json:"version"`
	DefaultAction string          `yaml:"default_action" json:"default_action"` // deny | allow
	Servers       []ServerPolicy  `yaml:"servers" json:"servers"`
	GlobalRules   []GlobalRule    `yaml:"global_rules" json:"global_rules"`
	TaintRules    []TaintRule     `yaml:"taint_rules" json:"taint_rules"`
	Redaction     RedactionConfig `yaml:"redaction" json:"redaction"`
	Audit         AuditConfig     `yaml:"audit" json:"audit"`
	Daemon        DaemonConfig    `yaml:"daemon" json:"daemon"`
}

// ServerPolicy defines the allowlist for a single MCP server.
type ServerPolicy struct {
	Name             string           `yaml:"name" json:"name"`
	Fingerprint      string           `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	TrustLevel       string           `yaml:"trust_level" json:"trust_level"` // trusted, verified, untrusted
	AllowedTools     []ToolPolicy     `yaml:"allowed_tools" json:"allowed_tools"`
	AllowedResources []ResourcePolicy `yaml:"allowed_resources,omitempty" json:"allowed_resources,omitempty"`
	RateLimit        int              `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"` // calls/min
}

// ToolPolicy defines access control for a single tool on a server.
type ToolPolicy struct {
	Name       string    `yaml:"name" json:"name"`
	Action     string    `yaml:"action" json:"action"` // allow, deny, require-approval
	ArgRules   []ArgRule `yaml:"arg_rules,omitempty" json:"arg_rules,omitempty"`
	PathRules  []string  `yaml:"path_restrict,omitempty" json:"path_restrict,omitempty"`
	TaintLabel string    `yaml:"taint_label,omitempty" json:"taint_label,omitempty"`
	RateLimit  int       `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// ArgRule validates a tool argument.
type ArgRule struct {
	Name     string `yaml:"name" json:"name"`
	Pattern  string `yaml:"pattern,omitempty" json:"pattern,omitempty"` // regex
	MaxLen   int    `yaml:"max_len,omitempty" json:"max_len,omitempty"`
	Required bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Redact   bool   `yaml:"redact,omitempty" json:"redact,omitempty"`
}

// ResourcePolicy controls access to MCP resources.
type ResourcePolicy struct {
	Pattern string `yaml:"pattern" json:"pattern"` // glob for resource URIs
	Action  string `yaml:"action" json:"action"`
}

// GlobalRule is a cross-server policy rule evaluated before server-specific rules.
type GlobalRule struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Match       Match  `yaml:"match" json:"match"`
	Action      string `yaml:"action" json:"action"`
	Reason      string `yaml:"reason" json:"reason"`
}

// Match conditions for a global rule.
type Match struct {
	Methods     []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	ServerTrust []string `yaml:"server_trust,omitempty" json:"server_trust,omitempty"`
	HasTaint    []string `yaml:"has_taint,omitempty" json:"has_taint,omitempty"`
	ArgPatterns []string `yaml:"arg_patterns,omitempty" json:"arg_patterns,omitempty"` // regex on serialized args
}

// TaintRule restricts data flow based on taint labels.
type TaintRule struct {
	Name        string     `yaml:"name" json:"name"`
	Description string     `yaml:"description" json:"description"`
	Match       TaintMatch `yaml:"match" json:"match"`
	Action      string     `yaml:"action" json:"action"` // deny, warn, allow
	Reason      string     `yaml:"reason" json:"reason"`
}

// TaintMatch specifies conditions for a taint rule.
type TaintMatch struct {
	SourceTaint  []string `yaml:"source_taint" json:"source_taint"`
	TargetTools  []string `yaml:"target_tools,omitempty" json:"target_tools,omitempty"`
	TargetServer []string `yaml:"target_server,omitempty" json:"target_server,omitempty"`
}

// RedactionConfig controls secret redaction.
type RedactionConfig struct {
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Patterns []string `yaml:"patterns" json:"patterns"` // email, api_key, bearer_token, etc.
}

// AuditConfig controls audit logging.
type AuditConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	LogPath           string `yaml:"log_path" json:"log_path"`
	SignReports       bool   `yaml:"sign_reports" json:"sign_reports"`
	KeyPath           string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	ReceiptAudience   string `yaml:"receipt_audience,omitempty" json:"receipt_audience,omitempty"`
	ReceiptTTLSeconds int    `yaml:"receipt_ttl_seconds,omitempty" json:"receipt_ttl_seconds,omitempty"`
}

// DaemonConfig for the HTTP server.
type DaemonConfig struct {
	BindAddr string `yaml:"bind_addr" json:"bind_addr"`
}

// ---------- request/decision types ----------

// EvalRequest is an MCP operation submitted for policy evaluation.
type EvalRequest struct {
	// Only the authenticated HTTP boundary supplies this scope. It cannot be
	// selected in JSON, reset by reconnecting, or changed by switching servers.
	taintContext      string
	Server            string            `json:"server"`
	ServerFingerprint string            `json:"server_fingerprint,omitempty"`
	Method            string            `json:"method"` // tools/call, resources/read, etc.
	Tool              string            `json:"tool,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Arguments         map[string]string `json:"arguments,omitempty"`
	SessionID         string            `json:"session_id"`
	SessionToken      string            `json:"session_token,omitempty"`
	RequestID         string            `json:"request_id,omitempty"`
}

// Decision is the firewall's verdict on an MCP operation.
type Decision struct {
	Action       string            `json:"action"` // allow, deny, require-approval, redact
	Server       string            `json:"server"`
	Tool         string            `json:"tool,omitempty"`
	Resource     string            `json:"resource,omitempty"`
	Rule         string            `json:"rule"` // name of matching rule
	Reason       string            `json:"reason"`
	Evidence     []string          `json:"evidence"`
	TaintApplied []string          `json:"taint_applied,omitempty"` // new taint labels from this call
	TaintActive  []string          `json:"taint_active,omitempty"`  // session taint at eval time
	RedactedArgs map[string]string `json:"redacted_args,omitempty"`
	SessionID    string            `json:"session_id"`
	RequestID    string            `json:"request_id,omitempty"`
}

// ---------- policy engine ----------

// PolicyEngine evaluates MCP requests against the loaded policy.
type PolicyEngine struct {
	policy      *FirewallPolicy
	serverIndex map[string]*ServerPolicy
	toolIndex   map[string]map[string]*ToolPolicy // server -> tool -> policy
	rateMu      sync.Mutex
	rateBuckets map[string]*policyRateBucket
}

type policyRateBucket struct {
	tokens float64
	last   time.Time
}

// NewPolicyEngine creates an engine from a policy.
func NewPolicyEngine(policy *FirewallPolicy) *PolicyEngine {
	pe := &PolicyEngine{
		policy:      policy,
		serverIndex: make(map[string]*ServerPolicy),
		toolIndex:   make(map[string]map[string]*ToolPolicy),
		rateBuckets: make(map[string]*policyRateBucket),
	}

	for i := range policy.Servers {
		s := &policy.Servers[i]
		pe.serverIndex[s.Name] = s
		pe.toolIndex[s.Name] = make(map[string]*ToolPolicy)
		for j := range s.AllowedTools {
			t := &s.AllowedTools[j]
			pe.toolIndex[s.Name][t.Name] = t
		}
	}

	return pe
}

// Evaluate assesses a single MCP request against the full policy stack.
func (pe *PolicyEngine) Evaluate(req EvalRequest, taintState *TaintState) Decision {
	d := Decision{
		Server:    req.Server,
		Tool:      req.Tool,
		Resource:  req.Resource,
		SessionID: req.SessionID,
		RequestID: req.RequestID,
	}
	if reason := validateEvalRequest(req); reason != "" {
		d.Action = "deny"
		d.Rule = "builtin:invalid-request"
		d.Reason = reason
		return d
	}

	if !taintState.Available() {
		d.Action, d.Rule, d.Reason = "deny", "builtin:taint-unavailable", "security context capacity exhausted"
		return d
	}
	contextID := req.SessionID
	if req.taintContext != "" {
		contextID = req.taintContext
	}
	activeTaint := taintState.Labels(contextID)
	activeTaint = append(activeTaint, taintState.Labels(legacyTaintContext)...)
	d.TaintActive = activeTaint

	// A global deny is terminal. A global require-approval rule is only a
	// restrictive overlay on a request that the server policy would otherwise
	// allow; it can never elevate an unknown/default-denied operation.
	globalDecision := pe.evalGlobalRules(req, activeTaint)
	if globalDecision != nil && globalDecision.Action == "deny" {
		d.Action = globalDecision.Action
		d.Rule = globalDecision.Rule
		d.Reason = globalDecision.Reason
		d.Evidence = globalDecision.Evidence
		return d
	}

	d = pe.evaluateServerPolicy(req, d, activeTaint)
	if globalDecision != nil && globalDecision.Action == "require-approval" && d.Action == "allow" {
		d.Action = globalDecision.Action
		d.Rule = globalDecision.Rule
		d.Reason = globalDecision.Reason
		d.Evidence = append(d.Evidence, globalDecision.Evidence...)
	}
	return d
}

func (pe *PolicyEngine) evaluateServerPolicy(req EvalRequest, d Decision, activeTaint []string) Decision {

	// 2. Taint flow rules
	if td := pe.evalTaintRules(req, activeTaint); td != nil {
		d.Action = td.Action
		d.Rule = td.Rule
		d.Reason = td.Reason
		d.Evidence = td.Evidence
		return d
	}

	// 3. Server allowlist
	server, ok := pe.serverIndex[req.Server]
	if !ok {
		d.Action = pe.policy.DefaultAction
		d.Rule = "default:server-not-found"
		d.Reason = fmt.Sprintf("server %q not in allowlist", req.Server)
		d.Evidence = []string{fmt.Sprintf("known servers: %d", len(pe.policy.Servers))}
		return d
	}
	if server.Fingerprint != "" &&
		subtle.ConstantTimeCompare([]byte(req.ServerFingerprint), []byte(server.Fingerprint)) != 1 {
		d.Action = "deny"
		d.Rule = "builtin:server-fingerprint"
		d.Reason = "server fingerprint mismatch"
		return d
	}
	if server.RateLimit > 0 && !pe.takeRateToken("server:"+server.Name, server.RateLimit) {
		d.Action = "deny"
		d.Rule = "builtin:server-rate-limit"
		d.Reason = "server rate limit exceeded"
		return d
	}

	d.Evidence = append(d.Evidence, fmt.Sprintf("server %q trust=%s", server.Name, server.TrustLevel))

	// 4. Route by MCP method
	switch {
	case req.Method == "tools/call" && req.Tool != "":
		return pe.evalToolCall(req, d, server)
	case req.Method == "resources/read" && req.Resource != "":
		return pe.evalResourceRead(req, d, server)
	case req.Method == "tools/list" || req.Method == "resources/list" || req.Method == "prompts/list":
		d.Action = "allow"
		d.Rule = "builtin:list-methods"
		d.Reason = "list methods are allowed for known servers"
		return d
	default:
		d.Action = pe.policy.DefaultAction
		d.Rule = "default:unrecognized-method"
		d.Reason = fmt.Sprintf("method %q not handled", req.Method)
		return d
	}
}

func validateEvalRequest(req EvalRequest) string {
	validIdentifier := func(value string) bool {
		return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
			!strings.ContainsAny(value, "\x00\r\n")
	}
	if !validIdentifier(req.Server) {
		return "invalid server identifier"
	}
	if !validIdentifier(req.Method) {
		return "invalid MCP method"
	}
	if !validIdentifier(req.SessionID) {
		return "invalid session identifier"
	}
	if req.Tool != "" && !validIdentifier(req.Tool) {
		return "invalid tool identifier"
	}
	if len(req.ServerFingerprint) > 4096 || strings.ContainsAny(req.ServerFingerprint, "\x00\r\n") {
		return "invalid server fingerprint"
	}
	if len(req.RequestID) > 256 || strings.ContainsAny(req.RequestID, "\x00\r\n") {
		return "invalid request identifier"
	}
	if len(req.SessionToken) > 256 || strings.ContainsAny(req.SessionToken, "\x00\r\n \t") {
		return "invalid session token"
	}
	if len(req.Resource) > 4096 || strings.ContainsAny(req.Resource, "\x00\r\n") {
		return "invalid resource identifier"
	}
	if len(req.Arguments) > 128 {
		return "too many arguments"
	}
	for key, value := range req.Arguments {
		if !validIdentifier(key) || len(value) > 1<<20 || strings.ContainsRune(value, 0) {
			return "invalid argument"
		}
	}
	switch req.Method {
	case "tools/call":
		if req.Tool == "" || req.Resource != "" {
			return "tools/call requires exactly one tool and no resource"
		}
	case "resources/read":
		if req.Resource == "" || req.Tool != "" || len(req.Arguments) != 0 {
			return "resources/read requires exactly one resource and no tool arguments"
		}
	case "tools/list", "resources/list", "prompts/list":
		if req.Tool != "" || req.Resource != "" || len(req.Arguments) != 0 {
			return "list methods do not accept tool, resource, or argument fields"
		}
	}
	return ""
}

func (pe *PolicyEngine) takeRateToken(key string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	capacity := perMinute
	if capacity > 20 {
		capacity = 20
	}
	if capacity < 1 {
		capacity = 1
	}
	pe.rateMu.Lock()
	defer pe.rateMu.Unlock()
	now := time.Now()
	bucket := pe.rateBuckets[key]
	if bucket == nil {
		pe.rateBuckets[key] = &policyRateBucket{tokens: float64(capacity - 1), last: now}
		return true
	}
	bucket.tokens += now.Sub(bucket.last).Seconds() * float64(perMinute) / 60
	if bucket.tokens > float64(capacity) {
		bucket.tokens = float64(capacity)
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// evalGlobalRules checks cross-server rules.
func (pe *PolicyEngine) evalGlobalRules(req EvalRequest, activeTaint []string) *Decision {
	serverTrust := ""
	if server := pe.serverIndex[req.Server]; server != nil {
		serverTrust = server.TrustLevel
	}
	var approval *Decision
	for _, rule := range pe.policy.GlobalRules {
		if matchGlobal(rule.Match, req, activeTaint, serverTrust) {
			decision := &Decision{
				Action:   rule.Action,
				Rule:     rule.Name,
				Reason:   rule.Reason,
				Evidence: []string{fmt.Sprintf("global rule %q matched", rule.Name)},
			}
			if rule.Action == "deny" {
				return decision
			}
			if approval == nil {
				approval = decision
			}
		}
	}
	return approval
}

func matchGlobal(m Match, req EvalRequest, activeTaint []string, serverTrust string) bool {
	if len(m.Methods) > 0 && !contains(m.Methods, req.Method) {
		return false
	}
	if len(m.ServerTrust) > 0 && !contains(m.ServerTrust, serverTrust) {
		return false
	}

	if len(m.HasTaint) > 0 {
		found := false
		for _, t := range m.HasTaint {
			if containsStr(activeTaint, t) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(m.ArgPatterns) > 0 {
		argStr := flattenArgs(req.Arguments)
		matched := false
		for _, p := range m.ArgPatterns {
			if re, err := regexp.Compile(p); err == nil && re.MatchString(argStr) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// evalTaintRules checks taint flow restrictions.
func (pe *PolicyEngine) evalTaintRules(req EvalRequest, activeTaint []string) *Decision {
	if len(activeTaint) == 0 {
		return nil
	}

	for _, rule := range pe.policy.TaintRules {
		if matchTaint(rule.Match, req, activeTaint) {
			if rule.Action == "allow" {
				continue
			}
			return &Decision{
				Action: rule.Action,
				Rule:   rule.Name,
				Reason: rule.Reason,
				Evidence: []string{
					fmt.Sprintf("taint rule %q matched", rule.Name),
					fmt.Sprintf("active taint: %v", activeTaint),
					fmt.Sprintf("target: %s/%s", req.Server, req.Tool),
				},
			}
		}
	}
	return nil
}

func matchTaint(m TaintMatch, req EvalRequest, activeTaint []string) bool {
	if len(m.SourceTaint) > 0 {
		found := false
		for _, t := range m.SourceTaint {
			if containsStr(activeTaint, t) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(m.TargetTools) > 0 && !contains(m.TargetTools, req.Tool) {
		return false
	}
	if len(m.TargetServer) > 0 && !contains(m.TargetServer, req.Server) {
		return false
	}

	return true
}

// evalToolCall checks per-server tool policy.
func (pe *PolicyEngine) evalToolCall(req EvalRequest, d Decision, server *ServerPolicy) Decision {
	toolMap, ok := pe.toolIndex[req.Server]
	if !ok {
		d.Action = pe.policy.DefaultAction
		d.Rule = "default:no-tool-policy"
		d.Reason = fmt.Sprintf("no tool policies for server %q", req.Server)
		return d
	}

	tool, ok := toolMap[req.Tool]
	if !ok {
		d.Action = pe.policy.DefaultAction
		d.Rule = "default:tool-not-in-allowlist"
		d.Reason = fmt.Sprintf("tool %q not in allowlist for server %q", req.Tool, req.Server)
		d.Evidence = append(d.Evidence, fmt.Sprintf("allowed tools: %d", len(server.AllowedTools)))
		return d
	}
	if tool.RateLimit > 0 && !pe.takeRateToken("tool:"+req.Server+":"+req.Tool, tool.RateLimit) {
		d.Action = "deny"
		d.Rule = "builtin:tool-rate-limit"
		d.Reason = "tool rate limit exceeded"
		return d
	}

	d.Evidence = append(d.Evidence, fmt.Sprintf("tool %q action=%s", tool.Name, tool.Action))

	// Check tool action
	if tool.Action == "deny" {
		d.Action = "deny"
		d.Rule = fmt.Sprintf("server:%s/tool:%s", req.Server, req.Tool)
		d.Reason = "tool explicitly denied by policy"
		return d
	}

	// Validate arguments
	if violations := validateArgs(tool.ArgRules, req.Arguments); len(violations) > 0 {
		d.Action = "deny"
		d.Rule = fmt.Sprintf("server:%s/tool:%s/arg-validation", req.Server, req.Tool)
		d.Reason = "argument validation failed"
		d.Evidence = append(d.Evidence, violations...)
		return d
	}

	// Check path restrictions
	if violation := checkPathRestrictions(tool.PathRules, req.Arguments); violation != "" {
		d.Action = "deny"
		d.Rule = fmt.Sprintf("server:%s/tool:%s/path-restrict", req.Server, req.Tool)
		d.Reason = "path restriction violated"
		d.Evidence = append(d.Evidence, violation)
		return d
	}

	// Apply redaction if configured
	if len(req.Arguments) > 0 {
		var redacted map[string]string
		if pe.policy.Redaction.Enabled {
			redacted = redactArguments(req.Arguments, pe.policy.Redaction.Patterns)
		}
		if redacted == nil {
			redacted = make(map[string]string)
		}
		for _, rule := range tool.ArgRules {
			if rule.Redact {
				if _, exists := req.Arguments[rule.Name]; exists {
					redacted[rule.Name] = "[REDACTED:policy]"
				}
			}
		}
		if len(redacted) > 0 {
			d.RedactedArgs = redacted
			d.Evidence = append(d.Evidence, "arguments redacted per policy")
		}
	}

	// Record the taint that a trusted executor must apply only after successful
	// execution through the completion endpoint. Evaluation alone never mutates
	// session taint.
	if tool.TaintLabel != "" {
		d.TaintApplied = []string{tool.TaintLabel}
		d.Evidence = append(d.Evidence, fmt.Sprintf("post-execution taint required: %s", tool.TaintLabel))
	}

	d.Action = tool.Action
	d.Rule = fmt.Sprintf("server:%s/tool:%s", req.Server, req.Tool)
	d.Reason = fmt.Sprintf("tool %q %s by server policy", req.Tool, tool.Action)
	return d
}

// evalResourceRead checks resource access policy.
func (pe *PolicyEngine) evalResourceRead(req EvalRequest, d Decision, server *ServerPolicy) Decision {
	resource, err := canonicalResourceURI(req.Resource)
	if err != nil {
		d.Action = "deny"
		d.Rule = "builtin:invalid-resource-uri"
		d.Reason = "resource URI is not canonical or safely contained"
		return d
	}
	var allowMatch *ResourcePolicy
	var approvalMatch *ResourcePolicy
	for _, rp := range server.AllowedResources {
		pattern, patternErr := canonicalResourcePolicy(rp.Pattern)
		if patternErr != nil || !pattern.matches(resource) {
			continue
		}
		switch rp.Action {
		case "deny":
			d.Action = "deny"
			d.Rule = fmt.Sprintf("server:%s/resource:%s", req.Server, rp.Pattern)
			d.Reason = fmt.Sprintf("resource is denied by pattern %q", rp.Pattern)
			return d
		case "require-approval":
			copy := rp
			approvalMatch = &copy
		case "allow":
			copy := rp
			allowMatch = &copy
		}
	}
	matched := approvalMatch
	if matched == nil {
		matched = allowMatch
	}
	if matched != nil {
		d.Action = matched.Action
		d.Rule = fmt.Sprintf("server:%s/resource:%s", req.Server, matched.Pattern)
		d.Reason = fmt.Sprintf("canonical resource matched pattern %q", matched.Pattern)
		return d
	}

	d.Action = pe.policy.DefaultAction
	d.Rule = "default:resource-not-in-allowlist"
	d.Reason = fmt.Sprintf("resource %q not in allowlist for server %q", req.Resource, req.Server)
	return d
}

type canonicalResource struct {
	scheme string
	host   string
	path   string
}

type canonicalResourcePatternValue struct {
	resource  canonicalResource
	direct    bool
	recursive bool
}

func canonicalResourceURI(raw string) (canonicalResource, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\x00\r\n") {
		return canonicalResource{}, fmt.Errorf("invalid resource URI")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return canonicalResource{}, fmt.Errorf("resource must be an absolute hierarchical URI without credentials, query, or fragment")
	}
	decoded, err := decodeResourcePath(u.EscapedPath())
	if err != nil || decoded == "" || !strings.HasPrefix(decoded, "/") {
		return canonicalResource{}, fmt.Errorf("invalid resource path")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme == "file" {
		if host == "localhost" {
			host = ""
		}
		if host != "" {
			return canonicalResource{}, fmt.Errorf("remote file URI authorities are not allowed")
		}
		clean, pathErr := canonicalPolicyPath(decoded)
		if pathErr != nil {
			return canonicalResource{}, pathErr
		}
		decoded = filepath.ToSlash(clean)
	} else {
		for _, r := range decoded {
			if r == '\\' || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
				return canonicalResource{}, fmt.Errorf("ambiguous resource path")
			}
		}
		decoded = pathpkg.Clean(decoded)
	}
	return canonicalResource{scheme: scheme, host: host, path: decoded}, nil
}

func decodeResourcePath(raw string) (string, error) {
	decoded := raw
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || strings.ContainsRune(next, 0) {
			return "", fmt.Errorf("invalid resource percent encoding")
		}
		if next == decoded {
			return decoded, nil
		}
		decoded = next
	}
	return "", fmt.Errorf("resource path is encoded too deeply")
}

func canonicalResourcePolicy(raw string) (canonicalResourcePatternValue, error) {
	value := canonicalResourcePatternValue{}
	base := raw
	switch {
	case strings.HasSuffix(base, "/**"):
		value.recursive = true
		base = strings.TrimSuffix(base, "/**")
	case strings.HasSuffix(base, "/*"):
		value.direct = true
		base = strings.TrimSuffix(base, "/*")
	case strings.ContainsAny(base, "*?["):
		return value, fmt.Errorf("resource wildcards are only allowed as a trailing /* or /**")
	}
	resource, err := canonicalResourceURI(base)
	if err != nil {
		return value, err
	}
	value.resource = resource
	return value, nil
}

func (pattern canonicalResourcePatternValue) matches(resource canonicalResource) bool {
	if pattern.resource.scheme != resource.scheme || pattern.resource.host != resource.host {
		return false
	}
	base := strings.TrimSuffix(pattern.resource.path, "/")
	if !pattern.direct && !pattern.recursive {
		return resource.path == pattern.resource.path
	}
	if resource.path == base || !strings.HasPrefix(resource.path, base+"/") {
		return false
	}
	if pattern.recursive {
		return true
	}
	relative := strings.TrimPrefix(resource.path, base+"/")
	return relative != "" && !strings.Contains(relative, "/")
}

// validateArgs checks arguments against rules.
func validateArgs(rules []ArgRule, args map[string]string) []string {
	var violations []string
	allowed := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		allowed[rule.Name] = struct{}{}
	}
	for name := range args {
		if _, ok := allowed[name]; !ok {
			violations = append(violations, fmt.Sprintf("argument %q is not declared by policy", name))
		}
	}

	for _, rule := range rules {
		val, exists := args[rule.Name]

		if rule.Required && !exists {
			violations = append(violations, fmt.Sprintf("required argument %q missing", rule.Name))
			continue
		}

		if !exists {
			continue
		}

		if rule.MaxLen > 0 && len(val) > rule.MaxLen {
			violations = append(violations, fmt.Sprintf("argument %q exceeds max length %d (got %d)", rule.Name, rule.MaxLen, len(val)))
		}

		if rule.Pattern != "" {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				violations = append(violations, fmt.Sprintf("invalid pattern for %q: %v", rule.Name, err))
			} else if !re.MatchString(val) {
				violations = append(violations, fmt.Sprintf("argument %q does not match required pattern", rule.Name))
			}
		}
	}

	return violations
}

// checkPathRestrictions ensures file path arguments stay within allowed directories.
func checkPathRestrictions(allowed []string, args map[string]string) string {
	if len(allowed) == 0 {
		return ""
	}

	pathKeys := []string{
		"path", "file", "filepath", "filename", "directory", "dir", "root", "cwd",
		"target", "source", "destination", "input_path", "output_path", "source_path", "destination_path",
	}
	found := false

	for _, key := range pathKeys {
		val, ok := args[key]
		if !ok || val == "" {
			continue
		}
		found = true
		clean, err := canonicalPolicyPath(val)
		if err != nil {
			return fmt.Sprintf("argument %q contains an invalid path", key)
		}

		withinAllowed := false
		for _, prefix := range allowed {
			allowedPath, err := canonicalPolicyPath(prefix)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(allowedPath, clean)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				withinAllowed = true
				break
			}
		}

		if !withinAllowed {
			return fmt.Sprintf("argument %q path is outside allowed directories", key)
		}
	}
	if !found {
		return "required path argument missing"
	}

	return ""
}

func canonicalPolicyPath(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsRune(raw, '\\') || !filepath.IsAbs(raw) {
		return "", fmt.Errorf("path must be absolute")
	}
	// Cleaning before resolving links changes the meaning of link/../file.
	// A policy decision must not reinterpret that ambiguous executor input.
	for _, component := range strings.Split(raw, "/") {
		if component == ".." {
			return "", fmt.Errorf("parent traversal is not allowed")
		}
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("control character in path")
		}
		switch r {
		case '\u2044', '\u2215', '\u2216', '\u29f8', '\uff0e', '\uff0f', '\uff3c', '\ufffd':
			return "", fmt.Errorf("unicode path confusable")
		}
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
			return "", fmt.Errorf("unicode path confusable")
		}
	}
	abs := filepath.Clean(raw)
	cursor := abs
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(cursor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		if info, lstatErr := os.Lstat(cursor); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("dangling symbolic link in path")
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return abs, nil
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

// ---------- policy loading ----------

// LoadPolicy reads and parses a policy YAML file.
func LoadPolicy(path string) (*FirewallPolicy, error) {
	data, err := readRegularPolicyFile(path, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var policy FirewallPolicy
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("policy must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("parse trailing policy data: %w", err)
	}
	if err := validatePolicyStrict(&policy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return &policy, nil
}

func readRegularPolicyFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path) // #nosec G703 -- operator-selected path is guarded by pre/open/post identity, symlink, type, mode, and size checks
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic links are not allowed")
	}
	f, err := os.Open(path) // #nosec G304,G703 -- operator-selected path is guarded by pre/open/post identity, symlink, type, mode, and size checks
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path) // #nosec G703 -- required post-open identity and symlink validation of the same operator-selected path
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("file changed while opening or is a symbolic link")
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if opened.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("policy must not be group- or other-writable")
	}
	if opened.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

func validatePolicyStrict(policy *FirewallPolicy) error {
	if policy.Version != 1 {
		return fmt.Errorf("unsupported version %d", policy.Version)
	}
	if policy.DefaultAction != "deny" {
		return fmt.Errorf("default_action must be deny")
	}
	if len(policy.Servers) > 1024 || len(policy.GlobalRules) > 1024 || len(policy.TaintRules) > 1024 {
		return fmt.Errorf("policy contains too many rules")
	}
	validName := func(value string) bool {
		return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
			!strings.ContainsAny(value, "\x00\r\n")
	}
	serverNames := make(map[string]struct{}, len(policy.Servers))
	for _, server := range policy.Servers {
		if !validName(server.Name) {
			return fmt.Errorf("invalid server name")
		}
		if _, exists := serverNames[server.Name]; exists {
			return fmt.Errorf("duplicate server %q", server.Name)
		}
		serverNames[server.Name] = struct{}{}
		if len(server.Fingerprint) > 4096 || strings.ContainsAny(server.Fingerprint, "\x00\r\n") {
			return fmt.Errorf("server %q has invalid fingerprint", server.Name)
		}
		if server.TrustLevel != "trusted" && server.TrustLevel != "verified" && server.TrustLevel != "untrusted" {
			return fmt.Errorf("server %q has invalid trust_level", server.Name)
		}
		if server.RateLimit < 0 || server.RateLimit > 1_000_000 || len(server.AllowedTools) > 2048 ||
			len(server.AllowedResources) > 2048 {
			return fmt.Errorf("server %q has invalid limits", server.Name)
		}
		toolNames := make(map[string]struct{}, len(server.AllowedTools))
		for _, tool := range server.AllowedTools {
			if !validName(tool.Name) {
				return fmt.Errorf("server %q has invalid tool name", server.Name)
			}
			if _, exists := toolNames[tool.Name]; exists {
				return fmt.Errorf("server %q has duplicate tool %q", server.Name, tool.Name)
			}
			toolNames[tool.Name] = struct{}{}
			if tool.Action != "allow" && tool.Action != "deny" && tool.Action != "require-approval" {
				return fmt.Errorf("tool %q has invalid action", tool.Name)
			}
			if tool.RateLimit < 0 || tool.RateLimit > 1_000_000 || len(tool.ArgRules) > 128 || len(tool.PathRules) > 256 ||
				(tool.TaintLabel != "" && !validName(tool.TaintLabel)) {
				return fmt.Errorf("tool %q has invalid limits", tool.Name)
			}
			argNames := make(map[string]struct{}, len(tool.ArgRules))
			for _, rule := range tool.ArgRules {
				if !validName(rule.Name) || rule.MaxLen < 0 || rule.MaxLen > 1<<20 {
					return fmt.Errorf("tool %q has invalid argument rule", tool.Name)
				}
				if _, exists := argNames[rule.Name]; exists {
					return fmt.Errorf("tool %q has duplicate argument rule %q", tool.Name, rule.Name)
				}
				argNames[rule.Name] = struct{}{}
				if len(rule.Pattern) > 4096 {
					return fmt.Errorf("tool %q has oversized argument regex", tool.Name)
				}
				if rule.Pattern != "" {
					if _, err := regexp.Compile(rule.Pattern); err != nil {
						return fmt.Errorf("tool %q has invalid argument regex", tool.Name)
					}
				}
			}
			for _, allowedPath := range tool.PathRules {
				if _, err := canonicalPolicyPath(allowedPath); err != nil {
					return fmt.Errorf("tool %q has invalid path restriction", tool.Name)
				}
			}
		}
		resourcePatterns := make(map[canonicalResourcePatternValue]string, len(server.AllowedResources))
		for _, resource := range server.AllowedResources {
			if resource.Pattern == "" || len(resource.Pattern) > 4096 || strings.ContainsAny(resource.Pattern, "\x00\r\n") ||
				(resource.Action != "allow" && resource.Action != "deny" && resource.Action != "require-approval") {
				return fmt.Errorf("server %q has invalid resource policy", server.Name)
			}
			canonical, err := canonicalResourcePolicy(resource.Pattern)
			if err != nil {
				return fmt.Errorf("server %q has invalid resource pattern", server.Name)
			}
			if previous, exists := resourcePatterns[canonical]; exists {
				return fmt.Errorf("server %q has canonically duplicate resource patterns %q and %q", server.Name, previous, resource.Pattern)
			}
			resourcePatterns[canonical] = resource.Pattern
		}
	}
	globalNames := make(map[string]struct{}, len(policy.GlobalRules))
	for _, rule := range policy.GlobalRules {
		if !validName(rule.Name) || (rule.Action != "deny" && rule.Action != "require-approval") ||
			len(rule.Description) > 4096 || len(rule.Reason) > 4096 ||
			len(rule.Match.Methods) > 256 || len(rule.Match.ServerTrust) > 256 ||
			len(rule.Match.HasTaint) > 256 || len(rule.Match.ArgPatterns) > 256 {
			return fmt.Errorf("invalid global rule")
		}
		if _, exists := globalNames[rule.Name]; exists {
			return fmt.Errorf("duplicate global rule %q", rule.Name)
		}
		globalNames[rule.Name] = struct{}{}
		for _, method := range rule.Match.Methods {
			if !validName(method) {
				return fmt.Errorf("global rule %q has invalid method", rule.Name)
			}
		}
		for _, label := range rule.Match.HasTaint {
			if !validName(label) {
				return fmt.Errorf("global rule %q has invalid taint label", rule.Name)
			}
		}
		for _, pattern := range rule.Match.ArgPatterns {
			if pattern == "" || len(pattern) > 4096 {
				return fmt.Errorf("global rule %q has invalid regex", rule.Name)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("global rule %q has invalid regex", rule.Name)
			}
		}
		for _, trust := range rule.Match.ServerTrust {
			if trust != "trusted" && trust != "verified" && trust != "untrusted" {
				return fmt.Errorf("global rule %q has invalid trust level", rule.Name)
			}
		}
	}
	taintNames := make(map[string]struct{}, len(policy.TaintRules))
	for _, rule := range policy.TaintRules {
		if !validName(rule.Name) || (rule.Action != "deny" && rule.Action != "allow") || len(rule.Match.SourceTaint) == 0 ||
			len(rule.Description) > 4096 || len(rule.Reason) > 4096 || len(rule.Match.SourceTaint) > 256 ||
			len(rule.Match.TargetTools) > 256 || len(rule.Match.TargetServer) > 256 {
			return fmt.Errorf("invalid taint rule")
		}
		if _, exists := taintNames[rule.Name]; exists {
			return fmt.Errorf("duplicate taint rule %q", rule.Name)
		}
		taintNames[rule.Name] = struct{}{}
		for _, values := range [][]string{rule.Match.SourceTaint, rule.Match.TargetTools, rule.Match.TargetServer} {
			for _, value := range values {
				if !validName(value) {
					return fmt.Errorf("taint rule %q has invalid match value", rule.Name)
				}
			}
		}
	}
	validRedaction := map[string]struct{}{
		"all": {}, "api_key": {}, "bearer_token": {}, "password": {}, "email": {}, "aws_key": {},
		"private_key": {}, "connection_string": {}, "ssn": {},
	}
	if len(policy.Redaction.Patterns) > len(validRedaction) {
		return fmt.Errorf("too many redaction patterns")
	}
	seenRedaction := make(map[string]struct{}, len(policy.Redaction.Patterns))
	for _, pattern := range policy.Redaction.Patterns {
		normalized := strings.ToLower(pattern)
		if _, ok := validRedaction[normalized]; !ok {
			return fmt.Errorf("unknown redaction pattern %q", pattern)
		}
		if _, exists := seenRedaction[normalized]; exists {
			return fmt.Errorf("duplicate redaction pattern %q", pattern)
		}
		seenRedaction[normalized] = struct{}{}
	}
	if !policy.Audit.Enabled || policy.Audit.LogPath == "" || len(policy.Audit.LogPath) > 4096 ||
		len(policy.Audit.KeyPath) > 4096 {
		return fmt.Errorf("audit logging must be enabled with a log_path")
	}
	if !policy.Audit.SignReports || policy.Audit.KeyPath == "" || !validName(policy.Audit.ReceiptAudience) ||
		policy.Audit.ReceiptTTLSeconds < 1 || policy.Audit.ReceiptTTLSeconds > 600 {
		return fmt.Errorf("signed receipts require sign_reports, key_path, receipt_audience, and a 1-600 second TTL")
	}
	return nil
}

// ---------- helpers ----------

func contains(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func containsStr(list []string, val string) bool {
	return contains(list, val)
}

func flattenArgs(args map[string]string) string {
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(args))
	for _, k := range keys {
		v := args[k]
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

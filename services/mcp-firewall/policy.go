package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	Methods      []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	ServerTrust  []string `yaml:"server_trust,omitempty" json:"server_trust,omitempty"`
	HasTaint     []string `yaml:"has_taint,omitempty" json:"has_taint,omitempty"`
	ArgPatterns  []string `yaml:"arg_patterns,omitempty" json:"arg_patterns,omitempty"` // regex on serialized args
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
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	LogPath    string `yaml:"log_path" json:"log_path"`
	SignReports bool  `yaml:"sign_reports" json:"sign_reports"`
	KeyPath    string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
}

// DaemonConfig for the HTTP server.
type DaemonConfig struct {
	BindAddr string `yaml:"bind_addr" json:"bind_addr"`
}

// ---------- request/decision types ----------

// EvalRequest is an MCP operation submitted for policy evaluation.
type EvalRequest struct {
	Server       string            `json:"server"`
	Method       string            `json:"method"`                  // tools/call, resources/read, etc.
	Tool         string            `json:"tool,omitempty"`
	Resource     string            `json:"resource,omitempty"`
	Arguments    map[string]string `json:"arguments,omitempty"`
	SessionID    string            `json:"session_id"`
	RequestID    string            `json:"request_id,omitempty"`
}

// Decision is the firewall's verdict on an MCP operation.
type Decision struct {
	Action         string            `json:"action"`                    // allow, deny, require-approval, redact
	Server         string            `json:"server"`
	Tool           string            `json:"tool,omitempty"`
	Resource       string            `json:"resource,omitempty"`
	Rule           string            `json:"rule"`                      // name of matching rule
	Reason         string            `json:"reason"`
	Evidence       []string          `json:"evidence"`
	TaintApplied   []string          `json:"taint_applied,omitempty"`   // new taint labels from this call
	TaintActive    []string          `json:"taint_active,omitempty"`    // session taint at eval time
	RedactedArgs   map[string]string `json:"redacted_args,omitempty"`
	SessionID      string            `json:"session_id"`
	RequestID      string            `json:"request_id,omitempty"`
}

// ---------- policy engine ----------

// PolicyEngine evaluates MCP requests against the loaded policy.
type PolicyEngine struct {
	policy       *FirewallPolicy
	serverIndex  map[string]*ServerPolicy
	toolIndex    map[string]map[string]*ToolPolicy // server -> tool -> policy
}

// NewPolicyEngine creates an engine from a policy.
func NewPolicyEngine(policy *FirewallPolicy) *PolicyEngine {
	pe := &PolicyEngine{
		policy:      policy,
		serverIndex: make(map[string]*ServerPolicy),
		toolIndex:   make(map[string]map[string]*ToolPolicy),
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

	activeTaint := taintState.Labels(req.SessionID)
	d.TaintActive = activeTaint

	// 1. Global rules (highest priority)
	if gd := pe.evalGlobalRules(req, activeTaint); gd != nil {
		d.Action = gd.Action
		d.Rule = gd.Rule
		d.Reason = gd.Reason
		d.Evidence = gd.Evidence
		return d
	}

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

	d.Evidence = append(d.Evidence, fmt.Sprintf("server %q trust=%s", server.Name, server.TrustLevel))

	// 4. Route by MCP method
	switch {
	case req.Method == "tools/call" && req.Tool != "":
		return pe.evalToolCall(req, d, server, taintState)
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

// evalGlobalRules checks cross-server rules.
func (pe *PolicyEngine) evalGlobalRules(req EvalRequest, activeTaint []string) *Decision {
	for _, rule := range pe.policy.GlobalRules {
		if matchGlobal(rule.Match, req, activeTaint) {
			return &Decision{
				Action:   rule.Action,
				Rule:     rule.Name,
				Reason:   rule.Reason,
				Evidence: []string{fmt.Sprintf("global rule %q matched", rule.Name)},
			}
		}
	}
	return nil
}

func matchGlobal(m Match, req EvalRequest, activeTaint []string) bool {
	if len(m.Methods) > 0 && !contains(m.Methods, req.Method) {
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
				Action:   rule.Action,
				Rule:     rule.Name,
				Reason:   rule.Reason,
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
func (pe *PolicyEngine) evalToolCall(req EvalRequest, d Decision, server *ServerPolicy, taintState *TaintState) Decision {
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
	if pe.policy.Redaction.Enabled && len(req.Arguments) > 0 {
		redacted := redactArguments(req.Arguments, pe.policy.Redaction.Patterns)
		if len(redacted) > 0 {
			d.RedactedArgs = redacted
			d.Evidence = append(d.Evidence, "arguments redacted per policy")
		}
	}

	// Apply taint label from tool output
	if tool.TaintLabel != "" {
		taintState.Add(req.SessionID, tool.TaintLabel, fmt.Sprintf("%s/%s", req.Server, req.Tool))
		d.TaintApplied = []string{tool.TaintLabel}
		d.Evidence = append(d.Evidence, fmt.Sprintf("taint label applied: %s", tool.TaintLabel))
	}

	d.Action = tool.Action
	d.Rule = fmt.Sprintf("server:%s/tool:%s", req.Server, req.Tool)
	d.Reason = fmt.Sprintf("tool %q %s by server policy", req.Tool, tool.Action)
	return d
}

// evalResourceRead checks resource access policy.
func (pe *PolicyEngine) evalResourceRead(req EvalRequest, d Decision, server *ServerPolicy) Decision {
	for _, rp := range server.AllowedResources {
		matched, _ := filepath.Match(rp.Pattern, req.Resource)
		if matched {
			d.Action = rp.Action
			d.Rule = fmt.Sprintf("server:%s/resource:%s", req.Server, rp.Pattern)
			d.Reason = fmt.Sprintf("resource %q matched pattern %q", req.Resource, rp.Pattern)
			return d
		}
	}

	d.Action = pe.policy.DefaultAction
	d.Rule = "default:resource-not-in-allowlist"
	d.Reason = fmt.Sprintf("resource %q not in allowlist for server %q", req.Resource, req.Server)
	return d
}

// validateArgs checks arguments against rules.
func validateArgs(rules []ArgRule, args map[string]string) []string {
	var violations []string

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

	pathKeys := []string{"path", "file", "filepath", "filename", "directory", "dir", "target"}

	for _, key := range pathKeys {
		val, ok := args[key]
		if !ok {
			continue
		}

		clean := filepath.Clean(val)

		// Block path traversal
		if strings.Contains(clean, "..") {
			return fmt.Sprintf("path traversal detected in argument %q: %s", key, val)
		}

		withinAllowed := false
		for _, prefix := range allowed {
			if strings.HasPrefix(clean, filepath.Clean(prefix)) {
				withinAllowed = true
				break
			}
		}

		if !withinAllowed {
			return fmt.Sprintf("argument %q path %q outside allowed directories %v", key, clean, allowed)
		}
	}

	return ""
}

// ---------- policy loading ----------

// LoadPolicy reads and parses a policy YAML file.
func LoadPolicy(path string) (*FirewallPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var policy FirewallPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	if policy.DefaultAction == "" {
		policy.DefaultAction = "deny"
	}

	return &policy, nil
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
	var parts []string
	for k, v := range args {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

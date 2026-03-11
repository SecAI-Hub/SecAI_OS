package main

import "fmt"

// ---------------------------------------------------------------------------
// Retrieval request and response types
// ---------------------------------------------------------------------------

// RetrievalRequest describes who is asking for what context.
type RetrievalRequest struct {
	Query         string   `json:"query"`
	User          string   `json:"user,omitempty"`
	Session       string   `json:"session,omitempty"`
	SessionTrust  string   `json:"session_trust,omitempty"` // high, medium, low
	Tool          string   `json:"tool,omitempty"`
	RequesterType string   `json:"requester_type,omitempty"` // user, tool, system
	Model         string   `json:"model,omitempty"`
	MaxChunks     int      `json:"max_chunks,omitempty"`
	ChunkIDs      []string `json:"chunk_ids,omitempty"`      // evaluate specific chunks
	DocumentIDs   []string `json:"document_ids,omitempty"`   // filter by document
}

// ChunkDecision records the policy verdict for a single chunk.
type ChunkDecision struct {
	ChunkID  string   `json:"chunk_id"`
	Action   string   `json:"action"` // allow, deny, redact, require-approval
	Rule     string   `json:"rule"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence"`
	Content  string   `json:"content,omitempty"` // included for allowed/redacted; omitted for denied
}

// RetrievalResponse is the full policy evaluation result.
type RetrievalResponse struct {
	Allowed         []ChunkDecision `json:"allowed"`
	Denied          []ChunkDecision `json:"denied"`
	Redacted        []ChunkDecision `json:"redacted,omitempty"`
	PendingApproval []ChunkDecision `json:"pending_approval,omitempty"`
	Summary         DecisionSummary `json:"summary"`
}

// DecisionSummary tallies the verdict breakdown.
type DecisionSummary struct {
	TotalChunks     int `json:"total_chunks"`
	Allowed         int `json:"allowed"`
	Denied          int `json:"denied"`
	Redacted        int `json:"redacted"`
	PendingApproval int `json:"pending_approval"`
}

// ---------------------------------------------------------------------------
// Policy rule types
// ---------------------------------------------------------------------------

// Rule defines a single policy rule evaluated against chunks.
type Rule struct {
	Name           string    `yaml:"name"`
	Description    string    `yaml:"description,omitempty"`
	Match          RuleMatch `yaml:"match"`
	Action         string    `yaml:"action"` // allow, deny, redact, require-approval
	Reason         string    `yaml:"reason,omitempty"`
	RedactPatterns []string  `yaml:"redact_patterns,omitempty"`
}

// RuleMatch specifies conditions that must ALL be true (AND logic).
type RuleMatch struct {
	Sensitivity         []string          `yaml:"sensitivity,omitempty"`
	TrustLevel          []string          `yaml:"trust_level,omitempty"`
	Source              []string          `yaml:"source,omitempty"`
	RequesterType       []string          `yaml:"requester_type,omitempty"`
	SessionTrust        []string          `yaml:"session_trust,omitempty"`
	Labels              map[string]string `yaml:"labels,omitempty"`
	ScanPromptInjection *bool             `yaml:"scan_prompt_injection,omitempty"`
	ScanPIIDetected     *bool             `yaml:"scan_pii_detected,omitempty"`
	MinRiskScore        *float64          `yaml:"min_risk_score,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy engine — deny-first precedence
// ---------------------------------------------------------------------------

// PolicyEngine evaluates retrieval requests against ordered rules.
// Deny rules are always evaluated first regardless of position in the
// rule list, ensuring security-critical blocks cannot be bypassed by
// an allow rule that appears earlier.
type PolicyEngine struct {
	defaultAction string
	rules         []Rule
}

// NewPolicyEngine creates an engine from policy config.
func NewPolicyEngine(defaultAction string, rules []Rule) *PolicyEngine {
	if defaultAction == "" {
		defaultAction = "deny"
	}
	return &PolicyEngine{
		defaultAction: defaultAction,
		rules:         rules,
	}
}

// EvaluateChunk evaluates a single chunk against the policy for a given request.
// Uses deny-first precedence: all deny rules are checked before any allow/redact rules.
func (e *PolicyEngine) EvaluateChunk(chunk Chunk, docSource string, req RetrievalRequest) ChunkDecision {
	// Pass 1: Deny rules take priority — any matching deny rule blocks immediately.
	for _, rule := range e.rules {
		if rule.Action != "deny" {
			continue
		}
		if matchesRule(chunk, docSource, req, rule.Match) {
			return ChunkDecision{
				ChunkID:  chunk.ID,
				Action:   "deny",
				Rule:     rule.Name,
				Reason:   rule.Reason,
				Evidence: buildEvidence(chunk, docSource, req, rule),
			}
		}
	}

	// Pass 2: Non-deny rules in config order (require-approval, redact, allow).
	for _, rule := range e.rules {
		if rule.Action == "deny" {
			continue
		}
		if matchesRule(chunk, docSource, req, rule.Match) {
			decision := ChunkDecision{
				ChunkID:  chunk.ID,
				Action:   rule.Action,
				Rule:     rule.Name,
				Reason:   rule.Reason,
				Evidence: buildEvidence(chunk, docSource, req, rule),
			}
			switch rule.Action {
			case "allow":
				decision.Content = chunk.Content
			case "redact":
				decision.Content = RedactContent(chunk.Content, rule.RedactPatterns)
			}
			return decision
		}
	}

	// Default action: no rule matched.
	decision := ChunkDecision{
		ChunkID: chunk.ID,
		Action:  e.defaultAction,
		Rule:    "default",
		Reason:  "no matching rule; default policy applied",
		Evidence: []string{
			fmt.Sprintf("chunk.sensitivity=%s", chunk.SensitivityLabel),
			fmt.Sprintf("chunk.trust=%s", chunk.TrustLevel),
			fmt.Sprintf("default_action=%s", e.defaultAction),
		},
	}
	if e.defaultAction == "allow" {
		decision.Content = chunk.Content
	}
	return decision
}

// Evaluate runs policy evaluation for all candidate chunks.
func (e *PolicyEngine) Evaluate(chunks []Chunk, docSourceMap map[string]string, req RetrievalRequest) RetrievalResponse {
	var resp RetrievalResponse

	for _, chunk := range chunks {
		docSource := docSourceMap[chunk.DocumentID]
		decision := e.EvaluateChunk(chunk, docSource, req)

		switch decision.Action {
		case "allow":
			resp.Allowed = append(resp.Allowed, decision)
		case "deny":
			resp.Denied = append(resp.Denied, decision)
		case "redact":
			resp.Redacted = append(resp.Redacted, decision)
		case "require-approval":
			resp.PendingApproval = append(resp.PendingApproval, decision)
		default:
			resp.Denied = append(resp.Denied, decision)
		}
	}

	resp.Summary = DecisionSummary{
		TotalChunks:     len(chunks),
		Allowed:         len(resp.Allowed),
		Denied:          len(resp.Denied),
		Redacted:        len(resp.Redacted),
		PendingApproval: len(resp.PendingApproval),
	}

	if req.MaxChunks > 0 && len(resp.Allowed) > req.MaxChunks {
		resp.Allowed = resp.Allowed[:req.MaxChunks]
	}

	return resp
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

func matchesRule(chunk Chunk, docSource string, req RetrievalRequest, match RuleMatch) bool {
	// All specified conditions must match (AND logic).
	if len(match.Sensitivity) > 0 && !containsStr(match.Sensitivity, chunk.SensitivityLabel) {
		return false
	}
	if len(match.TrustLevel) > 0 && !containsStr(match.TrustLevel, chunk.TrustLevel) {
		return false
	}
	if len(match.Source) > 0 && !containsStr(match.Source, docSource) {
		return false
	}
	if len(match.RequesterType) > 0 && !containsStr(match.RequesterType, req.RequesterType) {
		return false
	}
	if len(match.SessionTrust) > 0 && !containsStr(match.SessionTrust, req.SessionTrust) {
		return false
	}
	if match.ScanPromptInjection != nil && *match.ScanPromptInjection != chunk.Scan.PromptInjection {
		return false
	}
	if match.ScanPIIDetected != nil && *match.ScanPIIDetected != chunk.Scan.PIIDetected {
		return false
	}
	if match.MinRiskScore != nil && chunk.Scan.RiskScore < *match.MinRiskScore {
		return false
	}
	// Label matching: all specified labels must be present and equal.
	for k, v := range match.Labels {
		if chunk.Labels == nil || chunk.Labels[k] != v {
			return false
		}
	}
	return true
}

func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Evidence builder
// ---------------------------------------------------------------------------

func buildEvidence(chunk Chunk, docSource string, req RetrievalRequest, rule Rule) []string {
	var ev []string
	ev = append(ev, fmt.Sprintf("chunk.id=%s", chunk.ID))
	ev = append(ev, fmt.Sprintf("chunk.sensitivity=%s", chunk.SensitivityLabel))
	ev = append(ev, fmt.Sprintf("chunk.trust=%s", chunk.TrustLevel))

	if docSource != "" {
		ev = append(ev, fmt.Sprintf("document.source=%s", docSource))
	}
	if chunk.Scan.PromptInjection {
		ev = append(ev, "scan.prompt_injection=true")
	}
	if chunk.Scan.PIIDetected {
		ev = append(ev, fmt.Sprintf("scan.pii_types=%v", chunk.Scan.PIITypes))
	}
	if chunk.Scan.RiskScore > 0 {
		ev = append(ev, fmt.Sprintf("scan.risk_score=%.2f", chunk.Scan.RiskScore))
	}
	if req.RequesterType != "" {
		ev = append(ev, fmt.Sprintf("requester.type=%s", req.RequesterType))
	}
	if req.SessionTrust != "" {
		ev = append(ev, fmt.Sprintf("session.trust=%s", req.SessionTrust))
	}
	if req.Tool != "" {
		ev = append(ev, fmt.Sprintf("requester.tool=%s", req.Tool))
	}
	ev = append(ev, fmt.Sprintf("matched_rule=%s", rule.Name))
	ev = append(ev, fmt.Sprintf("action=%s", rule.Action))
	return ev
}

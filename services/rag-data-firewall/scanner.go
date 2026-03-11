package main

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Content scanning — prompt injection, PII, suspicious patterns
// ---------------------------------------------------------------------------

// ScanResult captures all findings from content analysis.
type ScanResult struct {
	PromptInjection    bool         `json:"prompt_injection"`
	PIIDetected        bool         `json:"pii_detected"`
	PIITypes           []string     `json:"pii_types,omitempty"`
	SuspiciousPatterns []string     `json:"suspicious_patterns,omitempty"`
	RiskScore          float64      `json:"risk_score"` // 0.0 (clean) to 1.0 (high risk)
	RiskReasons        []RiskReason `json:"risk_reasons,omitempty"`
}

// RiskReason explains one factor contributing to the risk score.
type RiskReason struct {
	Category string  `json:"category"` // prompt_injection, encoded_injection, smuggling, data_exfil, pii, suspicious
	Pattern  string  `json:"pattern"`
	Weight   float64 `json:"weight"`
	Detail   string  `json:"detail"`
}

// ScannerConfig controls which scans are enabled.
type ScannerConfig struct {
	PromptInjection    bool    `yaml:"prompt_injection"`
	PIIDetection       bool    `yaml:"pii_detection"`
	SuspiciousPatterns bool    `yaml:"suspicious_patterns"`
	MinRiskToFlag      float64 `yaml:"min_risk_to_flag"`
}

// ---------------------------------------------------------------------------
// Prompt injection detection
// ---------------------------------------------------------------------------

var promptInjectionPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`), "ignore_previous"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|above|prior)`), "disregard"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+`), "role_override"},
	{regexp.MustCompile(`(?i)forget\s+(everything|all|your)\b`), "forget"},
	{regexp.MustCompile(`(?i)new\s+instructions?\s*:`), "new_instructions"},
	{regexp.MustCompile(`(?i)system\s*prompt\s*:`), "system_prompt_leak"},
	{regexp.MustCompile(`(?i)<\|im_start\|>`), "chat_delimiter"},
	{regexp.MustCompile(`(?i)\[INST\]`), "inst_delimiter"},
	{regexp.MustCompile(`(?i)\[SYSTEM\]`), "system_delimiter"},
	{regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+are|a)\s+`), "act_as"},
	{regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+`), "pretend"},
	{regexp.MustCompile(`(?i)override\s+(your|the|all)\s+`), "override"},
	{regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your|the|any)\s+(rules|guidelines|instructions)`), "rule_bypass"},
	{regexp.MustCompile(`(?i)output\s+(your|the)\s+(system|initial)\s+prompt`), "prompt_extraction"},
}

func detectPromptInjection(content string) (bool, []string) {
	var matched []string
	for _, p := range promptInjectionPatterns {
		if p.Pattern.MatchString(content) {
			matched = append(matched, p.Name)
		}
	}
	return len(matched) > 0, matched
}

// ---------------------------------------------------------------------------
// Encoded / obfuscated injection detection
// ---------------------------------------------------------------------------

var encodedInjectionPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	// Unicode bidirectional override characters (used to hide injected text).
	{regexp.MustCompile("[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]"), "unicode_bidi_override"},
	// Clusters of zero-width characters that can hide instructions.
	{regexp.MustCompile("[\u200B\u200C\u200D\uFEFF]{3,}"), "zero_width_hiding"},
	// HTML entity-encoded tags (obfuscated script/iframe injection).
	{regexp.MustCompile(`(?i)&lt;\s*/?(?:script|iframe|object|embed)`), "html_entity_tag"},
	// Long hex escape sequences (potential obfuscated payload).
	{regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){4,}`), "hex_escape_sequence"},
}

func detectEncodedInjection(content string) []string {
	var found []string
	for _, p := range encodedInjectionPatterns {
		if p.Pattern.MatchString(content) {
			found = append(found, p.Name)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Instruction smuggling detection
// ---------------------------------------------------------------------------

var instructionSmugglingPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	// Markdown code fence with system/instruction label.
	{regexp.MustCompile("(?i)```\\s*(?:system|instructions?|prompt)"), "markdown_fence_injection"},
	// HTML comment-hidden instructions.
	{regexp.MustCompile(`(?i)<!--\s*(?:ignore|override|system|instruction)`), "html_comment_injection"},
	// CSS-based invisible text tricks.
	{regexp.MustCompile(`(?i)color\s*:\s*(?:white|transparent|rgba\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0)`), "invisible_text"},
	// Delimiter-based role switching.
	{regexp.MustCompile(`(?i)(?:###|---)\s*(?:system|assistant|human)\s*(?:###|---)`), "delimiter_role_switch"},
}

func detectInstructionSmuggling(content string) []string {
	var found []string
	for _, p := range instructionSmugglingPatterns {
		if p.Pattern.MatchString(content) {
			found = append(found, p.Name)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Data exfiltration pattern detection
// ---------------------------------------------------------------------------

var dataExfilPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	// URL fetch commands embedded in content.
	{regexp.MustCompile(`(?i)(?:fetch|curl|wget|http\.get)\s*\(\s*['"]https?://`), "url_fetch"},
	// File protocol references.
	{regexp.MustCompile(`(?i)file://`), "file_protocol"},
	// Markdown image/link exfiltration (data in query params).
	{regexp.MustCompile(`(?i)!\[.*?\]\(https?://[^\s)]+\?.*?(?:data|token|key|secret|password)=`), "markdown_exfil"},
	// DNS-based exfiltration hints.
	{regexp.MustCompile(`(?i)(?:nslookup|dig|host)\s+\S+\.\S+`), "dns_exfil"},
	// Instruction to send data to external service.
	{regexp.MustCompile(`(?i)(?:send|post|upload|transmit)\s+(?:this|the|all)\s+(?:the\s+)?(?:data|information|content|text)\s+to\s+`), "send_data_instruction"},
}

func detectDataExfil(content string) []string {
	var found []string
	for _, p := range dataExfilPatterns {
		if p.Pattern.MatchString(content) {
			found = append(found, p.Name)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Base64-encoded injection detection
// ---------------------------------------------------------------------------

var b64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// detectBase64Injection checks for base64-encoded strings that decode
// to prompt injection content.
func detectBase64Injection(content string) bool {
	matches := b64Pattern.FindAllString(content, 5) // limit checks
	for _, m := range matches {
		decoded, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(m)
			if err != nil {
				continue
			}
		}
		if injected, _ := detectPromptInjection(string(decoded)); injected {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// PII detection
// ---------------------------------------------------------------------------

var piiPatterns = []struct {
	Pattern *regexp.Regexp
	Type    string
}{
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "ssn"},
	{regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`), "email"},
	{regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`), "credit_card"},
	{regexp.MustCompile(`(?i)(password|secret|api[_-]?key)\s*[:=]\s*\S+`), "credential"},
	{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`), "bearer_token"},
	{regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`), "phone"},
}

func detectPII(content string) (bool, []string) {
	typeSet := make(map[string]bool)
	for _, p := range piiPatterns {
		if p.Pattern.MatchString(content) {
			typeSet[p.Type] = true
		}
	}
	if len(typeSet) == 0 {
		return false, nil
	}
	var types []string
	for t := range typeSet {
		types = append(types, t)
	}
	return true, types
}

// ---------------------------------------------------------------------------
// Suspicious pattern detection
// ---------------------------------------------------------------------------

var suspiciousPatterns = []struct {
	Pattern *regexp.Regexp
	Name    string
}{
	{regexp.MustCompile(`(?i)\beval\s*\(`), "eval_call"},
	{regexp.MustCompile(`(?i)\bexec\s*\(`), "exec_call"},
	{regexp.MustCompile(`(?i)\bimport\s+os\b`), "import_os"},
	{regexp.MustCompile(`(?i)\bsubprocess\b`), "subprocess"},
	{regexp.MustCompile(`(?i)\b__import__\b`), "dunder_import"},
	{regexp.MustCompile(`(?i)curl\s+.+\|\s*(?:bash|sh)`), "pipe_to_shell"},
	{regexp.MustCompile(`(?i)<script\b`), "script_tag"},
	{regexp.MustCompile(`(?i)javascript\s*:`), "js_uri"},
}

func detectSuspicious(content string) []string {
	var found []string
	for _, p := range suspiciousPatterns {
		if p.Pattern.MatchString(content) {
			found = append(found, p.Name)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Unified scanner
// ---------------------------------------------------------------------------

// ScanContent runs all enabled scans on content and returns a composite result.
func ScanContent(content string, cfg ScannerConfig) ScanResult {
	var result ScanResult
	var riskFactors int
	var riskSum float64

	if cfg.PromptInjection {
		injected, patterns := detectPromptInjection(content)
		result.PromptInjection = injected
		if injected {
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, patterns...)
			for _, p := range patterns {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "prompt_injection", Pattern: p, Weight: 0.9,
					Detail: "direct prompt injection pattern detected",
				})
			}
			riskFactors++
			riskSum += 0.9
		}

		// Encoded / obfuscated injection.
		encodedMatches := detectEncodedInjection(content)
		if len(encodedMatches) > 0 {
			result.PromptInjection = true
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, encodedMatches...)
			for _, p := range encodedMatches {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "encoded_injection", Pattern: p, Weight: 0.85,
					Detail: "obfuscated or encoded injection attempt",
				})
			}
			riskFactors++
			riskSum += 0.85
		}

		// Instruction smuggling via document structure.
		smuggling := detectInstructionSmuggling(content)
		if len(smuggling) > 0 {
			result.PromptInjection = true
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, smuggling...)
			for _, p := range smuggling {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "smuggling", Pattern: p, Weight: 0.8,
					Detail: "instruction smuggling via document structure",
				})
			}
			riskFactors++
			riskSum += 0.8
		}

		// Data exfiltration patterns.
		exfil := detectDataExfil(content)
		if len(exfil) > 0 {
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, exfil...)
			for _, p := range exfil {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "data_exfil", Pattern: p, Weight: 0.75,
					Detail: "potential data exfiltration attempt",
				})
			}
			riskFactors++
			riskSum += 0.75
		}

		// Base64-encoded injection.
		if detectBase64Injection(content) {
			result.PromptInjection = true
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, "base64_injection")
			result.RiskReasons = append(result.RiskReasons, RiskReason{
				Category: "encoded_injection", Pattern: "base64_injection", Weight: 0.85,
				Detail: "base64-encoded content contains injection patterns",
			})
			riskFactors++
			riskSum += 0.85
		}
	}

	if cfg.PIIDetection {
		hasPII, types := detectPII(content)
		result.PIIDetected = hasPII
		result.PIITypes = types
		if hasPII {
			for _, t := range types {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "pii", Pattern: t, Weight: 0.4,
					Detail: "personally identifiable information detected",
				})
			}
			riskFactors++
			riskSum += 0.4
		}
	}

	if cfg.SuspiciousPatterns {
		suspicious := detectSuspicious(content)
		if len(suspicious) > 0 {
			result.SuspiciousPatterns = append(result.SuspiciousPatterns, suspicious...)
			for _, p := range suspicious {
				result.RiskReasons = append(result.RiskReasons, RiskReason{
					Category: "suspicious", Pattern: p, Weight: 0.7,
					Detail: "suspicious code pattern detected",
				})
			}
			riskFactors++
			riskSum += 0.7
		}
	}

	if riskFactors > 0 {
		result.RiskScore = riskSum / float64(riskFactors)
	}

	return result
}

// ---------------------------------------------------------------------------
// PII redaction (for redact action)
// ---------------------------------------------------------------------------

var piiRedactionRules = []struct {
	Pattern *regexp.Regexp
	Tag     string
}{
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[REDACTED:ssn]"},
	{regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`), "[REDACTED:email]"},
	{regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`), "[REDACTED:card]"},
	{regexp.MustCompile(`(?i)(password|secret|api[_-]?key)\s*[:=]\s*\S+`), "[REDACTED:credential]"},
	{regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`), "[REDACTED:bearer]"},
	{regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`), "[REDACTED:phone]"},
}

// RedactContent replaces PII in content with tagged placeholders.
func RedactContent(content string, patterns []string) string {
	filterSet := make(map[string]bool)
	for _, p := range patterns {
		filterSet[p] = true
	}

	for _, rule := range piiRedactionRules {
		// If specific patterns requested, only apply matching ones.
		tag := strings.TrimPrefix(strings.TrimSuffix(rule.Tag, "]"), "[REDACTED:")
		if len(filterSet) > 0 && !filterSet[tag] {
			continue
		}
		content = rule.Pattern.ReplaceAllString(content, rule.Tag)
	}
	return content
}

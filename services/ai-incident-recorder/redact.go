package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// PII and credential redaction
// ---------------------------------------------------------------------------

// RedactionRule maps a pattern to a replacement tag.
type RedactionRule struct {
	Name    string
	Pattern *regexp.Regexp
	Tag     string // replacement text, e.g. [REDACTED:email]
}

// defaultRedactionRules returns the built-in redaction patterns.
// Tags preserve forensic meaning: investigators know what TYPE of data
// was removed without seeing the actual value.
var defaultRedactionRules = []RedactionRule{
	{
		Name:    "ssn",
		Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Tag:     "[REDACTED:ssn]",
	},
	{
		Name:    "email",
		Pattern: regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
		Tag:     "[REDACTED:email]",
	},
	{
		Name:    "credential",
		Pattern: regexp.MustCompile(`(?i)(password|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*\S+`),
		Tag:     "[REDACTED:credential]",
	},
	{
		Name:    "bearer_token",
		Pattern: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),
		Tag:     "[REDACTED:bearer]",
	},
	{
		Name:    "credit_card",
		Pattern: regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
		Tag:     "[REDACTED:card]",
	},
}

// RedactionStats tracks how many redactions of each type were applied.
type RedactionStats struct {
	Counts map[string]int `json:"counts"`
}

// RedactString applies all enabled redaction rules to a string.
func RedactString(s string, rules []RedactionRule, stats *RedactionStats) string {
	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringIndex(s, -1)
		if len(matches) > 0 {
			s = rule.Pattern.ReplaceAllString(s, rule.Tag)
			if stats != nil {
				stats.Counts[rule.Name] += len(matches)
			}
		}
	}
	return s
}

// RedactMap recursively redacts all string values in a map.
func RedactMap(data map[string]interface{}, rules []RedactionRule, stats *RedactionStats) map[string]interface{} {
	if data == nil {
		return nil
	}
	redacted := make(map[string]interface{}, len(data))
	for k, v := range data {
		redacted[k] = redactValue(v, rules, stats)
	}
	return redacted
}

func redactValue(v interface{}, rules []RedactionRule, stats *RedactionStats) interface{} {
	switch val := v.(type) {
	case string:
		return RedactString(val, rules, stats)
	case map[string]interface{}:
		return RedactMap(val, rules, stats)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = redactValue(item, rules, stats)
		}
		return result
	default:
		return v
	}
}

// RedactEvent returns a copy of the event with PII redacted from Data and Actor.
// The original event is NOT modified.
func RedactEvent(e Event, rules []RedactionRule, stats *RedactionStats) Event {
	redacted := e
	redacted.Actor = RedactString(e.Actor, rules, stats)
	redacted.Data = RedactMap(e.Data, rules, stats)
	return redacted
}

// RedactEvents redacts a slice of events, returning new copies.
func RedactEvents(events []Event, enabledPatterns []string) ([]Event, RedactionStats) {
	stats := RedactionStats{Counts: make(map[string]int)}

	// Filter rules by enabled pattern names.
	var rules []RedactionRule
	if len(enabledPatterns) == 0 {
		rules = defaultRedactionRules
	} else {
		enabled := make(map[string]bool)
		for _, p := range enabledPatterns {
			enabled[p] = true
		}
		for _, r := range defaultRedactionRules {
			if enabled[r.Name] {
				rules = append(rules, r)
			}
		}
	}

	redacted := make([]Event, len(events))
	for i, e := range events {
		redacted[i] = RedactEvent(e, rules, &stats)
	}
	return redacted, stats
}

// summarizeEvent generates a one-line human-readable summary of an event.
func summarizeEvent(e Event) string {
	switch e.Type {
	case "tool.decision":
		tool, _ := e.Data["tool"].(string)
		allowed, _ := e.Data["allowed"].(bool)
		reason, _ := e.Data["reason"].(string)
		verdict := "DENIED"
		if allowed {
			verdict = "allowed"
		}
		return fmt.Sprintf("Tool '%s' — %s (%s)", tool, verdict, reason)

	case "model.invoke":
		model, _ := e.Data["model"].(string)
		return fmt.Sprintf("Model '%s' invoked", model)

	case "model.load":
		model, _ := e.Data["model"].(string)
		return fmt.Sprintf("Model '%s' loaded", model)

	case "airlock.request":
		dest, _ := e.Data["destination"].(string)
		allowed, _ := e.Data["allowed"].(bool)
		verdict := "BLOCKED"
		if allowed {
			verdict = "allowed"
		}
		return fmt.Sprintf("Egress to %s — %s", dest, verdict)

	case "registry.promote":
		model, _ := e.Data["model"].(string)
		return fmt.Sprintf("Model '%s' promoted to registry", model)

	case "registry.delete":
		model, _ := e.Data["model"].(string)
		return fmt.Sprintf("Model '%s' deleted from registry", model)

	case "attestor.report":
		verdict, _ := e.Data["verdict"].(string)
		return fmt.Sprintf("Attestation: %s", strings.ToUpper(verdict))

	case "quarantine.scan":
		result, _ := e.Data["result"].(string)
		return fmt.Sprintf("Quarantine scan: %s", result)

	case "policy.reload":
		service, _ := e.Data["service"].(string)
		return fmt.Sprintf("Policy reloaded for %s", service)

	default:
		return fmt.Sprintf("[%s] %s event from %s", e.Severity, e.Type, e.Source)
	}
}

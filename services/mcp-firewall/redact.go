package main

import (
	"regexp"
	"strings"
)

// redactionRule maps a pattern name to a compiled regex and replacement.
type redactionRule struct {
	name    string
	re      *regexp.Regexp
	replace string
}

var defaultRedactionRules = []redactionRule{
	{
		name:    "api_key",
		re:      regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["']?[\w\-]{20,}["']?`),
		replace: "[REDACTED:api_key]",
	},
	{
		name:    "bearer_token",
		re:      regexp.MustCompile(`(?i)bearer\s+[\w\-\.]{20,}`),
		replace: "[REDACTED:bearer_token]",
	},
	{
		name:    "password",
		re:      regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{4,}["']?`),
		replace: "[REDACTED:password]",
	},
	{
		name:    "email",
		re:      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		replace: "[REDACTED:email]",
	},
	{
		name:    "aws_key",
		re:      regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
		replace: "[REDACTED:aws_key]",
	},
	{
		name:    "private_key",
		re:      regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		replace: "[REDACTED:private_key]",
	},
	{
		name:    "connection_string",
		re:      regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis)://[^\s]+`),
		replace: "[REDACTED:connection_string]",
	},
	{
		name:    "ssn",
		re:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		replace: "[REDACTED:ssn]",
	},
}

// redactString applies enabled redaction patterns to a string.
func redactString(s string, enabledPatterns []string) string {
	if len(enabledPatterns) == 0 {
		return s
	}

	enabled := make(map[string]bool)
	for _, p := range enabledPatterns {
		enabled[strings.ToLower(p)] = true
	}

	// Check for "all" pattern
	allEnabled := enabled["all"]

	for _, rule := range defaultRedactionRules {
		if allEnabled || enabled[rule.name] {
			s = rule.re.ReplaceAllString(s, rule.replace)
		}
	}

	return s
}

// redactArguments redacts secrets in tool arguments.
// Returns a new map with redacted values (only entries that changed).
func redactArguments(args map[string]string, patterns []string) map[string]string {
	if len(patterns) == 0 || len(args) == 0 {
		return nil
	}

	redacted := make(map[string]string)
	for k, v := range args {
		cleaned := redactString(v, patterns)
		if cleaned != v {
			redacted[k] = cleaned
		}
	}

	if len(redacted) == 0 {
		return nil
	}
	return redacted
}

// redactOutput applies redaction patterns to MCP tool output.
func redactOutput(output string, patterns []string) string {
	return redactString(output, patterns)
}

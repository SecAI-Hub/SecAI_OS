package main

import (
	"regexp"
	"strings"
)

// redaction patterns
var (
	reAbsPath  = regexp.MustCompile(`(?:^|[\s"':=])(/(?:home|Users|var|tmp|etc|opt|usr|root|vault|run)/[^\s"']+)`)
	reWinPath  = regexp.MustCompile(`[A-Z]:\\[^\s"']+`)
	reHostPort = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)\b`)
)

// redactReport applies privacy controls to a trust report.
// Returns a new report; the original is not modified.
func redactReport(report TrustReport, profile PrivacyProfile) TrustReport {
	result := report

	if profile.StripHostname {
		result.Hostname = "[REDACTED]"
	}

	// Redact collector findings
	result.Attestation.Collectors = make([]CollectorResult, len(report.Attestation.Collectors))
	for i, col := range report.Attestation.Collectors {
		result.Attestation.Collectors[i] = redactCollectorResult(col, profile)
	}

	return result
}

func redactCollectorResult(col CollectorResult, profile PrivacyProfile) CollectorResult {
	result := col
	result.Error = redactString(col.Error, profile)
	result.Findings = make([]Finding, len(col.Findings))
	for i, f := range col.Findings {
		result.Findings[i] = redactFinding(f, profile)
	}
	return result
}

func redactFinding(f Finding, profile PrivacyProfile) Finding {
	result := f
	result.Detail = redactString(f.Detail, profile)
	result.Expected = redactString(f.Expected, profile)
	result.Actual = redactString(f.Actual, profile)

	if profile.StripListeners && isListenerKey(f.Key) {
		result.Key = "[REDACTED:listener]"
	}
	if profile.StripPolicyNames && isPolicyKey(f.Key) {
		result.Key = "[REDACTED:policy]"
	}
	if profile.StripPaths && isPathValue(f.Key) {
		result.Key = redactPaths(f.Key)
	}

	return result
}

func redactString(s string, profile PrivacyProfile) string {
	if s == "" {
		return s
	}
	if profile.StripPaths {
		s = redactPaths(s)
	}
	if profile.StripListeners {
		s = reHostPort.ReplaceAllString(s, "[REDACTED:listener]")
	}
	return s
}

func redactPaths(s string) string {
	s = reAbsPath.ReplaceAllStringFunc(s, func(match string) string {
		for i, c := range match {
			if c == '/' {
				return match[:i] + "[REDACTED:path]"
			}
		}
		return "[REDACTED:path]"
	})
	s = reWinPath.ReplaceAllString(s, "[REDACTED:path]")
	return s
}

func isListenerKey(key string) bool {
	// Listener keys look like "127.0.0.1:8470" or "0.0.0.0:8080"
	return reHostPort.MatchString(key)
}

func isPolicyKey(key string) bool {
	return strings.HasPrefix(key, "tool-") || strings.HasPrefix(key, "airlock") ||
		strings.HasPrefix(key, "registry") || strings.HasPrefix(key, "attestor")
}

func isPathValue(key string) bool {
	return strings.HasPrefix(key, "/") || strings.Contains(key, ":\\")
}

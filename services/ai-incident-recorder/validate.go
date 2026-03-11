package main

import (
	"fmt"
	"regexp"
	"time"
)

var (
	validSeverities = map[string]bool{
		"info": true, "warning": true, "alert": true, "critical": true,
	}
	validStatuses = map[string]bool{
		"open": true, "investigating": true, "resolved": true, "closed": true,
	}
	reIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
)

const maxSessionIDLen = 128

// validateEvent checks structural validity of an event before recording.
func validateEvent(e Event) error {
	if e.Source == "" {
		return fmt.Errorf("source is required")
	}
	if e.Type == "" {
		return fmt.Errorf("type is required")
	}
	if !reIdentifier.MatchString(e.Source) {
		return fmt.Errorf("invalid source format")
	}
	if !reIdentifier.MatchString(e.Type) {
		return fmt.Errorf("invalid type format")
	}
	if e.Severity != "" && !validSeverities[e.Severity] {
		return fmt.Errorf("invalid severity: %s (must be info, warning, alert, or critical)", e.Severity)
	}
	if e.SessionID != "" && len(e.SessionID) > maxSessionIDLen {
		return fmt.Errorf("session_id too long (%d chars, max %d)", len(e.SessionID), maxSessionIDLen)
	}
	if e.Timestamp != "" {
		if _, ok := parseTimestamp(e.Timestamp); !ok {
			return fmt.Errorf("invalid timestamp format (expected RFC3339)")
		}
	}
	return nil
}

// validateIncident checks structural validity of an incident before creation.
func validateIncident(inc Incident) error {
	if inc.Title == "" {
		return fmt.Errorf("title is required")
	}
	if inc.Severity != "" && !validSeverities[inc.Severity] {
		return fmt.Errorf("invalid severity: %s", inc.Severity)
	}
	if inc.Status != "" && !validStatuses[inc.Status] {
		return fmt.Errorf("invalid status: %s", inc.Status)
	}
	if inc.SessionID != "" && len(inc.SessionID) > maxSessionIDLen {
		return fmt.Errorf("session_id too long")
	}
	return nil
}

// parseTimestamp tries RFC3339Nano then RFC3339.
func parseTimestamp(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// =========================================================================
// Recovery ceremony — explicit acknowledgment + re-attestation
// =========================================================================

// RecoveryRequirement defines what must happen before returning to trusted mode.
type RecoveryRequirement struct {
	IncidentID       string `json:"incident_id"`
	RequireAck       bool   `json:"require_ack"`
	RequireReattest  bool   `json:"require_reattest"`
	AckedAt          string `json:"acked_at,omitempty"`
	AckedBy          string `json:"acked_by,omitempty"`
	ReAttestedAt     string `json:"re_attested_at,omitempty"`
	RecoveryComplete bool   `json:"recovery_complete"`
}

// RecoveryManager tracks recovery ceremonies for contained incidents.
type RecoveryManager struct {
	mu           sync.RWMutex
	requirements map[string]*RecoveryRequirement // incident_id → requirement
}

func NewRecoveryManager() *RecoveryManager {
	return &RecoveryManager{
		requirements: make(map[string]*RecoveryRequirement),
	}
}

// RequireRecovery creates a recovery requirement for an incident.
// Critical incidents always require both ack and re-attestation.
func (rm *RecoveryManager) RequireRecovery(incidentID string, severity IncidentSeverity, class IncidentClass) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	req := &RecoveryRequirement{
		IncidentID:  incidentID,
		RequireAck:  true,
		RequireReattest: severity == SeverityCritical ||
			class == ClassAttestationFailure ||
			class == ClassIntegrityViolation,
	}
	rm.requirements[incidentID] = req
	log.Printf("recovery: ceremony required for incident %s (ack=%v reattest=%v)",
		incidentID, req.RequireAck, req.RequireReattest)
}

// Acknowledge records an operator acknowledgment for an incident.
func (rm *RecoveryManager) Acknowledge(incidentID, operator string) (bool, string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	req, ok := rm.requirements[incidentID]
	if !ok {
		return false, "no recovery requirement for incident"
	}

	req.AckedAt = time.Now().UTC().Format(time.RFC3339)
	req.AckedBy = operator
	rm.checkComplete(req)
	return true, "acknowledged"
}

// RecordReattestation records a successful re-attestation.
func (rm *RecoveryManager) RecordReattestation(incidentID string) (bool, string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	req, ok := rm.requirements[incidentID]
	if !ok {
		return false, "no recovery requirement for incident"
	}

	req.ReAttestedAt = time.Now().UTC().Format(time.RFC3339)
	rm.checkComplete(req)
	return true, "re-attestation recorded"
}

func (rm *RecoveryManager) checkComplete(req *RecoveryRequirement) {
	acked := !req.RequireAck || req.AckedAt != ""
	reattested := !req.RequireReattest || req.ReAttestedAt != ""
	req.RecoveryComplete = acked && reattested
	if req.RecoveryComplete {
		log.Printf("recovery: ceremony complete for incident %s", req.IncidentID)
	}
}

// IsRecoveryComplete checks if a recovery ceremony is fully satisfied.
func (rm *RecoveryManager) IsRecoveryComplete(incidentID string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	req, ok := rm.requirements[incidentID]
	if !ok {
		return true // No requirement = no ceremony needed
	}
	return req.RecoveryComplete
}

// GetRequirement returns the recovery requirement for an incident.
func (rm *RecoveryManager) GetRequirement(incidentID string) *RecoveryRequirement {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	req, ok := rm.requirements[incidentID]
	if !ok {
		return nil
	}
	// Return a copy
	copy := *req
	return &copy
}

// PendingRecoveries returns all incomplete recovery ceremonies.
func (rm *RecoveryManager) PendingRecoveries() []*RecoveryRequirement {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	var pending []*RecoveryRequirement
	for _, req := range rm.requirements {
		if !req.RecoveryComplete {
			copy := *req
			pending = append(pending, &copy)
		}
	}
	return pending
}

// =========================================================================
// Latched degraded states
// =========================================================================

// LatchedClasses are incident classes that remain in degraded state
// until explicit manual review. They cannot be auto-resolved.
var LatchedClasses = map[IncidentClass]bool{
	ClassAttestationFailure: true,
	ClassIntegrityViolation: true,
	ClassUnauthorizedAccess: true,
	ClassManifestMismatch:   true,
}

// IsLatched returns true if the incident class requires manual review
// before leaving degraded state.
func IsLatched(class IncidentClass) bool {
	return LatchedClasses[class]
}

// =========================================================================
// Severity escalation — repeated events escalate automatically
// =========================================================================

// EscalationRule defines when repeated events trigger severity escalation.
type EscalationRule struct {
	Class      IncidentClass    `yaml:"class"`
	Count      int              `yaml:"count"`       // events within window
	WindowSecs int              `yaml:"window_secs"` // time window
	EscalateTo IncidentSeverity `yaml:"escalate_to"`
}

// DefaultEscalationRules returns the built-in escalation rules.
func DefaultEscalationRules() []EscalationRule {
	return []EscalationRule{
		{Class: ClassPromptInjection, Count: 3, WindowSecs: 300, EscalateTo: SeverityCritical},
		{Class: ClassToolCallBurst, Count: 5, WindowSecs: 60, EscalateTo: SeverityHigh},
		{Class: ClassPolicyBypass, Count: 2, WindowSecs: 600, EscalateTo: SeverityCritical},
		{Class: ClassForbiddenAirlock, Count: 5, WindowSecs: 300, EscalateTo: SeverityHigh},
		{Class: ClassModelAnomaly, Count: 3, WindowSecs: 900, EscalateTo: SeverityCritical},
	}
}

// EscalationTracker watches for repeated incidents and escalates severity.
type EscalationTracker struct {
	mu    sync.Mutex
	rules []EscalationRule
	// class → list of timestamps
	history map[IncidentClass][]time.Time
}

func NewEscalationTracker(rules []EscalationRule) *EscalationTracker {
	return &EscalationTracker{
		rules:   rules,
		history: make(map[IncidentClass][]time.Time),
	}
}

// Record records a new incident and returns the escalated severity if
// escalation rules trigger, or empty string if no escalation.
func (et *EscalationTracker) Record(class IncidentClass, severity IncidentSeverity) IncidentSeverity {
	et.mu.Lock()
	defer et.mu.Unlock()

	now := time.Now()
	et.history[class] = append(et.history[class], now)

	for _, rule := range et.rules {
		if rule.Class != class {
			continue
		}
		window := now.Add(-time.Duration(rule.WindowSecs) * time.Second)
		// Count events in window
		count := 0
		var recent []time.Time
		for _, t := range et.history[class] {
			if t.After(window) {
				count++
				recent = append(recent, t)
			}
		}
		// Trim old entries
		et.history[class] = recent

		if count >= rule.Count {
			// Only escalate if the new severity is higher
			if severityRank(rule.EscalateTo) > severityRank(severity) {
				log.Printf("escalation: %s — %d events in %ds triggers escalation to %s",
					class, count, rule.WindowSecs, rule.EscalateTo)
				return rule.EscalateTo
			}
		}
	}
	return ""
}

// =========================================================================
// Forensic bundle export
// =========================================================================

// ForensicBundle is a signed export package for offline review.
type ForensicBundle struct {
	ExportedAt    string            `json:"exported_at"`
	Incidents     []Incident        `json:"incidents"`
	AuditEntries  []string          `json:"audit_entries"` // JSONL lines
	SystemState   map[string]string `json:"system_state"`
	PolicyDigest  string            `json:"policy_digest"`
	BundleHash    string            `json:"bundle_hash"`
	Signature     string            `json:"signature"`
}

// ExportForensicBundle creates a signed forensic bundle from current state.
func ExportForensicBundle(
	incidents []Incident,
	auditLog []string,
	systemState map[string]string,
	policyDigest string,
	signingKey []byte,
) *ForensicBundle {
	bundle := &ForensicBundle{
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		Incidents:    incidents,
		AuditEntries: auditLog,
		SystemState:  systemState,
		PolicyDigest: policyDigest,
	}

	// Compute hash over bundle contents (excluding hash and signature)
	hashData, _ := json.Marshal(struct {
		ExportedAt   string            `json:"exported_at"`
		Incidents    []Incident        `json:"incidents"`
		AuditEntries []string          `json:"audit_entries"`
		SystemState  map[string]string `json:"system_state"`
		PolicyDigest string            `json:"policy_digest"`
	}{
		ExportedAt:   bundle.ExportedAt,
		Incidents:    bundle.Incidents,
		AuditEntries: bundle.AuditEntries,
		SystemState:  bundle.SystemState,
		PolicyDigest: bundle.PolicyDigest,
	})
	h := sha256.Sum256(hashData)
	bundle.BundleHash = hex.EncodeToString(h[:])

	// HMAC sign the hash
	if len(signingKey) > 0 {
		mac := hmac.New(sha256.New, signingKey)
		mac.Write([]byte(bundle.BundleHash))
		bundle.Signature = hex.EncodeToString(mac.Sum(nil))
	}

	return bundle
}

// VerifyForensicBundle checks the integrity and authenticity of a forensic bundle.
func VerifyForensicBundle(bundle *ForensicBundle, signingKey []byte) (bool, string) {
	// Recompute hash
	hashData, _ := json.Marshal(struct {
		ExportedAt   string            `json:"exported_at"`
		Incidents    []Incident        `json:"incidents"`
		AuditEntries []string          `json:"audit_entries"`
		SystemState  map[string]string `json:"system_state"`
		PolicyDigest string            `json:"policy_digest"`
	}{
		ExportedAt:   bundle.ExportedAt,
		Incidents:    bundle.Incidents,
		AuditEntries: bundle.AuditEntries,
		SystemState:  bundle.SystemState,
		PolicyDigest: bundle.PolicyDigest,
	})
	h := sha256.Sum256(hashData)
	expected := hex.EncodeToString(h[:])

	if bundle.BundleHash != expected {
		return false, "bundle hash mismatch — content may have been tampered"
	}

	// Verify HMAC signature
	if len(signingKey) > 0 && bundle.Signature != "" {
		mac := hmac.New(sha256.New, signingKey)
		mac.Write([]byte(bundle.BundleHash))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(bundle.Signature), []byte(expectedSig)) {
			return false, "bundle signature mismatch"
		}
	}

	return true, "valid"
}

// =========================================================================
// HTTP handlers for recovery, escalation, and forensic export
// =========================================================================

func handleRecoveryAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
		Operator   string `json:"operator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ok, msg := recoveryMgr.Acknowledge(req.IncidentID, req.Operator)
	if !ok {
		http.Error(w, msg, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": msg})
}

func handleRecoveryReattest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ok, msg := recoveryMgr.RecordReattestation(req.IncidentID)
	if !ok {
		http.Error(w, msg, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": msg})
}

func handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pending := recoveryMgr.PendingRecoveries()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_recoveries": pending,
		"count":              len(pending),
	})
}

func handleForensicExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	incidentsMu.RLock()
	allIncidents := make([]Incident, 0, len(incidents))
	for _, inc := range incidents {
		allIncidents = append(allIncidents, inc)
	}
	incidentsMu.RUnlock()

	bundle := ExportForensicBundle(
		allIncidents,
		[]string{}, // audit log entries collected separately
		map[string]string{
			"export_time":     time.Now().UTC().Format(time.RFC3339),
			"service":         "incident-recorder",
			"total_incidents": fmt.Sprintf("%d", len(allIncidents)),
		},
		"", // policy digest retrieved separately
		[]byte(serviceToken),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=forensic-bundle.json")
	json.NewEncoder(w).Encode(bundle)
}

// Global recovery manager and escalation tracker (initialised in main or test setup)
var recoveryMgr = NewRecoveryManager()
var escalationTracker = NewEscalationTracker(DefaultEscalationRules())

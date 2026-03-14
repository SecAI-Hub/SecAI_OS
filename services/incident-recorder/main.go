package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Types
// =========================================================================

// IncidentClass categorizes the type of security event.
type IncidentClass string

const (
	ClassAttestationFailure IncidentClass = "attestation_failure"
	ClassPolicyBypass       IncidentClass = "policy_bypass_attempt"
	ClassManifestMismatch   IncidentClass = "manifest_mismatch"
	ClassForbiddenAirlock   IncidentClass = "forbidden_airlock_request"
	ClassPromptInjection    IncidentClass = "prompt_injection"
	ClassToolCallBurst      IncidentClass = "tool_call_burst"
	ClassModelAnomaly       IncidentClass = "model_behavior_anomaly"
	ClassIntegrityViolation IncidentClass = "integrity_violation"
	ClassUnauthorizedAccess IncidentClass = "unauthorized_access"
)

// IncidentSeverity is the urgency level.
type IncidentSeverity string

const (
	SeverityCritical IncidentSeverity = "critical"
	SeverityHigh     IncidentSeverity = "high"
	SeverityMedium   IncidentSeverity = "medium"
	SeverityLow      IncidentSeverity = "low"
)

// IncidentState tracks the lifecycle of an incident.
type IncidentState string

const (
	StateOpen       IncidentState = "open"
	StateContained  IncidentState = "contained"
	StateResolved   IncidentState = "resolved"
	StateAcknowledged IncidentState = "acknowledged"
)

// Incident is a single security event record.
type Incident struct {
	ID              string           `json:"id" yaml:"id"`
	CreatedAt       string           `json:"created_at" yaml:"created_at"`
	Class           IncidentClass    `json:"class" yaml:"class"`
	Severity        IncidentSeverity `json:"severity" yaml:"severity"`
	State           IncidentState    `json:"state" yaml:"state"`
	Source          string           `json:"source" yaml:"source"`
	Description     string           `json:"description" yaml:"description"`
	Evidence        map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	ContainmentActions []string      `json:"containment_actions,omitempty" yaml:"containment_actions,omitempty"`
	ResolvedAt      string           `json:"resolved_at,omitempty" yaml:"resolved_at,omitempty"`
	Hash            string           `json:"hash" yaml:"hash"`
}

// IncidentReport is the payload for creating a new incident.
type IncidentReport struct {
	Class       IncidentClass    `json:"class" yaml:"class"`
	Severity    IncidentSeverity `json:"severity" yaml:"severity"`
	Source      string           `json:"source" yaml:"source"`
	Description string           `json:"description" yaml:"description"`
	Evidence    map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// ContainmentPolicy defines automatic containment rules per incident class.
type ContainmentPolicy struct {
	Version int                             `yaml:"version"`
	Rules   map[IncidentClass]ContainmentRule `yaml:"rules"`
}

// ContainmentRule defines what actions to take for a given incident class.
type ContainmentRule struct {
	AutoContain bool     `yaml:"auto_contain"`
	Actions     []string `yaml:"actions"`
	Severity    IncidentSeverity `yaml:"default_severity"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	incidentsMu sync.RWMutex
	incidents   []Incident

	containmentPolicy   ContainmentPolicy
	containmentPolicyMu sync.RWMutex

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	serviceToken string

	incidentCount   atomic.Int64
	containedCount  atomic.Int64
	resolvedCount   atomic.Int64
	idCounter       atomic.Int64
)

const maxRequestBodySize = 64 * 1024
const maxIncidents = 1000

// =========================================================================
// Policy loading
// =========================================================================

func containmentPolicyPath() string {
	p := os.Getenv("CONTAINMENT_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/incident-containment.yaml"
	}
	return p
}

func loadContainmentPolicy() error {
	data, err := os.ReadFile(containmentPolicyPath())
	if err != nil {
		log.Printf("warning: containment policy not found (%v) — using defaults", err)
		containmentPolicyMu.Lock()
		containmentPolicy = defaultContainmentPolicy()
		containmentPolicyMu.Unlock()
		return nil
	}

	var pol ContainmentPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return fmt.Errorf("cannot parse containment policy: %w", err)
	}
	containmentPolicyMu.Lock()
	containmentPolicy = pol
	containmentPolicyMu.Unlock()
	log.Printf("containment policy loaded: %d rules", len(pol.Rules))
	return nil
}

func defaultContainmentPolicy() ContainmentPolicy {
	return ContainmentPolicy{
		Version: 1,
		Rules: map[IncidentClass]ContainmentRule{
			ClassAttestationFailure: {
				AutoContain: true,
				Actions:     []string{"freeze_agent", "disable_airlock", "force_vault_relock"},
				Severity:    SeverityCritical,
			},
			ClassPolicyBypass: {
				AutoContain: true,
				Actions:     []string{"freeze_agent", "log_alert"},
				Severity:    SeverityHigh,
			},
			ClassManifestMismatch: {
				AutoContain: true,
				Actions:     []string{"quarantine_model", "freeze_agent"},
				Severity:    SeverityHigh,
			},
			ClassForbiddenAirlock: {
				AutoContain: false,
				Actions:     []string{"log_alert"},
				Severity:    SeverityMedium,
			},
			ClassPromptInjection: {
				AutoContain: true,
				Actions:     []string{"freeze_agent", "log_alert"},
				Severity:    SeverityHigh,
			},
			ClassToolCallBurst: {
				AutoContain: true,
				Actions:     []string{"freeze_agent"},
				Severity:    SeverityMedium,
			},
			ClassModelAnomaly: {
				AutoContain: true,
				Actions:     []string{"quarantine_model", "log_alert"},
				Severity:    SeverityHigh,
			},
			ClassIntegrityViolation: {
				AutoContain: true,
				Actions:     []string{"freeze_agent", "disable_airlock", "force_vault_relock"},
				Severity:    SeverityCritical,
			},
			ClassUnauthorizedAccess: {
				AutoContain: true,
				Actions:     []string{"freeze_agent", "force_vault_relock", "log_alert"},
				Severity:    SeverityCritical,
			},
		},
	}
}

func getContainmentPolicy() ContainmentPolicy {
	containmentPolicyMu.RLock()
	defer containmentPolicyMu.RUnlock()
	return containmentPolicy
}

// =========================================================================
// Incident management
// =========================================================================

func generateIncidentID() string {
	seq := idCounter.Add(1)
	ts := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("INC-%s-%04d", ts, seq)
}

func computeIncidentHash(inc Incident) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		inc.ID, inc.CreatedAt, inc.Class, inc.Severity, inc.Source, inc.Description)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:16])
}

func createIncident(report IncidentReport) Incident {
	pol := getContainmentPolicy()
	now := time.Now().UTC().Format(time.RFC3339)

	// Look up severity and containment from policy
	severity := report.Severity
	var containmentActions []string
	state := StateOpen

	if rule, ok := pol.Rules[report.Class]; ok {
		if severity == "" {
			severity = rule.Severity
		}
		if rule.AutoContain {
			containmentActions = rule.Actions
			state = StateContained
			containedCount.Add(1)
		}
	}
	if severity == "" {
		severity = SeverityMedium
	}

	inc := Incident{
		ID:                 generateIncidentID(),
		CreatedAt:          now,
		Class:              report.Class,
		Severity:           severity,
		State:              state,
		Source:             report.Source,
		Description:        report.Description,
		Evidence:           report.Evidence,
		ContainmentActions: containmentActions,
	}
	inc.Hash = computeIncidentHash(inc)

	// Store incident
	incidentsMu.Lock()
	incidents = append(incidents, inc)
	// Trim old incidents if over limit
	if len(incidents) > maxIncidents {
		incidents = incidents[len(incidents)-maxIncidents:]
	}
	incidentsMu.Unlock()

	incidentCount.Add(1)

	// Audit log
	writeAudit(inc)

	log.Printf("incident created: id=%s class=%s severity=%s state=%s actions=%v",
		inc.ID, inc.Class, inc.Severity, inc.State, containmentActions)

	return inc
}

func getIncidents() []Incident {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()
	result := make([]Incident, len(incidents))
	copy(result, incidents)
	return result
}

func getIncidentByID(id string) (Incident, bool) {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()
	for _, inc := range incidents {
		if inc.ID == id {
			return inc, true
		}
	}
	return Incident{}, false
}

func getOpenIncidents() []Incident {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()
	var open []Incident
	for _, inc := range incidents {
		if inc.State == StateOpen || inc.State == StateContained {
			open = append(open, inc)
		}
	}
	return open
}

func resolveIncident(id string) (Incident, bool) {
	incidentsMu.Lock()
	defer incidentsMu.Unlock()
	for i := range incidents {
		if incidents[i].ID == id {
			incidents[i].State = StateResolved
			incidents[i].ResolvedAt = time.Now().UTC().Format(time.RFC3339)
			resolvedCount.Add(1)
			return incidents[i], true
		}
	}
	return Incident{}, false
}

func acknowledgeIncident(id string) (Incident, bool) {
	incidentsMu.Lock()
	defer incidentsMu.Unlock()
	for i := range incidents {
		if incidents[i].ID == id {
			incidents[i].State = StateAcknowledged
			return incidents[i], true
		}
	}
	return Incident{}, false
}

func severityRank(s IncidentSeverity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func isValidClass(c IncidentClass) bool {
	switch c {
	case ClassAttestationFailure, ClassPolicyBypass, ClassManifestMismatch,
		ClassForbiddenAirlock, ClassPromptInjection, ClassToolCallBurst,
		ClassModelAnomaly, ClassIntegrityViolation, ClassUnauthorizedAccess:
		return true
	}
	return false
}

func isValidSeverity(s IncidentSeverity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, "":
		return true
	}
	return false
}

// =========================================================================
// Audit logging
// =========================================================================

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/incident-recorder-audit.jsonl"
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

func writeAudit(inc Incident) {
	if auditFile == nil {
		return
	}
	data, err := json.Marshal(inc)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
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
// HTTP handlers
// =========================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	open := getOpenIncidents()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"open_incidents": len(open),
		"total_incidents": incidentCount.Load(),
	})
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	var report IncidentReport
	if err := json.Unmarshal(body, &report); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if report.Class == "" || report.Source == "" || report.Description == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "class, source, and description are required"})
		return
	}
	if !isValidClass(report.Class) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid incident class"})
		return
	}
	if !isValidSeverity(report.Severity) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid severity"})
		return
	}

	inc := createIncident(report)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inc)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	allInc := getIncidents()

	// Filter by query params
	classFilter := r.URL.Query().Get("class")
	stateFilter := r.URL.Query().Get("state")
	severityFilter := r.URL.Query().Get("severity")

	var filtered []Incident
	for _, inc := range allInc {
		if classFilter != "" && string(inc.Class) != classFilter {
			continue
		}
		if stateFilter != "" && string(inc.State) != stateFilter {
			continue
		}
		if severityFilter != "" && string(inc.Severity) != severityFilter {
			continue
		}
		filtered = append(filtered, inc)
	}

	// Sort by severity (highest first), then by creation time (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		ri := severityRank(filtered[i].Severity)
		rj := severityRank(filtered[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return filtered[i].CreatedAt > filtered[j].CreatedAt
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id parameter required"})
		return
	}

	inc, found := getIncidentByID(id)
	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id required"})
		return
	}

	inc, found := resolveIncident(req.ID)
	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

func handleAcknowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize))
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id required"})
		return
	}

	inc, found := acknowledgeIncident(req.ID)
	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	open := getOpenIncidents()

	// Count by class
	classCounts := make(map[string]int)
	for _, inc := range getIncidents() {
		classCounts[string(inc.Class)]++
	}

	// Count by severity among open
	severityCounts := make(map[string]int)
	for _, inc := range open {
		severityCounts[string(inc.Severity)]++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_incidents":  incidentCount.Load(),
		"open_incidents":   len(open),
		"contained_count":  containedCount.Load(),
		"resolved_count":   resolvedCount.Load(),
		"by_class":         classCounts,
		"open_by_severity": severityCounts,
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadContainmentPolicy(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadContainmentPolicy(); err != nil {
		log.Fatalf("failed to load containment policy: %v", err)
	}

	initAuditLog()
	loadServiceToken()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8515"
	}

	mux := http.NewServeMux()
	// Read-only endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/incidents", handleList)
	mux.HandleFunc("/api/v1/incidents/get", handleGet)
	mux.HandleFunc("/api/v1/stats", handleStats)
	// Mutating endpoints
	mux.HandleFunc("/api/v1/incidents/report", requireServiceToken(handleReport))
	mux.HandleFunc("/api/v1/incidents/resolve", requireServiceToken(handleResolve))
	mux.HandleFunc("/api/v1/incidents/acknowledge", requireServiceToken(handleAcknowledge))
	mux.HandleFunc("/api/v1/reload", requireServiceToken(handleReload))

	log.Printf("secure-ai-incident-recorder listening on %s", bind)
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

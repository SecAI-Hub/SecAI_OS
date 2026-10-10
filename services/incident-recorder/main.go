package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	StateOpen              IncidentState = "open"
	StateContained         IncidentState = "contained"
	StateContainmentFailed IncidentState = "containment_failed"
	StateResolved          IncidentState = "resolved"
	StateAcknowledged      IncidentState = "acknowledged"
)

// ContainmentResult records evidence for one mandatory containment action.
// Incidents are never marked contained unless every listed action succeeded.
type ContainmentResult struct {
	Action      string `json:"action" yaml:"action"`
	Success     bool   `json:"success" yaml:"success"`
	Error       string `json:"error,omitempty" yaml:"error,omitempty"`
	CompletedAt string `json:"completed_at" yaml:"completed_at"`
}

// Incident is a single security event record.
type Incident struct {
	ID                 string              `json:"id" yaml:"id"`
	CreatedAt          string              `json:"created_at" yaml:"created_at"`
	Class              IncidentClass       `json:"class" yaml:"class"`
	Severity           IncidentSeverity    `json:"severity" yaml:"severity"`
	State              IncidentState       `json:"state" yaml:"state"`
	Source             string              `json:"source" yaml:"source"`
	Description        string              `json:"description" yaml:"description"`
	Evidence           map[string]string   `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	ContainmentActions []string            `json:"containment_actions,omitempty" yaml:"containment_actions,omitempty"`
	ContainmentResults []ContainmentResult `json:"containment_results,omitempty" yaml:"containment_results,omitempty"`
	ResolvedAt         string              `json:"resolved_at,omitempty" yaml:"resolved_at,omitempty"`
	Hash               string              `json:"hash" yaml:"hash"`
}

// IncidentReport is the payload for creating a new incident.
type IncidentReport struct {
	Class       IncidentClass     `json:"class" yaml:"class"`
	Severity    IncidentSeverity  `json:"severity" yaml:"severity"`
	Source      string            `json:"source" yaml:"source"`
	Description string            `json:"description" yaml:"description"`
	Evidence    map[string]string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// ContainmentPolicy defines automatic containment rules per incident class.
type ContainmentPolicy struct {
	Version  int                               `yaml:"version"`
	Rules    map[IncidentClass]ContainmentRule `yaml:"rules"`
	Alerting AlertingConfig                    `yaml:"alerting"`
}

// ContainmentRule defines what actions to take for a given incident class.
type ContainmentRule struct {
	AutoContain bool             `yaml:"auto_contain"`
	Actions     []string         `yaml:"actions"`
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

	incidentPersistMu  sync.Mutex
	incidentMutationMu sync.Mutex
	storageDegraded    atomic.Bool

	readToken              string
	operatorToken          string
	recoveryAdminToken     string
	forensicToken          string
	canaryReporterToken    string
	gpuReporterToken       string
	integrityReporterToken string
	attestorReporterToken  string

	incidentCount  atomic.Int64
	containedCount atomic.Int64
	resolvedCount  atomic.Int64
	idCounter      atomic.Int64

	containmentExecutor = executeContainment
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
	setAlertingConfig(pol.Alerting)
	log.Printf("containment policy loaded: %d rules, %d webhooks", len(pol.Rules), len(pol.Alerting.Webhooks))
	return nil
}

func defaultContainmentPolicy() ContainmentPolicy {
	return ContainmentPolicy{
		Version:  1,
		Alerting: AlertingConfig{},
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
	return incidentHashWithKey(inc, forensicHMACKey)
}

func incidentHashWithKey(inc Incident, key []byte) string {
	inc.Hash = ""
	data, err := json.Marshal(inc)
	if err != nil || len(key) < 32 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("SecAI_OS incident record v1\x00"))
	mac.Write(data)
	return "hmac-sha256-v1:" + hex.EncodeToString(mac.Sum(nil))
}

func createIncident(report IncidentReport) (Incident, error) {
	incidentMutationMu.Lock()
	defer incidentMutationMu.Unlock()
	var durabilityErr error
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
			containmentActions = append([]string(nil), rule.Actions...)
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

	// Store pending intent before containment. At capacity, only terminal
	// history may be discarded; unresolved recovery gates remain visible.
	incidentsMu.Lock()
	if len(incidents) >= maxIncidents {
		remove := -1
		for i, old := range incidents {
			if old.State == StateResolved || old.State == StateAcknowledged {
				remove = i
				break
			}
		}
		if remove < 0 {
			incidentsMu.Unlock()
			storageDegraded.Store(true)
			// Full history must not disable emergency containment. This event
			// cannot be acknowledged durably; retain all existing recovery gates.
			if len(containmentActions) > 0 {
				results, ok := containmentExecutor(inc, endpoints, "")
				inc.ContainmentResults = results
				inc.State = StateContainmentFailed
				if ok {
					inc.State = StateContained
				}
				inc.Hash = computeIncidentHash(inc)
			}
			_ = writeAudit(inc) // Best effort only; the returned error remains authoritative.
			return inc, fmt.Errorf("incident capacity exhausted by unresolved events; emergency containment attempted")
		}
		incidents = append(incidents[:remove], incidents[remove+1:]...)
	}
	incidents = append(incidents, inc)
	incidentsMu.Unlock()

	incidentCount.Add(1)

	// Persist to disk and audit log
	durabilityErr = errors.Join(durabilityErr, persistIncidents(), writeAudit(inc))

	log.Printf("incident created: id=%s class=%s severity=%s state=%s actions=%v",
		inc.ID, inc.Class, inc.Severity, inc.State, containmentActions)

	// Execute every mandatory action before claiming containment. Critical
	// reporting may take longer while the fixed-function vault broker relocks
	// storage, but the returned state and persisted evidence are authoritative.
	if len(containmentActions) > 0 {
		results, allSucceeded := containmentExecutor(inc, endpoints, "")
		inc.ContainmentResults = results
		if allSucceeded {
			inc.State = StateContained
			containedCount.Add(1)
		} else {
			inc.State = StateContainmentFailed
		}
		inc.Hash = computeIncidentHash(inc)
		incidentsMu.Lock()
		for i := range incidents {
			if incidents[i].ID == inc.ID {
				incidents[i] = inc
				break
			}
		}
		incidentsMu.Unlock()
		durabilityErr = errors.Join(durabilityErr, persistIncidents(), writeAudit(inc))
		if allSucceeded {
			go fireWebhooks("containment", inc, containmentActions)
		} else {
			log.Printf("CONTAINMENT FAILED: incident=%s results=%v", inc.ID, results)
		}
	}
	if incidentRequiresRecovery(inc) {
		if err := recoveryMgr.RequireRecoveryForIncident(inc); err != nil {
			// Lifecycle transitions independently fail closed when a required
			// requirement is absent, so persistence failure cannot release the
			// incident's containment gate.
			log.Printf("recovery: failed to persist ceremony for incident %s: %v", inc.ID, err)
			durabilityErr = errors.Join(durabilityErr, err)
		}
	}

	if durabilityErr != nil {
		storageDegraded.Store(true)
		return inc, fmt.Errorf("incident durability unavailable: %w", durabilityErr)
	}
	return inc, nil
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
		if inc.State == StateOpen || inc.State == StateContained || inc.State == StateContainmentFailed {
			open = append(open, inc)
		}
	}
	return open
}

func transitionIncident(id string, state IncidentState) (Incident, bool) {
	incidentMutationMu.Lock()
	defer incidentMutationMu.Unlock()
	incidentsMu.Lock()
	index := -1
	var previous Incident
	for i, inc := range incidents {
		if inc.ID == id {
			if allowed, _ := recoveryMgr.CanReleaseIncident(inc); !allowed {
				incidentsMu.Unlock()
				return Incident{}, false
			}
			index, previous = i, inc
			break
		}
	}
	if index < 0 {
		incidentsMu.Unlock()
		return Incident{}, false
	}
	updated := previous
	updated.State = state
	if state == StateResolved {
		updated.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
	}
	updated.Hash = computeIncidentHash(updated)
	incidents[index] = updated
	incidentsMu.Unlock()
	if err := errors.Join(persistIncidents(), writeAudit(updated)); err != nil {
		incidentsMu.Lock()
		incidents[index] = previous
		incidentsMu.Unlock()
		// Restore disk state where possible; an audit failure still latches readiness.
		_ = persistIncidents()
		storageDegraded.Store(true)
		return Incident{}, false
	}
	if state == StateResolved {
		resolvedCount.Add(1)
	}
	return updated, true
}

func resolveIncident(id string) (Incident, bool) { return transitionIncident(id, StateResolved) }
func acknowledgeIncident(id string) (Incident, bool) {
	return transitionIncident(id, StateAcknowledged)
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
		storageDegraded.Store(true)
		log.Printf("warning: cannot create audit log dir: %v", err)
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		storageDegraded.Store(true)
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

func writeAudit(inc Incident) error {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile == nil {
		return fmt.Errorf("audit log is unavailable")
	}
	data, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := auditFile.Write(data)
	if err != nil {
		return fmt.Errorf("write incident audit: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := auditFile.Sync(); err != nil {
		return fmt.Errorf("sync incident audit: %w", err)
	}
	return nil
}

// =========================================================================
// Incident persistence (file-backed)
// =========================================================================

var incidentStorePath string

func initIncidentStore() {
	incidentStorePath = os.Getenv("INCIDENT_STORE_PATH")
	if incidentStorePath == "" {
		incidentStorePath = "/var/lib/secure-ai/data/incidents.jsonl"
	}
	dir := filepath.Dir(incidentStorePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		storageDegraded.Store(true)
		log.Printf("warning: cannot create incident store dir: %v", err)
	}
}

func loadIncidentsFromDisk() error {
	if strings.TrimSpace(incidentStorePath) == "" {
		return fmt.Errorf("incident store is not configured")
	}
	f, err := os.Open(incidentStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return fmt.Errorf("incident store is unsafe or exceeds capacity")
	}
	var loaded []Incident
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		var inc Incident
		if err := json.Unmarshal(scanner.Bytes(), &inc); err != nil {
			return fmt.Errorf("malformed incident record: %w", err)
		}
		if !validRecoveryIncidentID(inc.ID) || seen[inc.ID] || !isValidClass(inc.Class) || !isValidSeverity(inc.Severity) {
			return fmt.Errorf("invalid or duplicate incident record")
		}
		expected := computeIncidentHash(inc)
		if expected == "" || !hmac.Equal([]byte(expected), []byte(inc.Hash)) {
			return fmt.Errorf("incident authentication failed; preserve history for offline review (legacy records require explicit migration)")
		}
		seen[inc.ID] = true
		loaded = append(loaded, inc)
		if len(loaded) > maxIncidents {
			return fmt.Errorf("incident count exceeds capacity")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("incomplete incident store: %w", err)
	}
	incidentsMu.Lock()
	incidents = loaded
	incidentsMu.Unlock()
	var contained, resolved int64
	for _, inc := range loaded {
		if inc.State == StateContained {
			contained++
		}
		if inc.State == StateResolved {
			resolved++
		}
	}
	incidentCount.Store(int64(len(loaded)))
	containedCount.Store(contained)
	resolvedCount.Store(resolved)
	return nil
}

func persistIncidents() error {
	path := strings.TrimSpace(incidentStorePath)
	if path == "" {
		return fmt.Errorf("incident store is not configured")
	}
	incidentPersistMu.Lock()
	defer incidentPersistMu.Unlock()
	snapshot := getIncidents()
	dirPath := filepath.Dir(path)
	f, err := os.CreateTemp(dirPath, ".incidents-*.jsonl")
	if err != nil {
		return fmt.Errorf("create incident store: %w", err)
	}
	defer f.Close()
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0640); err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	total := 0
	for _, inc := range snapshot {
		data, err := json.Marshal(inc)
		if err != nil {
			return err
		}
		total += len(data) + 1
		if total > 16<<20 {
			return fmt.Errorf("incident store exceeds 16 MiB capacity")
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// =========================================================================
// Scoped service authentication
// =========================================================================

type reporterIdentity struct {
	Source  string
	Classes map[IncidentClass]bool
}

type reporterIdentityContextKey struct{}

func readRequiredAuthToken(pathEnv, label string) (string, error) {
	tokenPath := strings.TrimSpace(os.Getenv(pathEnv))
	if tokenPath == "" {
		return "", fmt.Errorf("%s is not configured", pathEnv)
	}
	token, _, err := readCanonicalCredentialFile(tokenPath, label)
	if err != nil {
		return "", err
	}
	return token, nil
}

func loadAuthorizationTokens() error {
	readToken, operatorToken = "", ""
	recoveryAdminToken, forensicToken = "", ""
	canaryReporterToken, gpuReporterToken = "", ""
	integrityReporterToken, attestorReporterToken = "", ""

	load := func(destination *string, pathEnv, label string) error {
		token, err := readRequiredAuthToken(pathEnv, label)
		if err != nil {
			return err
		}
		*destination = token
		return nil
	}
	for _, credential := range []struct {
		destination *string
		pathEnv     string
		label       string
	}{
		{&readToken, "INCIDENT_READ_TOKEN_PATH", "incident read"},
		{&operatorToken, "INCIDENT_OPERATOR_TOKEN_PATH", "incident operator"},
		{&recoveryAdminToken, "INCIDENT_RECOVERY_ADMIN_TOKEN_PATH", "incident recovery administrator"},
		{&forensicToken, "INCIDENT_FORENSIC_TOKEN_PATH", "incident forensic"},
		{&canaryReporterToken, "INCIDENT_REPORTER_CANARY_TOKEN_PATH", "canary reporter"},
		{&gpuReporterToken, "INCIDENT_REPORTER_GPU_INTEGRITY_TOKEN_PATH", "GPU integrity reporter"},
		{&integrityReporterToken, "INCIDENT_REPORTER_INTEGRITY_MONITOR_TOKEN_PATH", "integrity monitor reporter"},
		{&attestorReporterToken, "INCIDENT_REPORTER_RUNTIME_ATTESTOR_TOKEN_PATH", "runtime attestor reporter"},
	} {
		if err := load(credential.destination, credential.pathEnv, credential.label); err != nil {
			return err
		}
	}

	seen := make(map[string]struct{}, 8)
	for _, token := range []string{
		readToken,
		operatorToken,
		recoveryAdminToken,
		forensicToken,
		canaryReporterToken,
		gpuReporterToken,
		integrityReporterToken,
		attestorReporterToken,
	} {
		if _, duplicate := seen[token]; duplicate {
			return fmt.Errorf("incident authorization credentials must have distinct values")
		}
		seen[token] = struct{}{}
	}
	return nil
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	return token, token != ""
}

func requireBearerToken(tokenSource func() string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := tokenSource()
		if expected == "" {
			http.Error(w, `{"error":"service authentication unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		token, ok := bearerToken(r)
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

func requireReadToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return readToken }, next)
}

func requireOperatorToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return operatorToken }, next)
}

func requireRecoveryAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return recoveryAdminToken }, next)
}

func requireForensicToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerToken(func() string { return forensicToken }, next)
}

func configuredReporterIdentities() []struct {
	Token    string
	Identity reporterIdentity
} {
	return []struct {
		Token    string
		Identity reporterIdentity
	}{
		{
			Token: canaryReporterToken,
			Identity: reporterIdentity{
				Source:  "canary-tripwire",
				Classes: map[IncidentClass]bool{ClassIntegrityViolation: true},
			},
		},
		{
			Token: gpuReporterToken,
			Identity: reporterIdentity{
				Source: "gpu-integrity-watch",
				Classes: map[IncidentClass]bool{
					ClassModelAnomaly:       true,
					ClassManifestMismatch:   true,
					ClassIntegrityViolation: true,
				},
			},
		},
		{
			Token: integrityReporterToken,
			Identity: reporterIdentity{
				Source: "integrity-monitor",
				Classes: map[IncidentClass]bool{
					ClassManifestMismatch:   true,
					ClassIntegrityViolation: true,
				},
			},
		},
		{
			Token: attestorReporterToken,
			Identity: reporterIdentity{
				Source:  "runtime-attestor",
				Classes: map[IncidentClass]bool{ClassAttestationFailure: true},
			},
		},
	}
}

func requireReporterToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		configured := false
		var identity reporterIdentity
		matches := 0
		for _, reporter := range configuredReporterIdentities() {
			if reporter.Token == "" {
				continue
			}
			configured = true
			if subtle.ConstantTimeCompare([]byte(token), []byte(reporter.Token)) == 1 {
				identity = reporter.Identity
				matches++
			}
		}
		if !configured {
			http.Error(w, `{"error":"service authentication unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		if matches != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		ctx := context.WithValue(r.Context(), reporterIdentityContextKey{}, identity)
		next(w, r.WithContext(ctx))
	}
}

// =========================================================================
// Audit log tail reader (for forensic export)
// =========================================================================

// readAuditLogTail returns the last n lines from the audit JSONL file.
func readAuditLogTail(n int) ([]string, error) {
	if n < 1 || n > 1000 {
		return nil, fmt.Errorf("audit tail count must be between 1 and 1000")
	}
	f, err := os.Open(auditPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("audit log is not a regular file")
	}
	// Read only a bounded suffix, rather than allocating the entire growing log.
	const maxTailBytes = 4 << 20
	start := int64(0)
	if info.Size() > maxTailBytes {
		start = info.Size() - maxTailBytes
	}
	reader := bufio.NewReader(io.NewSectionReader(f, start, info.Size()-start))
	if start > 0 {
		if _, err := reader.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("audit tail has no complete bounded record")
		}
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	lines := make([]string, 0, n)
	next := 0
	for scanner.Scan() {
		if len(lines) < n {
			lines = append(lines, scanner.Text())
		} else {
			lines[next] = scanner.Text()
			next = (next + 1) % n
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit tail is incomplete: %w", err)
	}
	if len(lines) == n && next != 0 {
		lines = append(lines[next:], lines[:next]...)
	}
	return lines, nil
}

// =========================================================================
// HTTP handlers
// =========================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	open := getOpenIncidents()
	w.Header().Set("Content-Type", "application/json")
	if storageDegraded.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "degraded", "reason": "incident storage requires operator recovery"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"open_incidents":  len(open),
		"total_incidents": incidentCount.Load(),
	})
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var report IncidentReport
	if err := decoder.Decode(&report); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "request must contain exactly one JSON object"})
		return
	}
	report.Source = strings.TrimSpace(report.Source)
	report.Description = strings.TrimSpace(report.Description)

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
	if identity, authenticated := r.Context().Value(reporterIdentityContextKey{}).(reporterIdentity); authenticated {
		if report.Source != identity.Source || !identity.Classes[report.Class] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "reporter is not authorized for the requested source or class",
			})
			return
		}
	}

	inc, err := createIncident(report)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("incident report durability failure: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "incident storage unavailable; containment may have executed", "incident_id": inc.ID})
		return
	}
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

	if existing, found := getIncidentByID(req.ID); found {
		if allowed, reason := recoveryMgr.CanReleaseIncident(existing); !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": reason})
			return
		}
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

	if existing, found := getIncidentByID(req.ID); found {
		if allowed, reason := recoveryMgr.CanReleaseIncident(existing); !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": reason})
			return
		}
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

func newIncidentMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/incidents", requireReadToken(handleList))
	mux.HandleFunc("/api/v1/incidents/get", requireReadToken(handleGet))
	mux.HandleFunc("/api/v1/stats", requireReadToken(handleStats))
	mux.HandleFunc("/api/v1/incidents/report", requireReporterToken(handleReport))
	mux.HandleFunc("/api/v1/incidents/resolve", requireOperatorToken(handleResolve))
	mux.HandleFunc("/api/v1/incidents/acknowledge", requireOperatorToken(handleAcknowledge))
	mux.HandleFunc("/api/v1/reload", requireOperatorToken(handleReload))
	mux.HandleFunc("/api/v1/recovery/ack", requireRecoveryAdminToken(handleRecoveryAck))
	mux.HandleFunc("/api/v1/recovery/reattest", requireRecoveryAdminToken(handleRecoveryReattest))
	mux.HandleFunc("/api/v1/recovery/status", requireRecoveryAdminToken(handleRecoveryStatus))
	mux.HandleFunc("/api/v1/forensic/export", requireForensicToken(handleForensicExport))
	return mux
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate-history" {
		if err := runHistoryMigration(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := loadContainmentPolicy(); err != nil {
		log.Fatalf("failed to load containment policy: %v", err)
	}

	if err := loadForensicHMACKey(); err != nil {
		log.Fatalf("incident authentication unavailable: %v", err)
	}
	initAuditLog()
	initIncidentStore()
	if err := loadIncidentsFromDisk(); err != nil {
		log.Fatalf("incident history unavailable: %v", err)
	}
	if err := initializeRecoveryState(); err != nil {
		log.Fatalf("recovery state unavailable: %v", err)
	}
	if err := loadAuthorizationTokens(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := loadRuntimeAttestorToken(); err != nil {
		log.Fatalf("runtime-attestor authentication unavailable: %v", err)
	}
	if err := loadRuntimeAttestationHMACKey(); err != nil {
		log.Fatalf("runtime attestation verification unavailable: %v", err)
	}
	if err := loadContainmentTokens(); err != nil {
		log.Fatalf("containment authentication unavailable: %v", err)
	}
	loadServiceEndpoints()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8515"
	}

	log.Printf("secure-ai-incident-recorder listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           newIncidentMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// A critical report can synchronously wait for the fixed-function vault
		// relock broker. The action itself has a stricter 90-second deadline.
		WriteTimeout:   100 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Graceful shutdown on SIGTERM/SIGINT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down incident-recorder...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)

	// Final persistence flush
	persistIncidents()
	if auditFile != nil {
		auditFile.Sync()
		auditFile.Close()
	}
	log.Println("incident-recorder stopped")
}

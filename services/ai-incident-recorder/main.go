package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type RecorderPolicy struct {
	Version  int            `yaml:"version"`
	Recorder RecorderConfig `yaml:"recorder"`
}

type RecorderConfig struct {
	DataDir         string                           `yaml:"data_dir"`
	Retention       RetentionConfig                  `yaml:"retention"`
	Redaction       RedactionConfig                  `yaml:"redaction"`
	PrivacyProfiles map[string]PrivacyProfileConfig  `yaml:"privacy_profiles"`
	SigningKey       string                           `yaml:"signing_key"`
	Daemon          DaemonConfig                     `yaml:"daemon"`
	RateLimit       RateLimitConfig                  `yaml:"rate_limit"`
}

type RetentionConfig struct {
	MaxEventsPerSession int `yaml:"max_events_per_session"`
	MaxSessions         int `yaml:"max_sessions"`
	ExpireAfterDays     int `yaml:"expire_after_days"`
}

type RedactionConfig struct {
	OnPackage bool     `yaml:"on_package"`
	OnRecord  bool     `yaml:"on_record"`
	Patterns  []string `yaml:"patterns"`
}

type DaemonConfig struct {
	BindAddr        string `yaml:"bind_addr"`
	ReadTimeoutSec  int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int    `yaml:"write_timeout_seconds"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   RecorderPolicy

	eventStore    *EventStore
	incidentStore *IncidentStore

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests  atomic.Int64
	eventRequests  atomic.Int64

	serviceToken string
)

const (
	defaultPolicyPath = "/etc/secure-ai/policy/recorder.yaml"
	defaultTokenPath  = "/run/secure-ai/service-token"
	defaultAuditPath  = "/var/lib/secure-ai/logs/recorder-audit.jsonl"
	defaultDataDir    = "/var/lib/secure-ai/incidents"
	defaultBindAddr   = "127.0.0.1:8495"
	defaultRPM        = 120
	maxRequestBodySize = 1 << 20 // 1 MiB
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func loadPolicy() error {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p RecorderPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded from %s (version=%d)", policyFilePath(), p.Version)
	return nil
}

func getPolicy() RecorderPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

func getDataDir() string {
	p := getPolicy()
	if p.Recorder.DataDir != "" {
		return p.Recorder.DataDir
	}
	return defaultDataDir
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	idx := strings.LastIndex(auditPath, "/")
	if idx > 0 {
		if err := os.MkdirAll(auditPath[:idx], 0750); err != nil {
			log.Printf("warning: cannot create audit dir: %v", err)
			return
		}
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

func writeAudit(entry AuditEntry) {
	if auditFile == nil {
		return
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(entry)
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("service token not loaded (dev mode): %v", err)
		return
	}
	serviceToken = strings.TrimSpace(string(data))
	log.Printf("service token loaded")
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
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.Recorder.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"service":     "ai-incident-recorder",
		"event_count": eventStore.EventCount(),
	})
}

func handleRecordEvent(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	eventRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateEvent(event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if event.SessionID == "" {
		event.SessionID = "default"
	}

	// Apply on-record redaction if configured.
	pol := getPolicy()
	if pol.Recorder.Redaction.OnRecord {
		stats := &RedactionStats{Counts: make(map[string]int)}
		event = RedactEvent(event, defaultRedactionRules, stats)
	}

	recorded, err := eventStore.Record(event)
	if err != nil {
		log.Printf("error recording event: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeAudit(AuditEntry{Action: "event.recorded", Detail: recorded.ID})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(recorded)
}

func handleRecordBatch(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	eventRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkRateLimit() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize*10) // larger for batch

	var events []Event
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	pol := getPolicy()

	var recorded []Event
	for _, event := range events {
		if err := validateEvent(event); err != nil {
			continue
		}
		if event.SessionID == "" {
			event.SessionID = "default"
		}

		// Apply on-record redaction (consistent with single event handler).
		if pol.Recorder.Redaction.OnRecord {
			stats := &RedactionStats{Counts: make(map[string]int)}
			event = RedactEvent(event, defaultRedactionRules, stats)
		}

		e, err := eventStore.Record(event)
		if err != nil {
			log.Printf("error recording batch event: %v", err)
			continue
		}
		recorded = append(recorded, e)
	}

	writeAudit(AuditEntry{Action: "events.batch", Detail: fmt.Sprintf("recorded %d/%d", len(recorded), len(events))})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"recorded": len(recorded),
		"total":    len(events),
	})
}

func handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filter := EventFilter{
		SessionID: q.Get("session_id"),
		Source:    q.Get("source"),
		Type:      q.Get("type"),
		Severity:  q.Get("severity"),
		After:     q.Get("after"),
		Before:    q.Get("before"),
	}

	events := eventStore.Query(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(events),
		"events": events,
	})
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": eventStore.Sessions(),
	})
}

func handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var inc Incident
	if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateIncident(inc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := incidentStore.Create(inc)
	if err != nil {
		log.Printf("error creating incident: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeAudit(AuditEntry{Action: "incident.created", Detail: created.ID})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func handleListIncidents(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incidents": incidentStore.List(),
	})
}

func handleGetIncident(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	inc, ok := incidentStore.Get(id)
	if !ok {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	// Fetch associated events.
	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	timeline := BuildTimeline(events)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incident": inc,
		"timeline": timeline,
		"events":   len(events),
	})
}

func handlePackageBundle(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	inc, ok := incidentStore.Get(id)
	if !ok {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})

	pol := getPolicy()
	profileName := r.URL.Query().Get("profile")
	profile := resolvePrivacyProfile(pol, profileName)

	bundle, err := PackageBundle(inc, events, profile, pol.Recorder.SigningKey)
	if err != nil {
		log.Printf("error packaging bundle: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeAudit(AuditEntry{Action: "bundle.packaged", Detail: inc.ID})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := loadPolicy(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests": totalRequests.Load(),
		"event_requests": eventRequests.Load(),
		"stored_events":  int64(eventStore.EventCount()),
	})
}

// ---------------------------------------------------------------------------
// Privacy profile resolution
// ---------------------------------------------------------------------------

// resolvePrivacyProfile returns a profile config by name, or falls back to
// the legacy redaction config.
func resolvePrivacyProfile(pol RecorderPolicy, name string) PrivacyProfileConfig {
	if name != "" && pol.Recorder.PrivacyProfiles != nil {
		if p, ok := pol.Recorder.PrivacyProfiles[name]; ok {
			return p
		}
	}
	return PrivacyProfileConfig{
		Redact:   pol.Recorder.Redaction.OnPackage,
		Patterns: pol.Recorder.Redaction.Patterns,
	}
}

// ---------------------------------------------------------------------------
// Route multiplexer (exported for testing)
// ---------------------------------------------------------------------------

// buildMux constructs the HTTP mux with auth on all non-health endpoints.
func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/event", requireServiceToken(handleRecordEvent))
	mux.HandleFunc("/v1/events", requireServiceToken(handleQueryEvents))
	mux.HandleFunc("/v1/events/batch", requireServiceToken(handleRecordBatch))
	mux.HandleFunc("/v1/sessions", requireServiceToken(handleListSessions))
	mux.HandleFunc("/v1/incident", requireServiceToken(handleGetIncident))
	mux.HandleFunc("/v1/incidents", requireServiceToken(handleListIncidents))
	mux.HandleFunc("/v1/incident/create", requireServiceToken(handleCreateIncident))
	mux.HandleFunc("/v1/incident/package", requireServiceToken(handlePackageBundle))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// Daemon mode
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string) {
	loadServiceToken()
	initAuditLog()

	pol := getPolicy()

	readTimeout := time.Duration(pol.Recorder.Daemon.ReadTimeoutSec) * time.Second
	if readTimeout <= 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := time.Duration(pol.Recorder.Daemon.WriteTimeoutSec) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 60 * time.Second
	}

	mux := buildMux()

	srv := &http.Server{
		Addr:         bindAddr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	log.Printf("ai-incident-recorder daemon listening on %s (events: %d)", bindAddr, eventStore.EventCount())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdRecord(policyPath, bindAddr string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error
	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening event store: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening incident store: %v\n", err)
		return 1
	}

	if bindAddr == "" {
		bindAddr = pol.Recorder.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}

	runDaemon(bindAddr)
	return 0
}

func cmdIngest(policyPath, filePath, source, sessionID string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error
	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening event store: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		return 1
	}

	if sessionID == "" {
		sessionID = generateID()
	}

	var count int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			log.Printf("skipping invalid line: %v", err)
			continue
		}

		event := Event{
			SessionID: sessionID,
			Source:    source,
			Type:      inferEventType(raw, source),
			Data:      raw,
		}

		// Preserve original timestamp if present.
		if ts, ok := raw["timestamp"].(string); ok {
			event.Timestamp = ts
		}

		// Infer severity from the data.
		event.Severity = inferSeverity(raw)

		if _, err := eventStore.Record(event); err != nil {
			log.Printf("error recording event: %v", err)
			continue
		}
		count++
	}

	fmt.Printf("ingested %d events from %s (session: %s)\n", count, filePath, sessionID)
	return 0
}

func cmdList(policyPath, what string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	switch what {
	case "sessions":
		eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		defer eventStore.Close()

		sessions := eventStore.Sessions()
		if len(sessions) == 0 {
			fmt.Println("no sessions recorded")
			return 0
		}
		for _, s := range sessions {
			fmt.Printf("  %-30s  events=%-5d  sources=%s  range=%s..%s\n",
				s.SessionID, s.EventCount, strings.Join(s.Sources, ","),
				s.FirstEvent, s.LastEvent)
		}

	case "incidents":
		incidentStore, err = NewIncidentStore(dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		incidents := incidentStore.List()
		if len(incidents) == 0 {
			fmt.Println("no incidents recorded")
			return 0
		}
		for _, inc := range incidents {
			fmt.Printf("  %-30s  [%s] %s  (%s)\n",
				inc.ID, inc.Severity, inc.Title, inc.Status)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown list type: %s (use 'sessions' or 'incidents')\n", what)
		return 1
	}
	return 0
}

func cmdShow(policyPath, incidentID string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	inc, ok := incidentStore.Get(incidentID)
	if !ok {
		fmt.Fprintf(os.Stderr, "incident not found: %s\n", incidentID)
		return 1
	}

	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})
	timeline := BuildTimeline(events)

	fmt.Printf("Incident: %s\n", inc.Title)
	fmt.Printf("ID:       %s\n", inc.ID)
	fmt.Printf("Severity: %s\n", inc.Severity)
	fmt.Printf("Status:   %s\n", inc.Status)
	fmt.Printf("Created:  %s\n", inc.CreatedAt)
	fmt.Printf("Events:   %d\n\n", len(events))
	fmt.Println("Timeline:")
	fmt.Println(strings.Repeat("-", 80))

	for _, entry := range timeline {
		sev := entry.Severity
		switch sev {
		case "critical":
			sev = "CRIT"
		case "alert":
			sev = "ALRT"
		case "warning":
			sev = "WARN"
		case "info":
			sev = "INFO"
		}
		fmt.Printf("  T+%6dms  [%-4s] %-20s  %s\n",
			entry.RelativeMs, sev, entry.Source, entry.Summary)
	}
	return 0
}

func cmdPackage(policyPath, incidentID, outputPath, keyPath, profileName string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	dataDir := getDataDir()
	var err error

	incidentStore, err = NewIncidentStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	inc, ok := incidentStore.Get(incidentID)
	if !ok {
		fmt.Fprintf(os.Stderr, "incident not found: %s\n", incidentID)
		return 1
	}

	eventStore, err = NewEventStore(dataDir, pol.Recorder.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer eventStore.Close()

	events := eventStore.Query(EventFilter{SessionID: inc.SessionID})

	if keyPath != "" {
		pol.Recorder.SigningKey = keyPath
	}

	profile := resolvePrivacyProfile(pol, profileName)

	bundle, err := PackageBundle(inc, events, profile, pol.Recorder.SigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error packaging: %v\n", err)
		return 1
	}

	data, _ := json.MarshalIndent(bundle, "", "  ")

	if outputPath != "" && outputPath != "-" {
		if err := os.WriteFile(outputPath, append(data, '\n'), 0640); err != nil {
			fmt.Fprintf(os.Stderr, "error writing: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "case bundle written to %s (%d events, %d redactions)\n",
			outputPath, len(bundle.Events), totalRedactions(bundle.Redaction))
	} else {
		fmt.Println(string(data))
	}
	return 0
}

func cmdVerify(bundlePath, pubKeyPath string) int {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading bundle: %v\n", err)
		return 1
	}

	var bundle CaseBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing bundle: %v\n", err)
		return 1
	}

	if err := VerifyBundle(&bundle, pubKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
		return 1
	}

	fmt.Printf("bundle verified\n")
	fmt.Printf("  incident:  %s\n", bundle.Title)
	fmt.Printf("  events:    %d\n", len(bundle.Events))
	fmt.Printf("  integrity: %s\n", bundle.Integrity)
	if bundle.Signature != "" {
		fmt.Printf("  signed:    %s\n", bundle.SignedAt)
		fmt.Printf("  signature: valid\n")
	}
	return 0
}

func cmdKeygen(privPath, pubPath string) int {
	if err := generateKeypair(privPath, pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("keypair generated:\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// inferEventType guesses the event type from audit log data and source.
func inferEventType(data map[string]interface{}, source string) string {
	switch source {
	case "tool-firewall":
		return "tool.decision"
	case "airlock":
		return "airlock.request"
	case "registry":
		if _, ok := data["promoted_at"]; ok {
			return "registry.promote"
		}
		return "registry.event"
	case "quarantine":
		return "quarantine.scan"
	case "attestor", "runtime-attestor":
		return "attestor.report"
	default:
		if t, ok := data["type"].(string); ok {
			return t
		}
		return "unknown"
	}
}

// inferSeverity guesses severity from event data.
func inferSeverity(data map[string]interface{}) string {
	if allowed, ok := data["allowed"].(bool); ok && !allowed {
		return "alert"
	}
	if sev, ok := data["severity"].(string); ok {
		return sev
	}
	return "info"
}

func totalRedactions(stats RedactionStats) int {
	total := 0
	for _, c := range stats.Counts {
		total += c
	}
	return total
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "record":
		fs := flag.NewFlagSet("record", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdRecord(*policyPath, *bind))

	case "ingest":
		fs := flag.NewFlagSet("ingest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		filePath := fs.String("file", "", "JSONL file to ingest")
		source := fs.String("source", "", "source service name")
		sessionID := fs.String("session", "", "session ID (auto-generated if empty)")
		fs.Parse(os.Args[2:])
		if *filePath == "" || *source == "" {
			fmt.Fprintf(os.Stderr, "error: -file and -source are required\n")
			os.Exit(1)
		}
		os.Exit(cmdIngest(*policyPath, *filePath, *source, *sessionID))

	case "list":
		fs := flag.NewFlagSet("list", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		fs.Parse(os.Args[2:])
		what := "sessions"
		if fs.NArg() > 0 {
			what = fs.Arg(0)
		}
		os.Exit(cmdList(*policyPath, what))

	case "show":
		fs := flag.NewFlagSet("show", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		id := fs.String("id", "", "incident ID")
		fs.Parse(os.Args[2:])
		if *id == "" {
			fmt.Fprintf(os.Stderr, "error: -id is required\n")
			os.Exit(1)
		}
		os.Exit(cmdShow(*policyPath, *id))

	case "package":
		fs := flag.NewFlagSet("package", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		id := fs.String("id", "", "incident ID")
		output := fs.String("output", "-", "output file (- for stdout)")
		key := fs.String("key", "", "signing key path (overrides policy)")
		profileName := fs.String("profile", "", "privacy profile name (internal, external-share, legal-review)")
		fs.Parse(os.Args[2:])
		if *id == "" {
			fmt.Fprintf(os.Stderr, "error: -id is required\n")
			os.Exit(1)
		}
		os.Exit(cmdPackage(*policyPath, *id, *output, *key, *profileName))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		bundlePath := fs.String("bundle", "", "path to case bundle file")
		pubKey := fs.String("pubkey", "", "path to public key file")
		fs.Parse(os.Args[2:])
		if *bundlePath == "" {
			fmt.Fprintf(os.Stderr, "error: -bundle is required\n")
			os.Exit(1)
		}
		os.Exit(cmdVerify(*bundlePath, *pubKey))

	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		privPath := fs.String("priv", "recorder.key", "private key output path")
		pubPath := fs.String("pub", "recorder.pub", "public key output path")
		fs.Parse(os.Args[2:])
		os.Exit(cmdKeygen(*privPath, *pubPath))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ai-incident-recorder — black box flight recorder for AI agents

Usage:
  ai-incident-recorder <command> [options]

Commands:
  record    Start recording daemon (HTTP API on :8495)
  ingest    Import events from JSONL audit logs
  list      List sessions or incidents
  show      Show incident timeline
  package   Create a signed, redacted case bundle
  verify    Verify case bundle integrity and signature
  keygen    Generate ed25519 signing keypair

Use "ai-incident-recorder <command> -h" for command-specific options.
`)
}

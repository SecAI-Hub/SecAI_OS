package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestStores(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	var err error
	eventStore, err = NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}

	incidentStore, err = NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	policyMu.Lock()
	policy = RecorderPolicy{
		Version: 1,
		Recorder: RecorderConfig{
			DataDir: dir,
			Redaction: RedactionConfig{
				OnPackage: true,
				OnRecord:  false,
			},
			RateLimit: RateLimitConfig{RequestsPerMinute: 1000},
		},
	}
	policyMu.Unlock()

	serviceToken = ""
	return dir
}

func setupTestStoresWithRetention(t *testing.T, ret RetentionConfig) string {
	t.Helper()
	dir := t.TempDir()

	var err error
	eventStore, err = NewEventStore(dir, ret)
	if err != nil {
		t.Fatal(err)
	}

	incidentStore, err = NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	policyMu.Lock()
	policy = RecorderPolicy{
		Version: 1,
		Recorder: RecorderConfig{
			DataDir:   dir,
			Retention: ret,
			Redaction: RedactionConfig{OnPackage: true, OnRecord: false},
			RateLimit: RateLimitConfig{RequestsPerMinute: 1000},
		},
	}
	policyMu.Unlock()

	serviceToken = ""
	return dir
}

// ---------------------------------------------------------------------------
// Event store tests
// ---------------------------------------------------------------------------

func TestEventStore_RecordAndQuery(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Record events.
	e1, err := store.Record(Event{
		SessionID: "sess-1",
		Source:    "tool-firewall",
		Type:      "tool.decision",
		Severity:  "info",
		Data:      map[string]interface{}{"tool": "filesystem.read", "allowed": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e1.ID == "" {
		t.Fatal("expected event ID")
	}
	if e1.Hash == "" {
		t.Fatal("expected event hash")
	}

	e2, err := store.Record(Event{
		SessionID: "sess-1",
		Source:    "model",
		Type:      "model.invoke",
		Data:      map[string]interface{}{"model": "mistral-7b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Chain linkage.
	if e2.PrevHash != e1.Hash {
		t.Fatalf("expected chain: e2.PrevHash=%s, e1.Hash=%s", e2.PrevHash, e1.Hash)
	}

	// Query by session.
	results := store.Query(EventFilter{SessionID: "sess-1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events, got %d", len(results))
	}

	// Query by source.
	results = store.Query(EventFilter{Source: "model"})
	if len(results) != 1 {
		t.Fatalf("expected 1 model event, got %d", len(results))
	}

	// Count.
	if store.EventCount() != 2 {
		t.Fatalf("expected 2 total events, got %d", store.EventCount())
	}
}

func TestEventStore_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Write events.
	store1, _ := NewEventStore(dir, RetentionConfig{})
	store1.Record(Event{SessionID: "s1", Source: "a", Type: "t1"})
	store1.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})
	store1.Close()

	// Reopen and verify.
	store2, _ := NewEventStore(dir, RetentionConfig{})
	defer store2.Close()

	if store2.EventCount() != 2 {
		t.Fatalf("expected 2 persisted events, got %d", store2.EventCount())
	}
}

func TestEventStore_Sessions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "alpha", Source: "a", Type: "t"})
	store.Record(Event{SessionID: "alpha", Source: "b", Type: "t"})
	store.Record(Event{SessionID: "beta", Source: "c", Type: "t"})

	sessions := store.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// Hash chain tests
// ---------------------------------------------------------------------------

func TestEventChain_Integrity(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t1"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t2"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t3"})

	events := store.Query(EventFilter{SessionID: "s"})
	if err := verifyEventChain(events); err != nil {
		t.Fatalf("chain should be valid: %v", err)
	}
}

func TestEventChain_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t1"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t2"})

	events := store.Query(EventFilter{SessionID: "s"})

	// Tamper with the first event.
	events[0].Source = "TAMPERED"

	if err := verifyEventChain(events); err == nil {
		t.Fatal("expected chain verification to fail on tampered event")
	}
}

// ---------------------------------------------------------------------------
// Retention enforcement tests
// ---------------------------------------------------------------------------

func TestRetention_MaxEventsPerSession(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{MaxEventsPerSession: 3})
	defer store.Close()

	for i := 0; i < 3; i++ {
		_, err := store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
		if err != nil {
			t.Fatalf("event %d should succeed: %v", i, err)
		}
	}

	// 4th event should fail.
	_, err := store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	if err == nil {
		t.Fatal("expected error for exceeding max_events_per_session")
	}
	if !strings.Contains(err.Error(), "max events") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Different session should still work.
	_, err = store.Record(Event{SessionID: "s2", Source: "a", Type: "t"})
	if err != nil {
		t.Fatalf("different session should succeed: %v", err)
	}
}

func TestRetention_MaxSessions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{MaxSessions: 2})
	defer store.Close()

	store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	store.Record(Event{SessionID: "s2", Source: "a", Type: "t"})

	// 3rd session should fail.
	_, err := store.Record(Event{SessionID: "s3", Source: "a", Type: "t"})
	if err == nil {
		t.Fatal("expected error for exceeding max_sessions")
	}
	if !strings.Contains(err.Error(), "max sessions") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Existing session should still accept events.
	_, err = store.Record(Event{SessionID: "s1", Source: "a", Type: "t"})
	if err != nil {
		t.Fatalf("existing session should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Parsed timestamp query tests
// ---------------------------------------------------------------------------

func TestQuery_ParsedTimestamps(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T10:00:00Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T12:00:00Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T14:00:00Z"})

	// Query with after filter.
	results := store.Query(EventFilter{After: "2026-03-09T11:00:00Z"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events after 11:00, got %d", len(results))
	}

	// Query with before filter.
	results = store.Query(EventFilter{Before: "2026-03-09T13:00:00Z"})
	if len(results) != 2 {
		t.Fatalf("expected 2 events before 13:00, got %d", len(results))
	}

	// Query with both.
	results = store.Query(EventFilter{After: "2026-03-09T11:00:00Z", Before: "2026-03-09T13:00:00Z"})
	if len(results) != 1 {
		t.Fatalf("expected 1 event between 11:00 and 13:00, got %d", len(results))
	}
}

func TestQuery_ParsedTimestamps_DifferentFormats(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewEventStore(dir, RetentionConfig{})
	defer store.Close()

	// Events with nanosecond timestamps.
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T10:00:00.000000000Z"})
	store.Record(Event{SessionID: "s", Source: "a", Type: "t", Timestamp: "2026-03-09T12:00:00.500000000Z"})

	// Query with plain RFC3339 filter.
	results := store.Query(EventFilter{After: "2026-03-09T11:00:00Z"})
	if len(results) != 1 {
		t.Fatalf("expected 1 event with cross-format filter, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Redaction tests
// ---------------------------------------------------------------------------

func TestRedactString_Email(t *testing.T) {
	input := "Contact user@example.com for help"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "user@example.com") {
		t.Fatal("email should be redacted")
	}
	if !strings.Contains(result, "[REDACTED:email]") {
		t.Fatal("expected [REDACTED:email] tag")
	}
	if stats.Counts["email"] != 1 {
		t.Fatalf("expected 1 email redaction, got %d", stats.Counts["email"])
	}
}

func TestRedactString_SSN(t *testing.T) {
	input := "SSN: 123-45-6789"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "123-45-6789") {
		t.Fatal("SSN should be redacted")
	}
	if !strings.Contains(result, "[REDACTED:ssn]") {
		t.Fatal("expected [REDACTED:ssn] tag")
	}
}

func TestRedactString_Credential(t *testing.T) {
	input := "password=s3cret123!"
	stats := &RedactionStats{Counts: make(map[string]int)}
	result := RedactString(input, defaultRedactionRules, stats)

	if strings.Contains(result, "s3cret123") {
		t.Fatal("credential should be redacted")
	}
}

func TestRedactMap_Nested(t *testing.T) {
	data := map[string]interface{}{
		"prompt": "Send email to admin@corp.com",
		"nested": map[string]interface{}{
			"token": "bearer abc123def456",
		},
	}

	stats := &RedactionStats{Counts: make(map[string]int)}
	redacted := RedactMap(data, defaultRedactionRules, stats)

	prompt := redacted["prompt"].(string)
	if strings.Contains(prompt, "admin@corp.com") {
		t.Fatal("nested email should be redacted")
	}

	nested := redacted["nested"].(map[string]interface{})
	token := nested["token"].(string)
	if strings.Contains(token, "abc123def456") {
		t.Fatal("bearer token should be redacted")
	}
}

func TestRedactEvent_PreservesOriginal(t *testing.T) {
	original := Event{
		Source: "test",
		Actor:  "user@example.com",
		Data: map[string]interface{}{
			"content": "SSN is 123-45-6789",
		},
	}

	stats := &RedactionStats{Counts: make(map[string]int)}
	redacted := RedactEvent(original, defaultRedactionRules, stats)

	// Original should be unchanged.
	if original.Actor != "user@example.com" {
		t.Fatal("original event should not be modified")
	}

	// Redacted should have tags.
	if !strings.Contains(redacted.Actor, "[REDACTED:email]") {
		t.Fatal("actor should be redacted in copy")
	}
}

// ---------------------------------------------------------------------------
// Batch redaction consistency test
// ---------------------------------------------------------------------------

func TestBatchRedaction_ConsistentWithSingle(t *testing.T) {
	setupTestStores(t)

	// Enable on-record redaction.
	policyMu.Lock()
	policy.Recorder.Redaction.OnRecord = true
	policyMu.Unlock()

	mux := buildMux()

	// Record via single endpoint.
	body := `{"session_id":"s1","source":"model","type":"model.invoke","data":{"prompt":"Contact admin@corp.com"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("single event: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var singleEvent Event
	json.Unmarshal(w.Body.Bytes(), &singleEvent)

	// Record via batch endpoint.
	batchBody := `[{"session_id":"s2","source":"model","type":"model.invoke","data":{"prompt":"Contact admin@corp.com"}}]`
	req = httptest.NewRequest(http.MethodPost, "/v1/events/batch", strings.NewReader(batchBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("batch: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Query the batch event.
	batchEvents := eventStore.Query(EventFilter{SessionID: "s2"})
	if len(batchEvents) != 1 {
		t.Fatalf("expected 1 batch event, got %d", len(batchEvents))
	}

	// Both should have redacted the email.
	singlePrompt := singleEvent.Data["prompt"].(string)
	batchPrompt := batchEvents[0].Data["prompt"].(string)

	if strings.Contains(singlePrompt, "admin@corp.com") {
		t.Fatal("single event should have redacted email")
	}
	if strings.Contains(batchPrompt, "admin@corp.com") {
		t.Fatal("batch event should have redacted email (consistency fix)")
	}
}

// ---------------------------------------------------------------------------
// Incident and timeline tests
// ---------------------------------------------------------------------------

func TestIncidentStore_CreateAndGet(t *testing.T) {
	dir := t.TempDir()
	store, err := NewIncidentStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	inc, err := store.Create(Incident{
		SessionID: "sess-1",
		Title:     "Suspicious tool call denied",
		Severity:  "alert",
	})
	if err != nil {
		t.Fatal(err)
	}

	if inc.ID == "" {
		t.Fatal("expected incident ID")
	}
	if inc.Status != "open" {
		t.Fatalf("expected status open, got %s", inc.Status)
	}

	// Get.
	retrieved, ok := store.Get(inc.ID)
	if !ok {
		t.Fatal("incident not found")
	}
	if retrieved.Title != "Suspicious tool call denied" {
		t.Fatalf("wrong title: %s", retrieved.Title)
	}
}

func TestIncidentStore_Persistence(t *testing.T) {
	dir := t.TempDir()

	store1, _ := NewIncidentStore(dir)
	store1.Create(Incident{Title: "Test", SessionID: "s1"})

	// Reopen.
	store2, _ := NewIncidentStore(dir)
	incidents := store2.List()
	if len(incidents) != 1 {
		t.Fatalf("expected 1 persisted incident, got %d", len(incidents))
	}
}

func TestBuildTimeline(t *testing.T) {
	events := []Event{
		{ID: "3", Timestamp: "2026-03-09T10:00:02.000Z", Source: "airlock", Type: "airlock.request", Severity: "warning",
			Data: map[string]interface{}{"destination": "https://unknown.com", "allowed": false}},
		{ID: "1", Timestamp: "2026-03-09T10:00:00.000Z", Source: "model", Type: "model.invoke", Severity: "info",
			Data: map[string]interface{}{"model": "mistral-7b"}},
		{ID: "2", Timestamp: "2026-03-09T10:00:01.000Z", Source: "tool-firewall", Type: "tool.decision", Severity: "alert",
			Data: map[string]interface{}{"tool": "shell.exec", "allowed": false, "reason": "denied"}},
	}

	timeline := BuildTimeline(events)
	if len(timeline) != 3 {
		t.Fatalf("expected 3 timeline entries, got %d", len(timeline))
	}

	// Should be sorted by timestamp.
	if timeline[0].EventID != "1" {
		t.Fatalf("first entry should be event 1, got %s", timeline[0].EventID)
	}
	if timeline[0].RelativeMs != 0 {
		t.Fatalf("first entry relative_ms should be 0, got %d", timeline[0].RelativeMs)
	}
	if timeline[1].RelativeMs != 1000 {
		t.Fatalf("second entry relative_ms should be 1000, got %d", timeline[1].RelativeMs)
	}
}

// ---------------------------------------------------------------------------
// Case bundle tests
// ---------------------------------------------------------------------------

func TestPackageBundle_Unsigned(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t1", Data: map[string]interface{}{"info": "test"}})
	es.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test Incident"}

	profile := PrivacyProfileConfig{Redact: true}
	bundle, err := PackageBundle(inc, events, profile, "")
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Integrity == "" {
		t.Fatal("expected integrity hash")
	}
	if len(bundle.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(bundle.Events))
	}
	if len(bundle.Timeline) != 2 {
		t.Fatalf("expected 2 timeline entries, got %d", len(bundle.Timeline))
	}
}

func TestPackageBundle_SignedAndVerified(t *testing.T) {
	dir := t.TempDir()

	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "x", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Signed Test"}

	profile := PrivacyProfileConfig{Redact: false}
	bundle, err := PackageBundle(inc, events, profile, privPath)
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Signature == "" {
		t.Fatal("expected signature")
	}

	// Verify.
	if err := VerifyBundle(bundle, pubPath); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPackageBundle_TamperDetection(t *testing.T) {
	dir := t.TempDir()

	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "x", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false}
	bundle, _ := PackageBundle(inc, events, profile, privPath)

	// Tamper.
	bundle.Title = "TAMPERED"

	if err := VerifyBundle(bundle, pubPath); err == nil {
		t.Fatal("expected verification to fail on tampered bundle")
	}
}

func TestPackageBundle_Redaction(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{
		SessionID: "s1",
		Source:    "model",
		Type:      "model.invoke",
		Data: map[string]interface{}{
			"prompt": "Contact admin@corp.com about SSN 123-45-6789",
		},
	})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "PII Test"}

	profile := PrivacyProfileConfig{Redact: true}
	bundle, _ := PackageBundle(inc, events, profile, "")

	prompt := bundle.Events[0].Data["prompt"].(string)
	if strings.Contains(prompt, "admin@corp.com") {
		t.Fatal("email should be redacted in bundle")
	}
	if strings.Contains(prompt, "123-45-6789") {
		t.Fatal("SSN should be redacted in bundle")
	}

	// Verify redaction stats.
	if bundle.Redaction.Counts["email"] < 1 {
		t.Fatal("expected email redaction count")
	}
	if bundle.Redaction.Counts["ssn"] < 1 {
		t.Fatal("expected ssn redaction count")
	}
}

// ---------------------------------------------------------------------------
// Privacy profile tests
// ---------------------------------------------------------------------------

func TestPrivacyProfile_StripHostname(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false, StripHostname: true}
	bundle, _ := PackageBundle(inc, events, profile, "")

	if bundle.Hostname != "[REDACTED]" {
		t.Fatalf("expected hostname to be [REDACTED], got %s", bundle.Hostname)
	}
}

func TestPrivacyProfile_NoStripHostname(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	es.Record(Event{SessionID: "s1", Source: "a", Type: "t"})

	events := es.Query(EventFilter{SessionID: "s1"})
	inc := &Incident{ID: "inc-1", SessionID: "s1", Title: "Test"}

	profile := PrivacyProfileConfig{Redact: false, StripHostname: false}
	bundle, _ := PackageBundle(inc, events, profile, "")

	if bundle.Hostname == "[REDACTED]" {
		t.Fatal("hostname should not be redacted when StripHostname is false")
	}
}

func TestResolvePrivacyProfile_Named(t *testing.T) {
	pol := RecorderPolicy{
		Recorder: RecorderConfig{
			PrivacyProfiles: map[string]PrivacyProfileConfig{
				"external-share": {
					Redact:        true,
					StripHostname: true,
					Patterns:      []string{"ssn", "email"},
				},
			},
		},
	}

	profile := resolvePrivacyProfile(pol, "external-share")
	if !profile.Redact {
		t.Fatal("expected Redact=true")
	}
	if !profile.StripHostname {
		t.Fatal("expected StripHostname=true")
	}
	if len(profile.Patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(profile.Patterns))
	}
}

func TestResolvePrivacyProfile_FallbackToDefault(t *testing.T) {
	pol := RecorderPolicy{
		Recorder: RecorderConfig{
			Redaction: RedactionConfig{
				OnPackage: true,
				Patterns:  []string{"ssn", "email", "credential"},
			},
		},
	}

	profile := resolvePrivacyProfile(pol, "")
	if !profile.Redact {
		t.Fatal("expected Redact=true from fallback")
	}
	if len(profile.Patterns) != 3 {
		t.Fatalf("expected 3 patterns from fallback, got %d", len(profile.Patterns))
	}
}

// ---------------------------------------------------------------------------
// Schema validation tests
// ---------------------------------------------------------------------------

func TestValidateEvent_Valid(t *testing.T) {
	e := Event{Source: "tool-firewall", Type: "tool.decision", Severity: "info"}
	if err := validateEvent(e); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateEvent_MissingSource(t *testing.T) {
	e := Event{Type: "tool.decision"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestValidateEvent_MissingType(t *testing.T) {
	e := Event{Source: "tool-firewall"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestValidateEvent_InvalidSeverity(t *testing.T) {
	e := Event{Source: "a", Type: "t", Severity: "bogus"}
	err := validateEvent(e)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEvent_InvalidSourceFormat(t *testing.T) {
	e := Event{Source: "has spaces", Type: "t"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid source format")
	}
}

func TestValidateEvent_InvalidTypeFormat(t *testing.T) {
	e := Event{Source: "a", Type: "has spaces"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid type format")
	}
}

func TestValidateEvent_SessionIDTooLong(t *testing.T) {
	e := Event{Source: "a", Type: "t", SessionID: strings.Repeat("x", 200)}
	err := validateEvent(e)
	if err == nil {
		t.Fatal("expected error for session_id too long")
	}
	if !strings.Contains(err.Error(), "session_id too long") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEvent_InvalidTimestamp(t *testing.T) {
	e := Event{Source: "a", Type: "t", Timestamp: "not-a-timestamp"}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

func TestValidateEvent_ValidTimestampFormats(t *testing.T) {
	for _, ts := range []string{
		"2026-03-09T10:00:00Z",
		"2026-03-09T10:00:00.123456789Z",
		"2026-03-09T10:00:00+05:00",
	} {
		e := Event{Source: "a", Type: "t", Timestamp: ts}
		if err := validateEvent(e); err != nil {
			t.Errorf("timestamp %q should be valid: %v", ts, err)
		}
	}
}

func TestValidateIncident_Valid(t *testing.T) {
	inc := Incident{Title: "Test", Severity: "alert", Status: "open"}
	if err := validateIncident(inc); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateIncident_MissingTitle(t *testing.T) {
	inc := Incident{}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestValidateIncident_InvalidSeverity(t *testing.T) {
	inc := Incident{Title: "Test", Severity: "panic"}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestValidateIncident_InvalidStatus(t *testing.T) {
	inc := Incident{Title: "Test", Status: "deleted"}
	if err := validateIncident(inc); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

// ---------------------------------------------------------------------------
// Event summary tests
// ---------------------------------------------------------------------------

func TestSummarizeEvent(t *testing.T) {
	tests := []struct {
		event    Event
		contains string
	}{
		{
			Event{Type: "tool.decision", Data: map[string]interface{}{"tool": "shell.exec", "allowed": false, "reason": "denied"}},
			"DENIED",
		},
		{
			Event{Type: "model.invoke", Data: map[string]interface{}{"model": "mistral-7b"}},
			"mistral-7b",
		},
		{
			Event{Type: "airlock.request", Data: map[string]interface{}{"destination": "https://hf.co", "allowed": true}},
			"allowed",
		},
		{
			Event{Type: "attestor.report", Data: map[string]interface{}{"verdict": "drift"}},
			"DRIFT",
		},
	}

	for _, tt := range tests {
		summary := summarizeEvent(tt.event)
		if !strings.Contains(summary, tt.contains) {
			t.Errorf("summary for %s should contain %q, got: %s", tt.event.Type, tt.contains, summary)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests (via buildMux)
// ---------------------------------------------------------------------------

func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	setupTestStores(t)
	serviceToken = "secret-token"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	// Health should work without auth.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["service"] != "ai-incident-recorder" {
		t.Fatalf("unexpected service: %v", resp["service"])
	}
}

func TestAllEndpointsRequireAuth(t *testing.T) {
	setupTestStores(t)
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/event"},
		{http.MethodGet, "/v1/events"},
		{http.MethodPost, "/v1/events/batch"},
		{http.MethodGet, "/v1/sessions"},
		{http.MethodGet, "/v1/incident?id=test"},
		{http.MethodGet, "/v1/incidents"},
		{http.MethodPost, "/v1/incident/create"},
		{http.MethodPost, "/v1/incident/package?id=test"},
		{http.MethodPost, "/v1/reload"},
		{http.MethodGet, "/v1/metrics"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 without token, got %d", ep.method, ep.path, w.Code)
		}
	}
}

func TestEndpointsWorkWithValidAuth(t *testing.T) {
	setupTestStores(t)
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	// Record an event with valid auth.
	body := `{"session_id":"s1","source":"tool-firewall","type":"tool.decision","severity":"info"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 with valid auth, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecordEventEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"test-sess","source":"tool-firewall","type":"tool.decision","severity":"info","data":{"tool":"fs.read","allowed":true}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var event Event
	json.Unmarshal(w.Body.Bytes(), &event)
	if event.ID == "" {
		t.Fatal("expected event ID in response")
	}
	if event.Hash == "" {
		t.Fatal("expected event hash in response")
	}
}

func TestRecordEventEndpoint_ValidationRejectsInvalidSeverity(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"source":"a","type":"t","severity":"bogus"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid severity, got %d", w.Code)
	}
}

func TestRecordEventEndpoint_MissingFields(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/event", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRecordEventEndpoint_WrongMethod(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/v1/event", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestQueryEventsEndpoint(t *testing.T) {
	setupTestStores(t)

	// Record some events.
	eventStore.Record(Event{SessionID: "s1", Source: "a", Type: "t1"})
	eventStore.Record(Event{SessionID: "s1", Source: "b", Type: "t2"})
	eventStore.Record(Event{SessionID: "s2", Source: "a", Type: "t1"})

	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/v1/events?session_id=s1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	count := int(resp["count"].(float64))
	if count != 2 {
		t.Fatalf("expected 2 events for session s1, got %d", count)
	}
}

func TestListSessionsEndpoint(t *testing.T) {
	setupTestStores(t)

	eventStore.Record(Event{SessionID: "alpha", Source: "a", Type: "t"})
	eventStore.Record(Event{SessionID: "beta", Source: "b", Type: "t"})

	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCreateIncidentEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"s1","title":"Test Incident","severity":"alert"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var inc Incident
	json.Unmarshal(w.Body.Bytes(), &inc)
	if inc.ID == "" {
		t.Fatal("expected incident ID")
	}
}

func TestCreateIncidentEndpoint_MissingTitle(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"session_id":"s1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCreateIncidentEndpoint_InvalidSeverity(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	body := `{"title":"Test","severity":"panic"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/incident/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid severity, got %d", w.Code)
	}
}

func TestServiceToken_DevMode(t *testing.T) {
	serviceToken = ""
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called in dev mode")
	}
}

func TestServiceToken_InvalidToken(t *testing.T) {
	serviceToken = "correct-token"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	serviceToken = ""
}

func TestMetricsEndpoint(t *testing.T) {
	setupTestStores(t)

	mux := buildMux()

	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Ingest helper tests
// ---------------------------------------------------------------------------

func TestInferEventType(t *testing.T) {
	tests := []struct {
		source   string
		data     map[string]interface{}
		expected string
	}{
		{"tool-firewall", nil, "tool.decision"},
		{"airlock", nil, "airlock.request"},
		{"registry", map[string]interface{}{"promoted_at": "2026-01-01"}, "registry.promote"},
		{"unknown", map[string]interface{}{"type": "custom.event"}, "custom.event"},
	}

	for _, tt := range tests {
		result := inferEventType(tt.data, tt.source)
		if result != tt.expected {
			t.Errorf("inferEventType(%s) = %s, want %s", tt.source, result, tt.expected)
		}
	}
}

func TestInferSeverity(t *testing.T) {
	if s := inferSeverity(map[string]interface{}{"allowed": false}); s != "alert" {
		t.Errorf("denied action should be alert, got %s", s)
	}
	if s := inferSeverity(map[string]interface{}{"severity": "critical"}); s != "critical" {
		t.Errorf("explicit severity should be preserved, got %s", s)
	}
	if s := inferSeverity(map[string]interface{}{}); s != "info" {
		t.Errorf("default should be info, got %s", s)
	}
}

// ---------------------------------------------------------------------------
// Ingest from file test
// ---------------------------------------------------------------------------

func TestIngestFromFile(t *testing.T) {
	dir := t.TempDir()
	es, _ := NewEventStore(dir, RetentionConfig{})
	defer es.Close()

	// Create test JSONL file.
	jsonl := `{"timestamp":"2026-03-09T10:00:00Z","tool":"filesystem.read","allowed":true,"reason":"ok"}
{"timestamp":"2026-03-09T10:00:01Z","tool":"shell.exec","allowed":false,"reason":"denied"}
`
	filePath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(filePath, []byte(jsonl), 0644)

	// Simulate ingest.
	data, _ := os.ReadFile(filePath)
	sessionID := "ingest-test"
	source := "tool-firewall"

	var count int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		json.Unmarshal([]byte(line), &raw)

		event := Event{
			SessionID: sessionID,
			Source:    source,
			Type:      inferEventType(raw, source),
			Data:      raw,
			Severity:  inferSeverity(raw),
		}
		if ts, ok := raw["timestamp"].(string); ok {
			event.Timestamp = ts
		}
		es.Record(event)
		count++
	}

	if count != 2 {
		t.Fatalf("expected 2 ingested events, got %d", count)
	}

	events := es.Query(EventFilter{SessionID: sessionID})
	if len(events) != 2 {
		t.Fatalf("expected 2 queryable events, got %d", len(events))
	}
}

// ---------------------------------------------------------------------------
// Corruption tolerance test
// ---------------------------------------------------------------------------

func TestEventStore_CorruptionRecovery(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/events.jsonl"

	// Write some valid events + a corrupt line.
	valid1 := `{"id":"1","timestamp":"2026-01-01T00:00:00Z","session_id":"s","source":"a","type":"t","severity":"info","hash":"abc"}`
	corrupt := `{CORRUPT LINE`
	valid2 := `{"id":"2","timestamp":"2026-01-01T00:01:00Z","session_id":"s","source":"a","type":"t","severity":"info","hash":"def"}`
	os.WriteFile(filePath, []byte(valid1+"\n"+corrupt+"\n"+valid2+"\n"), 0640)

	store, err := NewEventStore(dir, RetentionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Should have loaded 2 events (skipped the corrupt line).
	if store.EventCount() != 2 {
		t.Fatalf("expected 2 events (skipping corrupt), got %d", store.EventCount())
	}
}

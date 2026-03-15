package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFireWebhooks_NoConfig(t *testing.T) {
	resetGlobalState(t)
	// No webhooks configured — should not panic
	fireWebhooks("containment", Incident{
		ID:       "INC-test-001",
		Class:    ClassPolicyBypass,
		Severity: SeverityHigh,
	}, []string{"freeze_agent"})
	// No assertion needed; test passes if no panic occurs.
}

func TestFireWebhooks_MatchingEvent(t *testing.T) {
	resetGlobalState(t)

	var received atomic.Int32
	var mu sync.Mutex
	var gotPayload AlertPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewDecoder(r.Body).Decode(&gotPayload)
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	setAlertingConfig(AlertingConfig{
		Webhooks: []WebhookTarget{
			{URL: srv.URL, Events: []string{"containment"}},
		},
	})

	inc := Incident{
		ID:       "INC-test-002",
		Class:    ClassAttestationFailure,
		Severity: SeverityCritical,
		Source:   "runtime-attestor",
	}
	fireWebhooks("containment", inc, []string{"freeze_agent", "disable_airlock"})

	// Wait for async delivery
	deadline := time.After(5 * time.Second)
	for received.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("webhook was not called within timeout")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPayload.Event != "containment" {
		t.Errorf("expected event 'containment', got %q", gotPayload.Event)
	}
	if gotPayload.Incident.ID != "INC-test-002" {
		t.Errorf("expected incident ID 'INC-test-002', got %q", gotPayload.Incident.ID)
	}
	if gotPayload.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", gotPayload.Severity)
	}
	if len(gotPayload.Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(gotPayload.Actions))
	}
}

func TestFireWebhooks_NonMatchingEvent(t *testing.T) {
	resetGlobalState(t)

	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Webhook only listens for "escalation", not "containment"
	setAlertingConfig(AlertingConfig{
		Webhooks: []WebhookTarget{
			{URL: srv.URL, Events: []string{"escalation"}},
		},
	})

	fireWebhooks("containment", Incident{ID: "INC-test-003"}, []string{"freeze_agent"})
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 0 {
		t.Errorf("webhook should not have been called for non-matching event, got %d calls", called.Load())
	}
}

func TestFireWebhooks_RetryOnFailure(t *testing.T) {
	resetGlobalState(t)

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	setAlertingConfig(AlertingConfig{
		Webhooks: []WebhookTarget{
			{URL: srv.URL, Events: []string{}}, // match all
		},
	})

	fireWebhooks("containment", Incident{ID: "INC-test-004", Severity: SeverityHigh}, []string{"log_alert"})

	// Wait for retry
	deadline := time.After(10 * time.Second)
	for attempts.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("expected 2 attempts (retry), got %d", attempts.Load())
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	if attempts.Load() != 2 {
		t.Errorf("expected exactly 2 attempts, got %d", attempts.Load())
	}
}

func TestMatchesEvent_EmptyMatchesAll(t *testing.T) {
	if !matchesEvent([]string{}, "containment") {
		t.Error("empty event filter should match all events")
	}
	if !matchesEvent([]string{}, "escalation") {
		t.Error("empty event filter should match all events")
	}
	if !matchesEvent(nil, "recovery") {
		t.Error("nil event filter should match all events")
	}
}

func TestMatchesEvent_SpecificFilter(t *testing.T) {
	events := []string{"containment", "recovery"}
	if !matchesEvent(events, "containment") {
		t.Error("should match 'containment'")
	}
	if !matchesEvent(events, "recovery") {
		t.Error("should match 'recovery'")
	}
	if matchesEvent(events, "escalation") {
		t.Error("should not match 'escalation'")
	}
}

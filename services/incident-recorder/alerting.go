package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// =========================================================================
// Alerting — fire-and-forget webhooks on containment/escalation events
// =========================================================================

// AlertingConfig holds webhook configuration loaded from the containment policy.
type AlertingConfig struct {
	Webhooks []WebhookTarget `yaml:"webhooks" json:"webhooks"`
}

// WebhookTarget defines a single webhook endpoint.
type WebhookTarget struct {
	URL    string   `yaml:"url" json:"url"`
	Events []string `yaml:"events" json:"events"` // "containment", "escalation", "recovery"
}

// AlertPayload is the JSON body sent to webhook endpoints.
type AlertPayload struct {
	Event     string   `json:"event"`
	Timestamp string   `json:"timestamp"`
	Incident  Incident `json:"incident"`
	Actions   []string `json:"actions,omitempty"`
	Severity  string   `json:"severity"`
	Source    string   `json:"source"`
}

var (
	alertingCfg   AlertingConfig
	alertingCfgMu sync.RWMutex
)

func getAlertingConfig() AlertingConfig {
	alertingCfgMu.RLock()
	defer alertingCfgMu.RUnlock()
	return alertingCfg
}

func setAlertingConfig(cfg AlertingConfig) {
	alertingCfgMu.Lock()
	defer alertingCfgMu.Unlock()
	alertingCfg = cfg
}

// fireWebhooks dispatches alert payloads to all configured webhook URLs
// matching the given event type.  Fire-and-forget with one retry.
func fireWebhooks(event string, inc Incident, actions []string) {
	cfg := getAlertingConfig()
	if len(cfg.Webhooks) == 0 {
		return
	}

	payload := AlertPayload{
		Event:     event,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Incident:  inc,
		Actions:   actions,
		Severity:  string(inc.Severity),
		Source:    "incident-recorder",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("alerting: failed to marshal payload: %v", err)
		return
	}

	for _, wh := range cfg.Webhooks {
		if !matchesEvent(wh.Events, event) {
			continue
		}
		go sendWebhook(wh.URL, body)
	}
}

// matchesEvent returns true if the event list is empty (match all) or
// contains the given event string.
func matchesEvent(events []string, event string) bool {
	if len(events) == 0 {
		return true // empty filter = match all events
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

// sendWebhook POSTs the JSON body to the given URL.
// Retries once after 1 second on failure.  5-second timeout per attempt.
func sendWebhook(url string, body []byte) {
	client := &http.Client{Timeout: 5 * time.Second}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("alerting: cannot create request for %s: %v", url, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SecAI-Incident-Recorder/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("alerting: POST to %s failed (attempt %d): %v", url, attempt+1, err)
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("alerting: webhook delivered to %s (status %d)", url, resp.StatusCode)
			return
		}
		log.Printf("alerting: webhook to %s returned status %d (attempt %d)", url, resp.StatusCode, attempt+1)
		if attempt == 0 {
			time.Sleep(1 * time.Second)
		}
	}
}

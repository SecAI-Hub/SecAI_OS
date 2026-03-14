package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// =========================================================================
// Containment action execution
// =========================================================================

// ServiceEndpoints holds the loopback addresses of services that
// containment actions target.  Populated from environment variables
// at startup, falling back to defaults.
type ServiceEndpoints struct {
	AgentURL    string
	AirlockURL  string
	RegistryURL string
}

var endpoints ServiceEndpoints

func loadServiceEndpoints() {
	endpoints = ServiceEndpoints{
		AgentURL:    envOrDefault("AGENT_URL", "http://127.0.0.1:8476"),
		AirlockURL:  envOrDefault("AIRLOCK_URL", "http://127.0.0.1:8490"),
		RegistryURL: envOrDefault("REGISTRY_URL", "http://127.0.0.1:8470"),
	}
	log.Printf("containment endpoints: agent=%s airlock=%s registry=%s",
		endpoints.AgentURL, endpoints.AirlockURL, endpoints.RegistryURL)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// executeContainment runs the list of containment actions returned by the
// containment policy.  Each action is a best-effort HTTP call to the
// target service.  Failures are logged but do not block other actions
// (defense-in-depth: each action is independent).
//
// ep and token are snapshots captured by the caller before spawning the
// goroutine, avoiding data races with concurrent test state resets.
func executeContainment(inc Incident, ep ServiceEndpoints, token string) {
	if len(inc.ContainmentActions) == 0 {
		return
	}

	for _, action := range inc.ContainmentActions {
		var err error
		switch action {
		case "freeze_agent":
			err = freezeAgent(inc, ep, token)
		case "disable_airlock":
			err = disableAirlock(inc, ep, token)
		case "force_vault_relock":
			err = forceVaultRelock(inc, ep, token)
		case "quarantine_model":
			err = quarantineModel(inc, ep, token)
		case "log_alert":
			logAlert(inc)
		default:
			log.Printf("containment: unknown action %q for incident %s", action, inc.ID)
		}
		if err != nil {
			log.Printf("containment: action %q failed for incident %s: %v", action, inc.ID, err)
		} else {
			log.Printf("containment: action %q executed for incident %s", action, inc.ID)
		}
	}
}

// freezeAgent tells the agent service to enter frozen/safe mode.
func freezeAgent(inc Incident, ep ServiceEndpoints, token string) error {
	payload := map[string]string{
		"action":      "freeze",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
	}
	return postJSON(ep.AgentURL+"/api/v1/freeze", payload, token)
}

// disableAirlock tells the airlock to reject all requests.
func disableAirlock(inc Incident, ep ServiceEndpoints, token string) error {
	payload := map[string]string{
		"action":      "disable",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
	}
	return postJSON(ep.AirlockURL+"/api/v1/disable", payload, token)
}

// forceVaultRelock triggers an immediate vault relock.
func forceVaultRelock(inc Incident, ep ServiceEndpoints, token string) error {
	payload := map[string]string{
		"action":      "relock",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
	}
	return postJSON(ep.AgentURL+"/api/v1/vault/relock", payload, token)
}

// quarantineModel instructs the registry to demote a model back to quarantine.
func quarantineModel(inc Incident, ep ServiceEndpoints, token string) error {
	modelPath := ""
	if inc.Evidence != nil {
		if p, ok := inc.Evidence["model_path"]; ok {
			modelPath = p
		}
		if p, ok := inc.Evidence["violation_0_path"]; ok && modelPath == "" {
			modelPath = p
		}
	}
	payload := map[string]string{
		"action":      "quarantine",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
		"model_path":  modelPath,
	}
	return postJSON(ep.RegistryURL+"/api/v1/quarantine", payload, token)
}

// logAlert writes a structured alert to the audit log.
func logAlert(inc Incident) {
	log.Printf("ALERT: incident %s class=%s severity=%s source=%s — %s",
		inc.ID, inc.Class, inc.Severity, inc.Source, inc.Description)
}

// postJSON is a helper that POSTs a JSON payload to a URL with an
// optional bearer token.  Returns nil on success (2xx), error otherwise.
func postJSON(url string, payload interface{}, token string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url = strings.TrimSuffix(url, "/")
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
}

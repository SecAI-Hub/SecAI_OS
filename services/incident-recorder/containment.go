package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	AgentURL        string
	AgentSocket     string
	AirlockURL      string
	RegistryURL     string
	VaultRequestDir string
	VaultResultDir  string
}

var endpoints ServiceEndpoints

type ContainmentTokens struct {
	Agent    string
	Airlock  string
	Registry string
}

var containmentTokens ContainmentTokens

func loadServiceEndpoints() {
	endpoints = ServiceEndpoints{
		AgentURL:        os.Getenv("AGENT_URL"),
		AgentSocket:     envOrDefault("AGENT_SOCKET", "/run/secure-ai/agent/agent.sock"),
		AirlockURL:      envOrDefault("AIRLOCK_URL", "http://127.0.0.1:8490"),
		RegistryURL:     envOrDefault("REGISTRY_URL", "http://127.0.0.1:8470"),
		VaultRequestDir: envOrDefault("VAULT_RELOCK_REQUEST_DIR", "/run/secure-ai/vault-control/requests"),
		VaultResultDir:  envOrDefault("VAULT_RELOCK_RESULT_DIR", "/run/secure-ai/vault-control/results"),
	}
	log.Printf(
		"containment endpoints: agent_socket=%s agent_url=%s airlock=%s registry=%s vault_requests=%s",
		endpoints.AgentSocket,
		endpoints.AgentURL,
		endpoints.AirlockURL,
		endpoints.RegistryURL,
		endpoints.VaultRequestDir,
	)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readRequiredToken(pathEnv string) (string, error) {
	path := strings.TrimSpace(os.Getenv(pathEnv))
	if path == "" {
		return "", fmt.Errorf("%s is not configured", pathEnv)
	}
	token, _, err := readCanonicalCredentialFile(path, pathEnv)
	if err != nil {
		return "", err
	}
	return token, nil
}

func readCanonicalCredentialFile(path, label string) (string, []byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, fmt.Errorf("%s path is not canonical and absolute", label)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", nil, fmt.Errorf("inspect %s credential %s: %w", label, path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		(before.Size() != sha256.Size*2 && before.Size() != sha256.Size*2+1) {
		return "", nil, fmt.Errorf("%s credential %s has an unsafe type or size", label, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("open %s credential %s: %w", label, path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("inspect open %s credential %s: %w", label, path, err)
	}
	if !os.SameFile(before, opened) {
		return "", nil, fmt.Errorf("%s credential %s changed while opening", label, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, sha256.Size*2+2))
	if err != nil {
		return "", nil, fmt.Errorf("read %s credential %s: %w", label, path, err)
	}
	if len(data) == sha256.Size*2+1 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	value := string(data)
	if !canonicalSHA256String(value) {
		return "", nil, fmt.Errorf("%s credential %s is not a canonical 256-bit lowercase hexadecimal value", label, path)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", nil, fmt.Errorf("decode %s credential %s: %w", label, path, err)
	}
	return value, decoded, nil
}

func loadContainmentTokens() error {
	var err error
	if containmentTokens.Agent, err = readRequiredToken("AGENT_CONTAINMENT_TOKEN_PATH"); err != nil {
		return err
	}
	if containmentTokens.Airlock, err = readRequiredToken("AIRLOCK_CONTAINMENT_TOKEN_PATH"); err != nil {
		return err
	}
	if containmentTokens.Registry, err = readRequiredToken("REGISTRY_CONTAINMENT_TOKEN_PATH"); err != nil {
		return err
	}
	return nil
}

// executeContainment attempts every mandatory action and returns durable
// per-action evidence. The caller may mark the incident contained only when
// every action succeeds.
func executeContainment(inc Incident, ep ServiceEndpoints, token string) ([]ContainmentResult, bool) {
	if len(inc.ContainmentActions) == 0 {
		return nil, true
	}

	results := make([]ContainmentResult, 0, len(inc.ContainmentActions))
	allSucceeded := true
	for _, action := range inc.ContainmentActions {
		var err error
		switch action {
		case "freeze_agent":
			err = freezeAgent(inc, ep, firstNonEmpty(token, containmentTokens.Agent))
		case "disable_airlock":
			err = disableAirlock(inc, ep, firstNonEmpty(token, containmentTokens.Airlock))
		case "force_vault_relock":
			err = forceVaultRelock(inc, ep, firstNonEmpty(token, containmentTokens.Agent))
		case "quarantine_model":
			err = quarantineModel(inc, ep, firstNonEmpty(token, containmentTokens.Registry))
		case "log_alert":
			logAlert(inc)
		default:
			err = fmt.Errorf("unsupported containment action")
		}
		result := ContainmentResult{
			Action:      action,
			Success:     err == nil,
			CompletedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err != nil {
			allSucceeded = false
			result.Error = err.Error()
			log.Printf("containment: action %q failed for incident %s: %v", action, inc.ID, err)
		} else {
			log.Printf("containment: action %q executed for incident %s", action, inc.ID)
		}
		results = append(results, result)
	}
	return results, allSucceeded
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// freezeAgent tells the agent service to enter frozen/safe mode.
func freezeAgent(inc Incident, ep ServiceEndpoints, token string) error {
	payload := map[string]string{
		"action":      "freeze",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
	}
	if strings.TrimSpace(ep.AgentSocket) != "" {
		return postJSONUnix(ep.AgentSocket, "/api/v1/freeze", payload, token)
	}
	if strings.TrimSpace(ep.AgentURL) == "" {
		return fmt.Errorf("agent containment endpoint is not configured")
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
	if ep.VaultRequestDir != "" || ep.VaultResultDir != "" {
		if ep.VaultRequestDir == "" || ep.VaultResultDir == "" {
			return fmt.Errorf("vault relock broker directories are incompletely configured")
		}
		return requestVaultRelock(inc, ep.VaultRequestDir, ep.VaultResultDir)
	}
	// Development-only HTTP fallback retained for sandbox compatibility. Native
	// production uses the fixed-function, root-owned path broker above.
	if strings.TrimSpace(ep.AgentURL) == "" {
		return fmt.Errorf("vault relock broker is not configured")
	}
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
	modelName := ""
	if inc.Evidence != nil {
		if p, ok := inc.Evidence["model_path"]; ok {
			modelPath = p
		}
		if p, ok := inc.Evidence["violation_0_path"]; ok && modelPath == "" {
			modelPath = p
		}
		if name, ok := inc.Evidence["model_name"]; ok {
			modelName = name
		}
	}
	payload := map[string]string{
		"action":      "quarantine",
		"reason":      fmt.Sprintf("containment for incident %s (%s)", inc.ID, inc.Class),
		"incident_id": inc.ID,
		"model_path":  modelPath,
		"model_name":  modelName,
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

func postJSONUnix(socketPath, requestPath string, payload interface{}, token string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://unix"+requestPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 40 * time.Second}
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST unix:%s%s: %w", socketPath, requestPath, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST unix:%s%s: status %d", socketPath, requestPath, resp.StatusCode)
	}
	return nil
}

type vaultRelockResult struct {
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	IncidentID string `json:"incident_id"`
}

func safeIncidentFilename(id string) (string, error) {
	if id == "" || len(id) > 128 {
		return "", fmt.Errorf("invalid incident id")
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return "", fmt.Errorf("invalid incident id")
		}
	}
	return id + ".json", nil
}

func requestVaultRelock(inc Incident, requestDir, resultDir string) error {
	filename, err := safeIncidentFilename(inc.ID)
	if err != nil {
		return err
	}
	resultPath := filepath.Join(resultDir, filename)
	if _, err := os.Stat(resultPath); err == nil {
		return fmt.Errorf("stale vault relock result already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect vault relock result: %w", err)
	}
	request := map[string]string{
		"action":      "relock",
		"incident_id": inc.ID,
		"reason":      fmt.Sprintf("incident containment for %s", inc.Class),
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(requestDir, ".request-*")
	if err != nil {
		return fmt.Errorf("create vault relock request: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0640); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	requestPath := filepath.Join(requestDir, filename)
	if err := os.Rename(tempPath, requestPath); err != nil {
		return fmt.Errorf("publish vault relock request: %w", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(resultPath)
		if err == nil {
			var result vaultRelockResult
			if err := json.Unmarshal(data, &result); err != nil {
				return fmt.Errorf("invalid vault relock result: %w", err)
			}
			if result.IncidentID != inc.ID {
				return fmt.Errorf("vault relock result incident mismatch")
			}
			if !result.Success {
				if result.Error == "" {
					result.Error = "root broker reported failure"
				}
				return fmt.Errorf("vault relock failed: %s", result.Error)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("read vault relock result: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("vault relock broker timed out")
}

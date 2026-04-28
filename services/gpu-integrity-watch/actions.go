package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var outboundHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ActionType identifies a response action.
type ActionType string

const (
	ActionReload     ActionType = "reload"
	ActionQuarantine ActionType = "quarantine"
	ActionAlert      ActionType = "alert"
	ActionFailClosed ActionType = "fail_closed"
)

// ActionConfig defines when and how to trigger a response action.
type ActionConfig struct {
	Name      string     `yaml:"name" json:"name"`
	Type      ActionType `yaml:"type" json:"type"`
	Trigger   Verdict    `yaml:"trigger" json:"trigger"` // verdict level that triggers this action
	Webhook   string     `yaml:"webhook,omitempty" json:"webhook,omitempty"`
	Command   string     `yaml:"command,omitempty" json:"command,omitempty"`
	TargetDir string     `yaml:"target_dir,omitempty" json:"target_dir,omitempty"` // for quarantine
}

// ActionResult records the outcome of an executed action.
type ActionResult struct {
	Action    string     `json:"action"`
	Type      ActionType `json:"type"`
	Triggered bool       `json:"triggered"`
	Success   bool       `json:"success"`
	Message   string     `json:"message"`
	Timestamp time.Time  `json:"timestamp"`
}

// ActionExecutor evaluates scoring results and triggers configured actions.
type ActionExecutor struct {
	actions  []ActionConfig
	modelDir string
	inferURL string
}

// NewActionExecutor creates an executor with the given action configs.
func NewActionExecutor(actions []ActionConfig, modelDir, inferURL string) *ActionExecutor {
	return &ActionExecutor{
		actions:  actions,
		modelDir: modelDir,
		inferURL: inferURL,
	}
}

// Evaluate checks the score entry against action triggers and executes matching actions.
func (e *ActionExecutor) Evaluate(entry ScoreEntry) []ActionResult {
	var results []ActionResult

	for _, ac := range e.actions {
		if !shouldTrigger(ac.Trigger, entry.Verdict) {
			continue
		}

		var ar ActionResult
		switch ac.Type {
		case ActionReload:
			ar = e.executeReload(ac)
		case ActionQuarantine:
			ar = e.executeQuarantine(ac)
		case ActionAlert:
			ar = e.executeAlert(ac, entry)
		case ActionFailClosed:
			ar = e.executeFailClosed(ac)
		default:
			ar = ActionResult{
				Action:    ac.Name,
				Type:      ac.Type,
				Triggered: true,
				Success:   false,
				Message:   fmt.Sprintf("unknown action type: %s", ac.Type),
			}
		}

		ar.Timestamp = time.Now()
		results = append(results, ar)
	}

	return results
}

// shouldTrigger returns true if the current verdict meets the trigger threshold.
func shouldTrigger(trigger Verdict, current Verdict) bool {
	order := map[Verdict]int{
		VerdictHealthy:  0,
		VerdictWarning:  1,
		VerdictCritical: 2,
	}

	return order[current] >= order[trigger]
}

// executeReload signals the inference server to reload the model.
func (e *ActionExecutor) executeReload(ac ActionConfig) ActionResult {
	ar := ActionResult{Action: ac.Name, Type: ActionReload, Triggered: true}

	target := e.inferURL
	if target == "" {
		ar.Success = false
		ar.Message = "no inference URL configured for reload"
		return ar
	}

	// Try llama.cpp-style reload endpoint
	url := strings.TrimSuffix(target, "/") + "/reload"
	resp, err := outboundHTTPClient.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		// Fall back to command if configured
		if ac.Command != "" {
			return executeCommand(ac)
		}
		ar.Success = false
		ar.Message = fmt.Sprintf("reload request failed: %v", err)
		return ar
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ar.Success = true
		ar.Message = "model reload triggered"
	} else {
		ar.Success = false
		ar.Message = fmt.Sprintf("reload returned status %d", resp.StatusCode)
	}

	return ar
}

// executeQuarantine moves model files to a quarantine directory.
func (e *ActionExecutor) executeQuarantine(ac ActionConfig) ActionResult {
	ar := ActionResult{Action: ac.Name, Type: ActionQuarantine, Triggered: true}

	srcDir := e.modelDir
	if srcDir == "" {
		ar.Success = false
		ar.Message = "no model directory configured for quarantine"
		return ar
	}

	qDir := ac.TargetDir
	if qDir == "" {
		qDir = filepath.Join(filepath.Dir(srcDir), "quarantine")
	}

	if err := os.MkdirAll(qDir, 0o700); err != nil {
		ar.Success = false
		ar.Message = fmt.Sprintf("failed to create quarantine dir: %v", err)
		return ar
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		ar.Success = false
		ar.Message = fmt.Sprintf("failed to read model dir: %v", err)
		return ar
	}

	moved := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Only quarantine model files
		for _, ext := range []string{".gguf", ".bin", ".safetensors"} {
			if strings.HasSuffix(name, ext) {
				src := filepath.Join(srcDir, name)
				dst := filepath.Join(qDir, name)
				if err := os.Rename(src, dst); err != nil {
					log.Printf("[action] quarantine move failed %s: %v", name, err)
				} else {
					moved++
				}
				break
			}
		}
	}

	ar.Success = true
	ar.Message = fmt.Sprintf("quarantined %d model files to %s", moved, qDir)
	return ar
}

// executeAlert sends an alert via webhook or command.
func (e *ActionExecutor) executeAlert(ac ActionConfig, entry ScoreEntry) ActionResult {
	ar := ActionResult{Action: ac.Name, Type: ActionAlert, Triggered: true}

	payload := map[string]interface{}{
		"source":    "gpu-integrity-watch",
		"verdict":   entry.Verdict,
		"score":     entry.CompositeScore,
		"probes":    entry.ProbeScores,
		"timestamp": entry.Timestamp.Format(time.RFC3339),
	}

	if ac.Webhook != "" {
		body, _ := json.Marshal(payload)
		resp, err := outboundHTTPClient.Post(ac.Webhook, "application/json", strings.NewReader(string(body)))
		if err != nil {
			ar.Success = false
			ar.Message = fmt.Sprintf("webhook failed: %v", err)
			return ar
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ar.Success = true
			ar.Message = "alert sent via webhook"
		} else {
			ar.Success = false
			ar.Message = fmt.Sprintf("webhook returned %d", resp.StatusCode)
		}
		return ar
	}

	if ac.Command != "" {
		return executeCommand(ac)
	}

	// Default: log the alert
	log.Printf("[ALERT] integrity verdict=%s score=%.2f", entry.Verdict, entry.CompositeScore)
	ar.Success = true
	ar.Message = "alert logged (no webhook or command configured)"
	return ar
}

// executeFailClosed attempts to shut down the inference server.
func (e *ActionExecutor) executeFailClosed(ac ActionConfig) ActionResult {
	ar := ActionResult{Action: ac.Name, Type: ActionFailClosed, Triggered: true}

	if ac.Command != "" {
		return executeCommand(ac)
	}

	// Try to signal inference server shutdown
	if e.inferURL != "" {
		url := strings.TrimSuffix(e.inferURL, "/") + "/shutdown"
		resp, err := outboundHTTPClient.Post(url, "application/json", strings.NewReader("{}"))
		if err != nil {
			ar.Success = false
			ar.Message = fmt.Sprintf("fail-closed shutdown request failed: %v", err)
			return ar
		}
		defer resp.Body.Close()
		ar.Success = true
		ar.Message = "fail-closed: shutdown signal sent to inference server"
		return ar
	}

	ar.Success = false
	ar.Message = "fail-closed: no command or inference URL configured"
	return ar
}

// executeCommand runs a shell command for an action.
func executeCommand(ac ActionConfig) ActionResult {
	ar := ActionResult{Action: ac.Name, Type: ac.Type, Triggered: true}

	if os.Getenv("GPU_WATCH_ALLOW_ACTION_COMMANDS") != "true" {
		ar.Success = false
		ar.Message = "command actions disabled; set GPU_WATCH_ALLOW_ACTION_COMMANDS=true"
		return ar
	}

	cmd := exec.Command("sh", "-c", ac.Command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		ar.Success = false
		ar.Message = fmt.Sprintf("command failed: %v\noutput: %s", err, string(output))
	} else {
		ar.Success = true
		ar.Message = fmt.Sprintf("command executed: %s", strings.TrimSpace(string(output)))
	}

	return ar
}

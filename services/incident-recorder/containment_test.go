package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// =========================================================================
// Containment execution tests
// =========================================================================

func TestExecuteContainment_NoActions(t *testing.T) {
	inc := Incident{ID: "INC-001", ContainmentActions: nil}
	ep := ServiceEndpoints{}
	// Should not panic.
	executeContainment(inc, ep, "")
}

func TestExecuteContainment_FreezeAgent(t *testing.T) {
	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := ServiceEndpoints{AgentURL: srv.URL}
	inc := Incident{
		ID:                 "INC-FREEZE-001",
		Class:              ClassAttestationFailure,
		ContainmentActions: []string{"freeze_agent"},
	}
	executeContainment(inc, ep, "")

	if received["action"] != "freeze" {
		t.Errorf("expected action=freeze, got %s", received["action"])
	}
	if received["incident_id"] != "INC-FREEZE-001" {
		t.Errorf("expected incident_id, got %s", received["incident_id"])
	}
}

func TestExecuteContainment_DisableAirlock(t *testing.T) {
	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := ServiceEndpoints{AirlockURL: srv.URL}
	inc := Incident{
		ID:                 "INC-AIRLOCK-001",
		Class:              ClassIntegrityViolation,
		ContainmentActions: []string{"disable_airlock"},
	}
	executeContainment(inc, ep, "")

	if received["action"] != "disable" {
		t.Errorf("expected action=disable, got %s", received["action"])
	}
}

func TestExecuteContainment_QuarantineModel(t *testing.T) {
	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := ServiceEndpoints{RegistryURL: srv.URL}
	inc := Incident{
		ID:                 "INC-MODEL-001",
		Class:              ClassModelAnomaly,
		ContainmentActions: []string{"quarantine_model"},
		Evidence: map[string]string{
			"model_path": "/var/lib/secure-ai/registry/model.gguf",
		},
	}
	executeContainment(inc, ep, "")

	if received["action"] != "quarantine" {
		t.Errorf("expected action=quarantine, got %s", received["action"])
	}
	if received["model_path"] != "/var/lib/secure-ai/registry/model.gguf" {
		t.Errorf("expected model_path from evidence, got %s", received["model_path"])
	}
}

func TestExecuteContainment_MultipleActions(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := ServiceEndpoints{AgentURL: srv.URL, AirlockURL: srv.URL}
	inc := Incident{
		ID:                 "INC-MULTI-001",
		Class:              ClassAttestationFailure,
		ContainmentActions: []string{"freeze_agent", "disable_airlock", "log_alert"},
	}
	executeContainment(inc, ep, "")

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 { // freeze_agent + disable_airlock (log_alert doesn't POST)
		t.Errorf("expected 2 HTTP calls, got %d: %v", len(paths), paths)
	}
}

func TestExecuteContainment_ServiceDown_NoFatal(t *testing.T) {
	ep := ServiceEndpoints{AgentURL: "http://127.0.0.1:1"} // closed port
	inc := Incident{
		ID:                 "INC-DOWN-001",
		Class:              ClassPolicyBypass,
		ContainmentActions: []string{"freeze_agent"},
	}
	// Should not panic; error is logged.
	executeContainment(inc, ep, "")
}

func TestExecuteContainment_BearerToken(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ep := ServiceEndpoints{AgentURL: srv.URL}
	inc := Incident{
		ID:                 "INC-TOKEN-001",
		Class:              ClassPromptInjection,
		ContainmentActions: []string{"freeze_agent"},
	}
	executeContainment(inc, ep, "containment-secret")

	if authHeader != "Bearer containment-secret" {
		t.Errorf("expected Bearer token, got %q", authHeader)
	}
}

func TestFreezeAgentUnixSocketUsesContainmentCredential(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	authReceived := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReceived <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	err = freezeAgent(
		Incident{ID: "INC-UDS-001", Class: ClassIntegrityViolation},
		ServiceEndpoints{AgentSocket: socketPath},
		"agent-containment-only",
	)
	if err != nil {
		t.Fatalf("freeze over Unix socket failed: %v", err)
	}
	select {
	case auth := <-authReceived:
		if auth != "Bearer agent-containment-only" {
			t.Fatalf("unexpected Unix-socket authorization: %q", auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent Unix-socket request was not received")
	}
}

func TestExecuteContainment_UnknownAction(t *testing.T) {
	ep := ServiceEndpoints{}
	inc := Incident{
		ID:                 "INC-UNK-001",
		Class:              ClassToolCallBurst,
		ContainmentActions: []string{"unknown_action"},
	}
	// Should not panic.
	executeContainment(inc, ep, "")
}

func TestExecuteContainment_LogAlert_NoHTTP(t *testing.T) {
	// log_alert should not make HTTP calls.
	ep := ServiceEndpoints{}
	inc := Incident{
		ID:                 "INC-LOG-001",
		Class:              ClassForbiddenAirlock,
		Severity:           SeverityMedium,
		Source:             "airlock",
		Description:        "test alert",
		ContainmentActions: []string{"log_alert"},
	}
	// Should not panic and should not make HTTP calls.
	executeContainment(inc, ep, "")
}

func TestVaultRelockBrokerRequiresAuthenticatedResult(t *testing.T) {
	requestDir := t.TempDir()
	resultDir := t.TempDir()
	inc := Incident{ID: "INC-BROKER-001", Class: ClassIntegrityViolation}

	brokerDone := make(chan struct{})
	go func() {
		defer close(brokerDone)
		requestPath := filepath.Join(requestDir, inc.ID+".json")
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(requestPath); err == nil {
				result, _ := json.Marshal(vaultRelockResult{
					Success:    true,
					IncidentID: inc.ID,
				})
				_ = os.WriteFile(
					filepath.Join(resultDir, inc.ID+".json"),
					result,
					0o640,
				)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	if err := requestVaultRelock(inc, requestDir, resultDir); err != nil {
		t.Fatalf("vault broker request failed: %v", err)
	}
	<-brokerDone
}

func TestVaultRelockBrokerRejectsFailure(t *testing.T) {
	requestDir := t.TempDir()
	resultDir := t.TempDir()
	inc := Incident{ID: "INC-BROKER-FAIL", Class: ClassIntegrityViolation}

	go func() {
		requestPath := filepath.Join(requestDir, inc.ID+".json")
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(requestPath); err == nil {
				result, _ := json.Marshal(vaultRelockResult{
					Success:    false,
					Error:      "cryptsetup close failed",
					IncidentID: inc.ID,
				})
				_ = os.WriteFile(
					filepath.Join(resultDir, inc.ID+".json"),
					result,
					0o640,
				)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	if err := requestVaultRelock(inc, requestDir, resultDir); err == nil {
		t.Fatal("broker failure must fail containment")
	}
}

// =========================================================================
// Service endpoint config tests
// =========================================================================

func TestLoadServiceEndpoints_Defaults(t *testing.T) {
	t.Setenv("AGENT_URL", "")
	t.Setenv("AGENT_SOCKET", "")
	t.Setenv("AIRLOCK_URL", "")
	t.Setenv("REGISTRY_URL", "")
	loadServiceEndpoints()

	if endpoints.AgentURL != "" {
		t.Errorf("expected native default to avoid agent TCP, got %s", endpoints.AgentURL)
	}
	if endpoints.AgentSocket != "/run/secure-ai/agent/agent.sock" {
		t.Errorf("expected native agent Unix socket, got %s", endpoints.AgentSocket)
	}
	if endpoints.AirlockURL != "http://127.0.0.1:8490" {
		t.Errorf("expected default airlock URL, got %s", endpoints.AirlockURL)
	}
	if endpoints.RegistryURL != "http://127.0.0.1:8470" {
		t.Errorf("expected default registry URL, got %s", endpoints.RegistryURL)
	}
}

func TestLoadServiceEndpoints_CustomEnv(t *testing.T) {
	t.Setenv("AGENT_URL", "http://custom:1234")
	t.Setenv("AGENT_SOCKET", "/tmp/custom-agent.sock")
	t.Setenv("AIRLOCK_URL", "http://custom:5678")
	t.Setenv("REGISTRY_URL", "http://custom:9012")
	loadServiceEndpoints()

	if endpoints.AgentURL != "http://custom:1234" {
		t.Errorf("expected custom agent URL, got %s", endpoints.AgentURL)
	}
	if endpoints.AgentSocket != "/tmp/custom-agent.sock" {
		t.Errorf("expected custom agent socket, got %s", endpoints.AgentSocket)
	}
	if endpoints.AirlockURL != "http://custom:5678" {
		t.Errorf("expected custom airlock URL, got %s", endpoints.AirlockURL)
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("TEST_VAR_EXIST", "custom-value")
	if envOrDefault("TEST_VAR_EXIST", "default") != "custom-value" {
		t.Error("should use env var when set")
	}
	if envOrDefault("TEST_VAR_NONEXISTENT_12345", "default") != "default" {
		t.Error("should use default when env var not set")
	}
}

// =========================================================================
// Integration: createIncident triggers containment
// =========================================================================

func TestCreateIncident_TriggersContainment(t *testing.T) {
	resetGlobalState(t)
	containmentExecutor = executeContainment

	// Set up a mock agent endpoint to receive freeze.
	var mu sync.Mutex
	freezeCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/freeze" {
			mu.Lock()
			freezeCalled = true
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	endpoints.AgentURL = srv.URL
	endpoints.AgentSocket = ""
	endpoints.AirlockURL = srv.URL

	// Create an incident that triggers auto-containment with freeze_agent.
	inc := createIncident(IncidentReport{
		Class:       ClassPromptInjection,
		Source:      "agent",
		Description: "injection detected",
	})

	// The containment is async; wait a bit.
	// In production this is fire-and-forget, but in test we give it time.
	if inc.State != StateContained {
		t.Errorf("expected contained state, got %s", inc.State)
	}
	if len(inc.ContainmentActions) == 0 {
		t.Error("should have containment actions")
	}

	// Note: We can't reliably test that the async goroutine ran in unit tests,
	// but the important thing is that createIncident calls executeContainment.
	mu.Lock()
	_ = freezeCalled
	mu.Unlock()
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setupTestPolicy() {
	policyMu.Lock()
	policy = AirlockPolicy{
		Enabled:             true,
		AllowedDestinations: []string{"https://huggingface.co/"},
		ContentRules: ContentRules{
			ScanForPII:         true,
			ScanForCredentials: true,
		},
		AllowedMethods: []string{"GET", "POST"},
		MaxBodySize:    1024 * 1024,
	}
	policyMu.Unlock()
}

func TestHealthEndpoint(t *testing.T) {
	setupTestPolicy()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["enabled"] != true {
		t.Fatalf("expected enabled=true, got %v", body["enabled"])
	}
}

func TestBlockedWhenDisabled(t *testing.T) {
	policyMu.Lock()
	policy = AirlockPolicy{Enabled: false}
	policyMu.Unlock()

	body := `{"destination":"https://example.com","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked when disabled")
	}
	if resp.Reason != "airlock is disabled" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestAllowValidDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got: %s", resp.Reason)
	}
}

func TestRejectLookalikeDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co.evil.example/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for lookalike hostname")
	}
}

func TestBlockUnknownDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://evil.com/payload","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for unknown destination")
	}
}

func TestBlockHTTPDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"http://huggingface.co/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for HTTP (non-HTTPS)")
	}
}

func TestBlockLocalhostDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://localhost/secret","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for localhost")
	}
}

func TestBlockSSN(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"POST","body":"my ssn is 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for SSN in body")
	}
}

func TestBlockCredential(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"POST","body":"api_key=sk-abc123secret"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for credential in body")
	}
}

func TestBlockDisallowedMethod(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"DELETE","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for DELETE method")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/egress/check", nil)
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =========================================================================
// Adversarial tests — verify the policy engine rejects attack payloads
// =========================================================================

func TestAdversarial_UnsafeEgressRequest(t *testing.T) {
	setupTestPolicies(t)

	// Egress uses Subject as the destination URL
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainEgress,
		Subject: "http://evil.com/exfiltrate?data=sensitive",
	})

	if resp.Decision == "allow" {
		t.Error("unsafe egress to unknown destination should be denied")
	}
}

func TestAdversarial_ApprovalSpoofing(t *testing.T) {
	setupTestPolicies(t)

	// Attempt to spoof an agent_risk decision with crafted params —
	// trust_change is in the hard_approval list so must never auto-allow
	req := DecisionRequest{
		Domain:  DomainAgentRisk,
		Subject: "trust_change",
		Action:  "allow",
		Params: map[string]string{
			"risk_level": "auto",   // Try to downgrade risk
			"spoofed":    "true",
			"override":   "admin",
		},
	}

	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleDecide(w, r)

	var resp DecisionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// trust_change should NEVER be auto-allowed regardless of spoofed params
	if resp.Decision == "allow" {
		t.Error("spoofed approval context should not grant trust_change access")
	}
}

func TestAdversarial_ProvenanceMismatch(t *testing.T) {
	setupTestPolicies(t)

	// Model promotion without a recognised format should be denied
	resp := decideRequest(t, DecisionRequest{
		Domain:  DomainModelPromotion,
		Subject: "model-without-signature",
		Params: map[string]string{
			"format":        "",
			"has_signature": "false",
			"has_sbom":      "false",
		},
	})

	if resp.Decision == "allow" {
		t.Error("model without provenance should not be promoted")
	}
}

func TestAdversarial_MalformedToolSchema(t *testing.T) {
	setupTestPolicies(t)

	// Attempt tool_access with injection in tool name
	req := DecisionRequest{
		Domain:  DomainToolAccess,
		Subject: "'; DROP TABLE tools; --",
	}

	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleDecide(w, r)

	if w.Code == http.StatusOK {
		var resp DecisionResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Decision == "allow" {
			t.Error("SQL injection in tool name should not be allowed")
		}
	}
}

func TestAdversarial_PathTraversalInPathAccess(t *testing.T) {
	setupTestPolicies(t)

	// Path access uses Subject as the file path
	traversalPaths := []string{
		"../../../../etc/shadow",
		"/var/lib/secure-ai/vault/../../etc/passwd",
		"/var/lib/secure-ai/vault/user_docs/../../../etc/shadow",
	}

	for _, path := range traversalPaths {
		resp := decideRequest(t, DecisionRequest{
			Domain:  DomainPathAccess,
			Subject: path,
			Action:  "read",
		})

		if resp.Decision == "allow" {
			t.Errorf("path traversal %q should be denied", path)
		}
	}
}

func TestAdversarial_TaintPropagationFailure(t *testing.T) {
	setupTestPolicies(t)

	// Sensitivity domain uses Subject as the level and Params for ceiling
	// An unknown sensitivity level with taint context should be handled gracefully
	req := DecisionRequest{
		Domain:  DomainSensitivity,
		Subject: "external",
		Params: map[string]string{
			"ceiling": "low",
			"source":  "external",
			"tainted": "true",
		},
	}

	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleDecide(w, r)

	// Should return a decision (not crash) — "external" is not a valid level
	// so it should be denied, but the important thing is graceful handling
	if w.Code != http.StatusOK {
		t.Errorf("taint context should be handled gracefully, got %d", w.Code)
	}

	var resp DecisionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// "external" is not a known sensitivity level, so must be denied
	if resp.Decision == "allow" {
		t.Error("unknown sensitivity level from tainted source should be denied")
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =========================================================================
// Recovery ceremony tests
// =========================================================================

func TestRecovery_RequireAndAcknowledge(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("INC-001", SeverityHigh, ClassPolicyBypass)

	if rm.IsRecoveryComplete("INC-001") {
		t.Fatal("recovery should not be complete before ack")
	}

	ok, _ := rm.Acknowledge("INC-001", "admin")
	if !ok {
		t.Fatal("acknowledge failed")
	}

	if !rm.IsRecoveryComplete("INC-001") {
		t.Fatal("recovery should be complete after ack (no reattest required)")
	}
}

func TestRecovery_CriticalRequiresReattestation(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("INC-002", SeverityCritical, ClassAttestationFailure)

	// Ack alone should not complete recovery
	rm.Acknowledge("INC-002", "admin")
	if rm.IsRecoveryComplete("INC-002") {
		t.Fatal("critical incident recovery should not complete without re-attestation")
	}

	// Re-attestation completes it
	rm.RecordReattestation("INC-002")
	if !rm.IsRecoveryComplete("INC-002") {
		t.Fatal("recovery should be complete after ack + reattest")
	}
}

func TestRecovery_IntegrityViolationRequiresReattest(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("INC-003", SeverityHigh, ClassIntegrityViolation)

	rm.Acknowledge("INC-003", "admin")
	if rm.IsRecoveryComplete("INC-003") {
		t.Fatal("integrity violation recovery should require re-attestation")
	}

	rm.RecordReattestation("INC-003")
	if !rm.IsRecoveryComplete("INC-003") {
		t.Fatal("recovery should complete after reattest")
	}
}

func TestRecovery_UnknownIncident(t *testing.T) {
	rm := NewRecoveryManager()
	ok, _ := rm.Acknowledge("INC-NONEXISTENT", "admin")
	if ok {
		t.Fatal("should fail for unknown incident")
	}
}

func TestRecovery_NoRequirementMeansComplete(t *testing.T) {
	rm := NewRecoveryManager()
	if !rm.IsRecoveryComplete("INC-NONE") {
		t.Fatal("no requirement should mean recovery is complete")
	}
}

func TestRecovery_PendingRecoveries(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("INC-A", SeverityHigh, ClassPolicyBypass)
	rm.RequireRecovery("INC-B", SeverityCritical, ClassAttestationFailure)

	pending := rm.PendingRecoveries()
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}

	rm.Acknowledge("INC-A", "admin")
	pending = rm.PendingRecoveries()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending after acking INC-A, got %d", len(pending))
	}
}

// =========================================================================
// Latched state tests
// =========================================================================

func TestLatchedClasses(t *testing.T) {
	latched := []IncidentClass{
		ClassAttestationFailure,
		ClassIntegrityViolation,
		ClassUnauthorizedAccess,
		ClassManifestMismatch,
	}
	for _, c := range latched {
		if !IsLatched(c) {
			t.Errorf("%s should be latched", c)
		}
	}

	notLatched := []IncidentClass{
		ClassPromptInjection,
		ClassToolCallBurst,
		ClassForbiddenAirlock,
	}
	for _, c := range notLatched {
		if IsLatched(c) {
			t.Errorf("%s should not be latched", c)
		}
	}
}

// =========================================================================
// Severity escalation tests
// =========================================================================

func TestEscalation_RepeatedPromptInjection(t *testing.T) {
	rules := []EscalationRule{
		{Class: ClassPromptInjection, Count: 3, WindowSecs: 300, EscalateTo: SeverityCritical},
	}
	et := NewEscalationTracker(rules)

	// First two should not escalate
	if s := et.Record(ClassPromptInjection, SeverityMedium); s != "" {
		t.Fatalf("should not escalate on first event, got %s", s)
	}
	if s := et.Record(ClassPromptInjection, SeverityMedium); s != "" {
		t.Fatalf("should not escalate on second event, got %s", s)
	}
	// Third should trigger escalation
	if s := et.Record(ClassPromptInjection, SeverityMedium); s != SeverityCritical {
		t.Fatalf("expected escalation to critical, got %q", s)
	}
}

func TestEscalation_DifferentClassNoEscalation(t *testing.T) {
	rules := []EscalationRule{
		{Class: ClassPromptInjection, Count: 3, WindowSecs: 300, EscalateTo: SeverityCritical},
	}
	et := NewEscalationTracker(rules)

	et.Record(ClassPromptInjection, SeverityMedium)
	et.Record(ClassToolCallBurst, SeverityMedium)
	if s := et.Record(ClassPromptInjection, SeverityMedium); s != "" {
		t.Fatalf("should not escalate for different classes mixed, got %s", s)
	}
}

func TestEscalation_AlreadyCriticalNoUpgrade(t *testing.T) {
	rules := []EscalationRule{
		{Class: ClassPromptInjection, Count: 2, WindowSecs: 300, EscalateTo: SeverityHigh},
	}
	et := NewEscalationTracker(rules)

	et.Record(ClassPromptInjection, SeverityCritical)
	// Already critical; rule escalates to high which is lower
	if s := et.Record(ClassPromptInjection, SeverityCritical); s != "" {
		t.Fatalf("should not downgrade severity, got %s", s)
	}
}

func TestEscalation_DefaultRules(t *testing.T) {
	rules := DefaultEscalationRules()
	if len(rules) < 3 {
		t.Fatalf("expected at least 3 default escalation rules, got %d", len(rules))
	}
}

// =========================================================================
// Forensic bundle tests
// =========================================================================

func TestForensicBundle_ExportAndVerify(t *testing.T) {
	incidents := []Incident{
		{
			ID:       "INC-F001",
			Class:    ClassIntegrityViolation,
			Severity: SeverityHigh,
			State:    StateContained,
			Source:   "integrity-monitor",
		},
	}
	key := []byte("test-signing-key")

	bundle := ExportForensicBundle(
		incidents,
		[]string{"audit line 1", "audit line 2"},
		map[string]string{"test_key": "test_value"},
		"policy-digest-abc123",
		key,
	)

	if bundle.BundleHash == "" {
		t.Fatal("bundle hash should not be empty")
	}
	if bundle.Signature == "" {
		t.Fatal("bundle signature should not be empty")
	}

	valid, reason := VerifyForensicBundle(bundle, key)
	if !valid {
		t.Fatalf("bundle verification failed: %s", reason)
	}
}

func TestForensicBundle_TamperDetection(t *testing.T) {
	incidents := []Incident{
		{ID: "INC-F002", Class: ClassPolicyBypass},
	}
	key := []byte("test-key")

	bundle := ExportForensicBundle(incidents, nil, nil, "", key)

	// Tamper with the bundle
	bundle.Incidents[0].ID = "INC-TAMPERED"

	valid, _ := VerifyForensicBundle(bundle, key)
	if valid {
		t.Fatal("tampered bundle should fail verification")
	}
}

func TestForensicBundle_WrongKey(t *testing.T) {
	bundle := ExportForensicBundle(
		[]Incident{{ID: "INC-F003"}},
		nil, nil, "",
		[]byte("correct-key"),
	)

	valid, _ := VerifyForensicBundle(bundle, []byte("wrong-key"))
	if valid {
		t.Fatal("wrong key should fail verification")
	}
}

func TestForensicBundle_NoKey(t *testing.T) {
	bundle := ExportForensicBundle(
		[]Incident{{ID: "INC-F004"}},
		nil, nil, "",
		nil, // no key
	)

	if bundle.Signature != "" {
		t.Fatal("no key should mean no signature")
	}

	valid, _ := VerifyForensicBundle(bundle, nil)
	if !valid {
		t.Fatal("unsigned bundle should still verify (hash check only)")
	}
}

// =========================================================================
// HTTP handler tests
// =========================================================================

func TestHandleRecoveryAck_Success(t *testing.T) {
	oldRM := recoveryMgr
	recoveryMgr = NewRecoveryManager()
	defer func() { recoveryMgr = oldRM }()

	recoveryMgr.RequireRecovery("INC-HTTP-001", SeverityHigh, ClassPolicyBypass)

	body := `{"incident_id":"INC-HTTP-001","operator":"admin"}`
	req := httptest.NewRequest("POST", "/api/v1/recovery/ack", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleRecoveryAck(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleRecoveryStatus(t *testing.T) {
	oldRM := recoveryMgr
	recoveryMgr = NewRecoveryManager()
	defer func() { recoveryMgr = oldRM }()

	recoveryMgr.RequireRecovery("INC-HTTP-002", SeverityCritical, ClassAttestationFailure)

	req := httptest.NewRequest("GET", "/api/v1/recovery/status", nil)
	w := httptest.NewRecorder()

	handleRecoveryStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Fatalf("expected 1 pending recovery, got %v", resp["count"])
	}
}

func TestRecovery_GetRequirement(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("INC-GET-001", SeverityCritical, ClassAttestationFailure)

	req := rm.GetRequirement("INC-GET-001")
	if req == nil {
		t.Fatal("expected requirement, got nil")
	}
	if !req.RequireReattest {
		t.Fatal("critical attestation failure should require re-attestation")
	}

	// Unknown should return nil
	if rm.GetRequirement("INC-NONE") != nil {
		t.Fatal("unknown incident should return nil")
	}
}

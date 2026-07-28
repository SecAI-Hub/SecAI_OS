package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// =========================================================================
// Recovery ceremony tests
// =========================================================================

func validRecoveryAttestation(t *testing.T, rm *RecoveryManager, incidentID string) RecoveryAttestationEvidence {
	t.Helper()
	requirement := rm.GetRequirement(incidentID)
	if requirement == nil {
		t.Fatalf("recovery requirement %q does not exist", incidentID)
	}
	requiredAfter, err := time.Parse(time.RFC3339Nano, requirement.RequiredAfter)
	if err != nil {
		t.Fatalf("parse recovery freshness boundary: %v", err)
	}
	attestedAt := requiredAfter.Add(time.Nanosecond)
	return RecoveryAttestationEvidence{
		RequestedAt:             requiredAfter.Format(time.RFC3339Nano),
		Timestamp:               attestedAt.Format(time.RFC3339Nano),
		State:                   "attested",
		AssuranceMode:           "hardware",
		EvidenceVerified:        true,
		SecureBootEnabled:       true,
		TPMAvailable:            true,
		TPMMeasurementsVerified: true,
		TPMQuoteVerified:        true,
		DeploymentVerified:      true,
		ReleaseBaselineVerified: true,
		DeploymentDigest:        strings.Repeat("c", 64),
		PolicyDigest:            strings.Repeat("d", 64),
		TPMAKPublicKeySHA256:    strings.Repeat("a", 64),
		BundleHMAC:              strings.Repeat("b", 64),
		BundleHMACVerified:      true,
		RequestNonce:            strings.Repeat("e", 64),
	}
}

func completeRecoveryCeremony(t *testing.T, rm *RecoveryManager, incidentID string) {
	t.Helper()
	ok, msg := rm.Acknowledge(incidentID, "test-operator")
	if !ok {
		t.Fatalf("acknowledge recovery ceremony for %q: %s", incidentID, msg)
	}
	requirement := rm.GetRequirement(incidentID)
	if requirement == nil {
		t.Fatalf("recovery requirement %q does not exist", incidentID)
	}
	if requirement.RequireReattest {
		ok, msg = rm.RecordVerifiedAttestation(
			incidentID,
			validRecoveryAttestation(t, rm, incidentID),
		)
		if !ok {
			t.Fatalf("re-attest recovery ceremony for %q: %s", incidentID, msg)
		}
	}
	if !rm.IsRecoveryComplete(incidentID) {
		t.Fatalf("recovery ceremony for %q is incomplete", incidentID)
	}
}

func TestCrossServiceBundleHMACGoldenVectorAndTamperRejection(t *testing.T) {
	runtimeAttestationHMACKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	bundle := runtimeAttestationResponse{
		Timestamp:        "2026-07-27T12:34:56.123456789Z",
		State:            "attested",
		AssuranceMode:    "hardware",
		EvidenceVerified: true,
		RequestNonce:     strings.Repeat("11", 32),
		BootMeasurements: runtimeBootMeasurements{
			SecureBootEnabled: true,
			PCRValues: map[string]string{
				"0": "0x" + strings.Repeat("22", 32),
				"7": "0x" + strings.Repeat("23", 32),
			},
			MeasuredAt: "2026-07-27T12:34:55.999999999Z",
		},
		DeploymentDigest:        "sha256:" + strings.Repeat("33", 32),
		DeploymentVerified:      true,
		ReleaseSourceCommit:     strings.Repeat("44", 20),
		ReleaseBaselineVerified: true,
		ServiceDigests: map[string]string{
			"registry":      strings.Repeat("55", 32),
			"tool-firewall": strings.Repeat("56", 32),
		},
		PolicyDigest:            strings.Repeat("66", 32),
		RegistryManifestHash:    strings.Repeat("77", 32),
		KernelCmdline:           "quiet lockdown=confidentiality",
		KernelLockdown:          "[confidentiality] integrity",
		TPMAvailable:            true,
		TPMMeasurementsVerified: true,
		TPMQuoteVerified:        true,
		TPMAKPublicKeySHA256:    strings.Repeat("88", 32),
		TPMQuotePCRSelection:    "sha256:0,2,4,7",
		Failures:                []string{"golden-vector"},
		BundleHMAC:              "2f79b51e951ec69d0de69a6a36893b9c3802734517942b465f782e643865fff5",
	}
	if err := verifyRuntimeAttestationHMAC(bundle); err != nil {
		t.Fatalf("runtime-attestor golden bundle did not verify: %v", err)
	}
	bundle.PolicyDigest = strings.Repeat("99", 32)
	if err := verifyRuntimeAttestationHMAC(bundle); err == nil {
		t.Fatal("tampered runtime-attestor bundle passed HMAC verification")
	}
}

func TestFreshRuntimeAttestationBindsRequestNonceAndVerifiesHMAC(t *testing.T) {
	runtimeAttestorToken = strings.Repeat("a", 64)
	runtimeAttestationHMACKey = []byte(strings.Repeat("k", 32))
	var wrongNonce atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("Authorization") != "Bearer "+runtimeAttestorToken {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		var refresh struct {
			RequestNonce string `json:"request_nonce"`
		}
		if err := json.NewDecoder(request.Body).Decode(&refresh); err != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		if wrongNonce.Load() {
			refresh.RequestNonce = strings.Repeat("f", 64)
		}
		bundle := runtimeAttestationResponse{
			Timestamp:               time.Now().UTC().Format(time.RFC3339Nano),
			State:                   "attested",
			AssuranceMode:           "hardware",
			EvidenceVerified:        true,
			RequestNonce:            refresh.RequestNonce,
			BootMeasurements:        runtimeBootMeasurements{SecureBootEnabled: true},
			DeploymentDigest:        "sha256:" + strings.Repeat("b", 64),
			DeploymentVerified:      true,
			ReleaseSourceCommit:     strings.Repeat("c", 40),
			ReleaseBaselineVerified: true,
			ServiceDigests:          map[string]string{},
			PolicyDigest:            strings.Repeat("d", 64),
			RegistryManifestHash:    strings.Repeat("e", 64),
			TPMAvailable:            true,
			TPMMeasurementsVerified: true,
			TPMQuoteVerified:        true,
			TPMAKPublicKeySHA256:    strings.Repeat("1", 64),
			TPMQuotePCRSelection:    "sha256:0,2,4,7",
		}
		payload, err := canonicalRuntimeAttestationJSON(bundle)
		if err != nil {
			http.Error(response, "internal", http.StatusInternalServerError)
			return
		}
		mac := hmac.New(sha256.New, runtimeAttestationHMACKey)
		_, _ = mac.Write(payload)
		bundle.BundleHMAC = hex.EncodeToString(mac.Sum(nil))
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(bundle)
	}))
	defer server.Close()
	t.Setenv("RUNTIME_ATTESTOR_URL", server.URL)

	evidence, err := requestFreshRuntimeAttestation(context.Background())
	if err != nil {
		t.Fatalf("fresh nonce-bound attestation failed: %v", err)
	}
	if !evidence.BundleHMACVerified ||
		!canonicalSHA256String(evidence.RequestNonce) {
		t.Fatalf("fresh attestation was not cryptographically bound: %+v", evidence)
	}

	wrongNonce.Store(true)
	if _, err := requestFreshRuntimeAttestation(context.Background()); err == nil {
		t.Fatal("validly signed response with the wrong request nonce was accepted")
	}
}

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
	ok, msg := rm.RecordVerifiedAttestation(
		"INC-002",
		validRecoveryAttestation(t, rm, "INC-002"),
	)
	if !ok {
		t.Fatalf("re-attestation failed: %s", msg)
	}
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

	ok, msg := rm.RecordVerifiedAttestation(
		"INC-003",
		validRecoveryAttestation(t, rm, "INC-003"),
	)
	if !ok {
		t.Fatalf("re-attestation failed: %s", msg)
	}
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
	key := []byte("0123456789abcdef0123456789abcdef")

	bundle, err := ExportForensicBundle(
		incidents,
		[]string{"audit line 1", "audit line 2"},
		map[string]string{"test_key": "test_value"},
		"policy-digest-abc123",
		key,
	)
	if err != nil {
		t.Fatalf("ExportForensicBundle: %v", err)
	}

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
	key := []byte("0123456789abcdef0123456789abcdef")

	bundle, err := ExportForensicBundle(incidents, nil, nil, "", key)
	if err != nil {
		t.Fatalf("ExportForensicBundle: %v", err)
	}

	// Tamper with the bundle
	bundle.Incidents[0].ID = "INC-TAMPERED"

	valid, _ := VerifyForensicBundle(bundle, key)
	if valid {
		t.Fatal("tampered bundle should fail verification")
	}
}

func TestForensicBundle_WrongKey(t *testing.T) {
	bundle, err := ExportForensicBundle(
		[]Incident{{ID: "INC-F003"}},
		nil, nil, "",
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatalf("ExportForensicBundle: %v", err)
	}

	valid, _ := VerifyForensicBundle(bundle, []byte("abcdef0123456789abcdef0123456789"))
	if valid {
		t.Fatal("wrong key should fail verification")
	}
}

func TestForensicBundle_NoKey(t *testing.T) {
	bundle, err := ExportForensicBundle(
		[]Incident{{ID: "INC-F004"}},
		nil, nil, "",
		nil, // no key
	)
	if err == nil || bundle != nil {
		t.Fatal("forensic export must fail closed when the signing key is unavailable")
	}
}

func TestForensicBundle_CanonicalPayloadTamperDetection(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	bundle, err := ExportForensicBundle(
		[]Incident{{ID: "INC-F005"}},
		[]string{`{"event":"test"}`},
		map[string]string{"service": "incident-recorder"},
		"digest",
		key,
	)
	if err != nil {
		t.Fatalf("ExportForensicBundle: %v", err)
	}

	bundle.SystemState["service"] = "tampered"
	valid, reason := VerifyForensicBundle(bundle, key)
	if valid || reason != "canonical payload does not match exposed bundle fields" {
		t.Fatalf("outer-field tampering must fail canonical comparison: valid=%v reason=%q", valid, reason)
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

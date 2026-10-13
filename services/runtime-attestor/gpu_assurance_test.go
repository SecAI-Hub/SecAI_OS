package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

func testGPUScope(scope string, now time.Time) GPUScopeOutcome {
	return GPUScopeOutcome{Scope: scope, Status: "verified", Authenticated: true, Verified: true,
		ProfileSHA256: strings.Repeat("a", 64), RequiredProbes: map[string]evidence.ProbeType{"ecc": evidence.ProbeECCStatus},
		MaxAgeSeconds: 90, MaxCycleSeconds: 30,
		Evidence: &evidence.Evidence{SchemaVersion: 1, Scope: scope, RequestNonce: strings.Repeat("b", 64),
			ProducerInstance: strings.Repeat("c", 64), LatestSequence: 1, Availability: "complete", Reason: "completed_cycle",
			Snapshot: &evidence.Snapshot{Sequence: 1, StartedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
				CompletedAt: now.Format(time.RFC3339Nano), ProfileSHA256: strings.Repeat("a", 64), BaselineState: "not_required",
				Verdict: evidence.VerdictHealthy, Probes: []evidence.Probe{{ID: "ecc", Type: evidence.ProbeECCStatus,
					Status: evidence.StatusPass, Reason: "probe_pass"}}}}}
}

func TestGPUFullScopeNeverInheritsBootstrapTrust(t *testing.T) {
	now := time.Now().UTC()
	gpu := GPUAssurance{Mode: "required", Bootstrap: testGPUScope("bootstrap", now),
		Runtime: GPUScopeOutcome{Scope: "runtime", Status: "unavailable"}}
	if !scopeCurrent(gpu.Bootstrap, now) || gpuScopesCurrent(gpu, now) {
		t.Fatal("bootstrap evidence was confused with full runtime trust")
	}
	gpu.Runtime = testGPUScope("runtime", now)
	if !gpuScopesCurrent(gpu, now) || gpuScopesCurrent(gpu, now.Add(91*time.Second)) {
		t.Fatal("full runtime evidence did not expire at the probe-cycle boundary")
	}
	gpu.Runtime.Evidence.Snapshot.CompletedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if gpuScopesCurrent(gpu, now) {
		t.Fatal("future runtime cycle accepted")
	}
}

func TestGPUExplicitModesAndNoDowngrade(t *testing.T) {
	for _, mode := range []string{"", "auto", "absent", "cpu"} {
		if validateGPUTrustPolicy(GPUTrustPolicy{Mode: mode}) == nil {
			t.Fatalf("inferred mode %q accepted", mode)
		}
	}
	if validateGPUTrustPolicy(GPUTrustPolicy{Mode: "no_gpu"}) != nil {
		t.Fatal("explicit CPU enrollment rejected")
	}
	if validateGPUTrustPolicy(GPUTrustPolicy{Mode: "no_gpu", Runtime: &GPUScopePolicy{}}) == nil {
		t.Fatal("CPU policy accepted a GPU scope")
	}
	gpu := collectGPUAssurance(GPUTrustPolicy{Mode: "no_gpu"}, strings.Repeat("a", 64))
	if !gpu.PolicySatisfied || gpu.Runtime.Verified || gpu.Runtime.Authenticated {
		t.Fatal("CPU enrollment made a GPU assurance claim")
	}
	gpu.Runtime.ProfileSHA256 = strings.Repeat("a", 64)
	if gpuScopesCurrent(gpu, time.Now()) {
		t.Fatal("inconsistent not-applicable scope accepted")
	}
}

func TestGPUScopeDedicatedNativeOrigins(t *testing.T) {
	for _, tc := range []struct {
		bootstrap string
		runtime   string
		accepted  bool
	}{
		{"http://127.0.0.1:8492", "http://127.0.0.1:8495", true},
		{"http://127.0.0.1:8496", "http://127.0.0.1:8495", false}, // MCP firewall
		{"http://127.0.0.1:8495", "http://127.0.0.1:8492", false}, // crossed scopes
		{"http://127.0.0.1:8492", "http://127.0.0.1:8497", false}, // probe adapter
	} {
		makeScope := func(origin string) *GPUScopePolicy {
			return &GPUScopePolicy{Origin: origin, MaxAge: "90s", MaxCycleDuration: "30s",
				RequiredProbes: map[string]evidence.ProbeType{"ecc": evidence.ProbeECCStatus}}
		}
		policy := GPUTrustPolicy{Mode: "required", Bootstrap: makeScope(tc.bootstrap), Runtime: makeScope(tc.runtime)}
		if (validateGPUTrustPolicy(policy) == nil) != tc.accepted {
			t.Fatalf("unexpected endpoint policy result for bootstrap=%s runtime=%s", tc.bootstrap, tc.runtime)
		}
	}
}

func TestExpiredCPUOnlyBundleCannotRetainVerificationFlags(t *testing.T) {
	resetGlobalState(t)
	bundle := RuntimeStateBundle{SchemaVersion: 2, State: StateAttested, AssuranceMode: "hardware",
		EvidenceVerified: true, Timestamp: time.Now().Add(-11 * time.Minute).UTC().Format(time.RFC3339Nano),
		BundleHMAC: strings.Repeat("a", 64), GPU: collectGPUAssurance(GPUTrustPolicy{Mode: "no_gpu"}, strings.Repeat("b", 64))}
	w := httptest.NewRecorder()
	writeVerification(w, httptest.NewRequest("GET", "/api/v1/verify", nil), bundle, "runtime")
	var response map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 503 || response["verified"] != false || response["evidence_verified"] != false || response["policy_satisfied"] != false {
		t.Fatal("expired CPU-only evidence retained a positive verification flag")
	}
}

func TestGPUSequenceRollbackEquivocationAndRetiredInstance(t *testing.T) {
	resetGlobalState(t)
	reply := *testGPUScope("runtime", time.Now().UTC()).Evidence
	if acceptGPUSequence("runtime", reply) != nil || acceptGPUSequence("runtime", reply) != nil {
		t.Fatal("identical fresh cycle rejected")
	}
	reply.LatestSequence = 0
	if acceptGPUSequence("runtime", reply) == nil {
		t.Fatal("sequence rollback accepted")
	}
	reply.LatestSequence = 1
	reply.Snapshot.CompositeScore = 0.1
	if acceptGPUSequence("runtime", reply) == nil {
		t.Fatal("same sequence changed its cycle")
	}
	reply.Snapshot.CompositeScore = 0
	old := reply
	reply.ProducerInstance = strings.Repeat("d", 64)
	if acceptGPUSequence("runtime", reply) != nil {
		t.Fatal("new producer instance rejected")
	}
	if acceptGPUSequence("runtime", old) == nil {
		t.Fatal("retired producer replay accepted")
	}
}

func TestGPUAuthenticatedLifecycleBootstrapThenRuntime(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte(strings.Repeat("h", 32))
	gpuScopeKeys = map[string][]byte{"bootstrap": []byte(strings.Repeat("b", 32)), "runtime": []byte(strings.Repeat("r", 32))}
	var ready atomic.Bool
	var bootstrapSequence atomic.Uint64
	var runtimeSequence atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		challenge, err := evidence.DecodeChallenge(raw)
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		key := gpuScopeKeys[challenge.Scope]
		mac, _ := evidence.RequestMAC(key, challenge)
		if mac != challenge.RequestMAC {
			t.Error("challenge MAC mismatch")
			http.Error(w, "invalid", 401)
			return
		}
		reply := *testGPUScope(challenge.Scope, time.Now().UTC()).Evidence
		reply.RequestNonce = challenge.RequestNonce
		sequence := bootstrapSequence.Add(1)
		if challenge.Scope == "runtime" {
			sequence = runtimeSequence.Add(1)
		}
		reply.LatestSequence, reply.Snapshot.Sequence = sequence, sequence
		if challenge.Scope == "runtime" && !ready.Load() {
			reply.Availability, reply.Reason, reply.LatestSequence, reply.Snapshot = "unavailable", "no_completed_cycle", 0, nil
		}
		reply.ResponseMAC, _ = evidence.ResponseMAC(key, reply)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer server.Close()
	original := fetchGPUScopeEvidence
	fetchGPUScopeEvidence = func(ctx context.Context, _origin, scope, nonce string, key []byte) (evidence.Evidence, error) {
		return evidence.Fetch(ctx, server.URL, scope, nonce, key)
	}
	t.Cleanup(func() { fetchGPUScopeEvidence = original })
	yaml := strings.Replace(testAttestPolicyYAML, "gpu: {mode: no_gpu}", fmt.Sprintf(`gpu:
  mode: required
  bootstrap:
    origin: http://127.0.0.1:8492
    profile_sha256: "%s"
    required_probes: {ecc: ecc_status}
    max_age: 90s
    max_cycle_duration: 30s
  runtime:
    origin: http://127.0.0.1:8495
    profile_sha256: "%s"
    required_probes: {ecc: ecc_status}
    max_age: 90s
    max_cycle_duration: 30s`, strings.Repeat("a", 64), strings.Repeat("a", 64)), 1)
	t.Setenv("ATTESTATION_POLICY_PATH", writeTempAttestPolicy(t, yaml))
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	installTestTrustInputs(t)
	bundle := performAttestation()
	if bundle.BootstrapState != StateAttested || !bundle.BootstrapPolicySatisfied || bundle.State != StatePending || bundle.EvidenceVerified {
		t.Fatalf("bootstrap was not scoped separately: %+v", bundle)
	}
	for scope, expected := range map[string]int{"bootstrap": 200, "runtime": 503} {
		w := httptest.NewRecorder()
		writeVerification(w, httptest.NewRequest("GET", "/api/v1/verify", nil), bundle, scope)
		if w.Code != expected {
			t.Fatalf("%s gate got %d", scope, w.Code)
		}
	}
	ready.Store(true)
	// The fixture publishes newly completed cycles under increasing sequences.
	bundle = performAttestation()
	if bundle.State != StateAttested || !bundle.GPU.PolicySatisfied || bundle.EvidenceVerified {
		t.Fatal("evaluation runtime scope did not pass honestly")
	}
	w := httptest.NewRecorder()
	writeVerification(w, httptest.NewRequest("GET", "/api/v1/verify", nil), bundle, "runtime")
	if w.Code != 200 {
		t.Fatal("healthy authenticated runtime gate failed")
	}
	bundle.GPU.Runtime.Evidence.Snapshot.StartedAt = time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	w = httptest.NewRecorder()
	writeVerification(w, httptest.NewRequest("GET", "/api/v1/verify", nil), bundle, "runtime")
	if w.Code != 503 {
		t.Fatal("cached attested state hid expired GPU evidence")
	}
}

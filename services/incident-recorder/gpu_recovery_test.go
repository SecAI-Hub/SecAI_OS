package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

func noGPURecoveryAssurance() GPUAssurance {
	return GPUAssurance{Mode: "no_gpu", PolicySatisfied: true,
		Bootstrap: GPUScopeOutcome{Scope: "bootstrap", Status: "not_applicable"},
		Runtime:   GPUScopeOutcome{Scope: "runtime", Status: "not_applicable"}}
}

func TestCPUOnlyRecoveryEvidenceExpires(t *testing.T) {
	now := time.Now().UTC()
	req := &RecoveryRequirement{RequiredAfter: now.Add(-12 * time.Minute).Format(time.RFC3339Nano)}
	rm := NewRecoveryManager()
	rm.RequireRecovery("CPU-EXPIRY", SeverityCritical, ClassAttestationFailure)
	proof := validRecoveryAttestation(t, rm, "CPU-EXPIRY")
	proof.RequestedAt = now.Add(-11 * time.Minute).Format(time.RFC3339Nano)
	proof.Timestamp = now.Add(-11*time.Minute + time.Second).Format(time.RFC3339Nano)
	if err := validateRecoveryEvidence(req, proof); err == nil {
		t.Fatal("expired CPU-only hardware evidence accepted without a GPU cycle age")
	}
}

func healthyRecoveryGPU(nonce string, start, end time.Time) GPUAssurance {
	scope := func(name string) GPUScopeOutcome {
		profile := strings.Repeat("a", 64)
		return GPUScopeOutcome{Scope: name, Status: "verified", Authenticated: true, Verified: true,
			ProfileSHA256: profile, RequiredProbes: map[string]evidence.ProbeType{"ecc": evidence.ProbeECCStatus},
			MaxAgeSeconds: 60, MaxCycleSeconds: 10,
			Evidence: &evidence.Evidence{SchemaVersion: 1, Scope: name, RequestNonce: nonce,
				ProducerInstance: strings.Repeat("c", 64), LatestSequence: 1, Availability: "complete", Reason: "completed_cycle", ResponseMAC: strings.Repeat("d", 64),
				Snapshot: &evidence.Snapshot{Sequence: 1, StartedAt: start.UTC().Format(time.RFC3339Nano), CompletedAt: end.UTC().Format(time.RFC3339Nano), ProfileSHA256: profile, BaselineState: "not_required", Verdict: evidence.VerdictHealthy,
					Probes: []evidence.Probe{{ID: "ecc", Type: evidence.ProbeECCStatus, Status: evidence.StatusPass, Reason: "probe_pass"}}}}}
	}
	return GPUAssurance{Mode: "required", PolicySatisfied: true, Bootstrap: scope("bootstrap"), Runtime: scope("runtime")}
}

func TestGPURecoveryRequiresCurrentFullAssurance(t *testing.T) {
	now := time.Now().UTC()
	rm := NewRecoveryManager()
	rm.RequireRecovery("GPU-RECOVERY", SeverityCritical, ClassAttestationFailure)
	req := rm.GetRequirement("GPU-RECOVERY")
	boundary, _ := time.Parse(time.RFC3339Nano, req.RequiredAfter)
	good := validRecoveryAttestation(t, rm, "GPU-RECOVERY")
	good.GPU = healthyRecoveryGPU(good.RequestNonce, boundary.Add(time.Nanosecond), boundary.Add(2*time.Nanosecond))
	cases := map[string]func(*RecoveryAttestationEvidence){
		"old schema":               func(e *RecoveryAttestationEvidence) { e.SchemaVersion = 1 },
		"missing GPU":              func(e *RecoveryAttestationEvidence) { e.GPU = GPUAssurance{} },
		"bootstrap summary false":  func(e *RecoveryAttestationEvidence) { e.BootstrapPolicySatisfied = false },
		"full summary false":       func(e *RecoveryAttestationEvidence) { e.GPU.PolicySatisfied = false },
		"runtime nonce mismatch":   func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.Evidence.RequestNonce = strings.Repeat("0", 64) },
		"bootstrap nonce mismatch": func(e *RecoveryAttestationEvidence) { e.GPU.Bootstrap.Evidence.RequestNonce = strings.Repeat("0", 64) },
		"scope mismatch":           func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.Evidence.Scope = "bootstrap" },
		"outcome scope mismatch":   func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.Scope = "bootstrap" },
		"missing authentication":   func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.Authenticated = false },
		"profile mismatch":         func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.ProfileSHA256 = strings.Repeat("0", 64) },
		"baseline missing": func(e *RecoveryAttestationEvidence) {
			e.GPU.Runtime.RequiredProbes["ecc"] = evidence.ProbeDriverFingerprint
		},
		"overflow duration": func(e *RecoveryAttestationEvidence) { e.GPU.Runtime.MaxAgeSeconds = 1 << 62 },
		"stale cycle": func(e *RecoveryAttestationEvidence) {
			e.GPU = healthyRecoveryGPU(e.RequestNonce, now.Add(-2*time.Minute), now.Add(-2*time.Minute))
		},
		"future cycle": func(e *RecoveryAttestationEvidence) {
			e.GPU = healthyRecoveryGPU(e.RequestNonce, now.Add(time.Minute), now.Add(time.Minute))
		},
		"preincident cycle": func(e *RecoveryAttestationEvidence) {
			e.GPU = healthyRecoveryGPU(e.RequestNonce, boundary.Add(-time.Second), boundary.Add(-time.Nanosecond))
		},
		"cycle straddles containment": func(e *RecoveryAttestationEvidence) {
			e.GPU = healthyRecoveryGPU(e.RequestNonce, boundary.Add(-time.Second), boundary.Add(time.Nanosecond))
		},
		"cycle starts at containment": func(e *RecoveryAttestationEvidence) {
			e.GPU = healthyRecoveryGPU(e.RequestNonce, boundary, boundary.Add(time.Nanosecond))
		},
		"optional unhealthy": func(e *RecoveryAttestationEvidence) { e.GPU.Mode = "optional"; e.GPU.Runtime.Verified = false },
	}
	if err := validateRecoveryEvidence(req, good); err != nil {
		t.Fatalf("healthy GPU recovery rejected: %v", err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := good
			bad.GPU = cloneGPUAssurance(good.GPU)
			mutate(&bad)
			if err := validateRecoveryEvidence(req, bad); err == nil {
				t.Fatal("invalid GPU recovery accepted")
			}
		})
	}
	good.GPU.Mode = "optional"
	if err := validateRecoveryEvidence(req, good); err != nil {
		t.Fatalf("healthy optional GPU rejected: %v", err)
	}
}

func TestGPURecoveryCPUOnlyMustBeExplicitAndEmpty(t *testing.T) {
	nonce := strings.Repeat("e", 64)
	good := noGPURecoveryAssurance()
	if err := validateRecoveryGPU(good, nonce, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*GPUAssurance){
		"profile":  func(g *GPUAssurance) { g.Runtime.ProfileSHA256 = strings.Repeat("a", 64) },
		"baseline": func(g *GPUAssurance) { g.Bootstrap.BaselineSHA256 = strings.Repeat("a", 64) },
		"probes": func(g *GPUAssurance) {
			g.Runtime.RequiredProbes = map[string]evidence.ProbeType{"ecc": evidence.ProbeECCStatus}
		},
		"authenticated": func(g *GPUAssurance) { g.Runtime.Authenticated = true },
		"verified":      func(g *GPUAssurance) { g.Bootstrap.Verified = true },
		"evidence":      func(g *GPUAssurance) { g.Runtime.Evidence = &evidence.Evidence{} },
		"bounds":        func(g *GPUAssurance) { g.Runtime.MaxAgeSeconds = 1 },
		"status":        func(g *GPUAssurance) { g.Runtime.Status = "verified" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			mutate(&bad)
			if err := validateRecoveryGPU(bad, nonce, time.Now()); err == nil {
				t.Fatal("inconsistent CPU-only assurance accepted")
			}
		})
	}
}

func TestGPURecoveryOldPersistedEvidenceCannotRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.json")
	rm := NewRecoveryManagerWithPath(path)
	rm.RequireRecovery("GPU-OLD", SeverityCritical, ClassAttestationFailure)
	completeRecoveryCeremony(t, rm, "GPU-OLD")
	rm.mu.Lock()
	rm.requirements["GPU-OLD"].AttestationEvidence.SchemaVersion = 1
	err := rm.persistLocked()
	rm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	loaded := NewRecoveryManagerWithPath(path)
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	if loaded.IsRecoveryComplete("GPU-OLD") || !loaded.GetRequirement("GPU-OLD").ContainmentLatchActive {
		t.Fatal("legacy persisted evidence released containment")
	}
}

func gpuTestRefreshBundle(nonce string) runtimeAttestationResponse {
	return runtimeAttestationResponse{SchemaVersion: 2, BootstrapState: "attested", BootstrapPolicySatisfied: true, GPU: noGPURecoveryAssurance(), Timestamp: time.Now().UTC().Format(time.RFC3339Nano), State: "attested", AssuranceMode: "hardware", EvidenceVerified: true, RequestNonce: nonce, BootMeasurements: runtimeBootMeasurements{SecureBootEnabled: true}, ServiceDigests: map[string]string{}}
}
func signGPURefreshBundle(t *testing.T, bundle runtimeAttestationResponse) []byte {
	t.Helper()
	raw, err := canonicalRuntimeAttestationJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, runtimeAttestationHMACKey)
	mac.Write(raw)
	bundle.BundleHMAC = hex.EncodeToString(mac.Sum(nil))
	raw, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGPURecoverySignedWireIsStrict(t *testing.T) {
	runtimeAttestationHMACKey = []byte(strings.Repeat("k", 32))
	raw := signGPURefreshBundle(t, gpuTestRefreshBundle(strings.Repeat("e", 64)))
	for name, bad := range map[string][]byte{
		"legacy schema":     bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":1`), 1),
		"missing gpu":       bytes.Replace(raw, []byte(`"gpu":`), []byte(`"missing_gpu":`), 1),
		"null gpu":          bytes.Replace(raw, []byte(`"gpu":{`), []byte(`"gpu":null,"unexpected":{`), 1),
		"duplicate":         bytes.Replace(raw, []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":2`), 1),
		"unicode duplicate": bytes.Replace(raw, []byte(`"scope":"bootstrap"`), []byte(`"scope":"bootstrap","ſcope":"bootstrap"`), 1),
		"case alias":        bytes.Replace(raw, []byte(`"policy_satisfied":true`), []byte(`"Policy_satisfied":true`), 1),
		"null boolean":      bytes.Replace(raw, []byte(`"policy_satisfied":true`), []byte(`"policy_satisfied":null`), 1),
		"null nested scope": bytes.Replace(raw, []byte(`"bootstrap":{`), []byte(`"bootstrap":null,"extra":{`), 1),
		"trailing":          append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRuntimeAttestationResponse(bad); err == nil {
				t.Fatal("malformed schema accepted")
			}
		})
	}
	bundle, err := decodeRuntimeAttestationResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeAttestationHMAC(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.GPU.Runtime.Authenticated = true
	if err := verifyRuntimeAttestationHMAC(bundle); err == nil {
		t.Fatal("tampered GPU field accepted")
	}
}

func TestGPURecoveryRefreshBoundsTransport(t *testing.T) {
	runtimeAttestorToken = strings.Repeat("a", 64)
	runtimeAttestationHMACKey = []byte(strings.Repeat("k", 32))
	for _, mode := range []string{"oversize", "compressed", "legacy", "missing_gpu", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "" {
					t.Error("refresh client enabled compression")
				}
				var request struct {
					RequestNonce string `json:"request_nonce"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				bundle := gpuTestRefreshBundle(request.RequestNonce)
				if mode == "legacy" {
					bundle.SchemaVersion = 1
				}
				raw := signGPURefreshBundle(t, bundle)
				switch mode {
				case "oversize":
					raw = append(raw, bytes.Repeat([]byte(" "), maxAttestationBodySize)...)
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "missing_gpu":
					raw = bytes.Replace(raw, []byte(`"gpu":`), []byte(`"missing_gpu":`), 1)
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1/")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				w.Write(raw)
			}))
			defer server.Close()
			t.Setenv("RUNTIME_ATTESTOR_URL", server.URL)
			if _, err := requestFreshRuntimeAttestation(context.Background()); err == nil {
				t.Fatal("invalid refresh response accepted")
			}
		})
	}
}

func TestGPURecoveryReadGatesRecheckFreshnessAndOwnEvidence(t *testing.T) {
	rm := NewRecoveryManager()
	rm.RequireRecovery("GPU-COPIES", SeverityCritical, ClassAttestationFailure)
	req := rm.GetRequirement("GPU-COPIES")
	boundary, _ := time.Parse(time.RFC3339Nano, req.RequiredAfter)
	good := validRecoveryAttestation(t, rm, "GPU-COPIES")
	good.GPU = healthyRecoveryGPU(good.RequestNonce, boundary.Add(time.Nanosecond), boundary.Add(2*time.Nanosecond))
	if ok, msg := rm.RecordVerifiedAttestation("GPU-COPIES", good); !ok {
		t.Fatal(msg)
	}
	if ok, msg := rm.Acknowledge("GPU-COPIES", "test-operator"); !ok {
		t.Fatal(msg)
	}
	good.GPU.Runtime.RequiredProbes["ecc"] = evidence.ProbeDriverFingerprint
	good.GPU.Runtime.Evidence.Snapshot.Probes[0].Score = 1
	copy := rm.GetRequirement("GPU-COPIES")
	copy.AttestationEvidence.GPU.Runtime.RequiredProbes["ecc"] = evidence.ProbeDriverFingerprint
	copy.AttestationEvidence.GPU.Runtime.Evidence.Snapshot.Probes[0].Score = 1
	if !rm.IsRecoveryComplete("GPU-COPIES") {
		t.Fatal("caller mutated stored GPU evidence")
	}
	rm.mu.Lock()
	snapshot := rm.requirements["GPU-COPIES"].AttestationEvidence.GPU.Runtime.Evidence.Snapshot
	snapshot.StartedAt = time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	snapshot.CompletedAt = snapshot.StartedAt
	rm.mu.Unlock()
	if rm.IsRecoveryComplete("GPU-COPIES") {
		t.Fatal("cached recovery completion accepted stale GPU evidence")
	}
	if ok, _ := rm.CanReleaseIncident(Incident{ID: "GPU-COPIES", Class: ClassAttestationFailure, Severity: SeverityCritical}); ok {
		t.Fatal("stale GPU evidence released incident")
	}
}

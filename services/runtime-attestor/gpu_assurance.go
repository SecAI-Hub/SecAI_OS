package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

// Approval is part of the release-measured attestation policy. Producer input
// hashes are observations, never enrollment authority.
type GPUTrustPolicy struct {
	Mode      string          `yaml:"mode"`
	Bootstrap *GPUScopePolicy `yaml:"bootstrap"`
	Runtime   *GPUScopePolicy `yaml:"runtime"`
}

type GPUScopePolicy struct {
	Origin           string                        `yaml:"origin"`
	ProfileSHA256    string                        `yaml:"profile_sha256"`
	BaselineSHA256   string                        `yaml:"baseline_sha256"`
	RequiredProbes   map[string]evidence.ProbeType `yaml:"required_probes"`
	MaxAge           string                        `yaml:"max_age"`
	MaxCycleDuration string                        `yaml:"max_cycle_duration"`
}

type GPUAssurance struct {
	Mode            string          `json:"mode"`
	PolicySatisfied bool            `json:"policy_satisfied"`
	Bootstrap       GPUScopeOutcome `json:"bootstrap"`
	Runtime         GPUScopeOutcome `json:"runtime"`
}

type GPUScopeOutcome struct {
	Scope           string                        `json:"scope"`
	Status          string                        `json:"status"`
	Authenticated   bool                          `json:"authenticated"`
	Verified        bool                          `json:"verified"`
	ProfileSHA256   string                        `json:"profile_sha256"`
	BaselineSHA256  string                        `json:"baseline_sha256"`
	RequiredProbes  map[string]evidence.ProbeType `json:"required_probes"`
	MaxAgeSeconds   int64                         `json:"max_age_seconds"`
	MaxCycleSeconds int64                         `json:"max_cycle_seconds"`
	Evidence        *evidence.Evidence            `json:"evidence"`
}

func (p GPUScopePolicy) consumer(scope string) evidence.Policy {
	age, _ := time.ParseDuration(p.MaxAge)
	cycle, _ := time.ParseDuration(p.MaxCycleDuration)
	return evidence.Policy{Scope: scope, ProfileSHA256: p.ProfileSHA256,
		BaselineSHA256: p.BaselineSHA256, RequiredProbes: p.RequiredProbes,
		MaxAge: age, MaxCycleDuration: cycle}
}

func validateGPUTrustPolicy(p GPUTrustPolicy) error {
	if p.Mode == "no_gpu" {
		if p.Bootstrap != nil || p.Runtime != nil {
			return fmt.Errorf("CPU-only GPU policy cannot contain GPU scopes")
		}
		return nil
	}
	if p.Mode != "required" && p.Mode != "optional" {
		return fmt.Errorf("GPU assurance mode must be explicitly enrolled")
	}
	for scope, configuration := range map[string]*GPUScopePolicy{"bootstrap": p.Bootstrap, "runtime": p.Runtime} {
		if configuration == nil {
			return fmt.Errorf("GPU %s policy is missing", scope)
		}
		// Empty pins represent an explicitly unprovisioned required scope. It
		// can report its state, but cannot pass verification or startup.
		if configuration.ProfileSHA256 != "" && !canonicalSHA256(configuration.ProfileSHA256) ||
			configuration.BaselineSHA256 != "" && !canonicalSHA256(configuration.BaselineSHA256) {
			return fmt.Errorf("GPU %s approval pin is malformed", scope)
		}
		if configuration.Origin != "http://127.0.0.1:8495" && configuration.Origin != "http://127.0.0.1:8496" {
			return fmt.Errorf("GPU %s origin must be a dedicated native endpoint", scope)
		}
		if scope == "bootstrap" && configuration.Origin != "http://127.0.0.1:8496" || scope == "runtime" && configuration.Origin != "http://127.0.0.1:8495" {
			return fmt.Errorf("GPU origins cannot cross assurance scopes")
		}
		policy := configuration.consumer(scope)
		if policy.MaxAge < time.Second || policy.MaxAge > 10*time.Minute || policy.MaxAge%time.Second != 0 ||
			policy.MaxCycleDuration < time.Second || policy.MaxCycleDuration > policy.MaxAge || policy.MaxCycleDuration%time.Second != 0 {
			return fmt.Errorf("GPU scope freshness bounds are invalid")
		}
		// Use the protocol's exact probe-policy validation even before pins
		// are enrolled. A deliberately unavailable reply cannot pass it.
		policy.ProfileSHA256 = fmt.Sprintf("%064x", 1)
		if policy.BaselineSHA256 == "" {
			policy.BaselineSHA256 = fmt.Sprintf("%064x", 2)
		}
		err := evidence.ValidatePolicy(policy)
		if err != nil {
			return fmt.Errorf("GPU %s probe policy is invalid: %v", scope, err)
		}
	}
	return nil
}

var gpuScopeKeys = map[string][]byte{}
var fetchGPUScopeEvidence = evidence.Fetch

func loadGPUScopeKeys() error {
	keys := make(map[string][]byte, 2)
	for scope, variable := range map[string]string{"bootstrap": "GPU_BOOTSTRAP_KEY_PATH", "runtime": "GPU_RUNTIME_KEY_PATH"} {
		_, key, err := readCanonicalHexCredential(os.Getenv(variable), "GPU "+scope+" evidence key")
		if err != nil {
			return err
		}
		keys[scope] = key
	}
	if string(keys["bootstrap"]) == string(keys["runtime"]) {
		return fmt.Errorf("GPU assurance scope keys must be distinct")
	}
	gpuScopeKeys = keys
	return nil
}

// Replay state survives unsuccessful checks within this process. A fresh
// nonce authenticates an exchange, not a new probe cycle.
type gpuReplayRecord struct {
	Instance  string
	Sequence  uint64
	Digest    string
	Retired   map[string]bool
	Completed time.Time
}

var gpuReplayMu sync.Mutex
var gpuReplay = map[string]gpuReplayRecord{}

func acceptGPUSequence(scope string, reply evidence.Evidence) error {
	data, err := evidence.Canonical(struct {
		Availability string
		Reason       string
		Snapshot     *evidence.Snapshot
	}{reply.Availability, reply.Reason, reply.Snapshot})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	gpuReplayMu.Lock()
	defer gpuReplayMu.Unlock()
	previous := gpuReplay[scope]
	if previous.Retired == nil {
		previous.Retired = map[string]bool{}
	}
	if previous.Instance == reply.ProducerInstance {
		if reply.LatestSequence < previous.Sequence || reply.LatestSequence == previous.Sequence && digest != previous.Digest {
			return fmt.Errorf("GPU producer cycle rollback or equivocation")
		}
	} else if previous.Instance != "" {
		if previous.Retired[reply.ProducerInstance] || len(previous.Retired) >= 64 {
			return fmt.Errorf("GPU producer instance replay or restart limit")
		}
		if reply.Snapshot != nil {
			completed, _ := time.Parse(time.RFC3339Nano, reply.Snapshot.CompletedAt)
			if completed.Before(previous.Completed) {
				return fmt.Errorf("GPU restarted producer replayed an older cycle")
			}
		}
		previous.Retired[previous.Instance] = true
	}
	previous.Instance, previous.Sequence, previous.Digest = reply.ProducerInstance, reply.LatestSequence, digest
	if reply.Snapshot != nil {
		completed, _ := time.Parse(time.RFC3339Nano, reply.Snapshot.CompletedAt)
		if completed.After(previous.Completed) {
			previous.Completed = completed
		}
	}
	gpuReplay[scope] = previous
	return nil
}

func collectGPUScope(scope, mode, nonce string, configuration *GPUScopePolicy, now time.Time) GPUScopeOutcome {
	outcome := GPUScopeOutcome{Scope: scope, Status: "unavailable"}
	if mode == "no_gpu" {
		outcome.Status = "not_applicable"
		return outcome
	}
	if configuration == nil {
		return outcome
	}
	policy := configuration.consumer(scope)
	outcome.ProfileSHA256, outcome.BaselineSHA256 = policy.ProfileSHA256, policy.BaselineSHA256
	outcome.RequiredProbes = configuration.RequiredProbes
	outcome.MaxAgeSeconds, outcome.MaxCycleSeconds = int64(policy.MaxAge/time.Second), int64(policy.MaxCycleDuration/time.Second)
	if !canonicalSHA256(configuration.ProfileSHA256) || len(gpuScopeKeys[scope]) != sha256.Size {
		return outcome
	}
	reply, err := fetchGPUScopeEvidence(context.Background(), configuration.Origin, scope, nonce, gpuScopeKeys[scope])
	if err != nil {
		return outcome
	}
	outcome.Authenticated, outcome.Evidence = true, &reply
	if err := acceptGPUSequence(scope, reply); err != nil {
		outcome.Status = "rejected"
		return outcome
	}
	if reply.Availability != "complete" {
		return outcome
	}
	if err := evidence.Validate(reply, policy, time.Now().UTC()); err != nil {
		outcome.Status = "rejected"
		return outcome
	}
	outcome.Status, outcome.Verified = "verified", true
	return outcome
}

func collectGPUAssurance(p GPUTrustPolicy, nonce string) GPUAssurance {
	gpu := GPUAssurance{Mode: p.Mode}
	gpu.Bootstrap = collectGPUScope("bootstrap", p.Mode, nonce, p.Bootstrap, time.Now().UTC())
	gpu.Runtime = collectGPUScope("runtime", p.Mode, nonce, p.Runtime, time.Now().UTC())
	gpu.PolicySatisfied = gpuScopesCurrent(gpu, time.Now().UTC())
	return gpu
}

func scopeCurrent(outcome GPUScopeOutcome, now time.Time) bool {
	if !outcome.Authenticated || !outcome.Verified || outcome.Status != "verified" || outcome.Evidence == nil {
		return false
	}
	return evidence.Validate(*outcome.Evidence, evidence.Policy{Scope: outcome.Scope,
		ProfileSHA256: outcome.ProfileSHA256, BaselineSHA256: outcome.BaselineSHA256,
		RequiredProbes: outcome.RequiredProbes, MaxAge: time.Duration(outcome.MaxAgeSeconds) * time.Second,
		MaxCycleDuration: time.Duration(outcome.MaxCycleSeconds) * time.Second}, now) == nil
}

func gpuScopesCurrent(gpu GPUAssurance, now time.Time) bool {
	if gpu.Mode == "no_gpu" {
		return gpu.Bootstrap.Scope == "bootstrap" && gpu.Runtime.Scope == "runtime" &&
			gpu.Bootstrap.Status == "not_applicable" && gpu.Runtime.Status == "not_applicable" &&
			!gpu.Bootstrap.Authenticated && !gpu.Runtime.Authenticated &&
			!gpu.Bootstrap.Verified && !gpu.Runtime.Verified &&
			gpu.Bootstrap.Evidence == nil && gpu.Runtime.Evidence == nil &&
			gpu.Bootstrap.ProfileSHA256 == "" && gpu.Runtime.ProfileSHA256 == "" &&
			gpu.Bootstrap.BaselineSHA256 == "" && gpu.Runtime.BaselineSHA256 == "" &&
			len(gpu.Bootstrap.RequiredProbes) == 0 && len(gpu.Runtime.RequiredProbes) == 0 &&
			gpu.Bootstrap.MaxAgeSeconds == 0 && gpu.Runtime.MaxAgeSeconds == 0 &&
			gpu.Bootstrap.MaxCycleSeconds == 0 && gpu.Runtime.MaxCycleSeconds == 0
	}
	return (gpu.Mode == "required" || gpu.Mode == "optional") &&
		gpu.Bootstrap.Scope == "bootstrap" && gpu.Runtime.Scope == "runtime" &&
		scopeCurrent(gpu.Bootstrap, now) && scopeCurrent(gpu.Runtime, now)
}

func bundleCurrent(bundle RuntimeStateBundle, now time.Time) bool {
	timestamp, err := time.Parse(time.RFC3339Nano, bundle.Timestamp)
	return err == nil && !timestamp.IsZero() && !timestamp.After(now.Add(5*time.Second)) &&
		now.Sub(timestamp) <= 10*time.Minute && canonicalSHA256(bundle.BundleHMAC)
}

func bootstrapPolicyCurrent(bundle RuntimeStateBundle, now time.Time) bool {
	if bundle.SchemaVersion != 2 || bundle.BootstrapState != StateAttested ||
		!bundle.BootstrapPolicySatisfied || !bundleCurrent(bundle, now) {
		return false
	}
	if bundle.GPU.Mode == "no_gpu" {
		if !gpuScopesCurrent(bundle.GPU, now) {
			return false
		}
	} else if bundle.GPU.Mode == "required" {
		if !scopeCurrent(bundle.GPU.Bootstrap, now) {
			return false
		}
	} else if bundle.GPU.Mode != "optional" {
		return false
	}
	if bundle.AssuranceMode == "evaluation" {
		return true
	}
	return bundle.AssuranceMode == "hardware" && bundle.DeploymentVerified && bundle.ReleaseBaselineVerified &&
		bundle.BootMeasurements.SecureBootEnabled && bundle.TPMAvailable &&
		bundle.TPMMeasurementsVerified && bundle.TPMQuoteVerified && canonicalSHA256(bundle.TPMAKPublicKeySHA256)
}

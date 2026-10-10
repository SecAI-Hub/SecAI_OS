package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

const maxGPUProbes = evidence.MaxProbes

var gpuHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gpuProbeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type GPUProbeEvidence = evidence.Probe

type GPUCompletedSnapshot = evidence.Snapshot

type gpuPublishedState struct {
	sequence     uint64
	availability string
	reason       string
	snapshot     *GPUCompletedSnapshot
}

type gpuEvidencePublisher struct {
	cycleMu                                  sync.Mutex
	mu                                       sync.RWMutex
	scope                                    string
	instance                                 string
	key                                      []byte
	profileHash, baselineHash, baselineState string
	probes                                   map[string]ProbeType
	state                                    gpuPublishedState
	now                                      func() time.Time
	requests                                 chan struct{}
}

func knownGPUProbe(t ProbeType) bool { return evidence.KnownProbe(t) }

func baselineCoversGPUProbe(b *Baseline, t ProbeType) bool {
	if t == ProbeECCStatus {
		return true
	}
	if b == nil || b.CapturedAt.IsZero() {
		return false
	}
	switch t {
	case ProbeTensorHash:
		if len(b.TensorHashes) == 0 {
			return false
		}
		for _, hash := range b.TensorHashes {
			if !gpuHex64.MatchString(hash) {
				return false
			}
		}
	case ProbeSentinelInfer, ProbeReferenceDrift:
		if len(b.SentinelRefs) == 0 || len(b.SentinelRefs) > 64 {
			return false
		}
		seen := map[string]bool{}
		for _, ref := range b.SentinelRefs {
			if !validProbeReference(ref, b) || seen[ref.Name] {
				return false
			}
			seen[ref.Name] = true
		}
	case ProbeDriverFingerprint:
		if b.DriverFingerprint == nil || b.DriverFingerprint.DriverVersion == "" || b.DriverFingerprint.KernelModule == "" {
			return false
		}
		if hash := b.DriverFingerprint.ModuleHash; hash != "" && !gpuHex64.MatchString(hash) {
			return false
		}
	case ProbeDeviceAllowlist:
		if len(b.DeviceAllowlist) == 0 || len(b.DeviceAllowlist) > 64 {
			return false
		}
		for _, path := range b.DeviceAllowlist {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return false
			}
		}
	default:
		return false
	}
	return true
}

func newGPUEvidencePublisher(scope string, key []byte, profile *IntegrityProfile, baseline *Baseline, profileHash, baselineHash string) (*gpuEvidencePublisher, error) {
	if (scope != "bootstrap" && scope != "runtime") || len(key) != 32 || profile == nil || profile.Version != 1 || !gpuHex64.MatchString(profileHash) || (baselineHash != "" && !gpuHex64.MatchString(baselineHash)) {
		return nil, fmt.Errorf("invalid GPU producer identity or protected inputs")
	}
	if len(profile.Probes) > maxGPUProbes || profile.Scoring.MaxHistory < 0 || profile.Scoring.MaxHistory > 1000 {
		return nil, fmt.Errorf("GPU profile exceeds retention/count limits")
	}
	for kind, weight := range profile.Scoring.Weights {
		if !knownGPUProbe(ProbeType(kind)) || math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 || weight > 100 {
			return nil, fmt.Errorf("invalid GPU scoring weight")
		}
	}
	p := &gpuEvidencePublisher{scope: scope, key: append([]byte(nil), key...), profileHash: profileHash, baselineHash: baselineHash, baselineState: "not_required", probes: map[string]ProbeType{}, now: time.Now, requests: make(chan struct{}, 8), state: gpuPublishedState{availability: "unavailable", reason: "no_completed_cycle"}}
	for _, probe := range profile.Probes {
		if !probe.Enabled {
			continue
		}
		if !gpuProbeID.MatchString(probe.Name) || !knownGPUProbe(probe.Type) || p.probes[probe.Name] != "" {
			return nil, fmt.Errorf("invalid or duplicate GPU probe identity")
		}
		if scope == "bootstrap" && probe.Type != ProbeECCStatus && probe.Type != ProbeDriverFingerprint && probe.Type != ProbeDeviceAllowlist {
			return nil, fmt.Errorf("bootstrap GPU profile contains dependent live probes")
		}
		p.probes[probe.Name] = probe.Type
		if probe.Type != ProbeECCStatus {
			if p.baselineState != "missing" {
				p.baselineState = "loaded"
			}
			if baselineHash == "" || !baselineCoversGPUProbe(baseline, probe.Type) {
				p.baselineState = "missing"
			}
		}
	}
	if len(p.probes) == 0 {
		return nil, fmt.Errorf("GPU profile has no enabled probes")
	}
	instance := make([]byte, 32)
	if _, err := rand.Read(instance); err != nil {
		return nil, fmt.Errorf("GPU producer instance entropy unavailable")
	}
	p.instance = hex.EncodeToString(instance)
	return p, nil
}

func (p *gpuEvidencePublisher) readState() gpuPublishedState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	state := p.state
	if state.snapshot != nil {
		copy := *state.snapshot
		copy.Probes = append([]GPUProbeEvidence(nil), copy.Probes...)
		state.snapshot = &copy
	}
	return state
}

// Capture owns ordering across the actual run and score. Concurrent cycles are
// refused; readers continue seeing the prior immutable completed cycle. An
// invalid newly completed cycle replaces prior success with unavailable state.
func (p *gpuEvidencePublisher) capture(run func() []ProbeResult, scorer *ScoringEngine) (results []ProbeResult, entry ScoreEntry, captureErr error) {
	if !p.cycleMu.TryLock() {
		return nil, ScoreEntry{}, fmt.Errorf("GPU cycle already active")
	}
	defer p.cycleMu.Unlock()
	p.mu.Lock()
	if p.state.sequence == ^uint64(0) {
		p.state = gpuPublishedState{sequence: p.state.sequence, availability: "unavailable", reason: "sequence_exhausted"}
		p.mu.Unlock()
		return nil, ScoreEntry{Verdict: VerdictUnknown}, fmt.Errorf("GPU cycle sequence exhausted")
	}
	previous := p.state.snapshot
	p.mu.Unlock()
	defer func() {
		if recover() != nil {
			p.mu.Lock()
			p.state = gpuPublishedState{sequence: p.state.sequence + 1, availability: "unavailable", reason: "cycle_aborted"}
			p.mu.Unlock()
			results, entry, captureErr = nil, ScoreEntry{Verdict: VerdictUnknown}, fmt.Errorf("GPU cycle aborted")
		}
	}()
	started := p.now()
	results = run()
	completed := p.now()
	invalid := func() ([]ProbeResult, ScoreEntry, error) {
		p.mu.Lock()
		p.state = gpuPublishedState{sequence: p.state.sequence + 1, availability: "unavailable", reason: "invalid_cycle"}
		p.mu.Unlock()
		return results, ScoreEntry{Verdict: VerdictUnknown}, fmt.Errorf("GPU cycle evidence invalid")
	}
	if previous != nil {
		previousEnd, err := time.Parse(time.RFC3339Nano, previous.CompletedAt)
		if err != nil || started.Before(previousEnd) {
			return invalid()
		}
	}
	if started.IsZero() || completed.Before(started) || completed.Sub(started) > 10*time.Minute || len(results) != len(p.probes) {
		return invalid()
	}
	seen := map[string]bool{}
	for _, result := range results {
		expected, exists := p.probes[result.Probe]
		if !exists || expected != result.Type || seen[result.Probe] || math.IsNaN(result.Score) || math.IsInf(result.Score, 0) || result.Score < 0 || result.Score > 1 || result.Timestamp.IsZero() || result.Timestamp.Before(started) || result.Timestamp.After(completed) {
			return invalid()
		}
		switch result.Status {
		case StatusPass, StatusDrift, StatusFail, StatusSkip, StatusError:
		default:
			return invalid()
		}
		seen[result.Probe] = true
	}
	entry = scorer.Score(results)
	if math.IsNaN(entry.CompositeScore) || math.IsInf(entry.CompositeScore, 0) || entry.CompositeScore < 0 || entry.CompositeScore > 1 {
		return invalid()
	}
	snapshot := &GPUCompletedSnapshot{StartedAt: started.UTC().Format(time.RFC3339Nano), CompletedAt: completed.UTC().Format(time.RFC3339Nano), ProfileSHA256: p.profileHash, BaselineSHA256: p.baselineHash, BaselineState: p.baselineState, Verdict: entry.Verdict, CompositeScore: entry.CompositeScore, Probes: make([]GPUProbeEvidence, 0, len(results))}
	for _, r := range results {
		reason := map[ProbeStatus]string{StatusPass: "probe_pass", StatusDrift: "probe_drift", StatusFail: "probe_failure", StatusSkip: "probe_skipped", StatusError: "probe_error"}[r.Status]
		snapshot.Probes = append(snapshot.Probes, GPUProbeEvidence{ID: r.Probe, Type: r.Type, Status: r.Status, Score: r.Score, Reason: reason})
	}
	sort.Slice(snapshot.Probes, func(i, j int) bool { return snapshot.Probes[i].ID < snapshot.Probes[j].ID })
	availability, reason := "complete", "completed_cycle"
	if p.baselineState == "missing" {
		availability, reason = "unverified", "required_baseline_missing"
		if snapshot.Verdict != VerdictCritical {
			snapshot.Verdict = VerdictUnknown
		}
	}
	p.mu.Lock()
	snapshot.Sequence = p.state.sequence + 1
	p.state = gpuPublishedState{sequence: snapshot.Sequence, availability: availability, reason: reason, snapshot: snapshot}
	p.mu.Unlock()
	return results, entry, nil
}

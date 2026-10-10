package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Run the real CLI entry point in a separate process because its error paths
// call os.Exit. The selected profile only scans an empty temporary directory.
func TestGPUCLIProfileHelper(t *testing.T) {
	if os.Getenv("GPU_TEST_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(99)
}

func TestGPUCLIProfileSelection(t *testing.T) {
	dir := t.TempDir()
	profile := IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "selected-profile", Type: ProbeDeviceAllowlist, Enabled: true, Settings: map[string]string{"device_dir": dir}}}}
	data, err := yaml.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"final pair":                   {"check", "-profile", path},
		"pair before another argument": {"check", "-profile", path, "unused"},
		"last selector wins":           {"check", "-profile", filepath.Join(dir, "missing"), "-profile", path},
		"environment fallback":         {"check"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestGPUCLIProfileHelper$", "--"}, args...)...)
			profileEnv := filepath.Join(dir, "missing-env-profile")
			if name == "environment fallback" {
				profileEnv = path
			}
			cmd.Env = append(os.Environ(), "GPU_TEST_CLI_HELPER=1", "INTEGRITY_PROFILE="+profileEnv, "AUDIT_LOG=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI failed: %v: %s", err, out)
			}
			var result struct {
				Probes []ProbeResult `json:"probes"`
			}
			if err := json.Unmarshal(out, &result); err != nil || len(result.Probes) != 1 || result.Probes[0].Probe != "selected-profile" || result.Probes[0].Status != StatusSkip {
				t.Fatalf("CLI did not run the selected synthetic profile: %s", out)
			}
		})
	}
}

func TestGPUEvidenceRealRunnerDriverHashUnavailable(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, "version")
	if err := os.WriteFile(versionPath, []byte("synthetic-version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := &IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "driver", Type: ProbeDriverFingerprint, Enabled: true, Settings: map[string]string{"driver_version_path": versionPath, "kernel_module": "synthetic-module-never-loaded"}}}}
	baseline := &Baseline{CapturedAt: time.Now(), DriverFingerprint: &DriverBaseline{DriverVersion: "synthetic-version", KernelModule: "synthetic-module-never-loaded", ModuleHash: strings.Repeat("a", 64)}}
	key := bytes.Repeat([]byte{7}, 32)
	p, err := newGPUEvidencePublisher("runtime", key, profile, baseline, strings.Repeat("b", 64), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	runner := NewProbeRunner(profile, baseline)
	results, _, err := p.capture(runner.RunAll, NewScoringEngine(nil, 10))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	defer server.Close()
	response, err := fetchGPUEvidence(context.Background(), server.URL, "runtime", strings.Repeat("d", 64), key)
	if err != nil {
		t.Fatal(err)
	}
	policy := GPUConsumerPolicy{Scope: "runtime", ProfileSHA256: strings.Repeat("b", 64), BaselineSHA256: strings.Repeat("c", 64), RequiredProbes: map[string]ProbeType{"driver": ProbeDriverFingerprint}, MaxAge: time.Minute, MaxCycleDuration: time.Minute}
	if results[0].Status != StatusError || response.Snapshot.Verdict != VerdictUnknown || validateGPUCompletedEvidence(response, policy, time.Now()) == nil {
		t.Fatal("unmeasured enrolled module hash became healthy authenticated evidence")
	}
}

func TestGPUEvidenceLoadedInputsRealRunner(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, "version")
	if err := os.WriteFile(versionPath, []byte("fixture-version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	baseline := &Baseline{CapturedAt: time.Now().UTC(), DriverFingerprint: &DriverBaseline{DriverVersion: "fixture-version", KernelModule: "fixture-module"}}
	baselinePath := filepath.Join(dir, "baseline.yaml")
	profile := &IntegrityProfile{Version: 1, BaselineFile: baselinePath, Probes: []ProbeConfig{{Name: "driver", Type: ProbeDriverFingerprint, Enabled: true, Settings: map[string]string{"driver_version_path": versionPath, "kernel_module": "fixture-module"}}}}
	profileData, _ := yaml.Marshal(profile)
	baselineData, _ := yaml.Marshal(baseline)
	profilePath := filepath.Join(dir, "profile.yaml")
	for path, data := range map[string][]byte{profilePath: profileData, baselinePath: baselineData} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	loadedProfile, loadedBaseline, profileHash, baselineHash, err := loadGPUProducerInputs(profilePath)
	if err != nil || profileHash != gpuInputDigest(profileData) || baselineHash != gpuInputDigest(baselineData) {
		t.Fatalf("loaded input identity mismatch: %v", err)
	}
	// Later filesystem replacements cannot relabel the daemon's loaded inputs.
	if err := os.WriteFile(baselinePath, []byte("captured_at: null\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	p, err := newGPUEvidencePublisher("runtime", key, loadedProfile, loadedBaseline, profileHash, baselineHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.capture(NewProbeRunner(loadedProfile, loadedBaseline).RunAll, NewScoringEngine(nil, 10)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	defer server.Close()
	response, err := fetchGPUEvidence(context.Background(), server.URL, "runtime", strings.Repeat("e", 64), key)
	if err != nil {
		t.Fatal(err)
	}
	policy := GPUConsumerPolicy{Scope: "runtime", ProfileSHA256: profileHash, BaselineSHA256: baselineHash, RequiredProbes: map[string]ProbeType{"driver": ProbeDriverFingerprint}, MaxAge: time.Minute, MaxCycleDuration: time.Minute}
	if err := validateGPUCompletedEvidence(response, policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(response)
	for _, private := range []string{dir, "fixture-version", "fixture-module"} {
		if bytes.Contains(body, []byte(private)) {
			t.Fatal("raw probe input leaked into signed DTO")
		}
	}
}

func TestGPUEvidenceConcurrentProducersHTTP(t *testing.T) {
	var work sync.WaitGroup
	for _, scope := range []string{"bootstrap", "runtime"} {
		f := newGPUEvidenceFixture(t, scope)
		f.capture(t, StatusPass)
		server := gpuFixtureServer(t, f.p)
		work.Add(1)
		go func() {
			defer work.Done()
			for sequence := 2; sequence <= 64; sequence++ {
				status := StatusPass
				if sequence%2 == 0 {
					status = StatusFail
				}
				if _, _, err := f.p.capture(func() []ProbeResult { return f.result(status) }, f.scorer); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		for reader := 0; reader < 4; reader++ {
			work.Add(1)
			go func() {
				defer work.Done()
				for request := 0; request < 32; request++ {
					r, err := fetchGPUEvidence(context.Background(), server.URL, scope, strings.Repeat("f", 64), f.key)
					if err != nil {
						t.Error(err)
						return
					}
					status, verdict := StatusPass, VerdictHealthy
					if r.LatestSequence%2 == 0 {
						status, verdict = StatusFail, VerdictCritical
					}
					if r.ProducerInstance != f.p.instance || r.Scope != scope || r.Snapshot.Sequence != r.LatestSequence || r.Snapshot.Probes[0].Status != status || r.Snapshot.Verdict != verdict {
						t.Error("HTTP evidence mixed producer/cycle metadata and results")
						return
					}
				}
			}()
		}
	}
	work.Wait()
}

func TestGPUEvidenceProfileBoundsAndRequiredBaselines(t *testing.T) {
	for _, kind := range []ProbeType{ProbeTensorHash, ProbeSentinelInfer, ProbeReferenceDrift, ProbeDriverFingerprint, ProbeDeviceAllowlist} {
		t.Run(string(kind), func(t *testing.T) {
			profile := &IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "required", Type: kind, Enabled: true}}}
			p, err := newGPUEvidencePublisher("runtime", bytes.Repeat([]byte{1}, 32), profile, &Baseline{CapturedAt: time.Now()}, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := p.capture(func() []ProbeResult {
				return []ProbeResult{{Probe: "required", Type: kind, Status: StatusPass, Timestamp: time.Now()}}
			}, NewScoringEngine(nil, 1)); err != nil {
				t.Fatal(err)
			}
			if state := p.readState(); state.availability != "unverified" || state.snapshot.Verdict != VerdictUnknown {
				t.Fatal("incomplete required baseline became healthy evidence")
			}
		})
	}
	profile := &IntegrityProfile{Version: 1}
	for i := 0; i < 64; i++ {
		profile.Probes = append(profile.Probes, ProbeConfig{Name: fmt.Sprintf("ecc-%02d", i), Type: ProbeECCStatus, Enabled: true})
	}
	key := bytes.Repeat([]byte{1}, 32)
	p, err := newGPUEvidencePublisher("runtime", key, profile, nil, strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal("maximum valid probe coverage rejected", err)
	}
	if _, _, err := p.capture(func() []ProbeResult {
		results := make([]ProbeResult, len(profile.Probes))
		for i, probe := range profile.Probes {
			results[i] = ProbeResult{Probe: probe.Name, Type: probe.Type, Status: StatusPass, Timestamp: time.Now()}
		}
		return results
	}, NewScoringEngine(nil, 1)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	defer server.Close()
	if response, err := fetchGPUEvidence(context.Background(), server.URL, "runtime", strings.Repeat("c", 64), key); err != nil || len(response.Snapshot.Probes) != 64 {
		t.Fatalf("bounded client/server cannot exchange maximum coverage: %v", err)
	}
	profile.Probes = append(profile.Probes, ProbeConfig{Name: "overflow", Type: ProbeECCStatus, Enabled: true})
	if _, err := newGPUEvidencePublisher("runtime", key, profile, nil, strings.Repeat("a", 64), ""); err == nil {
		t.Fatal("65-probe profile accepted")
	}
	profile.Probes = profile.Probes[:64]
	profile.Probes[1].Name = profile.Probes[0].Name
	if _, err := newGPUEvidencePublisher("runtime", key, profile, nil, strings.Repeat("a", 64), ""); err == nil {
		t.Fatal("duplicate probe profile accepted")
	}
}

func TestGPUEvidenceDefaultExchangeDeadlines(t *testing.T) {
	t.Run("client response deadline", func(t *testing.T) {
		t.Parallel()
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer server.Close()
		defer close(release)
		started := time.Now()
		_, err := fetchGPUEvidence(context.Background(), server.URL, "runtime", strings.Repeat("a", 64), bytes.Repeat([]byte{1}, 32))
		if err == nil || time.Since(started) < 4*time.Second || time.Since(started) > 7*time.Second {
			t.Fatal("default five-second client deadline not enforced", err)
		}
	})
	t.Run("server incomplete request deadline", func(t *testing.T) {
		t.Parallel()
		f := newGPUEvidenceFixture(t, "runtime")
		server := httptest.NewServer(f.p)
		defer server.Close()
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(7 * time.Second))
		started := time.Now()
		if _, err := io.WriteString(conn, "POST /v1/attest-state HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		// The server's write deadline can expire with its read deadline, so an
		// EOF without an HTTP error body is also an expected bounded rejection.
		if _, err := io.ReadAll(conn); err != nil || time.Since(started) < 4*time.Second || time.Since(started) > 7*time.Second {
			t.Fatal("default five-second server deadline not enforced", err)
		}
		if len(f.p.requests) != 0 || f.p.readState().sequence != 0 {
			t.Fatal("timed-out exchange retained capacity or triggered a cycle")
		}
	})
}

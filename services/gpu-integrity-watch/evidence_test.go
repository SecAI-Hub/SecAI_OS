package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type gpuEvidenceFixture struct {
	p       *gpuEvidencePublisher
	profile *IntegrityProfile
	scorer  *ScoringEngine
	clock   atomic.Int64
	key     []byte
	policy  GPUConsumerPolicy
}

func newGPUEvidenceFixture(t *testing.T, scope string) *gpuEvidenceFixture {
	t.Helper()
	f := &gpuEvidenceFixture{key: bytes.Repeat([]byte{0x37}, 32)}
	f.profile = &IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "ecc-check", Type: ProbeECCStatus, Enabled: true}}}
	var err error
	f.p, err = newGPUEvidencePublisher(scope, f.key, f.profile, nil, strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Store(time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).UnixNano())
	f.p.now = func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	f.scorer = NewScoringEngine(nil, 10)
	f.policy = GPUConsumerPolicy{Scope: scope, ProfileSHA256: strings.Repeat("a", 64), RequiredProbes: map[string]ProbeType{"ecc-check": ProbeECCStatus}, MaxAge: 5 * time.Minute, MaxCycleDuration: time.Minute}
	return f
}

func (f *gpuEvidenceFixture) result(status ProbeStatus) []ProbeResult {
	f.clock.Add(int64(time.Millisecond))
	return []ProbeResult{{Probe: "ecc-check", Type: ProbeECCStatus, Status: status, Timestamp: f.p.now(), Score: 0,
		Findings: []Finding{{Description: "password=fixture-secret-opaque", Detail: "private prompt and model output /vault/private.gguf"}}, ModelPaths: []string{"/vault/private.gguf"}}}
}

func (f *gpuEvidenceFixture) capture(t *testing.T, status ProbeStatus) {
	t.Helper()
	if _, _, err := f.p.capture(func() []ProbeResult { return f.result(status) }, f.scorer); err != nil {
		t.Fatal(err)
	}
}

func gpuFixtureServer(t *testing.T, p *gpuEvidencePublisher) *httptest.Server {
	t.Helper()
	monitoring := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s := httptest.NewServer(gpuDaemonEvidenceHandler(authenticatedGPUHandler(monitoring, "monitoring-bearer-token"), p))
	t.Cleanup(s.Close)
	return s
}

func TestGPUEvidenceAuthenticatedSnapshotAndPrivacy(t *testing.T) {
	for _, scope := range []string{"bootstrap", "runtime"} {
		t.Run(scope, func(t *testing.T) {
			f := newGPUEvidenceFixture(t, scope)
			f.capture(t, StatusPass)
			s := gpuFixtureServer(t, f.p)
			response, err := fetchGPUEvidence(context.Background(), s.URL, scope, strings.Repeat("b", 64), f.key)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateGPUCompletedEvidence(response, f.policy, f.p.now()); err != nil {
				t.Fatal(err)
			}
			if response.LatestSequence != 1 || response.Snapshot.Sequence != 1 {
				t.Fatal("missing completed sequence")
			}
			body, _ := json.Marshal(response)
			for _, secret := range []string{"fixture-secret-opaque", "private prompt", "model output", "/vault/", "Findings", "ModelPaths", strings.Repeat("37", 32)} {
				if bytes.Contains(body, []byte(secret)) {
					t.Fatalf("unsafe DTO contains %q", secret)
				}
			}
			response.Snapshot.Probes[0].ID = "mutated"
			if f.p.readState().snapshot.Probes[0].ID != "ecc-check" {
				t.Fatal("returned snapshot aliases producer state")
			}
		})
	}
}

func TestGPUEvidenceNoCycleAndStableCompletionTime(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	s := gpuFixtureServer(t, f.p)
	request := func(nonce string) GPUAuthenticatedEvidence {
		r, err := fetchGPUEvidence(context.Background(), s.URL, "runtime", nonce, f.key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	empty := request(strings.Repeat("b", 64))
	if empty.Snapshot != nil || empty.LatestSequence != 0 || empty.Availability != "unavailable" || empty.Reason != "no_completed_cycle" {
		t.Fatalf("no-cycle evidence fabricated: %+v", empty)
	}
	if validateGPUCompletedEvidence(empty, f.policy, f.p.now()) == nil {
		t.Fatal("no cycle became trusted")
	}
	f.capture(t, StatusPass)
	first := request(strings.Repeat("c", 64))
	f.clock.Add(int64(6 * time.Minute))
	later := request(strings.Repeat("d", 64))
	if first.Snapshot.CompletedAt != later.Snapshot.CompletedAt || first.LatestSequence != later.LatestSequence {
		t.Fatal("request refreshed the completed probe time")
	}
	if first.ResponseMAC == later.ResponseMAC {
		t.Fatal("response not bound to nonce")
	}
	if validateGPUCompletedEvidence(later, f.policy, f.p.now()) == nil {
		t.Fatal("fresh challenge hid stale probe evidence")
	}
}

func TestGPUEvidenceMissingBaselineNeverHealthy(t *testing.T) {
	for _, baseline := range []*Baseline{nil, {CapturedAt: time.Now()}} {
		t.Run(fmt.Sprintf("nil=%t", baseline == nil), func(t *testing.T) {
			profile := &IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "driver", Type: ProbeDriverFingerprint, Enabled: true}}}
			p, err := newGPUEvidencePublisher("runtime", bytes.Repeat([]byte{1}, 32), profile, baseline, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			results := func() []ProbeResult {
				return []ProbeResult{{Probe: "driver", Type: ProbeDriverFingerprint, Status: StatusPass, Timestamp: time.Now()}}
			}
			if _, _, err := p.capture(results, NewScoringEngine(nil, 10)); err != nil {
				t.Fatal(err)
			}
			state := p.readState()
			if state.availability != "unverified" || state.snapshot.Verdict != VerdictUnknown || state.reason != "required_baseline_missing" {
				t.Fatal("first-run observation became healthy evidence")
			}
		})
	}
}

func TestGPUEvidenceSerialPublicationAndCopies(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	f.capture(t, StatusPass)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = f.p.capture(func() []ProbeResult { close(entered); <-release; return f.result(StatusFail) }, f.scorer)
	}()
	<-entered
	if _, _, err := f.p.capture(func() []ProbeResult { t.Error("overlapping probe ran"); return nil }, f.scorer); err == nil {
		t.Fatal("overlapping cycles accepted")
	}
	var readers sync.WaitGroup
	for i := 0; i < 16; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				state := f.p.readState()
				if state.snapshot.Sequence != state.sequence || state.snapshot.Probes[0].Status != StatusPass {
					t.Error("partially published cycle")
				}
			}
		}()
	}
	readers.Wait()
	close(release)
	<-done
	state := f.p.readState()
	if state.sequence != 2 || state.snapshot.Sequence != 2 || state.snapshot.Verdict != VerdictCritical || state.snapshot.Probes[0].Status != StatusFail {
		t.Fatal("new complete cycle not atomically published")
	}
}

func TestGPUEvidenceMalformedCycleInvalidatesPriorSuccess(t *testing.T) {
	cases := map[string]func([]ProbeResult) []ProbeResult{
		"missing":            func([]ProbeResult) []ProbeResult { return nil },
		"duplicate":          func(r []ProbeResult) []ProbeResult { return append(r, r[0]) },
		"foreign empty type": func(r []ProbeResult) []ProbeResult { r[0].Probe = "foreign"; r[0].Type = ""; return r },
		"NaN":                func(r []ProbeResult) []ProbeResult { r[0].Score = math.NaN(); return r },
		"score overflow":     func(r []ProbeResult) []ProbeResult { r[0].Score = 2; return r },
		"unknown status":     func(r []ProbeResult) []ProbeResult { r[0].Status = "healthy"; return r },
		"future probe":       func(r []ProbeResult) []ProbeResult { r[0].Timestamp = r[0].Timestamp.Add(time.Hour); return r },
		"missing probe time": func(r []ProbeResult) []ProbeResult { r[0].Timestamp = time.Time{}; return r },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGPUEvidenceFixture(t, "runtime")
			f.capture(t, StatusPass)
			if _, _, err := f.p.capture(func() []ProbeResult { return change(f.result(StatusPass)) }, f.scorer); err == nil {
				t.Fatal("malformed cycle accepted")
			}
			s := f.p.readState()
			if s.sequence != 2 || s.snapshot != nil || s.availability != "unavailable" || s.reason != "invalid_cycle" {
				t.Fatal("prior healthy state survived invalid latest cycle")
			}
		})
	}
}

func TestGPUEvidenceAuthenticationRolesAndTampering(t *testing.T) {
	f := newGPUEvidenceFixture(t, "bootstrap")
	f.capture(t, StatusPass)
	s := gpuFixtureServer(t, f.p)
	for _, scope := range []string{"runtime", "unknown"} {
		if _, err := fetchGPUEvidence(context.Background(), s.URL, scope, strings.Repeat("a", 64), f.key); err == nil {
			t.Fatal("caller elevated producer scope")
		}
	}
	if _, err := fetchGPUEvidence(context.Background(), s.URL, "bootstrap", strings.Repeat("a", 64), bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("wrong scope key accepted")
	}
	request := GPUChallenge{SchemaVersion: 1, Scope: "bootstrap", RequestNonce: strings.Repeat("b", 64)}
	request.RequestMAC, _ = gpuRequestMAC(f.key, request)
	body, _ := json.Marshal(request)
	for _, token := range []string{"", "monitoring-bearer-token"} {
		r, err := http.NewRequest(http.MethodPost, s.URL+gpuEvidencePath, strings.NewReader(`{"schema_version":1,"scope":"bootstrap","request_nonce":"`+request.RequestNonce+`","request_mac":"`+strings.Repeat("0", 64)+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatal("bearer token authorized evidence signing")
		}
	}
	r, _ := http.NewRequest(http.MethodPost, s.URL+"/v1/check", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("evidence key authorized action route")
	}
	r, _ = http.NewRequest(http.MethodPost, s.URL+"/v1/check", nil)
	r.Header.Set("Authorization", "Bearer monitoring-bearer-token")
	resp, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatal("existing bearer route weakened or broken")
	}
	response, err := fetchGPUEvidence(context.Background(), s.URL, "bootstrap", request.RequestNonce, f.key)
	if err != nil {
		t.Fatal(err)
	}
	mac := response.ResponseMAC
	for name, change := range map[string]func(*GPUAuthenticatedEvidence){
		"nonce": func(r *GPUAuthenticatedEvidence) { r.RequestNonce = strings.Repeat("c", 64) }, "scope": func(r *GPUAuthenticatedEvidence) { r.Scope = "runtime" }, "sequence": func(r *GPUAuthenticatedEvidence) { r.LatestSequence++ }, "instance": func(r *GPUAuthenticatedEvidence) { r.ProducerInstance = strings.Repeat("d", 64) }, "completion": func(r *GPUAuthenticatedEvidence) { r.Snapshot.CompletedAt = "2026-01-01T00:00:00Z" }, "probe": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Probes[0].Status = StatusFail }, "profile": func(r *GPUAuthenticatedEvidence) { r.Snapshot.ProfileSHA256 = strings.Repeat("e", 64) }, "baseline": func(r *GPUAuthenticatedEvidence) { r.Snapshot.BaselineSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(response)
			var changed GPUAuthenticatedEvidence
			json.Unmarshal(raw, &changed)
			change(&changed)
			computed, _ := gpuResponseMAC(f.key, changed)
			if equalGPUMAC(mac, computed) {
				t.Fatal("evidence mutation was not MAC-bound")
			}
		})
	}
	response.ResponseMAC = ""
	other, _ := gpuMAC(f.key, "SecAI GPU evidence request v1", response)
	correct, _ := gpuResponseMAC(f.key, response)
	if other == correct {
		t.Fatal("MAC domains collide")
	}
}

func TestGPUEvidenceStrictWireRequests(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	valid := GPUChallenge{SchemaVersion: 1, Scope: "runtime", RequestNonce: strings.Repeat("a", 64)}
	valid.RequestMAC, _ = gpuRequestMAC(f.key, valid)
	raw, _ := json.Marshal(valid)
	cases := map[string][]byte{"null": []byte("null"), "trailing": append(append([]byte(nil), raw...), []byte(" {}")...), "unknown": []byte(strings.Replace(string(raw), `"schema_version":1`, `"unknown":0,"schema_version":1`, 1)), "duplicate": []byte(strings.Replace(string(raw), `"scope":`, `"scope":"runtime","scope":`, 1)), "Unicode alias": []byte(strings.Replace(string(raw), `"scope":`, `"ſcope":"runtime","scope":`, 1)), "missing": []byte(`{}`), "null version": []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":null`, 1)), "oversize": bytes.Repeat([]byte(" "), gpuRequestLimit+1), "invalid UTF8": []byte("{\xff}")}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, httptest.NewRequest(http.MethodPost, gpuEvidencePath, bytes.NewReader(body)))
			if w.Code < 400 {
				t.Fatal("malformed challenge accepted")
			}
			if f.p.readState().sequence != 0 {
				t.Fatal("request triggered cycle")
			}
		})
	}
	for i := 0; i < cap(f.p.requests); i++ {
		f.p.requests <- struct{}{}
	}
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, httptest.NewRequest(http.MethodPost, gpuEvidencePath, bytes.NewReader(raw)))
	if w.Code != 503 {
		t.Fatal("request capacity unbounded")
	}
}

func TestGPUEvidenceBoundedClientAndServerAuthenticity(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	f.capture(t, StatusPass)
	for _, origin := range []string{"http://localhost:12", "https://127.0.0.1:12", "http://127.0.0.1", "http://user@127.0.0.1:12", "http://127.0.0.1:12/path", "http://127.0.0.1:12?", "http://127.0.0.1:12#", "http://127.0.0.1:12?query", "http://127.0.0.1:12#fragment", "http://192.0.2.1:12"} {
		if _, err := gpuEvidenceURL(origin); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	for name, handler := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/", 302) },
		"forged healthy": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"schema_version":1,"scope":"runtime","request_nonce":"` + strings.Repeat("a", 64) + `","producer_instance":"` + strings.Repeat("b", 64) + `","latest_sequence":1,"availability":"complete","reason":"completed_cycle","snapshot":null,"response_mac":"` + strings.Repeat("0", 64) + `"}`))
		},
		"oversize": func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte(" "), gpuResponseLimit+1)) },
		"truncated": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("{}"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()
			if _, err := fetchGPUEvidence(context.Background(), s.URL, "runtime", strings.Repeat("a", 64), f.key); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	t.Run("deadline", func(t *testing.T) {
		release := make(chan struct{})
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}))
		defer s.Close()
		defer close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := fetchGPUEvidence(ctx, s.URL, "runtime", strings.Repeat("a", 64), f.key); err == nil {
			t.Fatal("deadline ignored")
		}
	})
	t.Run("no key disclosure or proxy", func(t *testing.T) {
		for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
			t.Setenv(name, "http://127.0.0.1:1")
		}
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("Authorization") != "" || bytes.Contains(body, []byte(strings.Repeat("37", 32))) {
				t.Error("key or bearer sent on wire")
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			f.p.ServeHTTP(w, r)
		}))
		defer s.Close()
		if _, err := fetchGPUEvidence(context.Background(), s.URL, "runtime", strings.Repeat("b", 64), f.key); err != nil {
			t.Fatal(err)
		}
	})
}

func TestGPUEvidenceFreshnessCoverageAndTrustInputs(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	f.capture(t, StatusPass)
	s := gpuFixtureServer(t, f.p)
	original, err := fetchGPUEvidence(context.Background(), s.URL, "runtime", strings.Repeat("a", 64), f.key)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*GPUAuthenticatedEvidence){"no cycle": func(r *GPUAuthenticatedEvidence) { r.Snapshot = nil }, "wrong profile": func(r *GPUAuthenticatedEvidence) { r.Snapshot.ProfileSHA256 = strings.Repeat("b", 64) }, "wrong baseline": func(r *GPUAuthenticatedEvidence) { r.Snapshot.BaselineSHA256 = strings.Repeat("b", 64) }, "future": func(r *GPUAuthenticatedEvidence) {
		r.Snapshot.CompletedAt = f.p.now().Add(time.Hour).Format(time.RFC3339Nano)
	}, "stale start": func(r *GPUAuthenticatedEvidence) {
		r.Snapshot.StartedAt = f.p.now().Add(-time.Hour).Format(time.RFC3339Nano)
	}, "unknown": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Verdict = VerdictUnknown }, "critical": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Verdict = VerdictCritical }, "warning": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Verdict = VerdictWarning }, "missing probe": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Probes = nil }, "skipped": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Probes[0].Status = StatusSkip }, "NaN": func(r *GPUAuthenticatedEvidence) { r.Snapshot.CompositeScore = math.NaN() }, "wrong cycle": func(r *GPUAuthenticatedEvidence) { r.Snapshot.Sequence++ }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var response GPUAuthenticatedEvidence
			json.Unmarshal(raw, &response)
			change(&response)
			if validateGPUCompletedEvidence(response, f.policy, f.p.now()) == nil {
				t.Fatal("unsafe evidence trusted")
			}
		})
	}
}

func TestGPUEvidenceProtectedInputsAndScope(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("1", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := loadGPUAttestationKey(keyPath); err != nil || len(key) != 32 {
		t.Fatal("valid key rejected")
	}
	for name, change := range map[string]func(){"writable": func() { os.Chmod(keyPath, 0666) }, "uppercase": func() { os.WriteFile(keyPath, []byte(strings.Repeat("A", 64)), 0600) }, "extra data": func() { os.WriteFile(keyPath, []byte(strings.Repeat("1", 64)+"\n\n"), 0600) }} {
		t.Run(name, func(t *testing.T) {
			os.Chmod(keyPath, 0600)
			os.WriteFile(keyPath, []byte(strings.Repeat("1", 64)), 0600)
			change()
			if _, err := loadGPUAttestationKey(keyPath); err == nil {
				t.Fatal("unsafe key accepted")
			}
		})
	}
	os.Chmod(keyPath, 0600)
	os.WriteFile(keyPath, []byte(strings.Repeat("1", 64)), 0600)
	link := filepath.Join(dir, "key-link")
	os.Symlink(keyPath, link)
	if _, err := loadGPUAttestationKey(link); err == nil {
		t.Fatal("symlink key accepted")
	}
	profile := &IntegrityProfile{Version: 1, Probes: []ProbeConfig{{Name: "hash", Type: ProbeTensorHash, Enabled: true}}}
	if _, err := newGPUEvidencePublisher("bootstrap", bytes.Repeat([]byte{1}, 32), profile, nil, strings.Repeat("a", 64), ""); err == nil {
		t.Fatal("dependent live probe elevated bootstrap scope")
	}
	data, _ := yaml.Marshal(profile)
	profilePath := filepath.Join(dir, "profile.yaml")
	os.WriteFile(profilePath, data, 0600)
	loaded, baseline, hash, baselineHash, err := loadGPUProducerInputs(profilePath)
	if err != nil || loaded == nil || baseline != nil || hash != gpuInputDigest(data) || baselineHash != "" {
		t.Fatal("protected input hash not bound to decoded bytes")
	}
	os.WriteFile(profilePath, append(data, []byte("unknown_field: true\n")...), 0600)
	if _, _, _, _, err := loadGPUProducerInputs(profilePath); err == nil {
		t.Fatal("unknown profile field accepted")
	}
}

func TestGPUEvidenceAbortClockAndSequenceFailures(t *testing.T) {
	t.Run("panic cannot retain healthy evidence or leak details", func(t *testing.T) {
		f := newGPUEvidenceFixture(t, "runtime")
		f.capture(t, StatusPass)
		_, _, err := f.p.capture(func() []ProbeResult { panic("private model prompt secret") }, f.scorer)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("cycle panic was not safely represented")
		}
		state := f.p.readState()
		if state.snapshot != nil || state.reason != "cycle_aborted" || state.sequence != 2 {
			t.Fatal("prior success survived aborted cycle")
		}
	})
	t.Run("clock rollback", func(t *testing.T) {
		f := newGPUEvidenceFixture(t, "runtime")
		f.capture(t, StatusPass)
		f.clock.Add(-int64(time.Hour))
		if _, _, err := f.p.capture(func() []ProbeResult { return f.result(StatusPass) }, f.scorer); err == nil {
			t.Fatal("rollback accepted")
		}
	})
	t.Run("sequence exhaustion", func(t *testing.T) {
		f := newGPUEvidenceFixture(t, "runtime")
		f.p.state.sequence = ^uint64(0)
		if _, _, err := f.p.capture(func() []ProbeResult { t.Error("exhausted cycle executed"); return nil }, f.scorer); err == nil {
			t.Fatal("sequence wrapped")
		}
		if state := f.p.readState(); state.sequence != ^uint64(0) || state.reason != "sequence_exhausted" {
			t.Fatal("invalid exhausted state")
		}
	})
}

func TestGPUEvidenceStrictResponseValues(t *testing.T) {
	f := newGPUEvidenceFixture(t, "runtime")
	f.capture(t, StatusPass)
	s := gpuFixtureServer(t, f.p)
	response, err := fetchGPUEvidence(context.Background(), s.URL, "runtime", strings.Repeat("a", 64), f.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(response)
	for name, body := range map[string][]byte{
		"null score":              []byte(strings.Replace(string(raw), `"score":0`, `"score":null`, 1)),
		"missing score":           []byte(strings.Replace(string(raw), `"score":0,`, "", 1)),
		"unknown field":           []byte(strings.Replace(string(raw), `"schema_version":1`, `"extra":true,"schema_version":1`, 1)),
		"duplicate Unicode alias": []byte(strings.Replace(string(raw), `"scope":`, `"ſcope":"runtime","scope":`, 1)),
		"invalid availability":    []byte(strings.Replace(string(raw), `"availability":"complete"`, `"availability":"trusted"`, 1)),
		"raw path as ID":          []byte(strings.Replace(string(raw), `"id":"ecc-check"`, `"id":"/vault/private"`, 1)),
		"contradictory verdict":   []byte(strings.Replace(string(raw), `"verdict":"healthy"`, `"verdict":"critical"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeGPUResponse(body); err == nil {
				t.Fatal("malformed signed-response schema accepted")
			}
		})
	}
}

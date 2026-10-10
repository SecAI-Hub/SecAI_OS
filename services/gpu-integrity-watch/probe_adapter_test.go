package main

import (
	"bytes"
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
)

func probeTestBaseline() *Baseline {
	hash := strings.Repeat("a", 64)
	return &Baseline{CapturedAt: time.Now(), TensorHashes: map[string]string{"approved.gguf": hash}, SentinelRefs: []SentinelRef{{Name: "known-answer", Input: "approved fixed input", Expected: "escaped \"answer\"\nline", ModelFilename: "approved.gguf", ModelSHA256: hash}}}
}
func probeTestKey() []byte            { return bytes.Repeat([]byte{0xab}, 32) }
func probeTestPins() (string, string) { return strings.Repeat("b", 64), strings.Repeat("c", 64) }
func newProbeFixture(t *testing.T, backend http.Handler) (*gpuProbeServer, *GPUProbeClient, *httptest.Server) {
	t.Helper()
	b := probeTestBaseline()
	ph, bh := probeTestPins()
	bs := httptest.NewServer(backend)
	t.Cleanup(bs.Close)
	s, err := newGPUProbeServer(ph, bh, b, probeTestKey(), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	s.backendOrigin = bs.URL
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := newGPUProbeClient(srv.URL, ph, bh, b, probeTestKey())
	if err != nil {
		t.Fatal(err)
	}
	return s, c, srv
}
func normalProbeBackend(t *testing.T, calls *atomic.Int32) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("d", 64) {
			t.Error("dedicated backend token absent")
		}
		if r.URL.Path == "/v1/models" {
			json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "approved.gguf"}}})
			return
		}
		if r.URL.Path != "/completion" || r.Method != "POST" {
			t.Error("unexpected backend capability")
			http.Error(w, "bad", 400)
			return
		}
		var data map[string]any
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			t.Error("invalid completion payload")
		}
		if len(data) != 5 || data["prompt"] != "approved fixed input" || data["n_predict"] != float64(64) || data["temperature"] != float64(0) || data["seed"] != float64(42) || data["stream"] != false {
			t.Errorf("unexpected fixed completion parameters: %v", data)
		}
		json.NewEncoder(w).Encode(map[string]string{"content": probeTestBaseline().SentinelRefs[0].Expected})
	})
}
func signedProbeRequest(n int) gpuProbeRequest {
	r := gpuProbeRequest{SchemaVersion: 1, ReferenceID: "known-answer", RequestNonce: fmt.Sprintf("%064x", n)}
	r.RequestMAC = requestProbeMAC(r, probeTestKey())
	return r
}
func sendProbeRaw(t *testing.T, origin, path string, data []byte) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest("POST", origin+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := boundedProbeHTTP().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestGPUProbeHTTPApprovedReferenceAndWatcher(t *testing.T) {
	var calls atomic.Int32
	_, c, srv := newProbeFixture(t, normalProbeBackend(t, &calls))
	output, err := c.Probe(context.Background(), "known-answer")
	if err != nil || output != probeTestBaseline().SentinelRefs[0].Expected {
		t.Fatalf("escaped content decode: %q %v", output, err)
	}
	runner := NewProbeRunner(&IntegrityProfile{}, probeTestBaseline())
	runner.probeClient = c
	pc := ProbeConfig{Name: "sentinel", Type: ProbeSentinelInfer}
	if result := runner.runSentinelInference(pc); result.Status != StatusPass {
		t.Fatalf("approved signed reference failed: %+v", result)
	}
	pc = ProbeConfig{Name: "drift", Type: ProbeReferenceDrift, Settings: map[string]string{"iterations": "2"}}
	if result := runner.runReferenceDrift(pc); result.Status != StatusPass {
		t.Fatalf("approved drift failed: %+v", result)
	}
	if calls.Load() != 12 {
		t.Fatalf("expected pre/post model check and fixed completion for four exchanges, got %d", calls.Load())
	}
	data, _ := json.Marshal(signedProbeRequest(123))
	status, body := sendProbeRaw(t, srv.URL, "/v1/probe", data)
	var signedFields map[string]json.RawMessage
	if json.Unmarshal(body, &signedFields) != nil || signedFields["expected_model_sha256"] == nil || signedFields["model_sha256"] != nil {
		t.Fatal("response must describe expected approved hash only")
	}
	if status != 200 || bytes.Contains(body, []byte(strings.Repeat("d", 64))) || bytes.Contains(body, []byte(strings.Repeat("ab", 32))) || bytes.Contains(body, []byte("approved fixed input")) {
		t.Fatalf("credential or prompt leaked: status %d", status)
	}
}

func TestGPUProbeHTTPRejectsUnboundedOrArbitraryInputs(t *testing.T) {
	var calls atomic.Int32
	_, _, srv := newProbeFixture(t, normalProbeBackend(t, &calls))
	good := signedProbeRequest(1)
	valid, _ := json.Marshal(good)
	wrongMAC := good
	wrongMAC.RequestMAC = strings.Repeat("0", 64)
	badMAC, _ := json.Marshal(wrongMAC)
	wrongRef := good
	wrongRef.ReferenceID = "other"
	wrongRef.RequestMAC = requestProbeMAC(wrongRef, probeTestKey())
	badRef, _ := json.Marshal(wrongRef)
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"prompt":"arbitrary"}`)...)
	duplicate := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"reference_id":"known-answer"}`)...)
	upper := bytes.Replace(valid, []byte(`"reference_id"`), []byte(`"Reference_ID"`), 1)
	null := bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
	cases := [][]byte{badMAC, badRef, unknown, duplicate, upper, null, append(append([]byte(nil), valid...), []byte(` {}`)...), []byte(strings.Repeat(" ", 4097)), {0xff}}
	for i, data := range cases {
		status, _ := sendProbeRaw(t, srv.URL, "/v1/probe", data)
		if status == 200 {
			t.Errorf("invalid request %d accepted", i)
		}
	}
	for _, path := range []string{"/completion", "/v1/models", "/slots", "/v1/probe?prompt=arbitrary", "/v1/probe/"} {
		status, _ := sendProbeRaw(t, srv.URL, path, valid)
		if status != 404 {
			t.Errorf("unexpected route %q status %d", path, status)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("rejected input reached backend %d times", calls.Load())
	}
}

func TestGPUProbeHTTPRejectsReplayAndRateBudget(t *testing.T) {
	var calls atomic.Int32
	s, _, srv := newProbeFixture(t, normalProbeBackend(t, &calls))
	data, _ := json.Marshal(signedProbeRequest(1))
	status, _ := sendProbeRaw(t, srv.URL, "/v1/probe", data)
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = sendProbeRaw(t, srv.URL, "/v1/probe", data)
	if status != 429 {
		t.Fatalf("replay status %d", status)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 2; i <= 256; i++ {
		if !s.reserve(fmt.Sprintf("%064x", i)) {
			t.Fatal("early rate rejection")
		}
	}
	data, _ = json.Marshal(signedProbeRequest(257))
	status, _ = sendProbeRaw(t, srv.URL, "/v1/probe", data)
	if status != 429 {
		t.Fatalf("rate budget status %d", status)
	}
	if calls.Load() != 3 {
		t.Fatal("rate/replay reached backend")
	}
	now = now.Add(5*time.Minute + time.Second)
	if !s.reserve(fmt.Sprintf("%064x", 257)) {
		t.Fatal("expired bounded cache did not release budget")
	}
	if len(s.nonces) > 256 {
		t.Fatal("nonce retention unbounded")
	}
}

func TestGPUProbeClientRejectsSignedBindingTamper(t *testing.T) {
	ph, bh := probeTestPins()
	ref := probeTestBaseline().SentinelRefs[0]
	for _, field := range []string{"nonce", "mac", "ref", "profile", "baseline", "alias", "model", "null", "oversize", "duplicate", "legacy-hash"} {
		t.Run(field, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("client sent backend credential")
				}
				var req gpuProbeRequest
				json.NewDecoder(r.Body).Decode(&req)
				response := gpuProbeResponse{SchemaVersion: 1, ReferenceID: req.ReferenceID, RequestNonce: req.RequestNonce, ProfileSHA256: ph, BaselineSHA256: bh, ModelAlias: ref.ModelFilename, ExpectedModelSHA256: ref.ModelSHA256, Output: ref.Expected}
				switch field {
				case "nonce":
					response.RequestNonce = strings.Repeat("0", 64)
				case "ref":
					response.ReferenceID = "other"
				case "profile":
					response.ProfileSHA256 = strings.Repeat("e", 64)
				case "baseline":
					response.BaselineSHA256 = strings.Repeat("e", 64)
				case "alias":
					response.ModelAlias = "other.gguf"
				case "model":
					response.ExpectedModelSHA256 = strings.Repeat("e", 64)
				case "oversize":
					response.Output = strings.Repeat("x", maxProbeOutput+1)
				}
				response.ResponseMAC = responseProbeMAC(response, probeTestKey())
				if field == "mac" {
					response.ResponseMAC = strings.Repeat("0", 64)
				}
				data, _ := json.Marshal(response)
				if field == "legacy-hash" {
					data = bytes.Replace(data, []byte(`"expected_model_sha256"`), []byte(`"model_sha256"`), 1)
				}
				if field == "null" {
					data = bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1)
				}
				if field == "duplicate" {
					data = append(data[:len(data)-1], []byte(`,"output":"second"}`)...)
				}
				w.Write(data)
			}))
			defer srv.Close()
			c, err := newGPUProbeClient(srv.URL, ph, bh, probeTestBaseline(), probeTestKey())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Probe(context.Background(), ref.Name); err == nil {
				t.Fatal("tampered binding passed")
			}
		})
	}
}

func TestGPUProbeBackendModelSwitchAndBounds(t *testing.T) {
	for _, scenario := range []string{"pre-alias", "post-alias", "no-content", "oversize-output", "oversize-body", "backend-error", "duplicate-content", "too-many-models", "redirect", "compressed"} {
		t.Run(scenario, func(t *testing.T) {
			var modelCalls atomic.Int32
			_, c, _ := newProbeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/models" {
					n := modelCalls.Add(1)
					alias := "approved.gguf"
					if scenario == "pre-alias" || (scenario == "post-alias" && n == 2) {
						alias = "other.gguf"
					}
					models := []map[string]string{{"id": alias}}
					if scenario == "too-many-models" {
						models = append(models, map[string]string{"id": "other.gguf"})
					}
					json.NewEncoder(w).Encode(map[string]any{"data": models})
					return
				}
				switch scenario {
				case "no-content":
					w.Write([]byte(`{}`))
				case "oversize-body":
					w.Write([]byte(strings.Repeat("x", maxProbeBody+1)))
				case "backend-error":
					http.Error(w, "backend secret "+strings.Repeat("d", 64), 500)
				case "duplicate-content":
					w.Write([]byte(`{"content":"a","content":"b"}`))
				case "redirect":
					http.Redirect(w, r, "/slots", 302)
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write([]byte("garbage"))
				default:
					output := "answer"
					if scenario == "oversize-output" {
						output = strings.Repeat("x", maxProbeOutput+1)
					}
					json.NewEncoder(w).Encode(map[string]string{"content": output})
				}
			}))
			output, err := c.Probe(context.Background(), "known-answer")
			if err == nil || output != "" || strings.Contains(err.Error(), strings.Repeat("d", 64)) || strings.Contains(err.Error(), "backend secret") {
				t.Fatalf("backend failure exposed output/error: %q %v", output, err)
			}
		})
	}
}

func TestGPUProbeHTTPExchangeTimeoutAndConcurrency(t *testing.T) {
	entered := make(chan struct{}, 2)
	_, c, srv := newProbeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	done := make(chan error, 2)
	start := time.Now()
	for i := 0; i < 2; i++ {
		go func() { _, err := c.Probe(context.Background(), "known-answer"); done <- err }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("bounded concurrency did not start")
		}
	}
	data, _ := json.Marshal(signedProbeRequest(900))
	status, _ := sendProbeRaw(t, srv.URL, "/v1/probe", data)
	if status != 503 {
		t.Fatalf("third concurrent execution accepted: %d", status)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err == nil {
			t.Fatal("timed out backend passed")
		}
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("exchange exceeded bound: %s", elapsed)
	}
}

func TestGPUProbePolicySubsetAndEnrollment(t *testing.T) {
	ph, bh := probeTestPins()
	valid := "version: 1\ngpu:\n  mode: required\n  runtime:\n    profile_sha256: " + ph + "\n    baseline_sha256: " + bh + "\n    origin: ignored\nroot_unrelated: value\n"
	if _, gotPH, gotBH, err := decodeGPUProbePolicy([]byte(valid)); err != nil || gotPH != ph || gotBH != bh {
		t.Fatal("approved policy subset failed", err)
	}
	for _, data := range []string{strings.Replace(valid, "required", "no_gpu", 1), strings.Replace(valid, ph, "\"\"", 1), valid + "gpu: {}\n", valid + "---\n{}\n", valid + "unexpected:\n  a: 1\n  a: 2\n", valid + "alias: &anchor {a: 1}\ncopy: *anchor\n"} {
		if _, _, _, err := decodeGPUProbePolicy([]byte(data)); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	for _, mode := range []string{"required", "optional", "no_gpu"} {
		if got, _, _, err := decodeGPUProbePolicySubset([]byte("version: 1\ngpu:\n  mode: " + mode + "\n")); err != nil || got != mode {
			t.Fatal("condition must not require enrollment pins", mode, err)
		}
	}
	for _, mutate := range []func(*Baseline){func(b *Baseline) { b.SentinelRefs[0].ModelFilename = "" }, func(b *Baseline) { b.SentinelRefs[0].ModelSHA256 = strings.Repeat("f", 64) }, func(b *Baseline) { b.SentinelRefs[0].ModelFilename = "../approved.gguf" }, func(b *Baseline) { b.SentinelRefs[0].ModelFilename = "unsafe,alias.gguf" }, func(b *Baseline) { b.SentinelRefs[0].Input = strings.Repeat("x", 4097) }, func(b *Baseline) { b.SentinelRefs = append(b.SentinelRefs, b.SentinelRefs[0]) }} {
		b := probeTestBaseline()
		mutate(b)
		if baselineCoversGPUProbe(b, ProbeSentinelInfer) || baselineCoversGPUProbe(b, ProbeReferenceDrift) {
			t.Fatal("unbound baseline accepted")
		}
	}
}

func TestGPUProbeOriginsAndDriftFailure(t *testing.T) {
	ph, bh := probeTestPins()
	for _, origin := range []string{"http://localhost:8497", "http://example.com:8497", "http://127.0.0.1:8465", "http://127.0.0.1:8497/completion", "http://127.0.0.1:8497?x=1", "http://user@127.0.0.1:8497", "https://127.0.0.1:8497"} {
		if _, err := NewGPUProbeClient(origin, ph, bh, probeTestBaseline(), probeTestKey()); err == nil {
			t.Fatal("unsafe native origin accepted", origin)
		}
	}
	var calls atomic.Int32
	_, c, _ := newProbeFixture(t, normalProbeBackend(t, &calls))
	r := NewProbeRunner(&IntegrityProfile{}, probeTestBaseline())
	r.probeClient = c
	for _, iterations := range []string{"0", "-1", "4", "10000000", "3extra"} {
		result := r.runReferenceDrift(ProbeConfig{Name: "drift", Settings: map[string]string{"iterations": iterations}})
		if result.Status != StatusError {
			t.Fatal("invalid iteration bound passed", iterations)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := r.runReferenceDriftContext(ctx, ProbeConfig{Name: "drift"}); result.Status != StatusError {
		t.Fatal("failed iteration became healthy")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid iterations reached backend")
	}
}

func TestGPUProbeSharedKeyCannotAuthorizeBackend(t *testing.T) {
	ph, bh := probeTestPins()
	if _, err := newGPUProbeServer(ph, bh, probeTestBaseline(), bytes.Repeat([]byte{0xdd}, 32), strings.Repeat("d", 64)); err == nil {
		t.Fatal("observer HMAC key also authorizes backend")
	}
}

func TestGPUProbeLowSimilarityNeverPassesOrProducesNegativeScore(t *testing.T) {
	_, c, _ := newProbeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Write([]byte(`{"data":[{"id":"approved.gguf"}]}`))
			return
		}
		w.Write([]byte(`{"content":"wrong response"}`))
	}))
	runner := NewProbeRunner(&IntegrityProfile{}, probeTestBaseline())
	runner.probeClient = c
	result := runner.runSentinelInference(ProbeConfig{Name: "sentinel", Settings: map[string]string{"similarity_threshold": "0.1"}})
	if result.Status != StatusFail || result.Score != 1 {
		t.Fatalf("low similarity escaped hard failure: %+v", result)
	}
}

func TestGPUProbeClientBodyAndHeaderLimits(t *testing.T) {
	ph, bh := probeTestPins()
	for _, scenario := range []string{"body", "header"} {
		t.Run(scenario, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "header" {
					w.Header().Set("X-Large", strings.Repeat("x", 17<<10))
					w.Write([]byte(`{}`))
					return
				}
				w.Write([]byte(strings.Repeat("x", maxProbeBody+1)))
			}))
			defer srv.Close()
			c, err := newGPUProbeClient(srv.URL, ph, bh, probeTestBaseline(), probeTestKey())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Probe(context.Background(), "known-answer"); err == nil {
				t.Fatal("unbounded response accepted")
			}
		})
	}
}

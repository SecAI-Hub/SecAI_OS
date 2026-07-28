package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func setupTestPolicy() {
	containmentDisabled.Store(false)
	policyMu.Lock()
	policy = AirlockPolicy{
		Enabled:             true,
		AllowedDestinations: []string{"https://huggingface.co/"},
		ContentRules: ContentRules{
			ScanForPII:         true,
			ScanForCredentials: true,
		},
		AllowedMethods: []string{"GET", "POST"},
		MaxBodySize:    1024 * 1024,
	}
	sourcePrefixes = nil
	policyMu.Unlock()
}

func TestHealthEndpoint(t *testing.T) {
	setupTestPolicy()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["enabled"] != true {
		t.Fatalf("expected enabled=true, got %v", body["enabled"])
	}
}

func TestBlockedWhenDisabled(t *testing.T) {
	policyMu.Lock()
	policy = AirlockPolicy{Enabled: false}
	policyMu.Unlock()

	body := `{"destination":"https://example.com","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked when disabled")
	}
	if resp.Reason != "airlock is disabled" {
		t.Fatalf("unexpected reason: %s", resp.Reason)
	}
}

func TestContainmentDisablePersistsAndBlocksEgress(t *testing.T) {
	setupTestPolicy()
	t.Cleanup(func() { containmentDisabled.Store(false) })
	statePath := filepath.Join(t.TempDir(), "containment.json")
	t.Setenv("AIRLOCK_CONTAINMENT_STATE_PATH", statePath)

	body := `{"action":"disable","incident_id":"INC-20260727-0001","reason":"test"}`
	w := httptest.NewRecorder()
	handleDisable(
		w,
		httptest.NewRequest(http.MethodPost, "/api/v1/disable", strings.NewReader(body)),
	)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !containmentDisabled.Load() {
		t.Fatal("containment latch was not activated")
	}
	containmentDisabled.Store(false)
	if err := loadContainmentState(); err != nil {
		t.Fatalf("reload containment state: %v", err)
	}
	if !containmentDisabled.Load() {
		t.Fatal("containment latch did not survive reload")
	}

	checkBody := `{"destination":"https://huggingface.co/model","method":"GET","body":""}`
	check := httptest.NewRecorder()
	handleEgressCheck(
		check,
		httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(checkBody)),
	)
	var response EgressResponse
	if err := json.Unmarshal(check.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Allowed || !strings.Contains(response.Reason, "incident containment") {
		t.Fatalf("latched airlock must deny egress: %+v", response)
	}
}

func TestAirlockMuxProtectsDisable(t *testing.T) {
	setupTestPolicy()
	serviceToken = "test-service-token"
	containmentToken = "test-containment-token"
	t.Cleanup(func() {
		serviceToken = ""
		containmentToken = ""
	})
	w := httptest.NewRecorder()
	newAirlockMux().ServeHTTP(
		w,
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/disable",
			strings.NewReader(`{"action":"disable","incident_id":"INC-1"}`),
		),
	)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected unauthenticated disable to be forbidden, got %d", w.Code)
	}
}

func TestAirlockContainmentCredentialCannotUseGeneralEgressRoute(t *testing.T) {
	setupTestPolicy()
	serviceToken = "general-airlock-token"
	containmentToken = "containment-only-token"
	t.Cleanup(func() {
		serviceToken = ""
		containmentToken = ""
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/egress/check",
		strings.NewReader(`{"destination":"https://huggingface.co/model","method":"GET"}`),
	)
	req.Header.Set("Authorization", "Bearer containment-only-token")
	w := httptest.NewRecorder()
	newAirlockMux().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("containment token must not authorize general egress routes, got %d", w.Code)
	}
}

func TestAirlockGeneralCredentialCannotDisable(t *testing.T) {
	setupTestPolicy()
	serviceToken = "general-airlock-token"
	containmentToken = "containment-only-token"
	t.Cleanup(func() {
		serviceToken = ""
		containmentToken = ""
		containmentDisabled.Store(false)
	})

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/disable",
		strings.NewReader(`{"action":"disable","incident_id":"INC-1"}`),
	)
	req.Header.Set("Authorization", "Bearer general-airlock-token")
	w := httptest.NewRecorder()
	newAirlockMux().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("general airlock token must not authorize containment, got %d", w.Code)
	}
	if containmentDisabled.Load() {
		t.Fatal("unauthorized disable request changed containment state")
	}
}

func TestAllowValidDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got: %s", resp.Reason)
	}
}

func TestRejectLookalikeDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co.evil.example/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for lookalike hostname")
	}
}

func TestBlockUnknownDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://evil.com/payload","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for unknown destination")
	}
}

func TestBlockHTTPDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"http://huggingface.co/models/test","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for HTTP (non-HTTPS)")
	}
}

func TestBlockLocalhostDestination(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://localhost/secret","method":"GET","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for localhost")
	}
}

func TestBlockSSN(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"POST","body":"my ssn is 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for SSN in body")
	}
}

func TestBlockCredential(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"POST","body":"api_key=sk-abc123secret"}` // gitleaks:allow
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for credential in body")
	}
}

func TestBlockDisallowedMethod(t *testing.T) {
	setupTestPolicy()
	body := `{"destination":"https://huggingface.co/api","method":"DELETE","body":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)

	var resp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Allowed {
		t.Fatal("expected blocked for DELETE method")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/egress/check", nil)
	w := httptest.NewRecorder()
	handleEgressCheck(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRejectPrivateAndMetadataAddresses(t *testing.T) {
	for _, destination := range []string{
		"https://127.9.8.7/secret",
		"https://10.1.2.3/secret",
		"https://172.20.1.2/secret",
		"https://192.168.1.2/secret",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/secret",
		"https://[fe80::1]/secret",
		"https://[fd00::1]/secret",
	} {
		if err := validateDestination(destination); err == nil {
			t.Errorf("expected %s to be rejected", destination)
		}
	}
}

func TestBlockedIPClassification(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.169.254",
		"100.64.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1",
		"203.0.113.1", "::1", "fe80::1", "fd00::1", "2001:db8::1",
	} {
		if !isBlockedIP(net.ParseIP(raw)) {
			t.Errorf("expected %s to be blocked", raw)
		}
	}
	if isBlockedIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("expected public unicast address to be allowed")
	}
}

func TestRateLimitKeyIgnoresCallerServiceLabel(t *testing.T) {
	first := httptest.NewRequest(http.MethodPost, "/v1/egress/check", nil)
	first.RemoteAddr = "192.0.2.10:41000"
	first.Header.Set("X-SecAI-Service", "ui")
	second := httptest.NewRequest(http.MethodPost, "/v1/egress/check", nil)
	second.RemoteAddr = "192.0.2.10:41001"
	second.Header.Set("X-SecAI-Service", "rotated-identity")
	if rateLimitKey(first) != rateLimitKey(second) {
		t.Fatal("caller-controlled label changed the authenticated rate bucket")
	}
}

func TestServiceTokenFailsClosedWhenUnavailable(t *testing.T) {
	original := serviceToken
	serviceToken = ""
	t.Cleanup(func() { serviceToken = original })

	called := false
	handler := requireServiceToken(func(http.ResponseWriter, *http.Request) {
		called = true
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Fatal("handler must not run without service authentication")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestServiceTokenRequired(t *testing.T) {
	original := serviceToken
	serviceToken = "expected-token"
	t.Cleanup(func() { serviceToken = original })

	handler := requireServiceToken(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid token, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer expected-token")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected authenticated handler response, got %d", w.Code)
	}
}

func TestAuditDestinationDropsSignedQuery(t *testing.T) {
	got := safeAuditDestination("https://example.com/model.gguf?token=secret&signature=abc")
	if strings.Contains(got, "secret") || strings.Contains(got, "signature") {
		t.Fatalf("audit destination leaked query credentials: %s", got)
	}
	if !strings.Contains(got, "example.com/model.gguf") {
		t.Fatalf("audit destination lost route information: %s", got)
	}
}

func TestRejectTrailingOrUnknownJSON(t *testing.T) {
	setupTestPolicy()
	for _, body := range []string{
		`{"destination":"https://huggingface.co/model","method":"GET"} {}`,
		`{"destination":"https://huggingface.co/model","method":"GET","unexpected":true}`,
	} {
		w := httptest.NewRecorder()
		handleEgressCheck(
			w,
			httptest.NewRequest(http.MethodPost, "/v1/egress/check", strings.NewReader(body)),
		)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected malformed request to be rejected, got %d", w.Code)
		}
	}
}

func TestPolicyValidationRejectsUnsafeLimitsAndAllowlistURLs(t *testing.T) {
	for _, pol := range []AirlockPolicy{
		{MaxResponseSize: maxConfiguredResponse + 1},
		{MaxBodySize: -1},
		{RateLimit: RateConfig{RequestsPerMinute: maxConfiguredRPM + 1}},
		{AllowedDestinations: []string{"https://user:pass@example.com/models"}},
		{AllowedDestinations: []string{"https://example.com/models?token=value"}},
		{AllowedMethods: []string{"CONNECT"}},
	} {
		if err := validatePolicy(pol); err == nil {
			t.Fatalf("expected unsafe policy to be rejected: %+v", pol)
		}
	}
}

func TestConfigurationReloadIsAtomicAndMissingSourcesClearOldEntries(t *testing.T) {
	previous := getSnapshot()
	t.Cleanup(func() {
		policyMu.Lock()
		policy = previous.policy
		sourcePrefixes = previous.sourcePrefixes
		policyMu.Unlock()
	})

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	sourcesPath := filepath.Join(dir, "sources.yaml")
	t.Setenv("POLICY_PATH", policyPath)
	t.Setenv("SOURCES_ALLOWLIST_PATH", sourcesPath)
	policyYAML := `airlock:
  enabled: true
  allowed_destinations: ["https://example.com/models/"]
  allowed_methods: ["GET"]
  max_response_size: 4096
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		sourcesPath,
		[]byte("models:\n  - name: extra\n    url_prefix: https://cdn.example.com/files/\n"),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if err := loadConfiguration(); err != nil {
		t.Fatalf("initial configuration: %v", err)
	}
	initial := getSnapshot()
	if len(initial.sourcePrefixes) != 1 {
		t.Fatalf("expected staged source prefix, got %#v", initial.sourcePrefixes)
	}

	if err := os.WriteFile(sourcesPath, []byte("models: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfiguration(); err == nil {
		t.Fatal("expected malformed sources to reject the complete reload")
	}
	afterFailure := getSnapshot()
	if len(afterFailure.sourcePrefixes) != 1 ||
		afterFailure.sourcePrefixes[0] != initial.sourcePrefixes[0] {
		t.Fatal("failed reload partially changed the active source snapshot")
	}

	if err := os.Remove(sourcesPath); err != nil {
		t.Fatal(err)
	}
	if err := loadConfiguration(); err != nil {
		t.Fatalf("reload without optional sources file: %v", err)
	}
	if prefixes := getSourcePrefixes(); len(prefixes) != 0 {
		t.Fatalf("deleted sources file retained stale prefixes: %#v", prefixes)
	}
}

func TestFetchRequiresPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/fetch", nil)
	w := httptest.NewRecorder()
	handleFetch(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestFetchDoesNotForwardBytePastResponseLimit(t *testing.T) {
	setupTestPolicy()
	policyMu.Lock()
	policy.MaxResponseSize = 4
	policyMu.Unlock()

	originalClient := fetchClient
	fetchClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Length": []string{"999"},
				},
				Body:    io.NopCloser(strings.NewReader("12345")),
				Request: req,
			}, nil
		}),
	}
	t.Cleanup(func() { fetchClient = originalClient })

	rateMu.Lock()
	rateBuckets = make(map[string]*rateBucket)
	rateMu.Unlock()
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/fetch",
		strings.NewReader(`{"destination":"https://huggingface.co/model","method":"GET"}`),
	)
	req.RemoteAddr = "203.0.113.20:1234"
	w := httptest.NewRecorder()
	handleFetch(w, req)

	if got := w.Body.String(); got != "1234" {
		t.Fatalf("expected exactly four forwarded bytes, got %q", got)
	}
	result := w.Result()
	if result.Header.Get("Content-Length") == "999" {
		t.Fatal("upstream Content-Length must not be forwarded across a capped stream")
	}
	if result.Trailer.Get("X-SecAI-Response-Truncated") != "true" {
		t.Fatal("expected truncation trailer")
	}
}

func TestFetchResponseHeaderDropsSignedQuery(t *testing.T) {
	setupTestPolicy()
	originalClient := fetchClient
	fetchClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			redirected, err := url.Parse(
				"https://huggingface.co/model.gguf?token=private-signature",
			)
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader("model")),
				ContentLength: 5,
				Request:       &http.Request{URL: redirected},
			}, nil
		}),
	}
	t.Cleanup(func() { fetchClient = originalClient })

	w := httptest.NewRecorder()
	handleFetch(
		w,
		httptest.NewRequest(
			http.MethodPost,
			"/v1/fetch",
			strings.NewReader(
				`{"destination":"https://huggingface.co/model.gguf?token=request-secret","method":"GET"}`,
			),
		),
	)
	header := w.Result().Header.Get("X-SecAI-Upstream-URL")
	if strings.Contains(header, "token") || strings.Contains(header, "private-signature") {
		t.Fatalf("upstream URL response header leaked a signed query: %q", header)
	}
	if header != "https://huggingface.co/model.gguf" {
		t.Fatalf("unexpected sanitized upstream URL: %q", header)
	}
}

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fetchAuditRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/v1/fetch", strings.NewReader(`{"destination":"https://huggingface.co/private-path?token=private-query","method":"GET","headers":{"Authorization":"Bearer private-header"}}`))
}
func TestAuditFailurePreventsUpstreamDial(t *testing.T) {
	for _, kind := range []string{"enospc", "shortwrite", "sync", "dirsync", "path"} {
		t.Run(kind, func(t *testing.T) {
			setupTestPolicy(t)
			old := fetchClient
			defer func() { fetchClient = old }()
			dialed := 0
			fetchClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { dialed++; return nil, syscall.EIO })}
			switch kind {
			case "enospc":
				auditLog.write = func([]byte) (int, error) { return 0, syscall.ENOSPC }
			case "shortwrite":
				auditLog.write = func(p []byte) (int, error) { return len(p) - 1, nil }
			case "sync":
				auditLog.syncFile = func() error { return syscall.EIO }
			case "dirsync":
				auditLog.syncDir = func() error { return syscall.EIO }
			case "path":
				os.Rename(auditLog.path, auditLog.path+".moved")
			}
			w := httptest.NewRecorder()
			handleFetch(w, fetchAuditRequest())
			if w.Code != 503 || dialed != 0 {
				t.Fatalf("status=%d upstream_dials=%d", w.Code, dialed)
			}
			h := httptest.NewRecorder()
			handleHealth(h, httptest.NewRequest("GET", "/health", nil))
			if h.Code != 503 {
				t.Fatal("audit failure not reflected by readiness")
			}
		})
	}
}
func TestRedirectRequiresAnotherDurableIntent(t *testing.T) {
	setupTestPolicy(t)
	old := fetchClient
	defer func() { fetchClient = old }()
	calls := 0
	original := auditLog.write
	fetchClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		// Persist this first response's headers, then fail the next redirected intent.
		writes := 0
		auditLog.write = func(p []byte) (int, error) {
			writes++
			if writes > 1 {
				return 0, syscall.ENOSPC
			}
			return original(p)
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://huggingface.co/redirected"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	w := httptest.NewRecorder()
	handleFetch(w, fetchAuditRequest())
	if w.Code != 503 || calls != 1 {
		t.Fatalf("status=%d attempts=%d", w.Code, calls)
	}
}
func TestAuditFetchRecordsOutcomesWithoutSecrets(t *testing.T) {
	setupTestPolicy(t)
	old := fetchClient
	defer func() { fetchClient = old }()
	fetchClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("test")), ContentLength: 4, Request: r}, nil
	})}
	w := httptest.NewRecorder()
	handleFetch(w, fetchAuditRequest())
	if w.Code != 200 || w.Body.String() != "test" {
		t.Fatal(w.Code, w.Body.String())
	}
	data, err := os.ReadFile(auditLog.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-path", "private-query", "private-header", "Authorization", "Bearer"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("audit exposed %s", secret)
		}
	}
	for _, event := range []string{"fetch-intent", "fetch-headers", "fetch-finished", "complete", "bytes_forwarded"} {
		if !strings.Contains(string(data), event) {
			t.Fatal("missing outcome", event)
		}
	}
}
func TestFinalAuditFailureReportedAsTrailerAndReadinessFailure(t *testing.T) {
	setupTestPolicy(t)
	old := fetchClient
	defer func() { fetchClient = old }()
	original := auditLog.write
	writes := 0
	auditLog.write = func(p []byte) (int, error) {
		writes++
		if writes == 3 {
			return 0, syscall.ENOSPC
		}
		return original(p)
	}
	fetchClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("test")), ContentLength: 4, Request: r}, nil
	})}
	w := httptest.NewRecorder()
	handleFetch(w, fetchAuditRequest())
	if w.Body.String() != "test" || w.Result().Trailer.Get("X-SecAI-Audit-Available") != "false" || auditLog.Ready() == nil {
		t.Fatal("lost completion evidence concealed")
	}
}
func TestContainmentSurvivesAuditAndPersistenceFailures(t *testing.T) {
	for _, persistFails := range []bool{false, true} {
		t.Run("containment", func(t *testing.T) {
			setupTestPolicy(t)
			defer containmentDisabled.Store(false)
			dir := t.TempDir()
			state := filepath.Join(dir, "state.json")
			if persistFails {
				os.WriteFile(filepath.Join(dir, "blocked"), nil, 0600)
				state = filepath.Join(dir, "blocked", "state.json")
			}
			t.Setenv("AIRLOCK_CONTAINMENT_STATE_PATH", state)
			auditLog.write = func([]byte) (int, error) { return 0, syscall.ENOSPC }
			w := httptest.NewRecorder()
			handleDisable(w, httptest.NewRequest("POST", "/api/v1/disable", strings.NewReader(`{"action":"disable","incident_id":"synthetic"}`)))
			var body map[string]any
			if json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatal(w.Body.String())
			}
			if !containmentDisabled.Load() || body["status"] != "disabled" || body["evidence_available"] != false || body["persisted"] == persistFails {
				t.Fatal(body)
			}
			check := httptest.NewRecorder()
			handleEgressCheck(check, httptest.NewRequest("POST", "/v1/egress/check", strings.NewReader(`{"destination":"https://huggingface.co/","method":"GET"}`)))
			var decision EgressResponse
			json.Unmarshal(check.Body.Bytes(), &decision)
			if decision.Allowed {
				t.Fatal("containment undone by missing audit")
			}
		})
	}
}
func TestAuditFailureDeniesAllowAndReload(t *testing.T) {
	setupTestPolicy(t)
	auditLog.failed = true
	w := httptest.NewRecorder()
	handleEgressCheck(w, httptest.NewRequest("POST", "/v1/egress/check", strings.NewReader(`{"destination":"https://huggingface.co/","method":"GET"}`)))
	var response EgressResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 503 || response.Allowed || response.EvidenceAvailable {
		t.Fatal(w.Code, response)
	}
	// Valid new policy/sources cannot clear an audit failure or publish a snapshot.
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(policyPath, []byte("airlock:\n  enabled: false\n"), 0600)
	t.Setenv("POLICY_PATH", policyPath)
	t.Setenv("SOURCES_ALLOWLIST_PATH", filepath.Join(t.TempDir(), "missing"))
	reload := httptest.NewRecorder()
	handleReload(reload, httptest.NewRequest("POST", "/v1/reload", nil))
	if reload.Code == 200 || !getPolicy().Enabled || auditLog.Ready() == nil {
		t.Fatal("reload bypassed audit failure")
	}
}

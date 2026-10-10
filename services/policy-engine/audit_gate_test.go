package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestAuditFailuresNeverReturnPolicyAllow(t *testing.T) {
	for _, kind := range []string{"enospc", "shortwrite", "sync", "dirsync", "path"} {
		t.Run(kind, func(t *testing.T) {
			setupTestPolicies(t)
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
			handleDecide(w, httptest.NewRequest("POST", "/api/v1/decide", strings.NewReader(`{"domain":"tool_access","subject":"filesystem.read"}`)))
			var resp DecisionResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != 503 || resp.Decision != "deny" || resp.EvidenceAvailable {
				t.Fatal(w.Code, resp)
			}
			h := httptest.NewRecorder()
			handleHealth(h, httptest.NewRequest("GET", "/health", nil))
			if h.Code != 503 {
				t.Fatal("readiness remained passing")
			}
			old, digest := getPolicy()
			r := httptest.NewRecorder()
			handleReload(r, httptest.NewRequest("POST", "/api/v1/reload", nil))
			_, after := getPolicy()
			if r.Code == 200 || after != digest || auditLog.Ready() == nil {
				t.Fatal("reload cleared failure", old)
			}
		})
	}
}
func TestPolicyDenyWorksWithoutEvidence(t *testing.T) {
	setupTestPolicies(t)
	auditLog.failed = true
	w := httptest.NewRecorder()
	handleDecide(w, httptest.NewRequest("POST", "/api/v1/decide", strings.NewReader(`{"domain":"tool_access","subject":"system.exec"}`)))
	var resp DecisionResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != 200 || resp.Decision != "deny" || resp.EvidenceAvailable {
		t.Fatal(w.Code, resp)
	}
}
func TestPolicyAuditMinimizesUntrustedFields(t *testing.T) {
	setupTestPolicies(t)
	w := httptest.NewRecorder()
	handleDecide(w, httptest.NewRequest("POST", "/api/v1/decide", strings.NewReader(`{"domain":"tool_access","subject":"private-subject?token=private-credential","action":"private-action","params":{"body":"private-body"}}`)))
	data, err := os.ReadFile(auditLog.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") {
		t.Fatal("raw subject/action/body/credential exposed")
	}
	if !strings.Contains(string(data), "subject_hash") || !strings.Contains(string(data), "input_hash") {
		t.Fatal("missing decision binding")
	}
}

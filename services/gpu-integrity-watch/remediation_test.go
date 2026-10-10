package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRequiredEvidenceAndFailurePrecedence(t *testing.T) {
	cases := []struct {
		name    string
		results []ProbeResult
		want    Verdict
	}{
		{"empty", nil, VerdictUnknown},
		{"skip", []ProbeResult{{Status: StatusSkip}}, VerdictUnknown},
		{"error and pass", []ProbeResult{{Status: StatusError}, {Status: StatusPass}}, VerdictUnknown},
		{"unknown enum", []ProbeResult{{Status: "unexpected"}}, VerdictUnknown},
		{"small drift", []ProbeResult{{Status: StatusDrift, Score: 0.001}, {Status: StatusPass}}, VerdictWarning},
		{"skip before failure", []ProbeResult{{Status: StatusSkip}, {Status: StatusFail}}, VerdictCritical},
		{"failure before skip", []ProbeResult{{Status: StatusFail}, {Status: StatusSkip}}, VerdictCritical},
		{"invalid score", []ProbeResult{{Status: StatusPass, Score: math.NaN()}}, VerdictUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyVerdict(0, tc.results); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAnyChangedModelFailsAndCarriesIdentity(t *testing.T) {
	dir := t.TempDir()
	baseline := &Baseline{TensorHashes: map[string]string{}}
	for _, name := range []string{"one.gguf", "two.gguf", "three.gguf", "four.gguf"} {
		writeFile(t, dir, name, "approved")
		baseline.TensorHashes[name] = sha256Hex("approved")
	}
	writeFile(t, dir, "one.gguf", "changed")
	r := NewProbeRunner(&IntegrityProfile{ModelDir: dir}, baseline).runTensorHash(ProbeConfig{Name: "hash"})
	if r.Status != StatusFail || !reflect.DeepEqual(r.ModelPaths, []string{filepath.Join(dir, "one.gguf")}) {
		t.Fatalf("one mismatch among four must fail with model identity: %+v", r)
	}
	writeFile(t, dir, "one.gguf", "approved")
	writeFile(t, dir, "extra.gguf", "unapproved")
	r = NewProbeRunner(&IntegrityProfile{ModelDir: dir}, baseline).runTensorHash(ProbeConfig{Name: "hash"})
	if r.Status != StatusFail {
		t.Fatalf("unapproved artifact was accepted: %+v", r)
	}
}

func TestModelScanRejectsIncompleteAndUnsafeTrees(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "model.gguf", "data")
	if err := os.Symlink(filepath.Join(dir, "model.gguf"), filepath.Join(dir, "link.gguf")); err != nil {
		t.Fatal(err)
	}
	if _, err := hashModelFiles(dir, []string{"*.gguf"}); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := hashModelFiles(filepath.Join(dir, "missing"), []string{"*.gguf"}); err == nil {
		t.Fatal("missing tree accepted")
	}
}

func TestShutdownNeverClaimsUnverifiedContainment(t *testing.T) {
	for _, status := range []int{200, 401, 404, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		r := NewActionExecutor(nil, "", srv.URL).executeFailClosed(ActionConfig{Name: "stop", Type: ActionFailClosed})
		srv.Close()
		if r.Success {
			t.Fatalf("HTTP %d incorrectly proves containment", status)
		}
	}
}

func TestGPUReportUsesRecorderWireContract(t *testing.T) {
	var reports []IncidentReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/incidents/report" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("incorrect report destination/credential")
		}
		// String-only evidence is the real recorder's wire contract.
		var report IncidentReport
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&report); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		reports = append(reports, report)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	paths := []string{"/var/lib/secure-ai/vault/models/a.gguf", "/var/lib/secure-ai/vault/models/b.gguf"}
	reportIncident(srv.URL, "fixture", ScoreEntry{Verdict: VerdictCritical, CompositeScore: 1, ProbeStatuses: map[string]ProbeStatus{"hash": StatusFail}}, []ProbeResult{{Probe: "hash", Type: ProbeTensorHash, Status: StatusFail, ModelPaths: paths}})
	if len(reports) != 2 {
		t.Fatalf("got %d reports", len(reports))
	}
	for i, report := range reports {
		if report.Class != "manifest_mismatch" || report.Evidence["model_path"] != paths[i] || report.Evidence["schema_version"] != "1" {
			t.Fatalf("invalid targeted incident: %+v", report)
		}
	}
}

func TestHTTPBaselineEnrollmentIsAlwaysDenied(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/baseline", nil)
	r.Header.Set("Authorization", "Bearer monitoring-token")
	baselineEnrollmentDisabled(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("monitoring token can change trust: %d", w.Code)
	}
}

func TestPartialLivePolicyReloadIsUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	maintenanceReloadRequired(w, httptest.NewRequest(http.MethodPost, "/v1/reload", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("live partial policy reload was accepted: %d", w.Code)
	}
}

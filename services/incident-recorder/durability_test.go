package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportCannotAcknowledgeLostStorage(t *testing.T) {
	for _, failure := range []string{"store", "audit"} {
		t.Run(failure, func(t *testing.T) {
			resetGlobalState(t)
			if failure == "store" {
				incidentStorePath = filepath.Join(t.TempDir(), "missing", "incidents.jsonl")
			} else {
				auditFile.Close()
			}
			w, _ := reportIncidentHTTP(t, IncidentReport{Class: ClassIntegrityViolation, Source: "gpu-integrity-watch", Description: "fixture fault"})
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("lost %s acknowledged with %d", failure, w.Code)
			}
			health := httptest.NewRecorder()
			handleHealth(health, httptest.NewRequest(http.MethodGet, "/health", nil))
			if health.Code != http.StatusServiceUnavailable {
				t.Fatal("storage fault hidden by health")
			}
			// Emergency containment still executes; no durable success is claimed.
			if got := getIncidents(); len(got) != 1 || len(got[0].ContainmentResults) == 0 {
				t.Fatal("storage loss suppressed emergency containment")
			}
		})
	}
}

func TestIncidentAuthenticationCoversEvidenceAndLifecycle(t *testing.T) {
	for _, field := range []string{"evidence", "state", "actions", "malformed"} {
		t.Run(field, func(t *testing.T) {
			resetGlobalState(t)
			inc := mustCreateIncident(t, IncidentReport{Class: ClassForbiddenAirlock, Source: "airlock", Description: "fixture", Evidence: map[string]string{"query": "original"}})
			switch field {
			case "evidence":
				inc.Evidence = map[string]string{"query": "modified"}
			case "state":
				inc.State = StateResolved
			case "actions":
				inc.ContainmentActions = []string{"freeze_agent"}
			}
			data, _ := json.Marshal(inc)
			if field == "malformed" {
				data = append(data, []byte("\n{broken")...)
			}
			if err := os.WriteFile(incidentStorePath, append(data, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := loadIncidentsFromDisk(); err == nil {
				t.Fatalf("%s tampering loaded successfully", field)
			}
		})
	}
}

func TestUnresolvedIncidentCapacityNeverDiscardsPendingRecovery(t *testing.T) {
	resetGlobalState(t)
	incidentsMu.Lock()
	for i := 0; i < maxIncidents; i++ {
		incidents = append(incidents, Incident{ID: fmt.Sprintf("INC-%d", i), State: StateContained})
	}
	incidentsMu.Unlock()
	if _, err := createIncident(IncidentReport{Class: ClassPolicyBypass, Source: "fixture", Description: "overflow"}); err == nil {
		t.Fatal("silently discarded unresolved history")
	}
	if got := getIncidents(); len(got) != maxIncidents || got[0].ID != "INC-0" {
		t.Fatal("oldest unresolved incident disappeared")
	}
}

func TestRecoveryCannotPublishStateItsReaderRejects(t *testing.T) {
	rm := NewRecoveryManagerWithPath(filepath.Join(t.TempDir(), "requirements.json"))
	if err := rm.persistLocked(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(rm.path)
	for i := 0; i < 15000; i++ {
		id := fmt.Sprintf("INC-%08d", i)
		rm.requirements[id] = &RecoveryRequirement{IncidentID: id, IncidentClass: ClassIntegrityViolation, Severity: SeverityCritical, RequiredAfter: "2026-09-04T00:00:00Z", ContainmentBinding: strings.Repeat("a", 64), RequireAck: true, RequireReattest: true}
	}
	if err := rm.persistLocked(); err == nil {
		t.Fatal("unrestartable recovery state was published")
	}
	after, _ := os.ReadFile(rm.path)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity failure replaced last readable state")
	}
}

func TestAuditTailIsBoundedAndRecent(t *testing.T) {
	resetGlobalState(t)
	f, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9000; i++ {
		fmt.Fprintf(f, "%06d %s\n", i, strings.Repeat("x", 1000))
	}
	f.Close()
	lines, err := readAuditLogTail(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "008997 ") || !strings.HasPrefix(lines[2], "008999 ") {
		t.Fatalf("incorrect bounded suffix: %d lines", len(lines))
	}
}

func TestActualRecorderAcceptsVersionedTargetedGPUReport(t *testing.T) {
	resetGlobalState(t)
	gpuReporterToken = "gpu-fixture"
	const model = "/var/lib/secure-ai/vault/models/a.gguf"
	report := map[string]any{
		"class": "manifest_mismatch", "severity": "critical", "source": "gpu-integrity-watch", "description": "GPU model file hash mismatch detected",
		"evidence": map[string]string{"schema_version": "1", "verdict": "critical", "composite_score": "1.000000", "probe_statuses": `{"hash":"fail"}`, "failed_probes": `["hash"]`, "model_path": model},
	}
	called := false
	containmentExecutor = func(inc Incident, _ ServiceEndpoints, _ string) ([]ContainmentResult, bool) {
		called = true
		if inc.Evidence["model_path"] != model {
			t.Fatal("model identity lost before containment")
		}
		return []ContainmentResult{{Action: "quarantine_model", Success: true, CompletedAt: "2026-09-04T00:00:00Z"}, {Action: "freeze_agent", Success: true, CompletedAt: "2026-09-04T00:00:00Z"}}, true
	}
	data, _ := json.Marshal(report)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/report", bytes.NewReader(data))
	r.Header.Set("Authorization", "Bearer gpu-fixture")
	w := httptest.NewRecorder()
	newIncidentMux().ServeHTTP(w, r)
	if w.Code != http.StatusCreated || !called {
		t.Fatalf("GPU contract failed: %d %s", w.Code, w.Body.String())
	}
	if err := loadIncidentsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if got := getIncidents(); len(got) != 1 || got[0].State != StateContained {
		t.Fatal("contained report was not durable")
	}
}

func TestReviewedLegacyMigrationPreservesOriginalAndAuthenticatesOutput(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "legacy.jsonl"), filepath.Join(dir, "authenticated.jsonl")
	inc := Incident{ID: "INC-fixture", CreatedAt: "2026-09-04T00:00:00Z", Class: ClassForbiddenAirlock, Severity: SeverityMedium, State: StateOpen, Source: "airlock", Description: "reviewed fixture", Evidence: map[string]string{"status": "reviewed"}}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s", inc.ID, inc.CreatedAt, inc.Class, inc.Severity, inc.Source, inc.Description)))
	inc.Hash = hex.EncodeToString(digest[:16])
	original, _ := json.Marshal(inc)
	if err := os.WriteFile(input, append(original, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runHistoryMigration([]string{"-in", input, "-out", output}); err == nil {
		t.Fatal("migration did not require explicit offline review")
	}
	if err := migrateReviewedHistory(input, output, forensicHMACKey); err != nil {
		t.Fatal(err)
	}
	if err := migrateReviewedHistory(input, output, forensicHMACKey); err == nil {
		t.Fatal("migration overwrote an existing output")
	}
	preserved, _ := os.ReadFile(input)
	if !bytes.Equal(preserved, append(original, '\n')) {
		t.Fatal("legacy original changed")
	}
	incidentStorePath = output
	if err := loadIncidentsFromDisk(); err != nil {
		t.Fatal(err)
	}
	if getIncidents()[0].Evidence["status"] != "reviewed" {
		t.Fatal("reviewed evidence lost")
	}
}

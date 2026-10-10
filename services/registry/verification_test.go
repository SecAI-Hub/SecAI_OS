package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test executable doubles as a local inert verifier. This code is not part
// of the production binary and receives no caller-supplied command selection.
func init() {
	if len(os.Args) != 4 || os.Args[1] != "verify-manifest" {
		return
	}
	// Match the real guard's regular sidecar path requirement; proc-fd
	// symlinks must not pass this compatibility fixture.
	info, err := os.Lstat(os.Args[3])
	if err != nil || !info.Mode().IsRegular() {
		os.Exit(5)
	}
	model, err := os.ReadFile(os.Args[2])
	if err != nil || !bytes.Equal(model, []byte("tiny inert model")) {
		os.Exit(6)
	}
	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		os.Exit(7)
	}
	var control struct{ Mode, Ready, Release string }
	if json.Unmarshal(data, &control) != nil {
		os.Exit(8)
	}
	if control.Ready != "" {
		if os.WriteFile(control.Ready, []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(9)
		}
	}
	switch control.Mode {
	case "wait":
		for {
			if _, err := os.Stat(control.Release); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	case "output":
		os.Stdout.Write(bytes.Repeat([]byte("x"), maxVerifierOutput*2))
		os.Exit(0)
	}
	fmt.Println("PASS: synthetic verifier completed")
	os.Exit(0)
}

type verificationFixture struct {
	dir, ready, release string
	service             *verificationService
}

func verificationTestState(t *testing.T, mode string) verificationFixture {
	t.Helper()
	oldManifest, oldDir, oldPath, oldSource, oldDigest, oldInfo, oldGeneration, oldService := manifest, registryDir, manifestPath, manifestSource, manifestDigest, manifestSourceInfo, manifestGeneration, verification
	dir := t.TempDir()
	ready := filepath.Join(dir, "verifier.ready")
	release := filepath.Join(dir, "verifier.release")
	registryDir = dir
	manifestPath = filepath.Join(dir, "enrollment.json")
	t.Setenv("INTEGRITY_RESULT_PATH", filepath.Join(dir, "integrity.json"))
	model := []byte("tiny inert model")
	digest := sha256.Sum256(model)
	if err := os.WriteFile(filepath.Join(dir, "tiny.gguf"), model, 0600); err != nil {
		t.Fatal(err)
	}
	control, _ := json.Marshal(map[string]string{"Mode": mode, "Ready": ready, "Release": release})
	if err := os.WriteFile(filepath.Join(dir, "tiny.manifest.json"), control, 0600); err != nil {
		t.Fatal(err)
	}
	manifest = Manifest{Version: 1, Models: []Artifact{{Name: "tiny", Filename: "tiny.gguf", Format: "gguf", SizeBytes: int64(len(model)), SHA256: hex.EncodeToString(digest[:]), GGUFGuardManifest: "tiny.manifest.json"}}}
	if err := saveManifest(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	service := &verificationService{slots: make(chan struct{}, 2), timeout: 2 * time.Second, verifierPath: executable, verifierUID: uint32(os.Geteuid())}
	verification = service
	t.Cleanup(func() {
		waitVerificationIdle(t, service)
		manifestMu.Lock()
		manifest, registryDir, manifestPath, manifestSource, manifestDigest, manifestSourceInfo, manifestGeneration, verification = oldManifest, oldDir, oldPath, oldSource, oldDigest, oldInfo, oldGeneration, oldService
		manifestMu.Unlock()
	})
	return verificationFixture{dir, ready, release, service}
}

func waitVerificationIdle(t *testing.T, v *verificationService) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for len(v.slots) != 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if len(v.slots) != 0 {
		t.Fatal("owned verification work did not finish")
	}
}

func waitVerifierPID(t *testing.T, path string) int {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if data, err := os.ReadFile(path); err == nil {
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture verifier did not reach its ready point")
	return 0
}

func requestVerification(ctx context.Context, method, path string, handler http.HandlerFunc) <-chan *httptest.ResponseRecorder {
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(method, path, nil).WithContext(ctx))
		result <- recorder
	}()
	return result
}

func receiveVerification(t *testing.T, result <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case reply := <-result:
		return reply
	case <-time.After(3 * time.Second):
		t.Fatal("request completion deadline")
		return nil
	}
}

func TestEligibilityRejectsBlockedOnEveryAuthorizationRouteButKeepsDiagnostics(t *testing.T) {
	verificationTestState(t, "pass")
	manifestMu.Lock()
	manifest.Models[0].Blocked = true
	manifest.Models[0].BlockedReason = "synthetic containment"
	if err := saveManifest(); err != nil {
		t.Fatal(err)
	}
	manifestMu.Unlock()
	for _, route := range []struct {
		method, path string
		handler      http.HandlerFunc
	}{{"GET", "/v1/model/path?name=tiny", handleModelPath}, {"POST", "/v1/model/verify?name=tiny", handleVerifyModel}, {"POST", "/v1/model/verify-manifest?name=tiny", handleVerifyGGUFManifest}, {"POST", "/v1/models/verify-all", handleVerifyAll}, {"GET", "/v1/integrity/status", handleIntegrityStatus}} {
		response := httptest.NewRecorder()
		route.handler(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), `"safe_to_use":"true"`) {
			t.Fatalf("%s improperly authorized: %d %s", route.path, response.Code, response.Body)
		}
	}
	for _, handler := range []http.HandlerFunc{handleListModels, handleGetModel} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest("GET", "/v1/model?name=tiny", nil))
		if response.Code != 200 || !strings.Contains(response.Body.String(), `"blocked":true`) {
			t.Fatalf("diagnostic visibility lost: %s", response.Body)
		}
	}
}

func TestAuthorizationRejectsMissingCorruptOrReplacedEnrollment(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "same-bytes-replacement", "group-writable"} {
		t.Run(kind, func(t *testing.T) {
			verificationTestState(t, "pass")
			switch kind {
			case "missing":
				os.Remove(manifestPath)
			case "corrupt":
				os.WriteFile(manifestPath, []byte("broken"), 0600)
			case "same-bytes-replacement":
				data, _ := os.ReadFile(manifestPath)
				other := manifestPath + ".replacement"
				os.WriteFile(other, data, 0600)
				os.Rename(other, manifestPath)
			case "group-writable":
				os.Chmod(manifestPath, 0664)
			}
			for _, route := range []struct {
				method  string
				handler http.HandlerFunc
			}{{"GET", handleModelPath}, {"POST", handleVerifyModel}, {"POST", handleVerifyGGUFManifest}, {"POST", handleVerifyAll}, {"GET", handleIntegrityStatus}} {
				response := httptest.NewRecorder()
				route.handler(response, httptest.NewRequest(route.method, "/?name=tiny", nil))
				if response.Code != 503 {
					t.Fatalf("%s returned %d: %s", kind, response.Code, response.Body)
				}
			}
		})
	}
}

type stalledFixtureReader struct {
	started chan struct{}
	release chan struct{}
}

func (reader stalledFixtureReader) Read(destination []byte) (int, error) {
	close(reader.started)
	<-reader.release
	destination[0] = 'x'
	return 1, nil
}

func TestHashReadCancellationRetainsWorkerUntilReadReturns(t *testing.T) {
	reader := stalledFixtureReader{make(chan struct{}), make(chan struct{})}
	v := &verificationService{slots: make(chan struct{}, 1), timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer waitVerificationIdle(t, v)
	defer close(reader.release)
	replies := make(chan verificationReply, 1)
	go func() {
		replies <- v.run(ctx, func(ctx context.Context) verificationReply {
			return verificationReply{err: copyVerification(ctx, io.Discard, reader, 1)}
		})
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("fixture read did not start")
	}
	cancel()
	select {
	case reply := <-replies:
		if reply.err != context.Canceled || len(v.slots) != 1 {
			t.Fatalf("read cancellation lost ownership: %v slots=%d", reply.err, len(v.slots))
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request did not finish")
	}
}

func TestHistoricalSnapshotRejectsChangedEnrollmentAndCanceledPublication(t *testing.T) {
	fixture := verificationTestState(t, "pass")
	reply := verifiedAllReply(context.Background())
	if reply.err != nil || reply.body["status"] != "ok" {
		t.Fatalf("initial verification failed: %#v", reply)
	}
	previous, err := os.ReadFile(integrityResultPath())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeIntegrityResult(ctx, map[string]any{"status": "late"}); err != context.Canceled {
		t.Fatalf("canceled publication: %v", err)
	}
	if err := writeIntegrityResult(context.Background(), map[string]any{"oversized": strings.Repeat("x", maxVerificationResult)}); err != errOutput {
		t.Fatalf("unbounded publication: %v", err)
	}
	current, _ := os.ReadFile(integrityResultPath())
	if !bytes.Equal(previous, current) {
		t.Fatal("rejected publication replaced the previous snapshot")
	}
	manifestMu.Lock()
	manifest.Models[0].Name = "renamed"
	err = saveManifest()
	manifestMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	status := currentIntegrityReply(context.Background())
	if status.err != nil || status.body["status"] != "unknown" {
		t.Fatalf("old revision accepted: %#v", status)
	}
	leftovers, _ := filepath.Glob(filepath.Join(fixture.dir, ".integrity-*"))
	if len(leftovers) != 0 {
		t.Fatal("temporary snapshot files remain")
	}
}

func TestPathResolutionHashesAndRejectsSymlinkOrChangedContent(t *testing.T) {
	fixture := verificationTestState(t, "pass")
	response := httptest.NewRecorder()
	handleModelPath(response, httptest.NewRequest("GET", "/?name=tiny", nil))
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	os.WriteFile(filepath.Join(fixture.dir, "tiny.gguf"), []byte("different bytes"), 0600)
	response = httptest.NewRecorder()
	handleModelPath(response, httptest.NewRequest("GET", "/?name=tiny", nil))
	if response.Code != 409 {
		t.Fatalf("tampered path authorized: %d", response.Code)
	}
	os.Remove(filepath.Join(fixture.dir, "tiny.gguf"))
	os.Symlink("tiny.manifest.json", filepath.Join(fixture.dir, "tiny.gguf"))
	response = httptest.NewRecorder()
	handleModelPath(response, httptest.NewRequest("GET", "/?name=tiny", nil))
	if response.Code != 409 {
		t.Fatalf("symlink path authorized: %d", response.Code)
	}
}

func TestGGUFVerifierUsesProtectedExecutableAndRegularInputsAndBoundsOutput(t *testing.T) {
	for _, mode := range []string{"pass", "output"} {
		t.Run(mode, func(t *testing.T) {
			fixture := verificationTestState(t, mode)
			reply := receiveVerification(t, requestVerification(context.Background(), "POST", "/?name=tiny", handleVerifyGGUFManifest))
			if mode == "pass" {
				if reply.Code != 200 || !strings.Contains(reply.Body.String(), "synthetic verifier completed") {
					t.Fatalf("unexpected verification: %d %s", reply.Code, reply.Body)
				}
			} else if reply.Code != 409 || len(reply.Body.Bytes()) > maxVerifierOutput {
				t.Fatalf("output bound failed: %d %d", reply.Code, reply.Body.Len())
			}
			waitVerificationIdle(t, fixture.service)
			pid := waitVerifierPID(t, fixture.ready)
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
				t.Fatalf("owned child %d not reaped", pid)
			}
		})
	}
}

func TestVerifierCancellationAndDeadlineReapExactChild(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			fixture := verificationTestState(t, "wait")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline" {
				fixture.service.timeout = 250 * time.Millisecond
			}
			result := requestVerification(ctx, "POST", "/?name=tiny", handleVerifyGGUFManifest)
			pid := waitVerifierPID(t, fixture.ready)
			if kind == "cancel" {
				cancel()
			}
			reply := receiveVerification(t, result)
			expected := 408
			if kind == "deadline" {
				expected = 504
			}
			if reply.Code != expected {
				t.Fatalf("got %d want %d: %s", reply.Code, expected, reply.Body)
			}
			waitVerificationIdle(t, fixture.service)
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
				t.Fatalf("owned child %d not reaped", pid)
			}
		})
	}
}

func TestLateVerificationCannotAuthorizeMutationOrEnrollmentChange(t *testing.T) {
	for _, kind := range []string{"blocked", "model-replaced", "enrollment-corrupt", "contained"} {
		t.Run(kind, func(t *testing.T) {
			fixture := verificationTestState(t, "wait")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := requestVerification(ctx, "POST", "/?name=tiny", handleVerifyGGUFManifest)
			waitVerifierPID(t, fixture.ready)
			updated := make(chan error, 1)
			go func() {
				if kind == "enrollment-corrupt" {
					updated <- os.WriteFile(manifestPath, []byte("corrupt"), 0600)
					return
				}
				if kind == "model-replaced" {
					data, _ := os.ReadFile(filepath.Join(fixture.dir, "tiny.gguf"))
					other := filepath.Join(fixture.dir, "other.gguf")
					os.WriteFile(other, data, 0600)
					updated <- os.Rename(other, filepath.Join(fixture.dir, "tiny.gguf"))
					return
				}
				if kind == "contained" {
					directory := filepath.Join(fixture.dir, "containment")
					os.Mkdir(directory, 0700)
					t.Setenv("REGISTRY_CONTAINMENT_DIR", directory)
					body := strings.NewReader(`{"action":"quarantine","incident_id":"synthetic-incident","model_name":"tiny"}`)
					rec := httptest.NewRecorder()
					handleQuarantine(rec, httptest.NewRequest("POST", "/api/v1/quarantine", body))
					if rec.Code != 200 {
						updated <- fmt.Errorf("containment %d: %s", rec.Code, rec.Body)
					} else {
						updated <- nil
					}
					return
				}
				manifestMu.Lock()
				manifest.Models[0].Blocked = true
				err := saveManifest()
				manifestMu.Unlock()
				updated <- err
			}()
			select {
			case err := <-updated:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("safety mutation blocked behind verifier I/O")
			}
			if err := os.WriteFile(fixture.release, []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			reply := receiveVerification(t, result)
			if reply.Code == 200 || strings.Contains(reply.Body.String(), `"safe_to_use":"true"`) {
				t.Fatalf("late result authorized: %d %s", reply.Code, reply.Body)
			}
		})
	}
}

func TestAdmissionIsPromptAndRetainsSlotUntilActualWorkCompletes(t *testing.T) {
	v := &verificationService{slots: make(chan struct{}, 2), timeout: 30 * time.Millisecond}
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	replies := make(chan verificationReply, 2)
	for range 2 {
		go func() {
			replies <- v.run(context.Background(), func(ctx context.Context) verificationReply {
				started <- struct{}{}
				<-release
				return verificationReply{body: map[string]any{"status": "verified"}}
			})
		}()
	}
	<-started
	<-started
	if reply := v.run(context.Background(), func(context.Context) verificationReply { t.Error("excess work ran"); return verificationReply{} }); reply.err != errCapacity {
		t.Fatal("missing capacity rejection")
	}
	for range 2 {
		if reply := <-replies; reply.err != context.DeadlineExceeded {
			t.Fatalf("expected deadline, got %v", reply.err)
		}
	}
	if len(v.slots) != 2 {
		t.Fatal("unfinished I/O stopped consuming capacity")
	}
	close(release)
	waitVerificationIdle(t, v)
}

func TestCancellationWinsWhenResultIsAlsoReady(t *testing.T) {
	v := &verificationService{slots: make(chan struct{}, 1), timeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	reply := v.run(ctx, func(context.Context) verificationReply {
		cancel()
		return verificationReply{body: map[string]any{"safe_to_use": "true"}}
	})
	if reply.err != context.Canceled {
		t.Fatalf("canceled result escaped: %#v", reply)
	}
	waitVerificationIdle(t, v)
}

func TestProtectedVerifierRejectsWritableOrMissingExecutable(t *testing.T) {
	fixture := verificationTestState(t, "pass")
	fixture.service.verifierPath = filepath.Join(fixture.dir, "missing")
	for _, mode := range []string{"missing", "writable"} {
		if mode == "writable" {
			if err := os.WriteFile(fixture.service.verifierPath, []byte("unused"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(fixture.service.verifierPath, 0777); err != nil {
				t.Fatal(err)
			}
		}
		reply := receiveVerification(t, requestVerification(context.Background(), "POST", "/?name=tiny", handleVerifyGGUFManifest))
		if reply.Code != 503 {
			t.Fatalf("unsafe executable accepted: %d", reply.Code)
		}
	}
}

type rejectMetadataCopy struct{}

func (rejectMetadataCopy) MarshalJSON() ([]byte, error) {
	panic("oversized enrollment metadata was copied")
}

func TestSnapshotRejectsOversizedPersistedGenerationBeforeCopy(t *testing.T) {
	verificationTestState(t, "pass")
	file, err := os.OpenFile(manifestPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxManifestBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	manifestSourceInfo, err = os.Lstat(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Models[0].GGUFGuardFingerprint = map[string]interface{}{"copy_probe": rejectMetadataCopy{}}
	if _, err := enrollmentSnapshot(); err != errEnrollment {
		t.Fatalf("oversized generation admitted: %v", err)
	}
}

func directoryVerificationState(t *testing.T) (string, Artifact) {
	t.Helper()
	fixture := verificationTestState(t, "pass")
	writeTinyDiffusionModel(t, fixture.dir, "registered-directory")
	root, err := os.OpenRoot(fixture.dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, _, size, err := computeDirectoryHashStats(root, "registered-directory")
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	model := Artifact{Name: "Reviewed Diffusion Model", Filename: "registered-directory",
		Format: "diffusion-directory", SHA256: digest, SizeBytes: size}
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{model}}
	err = saveManifest()
	manifestMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return fixture.dir, model
}

func TestVerifiedPathFilenameFullContractOverHTTPAndScopedAuth(t *testing.T) {
	dir, model := directoryVerificationState(t)
	oldRead, oldVerify, oldAdmin := readToken, verifyToken, adminToken
	readToken, verifyToken, adminToken = "read-only", "verify-only", "admin-only"
	t.Cleanup(func() { readToken, verifyToken, adminToken = oldRead, oldVerify, oldAdmin })
	server := httptest.NewServer(newRegistryMux())
	defer server.Close()
	for _, test := range []struct {
		selector, token string
		want            int
	}{
		{"filename=registered-directory", "verify-only", 200},
		{"filename=registered-directory", "read-only", 403},
		{"filename=registered-directory", "", 403},
		{"filename=registered-directory", "admin-only", 200},
		{"name=Reviewed+Diffusion+Model", "admin-only", 200},
	} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/model/path?"+test.selector, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.token != "" {
			req.Header.Set("Authorization", "Bearer "+test.token)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Fatalf("scope/selector status: %d want %d", response.StatusCode, test.want)
		}
		if test.want == 200 {
			want := map[string]any{"schema_version": float64(1), "status": "verified", "safe_to_use": "true",
				"name": model.Name, "filename": model.Filename, "format": model.Format,
				"sha256": model.SHA256, "path": filepath.Join(dir, model.Filename)}
			for key, value := range want {
				if body[key] != value {
					t.Fatalf("measured contract %s: got %v want %v", key, body[key], value)
				}
			}
		}
	}
}

func TestVerifiedPathFilenameRejectsInvalidOrAmbiguousSelectors(t *testing.T) {
	directoryVerificationState(t)
	for _, selector := range []string{"", "name=", "filename=", "name=x&filename=registered-directory",
		"name=&filename=registered-directory", "filename=registered-directory&filename=registered-directory",
		"name=x&name=y", "filename=../registered-directory", "filename=%2Fregistered-directory",
		"filename=child%2F..%2Fregistered-directory", "filename=.%2Fregistered-directory",
		"filename=registered-directory%5Cx", "filename=registered-directory%00", "filename=bad%zz"} {
		reply := httptest.NewRecorder()
		handleModelPath(reply, httptest.NewRequest("GET", "/v1/model/path?"+selector, nil))
		if reply.Code != 400 || strings.Contains(reply.Body.String(), `"safe_to_use":"true"`) {
			t.Fatalf("selector %q admitted: %d %s", selector, reply.Code, reply.Body)
		}
	}
	for _, handler := range []http.HandlerFunc{handleVerifyModel, handleVerifyGGUFManifest} {
		reply := httptest.NewRecorder()
		handler(reply, httptest.NewRequest("POST", "/?filename=registered-directory", nil))
		if reply.Code != 400 {
			t.Fatalf("filename selector expanded a non-path API: %d", reply.Code)
		}
	}
	view := enrollmentView{models: []Artifact{{Filename: "x"}, {Filename: "x"}}}
	if _, err := view.modelFilename("x"); err == nil {
		t.Fatal("ambiguous filename was selected")
	}
}

func TestVerifiedPathFilenameRejectsMissingBlockedTamperedOrSymlinkTree(t *testing.T) {
	for _, kind := range []string{"unknown", "missing", "blocked", "tampered", "symlink", "duplicate-enrollment"} {
		t.Run(kind, func(t *testing.T) {
			dir, model := directoryVerificationState(t)
			filename := model.Filename
			switch kind {
			case "unknown":
				filename = "unknown"
			case "missing":
				os.RemoveAll(filepath.Join(dir, filename))
			case "tampered":
				os.WriteFile(filepath.Join(dir, filename, "model_index.json"), []byte("tampered"), 0600)
			case "symlink":
				os.Rename(filepath.Join(dir, filename), filepath.Join(dir, "moved"))
				os.Symlink("moved", filepath.Join(dir, filename))
			case "blocked":
				manifest.Models[0].Blocked = true
				if err := saveManifest(); err != nil {
					t.Fatal(err)
				}
			case "duplicate-enrollment":
				// A duplicate persisted selector also fails strict enrollment decoding.
				manifest.Models = append(manifest.Models, model)
				manifest.Models[1].Name = "another name"
				data, _ := json.Marshal(manifest)
				if err := os.WriteFile(manifestPath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reply := httptest.NewRecorder()
			handleModelPath(reply, httptest.NewRequest("GET", "/?filename="+filename, nil))
			if reply.Code == 200 || strings.Contains(reply.Body.String(), `"safe_to_use":"true"`) || strings.Contains(reply.Body.String(), `"path":`) {
				t.Fatalf("%s produced usable path: %d %s", kind, reply.Code, reply.Body)
			}
		})
	}
}

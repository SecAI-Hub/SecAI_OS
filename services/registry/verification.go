package main

// Verification is a bounded, point-in-time enrollment check, not a lease over
// the pathname subsequently opened by a consumer. Slow I/O never owns manifestMu.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const verificationTimeout = 10 * time.Second
const maxVerifierOutput = 64 * 1024
const maxVerificationResult = 1024 * 1024
const maxVerificationInventory = 16 * 1024 * 1024

var (
	errEnrollment      = errors.New("registry enrollment is unavailable or changed")
	errBlocked         = errors.New("model is blocked")
	errChanged         = errors.New("model or enrollment changed during verification")
	errCapacity        = errors.New("verification capacity exhausted")
	errOutput          = errors.New("verification output limit exceeded")
	errVerifier        = errors.New("protected verification executable unavailable")
	errNotFound        = errors.New("model not found")
	registryBoot       = rand.Text()
	manifestGeneration uint64
	manifestSourceInfo fs.FileInfo
	verification       = &verificationService{slots: make(chan struct{}, 2), timeout: verificationTimeout,
		verifierPath: ggufGuardBin, verifierUID: 0}
)

type verificationService struct {
	slots   chan struct{}
	timeout time.Duration
	// Only internal tests substitute these. No request/environment path override.
	verifierPath string
	verifierUID  uint32
}

type verificationReply struct {
	body map[string]any
	err  error
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (v *verificationService) run(parent context.Context, work func(context.Context) verificationReply) verificationReply {
	ctx, cancel := context.WithTimeout(parent, v.timeout)
	defer cancel()
	if err := contextError(ctx); err != nil {
		return verificationReply{err: err}
	}
	select {
	case v.slots <- struct{}{}:
	default:
		return verificationReply{err: errCapacity}
	}
	result := make(chan verificationReply, 1)
	go func() {
		// Cancellation can return the HTTP response before a regular-file kernel
		// read finishes. Retain the slot until that work/process actually ends.
		reply := func() verificationReply {
			defer func() { <-v.slots }()
			return work(ctx)
		}()
		result <- reply
	}()
	select {
	case reply := <-result:
		// A result and cancellation may become ready together. Cancellation wins.
		if err := contextError(ctx); err != nil {
			return verificationReply{err: err}
		}
		return reply
	case <-ctx.Done():
		return verificationReply{err: ctx.Err()}
	}
}

type enrollmentView struct {
	models                []Artifact
	raw                   []byte
	dir, source, revision string
	digest                [sha256.Size]byte
	info                  fs.FileInfo
	generation            uint64
}

func enrollmentSnapshot() (enrollmentView, error) {
	manifestMu.RLock()
	// Mutation admission is a separate interface. Reject an oversized persisted
	// generation before allocating a copy of its in-memory metadata.
	if manifestSourceInfo == nil || manifestSourceInfo.Size() < 0 || manifestSourceInfo.Size() > maxManifestBytes || len(manifest.Models) > 10_000 {
		manifestMu.RUnlock()
		return enrollmentView{}, errEnrollment
	}
	raw, err := json.Marshal(manifest)
	view := enrollmentView{dir: registryDir, source: manifestSource, digest: manifestDigest,
		info: manifestSourceInfo, generation: manifestGeneration}
	manifestMu.RUnlock()
	if err != nil || len(raw) > maxManifestBytes {
		return view, errEnrollment
	}
	copy, err := decodeRuntimeManifest(raw)
	if err != nil {
		return view, errEnrollment
	}
	view.models, view.raw = copy.Models, raw
	identity, _ := json.Marshal([]any{registryBoot, view.generation, view.source, view.digest, raw})
	sum := sha256.Sum256(identity)
	view.revision = hex.EncodeToString(sum[:])
	return view, nil
}

func sameIdentity(a, b fs.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Nlink == y.Nlink && x.Uid == y.Uid && x.Gid == y.Gid && x.Ctim == y.Ctim
}

func (view enrollmentView) current(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if view.source == "" || view.info == nil {
		return errEnrollment
	}
	data, info, err := readVerificationControl(ctx, view.source, maxManifestBytes)
	if err != nil || !sameIdentity(view.info, info) || sha256.Sum256(data) != view.digest {
		return errEnrollment
	}
	manifestMu.RLock()
	same := manifestGeneration == view.generation && manifestSource == view.source && manifestDigest == view.digest && registryDir == view.dir
	if !same {
		manifestMu.RUnlock()
		return errChanged
	}
	currentRaw, marshalErr := json.Marshal(manifest)
	manifestMu.RUnlock()
	if marshalErr != nil || !bytes.Equal(currentRaw, view.raw) {
		return errChanged
	}
	return contextError(ctx)
}

func (view enrollmentView) model(name string) (Artifact, error) {
	for _, model := range view.models {
		if model.Name == name {
			if model.Blocked {
				return Artifact{}, errBlocked
			}
			return model, nil
		}
	}
	return Artifact{}, errNotFound
}

// Filename selection is exact and only exposed by the verified path operation.
func (view enrollmentView) modelFilename(filename string) (Artifact, error) {
	clean, err := strictBasename(filename)
	if err != nil || clean != filename || len(filename) > 512 || strings.ContainsAny(filename, "\r\n\t") {
		return Artifact{}, errNotFound
	}
	var selected Artifact
	matches := 0
	for _, model := range view.models {
		if model.Filename == filename {
			selected = model
			matches++
		}
	}
	if matches > 1 {
		return Artifact{}, errEnrollment
	}
	if matches == 0 {
		return Artifact{}, errNotFound
	}
	if selected.Blocked {
		return Artifact{}, errBlocked
	}
	return selected, nil
}

func readVerificationControl(ctx context.Context, path string, maximum int64) ([]byte, fs.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || linkCount(before) != 1 || before.Size() < 0 || before.Size() > maximum {
		return nil, nil, errEnrollment
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameIdentity(before, opened) {
		return nil, nil, errEnrollment
	}
	var data bytes.Buffer
	if err := copyVerification(ctx, &data, file, opened.Size()); err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !sameIdentity(opened, after) || !sameIdentity(after, pathAfter) {
		return nil, nil, errEnrollment
	}
	return data.Bytes(), after, nil
}

func copyVerification(ctx context.Context, destination io.Writer, source io.Reader, size int64) error {
	buffer := make([]byte, 256*1024)
	remaining := size
	for remaining > 0 {
		if err := contextError(ctx); err != nil {
			return err
		}
		count := int64(len(buffer))
		if remaining < count {
			count = remaining
		}
		n, err := source.Read(buffer[:count])
		if n > 0 {
			if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
			remaining -= int64(n)
		}
		if err != nil {
			return fmt.Errorf("artifact read incomplete: %w", err)
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	var extra [1]byte
	n, err := source.Read(extra[:])
	if n != 0 || err != io.EOF {
		return errChanged
	}
	return contextError(ctx)
}

type fileObservation struct {
	rel  string
	info fs.FileInfo
}
type hashInventory struct {
	observations []fileObservation
	bytes        int64
	names        int
}

func (inventory *hashInventory) add(rel string, info fs.FileInfo) error {
	inventory.names += len(rel) + 256
	if len(inventory.observations) >= maxDirectoryEntries || inventory.names > maxVerificationInventory {
		return errOutput
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() || linkCount(info) != 1 || info.Size() < 0 || info.Size() > maxDirectoryFileBytes || inventory.bytes > maxDirectoryTotalBytes-info.Size() {
			return errors.New("artifact type or size is not eligible")
		}
		inventory.bytes += info.Size()
	}
	inventory.observations = append(inventory.observations, fileObservation{rel, info})
	return nil
}

func checkedFile(root *os.Root, rel string, before fs.FileInfo) (*os.File, error) {
	if !before.Mode().IsRegular() || linkCount(before) != 1 {
		return nil, errors.New("artifact is not a single-link regular file")
	}
	file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !sameIdentity(before, opened) {
		file.Close()
		return nil, errChanged
	}
	return file, nil
}

func hashObserved(ctx context.Context, root *os.Root, entry fileObservation, destination io.Writer) error {
	file, err := checkedFile(root, entry.rel, entry.info)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := copyVerification(ctx, destination, file, entry.info.Size()); err != nil {
		return err
	}
	after, err := file.Stat()
	pathAfter, pathErr := root.Lstat(entry.rel)
	if err != nil || pathErr != nil || !sameIdentity(entry.info, after) || !sameIdentity(after, pathAfter) {
		return errChanged
	}
	return nil
}

func verifyObservedArtifact(ctx context.Context, root *os.Root, model Artifact, inventory *hashInventory) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	info, err := root.Lstat(model.Filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("artifact symbolic link rejected")
	}
	start := len(inventory.observations)
	if err := inventory.add(model.Filename, info); err != nil {
		return "", err
	}
	hash := sha256.New()
	var size int64
	if !info.IsDir() {
		if model.Format == "diffusion-directory" {
			return "", errChanged
		}
		size = info.Size()
		if err := hashObserved(ctx, root, fileObservation{model.Filename, info}, hash); err != nil {
			return "", err
		}
	} else {
		if model.Format != "diffusion-directory" {
			return "", errChanged
		}
		pending := []fileObservation{{model.Filename, info}}
		files := []fileObservation{}
		for len(pending) > 0 {
			if err := contextError(ctx); err != nil {
				return "", err
			}
			dir := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			handle, err := root.OpenFile(dir.rel, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return "", err
			}
			opened, statErr := handle.Stat()
			if statErr != nil || !sameIdentity(dir.info, opened) {
				handle.Close()
				return "", errChanged
			}
			for {
				if err := contextError(ctx); err != nil {
					handle.Close()
					return "", err
				}
				entries, readErr := handle.ReadDir(128)
				for _, entry := range entries {
					rel := filepath.Join(dir.rel, entry.Name())
					if len(rel) > maxDirectoryPathBytes {
						handle.Close()
						return "", errOutput
					}
					childInfo, err := root.Lstat(rel)
					if err != nil {
						handle.Close()
						return "", err
					}
					if err := inventory.add(rel, childInfo); err != nil {
						handle.Close()
						return "", err
					}
					observation := fileObservation{rel, childInfo}
					if childInfo.IsDir() {
						pending = append(pending, observation)
					} else {
						files = append(files, observation)
						size += childInfo.Size()
					}
					if len(files) > maxDirectoryFiles {
						handle.Close()
						return "", errOutput
					}
				}
				if readErr != nil {
					handle.Close()
					if readErr != io.EOF {
						return "", readErr
					}
					break
				}
			}
		}
		sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
		hash.Write([]byte("SecAI-Directory-Hash-v1\x00"))
		for _, file := range files {
			name, _ := filepath.Rel(model.Filename, file.rel)
			encodedName := []byte(filepath.ToSlash(name))
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], uint64(len(encodedName)))
			hash.Write(encoded[:])
			hash.Write(encodedName)
			binary.BigEndian.PutUint64(encoded[:], uint64(file.info.Size()))
			hash.Write(encoded[:])
			if err := hashObserved(ctx, root, file, hash); err != nil {
				return "", err
			}
		}
	}
	for _, observed := range inventory.observations[start:] {
		after, err := root.Lstat(observed.rel)
		if err != nil || !sameIdentity(observed.info, after) {
			return "", errChanged
		}
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if size != model.SizeBytes || actual != model.SHA256 {
		return actual, errors.New("artifact size or hash does not match enrollment")
	}
	return actual, contextError(ctx)
}

func verifyFinalIdentity(ctx context.Context, root *os.Root, view enrollmentView, rootInfo fs.FileInfo, inventory *hashInventory) error {
	for _, observed := range inventory.observations {
		if err := contextError(ctx); err != nil {
			return err
		}
		after, err := root.Lstat(observed.rel)
		if err != nil || !sameIdentity(observed.info, after) {
			return errChanged
		}
	}
	currentRoot, err := os.Stat(view.dir)
	// Changes to unrelated root entries can update directory timestamps; root
	// identity must remain the same, while enrolled subtree stamps are exact.
	if err != nil || !os.SameFile(rootInfo, currentRoot) {
		return errChanged
	}
	return view.current(ctx)
}

type boundedVerifierOutput struct {
	mu       sync.Mutex
	data     bytes.Buffer
	exceeded bool
	cancel   context.CancelFunc
}

func (out *boundedVerifierOutput) Write(data []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	remaining := maxVerifierOutput - out.data.Len()
	if len(data) > remaining {
		out.data.Write(data[:remaining])
		out.exceeded = true
		out.cancel()
		return len(data), errOutput
	}
	return out.data.Write(data)
}

func (v *verificationService) gguf(ctx context.Context, modelPath, sidecarPath string) (string, error) {
	before, err := os.Lstat(v.verifierPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || linkCount(before) != 1 {
		return "", errVerifier
	}
	metadata, ok := before.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != v.verifierUID {
		return "", errVerifier
	}
	binary, err := os.OpenFile(v.verifierPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errVerifier
	}
	defer binary.Close()
	opened, err := binary.Stat()
	if err != nil || !sameIdentity(before, opened) {
		return "", errVerifier
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedVerifierOutput{cancel: cancel}
	// Execute the protected opened binary. The guard requires regular pathname
	// inputs (its sidecar loader rejects proc-fd symlinks); surrounding identity
	// checks detect persistent replacement, not every transient pathname swap.
	// No caller command or ambient credential/proxy environment is inherited.
	command := exec.CommandContext(childCtx, "/proc/self/fd/3", "verify-manifest", modelPath, sidecarPath)
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = time.Second
	err = command.Run() // Kill targets this exact child; slot remains held through Wait.
	output.mu.Lock()
	text := strings.TrimSpace(output.data.String())
	exceeded := output.exceeded
	output.mu.Unlock()
	if exceeded {
		return "", errOutput
	}
	if contextError(ctx) != nil {
		return "", contextError(ctx)
	}
	current, statErr := os.Lstat(v.verifierPath)
	if statErr != nil || !sameIdentity(before, current) {
		return "", errVerifier
	}
	return text, err
}

func verificationFailure(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, errCapacity):
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		status = http.StatusRequestTimeout
	case errors.Is(err, errEnrollment), errors.Is(err, errVerifier):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errNotFound), errors.Is(err, fs.ErrNotExist):
		status = http.StatusNotFound
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"status": "unavailable", "safe_to_use": "false", "error": err.Error()})
}

func writeVerificationReply(w http.ResponseWriter, r *http.Request, reply verificationReply) {
	if err := contextError(r.Context()); err != nil {
		verificationFailure(w, err)
		return
	}
	if reply.err != nil {
		verificationFailure(w, reply.err)
		return
	}
	data, err := json.Marshal(reply.body)
	if err != nil || len(data) > maxVerificationResult {
		verificationFailure(w, errOutput)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if reply.body["status"] == "failed" {
		w.WriteHeader(http.StatusConflict)
	}
	w.Write(data)
}

func verifiedModelReply(ctx context.Context, name, operation string) verificationReply {
	return verifiedSelectedModelReply(ctx, name, "", operation)
}

func verifiedSelectedModelReply(ctx context.Context, name, filename, operation string) verificationReply {
	view, err := enrollmentSnapshot()
	if err != nil {
		return verificationReply{err: err}
	}
	if err = view.current(ctx); err != nil {
		return verificationReply{err: err}
	}
	var model Artifact
	if filename != "" && name == "" && operation == "path" {
		model, err = view.modelFilename(filename)
	} else if filename == "" && name != "" {
		model, err = view.model(name)
	} else {
		err = errNotFound
	}
	if err != nil {
		return verificationReply{err: err}
	}
	root, err := os.OpenRoot(view.dir)
	if err != nil {
		return verificationReply{err: err}
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return verificationReply{err: err}
	}
	inventory := &hashInventory{}
	actual, err := verifyObservedArtifact(ctx, root, model, inventory)
	if err != nil {
		return verificationReply{err: err}
	}
	body := map[string]any{"status": "verified", "name": name, "sha256": actual, "safe_to_use": "true"}
	if operation == "path" {
		body = map[string]any{"schema_version": 1, "status": "verified", "name": model.Name,
			"filename": model.Filename, "format": model.Format, "sha256": actual,
			"path": filepath.Join(view.dir, model.Filename), "safe_to_use": "true"}
	}
	if operation == "gguf" {
		if model.Format != "gguf" || model.GGUFGuardManifest == "" {
			body = map[string]any{"status": "skipped", "name": name, "safe_to_use": "false", "reason": "no gguf-guard manifest available"}
		} else {
			info, statErr := root.Lstat(model.GGUFGuardManifest)
			if statErr != nil {
				return verificationReply{err: statErr}
			}
			if info.Size() > maxControlFileBytes {
				return verificationReply{err: errOutput}
			}
			if err = inventory.add(model.GGUFGuardManifest, info); err != nil {
				return verificationReply{err: err}
			}
			file, openErr := checkedFile(root, model.Filename, inventory.observations[0].info)
			if openErr != nil {
				return verificationReply{err: openErr}
			}
			defer file.Close()
			sidecar, openErr := checkedFile(root, model.GGUFGuardManifest, info)
			if openErr != nil {
				return verificationReply{err: openErr}
			}
			defer sidecar.Close()
			output, verifyErr := verification.gguf(ctx, filepath.Join(view.dir, model.Filename), filepath.Join(view.dir, model.GGUFGuardManifest))
			if verifyErr != nil {
				return verificationReply{err: verifyErr}
			}
			body["detail"] = output
		}
	}
	if err = verifyFinalIdentity(ctx, root, view, rootInfo, inventory); err != nil {
		return verificationReply{err: err}
	}
	return verificationReply{body: body}
}

func handleVerifiedOperation(w http.ResponseWriter, r *http.Request, operation string) {
	expected := http.MethodPost
	if operation == "path" {
		expected = http.MethodGet
	}
	if r.Method != expected {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["name"]) > 1 || len(query["filename"]) > 1 {
		http.Error(w, "invalid model selector", http.StatusBadRequest)
		return
	}
	name, filename := query.Get("name"), query.Get("filename")
	if operation == "path" {
		if (len(query["name"]) == 1) == (len(query["filename"]) == 1) || (name == "" && filename == "") {
			http.Error(w, "exactly one model selector required", http.StatusBadRequest)
			return
		}
		if filename != "" {
			clean, err := strictBasename(filename)
			if err != nil || clean != filename || len(filename) > 512 || strings.ContainsAny(filename, "\r\n\t") {
				http.Error(w, "invalid model selector", http.StatusBadRequest)
				return
			}
		}
	} else if name == "" || len(query["filename"]) != 0 {
		http.Error(w, "name selector required", http.StatusBadRequest)
		return
	}
	writeVerificationReply(w, r, verification.run(r.Context(), func(ctx context.Context) verificationReply {
		return verifiedSelectedModelReply(ctx, name, filename, operation)
	}))
}

func verifiedAllReply(ctx context.Context) verificationReply {
	view, err := enrollmentSnapshot()
	if err != nil {
		return verificationReply{err: err}
	}
	if err = view.current(ctx); err != nil {
		return verificationReply{err: err}
	}
	results := make([]map[string]string, 0, len(view.models))
	allOK := true
	inventory := &hashInventory{}
	var root *os.Root
	var rootInfo fs.FileInfo
	if len(view.models) > 0 {
		root, err = os.OpenRoot(view.dir)
		if err != nil {
			return verificationReply{err: err}
		}
		defer root.Close()
		rootInfo, err = root.Stat(".")
		if err != nil {
			return verificationReply{err: err}
		}
	}
	for _, model := range view.models {
		if err = contextError(ctx); err != nil {
			return verificationReply{err: err}
		}
		actual := ""
		modelErr := error(nil)
		if model.Blocked {
			modelErr = errBlocked
		} else {
			actual, modelErr = verifyObservedArtifact(ctx, root, model, inventory)
		}
		row := map[string]string{"name": model.Name, "status": "verified", "sha256": actual}
		if modelErr != nil {
			allOK = false
			row = map[string]string{"name": model.Name, "status": "failed", "error": modelErr.Error(), "expected": model.SHA256, "actual": actual}
		}
		results = append(results, row)
	}
	if root != nil {
		err = verifyFinalIdentity(ctx, root, view, rootInfo, inventory)
	} else {
		err = view.current(ctx)
	}
	if err != nil {
		return verificationReply{err: err}
	}
	status := "ok"
	if !allOK {
		status = "failed"
	}
	body := map[string]any{"status": status, "models": results, "checked": len(results), "verified_at": time.Now().UTC().Format(time.RFC3339), "registry_revision": view.revision, "scope": "historical_verification_snapshot"}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > maxVerificationResult {
		return verificationReply{err: errOutput}
	}
	if err = contextError(ctx); err != nil {
		return verificationReply{err: err}
	}
	if err = writeIntegrityResult(ctx, body); err != nil {
		if contextError(ctx) != nil {
			return verificationReply{err: contextError(ctx)}
		}
		return verificationReply{err: errors.New("cannot persist verification snapshot")}
	}
	// A concurrently completed safety mutation invalidates even a successfully
	// written historical report; status readers check its revision again.
	if root != nil {
		err = verifyFinalIdentity(ctx, root, view, rootInfo, inventory)
	} else {
		err = view.current(ctx)
	}
	if err != nil {
		return verificationReply{err: err}
	}
	return verificationReply{body: body}
}

func currentIntegrityReply(ctx context.Context) verificationReply {
	view, err := enrollmentSnapshot()
	if err != nil {
		return verificationReply{err: err}
	}
	if err = view.current(ctx); err != nil {
		return verificationReply{err: err}
	}
	for _, model := range view.models {
		if model.Blocked {
			return verificationReply{err: errBlocked}
		}
	}
	data, _, err := readVerificationControl(ctx, integrityResultPath(), maxVerificationResult)
	if err != nil {
		return verificationReply{body: map[string]any{"status": "unknown", "detail": "no current verification snapshot is available"}}
	}
	var body map[string]any
	if json.Unmarshal(data, &body) != nil || body["registry_revision"] != view.revision {
		return verificationReply{body: map[string]any{"status": "unknown", "detail": "verification snapshot does not match current enrollment"}}
	}
	if err = view.current(ctx); err != nil {
		return verificationReply{err: err}
	}
	return verificationReply{body: body}
}

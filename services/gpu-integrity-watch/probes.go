package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

const (
	maxModelFileSize   = 1 << 40
	maxTotalModelBytes = 2 << 40
	maxModelFileCount  = 10000
	maxWalkEntryCount  = 50000
	modelScanTimeout   = 2 * time.Minute
)

// ProbeType identifies the kind of integrity probe.
type ProbeType = evidence.ProbeType

const (
	ProbeTensorHash        ProbeType = evidence.ProbeTensorHash
	ProbeSentinelInfer     ProbeType = evidence.ProbeSentinelInfer
	ProbeReferenceDrift    ProbeType = evidence.ProbeReferenceDrift
	ProbeECCStatus         ProbeType = evidence.ProbeECCStatus
	ProbeDriverFingerprint ProbeType = evidence.ProbeDriverFingerprint
	ProbeDeviceAllowlist   ProbeType = evidence.ProbeDeviceAllowlist
)

// ProbeStatus is the outcome of a single probe run.
type ProbeStatus = evidence.ProbeStatus

const (
	StatusPass  ProbeStatus = evidence.StatusPass
	StatusDrift ProbeStatus = evidence.StatusDrift
	StatusFail  ProbeStatus = evidence.StatusFail
	StatusSkip  ProbeStatus = evidence.StatusSkip
	StatusError ProbeStatus = evidence.StatusError
)

// Finding records a single observation from a probe.
type Finding struct {
	Description string `json:"description"`
	Severity    string `json:"severity"` // info, warning, critical
	Detail      string `json:"detail,omitempty"`
}

// ProbeResult is the output of running one probe.
type ProbeResult struct {
	Probe      string      `json:"probe"`
	Type       ProbeType   `json:"type"`
	Status     ProbeStatus `json:"status"`
	Score      float64     `json:"score"` // 0.0 = normal, 1.0 = severe
	Findings   []Finding   `json:"findings,omitempty"`
	ModelPaths []string    `json:"model_paths,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
	Duration   string      `json:"duration"`
}

// Baseline stores known-good state for comparison.
type Baseline struct {
	CapturedAt        time.Time         `json:"captured_at" yaml:"captured_at"`
	TensorHashes      map[string]string `json:"tensor_hashes" yaml:"tensor_hashes"` // file -> sha256
	SentinelRefs      []SentinelRef     `json:"sentinel_refs" yaml:"sentinel_refs"`
	DriverFingerprint *DriverBaseline   `json:"driver_fingerprint,omitempty" yaml:"driver_fingerprint,omitempty"`
	DeviceAllowlist   []string          `json:"device_allowlist,omitempty" yaml:"device_allowlist,omitempty"`
}

// DriverBaseline stores expected GPU driver state.
type DriverBaseline struct {
	DriverVersion string `json:"driver_version" yaml:"driver_version"`
	KernelModule  string `json:"kernel_module" yaml:"kernel_module"`
	ModuleHash    string `json:"module_hash,omitempty" yaml:"module_hash,omitempty"`
}

// SentinelRef is a known input/output pair for sentinel inference.
type SentinelRef struct {
	Name          string `json:"name" yaml:"name"`
	Input         string `json:"input" yaml:"input"`
	Expected      string `json:"expected" yaml:"expected"`
	ModelFilename string `json:"model_filename" yaml:"model_filename"`
	ModelSHA256   string `json:"model_sha256" yaml:"model_sha256"`
}

// ProbeRunner executes configured probes against the current system state.
type ProbeRunner struct {
	profile     *IntegrityProfile
	baseline    *Baseline
	probeClient *GPUProbeClient
}

// NewProbeRunner creates a runner with the given profile and baseline.
func NewProbeRunner(profile *IntegrityProfile, baseline *Baseline) *ProbeRunner {
	return &ProbeRunner{profile: profile, baseline: baseline}
}

// RunAll executes all enabled probes and returns results.
func (r *ProbeRunner) RunAll() []ProbeResult {
	var results []ProbeResult
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, pc := range r.profile.Probes {
		if !pc.Enabled {
			continue
		}
		start := time.Now()
		var result ProbeResult

		switch pc.Type {
		case ProbeTensorHash:
			result = r.runTensorHash(pc)
		case ProbeSentinelInfer:
			result = r.runSentinelInferenceContext(ctx, pc)
		case ProbeReferenceDrift:
			result = r.runReferenceDriftContext(ctx, pc)
		case ProbeECCStatus:
			result = r.runECCStatus(pc)
		case ProbeDriverFingerprint:
			result = r.runDriverFingerprint(pc)
		case ProbeDeviceAllowlist:
			result = r.runDeviceAllowlist(pc)
		default:
			result = ProbeResult{
				Probe:  pc.Name,
				Type:   pc.Type,
				Status: StatusError,
				Score:  0.5,
				Findings: []Finding{{
					Description: fmt.Sprintf("unknown probe type: %s", pc.Type),
					Severity:    "warning",
				}},
			}
		}

		result.Timestamp = time.Now()
		result.Duration = time.Since(start).String()
		results = append(results, result)
	}

	return results
}

// runTensorHash computes SHA-256 of model files and compares to baseline.
func (r *ProbeRunner) runTensorHash(pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeTensorHash}

	modelDir := pc.Settings["model_dir"]
	if modelDir == "" {
		modelDir = r.profile.ModelDir
	}
	if modelDir == "" {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no model directory configured",
			Severity:    "info",
		})
		return result
	}

	if r.baseline == nil || len(r.baseline.TensorHashes) == 0 {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no baseline hashes available; run baseline capture first",
			Severity:    "info",
		})
		return result
	}

	patterns := []string{"*.gguf", "*.bin", "*.safetensors"}
	if p, ok := pc.Settings["patterns"]; ok {
		patterns = strings.Split(p, ",")
	}

	currentHashes, err := hashModelFiles(modelDir, patterns)
	if err != nil {
		result.Status = StatusError
		result.Score = 1
		result.Findings = []Finding{{Description: "model scan incomplete", Severity: "critical", Detail: err.Error()}}
		return result
	}
	if len(currentHashes) == 0 && len(r.baseline.TensorHashes) == 0 {
		result.Status = StatusError
		result.Score = 0.5
		result.Findings = append(result.Findings, Finding{
			Description: "no model files found in " + modelDir,
			Severity:    "warning",
		})
		return result
	}

	mismatches := 0
	missing := 0
	extras := 0
	for file, baselineHash := range r.baseline.TensorHashes {
		if !filepath.IsLocal(file) {
			result.Status = StatusError
			result.Score = 1
			result.Findings = []Finding{{Description: "baseline contains an invalid model path", Severity: "critical"}}
			return result
		}
		currentHash, exists := currentHashes[file]
		if !exists {
			missing++
			modelPath, _ := filepath.Abs(filepath.Join(modelDir, file))
			result.ModelPaths = append(result.ModelPaths, modelPath)
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("baseline file missing: %s", file),
				Severity:    "critical",
				Detail:      "expected hash: " + baselineHash,
			})
			continue
		}
		if currentHash != baselineHash {
			mismatches++
			modelPath, _ := filepath.Abs(filepath.Join(modelDir, file))
			result.ModelPaths = append(result.ModelPaths, modelPath)
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("hash mismatch: %s", file),
				Severity:    "critical",
				Detail:      fmt.Sprintf("expected=%s got=%s", baselineHash, currentHash),
			})
		}
	}

	// Check for new files not in baseline
	for file := range currentHashes {
		if _, inBaseline := r.baseline.TensorHashes[file]; !inBaseline {
			extras++
			modelPath, _ := filepath.Abs(filepath.Join(modelDir, file))
			result.ModelPaths = append(result.ModelPaths, modelPath)
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("new file not in baseline: %s", file),
				Severity:    "warning",
			})
		}
	}

	total := len(r.baseline.TensorHashes)
	if total == 0 {
		total = 1
	}
	failCount := mismatches + missing + extras

	switch {
	case failCount == 0:
		result.Status = StatusPass
		result.Score = 0.0
	default:
		result.Status = StatusFail
		result.Score = float64(failCount) / float64(total)
		if result.Score > 1.0 {
			result.Score = 1.0
		}
	}

	return result
}

// hashModelFiles walks the directory and hashes files matching patterns.
func hashModelFiles(dir string, patterns []string) (map[string]string, error) {
	return hashModelFilesContext(context.Background(), dir, patterns)
}

func hashModelFilesContext(parent context.Context, dir string, patterns []string) (map[string]string, error) {
	hashes := make(map[string]string)
	ctx, cancel := context.WithTimeout(parent, modelScanTimeout)
	defer cancel()
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	entries := 0
	var totalBytes int64
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("model scan deadline exceeded: %w", err)
		}
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > maxWalkEntryCount {
			return fmt.Errorf("model tree exceeds %d total entries", maxWalkEntryCount)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink encountered: %s", path)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular entry encountered: %s", path)
		}
		name := info.Name()
		for _, pattern := range patterns {
			matched, matchErr := filepath.Match(strings.TrimSpace(pattern), name)
			if matchErr != nil {
				return fmt.Errorf("invalid model pattern: %w", matchErr)
			}
			if matched {
				if info.Size() < 0 || info.Size() > maxModelFileSize {
					return fmt.Errorf("model exceeds size limit: %s", path)
				}
				if info.Size() > maxTotalModelBytes-totalBytes {
					return fmt.Errorf("model tree exceeds %d total bytes", maxTotalModelBytes)
				}
				totalBytes += info.Size()
				h, err := hashFileBoundedContext(ctx, path, maxModelFileSize)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(root, path)
				if err != nil || !filepath.IsLocal(rel) {
					return fmt.Errorf("model escaped configured root")
				}
				hashes[rel] = h
				if len(hashes) > maxModelFileCount {
					return fmt.Errorf("model count exceeds %d", maxModelFileCount)
				}
				break
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return hashes, nil
}

// hashFile computes the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	return hashFileBounded(path, maxModelFileSize)
}

func hashFileBounded(path string, limit int64) (string, error) {
	return hashFileBoundedContext(context.Background(), path, limit)
}

// sameModelSnapshot checks the exact stable-file metadata used by registry
// verification. ctime detects in-place writes even if size and mtime are reset.
func sameModelSnapshot(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.Mode().IsRegular() || !b.Mode().IsRegular() || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Nlink == y.Nlink && x.Uid == y.Uid && x.Gid == y.Gid && x.Ctim == y.Ctim
}

// O_NONBLOCK prevents a regular-file-to-FIFO race from blocking open before
// context checks can run. Reject the opened descriptor before reading anything.
func openStableModelFile(path string, before os.FileInfo, limit int64) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("model descriptor unavailable")
	}
	opened, err := f.Stat()
	if err != nil || !sameModelSnapshot(before, opened) || opened.Size() < 0 || opened.Size() > limit {
		f.Close()
		return nil, fmt.Errorf("model changed while opening")
	}
	return f, nil
}

func hashFileBoundedContext(ctx context.Context, path string, limit int64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("hash deadline exceeded: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > limit {
		return "", fmt.Errorf("unsafe model file")
	}
	f, err := openStableModelFile(path, before, limit)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 128<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("hash deadline exceeded: %w", err)
		}
		read, readErr := f.Read(buffer)
		if read > 0 {
			written += int64(read)
			if written > limit {
				return "", fmt.Errorf("file exceeds size limit")
			}
			if _, err := h.Write(buffer[:read]); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !sameModelSnapshot(before, after) || !sameModelSnapshot(after, current) || written != before.Size() {
		return "", fmt.Errorf("model changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runSentinelInference sends known inputs to the inference endpoint and checks outputs.
func (r *ProbeRunner) runSentinelInference(pc ProbeConfig) ProbeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return r.runSentinelInferenceContext(ctx, pc)
}
func liveProbeError(result ProbeResult, reason string) ProbeResult {
	result.Status = StatusError
	result.Score = 1
	result.Findings = append(result.Findings, Finding{Description: reason, Severity: "critical"})
	return result
}
func (r *ProbeRunner) runSentinelInferenceContext(ctx context.Context, pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeSentinelInfer}
	if r.probeClient == nil || !baselineCoversGPUProbe(r.baseline, ProbeSentinelInfer) {
		return liveProbeError(result, "approved authenticated probe client or baseline unavailable")
	}
	threshold := 0.9
	if t, ok := pc.Settings["similarity_threshold"]; ok {
		var err error
		threshold, err = strconv.ParseFloat(t, 64)
		if err != nil || threshold < 0 || threshold > 1 || math.IsNaN(threshold) {
			return liveProbeError(result, "invalid similarity threshold")
		}
	}
	drifts, fails := 0, 0
	for _, ref := range r.baseline.SentinelRefs {
		actual, err := r.probeClient.Probe(ctx, ref.Name)
		if err != nil {
			return liveProbeError(result, "authenticated sentinel exchange unavailable")
		}
		similarity := computeSimilarity(ref.Expected, actual)
		severity := "info"
		if similarity < 0.5 {
			fails++
			severity = "critical"
		} else if similarity < threshold {
			drifts++
			severity = "warning"
		}
		result.Findings = append(result.Findings, Finding{Description: fmt.Sprintf("sentinel %q: similarity=%.2f", ref.Name, similarity), Severity: severity})
	}
	total := float64(len(r.baseline.SentinelRefs))
	switch {
	case fails > 0:
		result.Status = StatusFail
		result.Score = float64(fails+drifts) / total
	case drifts > 0:
		result.Status = StatusDrift
		result.Score = float64(drifts) / total * 0.5
	default:
		result.Status = StatusPass
	}
	return result
}

// computeSimilarity returns a simple word-overlap similarity between two strings.
func computeSimilarity(expected, actual string) float64 {
	if expected == actual {
		return 1.0
	}

	expectedWords := strings.Fields(strings.ToLower(expected))
	actualWords := strings.Fields(strings.ToLower(actual))

	if len(expectedWords) == 0 || len(actualWords) == 0 {
		return 0.0
	}

	actualSet := make(map[string]bool)
	for _, w := range actualWords {
		actualSet[w] = true
	}

	matches := 0
	for _, w := range expectedWords {
		if actualSet[w] {
			matches++
		}
	}

	// Jaccard-like similarity
	union := len(expectedWords)
	for _, w := range actualWords {
		found := false
		for _, e := range expectedWords {
			if w == e {
				found = true
				break
			}
		}
		if !found {
			union++
		}
	}

	if union == 0 {
		return 0.0
	}
	return float64(matches) / float64(union)
}

// runReferenceDrift checks if outputs have drifted from baseline over time.
func (r *ProbeRunner) runReferenceDrift(pc ProbeConfig) ProbeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return r.runReferenceDriftContext(ctx, pc)
}
func (r *ProbeRunner) runReferenceDriftContext(ctx context.Context, pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeReferenceDrift}
	if r.probeClient == nil || !baselineCoversGPUProbe(r.baseline, ProbeReferenceDrift) {
		return liveProbeError(result, "approved authenticated probe client or baseline unavailable")
	}
	iterations := 3
	if value, ok := pc.Settings["iterations"]; ok {
		var err error
		iterations, err = strconv.Atoi(value)
		if err != nil || iterations < 1 || iterations > 3 {
			return liveProbeError(result, "reference drift iterations outside 1..3")
		}
	}
	var totalDrift float64
	for _, ref := range r.baseline.SentinelRefs {
		similarities := make([]float64, 0, iterations)
		for i := 0; i < iterations; i++ {
			actual, err := r.probeClient.Probe(ctx, ref.Name)
			if err != nil {
				return liveProbeError(result, "authenticated reference exchange unavailable")
			}
			similarities = append(similarities, computeSimilarity(ref.Expected, actual))
		}
		avg := 0.0
		for _, sim := range similarities {
			avg += sim
		}
		avg /= float64(iterations)
		variance := 0.0
		for _, sim := range similarities {
			delta := sim - avg
			variance += delta * delta
		}
		variance /= float64(iterations)
		drift := 1 - avg
		totalDrift += drift
		severity := "info"
		if drift > 0.3 {
			severity = "warning"
		}
		if drift > 0.7 || variance > 0.1 {
			severity = "critical"
		}
		result.Findings = append(result.Findings, Finding{Description: fmt.Sprintf("drift %q: avg_similarity=%.2f variance=%.4f", ref.Name, avg, variance), Severity: severity})
	}
	result.Score = totalDrift / float64(len(r.baseline.SentinelRefs))
	switch {
	case result.Score < 0.1:
		result.Status = StatusPass
	case result.Score < 0.5:
		result.Status = StatusDrift
	default:
		result.Status = StatusFail
	}
	return result
}

// runECCStatus checks GPU ECC memory error counters.
func (r *ProbeRunner) runECCStatus(pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeECCStatus}

	// Check if nvidia-smi is available
	nvidiaSmi := "nvidia-smi"
	if custom, ok := pc.Settings["nvidia_smi_path"]; ok {
		nvidiaSmi = custom
	}

	_, err := exec.LookPath(nvidiaSmi)
	if err != nil {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "nvidia-smi not found; ECC check skipped",
			Severity:    "info",
		})
		return result
	}

	// Query ECC errors
	out, err := exec.Command(nvidiaSmi,
		"--query-gpu=ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,ecc.mode.current",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		result.Status = StatusError
		result.Score = 0.3
		result.Findings = append(result.Findings, Finding{
			Description: "failed to query ECC status",
			Severity:    "warning",
			Detail:      err.Error(),
		})
		return result
	}

	lines := strings.TrimSpace(string(out))
	result = parseECCOutput(result, lines)
	return result
}

// parseECCOutput parses nvidia-smi ECC output and updates the probe result.
func parseECCOutput(result ProbeResult, output string) ProbeResult {
	if output == "" {
		result.Status = StatusSkip
		result.Score = 0.0
		return result
	}

	re := regexp.MustCompile(`(\d+|N/A)\s*,\s*(\d+|N/A)\s*,\s*(\w+)`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if matches == nil {
			// Check for "[Not Supported]" or similar
			if strings.Contains(line, "Not Supported") || strings.Contains(line, "N/A") {
				result.Findings = append(result.Findings, Finding{
					Description: "ECC not supported on this GPU",
					Severity:    "info",
				})
				result.Status = StatusSkip
				result.Score = 0.0
			}
			continue
		}

		corrected := matches[1]
		uncorrected := matches[2]
		mode := matches[3]

		if mode == "Disabled" || mode == "N/A" {
			result.Findings = append(result.Findings, Finding{
				Description: "ECC is disabled on GPU",
				Severity:    "warning",
				Detail:      "enable ECC for production AI workloads",
			})
			result.Status = StatusDrift
			result.Score = 0.3
			return result
		}

		var correctedN, uncorrectedN int
		fmt.Sscanf(corrected, "%d", &correctedN)
		fmt.Sscanf(uncorrected, "%d", &uncorrectedN)

		if uncorrectedN > 0 {
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("uncorrected ECC errors detected: %d", uncorrectedN),
				Severity:    "critical",
				Detail:      "uncorrected memory errors may corrupt model weights in VRAM",
			})
			result.Status = StatusFail
			result.Score = 1.0
			return result
		}

		if correctedN > 100 {
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("high corrected ECC error count: %d", correctedN),
				Severity:    "warning",
				Detail:      "elevated corrected errors may indicate degrading memory",
			})
			result.Status = StatusDrift
			result.Score = 0.4
			return result
		}

		if correctedN > 0 {
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("corrected ECC errors: %d (within normal range)", correctedN),
				Severity:    "info",
			})
		}

		result.Findings = append(result.Findings, Finding{
			Description: "ECC enabled and healthy",
			Severity:    "info",
		})
		result.Status = StatusPass
		result.Score = 0.0
	}

	if result.Status == "" {
		result.Status = StatusSkip
		result.Score = 0.0
	}

	return result
}

// ---------- driver fingerprint probe ----------

// runDriverFingerprint captures the GPU driver version and kernel module
// identity and compares against the baseline.
func (r *ProbeRunner) runDriverFingerprint(pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeDriverFingerprint}

	// Detect driver version from sysfs or nvidia-smi
	version, module := detectDriverInfo(pc.Settings)

	if version == "" && module == "" {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no GPU driver detected (sysfs paths not present)",
			Severity:    "info",
		})
		return result
	}

	result.Findings = append(result.Findings, Finding{
		Description: "driver version detected",
		Severity:    "info",
		Detail:      version,
	})
	result.Findings = append(result.Findings, Finding{
		Description: "kernel module: " + module,
		Severity:    "info",
	})

	// No baseline → pass with info (first run)
	if r.baseline == nil || r.baseline.DriverFingerprint == nil {
		result.Status = StatusPass
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no driver baseline available; run baseline capture to track changes",
			Severity:    "info",
		})
		return result
	}

	baseline := r.baseline.DriverFingerprint
	mismatches := 0

	// Check driver version
	if baseline.DriverVersion != "" && version != baseline.DriverVersion {
		mismatches++
		result.Findings = append(result.Findings, Finding{
			Description: "driver version changed",
			Severity:    "critical",
			Detail:      fmt.Sprintf("expected=%s got=%s", baseline.DriverVersion, version),
		})
	}

	// Check kernel module
	if baseline.KernelModule != "" && module != baseline.KernelModule {
		mismatches++
		result.Findings = append(result.Findings, Finding{
			Description: "kernel module changed",
			Severity:    "critical",
			Detail:      fmt.Sprintf("expected=%s got=%s", baseline.KernelModule, module),
		})
	}

	// This runner has no enrolled module-binary measurement source. Sysfs
	// initstate is a lifecycle status string, not the module binary (nor loaded
	// kernel memory). Never silently skip an operator-required hash check.
	switch {
	case mismatches > 0:
		result.Status = StatusFail
		result.Score = 1.0
	case baseline.ModuleHash != "":
		result.Status = StatusError
		result.Score = 0.5
		result.Findings = append(result.Findings, Finding{
			Description: "configured kernel module hash cannot be measured by this runner",
			Severity:    "warning",
		})
	default:
		result.Status = StatusPass
		result.Score = 0.0
	}

	return result
}

// detectDriverInfo reads GPU driver information from available sources.
func detectDriverInfo(settings map[string]string) (version, module string) {
	// Try sysfs paths for known GPU vendors
	sysfsDriverPaths := map[string]string{
		"nvidia": "/sys/module/nvidia/version",
		"amdgpu": "/sys/module/amdgpu/version",
		"i915":   "/sys/module/i915/version",
		"xe":     "/sys/module/xe/version",
	}

	driverPathConfigured := false
	nvidiaSmiConfigured := false

	// Allow override via settings. When a probe explicitly points to a driver
	// version path, do not silently fall back to host auto-detection.
	if customPath, ok := settings["driver_version_path"]; ok {
		driverPathConfigured = true
		data, err := os.ReadFile(customPath)
		if err == nil {
			version = strings.TrimSpace(string(data))
		}
	}

	if moduleName, ok := settings["kernel_module"]; ok {
		module = moduleName
	}

	// Auto-detect if not configured
	if version == "" && !driverPathConfigured {
		for mod, path := range sysfsDriverPaths {
			data, err := os.ReadFile(path)
			if err == nil {
				version = strings.TrimSpace(string(data))
				if module == "" {
					module = mod
				}
				break
			}
		}
	}

	// Fallback: try nvidia-smi
	if version == "" {
		nvidiaSmi := "nvidia-smi"
		if custom, ok := settings["nvidia_smi_path"]; ok {
			nvidiaSmi = custom
			nvidiaSmiConfigured = true
		}
		if _, err := exec.LookPath(nvidiaSmi); err == nil && (!driverPathConfigured || nvidiaSmiConfigured) {
			out, err := exec.Command(nvidiaSmi, "--query-gpu=driver_version", "--format=csv,noheader,nounits").Output()
			if err == nil {
				version = strings.TrimSpace(string(out))
				if module == "" {
					module = "nvidia"
				}
			}
		}
	}

	return version, module
}

// ---------- device allowlist probe ----------

// runDeviceAllowlist verifies that GPU device nodes match the expected
// allowlist, detecting unexpected device additions or removals.
func (r *ProbeRunner) runDeviceAllowlist(pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeDeviceAllowlist}

	// Discover device nodes
	deviceDirs := []string{"/dev/dri", "/dev"}
	if custom, ok := pc.Settings["device_dir"]; ok {
		deviceDirs = []string{custom}
	}

	var currentDevices []string
	for _, dir := range deviceDirs {
		devices := discoverGPUDevices(dir)
		currentDevices = append(currentDevices, devices...)
	}

	if len(currentDevices) == 0 {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no GPU device nodes found",
			Severity:    "info",
		})
		return result
	}

	result.Findings = append(result.Findings, Finding{
		Description: fmt.Sprintf("device nodes detected: %d", len(currentDevices)),
		Severity:    "info",
		Detail:      strings.Join(currentDevices, ", "),
	})

	// No baseline → pass with info
	if r.baseline == nil || len(r.baseline.DeviceAllowlist) == 0 {
		result.Status = StatusPass
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no device allowlist baseline; run baseline capture to track changes",
			Severity:    "info",
		})
		return result
	}

	allowSet := make(map[string]bool)
	for _, d := range r.baseline.DeviceAllowlist {
		allowSet[d] = true
	}

	currentSet := make(map[string]bool)
	for _, d := range currentDevices {
		currentSet[d] = true
	}

	// Check for unexpected devices
	unexpected := 0
	for _, d := range currentDevices {
		if !allowSet[d] {
			unexpected++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("unexpected device: %s", d),
				Severity:    "critical",
				Detail:      "device not in baseline allowlist",
			})
		}
	}

	// Check for missing expected devices
	missing := 0
	for _, d := range r.baseline.DeviceAllowlist {
		if !currentSet[d] {
			missing++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("expected device missing: %s", d),
				Severity:    "warning",
				Detail:      "device from baseline not found",
			})
		}
	}

	switch {
	case unexpected > 0:
		result.Status = StatusFail
		result.Score = 1.0
	case missing > 0:
		result.Status = StatusDrift
		result.Score = float64(missing) / float64(len(r.baseline.DeviceAllowlist))
	default:
		result.Status = StatusPass
		result.Score = 0.0
	}

	return result
}

// discoverGPUDevices lists GPU-related device nodes in the given directory.
func discoverGPUDevices(dir string) []string {
	var devices []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return devices
	}

	gpuPrefixes := []string{"card", "render", "nvidia", "dri"}

	for _, entry := range entries {
		name := entry.Name()
		for _, prefix := range gpuPrefixes {
			if strings.HasPrefix(name, prefix) {
				devices = append(devices, filepath.Join(dir, name))
				break
			}
		}
	}

	return devices
}

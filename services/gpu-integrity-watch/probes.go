package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ProbeType identifies the kind of integrity probe.
type ProbeType string

const (
	ProbeTensorHash        ProbeType = "tensor_hash"
	ProbeSentinelInfer     ProbeType = "sentinel_inference"
	ProbeReferenceDrift    ProbeType = "reference_drift"
	ProbeECCStatus         ProbeType = "ecc_status"
	ProbeDriverFingerprint ProbeType = "driver_fingerprint"
	ProbeDeviceAllowlist   ProbeType = "device_allowlist"
)

// ProbeStatus is the outcome of a single probe run.
type ProbeStatus string

const (
	StatusPass  ProbeStatus = "pass"
	StatusDrift ProbeStatus = "drift"
	StatusFail  ProbeStatus = "fail"
	StatusSkip  ProbeStatus = "skip"
	StatusError ProbeStatus = "error"
)

// Finding records a single observation from a probe.
type Finding struct {
	Description string `json:"description"`
	Severity    string `json:"severity"` // info, warning, critical
	Detail      string `json:"detail,omitempty"`
}

// ProbeResult is the output of running one probe.
type ProbeResult struct {
	Probe     string      `json:"probe"`
	Type      ProbeType   `json:"type"`
	Status    ProbeStatus `json:"status"`
	Score     float64     `json:"score"` // 0.0 = normal, 1.0 = severe
	Findings  []Finding   `json:"findings,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Duration  string      `json:"duration"`
}

// Baseline stores known-good state for comparison.
type Baseline struct {
	CapturedAt        time.Time          `json:"captured_at" yaml:"captured_at"`
	TensorHashes      map[string]string  `json:"tensor_hashes" yaml:"tensor_hashes"` // file -> sha256
	SentinelRefs      []SentinelRef      `json:"sentinel_refs" yaml:"sentinel_refs"`
	DriverFingerprint *DriverBaseline    `json:"driver_fingerprint,omitempty" yaml:"driver_fingerprint,omitempty"`
	DeviceAllowlist   []string           `json:"device_allowlist,omitempty" yaml:"device_allowlist,omitempty"`
}

// DriverBaseline stores expected GPU driver state.
type DriverBaseline struct {
	DriverVersion string `json:"driver_version" yaml:"driver_version"`
	KernelModule  string `json:"kernel_module" yaml:"kernel_module"`
	ModuleHash    string `json:"module_hash,omitempty" yaml:"module_hash,omitempty"`
}

// SentinelRef is a known input/output pair for sentinel inference.
type SentinelRef struct {
	Name     string `json:"name" yaml:"name"`
	Input    string `json:"input" yaml:"input"`
	Expected string `json:"expected" yaml:"expected"`
}

// ProbeRunner executes configured probes against the current system state.
type ProbeRunner struct {
	profile  *IntegrityProfile
	baseline *Baseline
}

// NewProbeRunner creates a runner with the given profile and baseline.
func NewProbeRunner(profile *IntegrityProfile, baseline *Baseline) *ProbeRunner {
	return &ProbeRunner{profile: profile, baseline: baseline}
}

// RunAll executes all enabled probes and returns results.
func (r *ProbeRunner) RunAll() []ProbeResult {
	var results []ProbeResult

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
			result = r.runSentinelInference(pc)
		case ProbeReferenceDrift:
			result = r.runReferenceDrift(pc)
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

	currentHashes := hashModelFiles(modelDir, patterns)
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
	for file, baselineHash := range r.baseline.TensorHashes {
		currentHash, exists := currentHashes[file]
		if !exists {
			missing++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("baseline file missing: %s", file),
				Severity:    "critical",
				Detail:      "expected hash: " + baselineHash,
			})
			continue
		}
		if currentHash != baselineHash {
			mismatches++
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
	failCount := mismatches + missing

	switch {
	case failCount == 0:
		result.Status = StatusPass
		result.Score = 0.0
	case failCount <= total/2:
		result.Status = StatusDrift
		result.Score = float64(failCount) / float64(total)
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
func hashModelFiles(dir string, patterns []string) map[string]string {
	hashes := make(map[string]string)

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		for _, pattern := range patterns {
			matched, _ := filepath.Match(strings.TrimSpace(pattern), name)
			if matched {
				h, err := hashFile(path)
				if err == nil {
					rel, _ := filepath.Rel(dir, path)
					hashes[rel] = h
				}
				break
			}
		}
		return nil
	})

	return hashes
}

// hashFile computes the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runSentinelInference sends known inputs to the inference endpoint and checks outputs.
func (r *ProbeRunner) runSentinelInference(pc ProbeConfig) ProbeResult {
	result := ProbeResult{Probe: pc.Name, Type: ProbeSentinelInfer}

	endpoint := pc.Settings["inference_url"]
	if endpoint == "" {
		endpoint = r.profile.InferenceURL
	}
	if endpoint == "" {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no inference endpoint configured",
			Severity:    "info",
		})
		return result
	}

	if r.baseline == nil || len(r.baseline.SentinelRefs) == 0 {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "no sentinel references in baseline",
			Severity:    "info",
		})
		return result
	}

	drifts := 0
	fails := 0
	total := len(r.baseline.SentinelRefs)

	for _, ref := range r.baseline.SentinelRefs {
		actual, err := querySentinel(endpoint, ref.Input)
		if err != nil {
			fails++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("sentinel %q: request failed", ref.Name),
				Severity:    "critical",
				Detail:      err.Error(),
			})
			continue
		}

		similarity := computeSimilarity(ref.Expected, actual)
		threshold := 0.9
		if t, ok := pc.Settings["similarity_threshold"]; ok {
			fmt.Sscanf(t, "%f", &threshold)
		}

		if similarity >= threshold {
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("sentinel %q: pass (similarity=%.2f)", ref.Name, similarity),
				Severity:    "info",
			})
		} else if similarity >= 0.5 {
			drifts++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("sentinel %q: drift (similarity=%.2f)", ref.Name, similarity),
				Severity:    "warning",
				Detail:      fmt.Sprintf("expected=%q got=%q", ref.Expected, actual),
			})
		} else {
			fails++
			result.Findings = append(result.Findings, Finding{
				Description: fmt.Sprintf("sentinel %q: fail (similarity=%.2f)", ref.Name, similarity),
				Severity:    "critical",
				Detail:      fmt.Sprintf("expected=%q got=%q", ref.Expected, actual),
			})
		}
	}

	switch {
	case fails > 0:
		result.Status = StatusFail
		result.Score = float64(fails+drifts) / float64(total)
	case drifts > 0:
		result.Status = StatusDrift
		result.Score = float64(drifts) / float64(total) * 0.5
	default:
		result.Status = StatusPass
		result.Score = 0.0
	}

	if result.Score > 1.0 {
		result.Score = 1.0
	}
	return result
}

// querySentinel sends a completion request to the inference endpoint.
func querySentinel(endpoint, input string) (string, error) {
	payload := fmt.Sprintf(`{"prompt":%q,"n_predict":64,"temperature":0}`, input)
	resp, err := http.Post(endpoint+"/completion", "application/json", strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("inference returned %d: %s", resp.StatusCode, string(body))
	}

	// Extract content from JSON response (simple extraction)
	s := string(body)
	if idx := strings.Index(s, `"content"`); idx >= 0 {
		s = s[idx:]
		if start := strings.Index(s, `"`); start >= 0 {
			s = s[start+1:]
			if start2 := strings.Index(s, `"`); start2 >= 0 {
				s = s[start2+1:]
				if end := strings.Index(s, `"`); end >= 0 {
					return s[:end], nil
				}
			}
		}
	}
	return strings.TrimSpace(string(body)), nil
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
	result := ProbeResult{Probe: pc.Name, Type: ProbeReferenceDrift}

	endpoint := pc.Settings["inference_url"]
	if endpoint == "" {
		endpoint = r.profile.InferenceURL
	}
	if endpoint == "" || r.baseline == nil || len(r.baseline.SentinelRefs) == 0 {
		result.Status = StatusSkip
		result.Score = 0.0
		result.Findings = append(result.Findings, Finding{
			Description: "drift check skipped: no endpoint or baseline",
			Severity:    "info",
		})
		return result
	}

	// Run each sentinel multiple times to detect variance
	iterations := 3
	if n, ok := pc.Settings["iterations"]; ok {
		fmt.Sscanf(n, "%d", &iterations)
	}

	var totalDrift float64
	probeCount := 0

	for _, ref := range r.baseline.SentinelRefs {
		var similarities []float64
		for i := 0; i < iterations; i++ {
			actual, err := querySentinel(endpoint, ref.Input)
			if err != nil {
				result.Findings = append(result.Findings, Finding{
					Description: fmt.Sprintf("drift check %q iteration %d: error", ref.Name, i+1),
					Severity:    "warning",
					Detail:      err.Error(),
				})
				continue
			}
			sim := computeSimilarity(ref.Expected, actual)
			similarities = append(similarities, sim)
		}

		if len(similarities) == 0 {
			continue
		}

		avg := 0.0
		for _, s := range similarities {
			avg += s
		}
		avg /= float64(len(similarities))

		// Check variance (inconsistent outputs suggest corruption)
		variance := 0.0
		for _, s := range similarities {
			d := s - avg
			variance += d * d
		}
		variance /= float64(len(similarities))

		drift := 1.0 - avg
		totalDrift += drift
		probeCount++

		severity := "info"
		if drift > 0.3 {
			severity = "warning"
		}
		if drift > 0.7 || variance > 0.1 {
			severity = "critical"
		}

		result.Findings = append(result.Findings, Finding{
			Description: fmt.Sprintf("drift %q: avg_similarity=%.2f variance=%.4f", ref.Name, avg, variance),
			Severity:    severity,
		})
	}

	if probeCount == 0 {
		result.Status = StatusSkip
		result.Score = 0.0
		return result
	}

	avgDrift := totalDrift / float64(probeCount)
	result.Score = avgDrift

	switch {
	case avgDrift < 0.1:
		result.Status = StatusPass
	case avgDrift < 0.5:
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

	// Check module hash if configured
	if baseline.ModuleHash != "" {
		modulePath := modulePathForName(module)
		if modulePath != "" {
			currentHash, err := hashFile(modulePath)
			if err == nil && currentHash != baseline.ModuleHash {
				mismatches++
				result.Findings = append(result.Findings, Finding{
					Description: "kernel module binary hash changed",
					Severity:    "critical",
					Detail:      fmt.Sprintf("expected=%s got=%s", baseline.ModuleHash, currentHash),
				})
			}
		}
	}

	switch mismatches {
	case 0:
		result.Status = StatusPass
		result.Score = 0.0
	default:
		result.Status = StatusFail
		result.Score = 1.0
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

	// Allow override via settings
	if customPath, ok := settings["driver_version_path"]; ok {
		data, err := os.ReadFile(customPath)
		if err == nil {
			version = strings.TrimSpace(string(data))
		}
	}

	if moduleName, ok := settings["kernel_module"]; ok {
		module = moduleName
	}

	// Auto-detect if not configured
	if version == "" {
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
		}
		if _, err := exec.LookPath(nvidiaSmi); err == nil {
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

// modulePathForName returns the expected sysfs module path.
func modulePathForName(name string) string {
	if name == "" {
		return ""
	}
	// Typical kernel module object path
	path := fmt.Sprintf("/sys/module/%s/initstate", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
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

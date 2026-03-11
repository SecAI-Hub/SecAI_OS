package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Collector types
// ---------------------------------------------------------------------------

// CollectorResult holds the output from a single collector.
type CollectorResult struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // pass, drift, error, skipped
	Findings  []Finding `json:"findings"`
	Timestamp string    `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

// Finding represents an individual check within a collector.
type Finding struct {
	Key      string `json:"key"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Status   string `json:"status"` // pass, drift, fail
	Detail   string `json:"detail,omitempty"`
}

// RegistryModel mirrors the model entry from the SecAI_OS registry API.
type RegistryModel struct {
	Name     string `json:"name" yaml:"name"`
	Format   string `json:"format" yaml:"format"`
	Filename string `json:"filename" yaml:"filename"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

// ---------------------------------------------------------------------------
// Model collector
// ---------------------------------------------------------------------------

// collectModelState hashes model files in the vault and compares against
// the approved manifest from the registry API.
func collectModelState(cfg ModelConfig) CollectorResult {
	result := CollectorResult{
		Name:      "model",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if cfg.VaultDir == "" {
		result.Status = "skipped"
		result.Error = "vault_dir not configured"
		return result
	}

	// Enumerate model files in the vault.
	localModels, err := hashModelFiles(cfg.VaultDir, cfg.AllowedFormats, cfg.MaxFileSize)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("scan vault: %v", err)
		return result
	}

	if len(localModels) == 0 {
		result.Status = "pass"
		result.Findings = append(result.Findings, Finding{
			Key:    "vault_models",
			Status: "pass",
			Detail: "no model files found in vault (clean state)",
		})
		return result
	}

	// Fetch approved manifest from registry if available.
	approved, err := fetchRegistryManifest(cfg.RegistryURL, cfg.RegistryTokenEnv)
	if err != nil {
		// Registry unavailable — report local hashes without comparison.
		for filename, hash := range localModels {
			result.Findings = append(result.Findings, Finding{
				Key:    filename,
				Actual: hash,
				Status: "drift",
				Detail: fmt.Sprintf("registry unavailable (%v); cannot verify", err),
			})
		}
		result.Status = "drift"
		return result
	}

	// Build approved lookup: filename -> sha256.
	approvedMap := make(map[string]string)
	for _, m := range approved {
		approvedMap[m.Filename] = m.SHA256
	}

	hasDrift := false
	for filename, actualHash := range localModels {
		expectedHash, known := approvedMap[filename]
		if !known {
			result.Findings = append(result.Findings, Finding{
				Key:    filename,
				Actual: actualHash,
				Status: "drift",
				Detail: "model file not in approved registry manifest",
			})
			hasDrift = true
			continue
		}
		if actualHash != expectedHash {
			result.Findings = append(result.Findings, Finding{
				Key:      filename,
				Expected: expectedHash,
				Actual:   actualHash,
				Status:   "fail",
				Detail:   "hash mismatch — possible tampering or corruption",
			})
			hasDrift = true
			continue
		}
		result.Findings = append(result.Findings, Finding{
			Key:      filename,
			Expected: expectedHash,
			Actual:   actualHash,
			Status:   "pass",
		})
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

// defaultMaxModelSize is 10 GiB.
const defaultMaxModelSize = 10 << 30

// hashModelFiles walks a directory and returns filename -> sha256 for model files.
// Rejects symlinks, device files, FIFOs, and files exceeding maxSize.
func hashModelFiles(dir string, formats []string, maxSize int64) (map[string]string, error) {
	results := make(map[string]string)
	formatSet := make(map[string]bool)
	for _, f := range formats {
		formatSet["."+f] = true
	}

	if maxSize <= 0 {
		maxSize = defaultMaxModelSize
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Reject symlinks
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if len(formatSet) > 0 && !formatSet[ext] {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		// Use Lstat to detect symlinks that ReadDir may not flag
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		// Reject non-regular files (symlinks, devices, FIFOs, sockets)
		if !info.Mode().IsRegular() {
			continue
		}
		// Enforce max file size
		if info.Size() > maxSize {
			continue
		}

		hash, err := sha256File(path)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", entry.Name(), err)
		}
		results[entry.Name()] = hash
	}
	return results, nil
}

// sha256File computes the SHA-256 hex digest of a file.
func sha256File(path string) (string, error) {
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

// maxRegistryResponse is the maximum response body size from the registry (1 MiB).
const maxRegistryResponse = 1 << 20

// fetchRegistryManifest calls the SecAI_OS registry to get approved models.
// tokenEnv names the environment variable holding a bearer token for registry auth.
func fetchRegistryManifest(registryURL, tokenEnv string) ([]RegistryModel, error) {
	if registryURL == "" {
		return nil, fmt.Errorf("registry_url not configured")
	}

	// Basic URL validation: must start with http:// or https://
	if !strings.HasPrefix(registryURL, "http://") && !strings.HasPrefix(registryURL, "https://") {
		return nil, fmt.Errorf("registry_url must use http or https scheme: %q", registryURL)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, registryURL+"/v1/models", nil)
	if err != nil {
		return nil, fmt.Errorf("build registry request: %w", err)
	}

	// Add auth header if configured
	if tokenEnv != "" {
		if tok := os.Getenv(tokenEnv); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}

	var envelope struct {
		Models []RegistryModel `json:"models"`
	}
	// Limit response body to prevent unbounded reads
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistryResponse)).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode registry response: %w", err)
	}
	return envelope.Models, nil
}

// ---------------------------------------------------------------------------
// Container collector
// ---------------------------------------------------------------------------

// collectContainerState checks running containers against expected images.
func collectContainerState(cfg ContainerConfig) CollectorResult {
	result := CollectorResult{
		Name:      "container",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	rt := cfg.Runtime
	if rt == "" {
		rt = "podman"
	}

	// Check if runtime is available.
	if _, err := exec.LookPath(rt); err != nil {
		result.Status = "skipped"
		result.Error = fmt.Sprintf("%s not found in PATH", rt)
		return result
	}

	// List running containers: output image digests.
	out, err := exec.Command(rt, "ps", "--format", "{{.Image}}|||{{.Names}}|||{{.ID}}").Output()
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("%s ps: %v", rt, err)
		return result
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		result.Status = "pass"
		result.Findings = append(result.Findings, Finding{
			Key:    "running_containers",
			Status: "pass",
			Detail: "no running containers",
		})
		return result
	}

	expectedSet := make(map[string]bool)
	for _, img := range cfg.ExpectedImages {
		expectedSet[img] = true
	}

	hasDrift := false
	for _, line := range lines {
		parts := strings.SplitN(line, "|||", 3)
		if len(parts) < 1 {
			continue
		}
		image := strings.TrimSpace(parts[0])
		name := ""
		if len(parts) > 1 {
			name = strings.TrimSpace(parts[1])
		}

		key := fmt.Sprintf("container:%s", name)
		if len(expectedSet) > 0 && !expectedSet[image] {
			result.Findings = append(result.Findings, Finding{
				Key:    key,
				Actual: image,
				Status: "drift",
				Detail: "unexpected container image",
			})
			hasDrift = true
		} else {
			result.Findings = append(result.Findings, Finding{
				Key:    key,
				Actual: image,
				Status: "pass",
			})
		}
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

// ---------------------------------------------------------------------------
// Network collector
// ---------------------------------------------------------------------------

// collectNetworkState checks listening ports against the allowed list.
func collectNetworkState(cfg NetworkConfig) CollectorResult {
	result := CollectorResult{
		Name:      "network",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	listeners, err := getListeners()
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("get listeners: %v", err)
		return result
	}

	allowedSet := make(map[string]bool)
	for _, addr := range cfg.AllowedListeners {
		allowedSet[addr] = true
	}

	hasDrift := false
	for _, listener := range listeners {
		if allowedSet[listener] {
			result.Findings = append(result.Findings, Finding{
				Key:    listener,
				Status: "pass",
				Detail: "expected listener",
			})
		} else if cfg.DenyUnexpectedListeners {
			result.Findings = append(result.Findings, Finding{
				Key:    listener,
				Status: "drift",
				Detail: "unexpected listener — not in allowed list",
			})
			hasDrift = true
		}
	}

	// Check for expected listeners that are missing.
	listenerSet := make(map[string]bool)
	for _, l := range listeners {
		listenerSet[l] = true
	}
	for _, expected := range cfg.AllowedListeners {
		if !listenerSet[expected] {
			result.Findings = append(result.Findings, Finding{
				Key:      expected,
				Expected: "listening",
				Actual:   "not found",
				Status:   "drift",
				Detail:   "expected listener not active",
			})
			hasDrift = true
		}
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

// getListeners returns a list of listening TCP addresses (host:port).
func getListeners() ([]string, error) {
	if runtime.GOOS == "linux" {
		return getListenersLinux()
	}
	return getListenersFallback()
}

// getListenersLinux parses /proc/net/tcp and /proc/net/tcp6.
func getListenersLinux() ([]string, error) {
	var listeners []string
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 { // header
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// State 0A = LISTEN
			if fields[3] != "0A" {
				continue
			}
			addr, err := parseProcNetAddr(fields[1])
			if err != nil {
				continue
			}
			listeners = append(listeners, addr)
		}
	}
	return listeners, nil
}

// parseProcNetAddr converts hex address from /proc/net/tcp to host:port.
func parseProcNetAddr(hexAddr string) (string, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid address: %s", hexAddr)
	}

	hexIP := parts[0]
	hexPort := parts[1]

	portVal, err := hexToUint16(hexPort)
	if err != nil {
		return "", err
	}

	var ip string
	if len(hexIP) == 8 {
		// IPv4: stored in little-endian
		b, err := hex.DecodeString(hexIP)
		if err != nil {
			return "", err
		}
		ip = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	} else {
		ip = "[::]"
	}

	return fmt.Sprintf("%s:%d", ip, portVal), nil
}

func hexToUint16(s string) (uint16, error) {
	var val uint16
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			val |= uint16(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex char: %c", c)
		}
	}
	return val, nil
}

// getListenersFallback uses netstat for non-Linux platforms.
func getListenersFallback() ([]string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("netstat", "-an", "-p", "tcp")
	default:
		cmd = exec.Command("ss", "-tlnH")
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat/ss: %w", err)
	}

	var listeners []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if runtime.GOOS == "darwin" {
			// macOS netstat: look for LISTEN lines
			if !strings.Contains(line, "LISTEN") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				listeners = append(listeners, normalizeAddr(fields[3]))
			}
		} else {
			// ss output: 4th field is local address
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				listeners = append(listeners, normalizeAddr(fields[3]))
			}
		}
	}
	return listeners, nil
}

// normalizeAddr cleans up address formats (e.g., *.8470 -> 0.0.0.0:8470).
func normalizeAddr(addr string) string {
	addr = strings.Replace(addr, "*.", "0.0.0.0:", 1)
	addr = strings.Replace(addr, "[::]:", "0.0.0.0:", 1)
	return addr
}

// ---------------------------------------------------------------------------
// Mount collector
// ---------------------------------------------------------------------------

// collectMountState verifies expected mount points exist and have correct properties.
func collectMountState(cfg MountConfig) CollectorResult {
	result := CollectorResult{
		Name:      "mount",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if len(cfg.Expected) == 0 {
		result.Status = "skipped"
		result.Error = "no expected mounts configured"
		return result
	}

	mounts, err := parseMounts()
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("parse mounts: %v", err)
		return result
	}

	hasDrift := false
	for _, exp := range cfg.Expected {
		mount, found := mounts[exp.Path]
		if !found {
			result.Findings = append(result.Findings, Finding{
				Key:      exp.Path,
				Expected: "mounted",
				Actual:   "not found",
				Status:   "drift",
				Detail:   "expected mount point missing",
			})
			hasDrift = true
			continue
		}

		// Check filesystem type if specified.
		if exp.FSType != "" && mount.fstype != exp.FSType {
			result.Findings = append(result.Findings, Finding{
				Key:      exp.Path,
				Expected: exp.FSType,
				Actual:   mount.fstype,
				Status:   "drift",
				Detail:   "filesystem type mismatch",
			})
			hasDrift = true
			continue
		}

		// Check readonly flag.
		if exp.ReadOnly && !mount.readonly {
			result.Findings = append(result.Findings, Finding{
				Key:      exp.Path,
				Expected: "readonly",
				Actual:   "read-write",
				Status:   "drift",
				Detail:   "mount should be read-only",
			})
			hasDrift = true
			continue
		}

		result.Findings = append(result.Findings, Finding{
			Key:    exp.Path,
			Status: "pass",
			Detail: fmt.Sprintf("mounted (%s)", mount.fstype),
		})
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

type mountInfo struct {
	device   string
	fstype   string
	readonly bool
}

// parseMounts reads /proc/mounts (Linux) or runs mount (macOS).
func parseMounts() (map[string]mountInfo, error) {
	mounts := make(map[string]mountInfo)

	var data []byte
	var err error

	if runtime.GOOS == "linux" {
		data, err = os.ReadFile("/proc/mounts")
	} else {
		data, err = exec.Command("mount").Output()
	}
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		var mi mountInfo
		if runtime.GOOS == "linux" {
			// Format: device mountpoint fstype options ...
			mi.device = fields[0]
			mi.fstype = fields[2]
			mi.readonly = strings.Contains(fields[3], "ro")
			mounts[fields[1]] = mi
		} else {
			// macOS: device on mountpoint (fstype, options)
			onIdx := -1
			for i, f := range fields {
				if f == "on" {
					onIdx = i
					break
				}
			}
			if onIdx < 1 || onIdx+1 >= len(fields) {
				continue
			}
			mi.device = fields[0]
			mountpoint := fields[onIdx+1]
			if onIdx+2 < len(fields) {
				typeAndOpts := strings.Join(fields[onIdx+2:], " ")
				typeAndOpts = strings.Trim(typeAndOpts, "()")
				parts := strings.SplitN(typeAndOpts, ",", 2)
				if len(parts) > 0 {
					mi.fstype = strings.TrimSpace(parts[0])
				}
				if len(parts) > 1 {
					mi.readonly = strings.Contains(parts[1], "read-only")
				}
			}
			mounts[mountpoint] = mi
		}
	}
	return mounts, nil
}

// ---------------------------------------------------------------------------
// GPU collector
// ---------------------------------------------------------------------------

// collectGPUState checks for GPU device exposure and isolation.
func collectGPUState(cfg GPUConfig) CollectorResult {
	result := CollectorResult{
		Name:      "gpu",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Check NVIDIA devices.
	nvidiaDevices := findNVIDIADevices()

	allowedSet := make(map[string]bool)
	for _, d := range cfg.AllowedDevices {
		allowedSet[d] = true
	}

	hasDrift := false
	for _, dev := range nvidiaDevices {
		if len(allowedSet) > 0 && !allowedSet[dev] {
			if cfg.DenyUnexpectedDevices {
				result.Findings = append(result.Findings, Finding{
					Key:    dev,
					Status: "drift",
					Detail: "unexpected GPU device exposed",
				})
				hasDrift = true
			}
		} else {
			result.Findings = append(result.Findings, Finding{
				Key:    dev,
				Status: "pass",
				Detail: "allowed GPU device",
			})
		}
	}

	// Check nvidia-smi availability for additional info.
	if smiPath, err := exec.LookPath("nvidia-smi"); err == nil {
		out, err := exec.Command(smiPath, "--query-gpu=gpu_name,driver_version,memory.total", "--format=csv,noheader").Output()
		if err == nil {
			result.Findings = append(result.Findings, Finding{
				Key:    "nvidia-smi",
				Status: "pass",
				Detail: strings.TrimSpace(string(out)),
			})
		}
	}

	if len(nvidiaDevices) == 0 {
		result.Findings = append(result.Findings, Finding{
			Key:    "gpu_devices",
			Status: "pass",
			Detail: "no NVIDIA GPU devices found (may be expected)",
		})
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

// findNVIDIADevices returns paths of NVIDIA device nodes.
func findNVIDIADevices() []string {
	var devices []string
	patterns := []string{"/dev/nvidia*", "/dev/dri/renderD*"}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		devices = append(devices, matches...)
	}
	return devices
}

// ---------------------------------------------------------------------------
// Policy collector
// ---------------------------------------------------------------------------

// collectPolicyState hashes policy files and compares against approved hashes.
func collectPolicyState(cfg PolicyFilesConfig) CollectorResult {
	result := CollectorResult{
		Name:      "policy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if len(cfg.Files) == 0 {
		result.Status = "skipped"
		result.Error = "no policy files configured"
		return result
	}

	hasDrift := false
	for name, path := range cfg.Files {
		// Reject symlinks and non-regular files for policy files
		info, err := os.Lstat(path)
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				Key:    name,
				Status: "error",
				Detail: fmt.Sprintf("cannot stat: %v", err),
			})
			hasDrift = true
			continue
		}
		if !info.Mode().IsRegular() {
			result.Findings = append(result.Findings, Finding{
				Key:    name,
				Status: "fail",
				Detail: fmt.Sprintf("policy file is not a regular file (mode=%s)", info.Mode()),
			})
			hasDrift = true
			continue
		}

		hash, err := sha256File(path)
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				Key:    name,
				Status: "error",
				Detail: fmt.Sprintf("cannot hash: %v", err),
			})
			hasDrift = true
			continue
		}

		approvedHash, hasApproved := cfg.ApprovedHashes[name]
		if !hasApproved {
			result.Findings = append(result.Findings, Finding{
				Key:    name,
				Actual: hash,
				Status: "pass",
				Detail: "no approved hash to compare (first attestation)",
			})
			continue
		}

		if hash != approvedHash {
			result.Findings = append(result.Findings, Finding{
				Key:      name,
				Expected: approvedHash,
				Actual:   hash,
				Status:   "drift",
				Detail:   "policy file changed since last approved attestation",
			})
			hasDrift = true
		} else {
			result.Findings = append(result.Findings, Finding{
				Key:      name,
				Expected: approvedHash,
				Actual:   hash,
				Status:   "pass",
			})
		}
	}

	if hasDrift {
		result.Status = "drift"
	} else {
		result.Status = "pass"
	}
	return result
}

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Types
// =========================================================================

// IntegrityState tracks the appliance filesystem trust state.
type IntegrityState string

const (
	StateTrusted          IntegrityState = "trusted"
	StateDegraded         IntegrityState = "degraded"
	StateRecoveryRequired IntegrityState = "recovery_required"
)

// WatchCategory identifies what class of file changed.
type WatchCategory string

const (
	CatServiceBinary WatchCategory = "service_binary"
	CatPolicyFile    WatchCategory = "policy_file"
	CatModelFile     WatchCategory = "model_file"
	CatSystemdUnit   WatchCategory = "systemd_unit"
	CatTrustMaterial WatchCategory = "trust_material"
)

// IntegrityViolation records a single detected change.
type IntegrityViolation struct {
	DetectedAt   string        `json:"detected_at" yaml:"detected_at"`
	Category     WatchCategory `json:"category" yaml:"category"`
	Path         string        `json:"path" yaml:"path"`
	ExpectedHash string        `json:"expected_hash" yaml:"expected_hash"`
	ActualHash   string        `json:"actual_hash" yaml:"actual_hash"`
	Action       string        `json:"action" yaml:"action"`
}

// BaselineEntry represents a single file in the signed baseline.
type BaselineEntry struct {
	Path     string        `json:"path" yaml:"path"`
	Hash     string        `json:"hash" yaml:"hash"`
	Category WatchCategory `json:"category" yaml:"category"`
	Size     int64         `json:"size" yaml:"size"`
}

// SignedBaseline is the full baseline manifest.
type SignedBaseline struct {
	CreatedAt string          `json:"created_at" yaml:"created_at"`
	Entries   []BaselineEntry `json:"entries" yaml:"entries"`
	HMAC      string          `json:"hmac" yaml:"hmac"`
}

// ReleaseBaseline is generated from the immutable, signed OS image.  It is
// the trust input for first-boot baseline initialization; the runtime HMAC
// baseline may not self-bless files that disagree with these measurements.
type ReleaseBaseline struct {
	Version      int                   `json:"version"`
	SourceCommit string                `json:"source_commit"`
	Files        []ReleaseBaselineFile `json:"files"`
}

type ReleaseBaselineFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// MonitorPolicy defines what to watch.
type MonitorPolicy struct {
	Version          int      `yaml:"version"`
	ScanInterval     string   `yaml:"scan_interval"`
	ServiceBinaries  []string `yaml:"service_binaries"`
	PolicyFiles      []string `yaml:"policy_files"`
	ModelDirs        []string `yaml:"model_dirs"`
	RegistryManifest string   `yaml:"registry_manifest"`
	SystemdUnits     []string `yaml:"systemd_units"`
	TrustMaterial    []string `yaml:"trust_material"`
	HMACKeyPath      string   `yaml:"hmac_key_path"`
	// DegradationThreshold: number of violations before recovery_required
	DegradationThreshold int `yaml:"degradation_threshold"`
}

// StatusResponse is returned by /api/security/status
type StatusResponse struct {
	State            IntegrityState       `json:"state"`
	WatchedFiles     int                  `json:"watched_files"`
	ViolationCount   int                  `json:"violation_count"`
	LastScanAt       string               `json:"last_scan_at"`
	ScanCount        int64                `json:"scan_count"`
	DegradedCount    int64                `json:"degraded_count"`
	RecoveryCount    int64                `json:"recovery_count"`
	ActiveViolations []IntegrityViolation `json:"active_violations,omitempty"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	stateMu          sync.RWMutex
	currentState     IntegrityState = StateTrusted
	activeViolations []IntegrityViolation
	lastScanAt       string

	baselineMu sync.RWMutex
	baseline   SignedBaseline

	policyMu      sync.RWMutex
	monitorPolicy MonitorPolicy

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	serviceToken          string
	incidentRecorderToken string
	hmacKey               []byte

	scanCount     atomic.Int64
	degradedCount atomic.Int64
	recoveryCount atomic.Int64
)

const maxRequestBodySize = 64 * 1024

// =========================================================================
// Policy loading
// =========================================================================

func monitorPolicyPath() string {
	p := os.Getenv("MONITOR_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/integrity-monitor.yaml"
	}
	return p
}

func loadMonitorPolicy() error {
	data, err := os.ReadFile(monitorPolicyPath())
	if err != nil {
		log.Printf("warning: monitor policy not found (%v) — using defaults", err)
		policyMu.Lock()
		monitorPolicy = MonitorPolicy{
			Version:      1,
			ScanInterval: "30s",
			ServiceBinaries: []string{
				"/usr/libexec/secure-ai/registry",
				"/usr/libexec/secure-ai/tool-firewall",
				"/usr/libexec/secure-ai/airlock",
				"/usr/libexec/secure-ai/policy-engine",
				"/usr/libexec/secure-ai/runtime-attestor",
				"/usr/libexec/secure-ai/gpu-integrity-watch",
				"/usr/libexec/secure-ai/mcp-firewall",
			},
			PolicyFiles: []string{
				"/etc/secure-ai/policy/policy.yaml",
				"/etc/secure-ai/policy/agent.yaml",
				"/etc/secure-ai/policy/attestation.yaml",
				"/etc/secure-ai/policy/landlock.yaml",
			},
			ModelDirs: []string{
				"/var/lib/secure-ai/vault/models",
			},
			RegistryManifest: "/var/lib/secure-ai/registry/manifest.json",
			SystemdUnits:     []string{},
			TrustMaterial: []string{
				"/etc/secure-ai/cosign/cosign.pub",
			},
			DegradationThreshold: 3,
		}
		policyMu.Unlock()
		return nil
	}

	var pol MonitorPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return fmt.Errorf("cannot parse monitor policy: %w", err)
	}
	if pol.ScanInterval == "" {
		pol.ScanInterval = "30s"
	}
	if pol.DegradationThreshold <= 0 {
		pol.DegradationThreshold = 3
	}
	if strings.TrimSpace(pol.RegistryManifest) == "" {
		pol.RegistryManifest = "/var/lib/secure-ai/registry/manifest.json"
	}
	policyMu.Lock()
	monitorPolicy = pol
	policyMu.Unlock()
	log.Printf("monitor policy loaded: binaries=%d policies=%d model_dirs=%d units=%d trust=%d interval=%s",
		len(pol.ServiceBinaries), len(pol.PolicyFiles), len(pol.ModelDirs),
		len(pol.SystemdUnits), len(pol.TrustMaterial), pol.ScanInterval)
	return nil
}

func getMonitorPolicy() MonitorPolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return monitorPolicy
}

// =========================================================================
// File hashing
// =========================================================================

func hashFile(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("path is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), int64(len(data)), nil
}

// collectWatchedFiles gathers all files to monitor with their categories.
func collectWatchedFiles(pol MonitorPolicy) []struct {
	path     string
	category WatchCategory
} {
	var files []struct {
		path     string
		category WatchCategory
	}

	for _, p := range pol.ServiceBinaries {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatServiceBinary})
	}
	for _, p := range pol.PolicyFiles {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatPolicyFile})
	}
	// Mutable model registries are validated against manifest.json during each
	// scan. They are deliberately not frozen into the immutable baseline.
	for _, p := range pol.SystemdUnits {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatSystemdUnit})
	}
	for _, p := range pol.TrustMaterial {
		files = append(files, struct {
			path     string
			category WatchCategory
		}{p, CatTrustMaterial})
	}
	return files
}

// =========================================================================
// Baseline management
// =========================================================================

func computeBaseline(pol MonitorPolicy) SignedBaseline {
	files := collectWatchedFiles(pol)
	var entries []BaselineEntry

	for _, f := range files {
		hash, size, err := hashFile(f.path)
		if err != nil {
			continue // Skip missing files during baseline
		}
		entries = append(entries, BaselineEntry{
			Path:     f.path,
			Hash:     hash,
			Category: f.category,
			Size:     size,
		})
	}

	// Sort for deterministic ordering
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	bl := SignedBaseline{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
	}
	bl.HMAC = computeBaselineHMAC(bl)
	return bl
}

func computeBaselineHMAC(bl SignedBaseline) string {
	if len(hmacKey) == 0 {
		return "unsigned"
	}
	bl.HMAC = ""
	data, err := json.Marshal(bl)
	if err != nil {
		return "unsigned"
	}
	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func verifyBaselineHMAC(bl SignedBaseline) bool {
	if len(hmacKey) == 0 {
		return bl.HMAC == "unsigned"
	}
	expected := computeBaselineHMAC(bl)
	return subtle.ConstantTimeCompare([]byte(bl.HMAC), []byte(expected)) == 1
}

func getBaseline() SignedBaseline {
	baselineMu.RLock()
	defer baselineMu.RUnlock()
	return baseline
}

func setBaseline(bl SignedBaseline) {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	baseline = bl
}

func baselinePath() string {
	if path := os.Getenv("BASELINE_PATH"); path != "" {
		return path
	}
	return "/var/lib/secure-ai/integrity/baseline.json"
}

func saveBaseline(bl SignedBaseline) error {
	if len(hmacKey) == 0 || bl.HMAC == "" || bl.HMAC == "unsigned" {
		return fmt.Errorf("refusing to persist unauthenticated baseline")
	}
	data, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	data = append(data, '\n')

	path := baselinePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".baseline-*")
	if err != nil {
		return fmt.Errorf("create baseline temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0644); err != nil {
		temp.Close()
		return fmt.Errorf("set baseline permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync baseline: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close baseline: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("commit baseline: %w", err)
	}
	return nil
}

func loadBaseline() (SignedBaseline, error) {
	data, err := os.ReadFile(baselinePath())
	if err != nil {
		return SignedBaseline{}, fmt.Errorf("read persisted baseline: %w", err)
	}
	if len(data) > 16*1024*1024 {
		return SignedBaseline{}, fmt.Errorf("persisted baseline exceeds 16 MiB limit")
	}
	var bl SignedBaseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return SignedBaseline{}, fmt.Errorf("decode persisted baseline: %w", err)
	}
	if bl.CreatedAt == "" || len(bl.Entries) == 0 {
		return SignedBaseline{}, fmt.Errorf("persisted baseline is incomplete")
	}
	if !verifyBaselineHMAC(bl) {
		return SignedBaseline{}, fmt.Errorf("persisted baseline HMAC verification failed")
	}
	return bl, nil
}

func initializePersistedBaseline() error {
	bl := computeBaseline(getMonitorPolicy())
	if len(bl.Entries) == 0 {
		return fmt.Errorf("refusing to initialize an empty integrity baseline")
	}
	if err := verifyReleaseBaseline(bl); err != nil {
		return fmt.Errorf("release-bound baseline verification failed: %w", err)
	}
	if err := saveBaseline(bl); err != nil {
		return err
	}
	setBaseline(bl)
	log.Printf("persisted integrity baseline initialized: entries=%d path=%s",
		len(bl.Entries), baselinePath())
	return nil
}

func expectedBaselinePath() string {
	if path := os.Getenv("EXPECTED_BASELINE_PATH"); path != "" {
		return path
	}
	return "/usr/share/secure-ai/integrity/release-baseline.json"
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func verifyReleaseBaseline(runtime SignedBaseline) error {
	data, err := os.ReadFile(expectedBaselinePath())
	if err != nil {
		return fmt.Errorf("read expected baseline: %w", err)
	}
	if len(data) > 32*1024*1024 {
		return fmt.Errorf("expected baseline exceeds 32 MiB limit")
	}
	var expected ReleaseBaseline
	if err := json.Unmarshal(data, &expected); err != nil {
		return fmt.Errorf("decode expected baseline: %w", err)
	}
	if expected.Version != 1 {
		return fmt.Errorf("unsupported expected baseline version %d", expected.Version)
	}
	if !isLowerHex(expected.SourceCommit, 40) {
		return fmt.Errorf("expected baseline source_commit is not a canonical git SHA")
	}
	if len(expected.Files) == 0 {
		return fmt.Errorf("expected baseline contains no files")
	}

	expectedByPath := make(map[string]ReleaseBaselineFile, len(expected.Files))
	for _, entry := range expected.Files {
		if !filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path {
			return fmt.Errorf("expected baseline contains invalid path %q", entry.Path)
		}
		if !isLowerHex(entry.SHA256, sha256.Size*2) || entry.Size < 0 {
			return fmt.Errorf("expected baseline contains invalid measurement for %s", entry.Path)
		}
		if _, duplicate := expectedByPath[entry.Path]; duplicate {
			return fmt.Errorf("expected baseline contains duplicate path %s", entry.Path)
		}
		expectedByPath[entry.Path] = entry

		actualHash, actualSize, err := hashFile(entry.Path)
		if err != nil {
			return fmt.Errorf("measure expected file %s: %w", entry.Path, err)
		}
		if actualHash != entry.SHA256 || actualSize != entry.Size {
			return fmt.Errorf("release measurement mismatch for %s", entry.Path)
		}
	}

	for _, entry := range runtime.Entries {
		if entry.Category == CatModelFile {
			continue
		}
		expected, ok := expectedByPath[entry.Path]
		if !ok {
			return fmt.Errorf("critical runtime path is absent from release baseline: %s", entry.Path)
		}
		if expected.SHA256 != entry.Hash || expected.Size != entry.Size {
			return fmt.Errorf("runtime baseline disagrees with release measurement for %s", entry.Path)
		}
	}
	return nil
}

type registryManifest struct {
	Version int             `json:"version"`
	Models  []registryModel `json:"models"`
}

type registryModel struct {
	Name      string `json:"name"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type registryHashedEntry struct {
	path string
	name string
	info fs.FileInfo
}

func hashRegistryArtifact(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if info.Mode().IsRegular() {
		return hashFile(path)
	}
	if !info.IsDir() {
		return "", 0, fmt.Errorf("artifact is not a regular file or directory")
	}

	var entries []registryHashedEntry
	var total int64
	entryCount := 0
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path {
			return nil
		}
		entryCount++
		if entryCount > 25_000 {
			return fmt.Errorf("artifact contains too many entries")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact contains a symbolic link: %s", current)
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("artifact contains a non-regular entry: %s", current)
		}
		if statInfo, ok := entryInfo.Sys().(*syscall.Stat_t); ok && statInfo.Nlink != 1 {
			return fmt.Errorf("artifact contains a hard-linked entry: %s", current)
		}
		relative, err := filepath.Rel(path, current)
		relative = filepath.ToSlash(relative)
		if err != nil || !filepath.IsLocal(relative) || !utf8.ValidString(relative) ||
			len([]byte(relative)) > 4096 {
			return fmt.Errorf("artifact entry escapes root: %s", current)
		}
		entries = append(entries, registryHashedEntry{
			path: current,
			name: relative,
			info: entryInfo,
		})
		if len(entries) > 20_000 || entryInfo.Size() < 0 ||
			entryInfo.Size() > int64(50)*1024*1024*1024 {
			return fmt.Errorf("artifact exceeds file limits")
		}
		total += entryInfo.Size()
		if total > int64(64)*1024*1024*1024 {
			return fmt.Errorf("artifact exceeds total size limit")
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	digest := sha256.New()
	_, _ = digest.Write([]byte("SecAI-Directory-Hash-v1\x00"))
	for _, entry := range entries {
		nameBytes := []byte(entry.name)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(len(nameBytes)))
		_, _ = digest.Write(encoded[:])
		_, _ = digest.Write(nameBytes)
		binary.BigEndian.PutUint64(encoded[:], uint64(entry.info.Size()))
		_, _ = digest.Write(encoded[:])
		file, err := os.Open(entry.path)
		if err != nil {
			return "", 0, err
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() ||
			!os.SameFile(entry.info, openedInfo) ||
			openedInfo.Size() != entry.info.Size() {
			file.Close()
			return "", 0, fmt.Errorf("artifact changed while hashing: %s", entry.path)
		}
		_, copyErr := io.CopyN(digest, file, openedInfo.Size())
		var extra [1]byte
		if extraCount, extraErr := file.Read(extra[:]); extraErr != nil && extraErr != io.EOF {
			copyErr = extraErr
		} else if extraCount != 0 {
			copyErr = fmt.Errorf("artifact changed while hashing: %s", entry.path)
		}
		afterInfo, afterErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil {
			return "", 0, copyErr
		}
		if afterErr != nil || !os.SameFile(openedInfo, afterInfo) ||
			afterInfo.Size() != openedInfo.Size() ||
			!afterInfo.ModTime().Equal(openedInfo.ModTime()) {
			return "", 0, fmt.Errorf("artifact changed while hashing: %s", entry.path)
		}
		if closeErr != nil {
			return "", 0, closeErr
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), total, nil
}

func modelViolation(now, path, expected, actual string) IntegrityViolation {
	return IntegrityViolation{
		DetectedAt:   now,
		Category:     CatModelFile,
		Path:         path,
		ExpectedHash: expected,
		ActualHash:   actual,
		Action:       actionForCategory(CatModelFile),
	}
}

// verifyModelRegistry treats the registry manifest as the enrollment
// authority for mutable model artifacts. The manifest itself is never frozen
// into the release baseline; every scan instead validates its schema, rejects
// unknown files, and re-hashes every registered artifact.
func verifyModelRegistry(dir, manifestFile, now string) []IntegrityViolation {
	info, err := os.Lstat(manifestFile)
	if err != nil || !info.Mode().IsRegular() {
		return []IntegrityViolation{
			modelViolation(now, manifestFile, "valid registry manifest", "missing_or_nonregular"),
		}
	}
	data, err := os.ReadFile(manifestFile)
	if err != nil || len(data) > 16*1024*1024 {
		return []IntegrityViolation{
			modelViolation(now, manifestFile, "valid registry manifest", "unreadable_or_oversized"),
		}
	}
	var manifest registryManifest
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Version != 1 {
		return []IntegrityViolation{
			modelViolation(now, manifestFile, "valid version-1 registry manifest", "invalid"),
		}
	}

	expected := make(map[string]registryModel, len(manifest.Models))
	var violations []IntegrityViolation
	for _, model := range manifest.Models {
		clean := filepath.Clean(model.Filename)
		if model.Name == "" || clean == "." || filepath.Base(clean) != clean ||
			!filepath.IsLocal(clean) || !isLowerHex(model.SHA256, sha256.Size*2) ||
			model.SizeBytes < 0 {
			violations = append(violations,
				modelViolation(now, manifestFile, "canonical model entry", "invalid_entry"))
			continue
		}
		if _, duplicate := expected[clean]; duplicate {
			violations = append(violations,
				modelViolation(now, manifestFile, "unique model filename", "duplicate_entry"))
			continue
		}
		expected[clean] = model
	}

	for filename, model := range expected {
		artifactPath := filepath.Join(dir, filename)
		actualHash, actualSize, err := hashRegistryArtifact(artifactPath)
		if err != nil {
			violations = append(violations,
				modelViolation(now, artifactPath, model.SHA256, "missing_or_invalid"))
			continue
		}
		if actualHash != model.SHA256 || actualSize != model.SizeBytes {
			violations = append(violations,
				modelViolation(now, artifactPath, model.SHA256, actualHash))
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return append(violations,
			modelViolation(now, dir, "readable registry directory", "unreadable"))
	}
	for _, entry := range entries {
		if entry.Name() == "manifest.json" {
			continue
		}
		if _, enrolled := expected[entry.Name()]; !enrolled {
			violations = append(violations,
				modelViolation(now, filepath.Join(dir, entry.Name()),
					"registered artifact", "unregistered"))
		}
	}
	return violations
}

// =========================================================================
// Integrity scan
// =========================================================================

func performScan() (IntegrityState, []IntegrityViolation) {
	pol := getMonitorPolicy()
	bl := getBaseline()
	files := collectWatchedFiles(pol)

	// Build lookup from baseline
	baselineMap := make(map[string]BaselineEntry)
	for _, e := range bl.Entries {
		baselineMap[e.Path] = e
	}

	var violations []IntegrityViolation
	now := time.Now().UTC().Format(time.RFC3339)
	for _, dir := range pol.ModelDirs {
		violations = append(violations, verifyModelRegistry(dir, pol.RegistryManifest, now)...)
	}

	for _, f := range files {
		baseEntry, inBaseline := baselineMap[f.path]
		hash, _, err := hashFile(f.path)

		if err != nil {
			if inBaseline {
				// File was in baseline but now missing
				violations = append(violations, IntegrityViolation{
					DetectedAt:   now,
					Category:     f.category,
					Path:         f.path,
					ExpectedHash: baseEntry.Hash,
					ActualHash:   "missing",
					Action:       actionForCategory(f.category),
				})
			}
			continue
		}

		if inBaseline && hash != baseEntry.Hash {
			violations = append(violations, IntegrityViolation{
				DetectedAt:   now,
				Category:     f.category,
				Path:         f.path,
				ExpectedHash: baseEntry.Hash,
				ActualHash:   hash,
				Action:       actionForCategory(f.category),
			})
		}
	}

	// Check for files in baseline that are no longer watched (deleted)
	for path, entry := range baselineMap {
		if entry.Category == CatModelFile {
			continue
		}
		found := false
		for _, f := range files {
			if f.path == path {
				found = true
				break
			}
		}
		if !found {
			// File was removed entirely
			violations = append(violations, IntegrityViolation{
				DetectedAt:   now,
				Category:     entry.Category,
				Path:         path,
				ExpectedHash: entry.Hash,
				ActualHash:   "removed",
				Action:       actionForCategory(entry.Category),
			})
		}
	}

	// Determine state
	state := StateTrusted
	if len(violations) > 0 {
		state = StateDegraded
		degradedCount.Add(1)
	}
	if len(violations) >= pol.DegradationThreshold {
		state = StateRecoveryRequired
		recoveryCount.Add(1)
	}

	scanCount.Add(1)

	// Update global state
	stateMu.Lock()
	currentState = state
	activeViolations = violations
	lastScanAt = now
	stateMu.Unlock()

	// Audit log
	for _, v := range violations {
		writeAudit(v)
	}

	log.Printf("scan complete: state=%s violations=%d watched=%d",
		state, len(violations), len(files))

	// Report violations to the incident-recorder (async, non-blocking).
	// Capture token to avoid race with global state reset.
	if len(violations) > 0 {
		token := incidentRecorderToken
		go reportViolations(state, violations, token)
	}

	return state, violations
}

func actionForCategory(cat WatchCategory) string {
	switch cat {
	case CatServiceBinary:
		return "degrade_appliance"
	case CatPolicyFile:
		return "reload_policy"
	case CatModelFile:
		return "quarantine_model"
	case CatSystemdUnit:
		return "degrade_appliance"
	case CatTrustMaterial:
		return "degrade_appliance"
	default:
		return "log_alert"
	}
}

func getCurrentStatus() StatusResponse {
	stateMu.RLock()
	defer stateMu.RUnlock()

	bl := getBaseline()
	return StatusResponse{
		State:            currentState,
		WatchedFiles:     len(bl.Entries),
		ViolationCount:   len(activeViolations),
		LastScanAt:       lastScanAt,
		ScanCount:        scanCount.Load(),
		DegradedCount:    degradedCount.Load(),
		RecoveryCount:    recoveryCount.Load(),
		ActiveViolations: activeViolations,
	}
}

// =========================================================================
// Audit logging
// =========================================================================

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/integrity-monitor-audit.jsonl"
	}
	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("warning: cannot create audit log dir: %v", err)
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

func writeAudit(v IntegrityViolation) {
	if auditFile == nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
}

// =========================================================================
// Service token auth
// =========================================================================

func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("read service token %s: %w", tokenPath, err)
	}
	serviceToken = strings.TrimSpace(string(data))
	if serviceToken == "" {
		return fmt.Errorf("service token %s is empty", tokenPath)
	}
	return nil
}

func loadIncidentRecorderToken() error {
	path := os.Getenv("INCIDENT_RECORDER_TOKEN_PATH")
	if path == "" {
		return fmt.Errorf("INCIDENT_RECORDER_TOKEN_PATH is not configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read incident-recorder token %s: %w", path, err)
	}
	incidentRecorderToken = strings.TrimSpace(string(data))
	if incidentRecorderToken == "" {
		return fmt.Errorf("incident-recorder token %s is empty", path)
	}
	return nil
}

func loadHMACKey() error {
	pol := getMonitorPolicy()
	keyPath := os.Getenv("HMAC_KEY_PATH")
	if keyPath == "" {
		keyPath = pol.HMACKeyPath
	}
	if keyPath == "" {
		keyPath = "/run/secure-ai/integrity-hmac-key"
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read integrity HMAC key %s: %w", keyPath, err)
	}
	if len(data) < 32 {
		return fmt.Errorf("integrity HMAC key %s is too short", keyPath)
	}
	hmacKey = data
	return nil
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			http.Error(w, `{"error":"service authentication unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

// =========================================================================
// HTTP handlers
// =========================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	state := currentState
	stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"state":  state,
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := getCurrentStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bl := getBaseline()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bl)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, violations := performScan()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"state":      state,
		"violations": violations,
	})
}

func handleRebaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if os.Getenv("ENABLE_REMOTE_REBASELINE") != "true" {
		http.Error(w, `{"error":"remote rebaseline is disabled; use the offline recovery workflow"}`,
			http.StatusForbidden)
		return
	}
	pol := getMonitorPolicy()
	bl := computeBaseline(pol)
	if len(bl.Entries) == 0 {
		http.Error(w, `{"error":"refusing to persist an empty baseline"}`,
			http.StatusConflict)
		return
	}
	if err := verifyReleaseBaseline(bl); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"release-bound verification failed: %s"}`, err),
			http.StatusConflict)
		return
	}
	if err := saveBaseline(bl); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"persist baseline: %s"}`, err),
			http.StatusInternalServerError)
		return
	}
	setBaseline(bl)
	log.Printf("baseline recomputed: %d entries", len(bl.Entries))

	// Clear violations after rebaseline
	stateMu.Lock()
	currentState = StateTrusted
	activeViolations = nil
	stateMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "rebaselined",
		"entries": len(bl.Entries),
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadMonitorPolicy(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	state := currentState
	stateMu.RUnlock()

	trusted := state == StateTrusted
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if !trusted {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"trusted": trusted,
		"state":   state,
	})
}

func newIntegrityMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Only liveness is unauthenticated. Baseline/status data and every control
	// operation require the target-specific service credential.
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/status", requireServiceToken(handleStatus))
	mux.HandleFunc("/api/v1/baseline", requireServiceToken(handleBaseline))
	mux.HandleFunc("/api/v1/verify", requireServiceToken(handleVerify))
	mux.HandleFunc("/api/v1/scan", requireServiceToken(handleScan))
	mux.HandleFunc("/api/v1/rebaseline", requireServiceToken(handleRebaseline))
	mux.HandleFunc("/api/v1/reload", requireServiceToken(handleReload))
	return mux
}

// =========================================================================
// Scan loop
// =========================================================================

func startScanLoop() {
	pol := getMonitorPolicy()
	interval := 30 * time.Second
	if pol.ScanInterval != "" {
		if d, err := time.ParseDuration(pol.ScanInterval); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			performScan()
		}
	}()
	log.Printf("continuous scan loop started: interval=%s", interval)
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadMonitorPolicy(); err != nil {
		log.Fatalf("failed to load monitor policy: %v", err)
	}

	if err := loadHMACKey(); err != nil {
		log.Fatalf("baseline authentication unavailable: %v", err)
	}

	if len(os.Args) == 2 && os.Args[1] == "--initialize-baseline" {
		if err := initializePersistedBaseline(); err != nil {
			log.Fatalf("cannot initialize integrity baseline: %v", err)
		}
		return
	}

	initAuditLog()
	if err := loadServiceToken(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := loadIncidentRecorderToken(); err != nil {
		log.Fatalf("incident-recorder authentication unavailable: %v", err)
	}

	// The baseline is initialized once during trusted first boot.  Restarts
	// verify and reuse it; they never bless the current filesystem state.
	bl, err := loadBaseline()
	if err != nil {
		log.Fatalf("trusted integrity baseline unavailable: %v", err)
	}
	setBaseline(bl)
	log.Printf("authenticated baseline loaded: %d entries", len(bl.Entries))

	// Initial scan
	state, violations := performScan()
	log.Printf("initial scan: state=%s violations=%d", state, len(violations))

	// Start continuous scanning
	startScanLoop()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8510"
	}

	log.Printf("secure-ai-integrity-monitor listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           newIntegrityMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down integrity-monitor...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("integrity-monitor stopped")
}

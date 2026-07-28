package main

import (
	"bytes"
	"context"
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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Artifact represents a promoted model in the trusted registry.
type Artifact struct {
	Name                string                `json:"name" yaml:"name"`
	Format              string                `json:"format" yaml:"format"`
	Filename            string                `json:"filename" yaml:"filename"`
	SHA256              string                `json:"sha256" yaml:"sha256"`
	SizeBytes           int64                 `json:"size_bytes" yaml:"size_bytes"`
	Source              string                `json:"source,omitempty" yaml:"source,omitempty"`
	PromotedAt          string                `json:"promoted_at" yaml:"promoted_at"`
	ScanResults         map[string]string     `json:"scan_results,omitempty" yaml:"scan_results,omitempty"`
	ScannerVersions     map[string]string     `json:"scanner_versions,omitempty" yaml:"scanner_versions,omitempty"`
	PolicyVersion       string                `json:"policy_version,omitempty" yaml:"policy_version,omitempty"`
	PolicyBundle        *PolicyBundleEvidence `json:"policy_bundle,omitempty" yaml:"policy_bundle,omitempty"`
	SourceRevision      string                `json:"source_revision,omitempty" yaml:"source_revision,omitempty"`
	DirectoryProvenance *DirectoryProvenance  `json:"directory_provenance,omitempty" yaml:"directory_provenance,omitempty"`
	Blocked             bool                  `json:"blocked,omitempty" yaml:"blocked,omitempty"`
	BlockedReason       string                `json:"blocked_reason,omitempty" yaml:"blocked_reason,omitempty"`
	// gguf-guard integrity data (GGUF files only)
	GGUFGuardFingerprint map[string]any `json:"gguf_guard_fingerprint,omitempty" yaml:"gguf_guard_fingerprint,omitempty"`
	GGUFGuardManifest    string         `json:"gguf_guard_manifest,omitempty" yaml:"gguf_guard_manifest,omitempty"` // path to manifest file
}

// Manifest is the runtime registry manifest. Metadata remains outside the
// relockable vault while encrypted model blobs live under the vault mount.
type Manifest struct {
	Version int        `json:"version"`
	Models  []Artifact `json:"models"`
}

// ModelsLock is the baked-in models.lock.yaml from /etc/secure-ai.
type ModelsLock struct {
	Version int        `yaml:"version"`
	Models  []Artifact `yaml:"models"`
}

type PolicyBundleEvidence struct {
	Version    int               `json:"version" yaml:"version"`
	SHA256     string            `json:"sha256" yaml:"sha256"`
	Components map[string]string `json:"components" yaml:"components"`
}

type DirectoryProvenance struct {
	Trust               string  `json:"trust" yaml:"trust"`
	ManifestSHA256      string  `json:"manifest_sha256" yaml:"manifest_sha256"`
	Revision            string  `json:"revision" yaml:"revision"`
	RepoID              string  `json:"repo_id" yaml:"repo_id"`
	Variant             *string `json:"variant" yaml:"variant"`
	FilesChecked        int     `json:"files_checked" yaml:"files_checked"`
	TotalSizeBytes      int64   `json:"total_size_bytes" yaml:"total_size_bytes"`
	SHA256FilesChecked  int     `json:"sha256_files_checked" yaml:"sha256_files_checked"`
	GitBlobFilesChecked int     `json:"git_blob_files_checked" yaml:"git_blob_files_checked"`
}

type directoryModelPin struct {
	Filename       string  `yaml:"filename"`
	Source         string  `yaml:"source"`
	RepoID         string  `yaml:"repo_id"`
	Revision       string  `yaml:"revision"`
	Variant        *string `yaml:"variant"`
	FileCount      int     `yaml:"file_count"`
	TotalSizeBytes int64   `yaml:"total_size_bytes"`
	ManifestSHA256 string  `yaml:"manifest_sha256"`
}

type directoryModelsLock struct {
	Version         int                 `yaml:"version"`
	DirectoryModels []directoryModelPin `yaml:"directory_models"`
}

// PromoteRequest is sent by the quarantine pipeline to promote an artifact.
type PromoteRequest struct {
	Name                 string                `json:"name"`
	Filename             string                `json:"filename"`
	StagedFilename       string                `json:"staged_filename,omitempty"`
	SHA256               string                `json:"sha256"`
	SizeBytes            int64                 `json:"size_bytes"`
	Source               string                `json:"source,omitempty"`
	ScanResults          map[string]string     `json:"scan_results,omitempty"`
	ScannerVersions      map[string]string     `json:"scanner_versions,omitempty"`
	PolicyVersion        string                `json:"policy_version,omitempty"`
	PolicyBundle         *PolicyBundleEvidence `json:"policy_bundle,omitempty"`
	SourceRevision       string                `json:"source_revision,omitempty"`
	DirectoryProvenance  *DirectoryProvenance  `json:"directory_provenance,omitempty"`
	GGUFGuardFingerprint map[string]any        `json:"gguf_guard_fingerprint,omitempty"`
	GGUFGuardManifest    string                `json:"gguf_guard_manifest,omitempty"`
}

// QuarantineRequest is a fail-closed containment transaction. The requested
// model must resolve to exactly one manifest entry; arbitrary filesystem paths
// are never accepted.
type QuarantineRequest struct {
	Action     string `json:"action"`
	IncidentID string `json:"incident_id"`
	Reason     string `json:"reason,omitempty"`
	ModelName  string `json:"model_name,omitempty"`
	ModelPath  string `json:"model_path,omitempty"`
}

var (
	manifest         Manifest
	manifestMu       sync.RWMutex
	registryDir      string
	manifestPath     string
	allowedFmts      = map[string]bool{"gguf": true, "safetensors": true, "diffusion-directory": true}
	readToken        string
	verifyToken      string
	promoteToken     string
	adminToken       string
	serviceToken     string
	containmentToken string
	manifestSource   string
	manifestDigest   [sha256.Size]byte
)

func readTokenFile(path, label string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s token path is not configured", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s token %s: %w", label, path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s token %s is empty", label, path)
	}
	return token, nil
}

// loadEndpointTokens loads independent credentials for each registry authority.
// The legacy shared token is accepted only in an explicitly declared sandbox
// deployment; a missing native credential can therefore never widen access.
func loadEndpointTokens() error {
	readPath := strings.TrimSpace(os.Getenv("REGISTRY_READ_TOKEN_PATH"))
	verifyPath := strings.TrimSpace(os.Getenv("REGISTRY_VERIFY_TOKEN_PATH"))
	promotePath := strings.TrimSpace(os.Getenv("REGISTRY_PROMOTE_TOKEN_PATH"))
	adminPath := strings.TrimSpace(os.Getenv("REGISTRY_ADMIN_TOKEN_PATH"))
	scopedPaths := []string{readPath, verifyPath, promotePath, adminPath}
	configured := 0
	for _, path := range scopedPaths {
		if path != "" {
			configured++
		}
	}

	readToken, verifyToken, promoteToken, adminToken, serviceToken = "", "", "", "", ""
	if configured == 0 && strings.TrimSpace(os.Getenv("SECURE_AI_DEPLOYMENT_MODE")) == "sandbox" {
		legacy, err := readTokenFile(
			strings.TrimSpace(os.Getenv("SERVICE_TOKEN_PATH")),
			"sandbox registry service",
		)
		if err != nil {
			return err
		}
		serviceToken = legacy
		readToken, verifyToken, promoteToken, adminToken = legacy, legacy, legacy, legacy
		return nil
	}
	if configured != len(scopedPaths) {
		return fmt.Errorf("all registry scope token paths must be configured")
	}

	var err error
	if readToken, err = readTokenFile(readPath, "registry read"); err != nil {
		return err
	}
	if verifyToken, err = readTokenFile(verifyPath, "registry verify"); err != nil {
		return err
	}
	if promoteToken, err = readTokenFile(promotePath, "registry promote"); err != nil {
		return err
	}
	if adminToken, err = readTokenFile(adminPath, "registry admin"); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(scopedPaths))
	for _, token := range []string{readToken, verifyToken, promoteToken, adminToken} {
		if _, duplicate := seen[token]; duplicate {
			return fmt.Errorf("registry scope credentials must have distinct values")
		}
		seen[token] = struct{}{}
	}
	return nil
}

func loadContainmentToken() error {
	containmentToken = ""
	tokenPath := strings.TrimSpace(os.Getenv("CONTAINMENT_TOKEN_PATH"))
	if tokenPath == "" {
		return fmt.Errorf("CONTAINMENT_TOKEN_PATH is not configured")
	}
	token, err := readTokenFile(tokenPath, "registry containment")
	if err != nil {
		return err
	}
	containmentToken = token
	return nil
}

func requireReadToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerTokens(next,
		func() string { return readToken },
		func() string { return adminToken },
	)
}

func requireVerifyToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerTokens(next,
		func() string { return verifyToken },
		func() string { return adminToken },
	)
}

func requirePromoteToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerTokens(next, func() string { return promoteToken })
}

func requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerTokens(next, func() string { return adminToken })
}

func requireContainmentToken(next http.HandlerFunc) http.HandlerFunc {
	return requireBearerTokens(next, func() string { return containmentToken })
}

func requireBearerTokens(next http.HandlerFunc, tokenSources ...func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedTokens := make([]string, 0, len(tokenSources))
		for _, source := range tokenSources {
			if expected := source(); expected != "" {
				expectedTokens = append(expectedTokens, expected)
			}
		}
		if len(expectedTokens) == 0 {
			http.Error(w, `{"error":"service authentication unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		authorized := 0
		for _, expected := range expectedTokens {
			authorized |= subtle.ConstantTimeCompare([]byte(token), []byte(expected))
		}
		if authorized != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

const maxManifestBytes = 16 * 1024 * 1024

func readRegularBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the size limit", path)
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) ||
		openedInfo.Size() != info.Size() ||
		!openedInfo.ModTime().Equal(info.ModTime()) {
		return nil, fmt.Errorf("%s changed while being read", path)
	}
	return data, nil
}

func validateManifest(candidate Manifest) error {
	if candidate.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", candidate.Version)
	}
	if len(candidate.Models) > 10_000 {
		return fmt.Errorf("manifest contains too many models")
	}
	names := make(map[string]struct{}, len(candidate.Models))
	filenames := make(map[string]struct{}, len(candidate.Models))
	for index, artifact := range candidate.Models {
		name := strings.TrimSpace(artifact.Name)
		if name == "" || len(name) > 512 || strings.ContainsRune(name, 0) {
			return fmt.Errorf("model %d has an invalid name", index)
		}
		if _, duplicate := names[name]; duplicate {
			return fmt.Errorf("duplicate model name %q", name)
		}
		names[name] = struct{}{}
		filename, err := registryRel(artifact.Filename)
		if err != nil || filename != artifact.Filename {
			return fmt.Errorf("model %q has an invalid filename", name)
		}
		if _, duplicate := filenames[filename]; duplicate {
			return fmt.Errorf("duplicate model filename %q", filename)
		}
		filenames[filename] = struct{}{}
		if !allowedFmts[artifact.Format] {
			return fmt.Errorf("model %q has unsupported format %q", name, artifact.Format)
		}
		if artifact.Format != "diffusion-directory" &&
			formatFromFilename(filename) != artifact.Format {
			return fmt.Errorf("model %q format does not match its filename", name)
		}
		if !lowerHex64Pattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("model %q has an invalid sha256", name)
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > maxDirectoryTotalBytes {
			return fmt.Errorf("model %q has an invalid size", name)
		}
		if artifact.GGUFGuardManifest != "" {
			clean, err := registryRel(artifact.GGUFGuardManifest)
			if err != nil || clean != artifact.GGUFGuardManifest {
				return fmt.Errorf("model %q has an invalid gguf-guard manifest path", name)
			}
		}
	}
	return nil
}

func decodeRuntimeManifest(data []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var candidate Manifest
	if err := decoder.Decode(&candidate); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, fmt.Errorf("manifest must contain exactly one JSON object")
	}
	if err := validateManifest(candidate); err != nil {
		return Manifest{}, err
	}
	return candidate, nil
}

func decodeModelsLock(data []byte) (Manifest, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var lock ModelsLock
	if err := decoder.Decode(&lock); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, fmt.Errorf("models lock must contain exactly one YAML document")
	}
	candidate := Manifest{Version: lock.Version, Models: lock.Models}
	if err := validateManifest(candidate); err != nil {
		return Manifest{}, err
	}
	return candidate, nil
}

func loadManifest() error {
	// A missing runtime manifest is a supported first-boot condition. Any other
	// access or parse failure is evidence of damaged state and must not be
	// silently replaced with an empty registry.
	data, err := readRegularBounded(manifestPath, maxManifestBytes)
	if err == nil {
		candidate, decodeErr := decodeRuntimeManifest(data)
		if decodeErr != nil {
			return fmt.Errorf("decode runtime manifest %s: %w", manifestPath, decodeErr)
		}
		manifest = candidate
		manifestSource = manifestPath
		manifestDigest = sha256.Sum256(data)
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("read runtime manifest %s: %w", manifestPath, err)
	}

	// Fall back to baked-in models.lock.yaml
	lockPath := os.Getenv("REGISTRY_LOCK_PATH")
	if lockPath == "" {
		lockPath = "/etc/secure-ai/policy/models.lock.yaml"
	}
	data, err = readRegularBounded(lockPath, maxManifestBytes)
	if err != nil {
		return fmt.Errorf("read registry lock %s: %w", lockPath, err)
	}
	candidate, err := decodeModelsLock(data)
	if err != nil {
		return fmt.Errorf("decode registry lock %s: %w", lockPath, err)
	}
	manifest = candidate
	manifestSource = lockPath
	manifestDigest = sha256.Sum256(data)
	return nil
}

func manifestSourceError() error {
	if manifestSource == "" {
		return fmt.Errorf("manifest source is unavailable")
	}
	data, err := readRegularBounded(manifestSource, maxManifestBytes)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(actual[:], manifestDigest[:]) != 1 {
		return fmt.Errorf("manifest source changed after startup")
	}
	if manifestSource == manifestPath {
		_, err = decodeRuntimeManifest(data)
	} else {
		_, err = decodeModelsLock(data)
	}
	return err
}

func saveManifest() error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(manifestPath), ".manifest-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, manifestPath); err != nil {
		return err
	}
	manifestSource = manifestPath
	manifestDigest = sha256.Sum256(data)
	return nil
}

func formatFromFilename(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".gguf":
		return "gguf"
	case ".safetensors":
		return "safetensors"
	default:
		return ext
	}
}

func registryRel(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("empty filename")
	}
	if strings.ContainsRune(filename, 0) {
		return "", fmt.Errorf("filename contains null byte")
	}
	if strings.Contains(filename, "\\") {
		return "", fmt.Errorf("filename contains path separator")
	}

	clean := filepath.Clean(filename)
	if clean == "." || !filepath.IsLocal(clean) {
		return "", fmt.Errorf("filename escapes registry directory")
	}
	return clean, nil
}

func registryPath(filename string) (string, error) {
	clean, err := registryRel(filename)
	if err != nil {
		return "", err
	}
	return filepath.Join(registryDir, clean), nil
}

func openRegistryRoot() (*os.Root, error) {
	return os.OpenRoot(registryDir)
}

func promotionStagingDir() string {
	if dir := os.Getenv("PROMOTION_STAGING_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/secure-ai/promotion-staging"
}

func registryContainmentDir() string {
	if dir := strings.TrimSpace(os.Getenv("REGISTRY_CONTAINMENT_DIR")); dir != "" {
		return dir
	}
	return "/var/lib/secure-ai/vault/contained-models"
}

func strictBasename(name string) (string, error) {
	clean, err := registryRel(name)
	if err != nil {
		return "", err
	}
	if filepath.Base(clean) != clean {
		return "", fmt.Errorf("nested paths are not allowed")
	}
	return clean, nil
}

const (
	maxPromotionBodyBytes  = 1 << 20
	maxDirectoryFiles      = 20_000
	maxDirectoryEntries    = 25_000
	maxDirectoryPathBytes  = 4096
	maxDirectoryTotalBytes = int64(64) * 1024 * 1024 * 1024
	maxDirectoryFileBytes  = int64(50) * 1024 * 1024 * 1024
	maxControlFileBytes    = 16 * 1024 * 1024
)

var (
	lowerHex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerHex40Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoIDPattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$`)
	yaraNamePattern   = regexp.MustCompile(`^yara/[A-Za-z0-9._-]+\.yar$`)
)

func sha256RegularControlFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxControlFileBytes {
		return "", fmt.Errorf("control file is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxControlFileBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func resolveYARARulesDir() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("REGISTRY_YARA_RULES_DIR")); configured != "" {
		return configured, nil
	}
	var candidates []string
	for _, pattern := range []string{
		"/usr/lib/python*/site-packages/quarantine/yara_rules",
		"/usr/lib64/python*/site-packages/quarantine/yara_rules",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return "", err
		}
		for _, match := range matches {
			if info, err := os.Lstat(match); err == nil && info.IsDir() {
				candidates = append(candidates, match)
			}
		}
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("expected one installed quarantine YARA directory, found %d", len(candidates))
	}
	return candidates[0], nil
}

func validatePolicyBundle(req PromoteRequest) error {
	evidence := req.PolicyBundle
	if evidence == nil || evidence.Version != 1 ||
		!lowerHex64Pattern.MatchString(evidence.SHA256) ||
		req.PolicyVersion != evidence.SHA256 ||
		len(evidence.Components) < 5 || len(evidence.Components) > 1024 {
		return fmt.Errorf("complete version-1 policy_bundle evidence is required")
	}

	required := []string{
		"policy.yaml",
		"models.lock.yaml",
		"diffusion-models.lock.yaml",
		"sources.allowlist.yaml",
	}
	for _, name := range required {
		if !lowerHex64Pattern.MatchString(evidence.Components[name]) {
			return fmt.Errorf("policy_bundle component %s is missing or invalid", name)
		}
	}
	var yaraNames []string
	for name, digest := range evidence.Components {
		if !lowerHex64Pattern.MatchString(digest) {
			return fmt.Errorf("policy_bundle component %s has an invalid digest", name)
		}
		if slicesContain(required, name) {
			continue
		}
		if !yaraNamePattern.MatchString(name) {
			return fmt.Errorf("policy_bundle component name %q is not allowed", name)
		}
		yaraNames = append(yaraNames, name)
	}
	if len(yaraNames) == 0 {
		return fmt.Errorf("policy_bundle contains no YARA rules")
	}
	sort.Strings(yaraNames)

	digest := sha256.New()
	_, _ = digest.Write([]byte("SecAI-Policy-Bundle-v1\x00"))
	for _, name := range append(required, yaraNames...) {
		nameBytes := []byte(name)
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(nameBytes)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(nameBytes)
		componentDigest, _ := hex.DecodeString(evidence.Components[name])
		_, _ = digest.Write(componentDigest)
	}
	if subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(digest.Sum(nil))),
		[]byte(evidence.SHA256),
	) != 1 {
		return fmt.Errorf("policy_bundle digest is inconsistent")
	}

	policyDir := strings.TrimSpace(os.Getenv("REGISTRY_POLICY_DIR"))
	if policyDir == "" {
		policyDir = "/etc/secure-ai/policy"
	}
	for _, name := range required {
		actual, err := sha256RegularControlFile(filepath.Join(policyDir, name))
		if err != nil {
			return fmt.Errorf("cannot verify installed policy component %s: %w", name, err)
		}
		if subtle.ConstantTimeCompare(
			[]byte(actual),
			[]byte(evidence.Components[name]),
		) != 1 {
			return fmt.Errorf("installed policy component %s does not match scan evidence", name)
		}
	}
	yaraDir, err := resolveYARARulesDir()
	if err != nil {
		return fmt.Errorf("cannot resolve installed YARA policy: %w", err)
	}
	installedRules, err := filepath.Glob(filepath.Join(yaraDir, "*.yar"))
	if err != nil || len(installedRules) != len(yaraNames) {
		return fmt.Errorf("installed YARA policy set does not match scan evidence")
	}
	expectedRules := make(map[string]string, len(yaraNames))
	for _, logicalName := range yaraNames {
		expectedRules[filepath.Base(logicalName)] = evidence.Components[logicalName]
	}
	for _, rulePath := range installedRules {
		expected, enrolled := expectedRules[filepath.Base(rulePath)]
		if !enrolled {
			return fmt.Errorf("installed YARA rule %s was not included in scan evidence", filepath.Base(rulePath))
		}
		actual, err := sha256RegularControlFile(rulePath)
		if err != nil || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			return fmt.Errorf("installed YARA rule %s does not match scan evidence", filepath.Base(rulePath))
		}
	}
	return nil
}

func slicesContain(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func directoryLockPath() string {
	if path := strings.TrimSpace(os.Getenv("DIFFUSION_MODELS_LOCK_PATH")); path != "" {
		return path
	}
	return "/etc/secure-ai/policy/diffusion-models.lock.yaml"
}

func validateDirectoryProvenance(
	req PromoteRequest,
	finalRel string,
	files int,
	totalBytes int64,
) error {
	provenance := req.DirectoryProvenance
	if provenance == nil ||
		provenance.Trust != "image-owned-manifest-pin" ||
		!lowerHex64Pattern.MatchString(provenance.ManifestSHA256) ||
		!lowerHex40Pattern.MatchString(provenance.Revision) ||
		!repoIDPattern.MatchString(provenance.RepoID) ||
		(provenance.Variant != nil && *provenance.Variant != "fp16") ||
		provenance.FilesChecked < 1 ||
		provenance.FilesChecked > maxDirectoryFiles ||
		provenance.TotalSizeBytes < 1 ||
		provenance.TotalSizeBytes > maxDirectoryTotalBytes ||
		provenance.SHA256FilesChecked < 0 ||
		provenance.GitBlobFilesChecked < 0 ||
		provenance.SHA256FilesChecked+provenance.GitBlobFilesChecked != provenance.FilesChecked {
		return fmt.Errorf("directory_provenance is incomplete or invalid")
	}
	expectedSource := "https://huggingface.co/" + provenance.RepoID
	parsed, err := url.Parse(req.Source)
	if err != nil || req.Source != expectedSource || parsed.Scheme != "https" ||
		parsed.Host != "huggingface.co" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("directory source does not match provenance repository")
	}
	if req.SourceRevision != provenance.Revision ||
		req.SizeBytes != totalBytes ||
		provenance.TotalSizeBytes != totalBytes ||
		provenance.FilesChecked != files {
		return fmt.Errorf("directory provenance does not match copied artifact")
	}

	lockData, err := os.ReadFile(directoryLockPath())
	if err != nil || len(lockData) > maxControlFileBytes {
		return fmt.Errorf("trusted diffusion model lock is unavailable")
	}
	var lock directoryModelsLock
	if err := yaml.Unmarshal(lockData, &lock); err != nil || lock.Version != 1 {
		return fmt.Errorf("trusted diffusion model lock is invalid")
	}
	var matched *directoryModelPin
	for index := range lock.DirectoryModels {
		entry := &lock.DirectoryModels[index]
		if entry.Filename == finalRel {
			if matched != nil {
				return fmt.Errorf("trusted diffusion model lock has duplicate filename")
			}
			matched = entry
		}
	}
	if matched == nil ||
		matched.Source != req.Source ||
		matched.RepoID != provenance.RepoID ||
		matched.Revision != provenance.Revision ||
		!equalOptionalString(matched.Variant, provenance.Variant) ||
		matched.FileCount != files ||
		matched.TotalSizeBytes != totalBytes ||
		matched.ManifestSHA256 != provenance.ManifestSHA256 {
		return fmt.Errorf("directory provenance does not match image-owned lock")
	}
	return nil
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func copyStagedArtifact(srcRoot, dstRoot *os.Root, srcRel, dstRel string) error {
	info, err := srcRoot.Lstat(srcRel)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("staged artifact must not be a symbolic link")
	}
	if info.Mode().IsRegular() {
		if links := linkCount(info); links != 0 && links != 1 {
			return fmt.Errorf("hard-linked staged artifacts are not allowed")
		}
		if info.Size() < 0 || info.Size() > maxDirectoryFileBytes {
			return fmt.Errorf("staged artifact exceeds size limit")
		}
		src, err := srcRoot.Open(srcRel)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := dstRoot.OpenFile(dstRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(dst, src, info.Size())
		var extra [1]byte
		if extraCount, extraErr := src.Read(extra[:]); extraErr != nil && extraErr != io.EOF {
			copyErr = extraErr
		} else if extraCount != 0 {
			copyErr = fmt.Errorf("staged artifact changed while copying")
		}
		syncErr := dst.Sync()
		closeErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	if !info.IsDir() {
		return fmt.Errorf("staged artifact must be a regular file or directory")
	}
	if err := dstRoot.Mkdir(dstRel, 0750); err != nil {
		return err
	}
	entryCount := 0
	fileCount := 0
	var totalBytes int64
	return fs.WalkDir(srcRoot.FS(), filepath.ToSlash(srcRel), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == filepath.ToSlash(srcRel) {
			return nil
		}
		entryCount++
		if entryCount > maxDirectoryEntries {
			return fmt.Errorf("staged directory contains too many entries")
		}
		relative, err := filepath.Rel(srcRel, filepath.FromSlash(path))
		if err != nil || relative == "." || !filepath.IsLocal(relative) {
			return fmt.Errorf("invalid staged directory entry %q", path)
		}
		relativeSlash := filepath.ToSlash(relative)
		if !utf8.ValidString(relativeSlash) ||
			len([]byte(relativeSlash)) > maxDirectoryPathBytes {
			return fmt.Errorf("invalid staged directory path %q", path)
		}
		target := filepath.Join(dstRel, relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed in staged directories")
		}
		if entry.IsDir() {
			return dstRoot.Mkdir(target, 0750)
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("non-regular staged entry %q is not allowed", path)
		}
		if links := linkCount(entryInfo); links != 0 && links != 1 {
			return fmt.Errorf("hard-linked staged entry %q is not allowed", path)
		}
		if entryInfo.Size() < 0 || entryInfo.Size() > maxDirectoryFileBytes {
			return fmt.Errorf("staged entry %q exceeds size limit", path)
		}
		fileCount++
		totalBytes += entryInfo.Size()
		if fileCount > maxDirectoryFiles || totalBytes > maxDirectoryTotalBytes {
			return fmt.Errorf("staged directory exceeds resource limits")
		}
		src, err := srcRoot.Open(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		dst, err := dstRoot.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.CopyN(dst, src, entryInfo.Size())
		var extra [1]byte
		if extraCount, extraErr := src.Read(extra[:]); extraErr != nil && extraErr != io.EOF {
			copyErr = extraErr
		} else if extraCount != 0 {
			copyErr = fmt.Errorf("staged entry %q changed while copying", path)
		}
		syncErr := dst.Sync()
		closeErr := dst.Close()
		srcCloseErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		return srcCloseErr
	})
}

// verifyFileHash computes sha256 of a file and compares to expected.
func verifyFileHash(root *os.Root, rel, expected string) (string, error) {
	f, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return actual, fmt.Errorf("hash mismatch: expected %s, got %s", expected, actual)
	}
	return actual, nil
}

type hashedEntry struct {
	fsPath   string
	hashName string
	info     fs.FileInfo
}

func linkCount(info fs.FileInfo) uint64 {
	if statInfo, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(statInfo.Nlink)
	}
	return 0
}

func computeDirectoryHashStats(root *os.Root, rel string) (string, int, int64, error) {
	entries := make([]hashedEntry, 0, 16)
	entryCount := 0
	var totalBytes int64
	if err := fs.WalkDir(root.FS(), filepath.ToSlash(rel), func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if current == filepath.ToSlash(rel) {
			return nil
		}
		entryCount++
		if entryCount > maxDirectoryEntries {
			return fmt.Errorf("artifact directory contains too many entries")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are not allowed in artifact directories")
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular entry %q is not allowed", current)
		}
		if links := linkCount(info); links != 0 && links != 1 {
			return fmt.Errorf("hard-linked entry %q is not allowed", current)
		}
		if info.Size() < 0 || info.Size() > maxDirectoryFileBytes {
			return fmt.Errorf("artifact file %q exceeds size limit", current)
		}
		totalBytes += info.Size()
		if totalBytes > maxDirectoryTotalBytes {
			return fmt.Errorf("artifact directory exceeds total size limit")
		}
		hashName, relErr := filepath.Rel(filepath.FromSlash(rel), filepath.FromSlash(current))
		if relErr != nil {
			return relErr
		}
		hashName = filepath.ToSlash(hashName)
		if hashName == "" || hashName == "." || !utf8.ValidString(hashName) ||
			len([]byte(hashName)) > maxDirectoryPathBytes {
			return fmt.Errorf("invalid artifact path %q", current)
		}
		entries = append(entries, hashedEntry{
			fsPath: current, hashName: hashName, info: info,
		})
		if len(entries) > maxDirectoryFiles {
			return fmt.Errorf("artifact directory contains too many files")
		}
		return nil
	}); err != nil {
		return "", 0, 0, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].hashName < entries[j].hashName
	})

	h := sha256.New()
	_, _ = h.Write([]byte("SecAI-Directory-Hash-v1\x00"))
	for _, entry := range entries {
		nameBytes := []byte(entry.hashName)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(len(nameBytes)))
		_, _ = h.Write(encoded[:])
		_, _ = h.Write(nameBytes)
		binary.BigEndian.PutUint64(encoded[:], uint64(entry.info.Size()))
		_, _ = h.Write(encoded[:])
		f, err := root.Open(entry.fsPath)
		if err != nil {
			return "", 0, 0, err
		}
		openedInfo, statErr := f.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() ||
			!os.SameFile(entry.info, openedInfo) ||
			openedInfo.Size() != entry.info.Size() ||
			(linkCount(openedInfo) != 0 && linkCount(openedInfo) != 1) {
			f.Close()
			return "", 0, 0, fmt.Errorf("artifact changed while hashing %q", entry.hashName)
		}
		_, copyErr := io.CopyN(h, f, openedInfo.Size())
		var extra [1]byte
		extraCount, extraErr := f.Read(extra[:])
		if extraErr != nil && extraErr != io.EOF {
			copyErr = extraErr
		} else if extraCount != 0 {
			copyErr = fmt.Errorf("artifact changed while hashing %q", entry.hashName)
		}
		afterInfo, afterErr := f.Stat()
		closeErr := f.Close()
		if copyErr != nil {
			return "", 0, 0, copyErr
		}
		if afterErr != nil || !os.SameFile(openedInfo, afterInfo) ||
			afterInfo.Size() != openedInfo.Size() ||
			!afterInfo.ModTime().Equal(openedInfo.ModTime()) {
			return "", 0, 0, fmt.Errorf("artifact changed while hashing %q", entry.hashName)
		}
		if closeErr != nil {
			return "", 0, 0, closeErr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), len(entries), totalBytes, nil
}

func computeDirectoryHash(root *os.Root, rel string) (string, error) {
	digest, _, _, err := computeDirectoryHashStats(root, rel)
	return digest, err
}

func verifyArtifactHash(root *os.Root, rel, expected string) (string, error) {
	info, err := root.Stat(rel)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		actual, err := computeDirectoryHash(root, rel)
		if err != nil {
			return "", err
		}
		if expected != "" && actual != expected {
			return actual, fmt.Errorf("hash mismatch: expected %s, got %s", expected, actual)
		}
		return actual, nil
	}
	return verifyFileHash(root, rel, expected)
}

func artifactSize(root *os.Root, rel string) (int64, error) {
	info, err := root.Stat(rel)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return info.Size(), nil
	}
	var total int64
	if err := fs.WalkDir(root.FS(), filepath.ToSlash(rel), func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	}); err != nil {
		return 0, err
	}
	return total, nil
}

func artifactFormatFromPath(root *os.Root, rel, filename string) (string, error) {
	info, err := root.Stat(rel)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		if _, err := root.Stat(filepath.Join(rel, "model_index.json")); err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("directory artifact missing model_index.json")
			}
			return "", err
		}
		return "diffusion-directory", nil
	}
	format := formatFromFilename(filename)
	if !allowedFmts[format] {
		return "", fmt.Errorf("format %q not allowed", format)
	}
	return format, nil
}

func handleListModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest.Models)
}

func handleGetModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m)
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleModelPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			rel, err := registryRel(m.Filename)
			if err != nil {
				http.Error(w, "invalid registry filename", http.StatusInternalServerError)
				return
			}
			root, err := openRegistryRoot()
			if err != nil {
				http.Error(w, "registry unavailable", http.StatusInternalServerError)
				return
			}
			defer root.Close()
			if _, err := root.Stat(rel); err != nil {
				http.Error(w, "model file not found on disk", http.StatusNotFound)
				return
			}
			path, err := registryPath(rel)
			if err != nil {
				http.Error(w, "invalid registry filename", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"path": path})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handlePromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPromotionBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req PromoteRequest
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "request body must contain exactly one JSON object", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Filename = strings.TrimSpace(req.Filename)
	req.StagedFilename = strings.TrimSpace(req.StagedFilename)
	if req.Name == "" || req.Filename == "" || req.SHA256 == "" {
		http.Error(w, "name, filename, and sha256 are required", http.StatusBadRequest)
		return
	}

	rel, err := strictBasename(req.Filename)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid filename: %v", err), http.StatusBadRequest)
		return
	}

	if req.StagedFilename == "" {
		http.Error(w, "direct promotion is disabled; staged_filename is required", http.StatusForbidden)
		return
	}

	handleStagedPromotion(w, req, rel)
}

func handleStagedPromotion(w http.ResponseWriter, req PromoteRequest, finalRel string) {
	stagedRel, err := strictBasename(req.StagedFilename)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid staged_filename: %v", err), http.StatusBadRequest)
		return
	}
	if !lowerHex64Pattern.MatchString(req.SHA256) {
		http.Error(w, "sha256 must be a lowercase 64-character hexadecimal digest", http.StatusBadRequest)
		return
	}
	if err := validatePolicyBundle(req); err != nil {
		http.Error(w, fmt.Sprintf("policy evidence rejected: %v", err), http.StatusForbidden)
		return
	}

	stagingRoot, err := os.OpenRoot(promotionStagingDir())
	if err != nil {
		http.Error(w, "promotion staging unavailable", http.StatusInternalServerError)
		return
	}
	defer stagingRoot.Close()
	registryRoot, err := openRegistryRoot()
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusInternalServerError)
		return
	}
	defer registryRoot.Close()

	tempContainer, err := os.MkdirTemp(registryDir, ".promotion-")
	if err != nil {
		http.Error(w, "cannot create promotion transaction", http.StatusInternalServerError)
		return
	}
	tempContainerRel := filepath.Base(tempContainer)
	defer registryRoot.RemoveAll(tempContainerRel)
	tempArtifactRel := filepath.Join(tempContainerRel, "artifact")

	if err := copyStagedArtifact(stagingRoot, registryRoot, stagedRel, tempArtifactRel); err != nil {
		http.Error(w, fmt.Sprintf("cannot copy staged artifact: %v", err), http.StatusForbidden)
		return
	}
	format, err := artifactFormatFromPath(registryRoot, tempArtifactRel, finalRel)
	if err != nil {
		http.Error(w, fmt.Sprintf("artifact validation failed: %v", err), http.StatusForbidden)
		return
	}
	var actualHash string
	var sizeBytes int64
	if format == "diffusion-directory" {
		var fileCount int
		actualHash, fileCount, sizeBytes, err = computeDirectoryHashStats(
			registryRoot,
			tempArtifactRel,
		)
		if err == nil && actualHash != req.SHA256 {
			err = fmt.Errorf("hash mismatch: expected %s, got %s", req.SHA256, actualHash)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("hash verification failed: %v", err), http.StatusConflict)
			return
		}
		if err := validateDirectoryProvenance(req, finalRel, fileCount, sizeBytes); err != nil {
			http.Error(w, fmt.Sprintf("directory evidence rejected: %v", err), http.StatusForbidden)
			return
		}
	} else {
		if req.DirectoryProvenance != nil {
			http.Error(w, "directory_provenance is only valid for directory artifacts", http.StatusBadRequest)
			return
		}
		actualHash, err = verifyFileHash(registryRoot, tempArtifactRel, req.SHA256)
		if err != nil {
			http.Error(w, fmt.Sprintf("hash verification failed: %v", err), http.StatusConflict)
			return
		}
		sizeBytes, err = artifactSize(registryRoot, tempArtifactRel)
		if err != nil {
			http.Error(w, "cannot stat staged artifact", http.StatusInternalServerError)
			return
		}
	}
	if req.SizeBytes != sizeBytes {
		http.Error(w, "size_bytes does not match copied artifact", http.StatusConflict)
		return
	}

	artifact := Artifact{
		Name:                req.Name,
		Format:              format,
		Filename:            finalRel,
		SHA256:              actualHash,
		SizeBytes:           sizeBytes,
		Source:              req.Source,
		PromotedAt:          time.Now().UTC().Format(time.RFC3339),
		ScanResults:         req.ScanResults,
		ScannerVersions:     req.ScannerVersions,
		PolicyVersion:       req.PolicyVersion,
		PolicyBundle:        req.PolicyBundle,
		SourceRevision:      req.SourceRevision,
		DirectoryProvenance: req.DirectoryProvenance,
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

	for _, existing := range manifest.Models {
		if existing.Name == req.Name || existing.Filename == finalRel {
			http.Error(w, "model name or final filename already exists", http.StatusConflict)
			return
		}
	}
	if _, err := registryRoot.Lstat(finalRel); err == nil {
		http.Error(w, "final artifact already exists", http.StatusConflict)
		return
	} else if !os.IsNotExist(err) {
		http.Error(w, "cannot inspect final artifact path", http.StatusInternalServerError)
		return
	}

	if err := registryRoot.Rename(tempArtifactRel, finalRel); err != nil {
		http.Error(w, "cannot commit promoted artifact", http.StatusInternalServerError)
		return
	}
	committed := false
	defer func() {
		if !committed {
			if removeErr := registryRoot.RemoveAll(finalRel); removeErr != nil {
				log.Printf("ERROR: promotion rollback failed for %s: %v", finalRel, removeErr)
			}
		}
	}()

	manifest.Models = append(manifest.Models, artifact)
	if err := saveManifest(); err != nil {
		manifest.Models = manifest.Models[:len(manifest.Models)-1]
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}
	committed = true
	if err := stagingRoot.RemoveAll(stagedRel); err != nil {
		log.Printf("warning: promoted staging input could not be removed: %v", err)
	}

	log.Printf("PROMOTED TRANSACTION: %s (%s) sha256=%s", artifact.Name, artifact.Filename, artifact.SHA256)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(artifact)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

	found := false
	filtered := make([]Artifact, 0, len(manifest.Models))
	for _, m := range manifest.Models {
		if m.Name == name {
			found = true
			// Remove the model artifact (file or directory) from disk.
			rel, err := registryRel(m.Filename)
			if err != nil {
				http.Error(w, "invalid registry filename", http.StatusInternalServerError)
				return
			}
			root, rootErr := openRegistryRoot()
			if rootErr != nil {
				http.Error(w, "registry unavailable", http.StatusInternalServerError)
				return
			}
			defer root.Close()
			if err := root.RemoveAll(rel); err != nil && !os.IsNotExist(err) {
				log.Printf("warning: could not remove %s: %v", m.Filename, err)
			}
			log.Printf("REMOVED: %s (%s)", m.Name, m.Filename)
		} else {
			filtered = append(filtered, m)
		}
	}

	if !found {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}

	manifest.Models = filtered
	if err := saveManifest(); err != nil {
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
}

func quarantineRequestMatches(req QuarantineRequest, artifact Artifact) bool {
	if req.ModelName != "" && req.ModelName != artifact.Name {
		return false
	}
	if req.ModelPath == "" {
		return req.ModelName != ""
	}
	rel, err := registryRel(artifact.Filename)
	if err != nil {
		return false
	}
	expectedPath, err := registryPath(rel)
	if err != nil {
		return false
	}
	requested := filepath.Clean(req.ModelPath)
	if filepath.IsAbs(requested) {
		return requested == filepath.Clean(expectedPath)
	}
	requestedRel, err := registryRel(requested)
	return err == nil && requestedRel == rel
}

func handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req QuarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Action = strings.TrimSpace(req.Action)
	req.IncidentID = strings.TrimSpace(req.IncidentID)
	req.ModelName = strings.TrimSpace(req.ModelName)
	req.ModelPath = strings.TrimSpace(req.ModelPath)
	if req.Action != "quarantine" || req.IncidentID == "" {
		http.Error(w, "action=quarantine and incident_id are required", http.StatusBadRequest)
		return
	}
	if req.ModelName == "" && req.ModelPath == "" {
		http.Error(w, "model_name or model_path is required", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

	matchIndex := -1
	for i, artifact := range manifest.Models {
		if quarantineRequestMatches(req, artifact) {
			if matchIndex != -1 {
				http.Error(w, "model selector is ambiguous", http.StatusConflict)
				return
			}
			matchIndex = i
		}
	}
	if matchIndex == -1 {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	artifact := manifest.Models[matchIndex]
	sourceRel, err := registryRel(artifact.Filename)
	if err != nil {
		http.Error(w, "manifest contains an invalid filename", http.StatusInternalServerError)
		return
	}
	sourceRoot, err := openRegistryRoot()
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusInternalServerError)
		return
	}
	defer sourceRoot.Close()
	sourceInfo, err := sourceRoot.Lstat(sourceRel)
	if err != nil {
		http.Error(w, "model artifact unavailable", http.StatusConflict)
		return
	}
	if sourceInfo.Mode()&os.ModeSymlink != 0 || (!sourceInfo.Mode().IsRegular() && !sourceInfo.IsDir()) {
		http.Error(w, "model artifact is not a regular file or directory", http.StatusConflict)
		return
	}

	containmentRoot, err := os.OpenRoot(registryContainmentDir())
	if err != nil {
		http.Error(w, "registry containment directory unavailable", http.StatusInternalServerError)
		return
	}
	defer containmentRoot.Close()
	incidentHash := sha256.Sum256([]byte(req.IncidentID))
	destinationRel := fmt.Sprintf(
		"contained-%s-%s",
		hex.EncodeToString(incidentHash[:6]),
		filepath.Base(sourceRel),
	)
	if _, err := strictBasename(destinationRel); err != nil {
		http.Error(w, "cannot construct containment destination", http.StatusInternalServerError)
		return
	}
	if _, err := containmentRoot.Lstat(destinationRel); err == nil {
		http.Error(w, "containment destination already exists", http.StatusConflict)
		return
	} else if !os.IsNotExist(err) {
		http.Error(w, "cannot inspect containment destination", http.StatusInternalServerError)
		return
	}

	sourcePath, err := registryPath(sourceRel)
	if err != nil {
		http.Error(w, "invalid registry source path", http.StatusInternalServerError)
		return
	}
	destinationPath := filepath.Join(registryContainmentDir(), destinationRel)
	if err := os.Rename(sourcePath, destinationPath); err != nil {
		http.Error(w, fmt.Sprintf("cannot quarantine artifact: %v", err), http.StatusInternalServerError)
		return
	}

	previousModels := append([]Artifact(nil), manifest.Models...)
	manifest.Models = append(
		append([]Artifact(nil), manifest.Models[:matchIndex]...),
		manifest.Models[matchIndex+1:]...,
	)
	if err := saveManifest(); err != nil {
		manifest.Models = previousModels
		if rollbackErr := os.Rename(destinationPath, sourcePath); rollbackErr != nil {
			log.Printf("ERROR: quarantine rollback failed for %s: %v", artifact.Name, rollbackErr)
		}
		http.Error(w, "cannot commit quarantine manifest transaction", http.StatusInternalServerError)
		return
	}

	log.Printf(
		"CONTAINED: model=%s incident=%s destination=%s reason=%q",
		artifact.Name,
		req.IncidentID,
		destinationRel,
		strings.TrimSpace(req.Reason),
	)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":               "quarantined",
		"incident_id":          req.IncidentID,
		"model_name":           artifact.Name,
		"original_filename":    artifact.Filename,
		"containment_filename": destinationRel,
		"manifest_updated":     true,
	})
}

func handleVerifyAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manifestMu.RLock()
	models := make([]Artifact, len(manifest.Models))
	copy(models, manifest.Models)
	manifestMu.RUnlock()

	results := make([]map[string]string, 0, len(models))
	allOk := true
	var root *os.Root
	if len(models) > 0 {
		var rootErr error
		root, rootErr = openRegistryRoot()
		if rootErr != nil {
			http.Error(w, "registry unavailable", http.StatusInternalServerError)
			return
		}
		defer root.Close()
	}

	for _, m := range models {
		rel, err := registryRel(m.Filename)
		if err != nil {
			allOk = false
			results = append(results, map[string]string{
				"name":   m.Name,
				"status": "failed",
				"error":  "invalid registry filename",
			})
			continue
		}
		actual, err := verifyArtifactHash(root, rel, m.SHA256)
		if err != nil {
			allOk = false
			results = append(results, map[string]string{
				"name":     m.Name,
				"status":   "failed",
				"expected": m.SHA256,
				"actual":   actual,
				"error":    err.Error(),
			})
		} else {
			results = append(results, map[string]string{
				"name":   m.Name,
				"status": "verified",
				"sha256": actual,
			})
		}
	}

	status := "ok"
	if !allOk {
		status = "failed"
	}

	resultBody := map[string]interface{}{
		"status":      status,
		"models":      results,
		"checked":     len(results),
		"verified_at": time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeIntegrityResult(resultBody); err != nil {
		log.Printf("warning: failed to persist integrity result: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	if !allOk {
		w.WriteHeader(http.StatusConflict)
	}
	json.NewEncoder(w).Encode(resultBody)
}

func handleIntegrityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resultPath := integrityResultPath()

	data, err := os.ReadFile(resultPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unknown",
			"detail": "no integrity check has run yet",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unknown",
			"detail": "integrity status file is not valid JSON",
		})
		return
	}
	json.NewEncoder(w).Encode(payload)
}

func integrityResultPath() string {
	resultPath := os.Getenv("INTEGRITY_RESULT_PATH")
	if resultPath == "" {
		resultPath = "/var/lib/secure-ai/logs/integrity-last.json"
	}
	return resultPath
}

func writeIntegrityResult(result map[string]interface{}) error {
	resultPath := integrityResultPath()
	if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(resultPath, data, 0o644)
}

func handleVerifyModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()

	for _, m := range manifest.Models {
		if m.Name == name {
			rel, err := registryRel(m.Filename)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"status":      "failed",
					"name":        name,
					"error":       "invalid registry filename",
					"safe_to_use": "false",
				})
				return
			}
			root, rootErr := openRegistryRoot()
			if rootErr != nil {
				http.Error(w, "registry unavailable", http.StatusInternalServerError)
				return
			}
			defer root.Close()
			actual, err := verifyArtifactHash(root, rel, m.SHA256)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"status":      "failed",
					"name":        name,
					"expected":    m.SHA256,
					"actual":      actual,
					"error":       err.Error(),
					"safe_to_use": "false",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":      "verified",
				"name":        name,
				"sha256":      actual,
				"safe_to_use": "true",
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	manifestMu.RLock()
	count := len(manifest.Models)
	sourceErr := manifestSourceError()
	manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	if sourceErr != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "degraded",
			"model_count": count,
			"error":       "registry enrollment metadata is unavailable or changed",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"model_count":  count,
		"registry_dir": registryDir,
	})
}

func newRegistryMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/models", requireReadToken(handleListModels))
	mux.HandleFunc("/v1/model", requireReadToken(handleGetModel))
	mux.HandleFunc("/v1/model/path", requireReadToken(handleModelPath))
	mux.HandleFunc("/v1/model/verify", requireVerifyToken(handleVerifyModel))
	mux.HandleFunc("/v1/models/verify-all", requireVerifyToken(handleVerifyAll))
	mux.HandleFunc("/v1/integrity/status", requireVerifyToken(handleIntegrityStatus))
	mux.HandleFunc("/v1/model/verify-manifest", requireVerifyToken(handleVerifyGGUFManifest))
	mux.HandleFunc("/v1/model/promote", requirePromoteToken(handlePromote))
	mux.HandleFunc("/v1/model/delete", requireAdminToken(handleDelete))
	mux.HandleFunc("/api/v1/quarantine", requireContainmentToken(handleQuarantine))
	return mux
}

// ggufGuardBin is the path to the gguf-guard binary for manifest verification.
const ggufGuardBin = "/usr/local/bin/gguf-guard"

func handleVerifyGGUFManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()

	for _, m := range manifest.Models {
		if m.Name == name {
			if m.GGUFGuardManifest == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "skipped",
					"name":   name,
					"reason": "no gguf-guard manifest available",
				})
				return
			}

			modelPath, err := registryPath(m.Filename)
			if err != nil {
				http.Error(w, "invalid registry filename", http.StatusConflict)
				return
			}
			manifestFile, err := registryPath(m.GGUFGuardManifest)
			if err != nil {
				http.Error(w, "invalid gguf-guard manifest path", http.StatusConflict)
				return
			}

			out, err := runGGUFGuardVerify(modelPath, manifestFile)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"status": "failed",
					"name":   name,
					"error":  out,
				})
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "verified",
				"name":   name,
				"detail": out,
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

// runGGUFGuardVerify runs gguf-guard verify-manifest and returns output and error.
func runGGUFGuardVerify(modelPath, manifestFile string) (string, error) {
	out, err := exec.Command(ggufGuardBin, "verify-manifest", modelPath, manifestFile).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		return result, err
	}
	return result, nil
}

func main() {
	registryDir = os.Getenv("REGISTRY_DIR")
	if registryDir == "" {
		registryDir = "/registry"
	}
	manifestPath = strings.TrimSpace(os.Getenv("REGISTRY_MANIFEST_PATH"))
	if manifestPath == "" {
		manifestPath = filepath.Join(registryDir, "manifest.json")
	}

	if err := loadManifest(); err != nil {
		log.Fatalf("registry enrollment metadata unavailable: %v", err)
	}
	log.Printf("loaded %d model(s) from manifest", len(manifest.Models))

	if err := loadEndpointTokens(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := loadContainmentToken(); err != nil {
		if strings.TrimSpace(os.Getenv("CONTAINMENT_TOKEN_PATH")) != "" {
			log.Fatalf("containment authentication unavailable: %v", err)
		}
		log.Printf("containment endpoint disabled: %v", err)
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8470"
	}

	log.Printf("secure-ai-registry listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           newRegistryMux(),
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
	log.Println("shutting down registry...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	log.Println("registry stopped")
}

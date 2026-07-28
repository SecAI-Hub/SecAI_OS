package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// =========================================================================
// Attestation state types
// =========================================================================

// AttestationState tracks the overall appliance trust state.
type AttestationState string

const (
	StateAttested AttestationState = "attested"
	StateDegraded AttestationState = "degraded"
	StateFailed   AttestationState = "failed"
	StatePending  AttestationState = "pending"
)

// RuntimeStateBundle is the signed evidence emitted at boot and periodically.
type RuntimeStateBundle struct {
	Timestamp               string            `json:"timestamp" yaml:"timestamp"`
	State                   AttestationState  `json:"state" yaml:"state"`
	AssuranceMode           string            `json:"assurance_mode" yaml:"assurance_mode"`
	EvidenceVerified        bool              `json:"evidence_verified" yaml:"evidence_verified"`
	RequestNonce            string            `json:"request_nonce" yaml:"request_nonce"`
	BootMeasurements        BootMeasurements  `json:"boot_measurements" yaml:"boot_measurements"`
	DeploymentDigest        string            `json:"deployment_digest" yaml:"deployment_digest"`
	DeploymentVerified      bool              `json:"deployment_verified" yaml:"deployment_verified"`
	ReleaseSourceCommit     string            `json:"release_source_commit" yaml:"release_source_commit"`
	ReleaseBaselineVerified bool              `json:"release_baseline_verified" yaml:"release_baseline_verified"`
	ServiceDigests          map[string]string `json:"service_digests" yaml:"service_digests"`
	PolicyDigest            string            `json:"policy_digest" yaml:"policy_digest"`
	RegistryManifestHash    string            `json:"registry_manifest_hash" yaml:"registry_manifest_hash"`
	KernelCmdline           string            `json:"kernel_cmdline" yaml:"kernel_cmdline"`
	KernelLockdown          string            `json:"kernel_lockdown" yaml:"kernel_lockdown"`
	TPMAvailable            bool              `json:"tpm_available" yaml:"tpm_available"`
	TPMMeasurementsVerified bool              `json:"tpm_measurements_verified" yaml:"tpm_measurements_verified"`
	TPMQuoteVerified        bool              `json:"tpm_quote_verified" yaml:"tpm_quote_verified"`
	TPMAKPublicKeySHA256    string            `json:"tpm_ak_public_key_sha256" yaml:"tpm_ak_public_key_sha256"`
	TPMQuotePCRSelection    string            `json:"tpm_quote_pcr_selection" yaml:"tpm_quote_pcr_selection"`
	Failures                []string          `json:"failures,omitempty" yaml:"failures,omitempty"`
	BundleHMAC              string            `json:"bundle_hmac" yaml:"bundle_hmac"`
}

// BootMeasurements captures TPM2 PCR values and Secure Boot state.
type BootMeasurements struct {
	SecureBootEnabled bool              `json:"secure_boot_enabled" yaml:"secure_boot_enabled"`
	PCRValues         map[string]string `json:"pcr_values,omitempty" yaml:"pcr_values,omitempty"`
	MeasuredAt        string            `json:"measured_at" yaml:"measured_at"`
}

// AttestationPolicy defines what must be verified.
type AttestationPolicy struct {
	Version           int               `yaml:"version"`
	RequireTPM        bool              `yaml:"require_tpm"`
	RequireSecureBoot bool              `yaml:"require_secure_boot"`
	ExpectedPCRs      map[string]string `yaml:"expected_pcrs"`
	ServiceBinaries   map[string]string `yaml:"service_binaries"`
	PolicyFiles       []string          `yaml:"policy_files"`
	RefreshInterval   string            `yaml:"refresh_interval"`
	HMACKeyPath       string            `yaml:"hmac_key_path"`
}

// AttestationHardwareProfile is enrolled locally after the signed boot chain,
// Secure Boot, TPM, AK, and PCR baseline have all been verified. A hardware
// profile is mandatory before the service may claim hardware assurance.
type AttestationHardwareProfile struct {
	Version               int               `json:"version"`
	Mode                  string            `json:"mode"`
	RequireTPM            bool              `json:"require_tpm"`
	RequireSecureBoot     bool              `json:"require_secure_boot"`
	AKHandle              string            `json:"ak_handle"`
	AKPublicKeySHA256     string            `json:"ak_public_key_sha256"`
	PCRSelection          string            `json:"pcr_selection"`
	ExpectedPCRs          map[string]string `json:"expected_pcrs"`
	QuotedPCRDigestSHA256 string            `json:"quoted_pcr_digest_sha256"`
	EnrolledDeployment    string            `json:"enrolled_deployment"`
	EnrolledAt            string            `json:"enrolled_at"`
}

// ReleaseBaseline is generated within the signed appliance image. Runtime
// attestation compares configured services and policies to these expected
// measurements rather than treating the existence of a file as trust.
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

type bootVerificationRecord struct {
	Status string `json:"status"`
	Checks struct {
		OstreeSignature struct {
			State  string `json:"state"`
			Commit string `json:"commit"`
		} `json:"ostree_signature"`
	} `json:"checks"`
}

// =========================================================================
// Globals
// =========================================================================

var (
	stateMu       sync.RWMutex
	currentState  AttestationState = StatePending
	currentBundle RuntimeStateBundle

	attestPolicy   AttestationPolicy
	attestPolicyMu sync.RWMutex

	hardwareProfile   AttestationHardwareProfile
	hardwareProfileMu sync.RWMutex

	auditFile     *os.File
	auditMu       sync.Mutex
	auditPath     string
	auditEnforced bool

	serviceToken          string
	incidentRecorderToken string
	hmacKey               []byte

	attestCount  atomic.Int64
	degradeCount atomic.Int64
	failCount    atomic.Int64
)

const (
	maxRequestBodySize   = 64 * 1024
	maxCommandOutput     = 1 << 20
	maxAKPublicKeyBytes  = 64 << 10
	commandTimeout       = 5 * time.Second
	hardwarePCRSelection = "sha256:0,2,4,7"
	hardwareAKHandle     = "0x81010020"
)

// =========================================================================
// Policy loading
// =========================================================================

func attestPolicyPath() string {
	p := os.Getenv("ATTESTATION_POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/attestation.yaml"
	}
	return p
}

func loadAttestPolicy() error {
	data, err := os.ReadFile(attestPolicyPath())
	if err != nil {
		// Use defaults if no policy file
		log.Printf("warning: attestation policy not found (%v) — using defaults", err)
		attestPolicyMu.Lock()
		attestPolicy = AttestationPolicy{
			Version:           1,
			RequireTPM:        false,
			RequireSecureBoot: false,
			RefreshInterval:   "5m",
			ServiceBinaries: map[string]string{
				"registry":      "/usr/libexec/secure-ai/registry",
				"tool-firewall": "/usr/libexec/secure-ai/tool-firewall",
				"airlock":       "/usr/libexec/secure-ai/airlock",
				"policy-engine": "/usr/libexec/secure-ai/policy-engine",
			},
			PolicyFiles: []string{
				"/etc/secure-ai/policy/policy.yaml",
				"/etc/secure-ai/policy/agent.yaml",
			},
		}
		attestPolicyMu.Unlock()
		return nil
	}

	var pol AttestationPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return fmt.Errorf("cannot parse attestation policy: %w", err)
	}
	attestPolicyMu.Lock()
	attestPolicy = pol
	attestPolicyMu.Unlock()
	log.Printf("attestation policy loaded: require_tpm=%t require_sb=%t services=%d",
		pol.RequireTPM, pol.RequireSecureBoot, len(pol.ServiceBinaries))
	return nil
}

func getAttestPolicy() AttestationPolicy {
	attestPolicyMu.RLock()
	defer attestPolicyMu.RUnlock()
	return attestPolicy
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("path is not canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("path is not a regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("file size %d exceeds limit %d", info.Size(), limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) ||
		opened.Size() < 0 || opened.Size() > limit {
		return nil, fmt.Errorf("file changed or became unsafe while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds limit %d", limit)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("file changed while reading")
	}
	return data, nil
}

func loadHardwareProfile() error {
	path := strings.TrimSpace(os.Getenv("ATTESTATION_PROFILE_PATH"))
	if path == "" {
		hardwareProfileMu.Lock()
		hardwareProfile = AttestationHardwareProfile{Version: 1, Mode: "software"}
		hardwareProfileMu.Unlock()
		return nil
	}
	data, err := readBoundedRegularFile(path, 64*1024)
	if err != nil {
		return fmt.Errorf("read attestation hardware profile %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile AttestationHardwareProfile
	if err := decoder.Decode(&profile); err != nil {
		return fmt.Errorf("decode attestation hardware profile: %w", err)
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return fmt.Errorf("decode attestation hardware profile: %w", err)
	}
	if profile.Version != 1 {
		return fmt.Errorf("unsupported attestation hardware profile version %d", profile.Version)
	}
	switch profile.Mode {
	case "evaluation":
		if profile.RequireTPM || profile.RequireSecureBoot ||
			profile.AKHandle != "" || profile.AKPublicKeySHA256 != "" ||
			profile.PCRSelection != "" || len(profile.ExpectedPCRs) != 0 ||
			profile.QuotedPCRDigestSHA256 != "" {
			return fmt.Errorf("evaluation profile contains hardware trust assertions")
		}
	case "hardware":
		if !profile.RequireTPM || !profile.RequireSecureBoot {
			return fmt.Errorf("hardware profile must require TPM and Secure Boot")
		}
		if profile.AKHandle != hardwareAKHandle ||
			profile.PCRSelection != hardwarePCRSelection ||
			!canonicalSHA256(profile.AKPublicKeySHA256) ||
			!canonicalSHA256(profile.QuotedPCRDigestSHA256) {
			return fmt.Errorf("hardware profile has invalid AK or PCR binding")
		}
		if !validExpectedPCRs(profile.ExpectedPCRs) {
			return fmt.Errorf("hardware profile has invalid expected PCR values")
		}
		if !strings.HasPrefix(profile.EnrolledDeployment, "sha256:") ||
			!canonicalSHA256(strings.TrimPrefix(profile.EnrolledDeployment, "sha256:")) {
			return fmt.Errorf("hardware profile lacks a verified deployment digest")
		}
		if _, err := time.Parse(time.RFC3339Nano, profile.EnrolledAt); err != nil {
			return fmt.Errorf("hardware profile enrollment time is invalid")
		}
	default:
		return fmt.Errorf("unsupported attestation assurance mode %q", profile.Mode)
	}
	hardwareProfileMu.Lock()
	hardwareProfile = profile
	hardwareProfileMu.Unlock()
	return nil
}

func getHardwareProfile() AttestationHardwareProfile {
	hardwareProfileMu.RLock()
	defer hardwareProfileMu.RUnlock()
	profile := hardwareProfile
	profile.ExpectedPCRs = cloneStringMap(profile.ExpectedPCRs)
	return profile
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func validExpectedPCRs(values map[string]string) bool {
	if len(values) != 4 {
		return false
	}
	for _, pcr := range []string{"0", "2", "4", "7"} {
		value, ok := values[pcr]
		if !ok || len(value) != 66 || !strings.HasPrefix(value, "0x") ||
			!canonicalSHA256(strings.TrimPrefix(value, "0x")) {
			return false
		}
	}
	return true
}

func ensureDecoderEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

// =========================================================================
// Measurement collectors
// =========================================================================

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > writer.limit-writer.buffer.Len() {
		return 0, fmt.Errorf("command output exceeds %d bytes", writer.limit)
	}
	return writer.buffer.Write(data)
}

func runBoundedCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	output := &boundedBuffer{limit: maxCommandOutput}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s timed out after %s", name, commandTimeout)
	}
	if err != nil {
		detail := strings.TrimSpace(output.buffer.String())
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail == "" {
			return nil, fmt.Errorf("%s failed: %w", name, err)
		}
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, detail)
	}
	result := append([]byte(nil), output.buffer.Bytes()...)
	return result, nil
}

// collectBootMeasurements reads Secure Boot status and TPM2 PCR values.
func collectBootMeasurements(pol AttestationPolicy) (BootMeasurements, bool, []string) {
	m := BootMeasurements{
		MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano),
		PCRValues:  make(map[string]string),
	}
	var failures []string
	tpmAvailable := false

	// Check Secure Boot
	sbData, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err == nil && len(sbData) >= 5 {
		m.SecureBootEnabled = sbData[4] == 1
	}
	if pol.RequireSecureBoot && !m.SecureBootEnabled {
		failures = append(failures, "Secure Boot not enabled (required by policy)")
	}

	// Read TPM2 PCR values
	out, err := runBoundedCommand("tpm2_pcrread", hardwarePCRSelection)
	if err != nil {
		if pol.RequireTPM {
			failures = append(failures, fmt.Sprintf("TPM2 not available: %v", err))
		}
	} else {
		tpmAvailable = true
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") && strings.Contains(line, "0x") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					pcr := strings.TrimSpace(parts[0])
					value := strings.ToLower(strings.TrimSpace(parts[1]))
					if len(value) == 66 && strings.HasPrefix(value, "0x") &&
						canonicalSHA256(strings.TrimPrefix(value, "0x")) {
						if _, duplicate := m.PCRValues[pcr]; duplicate {
							failures = append(failures,
								fmt.Sprintf("TPM2 returned duplicate PCR %s", pcr))
							continue
						}
						m.PCRValues[pcr] = value
					}
				}
			}
		}

		// Verify expected PCR values
		for pcr, expected := range pol.ExpectedPCRs {
			if actual, ok := m.PCRValues[pcr]; ok {
				if actual != expected {
					failures = append(failures, fmt.Sprintf("PCR %s mismatch: expected=%s actual=%s", pcr, expected, actual))
				}
			} else {
				failures = append(failures, fmt.Sprintf("PCR %s required by policy but not measured", pcr))
			}
		}
	}

	return m, tpmAvailable, failures
}

// collectDeploymentDigest reads the current rpm-ostree deployment digest.
func collectDeploymentDigest() string {
	out, err := runBoundedCommand("rpm-ostree", "status", "--json")
	if err != nil {
		return "unavailable"
	}
	h := sha256.Sum256(out)
	return hex.EncodeToString(h[:16])
}

// collectServiceDigests hashes each service binary.
func collectServiceDigests(binaries map[string]string) (map[string]string, []string) {
	digests := make(map[string]string)
	var failures []string

	for name, path := range binaries {
		data, err := os.ReadFile(path)
		if err != nil {
			digests[name] = "missing"
			failures = append(failures, fmt.Sprintf("service binary missing: %s (%s)", name, path))
			continue
		}
		h := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(h[:])
	}
	return digests, failures
}

// collectPolicyDigest hashes all policy files together and reports every
// missing/unreadable policy. Paths and separators are included to avoid
// ambiguous concatenations.
func collectPolicyDigest(files []string) (string, []string) {
	h := sha256.New()
	var failures []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			failures = append(failures,
				fmt.Sprintf("policy file missing or unreadable: %s: %v", f, err))
			continue
		}
		h.Write([]byte(f))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), failures
}

// collectRegistryManifestHash hashes the registry manifest file.
func collectRegistryManifestHash() string {
	manifestPath := strings.TrimSpace(os.Getenv("REGISTRY_MANIFEST_PATH"))
	if manifestPath == "" {
		manifestPath = "/var/lib/secure-ai/registry/manifest.json"
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "unavailable"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// collectKernelState reads kernel cmdline and lockdown state.
func collectKernelState() (string, string) {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	lockdown, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return strings.TrimSpace(string(cmdline)), "unavailable"
	}
	return strings.TrimSpace(string(cmdline)), strings.TrimSpace(string(lockdown))
}

func expectedBaselinePath() string {
	if path := os.Getenv("EXPECTED_BASELINE_PATH"); path != "" {
		return path
	}
	return "/usr/share/secure-ai/integrity/release-baseline.json"
}

func bootVerificationPath() string {
	if path := os.Getenv("BOOT_VERIFICATION_PATH"); path != "" {
		return path
	}
	return "/var/lib/secure-ai/logs/boot-verify-last.json"
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifyReleaseMeasurements(
	pol AttestationPolicy,
	serviceDigests map[string]string,
) (string, bool, []string) {
	data, err := os.ReadFile(expectedBaselinePath())
	if err != nil {
		return "", false, []string{fmt.Sprintf("release baseline unavailable: %v", err)}
	}
	if len(data) > 32*1024*1024 {
		return "", false, []string{"release baseline exceeds 32 MiB limit"}
	}

	var expected ReleaseBaseline
	if err := json.Unmarshal(data, &expected); err != nil {
		return "", false, []string{fmt.Sprintf("release baseline is invalid JSON: %v", err)}
	}
	if expected.Version != 1 {
		return expected.SourceCommit, false, []string{
			fmt.Sprintf("unsupported release baseline version: %d", expected.Version),
		}
	}
	if len(expected.SourceCommit) != 40 ||
		strings.ToLower(expected.SourceCommit) != expected.SourceCommit {
		return expected.SourceCommit, false,
			[]string{"release baseline source_commit is not a canonical git SHA"}
	}
	if _, err := hex.DecodeString(expected.SourceCommit); err != nil {
		return expected.SourceCommit, false,
			[]string{"release baseline source_commit is not hexadecimal"}
	}
	if len(expected.Files) == 0 {
		return expected.SourceCommit, false,
			[]string{"release baseline contains no measurements"}
	}

	byPath := make(map[string]ReleaseBaselineFile, len(expected.Files))
	var failures []string
	for _, entry := range expected.Files {
		if !filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path ||
			!canonicalSHA256(entry.SHA256) || entry.Size < 0 {
			failures = append(failures, fmt.Sprintf("invalid release measurement: %q", entry.Path))
			continue
		}
		if _, duplicate := byPath[entry.Path]; duplicate {
			failures = append(failures, fmt.Sprintf("duplicate release measurement: %s", entry.Path))
			continue
		}
		byPath[entry.Path] = entry
	}

	verifyPath := func(path, actualDigest string) {
		expectedEntry, ok := byPath[path]
		if !ok {
			failures = append(failures, fmt.Sprintf("path absent from release baseline: %s", path))
			return
		}
		info, err := os.Lstat(path)
		if err != nil {
			failures = append(failures,
				fmt.Sprintf("release-bound path unavailable: %s: %v", path, err))
			return
		}
		if !info.Mode().IsRegular() {
			failures = append(failures,
				fmt.Sprintf("release-bound path is not a regular file: %s", path))
			return
		}
		if actualDigest == "" {
			content, err := os.ReadFile(path)
			if err != nil {
				failures = append(failures,
					fmt.Sprintf("read release-bound path %s: %v", path, err))
				return
			}
			sum := sha256.Sum256(content)
			actualDigest = hex.EncodeToString(sum[:])
		}
		if actualDigest != expectedEntry.SHA256 || info.Size() != expectedEntry.Size {
			failures = append(failures, fmt.Sprintf("release measurement mismatch: %s", path))
		}
	}

	for name, path := range pol.ServiceBinaries {
		verifyPath(path, serviceDigests[name])
	}
	for _, path := range pol.PolicyFiles {
		verifyPath(path, "")
	}
	return expected.SourceCommit, len(failures) == 0, failures
}

func verifyDeploymentEvidence() (string, bool, []string) {
	data, err := os.ReadFile(bootVerificationPath())
	if err != nil {
		return collectDeploymentDigest(), false,
			[]string{fmt.Sprintf("boot deployment verification evidence unavailable: %v", err)}
	}
	if len(data) > 1024*1024 {
		return collectDeploymentDigest(), false,
			[]string{"boot deployment verification evidence exceeds 1 MiB limit"}
	}

	var record bootVerificationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return collectDeploymentDigest(), false,
			[]string{fmt.Sprintf("boot deployment verification evidence is invalid: %v", err)}
	}
	commit := record.Checks.OstreeSignature.Commit
	if record.Checks.OstreeSignature.State != "valid" {
		return commit, false, []string{
			fmt.Sprintf("booted deployment signature is not verified (state=%s)",
				record.Checks.OstreeSignature.State),
		}
	}
	digest := strings.TrimPrefix(commit, "sha256:")
	if !strings.HasPrefix(commit, "sha256:") || !canonicalSHA256(digest) {
		return commit, false,
			[]string{"verified deployment evidence lacks an exact sha256 digest"}
	}
	return commit, true, nil
}

type tpmQuoteEvidence struct {
	available            bool
	quoteVerified        bool
	measurementsVerified bool
	akPublicKeySHA256    string
	pcrSelection         string
	failures             []string
}

func canonicalNonce(value string) bool {
	return canonicalSHA256(value)
}

func enrolledDeploymentMatches(profile AttestationHardwareProfile, digest string) bool {
	if profile.Mode != "hardware" {
		return true
	}
	return subtle.ConstantTimeCompare(
		[]byte(profile.EnrolledDeployment),
		[]byte(digest),
	) == 1
}

func randomNonce() (string, error) {
	nonce := make([]byte, sha256.Size)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate attestation nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

func safeQuoteArtifact(path string, limit int64) ([]byte, error) {
	data, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("quote artifact is accessible outside its owner")
	}
	return data, nil
}

func verifyTPMQuote(profile AttestationHardwareProfile, nonce string) tpmQuoteEvidence {
	evidence := tpmQuoteEvidence{pcrSelection: profile.PCRSelection}
	if profile.Mode != "hardware" {
		return evidence
	}
	if !canonicalNonce(nonce) {
		evidence.failures = append(evidence.failures, "TPM quote nonce is not canonical")
		return evidence
	}
	akPath := strings.TrimSpace(os.Getenv("TPM_AK_PUBLIC_KEY_PATH"))
	if akPath == "" {
		evidence.failures = append(evidence.failures, "TPM AK public key path is not configured")
		return evidence
	}
	akPublic, err := readBoundedRegularFile(akPath, maxAKPublicKeyBytes)
	if err != nil {
		evidence.failures = append(evidence.failures,
			fmt.Sprintf("TPM AK public key is unavailable: %v", err))
		return evidence
	}
	akDigest := sha256.Sum256(akPublic)
	evidence.akPublicKeySHA256 = hex.EncodeToString(akDigest[:])
	if subtle.ConstantTimeCompare(
		[]byte(evidence.akPublicKeySHA256),
		[]byte(profile.AKPublicKeySHA256),
	) != 1 {
		evidence.failures = append(evidence.failures,
			"TPM AK public key does not match the enrolled digest")
		return evidence
	}

	directory, err := os.MkdirTemp("", "secure-ai-tpm-quote-")
	if err != nil {
		evidence.failures = append(evidence.failures,
			fmt.Sprintf("create private TPM quote directory: %v", err))
		return evidence
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			log.Printf("ERROR: cannot remove private TPM quote directory: %v", err)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		evidence.failures = append(evidence.failures,
			fmt.Sprintf("protect private TPM quote directory: %v", err))
		return evidence
	}
	messagePath := filepath.Join(directory, "quote.message")
	signaturePath := filepath.Join(directory, "quote.signature")
	pcrPath := filepath.Join(directory, "quote.pcr")

	if _, err := runBoundedCommand(
		"tpm2_quote",
		"-c", profile.AKHandle,
		"-l", profile.PCRSelection,
		"-q", nonce,
		"-m", messagePath,
		"-s", signaturePath,
		"-o", pcrPath,
		"-g", "sha256",
	); err != nil {
		evidence.failures = append(evidence.failures,
			fmt.Sprintf("TPM nonce-bound quote failed: %v", err))
		return evidence
	}
	message, err := safeQuoteArtifact(messagePath, 256*1024)
	if err != nil || len(message) == 0 {
		evidence.failures = append(evidence.failures, "TPM quote message is missing or unsafe")
		return evidence
	}
	signature, err := safeQuoteArtifact(signaturePath, 64*1024)
	if err != nil || len(signature) == 0 {
		evidence.failures = append(evidence.failures, "TPM quote signature is missing or unsafe")
		return evidence
	}
	pcrData, err := safeQuoteArtifact(pcrPath, 256*1024)
	if err != nil || len(pcrData) == 0 {
		evidence.failures = append(evidence.failures, "TPM quoted PCR data is missing or unsafe")
		return evidence
	}
	evidence.available = true

	if _, err := runBoundedCommand(
		"tpm2_checkquote",
		"-u", akPath,
		"-m", messagePath,
		"-s", signaturePath,
		"-f", pcrPath,
		"-g", "sha256",
		"-q", nonce,
	); err != nil {
		evidence.failures = append(evidence.failures,
			fmt.Sprintf("TPM quote signature or nonce verification failed: %v", err))
		return evidence
	}
	evidence.quoteVerified = true
	pcrDigest := sha256.Sum256(pcrData)
	actualPCRDigest := hex.EncodeToString(pcrDigest[:])
	if subtle.ConstantTimeCompare(
		[]byte(actualPCRDigest),
		[]byte(profile.QuotedPCRDigestSHA256),
	) != 1 {
		evidence.failures = append(evidence.failures,
			"TPM quoted PCR set differs from the enrolled hardware baseline")
		return evidence
	}
	evidence.measurementsVerified = true
	return evidence
}

// =========================================================================
// Attestation engine
// =========================================================================

func computeBundleHMAC(bundle RuntimeStateBundle) string {
	if len(hmacKey) == 0 {
		return "unsigned"
	}
	bundle.BundleHMAC = ""
	data, err := canonicalBundleJSON(bundle)
	if err != nil {
		return "unsigned"
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalBundleJSON(bundle RuntimeStateBundle) ([]byte, error) {
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return nil, err
	}
	object["bundle_hmac"] = ""
	// encoding/json deterministically sorts string map keys recursively.
	return json.Marshal(object)
}

func performAttestation() RuntimeStateBundle {
	nonce, err := randomNonce()
	if err != nil {
		log.Printf("ERROR: %v", err)
		nonce = strings.Repeat("0", sha256.Size*2)
	}
	return performAttestationWithNonce(nonce, err)
}

func performAttestationWithNonce(nonce string, nonceErr error) RuntimeStateBundle {
	pol := getAttestPolicy()
	profile := getHardwareProfile()
	if profile.Mode == "" {
		profile.Mode = "software"
	}
	effectivePolicy := pol
	effectivePolicy.RequireTPM = pol.RequireTPM || profile.RequireTPM
	effectivePolicy.RequireSecureBoot = pol.RequireSecureBoot || profile.RequireSecureBoot
	if profile.Mode == "hardware" {
		effectivePolicy.ExpectedPCRs = cloneStringMap(profile.ExpectedPCRs)
	}

	boot, tpmAvail, bootFailures := collectBootMeasurements(effectivePolicy)
	svcDigests, svcFailures := collectServiceDigests(pol.ServiceBinaries)
	policyDigest, policyFailures := collectPolicyDigest(pol.PolicyFiles)
	registryHash := collectRegistryManifestHash()
	cmdline, lockdown := collectKernelState()
	releaseSource, releaseVerified, releaseFailures := verifyReleaseMeasurements(pol, svcDigests)
	deployDigest, deploymentVerified, deploymentFailures := verifyDeploymentEvidence()
	quoteEvidence := verifyTPMQuote(profile, nonce)
	enrolledDeploymentVerified := enrolledDeploymentMatches(profile, deployDigest)

	// Combine all failures
	var failures []string
	if nonceErr != nil || !canonicalNonce(nonce) {
		failures = append(failures, "cryptographically secure attestation nonce unavailable")
	}
	failures = append(failures, bootFailures...)
	failures = append(failures, svcFailures...)
	failures = append(failures, policyFailures...)
	failures = append(failures, releaseFailures...)
	failures = append(failures, deploymentFailures...)
	failures = append(failures, quoteEvidence.failures...)
	if !enrolledDeploymentVerified {
		failures = append(failures,
			"verified deployment differs from the hardware attestation enrollment")
	}
	if effectivePolicy.RequireTPM && profile.Mode != "hardware" {
		failures = append(failures,
			"TPM policy requires an enrolled hardware attestation profile")
	}

	measurementsVerified := quoteEvidence.measurementsVerified &&
		tpmAvail && len(effectivePolicy.ExpectedPCRs) > 0
	if measurementsVerified {
		for pcr, expected := range effectivePolicy.ExpectedPCRs {
			if actual, ok := boot.PCRValues[pcr]; !ok || actual != expected {
				measurementsVerified = false
				failures = append(failures,
					"live PCR values do not match the authenticated enrolled baseline")
				break
			}
		}
	}

	// Determine state. Required hardware failures are terminal; software and
	// release drift remains degraded so operators can inspect the evidence.
	state := StateAttested
	hardwareFailure := effectivePolicy.RequireTPM &&
		(!tpmAvail || !quoteEvidence.quoteVerified || !measurementsVerified ||
			!enrolledDeploymentVerified)
	secureBootFailure := effectivePolicy.RequireSecureBoot && !boot.SecureBootEnabled
	if len(failures) > 0 {
		state = StateDegraded
		degradeCount.Add(1)
	}
	if hardwareFailure || secureBootFailure || nonceErr != nil {
		state = StateFailed
		failCount.Add(1)
	}

	attestCount.Add(1)

	bundle := RuntimeStateBundle{
		// This timestamp is deliberately captured only after the fresh quote
		// and all verification commands complete.
		Timestamp:               time.Now().UTC().Format(time.RFC3339Nano),
		State:                   state,
		AssuranceMode:           profile.Mode,
		RequestNonce:            nonce,
		BootMeasurements:        boot,
		DeploymentDigest:        deployDigest,
		DeploymentVerified:      deploymentVerified,
		ReleaseSourceCommit:     releaseSource,
		ReleaseBaselineVerified: releaseVerified,
		ServiceDigests:          svcDigests,
		PolicyDigest:            policyDigest,
		RegistryManifestHash:    registryHash,
		KernelCmdline:           cmdline,
		KernelLockdown:          lockdown,
		TPMAvailable:            tpmAvail,
		TPMMeasurementsVerified: measurementsVerified,
		TPMQuoteVerified:        quoteEvidence.quoteVerified,
		TPMAKPublicKeySHA256:    quoteEvidence.akPublicKeySHA256,
		TPMQuotePCRSelection:    quoteEvidence.pcrSelection,
		Failures:                failures,
	}
	bundle.EvidenceVerified = state == StateAttested &&
		profile.Mode == "hardware" &&
		boot.SecureBootEnabled &&
		tpmAvail &&
		measurementsVerified &&
		quoteEvidence.quoteVerified &&
		canonicalSHA256(quoteEvidence.akPublicKeySHA256) &&
		deploymentVerified &&
		enrolledDeploymentVerified &&
		releaseVerified &&
		len(hmacKey) == sha256.Size
	bundle.BundleHMAC = computeBundleHMAC(bundle)

	// Audit persistence is part of the trust decision. Never publish a
	// policy-satisfying bundle if its durable audit record could not be
	// written and synchronized.
	if err := writeAudit(bundle); err != nil && auditEnforced {
		log.Printf("ERROR: attestation audit persistence failed: %v", err)
		if bundle.State != StateFailed {
			failCount.Add(1)
		}
		bundle.State = StateFailed
		bundle.EvidenceVerified = false
		bundle.Failures = append(bundle.Failures,
			"attestation audit persistence failed")
		bundle.BundleHMAC = computeBundleHMAC(bundle)
		state = StateFailed
	}

	// Store as current state only after the audit decision is final.
	stateMu.Lock()
	currentState = state
	currentBundle = bundle
	stateMu.Unlock()

	log.Printf("attestation complete: state=%s assurance=%s evidence_verified=%t tpm=%t quote=%t sb=%t failures=%d",
		state, profile.Mode, bundle.EvidenceVerified, tpmAvail,
		bundle.TPMQuoteVerified, boot.SecureBootEnabled, len(bundle.Failures))

	// Report degraded/failed attestation to the incident-recorder (async).
	// Capture token to avoid race with global state reset in tests.
	if state == StateDegraded || state == StateFailed {
		token := incidentRecorderToken
		go reportAttestationFailure(bundle, token)
	}

	return bundle
}

func getCurrentState() (AttestationState, RuntimeStateBundle) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return currentState, currentBundle
}

// =========================================================================
// Audit logging
// =========================================================================

func initAuditLog() error {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/runtime-attestor-audit.jsonl"
	}
	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	auditFile = f
	auditEnforced = true
	return nil
}

func writeAudit(bundle RuntimeStateBundle) error {
	if auditFile == nil {
		return fmt.Errorf("audit log is unavailable")
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	record := append(data, '\n')
	written, err := auditFile.Write(record)
	if err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	if err := auditFile.Sync(); err != nil {
		return fmt.Errorf("sync audit record: %w", err)
	}
	return nil
}

// =========================================================================
// Service token auth
// =========================================================================

func readCanonicalHexCredential(path, label string) (string, []byte, error) {
	data, err := readBoundedRegularFile(path, sha256.Size*2+1)
	if err != nil {
		return "", nil, fmt.Errorf("read %s %s: %w", label, path, err)
	}
	if len(data) == sha256.Size*2+1 {
		if data[len(data)-1] != '\n' {
			return "", nil, fmt.Errorf("%s %s has invalid trailing data", label, path)
		}
		data = data[:len(data)-1]
	}
	value := string(data)
	if !canonicalSHA256(value) {
		return "", nil, fmt.Errorf("%s %s is not a canonical 256-bit lowercase hexadecimal credential", label, path)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", nil, fmt.Errorf("decode %s %s: %w", label, path, err)
	}
	return value, decoded, nil
}

func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	token, _, err := readCanonicalHexCredential(tokenPath, "service token")
	if err != nil {
		return err
	}
	serviceToken = token
	return nil
}

func loadIncidentRecorderToken() error {
	path := os.Getenv("INCIDENT_RECORDER_TOKEN_PATH")
	if path == "" {
		return fmt.Errorf("INCIDENT_RECORDER_TOKEN_PATH is not configured")
	}
	token, _, err := readCanonicalHexCredential(path, "incident-recorder reporter token")
	if err != nil {
		return err
	}
	incidentRecorderToken = token
	return nil
}

func loadHMACKey() error {
	pol := getAttestPolicy()
	keyPath := os.Getenv("HMAC_KEY_PATH")
	if keyPath == "" {
		keyPath = pol.HMACKeyPath
	}
	if keyPath == "" {
		keyPath = "/run/secure-ai/attestation-hmac-key"
	}
	_, decoded, err := readCanonicalHexCredential(keyPath, "attestation HMAC key")
	if err != nil {
		return err
	}
	hmacKey = decoded
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
	state, _ := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"state":  state,
	})
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state, bundle := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"state":  state,
		"bundle": bundle,
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		RequestNonce string `json:"request_nonce"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodySize))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&request)
	switch {
	case err == io.EOF:
		nonce, nonceErr := randomNonce()
		if nonceErr != nil {
			http.Error(w, "secure attestation nonce unavailable", http.StatusServiceUnavailable)
			return
		}
		request.RequestNonce = nonce
	case err != nil:
		http.Error(w, "invalid refresh request", http.StatusBadRequest)
		return
	default:
		if err := ensureDecoderEOF(decoder); err != nil {
			http.Error(w, "invalid refresh request", http.StatusBadRequest)
			return
		}
	}
	if !canonicalNonce(request.RequestNonce) {
		http.Error(w, "request_nonce must be 64 lowercase hexadecimal characters", http.StatusBadRequest)
		return
	}
	bundle := performAttestationWithNonce(request.RequestNonce, nil)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(bundle); err != nil {
		log.Printf("ERROR: write refresh response: %v", err)
	}
}

func handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	state, bundle := getCurrentState()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attestation_state":         state,
		"assurance_mode":            bundle.AssuranceMode,
		"evidence_verified":         bundle.EvidenceVerified,
		"tpm_available":             bundle.TPMAvailable,
		"tpm_quote_verified":        bundle.TPMQuoteVerified,
		"secure_boot":               bundle.BootMeasurements.SecureBootEnabled,
		"deployment_verified":       bundle.DeploymentVerified,
		"release_baseline_verified": bundle.ReleaseBaselineVerified,
		"release_source_commit":     bundle.ReleaseSourceCommit,
		"policy_digest":             bundle.PolicyDigest,
		"deployment_digest":         bundle.DeploymentDigest,
		"service_count":             len(bundle.ServiceDigests),
		"failure_count":             len(bundle.Failures),
		"last_attested":             bundle.Timestamp,
		"attest_count":              attestCount.Load(),
		"degrade_count":             degradeCount.Load(),
		"fail_count":                failCount.Load(),
	})
}

func newRuntimeMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Only liveness is public. Loopback is not an authentication boundary.
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/attest", requireServiceToken(handleAttest))
	mux.HandleFunc("/api/v1/verify", requireServiceToken(handleVerify))
	mux.HandleFunc("/api/security/status", requireServiceToken(handleSecurityStatus))
	mux.HandleFunc("/api/v1/refresh", requireServiceToken(handleRefresh))
	return mux
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	state, bundle := getCurrentState()
	verified := state == StateAttested &&
		bundle.AssuranceMode == "hardware" &&
		bundle.EvidenceVerified
	policySatisfied := state == StateAttested &&
		((bundle.AssuranceMode == "hardware" && verified) ||
			bundle.AssuranceMode == "evaluation")
	w.Header().Set("Content-Type", "application/json")

	status := http.StatusOK
	if !policySatisfied {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified":          verified,
		"policy_satisfied":  policySatisfied,
		"state":             state,
		"assurance_mode":    bundle.AssuranceMode,
		"evidence_verified": bundle.EvidenceVerified,
	})
}

// =========================================================================
// Periodic refresh loop
// =========================================================================

func startRefreshLoop() {
	pol := getAttestPolicy()
	interval := 5 * time.Minute
	if pol.RefreshInterval != "" {
		if d, err := time.ParseDuration(pol.RefreshInterval); err == nil {
			interval = d
		}
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			performAttestation()
		}
	}()
	log.Printf("attestation refresh loop started: interval=%s", interval)
}

// =========================================================================
// Main
// =========================================================================

func main() {
	if err := loadAttestPolicy(); err != nil {
		log.Fatalf("failed to load attestation policy: %v", err)
	}

	if err := initAuditLog(); err != nil {
		log.Fatalf("attestation audit unavailable: %v", err)
	}
	if err := loadServiceToken(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := loadIncidentRecorderToken(); err != nil {
		log.Fatalf("incident-recorder authentication unavailable: %v", err)
	}
	if err := loadHMACKey(); err != nil {
		log.Fatalf("attestation signing unavailable: %v", err)
	}
	if err := loadHardwareProfile(); err != nil {
		log.Fatalf("hardware attestation profile unavailable: %v", err)
	}

	// Initial attestation at startup
	bundle := performAttestation()
	log.Printf("initial attestation: state=%s", bundle.State)

	// Start periodic refresh
	startRefreshLoop()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8505"
	}

	log.Printf("secure-ai-runtime-attestor listening on %s", bind)
	server := &http.Server{
		Addr:              bind,
		Handler:           newRuntimeMux(),
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
	log.Println("shutting down runtime-attestor...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("ERROR: runtime-attestor shutdown failed: %v", err)
	}
	if auditFile != nil {
		if err := auditFile.Close(); err != nil {
			log.Printf("ERROR: runtime-attestor audit close failed: %v", err)
		}
	}
	log.Println("runtime-attestor stopped")
}

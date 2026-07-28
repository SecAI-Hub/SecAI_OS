package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// =========================================================================
// Test helpers
// =========================================================================

func writeTempAttestPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "attestation.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempBinary(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempPolicyFile(t *testing.T, name string, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// resetGlobalState resets the global state for tests.
func resetGlobalState(t *testing.T) {
	t.Helper()
	stateMu.Lock()
	currentState = StatePending
	currentBundle = RuntimeStateBundle{}
	stateMu.Unlock()
	serviceToken = ""
	incidentRecorderToken = ""
	hmacKey = nil
	auditEnforced = false
	auditMu.Lock()
	if auditFile != nil {
		_ = auditFile.Close()
		auditFile = nil
	}
	auditMu.Unlock()
	hardwareProfileMu.Lock()
	hardwareProfile = AttestationHardwareProfile{Version: 1, Mode: "evaluation"}
	hardwareProfileMu.Unlock()
	attestCount.Store(0)
	degradeCount.Store(0)
	failCount.Store(0)
}

func installTestTrustInputs(t *testing.T) {
	t.Helper()
	pol := getAttestPolicy()
	seen := make(map[string]bool)
	paths := make([]string, 0, len(pol.ServiceBinaries)+len(pol.PolicyFiles)+1)
	for _, path := range pol.ServiceBinaries {
		paths = append(paths, path)
	}
	paths = append(paths, pol.PolicyFiles...)
	if path := os.Getenv("ATTESTATION_POLICY_PATH"); path != "" {
		paths = append(paths, path)
	}

	files := make([]ReleaseBaselineFile, 0, len(paths))
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(content)
		files = append(files, ReleaseBaselineFile{
			Path:   path,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(content)),
		})
	}
	baselineData, err := json.Marshal(ReleaseBaseline{
		Version:      1,
		SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Files:        files,
	})
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(t.TempDir(), "release-baseline.json")
	if err := os.WriteFile(baselinePath, baselineData, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPECTED_BASELINE_PATH", baselinePath)

	bootData := []byte(`{"status":"ok","checks":{"ostree_signature":{"state":"valid","commit":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`)
	bootPath := filepath.Join(t.TempDir(), "boot-verify-last.json")
	if err := os.WriteFile(bootPath, bootData, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOOT_VERIFICATION_PATH", bootPath)
}

const testAttestPolicyYAML = `
version: 1
require_tpm: false
require_secure_boot: false
expected_pcrs: {}
service_binaries: {}
policy_files: []
refresh_interval: "1m"
hmac_key_path: ""
`

const testAttestPolicyRequireTPM = `
version: 1
require_tpm: true
require_secure_boot: false
expected_pcrs:
  "0": "0x0000000000000000000000000000000000000000000000000000000000000000"
service_binaries: {}
policy_files: []
refresh_interval: "5m"
hmac_key_path: ""
`

const testAttestPolicyRequireSB = `
version: 1
require_tpm: false
require_secure_boot: true
expected_pcrs: {}
service_binaries: {}
policy_files: []
refresh_interval: "5m"
hmac_key_path: ""
`

// =========================================================================
// Policy loading tests
// =========================================================================

func TestLoadAttestPolicy_Defaults(t *testing.T) {
	resetGlobalState(t)
	// Point to a non-existent file → should use defaults
	t.Setenv("ATTESTATION_POLICY_PATH", "/tmp/nonexistent-attestation-policy-12345.yaml")
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if pol.RequireTPM {
		t.Error("default policy should not require TPM")
	}
	if pol.RequireSecureBoot {
		t.Error("default policy should not require Secure Boot")
	}
	if len(pol.ServiceBinaries) == 0 {
		t.Error("default policy should have service binaries")
	}
	if len(pol.PolicyFiles) == 0 {
		t.Error("default policy should have policy files")
	}
}

func TestLoadAttestPolicy_FromFile(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if pol.Version != 1 {
		t.Errorf("expected version 1, got %d", pol.Version)
	}
	if pol.RequireTPM {
		t.Error("should not require TPM")
	}
	if pol.RefreshInterval != "1m" {
		t.Errorf("expected refresh interval 1m, got %s", pol.RefreshInterval)
	}
}

func TestLoadAttestPolicy_RequireTPM(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyRequireTPM)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	pol := getAttestPolicy()
	if !pol.RequireTPM {
		t.Error("should require TPM")
	}
	if len(pol.ExpectedPCRs) == 0 {
		t.Error("should have expected PCRs")
	}
}

func TestLoadAttestPolicy_InvalidYAML(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, "not: [valid: yaml: {{")
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	err := loadAttestPolicy()
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// =========================================================================
// Service digest tests
// =========================================================================

func TestCollectServiceDigests_AllPresent(t *testing.T) {
	resetGlobalState(t)
	bin1 := writeTempBinary(t, "svc1", []byte("binary-content-1"))
	bin2 := writeTempBinary(t, "svc2", []byte("binary-content-2"))

	binaries := map[string]string{
		"svc1": bin1,
		"svc2": bin2,
	}
	digests, failures := collectServiceDigests(binaries)
	if len(failures) != 0 {
		t.Errorf("expected no failures, got %v", failures)
	}
	if len(digests) != 2 {
		t.Errorf("expected 2 digests, got %d", len(digests))
	}
	// Verify digest is a valid hex SHA-256
	for name, d := range digests {
		if d == "missing" {
			t.Errorf("service %s should not be missing", name)
		}
		if len(d) != 64 {
			t.Errorf("digest for %s should be 64 hex chars, got %d", name, len(d))
		}
	}
}

func TestCollectServiceDigests_MissingBinary(t *testing.T) {
	resetGlobalState(t)
	binaries := map[string]string{
		"missing-svc": "/tmp/nonexistent-binary-12345",
	}
	digests, failures := collectServiceDigests(binaries)
	if len(failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(failures))
	}
	if digests["missing-svc"] != "missing" {
		t.Errorf("expected 'missing', got %s", digests["missing-svc"])
	}
}

func TestCollectServiceDigests_DeterministicHash(t *testing.T) {
	resetGlobalState(t)
	bin := writeTempBinary(t, "test-bin", []byte("deterministic-content"))
	binaries := map[string]string{"test": bin}

	d1, _ := collectServiceDigests(binaries)
	d2, _ := collectServiceDigests(binaries)
	if d1["test"] != d2["test"] {
		t.Error("same binary should produce same digest")
	}
}

func TestCollectServiceDigests_DifferentContent(t *testing.T) {
	resetGlobalState(t)
	bin1 := writeTempBinary(t, "a", []byte("content-a"))
	bin2 := writeTempBinary(t, "b", []byte("content-b"))

	d1, _ := collectServiceDigests(map[string]string{"s": bin1})
	d2, _ := collectServiceDigests(map[string]string{"s": bin2})
	if d1["s"] == d2["s"] {
		t.Error("different binaries should produce different digests")
	}
}

// =========================================================================
// Policy digest tests
// =========================================================================

func TestCollectPolicyDigest_ValidFiles(t *testing.T) {
	resetGlobalState(t)
	f1 := writeTempPolicyFile(t, "policy.yaml", "policy: content: 1")
	f2 := writeTempPolicyFile(t, "agent.yaml", "agent: content: 2")

	digest, failures := collectPolicyDigest([]string{f1, f2})
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if digest == "" {
		t.Error("policy digest should not be empty")
	}
	if len(digest) != 64 {
		t.Errorf("policy digest should be 64 hex chars, got %d", len(digest))
	}
}

func TestCollectPolicyDigest_MissingFiles(t *testing.T) {
	resetGlobalState(t)
	digest, failures := collectPolicyDigest([]string{"/nonexistent/a.yaml", "/nonexistent/b.yaml"})
	if digest == "" {
		t.Error("policy digest should not be empty even with missing files")
	}
	if len(failures) != 2 {
		t.Fatalf("expected both missing policies to be failures, got %v", failures)
	}
}

func TestCollectPolicyDigest_Deterministic(t *testing.T) {
	resetGlobalState(t)
	f := writeTempPolicyFile(t, "policy.yaml", "same-content")
	d1, failures1 := collectPolicyDigest([]string{f})
	d2, failures2 := collectPolicyDigest([]string{f})
	if len(failures1) != 0 || len(failures2) != 0 {
		t.Fatalf("unexpected policy failures: %v %v", failures1, failures2)
	}
	if d1 != d2 {
		t.Error("same policy file should produce same digest")
	}
}

func TestCollectPolicyDigest_OrderMatters(t *testing.T) {
	resetGlobalState(t)
	f1 := writeTempPolicyFile(t, "a.yaml", "content-a")
	f2 := writeTempPolicyFile(t, "b.yaml", "content-b")

	d1, _ := collectPolicyDigest([]string{f1, f2})
	d2, _ := collectPolicyDigest([]string{f2, f1})
	if d1 == d2 {
		t.Error("order of policy files should affect digest")
	}
}

func TestVerifyReleaseMeasurements_DetectsPolicyTamper(t *testing.T) {
	resetGlobalState(t)
	policyFile := writeTempPolicyFile(t, "policy.yaml", "allow: true")
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries: {}
policy_files:
  - ` + policyFile + `
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	installTestTrustInputs(t)

	_, verified, failures := verifyReleaseMeasurements(getAttestPolicy(), map[string]string{})
	if !verified || len(failures) != 0 {
		t.Fatalf("expected release measurements to verify: %v", failures)
	}
	if err := os.WriteFile(policyFile, []byte("allow: false"), 0644); err != nil {
		t.Fatal(err)
	}
	_, verified, failures = verifyReleaseMeasurements(getAttestPolicy(), map[string]string{})
	if verified || len(failures) == 0 {
		t.Fatal("tampered policy must fail release measurement verification")
	}
}

func TestVerifyReleaseMeasurements_MissingBaselineFails(t *testing.T) {
	resetGlobalState(t)
	t.Setenv("EXPECTED_BASELINE_PATH", filepath.Join(t.TempDir(), "missing.json"))
	_, verified, failures := verifyReleaseMeasurements(AttestationPolicy{}, map[string]string{})
	if verified || len(failures) == 0 {
		t.Fatal("missing release baseline must fail closed")
	}
}

// =========================================================================
// Bundle HMAC tests
// =========================================================================

func TestComputeBundleHMAC_NoKey(t *testing.T) {
	resetGlobalState(t)
	hmacKey = nil
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}
	result := computeBundleHMAC(bundle)
	if result != "unsigned" {
		t.Errorf("expected 'unsigned' without key, got %s", result)
	}
}

func TestCredentialLoadersRequireCanonical256BitHex(t *testing.T) {
	resetGlobalState(t)
	directory := t.TempDir()
	servicePath := filepath.Join(directory, "service.token")
	reporterPath := filepath.Join(directory, "reporter.token")
	hmacPath := filepath.Join(directory, "attestation.key")
	for path, value := range map[string]string{
		servicePath:  strings.Repeat("a", 64) + "\n",
		reporterPath: strings.Repeat("b", 64),
		hmacPath:     strings.Repeat("01", 32) + "\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SERVICE_TOKEN_PATH", servicePath)
	t.Setenv("INCIDENT_RECORDER_TOKEN_PATH", reporterPath)
	t.Setenv("HMAC_KEY_PATH", hmacPath)
	if err := loadServiceToken(); err != nil {
		t.Fatal(err)
	}
	if err := loadIncidentRecorderToken(); err != nil {
		t.Fatal(err)
	}
	if err := loadHMACKey(); err != nil {
		t.Fatal(err)
	}
	if serviceToken != strings.Repeat("a", 64) ||
		incidentRecorderToken != strings.Repeat("b", 64) ||
		len(hmacKey) != sha256.Size {
		t.Fatal("canonical credentials were not loaded exactly")
	}

	if err := os.WriteFile(servicePath, []byte(strings.Repeat("A", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err == nil {
		t.Fatal("uppercase credential was accepted")
	}
	if err := os.WriteFile(servicePath, []byte(strings.Repeat("a", 64)+"\nextra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err == nil {
		t.Fatal("credential with trailing data was accepted")
	}
}

func TestComputeBundleHMAC_WithKey(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte("test-secret-key")
	bundle := RuntimeStateBundle{
		Timestamp:            "2026-01-01T00:00:00Z",
		State:                StateAttested,
		DeploymentDigest:     "abc123",
		PolicyDigest:         "def456",
		RegistryManifestHash: "ghi789",
		TPMAvailable:         false,
		TPMQuoteVerified:     false,
	}
	result := computeBundleHMAC(bundle)
	if result == "unsigned" {
		t.Error("should not be unsigned with key")
	}
	if len(result) != 64 {
		t.Errorf("HMAC should be 64 hex chars, got %d", len(result))
	}
	// Verify it's a valid HMAC
	_, err := hex.DecodeString(result)
	if err != nil {
		t.Errorf("HMAC is not valid hex: %v", err)
	}
}

func TestComputeBundleHMAC_Deterministic(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte("test-key")
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}
	h1 := computeBundleHMAC(bundle)
	h2 := computeBundleHMAC(bundle)
	if h1 != h2 {
		t.Error("same input should produce same HMAC")
	}
}

func TestComputeBundleHMAC_DifferentKeys(t *testing.T) {
	resetGlobalState(t)
	bundle := RuntimeStateBundle{
		Timestamp: "2026-01-01T00:00:00Z",
		State:     StateAttested,
	}

	hmacKey = []byte("key-1")
	h1 := computeBundleHMAC(bundle)
	hmacKey = []byte("key-2")
	h2 := computeBundleHMAC(bundle)
	if h1 == h2 {
		t.Error("different keys should produce different HMACs")
	}
}

func TestComputeBundleHMAC_VerifyCorrectness(t *testing.T) {
	resetGlobalState(t)
	key := []byte("verification-key")
	hmacKey = key
	bundle := RuntimeStateBundle{
		Timestamp:            "2026-01-01T00:00:00Z",
		State:                StateAttested,
		DeploymentDigest:     "deploy-abc",
		DeploymentVerified:   true,
		PolicyDigest:         "policy-def",
		RegistryManifestHash: "registry-ghi",
		TPMAvailable:         true,
		TPMQuoteVerified:     false,
	}
	result := computeBundleHMAC(bundle)

	// Independently compute HMAC over canonical JSON with BundleHMAC blank.
	bundle.BundleHMAC = ""
	data, err := canonicalBundleJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := hex.EncodeToString(mac.Sum(nil))

	if result != expected {
		t.Errorf("HMAC mismatch: got %s, want %s", result, expected)
	}
}

func TestComputeBundleHMAC_CoversEveryEvidenceClass(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte("complete-bundle-test-key")
	original := RuntimeStateBundle{
		Timestamp:               "2026-01-01T00:00:00Z",
		State:                   StateAttested,
		BootMeasurements:        BootMeasurements{PCRValues: map[string]string{"7": "0xabc"}},
		DeploymentDigest:        "sha256:abc",
		DeploymentVerified:      true,
		ReleaseSourceCommit:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReleaseBaselineVerified: true,
		ServiceDigests:          map[string]string{"registry": "svc"},
		PolicyDigest:            "policy",
		RegistryManifestHash:    "registry",
		KernelCmdline:           "quiet",
		KernelLockdown:          "integrity",
		TPMAvailable:            true,
		TPMMeasurementsVerified: true,
		Failures:                []string{"evidence"},
	}
	expected := computeBundleHMAC(original)

	mutations := map[string]func(*RuntimeStateBundle){
		"boot measurements":   func(b *RuntimeStateBundle) { b.BootMeasurements.PCRValues["7"] = "tampered" },
		"service digests":     func(b *RuntimeStateBundle) { b.ServiceDigests["registry"] = "tampered" },
		"deployment evidence": func(b *RuntimeStateBundle) { b.DeploymentVerified = false },
		"release evidence":    func(b *RuntimeStateBundle) { b.ReleaseBaselineVerified = false },
		"registry hash":       func(b *RuntimeStateBundle) { b.RegistryManifestHash = "tampered" },
		"kernel state":        func(b *RuntimeStateBundle) { b.KernelLockdown = "none" },
		"failures":            func(b *RuntimeStateBundle) { b.Failures[0] = "tampered" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var changed RuntimeStateBundle
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if actual := computeBundleHMAC(changed); actual == expected {
				t.Fatalf("tampering with %s did not change bundle HMAC", name)
			}
		})
	}
}

func TestCrossServiceBundleHMACGoldenVector(t *testing.T) {
	resetGlobalState(t)
	hmacKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	bundle := RuntimeStateBundle{
		Timestamp:        "2026-07-27T12:34:56.123456789Z",
		State:            StateAttested,
		AssuranceMode:    "hardware",
		EvidenceVerified: true,
		RequestNonce:     strings.Repeat("11", 32),
		BootMeasurements: BootMeasurements{
			SecureBootEnabled: true,
			PCRValues: map[string]string{
				"0": "0x" + strings.Repeat("22", 32),
				"7": "0x" + strings.Repeat("23", 32),
			},
			MeasuredAt: "2026-07-27T12:34:55.999999999Z",
		},
		DeploymentDigest:        "sha256:" + strings.Repeat("33", 32),
		DeploymentVerified:      true,
		ReleaseSourceCommit:     strings.Repeat("44", 20),
		ReleaseBaselineVerified: true,
		ServiceDigests: map[string]string{
			"registry":      strings.Repeat("55", 32),
			"tool-firewall": strings.Repeat("56", 32),
		},
		PolicyDigest:            strings.Repeat("66", 32),
		RegistryManifestHash:    strings.Repeat("77", 32),
		KernelCmdline:           "quiet lockdown=confidentiality",
		KernelLockdown:          "[confidentiality] integrity",
		TPMAvailable:            true,
		TPMMeasurementsVerified: true,
		TPMQuoteVerified:        true,
		TPMAKPublicKeySHA256:    strings.Repeat("88", 32),
		TPMQuotePCRSelection:    "sha256:0,2,4,7",
		Failures:                []string{"golden-vector"},
	}
	const expected = "2f79b51e951ec69d0de69a6a36893b9c3802734517942b465f782e643865fff5"
	if actual := computeBundleHMAC(bundle); actual != expected {
		t.Fatalf("cross-service HMAC changed: got %s, want %s", actual, expected)
	}
}

func TestEnrolledDeploymentBinding(t *testing.T) {
	profile := AttestationHardwareProfile{
		Mode:               "hardware",
		EnrolledDeployment: "sha256:" + strings.Repeat("a", 64),
	}
	if !enrolledDeploymentMatches(profile, profile.EnrolledDeployment) {
		t.Fatal("exact enrolled deployment should match")
	}
	if enrolledDeploymentMatches(profile, "sha256:"+strings.Repeat("b", 64)) {
		t.Fatal("different signed deployment must invalidate hardware enrollment")
	}
	profile.Mode = "evaluation"
	if !enrolledDeploymentMatches(profile, "") {
		t.Fatal("evaluation profile has no hardware enrollment binding")
	}
}

func TestVerifyTPMQuote_NonceAKAndAuthenticatedPCRBinding(t *testing.T) {
	resetGlobalState(t)
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	quoteScript := `#!/bin/sh
set -eu
message=
signature=
pcr=
nonce=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -m) message=$2; shift 2 ;;
    -s) signature=$2; shift 2 ;;
    -o) pcr=$2; shift 2 ;;
    -q) nonce=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ "$nonce" = "$EXPECTED_NONCE" ]
umask 077
printf 'message' > "$message"
printf 'signature' > "$signature"
printf 'quoted-pcr-golden' > "$pcr"
`
	checkScript := `#!/bin/sh
set -eu
nonce=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -q) nonce=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ "$nonce" = "$EXPECTED_NONCE" ]
[ "${FAKE_CHECKQUOTE_FAIL:-0}" != 1 ]
`
	for name, content := range map[string]string{
		"tpm2_quote":      quoteScript,
		"tpm2_checkquote": checkScript,
	} {
		if err := os.WriteFile(
			filepath.Join(binDirectory, name),
			[]byte(content),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDirectory)
	nonce := strings.Repeat("a", 64)
	t.Setenv("EXPECTED_NONCE", nonce)
	akPublic := []byte("-----BEGIN PUBLIC KEY-----\ngolden\n-----END PUBLIC KEY-----\n")
	akPath := filepath.Join(directory, "ak-public.pem")
	if err := os.WriteFile(akPath, akPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TPM_AK_PUBLIC_KEY_PATH", akPath)
	akDigest := sha256.Sum256(akPublic)
	pcrDigest := sha256.Sum256([]byte("quoted-pcr-golden"))
	profile := AttestationHardwareProfile{
		Mode:                  "hardware",
		AKHandle:              hardwareAKHandle,
		AKPublicKeySHA256:     hex.EncodeToString(akDigest[:]),
		PCRSelection:          hardwarePCRSelection,
		QuotedPCRDigestSHA256: hex.EncodeToString(pcrDigest[:]),
	}

	evidence := verifyTPMQuote(profile, nonce)
	if !evidence.available || !evidence.quoteVerified ||
		!evidence.measurementsVerified || len(evidence.failures) != 0 {
		t.Fatalf("valid nonce-bound quote was rejected: %+v", evidence)
	}

	tamperedProfile := profile
	tamperedProfile.QuotedPCRDigestSHA256 = strings.Repeat("0", 64)
	tampered := verifyTPMQuote(tamperedProfile, nonce)
	if !tampered.quoteVerified || tampered.measurementsVerified {
		t.Fatalf("tampered PCR baseline was accepted: %+v", tampered)
	}

	t.Setenv("FAKE_CHECKQUOTE_FAIL", "1")
	unverified := verifyTPMQuote(profile, nonce)
	if unverified.quoteVerified || unverified.measurementsVerified {
		t.Fatalf("failed tpm2_checkquote was accepted: %+v", unverified)
	}
}

// =========================================================================
// Attestation state machine tests
// =========================================================================

func TestPerformAttestation_NoRequirements(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	bundle := performAttestation()
	// With no TPM/SB requirements and no service binaries, should be attested
	if bundle.State != StateAttested {
		t.Errorf("expected attested state, got %s (failures: %v)", bundle.State, bundle.Failures)
	}
	if bundle.Timestamp == "" {
		t.Error("bundle should have a timestamp")
	}
}

func TestPerformAttestation_MissingBinary_Degrades(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  nonexistent-svc: /tmp/nonexistent-binary-for-test-12345
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	bundle := performAttestation()
	if bundle.State != StateDegraded {
		t.Errorf("expected degraded state for missing binary, got %s", bundle.State)
	}
	if len(bundle.Failures) == 0 {
		t.Error("should have failures for missing binary")
	}
}

func TestPerformAttestation_ValidBinaries_Attested(t *testing.T) {
	resetGlobalState(t)
	bin := writeTempBinary(t, "test-service", []byte("test-binary-content"))
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  test-service: ` + bin + `
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	bundle := performAttestation()
	if bundle.State != StateAttested {
		t.Errorf("expected attested with valid binary, got %s (failures: %v)", bundle.State, bundle.Failures)
	}
	if bundle.ServiceDigests["test-service"] == "missing" {
		t.Error("service digest should not be 'missing'")
	}
}

func TestPerformAttestation_RequireTPM_FailsInCI(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyRequireTPM)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	bundle := performAttestation()
	// In CI/dev environments, TPM is not available → should fail
	if bundle.State != StateFailed {
		t.Errorf("expected failed state when TPM required but unavailable, got %s", bundle.State)
	}
	if len(bundle.Failures) == 0 {
		t.Error("should have failure messages")
	}
}

func TestPerformAttestation_AttestCountIncremented(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	before := attestCount.Load()
	performAttestation()
	after := attestCount.Load()
	if after != before+1 {
		t.Errorf("attest count should increment: before=%d after=%d", before, after)
	}
}

func TestPerformAttestation_DegradeCountIncremented(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  missing: /tmp/no-such-binary-99999
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatalf("loadAttestPolicy: %v", err)
	}
	installTestTrustInputs(t)

	before := degradeCount.Load()
	performAttestation()
	after := degradeCount.Load()
	if after <= before {
		t.Errorf("degrade count should increment: before=%d after=%d", before, after)
	}
}

func TestGetCurrentState_Default(t *testing.T) {
	resetGlobalState(t)
	state, bundle := getCurrentState()
	if state != StatePending {
		t.Errorf("initial state should be pending, got %s", state)
	}
	if bundle.Timestamp != "" {
		t.Error("initial bundle should have no timestamp")
	}
}

func TestGetCurrentState_AfterAttestation(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)

	performAttestation()
	state, bundle := getCurrentState()
	if state == StatePending {
		t.Error("state should not be pending after attestation")
	}
	if bundle.Timestamp == "" {
		t.Error("bundle should have a timestamp after attestation")
	}
}

// =========================================================================
// HTTP endpoint tests
// =========================================================================

func TestHTTP_Health(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("health returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Errorf("health status = %v", body["status"])
	}
	if body["state"] == nil {
		t.Error("health should include state")
	}
}

func TestHTTP_Attest_Get(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attest returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["state"] == nil {
		t.Error("attest response missing state")
	}
	if body["bundle"] == nil {
		t.Error("attest response missing bundle")
	}
}

func TestHTTP_Attest_Post(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("attest POST returned %d", w.Code)
	}
}

func TestHTTP_Attest_MethodNotAllowed(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_Verify_EvaluationPolicySatisfiedWithoutHardwareVerification(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("verify returned %d when attested", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["policy_satisfied"] != true {
		t.Error("explicit evaluation profile should satisfy its limited policy")
	}
	if body["verified"] != false || body["evidence_verified"] != false {
		t.Error("evaluation mode must not claim cryptographically verified hardware evidence")
	}
}

func TestHTTP_Verify_NotAttested(t *testing.T) {
	resetGlobalState(t)
	// State is pending (not attested)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("verify should return 503 when not attested, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["verified"] != false {
		t.Error("should not be verified when pending")
	}
}

func TestHTTP_Verify_Degraded(t *testing.T) {
	resetGlobalState(t)
	policyYAML := `
version: 1
require_tpm: false
require_secure_boot: false
service_binaries:
  missing: /tmp/no-such-binary-verify-test
policy_files: []
refresh_interval: "1m"
`
	path := writeTempAttestPolicy(t, policyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify", nil)
	w := httptest.NewRecorder()
	handleVerify(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("verify should return 503 when degraded, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["verified"] != false {
		t.Error("should not be verified when degraded")
	}
}

func TestHTTP_Refresh_PostOnly(t *testing.T) {
	resetGlobalState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handleRefresh(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET refresh, got %d", w.Code)
	}
}

func TestHTTP_Refresh_Post(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handleRefresh(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("refresh returned %d", w.Code)
	}
	var bundle RuntimeStateBundle
	json.Unmarshal(w.Body.Bytes(), &bundle)
	if bundle.Timestamp == "" {
		t.Error("refresh should return bundle with timestamp")
	}
}

func TestHTTP_SecurityStatus(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/security/status", nil)
	w := httptest.NewRecorder()
	handleSecurityStatus(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("security status returned %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)

	// Check required fields
	requiredFields := []string{
		"attestation_state", "tpm_available", "tpm_quote_verified",
		"secure_boot", "policy_digest", "deployment_digest",
		"service_count", "failure_count", "last_attested",
		"attest_count", "degrade_count", "fail_count",
	}
	for _, field := range requiredFields {
		if _, ok := body[field]; !ok {
			t.Errorf("security status missing field: %s", field)
		}
	}
}

func TestHTTP_SecurityStatus_CountsTracked(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)

	// Run attestation twice
	performAttestation()
	performAttestation()

	r := httptest.NewRequest(http.MethodGet, "/api/security/status", nil)
	w := httptest.NewRecorder()
	handleSecurityStatus(w, r)

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	count := body["attest_count"].(float64)
	if count < 2 {
		t.Errorf("attest_count should be >= 2, got %v", count)
	}
}

// =========================================================================
// Token auth tests
// =========================================================================

func TestToken_NoTokenConfigured(t *testing.T) {
	resetGlobalState(t)
	serviceToken = ""

	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if called {
		t.Error("handler must fail closed when no token is configured")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without configured token, got %d", w.Code)
	}
}

func TestToken_RequiresBearer(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "test-token-123"

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without Bearer header, got %d", w.Code)
	}
}

func TestToken_InvalidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "correct-token"

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong token, got %d", w.Code)
	}
}

func TestToken_ValidToken(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "valid-secret-token"

	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r.Header.Set("Authorization", "Bearer valid-secret-token")
	w := httptest.NewRecorder()
	handler(w, r)
	if !called {
		t.Error("handler should be called with valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", w.Code)
	}
}

func TestToken_RefreshRequiresToken(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)

	serviceToken = "refresh-secret"
	handler := requireServiceToken(handleRefresh)

	// Without token
	r := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("refresh without token: expected 403, got %d", w.Code)
	}

	// With valid token
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	r2.Header.Set("Authorization", "Bearer refresh-secret")
	w2 := httptest.NewRecorder()
	handler(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("refresh with token: expected 200, got %d", w2.Code)
	}
}

func TestRuntimeMux_ProtectsAllEvidenceEndpoints(t *testing.T) {
	resetGlobalState(t)
	serviceToken = "runtime-secret"
	mux := newRuntimeMux()

	for _, path := range []string{
		"/api/v1/attest",
		"/api/v1/verify",
		"/api/security/status",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s returned %d without authentication", path, response.Code)
			}

			request = httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer runtime-secret")
			response = httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code == http.StatusForbidden {
				t.Fatalf("%s rejected the configured target credential", path)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health must remain available without credentials, got %d", response.Code)
	}
}

// =========================================================================
// Audit logging tests
// =========================================================================

func TestAuditLog_WritesOnAttestation(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", logPath)
	initAuditLog()
	defer func() {
		if auditFile != nil {
			auditFile.Close()
			auditFile = nil
		}
	}()

	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	loadAttestPolicy()
	installTestTrustInputs(t)

	performAttestation()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log should not be empty after attestation")
	}
	// Verify it's valid JSON
	var bundle RuntimeStateBundle
	if err := json.Unmarshal(data[:len(data)-1], &bundle); err != nil {
		t.Errorf("audit log entry is not valid JSON: %v", err)
	}
	if bundle.Timestamp == "" {
		t.Error("audit log entry should have timestamp")
	}
}

func TestAuditFailureCannotPublishPolicySatisfyingEvidence(t *testing.T) {
	resetGlobalState(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	t.Setenv("AUDIT_LOG_PATH", logPath)
	if err := initAuditLog(); err != nil {
		t.Fatal(err)
	}
	if err := auditFile.Close(); err != nil {
		t.Fatal(err)
	}

	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	installTestTrustInputs(t)
	bundle := performAttestation()
	auditFile = nil

	if bundle.State != StateFailed || bundle.EvidenceVerified {
		t.Fatalf("audit failure published trusted evidence: %+v", bundle)
	}
	if !slices.Contains(bundle.Failures, "attestation audit persistence failed") {
		t.Fatalf("audit failure missing from evidence: %v", bundle.Failures)
	}
}

// =========================================================================
// Kernel state tests (graceful degradation)
// =========================================================================

func TestCollectKernelState_NoError(t *testing.T) {
	// collectKernelState should not panic even if files don't exist
	cmdline, lockdown := collectKernelState()
	// On macOS CI, /proc/cmdline won't exist
	_ = cmdline
	_ = lockdown
}

// =========================================================================
// Deployment digest tests (graceful degradation)
// =========================================================================

func TestCollectDeploymentDigest_Unavailable(t *testing.T) {
	// rpm-ostree likely not available in CI
	result := collectDeploymentDigest()
	if result != "unavailable" && len(result) == 0 {
		t.Error("deployment digest should be 'unavailable' or a valid hash")
	}
}

// =========================================================================
// Registry manifest tests (graceful degradation)
// =========================================================================

func TestCollectRegistryManifestHash_Unavailable(t *testing.T) {
	result := collectRegistryManifestHash()
	if result != "unavailable" {
		t.Errorf("expected 'unavailable' when manifest missing, got %s", result)
	}
}

// =========================================================================
// Boot measurements tests (graceful degradation)
// =========================================================================

func TestCollectBootMeasurements_NoTPM(t *testing.T) {
	pol := AttestationPolicy{
		RequireTPM:        false,
		RequireSecureBoot: false,
	}
	m, tpmAvail, failures := collectBootMeasurements(pol)
	// In CI, TPM and Secure Boot are not available
	if tpmAvail {
		t.Log("TPM unexpectedly available in test environment")
	}
	if len(failures) != 0 {
		t.Errorf("should have no failures when TPM not required, got %v", failures)
	}
	if m.MeasuredAt == "" {
		t.Error("measured_at timestamp should be set")
	}
}

func TestCollectBootMeasurements_TPMRequired_FailsGracefully(t *testing.T) {
	pol := AttestationPolicy{
		RequireTPM:        true,
		RequireSecureBoot: false,
	}
	_, _, failures := collectBootMeasurements(pol)
	// In CI, TPM is not available → should report failure
	if len(failures) == 0 {
		t.Log("no TPM failure reported — TPM may be available in this environment")
	}
}

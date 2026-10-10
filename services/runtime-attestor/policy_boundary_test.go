package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAttestationPolicyBoundaryRejectsInvalidInput(t *testing.T) {
	for name, data := range map[string]string{
		"unknown field":   testAttestPolicyYAML + "unexpected_trust: true\n",
		"second document": testAttestPolicyYAML + "---\nversion: 1\n",
		"wrong version":   strings.Replace(testAttestPolicyYAML, "version: 1", "version: 99", 1),
		"zero interval":   strings.Replace(testAttestPolicyYAML, `"1m"`, `"0s"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			resetGlobalState(t)
			path := writeTempAttestPolicy(t, data)
			t.Setenv("ATTESTATION_POLICY_PATH", path)
			if err := loadAttestPolicy(); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}

func TestAttestationPolicyBoundaryRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "symlink", "fifo", "oversize", "writable"} {
		t.Run(kind, func(t *testing.T) {
			resetGlobalState(t)
			path := filepath.Join(t.TempDir(), "policy.yaml")
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink(writeTempAttestPolicy(t, testAttestPolicyYAML), path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "oversize":
				err = os.WriteFile(path, []byte(strings.Repeat("x", maxAttestationPolicyBytes+1)), 0600)
			case "writable":
				err = os.WriteFile(path, []byte(testAttestPolicyYAML), 0600)
				if err == nil {
					err = os.Chmod(path, 0666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("ATTESTATION_POLICY_PATH", path)
			if err := loadAttestPolicy(); err == nil {
				t.Fatal("unsafe policy file accepted")
			}
		})
	}
}

func TestAttestationPolicyLoadFailurePreservesLastSnapshot(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	before := getAttestPolicy()
	if err := os.WriteFile(path, []byte("version: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadAttestPolicy(); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	after := getAttestPolicy()
	if after.sourceSHA256 != before.sourceSHA256 || after.RefreshInterval != before.RefreshInterval {
		t.Fatal("invalid load replaced the valid policy snapshot")
	}
	installTestTrustInputs(t)
	if _, verified, _ := verifyReleaseMeasurements(after, nil); verified {
		t.Fatal("preserved snapshot ignored changed policy file")
	}
}

func TestAttestationPolicyCannotExcludeItselfFromRelease(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	unrelated := writeTempPolicyFile(t, "unrelated", "unrelated release file")
	content, _ := os.ReadFile(unrelated)
	digest := sha256.Sum256(content)
	data, err := json.Marshal(ReleaseBaseline{Version: 1, SourceCommit: strings.Repeat("a", 40),
		Files: []ReleaseBaselineFile{{Path: unrelated, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}}})
	if err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(baseline, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPECTED_BASELINE_PATH", baseline)
	if _, verified, failures := verifyReleaseMeasurements(getAttestPolicy(), nil); verified || len(failures) == 0 {
		t.Fatal("a policy absent from the release baseline verified")
	}
}

func TestAttestationPolicyLoadedSnapshotMustMatchRelease(t *testing.T) {
	resetGlobalState(t)
	path := writeTempAttestPolicy(t, testAttestPolicyYAML)
	t.Setenv("ATTESTATION_POLICY_PATH", path)
	if err := loadAttestPolicy(); err != nil {
		t.Fatal(err)
	}
	// The file now contains a different policy. Pinning those new bytes must
	// not authenticate the old policy still loaded by this process.
	changed := strings.Replace(testAttestPolicyYAML, `"1m"`, `"2m"`, 1)
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	installTestTrustInputs(t)
	if _, verified, failures := verifyReleaseMeasurements(getAttestPolicy(), nil); verified || len(failures) == 0 {
		t.Fatal("new on-disk bytes authenticated an older loaded policy")
	}
}

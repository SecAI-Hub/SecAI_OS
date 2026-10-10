package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Match the appliance's protected credential/file pattern: bounded regular
// no-symlink input, trusted owner, safe permissions, and identity checks around
// open/read. Hash the exact bytes decoded by the daemon, never a later reread.
func readGPUEvidenceFile(path string, limit int64, key bool) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, fmt.Errorf("invalid evidence input path")
	}
	before, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("evidence input unavailable")
	}
	safe := func(info os.FileInfo) bool {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 0 || info.Size() > limit {
			return false
		}
		return !key || (stat.Nlink == 1 && (info.Mode().Perm() == 0400 || info.Mode().Perm() == 0600))
	}
	if !safe(before) {
		return nil, fmt.Errorf("unsafe evidence input")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("evidence input cannot be opened")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !safe(opened) || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("evidence input changed on open")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("evidence input exceeds bounds or is incomplete")
	}
	after, err := f.Stat()
	pathAfter, pathErr := os.Lstat(abs)
	if err != nil || pathErr != nil || !safe(after) || !safe(pathAfter) || !os.SameFile(before, after) || !os.SameFile(after, pathAfter) || after.Size() != int64(len(data)) || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("evidence input changed during read")
	}
	return data, nil
}

func decodeGPUEvidenceYAML(data []byte, into any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("invalid evidence YAML schema")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple evidence YAML documents")
	}
	return nil
}

func gpuInputDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func loadGPUProducerInputs(path string) (*IntegrityProfile, *Baseline, string, string, error) {
	data, err := readGPUEvidenceFile(path, 64<<10, false)
	if err != nil {
		return nil, nil, "", "", err
	}
	var profile IntegrityProfile
	if err := decodeGPUEvidenceYAML(data, &profile); err != nil {
		return nil, nil, "", "", err
	}
	profileHash := gpuInputDigest(data)
	baselineData, err := readGPUEvidenceFile(profile.BaselineFile, 1<<20, false)
	if err != nil {
		return &profile, nil, profileHash, "", nil
	}
	var baseline Baseline
	if err := decodeGPUEvidenceYAML(baselineData, &baseline); err != nil {
		return &profile, nil, profileHash, "", nil
	}
	return &profile, &baseline, profileHash, gpuInputDigest(baselineData), nil
}

func loadGPUAttestationKey(path string) ([]byte, error) {
	data, err := readGPUEvidenceFile(path, 65, true)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if !gpuHex64.MatchString(value) || (len(data) != 64 && len(data) != 65) {
		return nil, fmt.Errorf("GPU attestation key must be canonical 256-bit lowercase hex")
	}
	return hex.DecodeString(value)
}

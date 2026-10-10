package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxAttestationPolicyBytes = 1024 * 1024

// Policy is executable trust configuration. Read a bounded, stable snapshot
// through a nonblocking descriptor; neither a link nor a special file may
// redirect the read or turn a missing policy into weaker defaults.
func readAttestationPolicyFile(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("policy path must be canonical and absolute")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	metadata, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 ||
		(metadata.Uid != 0 && metadata.Uid != uint32(os.Geteuid())) ||
		before.Size() <= 0 || before.Size() > maxAttestationPolicyBytes {
		return nil, fmt.Errorf("policy type, ownership, permissions or size is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAttestationPolicyBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() ||
		after.Size() != before.Size() || after.Size() != int64(len(data)) ||
		!after.ModTime().Equal(before.ModTime()) || len(data) > maxAttestationPolicyBytes {
		return nil, fmt.Errorf("policy changed during read")
	}
	afterMetadata, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterMetadata.Uid != metadata.Uid || afterMetadata.Gid != metadata.Gid ||
		afterMetadata.Ctim != metadata.Ctim {
		return nil, fmt.Errorf("policy ownership or metadata changed during read")
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, current) {
		return nil, fmt.Errorf("policy path changed during read")
	}
	return data, nil
}

func validateAttestationPolicy(pol AttestationPolicy) error {
	if pol.Version != 1 {
		return fmt.Errorf("unsupported attestation policy version")
	}
	if err := validateGPUTrustPolicy(pol.GPU); err != nil {
		return err
	}
	if pol.RefreshInterval != "" {
		interval, err := time.ParseDuration(pol.RefreshInterval)
		if err != nil || interval < time.Second || interval > 24*time.Hour {
			return fmt.Errorf("attestation refresh interval must be between 1s and 24h")
		}
	}
	if len(pol.ServiceBinaries) > 128 || len(pol.PolicyFiles) > 256 || len(pol.ExpectedPCRs) > 24 {
		return fmt.Errorf("attestation policy measurement count exceeds limits")
	}
	validPath := func(path string) bool {
		return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path &&
			!strings.ContainsAny(path, "\x00\r\n")
	}
	for name, path := range pol.ServiceBinaries {
		if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") || !validPath(path) {
			return fmt.Errorf("invalid service measurement")
		}
	}
	seen := make(map[string]bool, len(pol.PolicyFiles))
	for _, path := range pol.PolicyFiles {
		if !validPath(path) || seen[path] {
			return fmt.Errorf("invalid or duplicate policy measurement")
		}
		seen[path] = true
	}
	for name, digest := range pol.ExpectedPCRs {
		number, err := strconv.Atoi(name)
		if err != nil || number < 0 || number > 23 || strconv.Itoa(number) != name ||
			!canonicalSHA256(strings.TrimPrefix(digest, "0x")) {
			return fmt.Errorf("invalid SHA256 PCR measurement")
		}
	}
	if pol.HMACKeyPath != "" && !validPath(pol.HMACKeyPath) {
		return fmt.Errorf("attestation key path must be canonical and absolute")
	}
	return nil
}

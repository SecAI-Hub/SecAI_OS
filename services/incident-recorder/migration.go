package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Legacy hashes did not authenticate evidence or lifecycle state. Migration is
// deliberately offline and never overwrites the original: an operator must
// review the legacy evidence and retain a backup before explicitly accepting it.
func runHistoryMigration(args []string) error {
	fs := flag.NewFlagSet("migrate-history", flag.ContinueOnError)
	input := fs.String("in", "", "reviewed legacy JSONL history")
	output := fs.String("out", "", "new authenticated history; must not exist")
	keyPath := fs.String("key", "", "existing forensic HMAC credential file")
	reviewed := fs.Bool("acknowledge-reviewed-history", false, "confirm independent review of unauthenticated legacy fields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !*reviewed || *input == "" || *output == "" || *keyPath == "" {
		return fmt.Errorf("migration requires -in, -out, -key and -acknowledge-reviewed-history; stop the service and preserve a backup first")
	}
	key, _, err := readCanonicalCredentialFile(*keyPath, "incident history signing key")
	if err != nil {
		return err
	}
	return migrateReviewedHistory(*input, *output, []byte(key))
}

func migrateReviewedHistory(input, output string, key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("incident signing key is unavailable")
	}
	info, err := os.Lstat(input)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return fmt.Errorf("legacy history must be a bounded regular file")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 256<<10)
	var converted bytes.Buffer
	seen := map[string]bool{}
	for scanner.Scan() {
		var inc Incident
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&inc); err != nil {
			return err
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return err
		}
		if !validRecoveryIncidentID(inc.ID) || seen[inc.ID] || !isValidClass(inc.Class) || !isValidSeverity(inc.Severity) {
			return fmt.Errorf("invalid or duplicate legacy incident")
		}
		legacy := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s", inc.ID, inc.CreatedAt, inc.Class, inc.Severity, inc.Source, inc.Description)))
		if inc.Hash != hex.EncodeToString(legacy[:16]) {
			return fmt.Errorf("legacy checksum mismatch; preserve the source for investigation")
		}
		seen[inc.ID] = true
		if len(seen) > maxIncidents {
			return fmt.Errorf("legacy history exceeds capacity")
		}
		inc.Hash = incidentHashWithKey(inc, key)
		if err := json.NewEncoder(&converted).Encode(inc); err != nil {
			return err
		}
		if converted.Len() > 16<<20 {
			return fmt.Errorf("migrated history exceeds capacity")
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(converted.Bytes()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

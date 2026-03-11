package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// Trust report types
// ---------------------------------------------------------------------------

// TrustReport is the signed attestation output.
type TrustReport struct {
	Version     string            `json:"version"`
	Hostname    string            `json:"hostname"`
	Attestation AttestationResult `json:"attestation"`
	Signature   string            `json:"signature,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
	SignedAt    string            `json:"signed_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

// generateReport creates a trust report from an attestation result.
func generateReport(att AttestationResult) TrustReport {
	hostname, _ := os.Hostname()
	return TrustReport{
		Version:     "1",
		Hostname:    hostname,
		Attestation: att,
	}
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification
// ---------------------------------------------------------------------------

// signablePayload returns the canonical JSON bytes for signing.
// Excludes signature fields to prevent circular dependency.
func signablePayload(report TrustReport) ([]byte, error) {
	// Zero out signature fields before marshalling.
	clean := report
	clean.Signature = ""
	clean.PublicKey = ""
	clean.SignedAt = ""
	return json.Marshal(clean)
}

// signReport signs the report with an ed25519 private key.
func signReport(report TrustReport, keyPath string) (TrustReport, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return report, fmt.Errorf("read signing key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return report, fmt.Errorf("decode signing key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return report, fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	payload, err := signablePayload(report)
	if err != nil {
		return report, fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)

	report.Signature = base64.StdEncoding.EncodeToString(sig)
	report.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	report.SignedAt = time.Now().UTC().Format(time.RFC3339)
	return report, nil
}

// verifyReport verifies the signature on a trust report.
func verifyReport(report TrustReport, pubKeyPath string) error {
	var pubBytes []byte

	if pubKeyPath != "" {
		// Use explicitly provided public key file.
		data, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("read public key: %w", err)
		}
		pubBytes, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return fmt.Errorf("decode public key file: %w", err)
		}
	} else if report.PublicKey != "" {
		// Use embedded public key.
		var err error
		pubBytes, err = base64.StdEncoding.DecodeString(report.PublicKey)
		if err != nil {
			return fmt.Errorf("decode embedded public key: %w", err)
		}
	} else {
		return fmt.Errorf("no public key available for verification")
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubBytes))
	}

	sigBytes, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	payload, err := signablePayload(report)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		return fmt.Errorf("signature verification failed — report may have been tampered with")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// generateKeypair creates an ed25519 keypair and writes to files.
func generateKeypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if err := os.WriteFile(privPath, []byte(privB64), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

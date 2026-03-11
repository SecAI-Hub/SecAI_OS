package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EvidenceItem records a scan result, test outcome, or attestation.
type EvidenceItem struct {
	Type        string            `json:"type" yaml:"type"`               // scan, test, attestation, review
	Source      string            `json:"source" yaml:"source"`           // ai-quarantine, gguf-guard, manual, etc.
	Timestamp   string            `json:"timestamp" yaml:"timestamp"`
	Result      string            `json:"result" yaml:"result"`           // pass, fail, warning, info
	Description string            `json:"description" yaml:"description"`
	Details     map[string]string `json:"details,omitempty" yaml:"details,omitempty"`
	Hash        string            `json:"hash,omitempty" yaml:"hash,omitempty"`
}

// Attestation is a signed statement about a model's trustworthiness.
type Attestation struct {
	Subject     string         `json:"subject"`     // model name or hash
	Predicate   string         `json:"predicate"`   // what is being attested
	Issuer      string         `json:"issuer"`      // who is attesting
	IssuedAt    string         `json:"issued_at"`
	Evidence    []EvidenceItem `json:"evidence"`
	Hash        string         `json:"hash"`
	Signature   string         `json:"signature,omitempty"`
}

// SignedBOM wraps a BOM with a signature.
type SignedBOM struct {
	BOM       *ModelBOM `json:"bom"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature"`
	SignedAt  string    `json:"signed_at"`
	SignedBy  string    `json:"signed_by,omitempty"`
}

// ImportEvidence reads evidence items from a JSON file (e.g. quarantine scan results).
func ImportEvidence(path string) ([]EvidenceItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence file: %w", err)
	}

	// Try array first, then single item
	var items []EvidenceItem
	if err := json.Unmarshal(data, &items); err == nil {
		return items, nil
	}

	var item EvidenceItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("parse evidence: %w", err)
	}
	return []EvidenceItem{item}, nil
}

// AttachEvidence adds evidence items to a BOM component.
func AttachEvidence(bom *ModelBOM, componentRef string, evidence []EvidenceItem) bool {
	for i := range bom.Components {
		if bom.Components[i].BOMRef == componentRef || bom.Components[i].Name == componentRef {
			bom.Components[i].Evidence = append(bom.Components[i].Evidence, evidence...)
			return true
		}
	}
	return false
}

// CreateAttestation builds an attestation for a model.
func CreateAttestation(subject, predicate, issuer string, evidence []EvidenceItem) Attestation {
	att := Attestation{
		Subject:   subject,
		Predicate: predicate,
		Issuer:    issuer,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		Evidence:  evidence,
	}

	att.Hash = computeAttestationHash(att)
	return att
}

// SignAttestation signs an attestation with an Ed25519 key.
func SignAttestation(att *Attestation, privKey ed25519.PrivateKey) {
	hashBytes, _ := hex.DecodeString(att.Hash)
	sig := ed25519.Sign(privKey, hashBytes)
	att.Signature = hex.EncodeToString(sig)
}

// VerifyAttestation checks an attestation's signature.
func VerifyAttestation(att Attestation, pubKey ed25519.PublicKey) bool {
	if att.Signature == "" || pubKey == nil {
		return false
	}

	expected := computeAttestationHash(att)
	if att.Hash != expected {
		return false
	}

	hashBytes, err := hex.DecodeString(att.Hash)
	if err != nil {
		return false
	}

	sig, err := hex.DecodeString(att.Signature)
	if err != nil {
		return false
	}

	return ed25519.Verify(pubKey, hashBytes, sig)
}

// SignBOM creates a signed BOM wrapper.
func SignBOM(bom *ModelBOM, privKey ed25519.PrivateKey, signer string) SignedBOM {
	data, _ := json.Marshal(bom)
	h := sha256.Sum256(data)
	hashStr := hex.EncodeToString(h[:])

	sig := ed25519.Sign(privKey, h[:])

	return SignedBOM{
		BOM:       bom,
		Hash:      hashStr,
		Signature: hex.EncodeToString(sig),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
		SignedBy:  signer,
	}
}

// VerifySignedBOM checks a signed BOM's integrity and signature.
func VerifySignedBOM(sb SignedBOM, pubKey ed25519.PublicKey) (bool, string) {
	if sb.Signature == "" || pubKey == nil {
		return false, "missing signature or public key"
	}

	data, _ := json.Marshal(sb.BOM)
	h := sha256.Sum256(data)
	hashStr := hex.EncodeToString(h[:])

	if hashStr != sb.Hash {
		return false, "BOM hash mismatch: content has been modified"
	}

	sig, err := hex.DecodeString(sb.Signature)
	if err != nil {
		return false, "invalid signature encoding"
	}

	if !ed25519.Verify(pubKey, h[:], sig) {
		return false, "signature verification failed"
	}

	return true, "valid"
}

// ---------- helpers ----------

func computeAttestationHash(att Attestation) string {
	data, _ := json.Marshal(map[string]interface{}{
		"subject":   att.Subject,
		"predicate": att.Predicate,
		"issuer":    att.Issuer,
		"issued_at": att.IssuedAt,
		"evidence":  att.Evidence,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// EvaluateReadiness checks if a BOM meets minimum deployment criteria.
func EvaluateReadiness(bom *ModelBOM, requiredFields []string) (bool, []string) {
	var missing []string

	if len(bom.Components) == 0 {
		missing = append(missing, "no components in BOM")
	}

	for _, comp := range bom.Components {
		if comp.Type != "machine-learning-model" {
			continue
		}

		for _, field := range requiredFields {
			switch field {
			case "hash":
				if len(comp.Hashes) == 0 {
					missing = append(missing, fmt.Sprintf("%s: no hash", comp.Name))
				}
			case "license":
				if len(comp.Licenses) == 0 {
					missing = append(missing, fmt.Sprintf("%s: no license", comp.Name))
				}
			case "model_card":
				if comp.ModelCard == nil {
					missing = append(missing, fmt.Sprintf("%s: no model card", comp.Name))
				}
			case "evidence":
				if len(comp.Evidence) == 0 {
					missing = append(missing, fmt.Sprintf("%s: no evidence", comp.Name))
				}
			case "trust_labels":
				if comp.ModelCard == nil || len(comp.ModelCard.TrustLabels) == 0 {
					missing = append(missing, fmt.Sprintf("%s: no trust labels", comp.Name))
				}
			case "quantization":
				if comp.ModelCard == nil || comp.ModelCard.Quantization == nil {
					missing = append(missing, fmt.Sprintf("%s: no quantization info", comp.Name))
				}
			case "source":
				if len(comp.ExternalRefs) == 0 {
					missing = append(missing, fmt.Sprintf("%s: no source URL", comp.Name))
				}
			}
		}
	}

	return len(missing) == 0, missing
}

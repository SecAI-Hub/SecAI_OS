package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEntry is a single record in the tamper-evident audit log.
type AuditEntry struct {
	Sequence  int64     `json:"sequence"`
	Timestamp string    `json:"timestamp"`
	Hash      string    `json:"hash"`
	PrevHash  string    `json:"prev_hash"`
	Event     string    `json:"event"`                // evaluate, reload, startup, etc.
	Decision  *Decision `json:"decision,omitempty"`
	Request   *EvalRequest `json:"request,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

// DecisionReceipt is a signed proof of a firewall decision.
type DecisionReceipt struct {
	Decision  Decision  `json:"decision"`
	Request   EvalRequest `json:"request"`
	Timestamp string    `json:"timestamp"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature,omitempty"`
}

// AuditLog provides tamper-evident, hash-chained audit logging.
type AuditLog struct {
	mu       sync.Mutex
	file     *os.File
	seq      int64
	prevHash string
	privKey  ed25519.PrivateKey
	entries  []AuditEntry // in-memory for queries
	maxMem   int
}

// NewAuditLog creates an audit log writer.
func NewAuditLog(path string, privKey ed25519.PrivateKey, maxMem int) (*AuditLog, error) {
	if maxMem <= 0 {
		maxMem = 1000
	}

	al := &AuditLog{
		prevHash: "genesis",
		privKey:  privKey,
		maxMem:   maxMem,
	}

	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		al.file = f
	}

	return al, nil
}

// Record writes an audit entry.
func (al *AuditLog) Record(event string, decision *Decision, request *EvalRequest, detail string) AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.seq++

	// Copy pointer values so callers can reuse variables safely.
	var decCopy *Decision
	if decision != nil {
		c := *decision
		decCopy = &c
	}
	var reqCopy *EvalRequest
	if request != nil {
		c := *request
		reqCopy = &c
	}

	entry := AuditEntry{
		Sequence:  al.seq,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash:  al.prevHash,
		Event:     event,
		Decision:  decCopy,
		Request:   reqCopy,
		Detail:    detail,
	}

	entry.Hash = computeAuditHash(entry)
	al.prevHash = entry.Hash

	if al.file != nil {
		json.NewEncoder(al.file).Encode(entry)
	}

	al.entries = append(al.entries, entry)
	if len(al.entries) > al.maxMem {
		al.entries = al.entries[len(al.entries)-al.maxMem:]
	}

	return entry
}

// SignReceipt creates a signed decision receipt.
func (al *AuditLog) SignReceipt(decision Decision, request EvalRequest) DecisionReceipt {
	receipt := DecisionReceipt{
		Decision:  decision,
		Request:   request,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	hashData, _ := json.Marshal(map[string]interface{}{
		"decision":  decision,
		"request":   request,
		"timestamp": receipt.Timestamp,
	})
	h := sha256.Sum256(hashData)
	receipt.Hash = hex.EncodeToString(h[:])

	if al.privKey != nil {
		sig := ed25519.Sign(al.privKey, h[:])
		receipt.Signature = hex.EncodeToString(sig)
	}

	return receipt
}

// VerifyReceipt checks a receipt's signature.
func VerifyReceipt(receipt DecisionReceipt, pubKey ed25519.PublicKey) bool {
	if receipt.Signature == "" || pubKey == nil {
		return false
	}

	hashData, _ := json.Marshal(map[string]interface{}{
		"decision":  receipt.Decision,
		"request":   receipt.Request,
		"timestamp": receipt.Timestamp,
	})
	h := sha256.Sum256(hashData)

	sig, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return false
	}

	return ed25519.Verify(pubKey, h[:], sig)
}

// Entries returns recent audit entries.
func (al *AuditLog) Entries(limit int) []AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if limit <= 0 || limit > len(al.entries) {
		limit = len(al.entries)
	}

	start := len(al.entries) - limit
	out := make([]AuditEntry, limit)
	copy(out, al.entries[start:])
	return out
}

// VerifyChain checks the hash chain integrity of audit entries.
func VerifyChain(entries []AuditEntry) (bool, int) {
	for i, entry := range entries {
		expected := computeAuditHash(entry)
		if entry.Hash != expected {
			return false, i
		}
		if i > 0 && entry.PrevHash != entries[i-1].Hash {
			return false, i
		}
	}
	return true, -1
}

// computeAuditHash computes the SHA-256 hash for an audit entry.
func computeAuditHash(entry AuditEntry) string {
	// Hash everything except the Hash field itself
	data, _ := json.Marshal(map[string]interface{}{
		"sequence":  entry.Sequence,
		"timestamp": entry.Timestamp,
		"prev_hash": entry.PrevHash,
		"event":     entry.Event,
		"decision":  entry.Decision,
		"request":   entry.Request,
		"detail":    entry.Detail,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Close flushes and closes the audit log file.
func (al *AuditLog) Close() error {
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

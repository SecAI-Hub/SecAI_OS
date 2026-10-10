package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxAuditLogBytes int64 = 256 << 20

// AuditEntry is a single record in the tamper-evident audit log.
type AuditEntry struct {
	Sequence        int64            `json:"sequence"`
	Timestamp       string           `json:"timestamp"`
	Hash            string           `json:"hash"`
	PrevHash        string           `json:"prev_hash"`
	Event           string           `json:"event"` // evaluate, reload, startup, etc.
	Identity        string           `json:"identity,omitempty"`
	PolicyDigest    string           `json:"policy_digest,omitempty"`
	OldPolicyDigest string           `json:"old_policy_digest,omitempty"`
	NewPolicyDigest string           `json:"new_policy_digest,omitempty"`
	Decision        *Decision        `json:"decision,omitempty"`
	Request         *EvalRequest     `json:"request,omitempty"`
	Detail          string           `json:"detail,omitempty"`
	ReceiptUse      *AuditReceiptUse `json:"receipt_use,omitempty"`
}

// AuditContext contains structured attribution that must remain distinct from
// free-form detail redaction. In particular, identities such as
// "password:operator" are valid principal names, not credential material.
type AuditContext struct {
	Identity        string
	PolicyDigest    string
	OldPolicyDigest string
	NewPolicyDigest string
}

type AuditReceiptUse struct {
	NonceHash string `json:"nonce_hash"`
	ExpiresAt string `json:"expires_at"`
	Success   bool   `json:"success"`
}

// DecisionReceipt is a signed proof of a firewall decision.
type DecisionReceipt struct {
	Version          int      `json:"version"`
	Identity         string   `json:"identity,omitempty"`
	SessionTokenHash string   `json:"session_token_hash"`
	Decision         Decision `json:"decision"`
	RequestDigest    string   `json:"request_digest"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
	Nonce            string   `json:"nonce"`
	Audience         string   `json:"audience"`
	KeyID            string   `json:"key_id"`
	PolicyDigest     string   `json:"policy_digest"`
	AuditSequence    int64    `json:"audit_sequence"`
	AuditHash        string   `json:"audit_hash"`
	BatchID          string   `json:"batch_id,omitempty"`
	BatchIndex       int      `json:"batch_index"`
	BatchSize        int      `json:"batch_size"`
	Hash             string   `json:"hash"`
	Signature        string   `json:"signature"`
}

type ReceiptOptions struct {
	Audience     string
	PolicyDigest string
	TTL          time.Duration
	BatchID      string
	BatchIndex   int
	BatchSize    int
}

type receiptRequestClaims struct {
	Server            string            `json:"server"`
	ServerFingerprint string            `json:"server_fingerprint,omitempty"`
	Method            string            `json:"method"`
	Tool              string            `json:"tool,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Arguments         map[string]string `json:"arguments,omitempty"`
	SessionID         string            `json:"session_id"`
	RequestID         string            `json:"request_id,omitempty"`
}

// ReceiptVerifier validates receipt context and consumes each nonce once.
type ReceiptVerifier struct {
	mu           sync.Mutex
	publicKey    ed25519.PublicKey
	audience     string
	policyDigest string
	used         map[string]receiptNonceState
}

type receiptNonceState struct {
	expires     time.Time
	reservation string
	consumed    bool
}

type ReceiptReservation struct {
	nonce string
	id    string
}

// AuditLog provides tamper-evident, hash-chained audit logging.
type AuditLog struct {
	mu        sync.Mutex
	file      *os.File
	seq       int64
	prevHash  string
	privKey   ed25519.PrivateKey
	entries   []AuditEntry // in-memory for queries
	maxMem    int
	writeErr  error
	path      string
	consumed  map[string]time.Time
	decisions map[int64]decisionEvidence
	taints    map[string]map[string]bool
}

type decisionEvidence struct {
	hash    string
	expires time.Time
}

// NewAuditLog creates an audit log writer.
func NewAuditLog(path string, privKey ed25519.PrivateKey, maxMem int) (*AuditLog, error) {
	if maxMem <= 0 {
		maxMem = 1000
	}

	al := &AuditLog{
		prevHash:  "genesis",
		privKey:   privKey,
		maxMem:    maxMem,
		consumed:  make(map[string]time.Time),
		decisions: make(map[int64]decisionEvidence),
		taints:    make(map[string]map[string]bool),
	}

	if path != "" {
		f, err := openAuditFile(path)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		entries, seq, prevHash, consumed, err := scanAuditEntriesFromFile(f, maxMem, al.indexEntry)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("resume audit log: %w", err)
		}
		al.entries = entries
		al.seq = seq
		al.consumed = consumed
		if prevHash != "" {
			al.prevHash = prevHash
		}
		al.file = f
		al.path = path
	}

	return al, nil
}

// Record writes an audit entry.
func (al *AuditLog) Record(event string, decision *Decision, request *EvalRequest, detail string) (AuditEntry, error) {
	return al.record(event, decision, request, detail, nil, AuditContext{})
}

func (al *AuditLog) RecordContext(event string, decision *Decision, request *EvalRequest, detail string, context AuditContext) (AuditEntry, error) {
	return al.record(event, decision, request, detail, nil, context)
}

func (al *AuditLog) RecordCompletion(receipt DecisionReceipt, success bool, actors ...string) (AuditEntry, error) {
	expires, err := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	if err != nil || receipt.Nonce == "" {
		return AuditEntry{}, fmt.Errorf("invalid receipt completion claims")
	}
	use := &AuditReceiptUse{NonceHash: receiptReplayKey(receipt.Nonce), ExpiresAt: expires.UTC().Format(time.RFC3339Nano), Success: success}
	detail := fmt.Sprintf("receipt=%s success=%t", use.NonceHash, success)
	context := AuditContext{PolicyDigest: receipt.PolicyDigest}
	if len(actors) > 0 && credentialIdentityPattern.MatchString(actors[0]) {
		context.Identity = actors[0]
	}
	return al.record("execution-complete", &receipt.Decision, nil, detail, use, context)
}

func (al *AuditLog) record(event string, decision *Decision, request *EvalRequest, detail string, receiptUse *AuditReceiptUse, context AuditContext) (AuditEntry, error) {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.writeErr != nil {
		return AuditEntry{}, al.writeErr
	}
	if receiptUse != nil {
		al.pruneConsumedLocked(time.Now())
		if _, exists := al.consumed[receiptUse.NonceHash]; exists {
			return AuditEntry{}, fmt.Errorf("receipt completion is already recorded")
		}
		if len(al.consumed) >= 20_000 {
			return AuditEntry{}, fmt.Errorf("audit receipt-use index is at capacity")
		}
	}
	if event == "" || len(event) > 128 || strings.ContainsAny(event, "\x00\r\n") {
		return AuditEntry{}, fmt.Errorf("invalid audit event")
	}
	if context.Identity != "" && !credentialIdentityPattern.MatchString(context.Identity) {
		return AuditEntry{}, fmt.Errorf("invalid audit identity")
	}
	for name, digest := range map[string]string{
		"policy": context.PolicyDigest, "old policy": context.OldPolicyDigest, "new policy": context.NewPolicyDigest,
	} {
		if digest != "" && !validPrefixedSHA256(digest) {
			return AuditEntry{}, fmt.Errorf("invalid %s digest", name)
		}
	}

	decCopy, reqCopy, err := cloneAuditPayload(decision, request)
	if err != nil {
		return AuditEntry{}, err
	}
	if receiptUse != nil {
		copy := *receiptUse
		receiptUse = &copy
	}

	entry := AuditEntry{
		Sequence:        al.seq + 1,
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash:        al.prevHash,
		Event:           event,
		Identity:        context.Identity,
		PolicyDigest:    context.PolicyDigest,
		OldPolicyDigest: context.OldPolicyDigest,
		NewPolicyDigest: context.NewPolicyDigest,
		Decision:        decCopy,
		Request:         reqCopy,
		Detail:          "", // Free-form messages can contain arbitrary private payloads.
		ReceiptUse:      receiptUse,
	}

	entry.Hash = computeAuditHash(entry)
	// Admission to bounded recovery indexes must succeed before the durable
	// append and before any actionable receipt can be issued.
	if err := al.checkIndexCapacity(entry); err != nil {
		return AuditEntry{}, err
	}

	if al.file != nil {
		line, err := json.Marshal(entry)
		if err != nil {
			return AuditEntry{}, err
		}
		line = append(line, '\n')
		if err := al.validateLiveFileLocked(int64(len(line))); err != nil {
			al.writeErr = err
			return AuditEntry{}, err
		}
		for len(line) > 0 {
			n, writeErr := al.file.Write(line)
			if writeErr != nil {
				al.writeErr = fmt.Errorf("write audit entry: %w", writeErr)
				return AuditEntry{}, al.writeErr
			}
			if n == 0 {
				al.writeErr = fmt.Errorf("write audit entry: zero-byte write")
				return AuditEntry{}, al.writeErr
			}
			line = line[n:]
		}
		if err := al.file.Sync(); err != nil {
			al.writeErr = fmt.Errorf("sync audit entry: %w", err)
		}
		if al.writeErr == nil {
			if err := al.validateLiveFileLocked(0); err != nil {
				al.writeErr = err
			}
		}
	}
	al.seq = entry.Sequence
	al.prevHash = entry.Hash

	al.entries = append(al.entries, entry)
	if err := al.indexEntry(entry); err != nil {
		al.writeErr = err
	}
	if receiptUse != nil {
		if expiry, err := time.Parse(time.RFC3339Nano, receiptUse.ExpiresAt); err == nil {
			al.consumed[receiptUse.NonceHash] = expiry
		}
	}
	if len(al.entries) > al.maxMem {
		al.entries = al.entries[len(al.entries)-al.maxMem:]
	}

	if al.writeErr != nil {
		return entry, al.writeErr
	}
	return entry, nil
}

func cloneAuditPayload(decision *Decision, request *EvalRequest) (*Decision, *EvalRequest, error) {
	if request != nil {
		clean := sanitizeRequestForAudit(*request)
		request = &clean
	}
	if decision != nil {
		clean := sanitizeDecisionForAudit(*decision)
		decision = &clean
	}
	return copyAuditPayload(decision, request)
}

func copyAuditPayload(decision *Decision, request *EvalRequest) (*Decision, *EvalRequest, error) {
	var envelope struct {
		Decision *Decision    `json:"decision,omitempty"`
		Request  *EvalRequest `json:"request,omitempty"`
	}
	data, err := json.Marshal(struct {
		Decision *Decision    `json:"decision,omitempty"`
		Request  *EvalRequest `json:"request,omitempty"`
	}{decision, request})
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, nil, err
	}
	return envelope.Decision, envelope.Request, nil
}

// SignReceipt creates a short-lived, context-bound decision receipt.
func (al *AuditLog) SignReceipt(decision Decision, request EvalRequest, auditEntry AuditEntry, options ReceiptOptions) (DecisionReceipt, error) {
	if len(al.privKey) != ed25519.PrivateKeySize {
		return DecisionReceipt{}, fmt.Errorf("receipt signing key is unavailable")
	}
	if auditEntry.Decision == nil || auditEntry.Sequence <= 0 || auditEntry.Hash == "" ||
		!sameJSON(*auditEntry.Decision, sanitizeDecisionForAudit(decision)) {
		return DecisionReceipt{}, fmt.Errorf("receipt is not bound to its durable audit decision")
	}
	if options.Audience == "" || options.PolicyDigest == "" {
		return DecisionReceipt{}, fmt.Errorf("receipt audience and policy digest are required")
	}
	if options.TTL <= 0 || options.TTL > 10*time.Minute {
		return DecisionReceipt{}, fmt.Errorf("receipt TTL must be between 1ns and 10m")
	}
	if options.BatchSize < 1 || options.BatchSize > 100 || options.BatchIndex < 0 || options.BatchIndex >= options.BatchSize {
		return DecisionReceipt{}, fmt.Errorf("invalid receipt batch binding")
	}
	if options.BatchSize > 1 && options.BatchID == "" {
		return DecisionReceipt{}, fmt.Errorf("batch receipts require a batch ID")
	}
	issued, err := time.Parse(time.RFC3339Nano, auditEntry.Timestamp)
	if err != nil || time.Since(issued) > time.Minute || !al.ContainsDecision(auditEntry.Sequence, auditEntry.Hash) {
		return DecisionReceipt{}, fmt.Errorf("receipt requires a recent durable decision")
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return DecisionReceipt{}, fmt.Errorf("generate receipt nonce: %w", err)
	}
	now := time.Now().UTC()
	requestDigest, err := ComputeRequestDigest(request)
	if err != nil {
		return DecisionReceipt{}, err
	}
	publicKey := al.privKey.Public().(ed25519.PublicKey)
	receipt := DecisionReceipt{
		Version:          2,
		Identity:         auditEntry.Identity,
		SessionTokenHash: receiptReplayKey(request.SessionToken),
		Decision:         decision,
		RequestDigest:    requestDigest,
		IssuedAt:         now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(options.TTL).Format(time.RFC3339Nano),
		Nonce:            base64.RawURLEncoding.EncodeToString(nonceBytes),
		Audience:         options.Audience,
		KeyID:            receiptKeyID(publicKey),
		PolicyDigest:     options.PolicyDigest,
		AuditSequence:    auditEntry.Sequence,
		AuditHash:        auditEntry.Hash,
		BatchID:          options.BatchID,
		BatchIndex:       options.BatchIndex,
		BatchSize:        options.BatchSize,
	}
	h, err := receiptHash(receipt)
	if err != nil {
		return DecisionReceipt{}, err
	}
	receipt.Hash = hex.EncodeToString(h[:])
	receipt.Signature = hex.EncodeToString(ed25519.Sign(al.privKey, h[:]))
	return receipt, nil
}

// ComputeRequestDigest returns the exact digest an executor must bind to an
// operation. The secret session token is intentionally excluded.
func ComputeRequestDigest(request EvalRequest) (string, error) {
	requestData, err := json.Marshal(receiptRequestClaims{
		Server: request.Server, ServerFingerprint: request.ServerFingerprint, Method: request.Method,
		Tool: request.Tool, Resource: request.Resource, Arguments: request.Arguments,
		SessionID: request.SessionID, RequestID: request.RequestID,
	})
	if err != nil {
		return "", err
	}
	requestHash := sha256.Sum256(append([]byte("mcp-firewall/request/v1\x00"), requestData...))
	return "sha256:" + hex.EncodeToString(requestHash[:]), nil
}

// VerifyReceipt checks cryptographic and temporal validity. Use ReceiptVerifier
// in execution paths to additionally enforce audience, policy, and one-time use.
func VerifyReceipt(receipt DecisionReceipt, pubKey ed25519.PublicKey) bool {
	if len(pubKey) != ed25519.PublicKeySize || receipt.Version != 2 ||
		!validPrefixedSHA256(receipt.SessionTokenHash) ||
		(receipt.Identity != "" && !credentialIdentityPattern.MatchString(receipt.Identity)) ||
		receipt.KeyID != receiptKeyID(pubKey) || receipt.Audience == "" ||
		receipt.PolicyDigest == "" || receipt.AuditSequence <= 0 ||
		len(receipt.AuditHash) != 64 || receipt.BatchSize < 1 || receipt.BatchSize > 100 ||
		receipt.BatchIndex < 0 || receipt.BatchIndex >= receipt.BatchSize ||
		(receipt.BatchSize > 1 && receipt.BatchID == "") || len(receipt.BatchID) > 128 {
		return false
	}
	if !validPrefixedSHA256(receipt.PolicyDigest) || !validPrefixedSHA256(receipt.RequestDigest) ||
		!validHexBytes(receipt.AuditHash, sha256.Size) {
		return false
	}
	issued, err := time.Parse(time.RFC3339Nano, receipt.IssuedAt)
	if err != nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 10*time.Minute {
		return false
	}
	now := time.Now()
	if issued.After(now.Add(30*time.Second)) || !now.Before(expires) {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(receipt.Nonce)
	if err != nil || len(nonce) != 32 {
		return false
	}
	h, err := receiptHash(receipt)
	if err != nil {
		return false
	}
	if len(receipt.Hash) != hex.EncodedLen(len(h)) ||
		subtle.ConstantTimeCompare([]byte(receipt.Hash), []byte(hex.EncodeToString(h[:]))) != 1 {
		return false
	}

	sig, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return false
	}

	return ed25519.Verify(pubKey, h[:], sig)
}

func validPrefixedSHA256(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && validHexBytes(strings.TrimPrefix(value, "sha256:"), sha256.Size)
}

func validHexBytes(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size
}

func NewReceiptVerifier(publicKey ed25519.PublicKey, audience, policyDigest string) (*ReceiptVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || audience == "" || policyDigest == "" {
		return nil, fmt.Errorf("receipt verification context is incomplete")
	}
	return &ReceiptVerifier{publicKey: append(ed25519.PublicKey(nil), publicKey...), audience: audience, policyDigest: policyDigest, used: make(map[string]receiptNonceState)}, nil
}

func (rv *ReceiptVerifier) VerifyAndConsume(receipt DecisionReceipt) error {
	return rv.VerifyAndConsumeForPolicy(receipt, rv.policyDigest)
}

func (rv *ReceiptVerifier) VerifyAndConsumeForPolicy(receipt DecisionReceipt, expectedPolicyDigest string) error {
	reservation, err := rv.ReserveForPolicy(receipt, expectedPolicyDigest)
	if err != nil {
		return err
	}
	rv.Commit(reservation)
	return nil
}

func (rv *ReceiptVerifier) ReserveForPolicy(receipt DecisionReceipt, expectedPolicyDigest string) (ReceiptReservation, error) {
	if !VerifyReceipt(receipt, rv.publicKey) {
		return ReceiptReservation{}, fmt.Errorf("receipt signature or claims are invalid")
	}
	if subtle.ConstantTimeCompare([]byte(receipt.Audience), []byte(rv.audience)) != 1 ||
		subtle.ConstantTimeCompare([]byte(receipt.PolicyDigest), []byte(expectedPolicyDigest)) != 1 {
		return ReceiptReservation{}, fmt.Errorf("receipt context mismatch")
	}
	expires, _ := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	reservationBytes := make([]byte, 16)
	if _, err := rand.Read(reservationBytes); err != nil {
		return ReceiptReservation{}, fmt.Errorf("generate receipt reservation: %w", err)
	}
	reservation := ReceiptReservation{nonce: receipt.Nonce, id: base64.RawURLEncoding.EncodeToString(reservationBytes)}
	replayKey := receiptReplayKey(receipt.Nonce)
	reservation.nonce = replayKey
	rv.mu.Lock()
	defer rv.mu.Unlock()
	now := time.Now()
	for nonce, state := range rv.used {
		if !now.Before(state.expires) {
			delete(rv.used, nonce)
		}
	}
	if _, exists := rv.used[replayKey]; exists {
		return ReceiptReservation{}, fmt.Errorf("receipt nonce is reserved or has already been consumed")
	}
	if len(rv.used) >= 20_000 {
		return ReceiptReservation{}, fmt.Errorf("receipt replay cache is at capacity")
	}
	rv.used[replayKey] = receiptNonceState{expires: expires, reservation: reservation.id}
	return reservation, nil
}

func (rv *ReceiptVerifier) Commit(reservation ReceiptReservation) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	state, ok := rv.used[reservation.nonce]
	if !ok || subtle.ConstantTimeCompare([]byte(state.reservation), []byte(reservation.id)) != 1 {
		return
	}
	state.consumed = true
	state.reservation = ""
	rv.used[reservation.nonce] = state
}

func (rv *ReceiptVerifier) Release(reservation ReceiptReservation) {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	state, ok := rv.used[reservation.nonce]
	if ok && !state.consumed && subtle.ConstantTimeCompare([]byte(state.reservation), []byte(reservation.id)) == 1 {
		delete(rv.used, reservation.nonce)
	}
}

func receiptHash(receipt DecisionReceipt) ([32]byte, error) {
	receipt.Hash = ""
	receipt.Signature = ""
	data, err := json.Marshal(receipt)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("mcp-firewall/decision-receipt/v2\x00"), data...)), nil
}

func receiptKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func receiptReplayKey(nonce string) string {
	digest := sha256.Sum256([]byte(nonce))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func sameJSON(left, right any) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
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
	for i, entry := range al.entries[start:] {
		decision, request, err := copyAuditPayload(entry.Decision, entry.Request)
		if err != nil {
			return nil
		}
		entry.Decision = decision
		entry.Request = request
		if entry.ReceiptUse != nil {
			receiptUse := *entry.ReceiptUse
			entry.ReceiptUse = &receiptUse
		}
		out[i] = entry
	}
	return out
}

// VerifyChain checks the hash chain integrity of audit entries.
func VerifyChain(entries []AuditEntry) (bool, int) {
	for i, entry := range entries {
		if entry.Sequence <= 0 {
			return false, i
		}
		if i > 0 && entry.Sequence != entries[i-1].Sequence+1 {
			return false, i
		}
		expected := computeAuditHash(entry)
		if entry.Hash != expected {
			return false, i
		}
		if i == 0 && entry.Sequence == 1 && entry.PrevHash != "genesis" {
			return false, i
		}
		if i > 0 && entry.PrevHash != entries[i-1].Hash {
			return false, i
		}
	}
	return true, -1
}

func loadAuditEntries(path string, maxMem int) ([]AuditEntry, int64, string, error) {
	before, err := os.Lstat(path) // #nosec G304,G703 -- operator-selected audit path is checked for symlinks and identity before use
	if err != nil {
		return nil, 0, "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, 0, "", fmt.Errorf("audit log must not be a symbolic link")
	}
	f, err := os.Open(path) // #nosec G304,G703 -- the validated audit path is intentionally configurable
	if err != nil {
		return nil, 0, "", err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, 0, "", err
	}
	after, err := os.Lstat(path) // #nosec G304,G703 -- required post-open identity check of the configured path
	if err != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, 0, "", fmt.Errorf("audit log changed while opening or is a symbolic link")
	}
	return loadAuditEntriesFromFile(f, maxMem)
}

func openAuditFile(path string) (*os.File, error) {
	before, err := os.Lstat(path) // #nosec G304,G703 -- pre-open validation for the configured audit destination
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("audit log must not be a symbolic link")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600) // #nosec G304,G703 -- identity, mode, type and link count are validated immediately and on every append
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	after, err := os.Lstat(path) // #nosec G304,G703 -- post-open identity validation for the configured audit destination
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) ||
		(before != nil && !os.SameFile(before, opened)) {
		_ = f.Close()
		return nil, fmt.Errorf("audit log changed while opening or is a symbolic link")
	}
	if err := validateAuditFileInfo(opened); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit log already has a writer: %w", err)
	}
	return f, nil
}

func loadAuditEntriesFromFile(f *os.File, maxMem int) ([]AuditEntry, int64, string, error) {
	entries, sequence, previous, _, err := scanAuditEntriesFromFile(f, maxMem)
	return entries, sequence, previous, err
}

func scanAuditEntriesFromFile(f *os.File, maxMem int, visitors ...func(AuditEntry) error) ([]AuditEntry, int64, string, map[string]time.Time, error) {
	consumed := make(map[string]time.Time)
	info, err := f.Stat()
	if err != nil {
		return nil, 0, "", nil, err
	}
	if err := validateAuditFileInfo(info); err != nil || info.Size() > maxAuditLogBytes {
		return nil, 0, "", nil, fmt.Errorf("audit log is not regular or exceeds 256 MiB")
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
			return nil, 0, "", nil, err
		}
		if last[0] != '\n' {
			return nil, 0, "", nil, fmt.Errorf("audit log has an incomplete final entry")
		}
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, 0, "", nil, err
	}

	var retained []AuditEntry
	var previous = "genesis"
	var sequence int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			return nil, sequence, previous, nil, fmt.Errorf("empty audit entry at sequence %d", sequence+1)
		}
		var entry AuditEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return nil, sequence, previous, nil, fmt.Errorf("invalid JSON at entry %d: %w", sequence+1, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != nil && err != io.EOF {
			return nil, sequence, previous, nil, fmt.Errorf("invalid trailing JSON at entry %d: %w", sequence+1, err)
		} else if err == nil {
			return nil, sequence, previous, nil, fmt.Errorf("multiple JSON values at entry %d", sequence+1)
		}
		if entry.Sequence != sequence+1 || entry.PrevHash != previous ||
			entry.Hash != computeAuditHash(entry) {
			return nil, sequence, previous, nil, fmt.Errorf("chain break at entry %d", sequence+1)
		}
		if entry.Identity != "" && !credentialIdentityPattern.MatchString(entry.Identity) {
			return nil, sequence, previous, nil, fmt.Errorf("invalid identity at entry %d", sequence+1)
		}
		for _, digest := range []string{entry.PolicyDigest, entry.OldPolicyDigest, entry.NewPolicyDigest} {
			if digest != "" && !validPrefixedSHA256(digest) {
				return nil, sequence, previous, nil, fmt.Errorf("invalid policy digest at entry %d", sequence+1)
			}
		}
		if entry.ReceiptUse != nil {
			expires, expiryErr := time.Parse(time.RFC3339Nano, entry.ReceiptUse.ExpiresAt)
			if entry.Event != "execution-complete" || !validPrefixedSHA256(entry.ReceiptUse.NonceHash) || expiryErr != nil {
				return nil, sequence, previous, nil, fmt.Errorf("invalid receipt-use record at entry %d", sequence+1)
			}
			if time.Now().Before(expires) {
				consumed[entry.ReceiptUse.NonceHash] = expires
			}
		}
		sequence = entry.Sequence
		previous = entry.Hash
		for _, visit := range visitors {
			if err := visit(entry); err != nil {
				return nil, sequence, previous, nil, err
			}
		}
		retained = append(retained, entry)
		if len(retained) > maxMem {
			retained = retained[len(retained)-maxMem:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, sequence, previous, nil, err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, sequence, previous, nil, fmt.Errorf("audit log changed during validation")
	}
	return retained, sequence, previous, consumed, nil
}

func validateAuditFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("audit log must be a regular mode-0600 file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("audit log must have exactly one hard link")
	}
	return nil
}

func (al *AuditLog) validateLiveFileLocked(pending int64) error {
	if al.file == nil {
		return nil
	}
	opened, err := al.file.Stat()
	if err != nil {
		return fmt.Errorf("inspect live audit file: %w", err)
	}
	if err := validateAuditFileInfo(opened); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(al.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return fmt.Errorf("audit path identity changed")
	}
	if pending < 0 || opened.Size() > maxAuditLogBytes-pending {
		return fmt.Errorf("audit log reached the %d-byte runtime cap", maxAuditLogBytes)
	}
	return nil
}

func (al *AuditLog) ContainsDecision(sequence int64, hash string) bool {
	al.mu.Lock()
	defer al.mu.Unlock()
	entry, ok := al.decisions[sequence]
	return ok && time.Now().Before(entry.expires) && subtle.ConstantTimeCompare([]byte(entry.hash), []byte(hash)) == 1
}

func (al *AuditLog) ConsumedReceipts() map[string]time.Time {
	al.mu.Lock()
	defer al.mu.Unlock()
	now := time.Now()
	al.pruneConsumedLocked(now)
	out := make(map[string]time.Time)
	for nonceHash, expires := range al.consumed {
		if now.Before(expires) {
			out[nonceHash] = expires
		}
	}
	return out
}

func (al *AuditLog) pruneConsumedLocked(now time.Time) {
	for nonceHash, expires := range al.consumed {
		if !now.Before(expires) {
			delete(al.consumed, nonceHash)
		}
	}
}

func (rv *ReceiptVerifier) SeedConsumed(consumed map[string]time.Time) error {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	now := time.Now()
	for nonceHash, expires := range consumed {
		if !validPrefixedSHA256(nonceHash) || !now.Before(expires) {
			continue
		}
		if len(rv.used) >= 20_000 {
			return fmt.Errorf("receipt replay cache is at capacity during audit recovery")
		}
		rv.used[nonceHash] = receiptNonceState{expires: expires, consumed: true}
	}
	return nil
}

// computeAuditHash computes the SHA-256 hash for an audit entry.
func computeAuditHash(entry AuditEntry) string {
	// Hash everything except the Hash field itself
	payload := map[string]interface{}{
		"sequence":  entry.Sequence,
		"timestamp": entry.Timestamp,
		"prev_hash": entry.PrevHash,
		"event":     entry.Event,
		"decision":  entry.Decision,
		"request":   entry.Request,
		"detail":    entry.Detail,
	}
	if entry.Identity != "" {
		payload["identity"] = entry.Identity
	}
	if entry.PolicyDigest != "" {
		payload["policy_digest"] = entry.PolicyDigest
	}
	if entry.OldPolicyDigest != "" {
		payload["old_policy_digest"] = entry.OldPolicyDigest
	}
	if entry.NewPolicyDigest != "" {
		payload["new_policy_digest"] = entry.NewPolicyDigest
	}
	if entry.ReceiptUse != nil {
		payload["receipt_use"] = entry.ReceiptUse
	}
	data, _ := json.Marshal(payload)
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

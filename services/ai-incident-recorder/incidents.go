package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Incident types
// ---------------------------------------------------------------------------

// Incident represents a flagged event sequence requiring investigation.
type Incident struct {
	ID        string   `json:"id"`
	SessionID string   `json:"session_id"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"` // info, warning, alert, critical
	Status    string   `json:"status"`   // open, investigating, resolved, closed
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	EventIDs  []string `json:"event_ids,omitempty"` // specific events, or empty = all session events
}

// TimelineEntry is a human-readable view of an event within an incident.
type TimelineEntry struct {
	RelativeMs int64  `json:"relative_ms"`
	Timestamp  string `json:"timestamp"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	EventID    string `json:"event_id"`
}

// CaseBundle is a signed, exportable evidence package.
type CaseBundle struct {
	Version    string         `json:"version"`
	IncidentID string         `json:"incident_id"`
	Title      string         `json:"title"`
	CreatedAt  string         `json:"created_at"`
	Hostname   string         `json:"hostname"`
	Incident   Incident       `json:"incident"`
	Events     []Event        `json:"events"`
	Timeline   []TimelineEntry `json:"timeline"`
	Redaction  RedactionStats `json:"redaction"`
	Integrity  string         `json:"integrity"`            // SHA-256 of event hashes
	Signature  string         `json:"signature,omitempty"`
	PublicKey  string         `json:"public_key,omitempty"`
	SignedAt   string         `json:"signed_at,omitempty"`
}

// PrivacyProfileConfig controls what gets redacted in case bundles.
type PrivacyProfileConfig struct {
	Redact        bool     `yaml:"redact"`
	StripHostname bool     `yaml:"strip_hostname"`
	Patterns      []string `yaml:"patterns"`
}

// ---------------------------------------------------------------------------
// Timeline builder
// ---------------------------------------------------------------------------

// BuildTimeline creates a chronological timeline from events.
func BuildTimeline(events []Event) []TimelineEntry {
	if len(events) == 0 {
		return nil
	}

	// Sort by timestamp.
	sorted := make([]Event, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp < sorted[j].Timestamp
	})

	// Parse first event time for relative calculation.
	firstTime, _ := time.Parse(time.RFC3339Nano, sorted[0].Timestamp)

	entries := make([]TimelineEntry, len(sorted))
	for i, e := range sorted {
		eventTime, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
		entries[i] = TimelineEntry{
			RelativeMs: eventTime.Sub(firstTime).Milliseconds(),
			Timestamp:  e.Timestamp,
			Source:     e.Source,
			Type:       e.Type,
			Severity:   e.Severity,
			Summary:    summarizeEvent(e),
			EventID:    e.ID,
		}
	}
	return entries
}

// ---------------------------------------------------------------------------
// Incident store (file-backed with fsync)
// ---------------------------------------------------------------------------

// IncidentStore manages incident persistence.
type IncidentStore struct {
	mu        sync.RWMutex
	incidents map[string]*Incident
	dataDir   string
}

// NewIncidentStore creates or loads an incident store.
func NewIncidentStore(dataDir string) (*IncidentStore, error) {
	dir := dataDir + "/incidents"
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create incidents dir: %w", err)
	}

	store := &IncidentStore{
		incidents: make(map[string]*Incident),
		dataDir:   dir,
	}

	// Load existing incidents (corruption-tolerant).
	entries, err := os.ReadDir(dir)
	if err != nil {
		return store, nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(dir + "/" + entry.Name())
		if err != nil {
			continue
		}
		var inc Incident
		if err := json.Unmarshal(data, &inc); err != nil {
			log.Printf("warning: skipping corrupt incident file %s: %v", entry.Name(), err)
			continue
		}
		store.incidents[inc.ID] = &inc
	}
	return store, nil
}

// Create adds a new incident with fsync.
func (s *IncidentStore) Create(inc Incident) (*Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if inc.ID == "" {
		inc.ID = generateID()
	}
	if inc.CreatedAt == "" {
		inc.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if inc.Status == "" {
		inc.Status = "open"
	}
	if inc.Severity == "" {
		inc.Severity = "alert"
	}

	// Persist with fsync.
	data, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal incident: %w", err)
	}
	path := fmt.Sprintf("%s/%s.json", s.dataDir, inc.ID)
	if err := writeFileSync(path, data, 0640); err != nil {
		return nil, fmt.Errorf("write incident: %w", err)
	}

	s.incidents[inc.ID] = &inc
	return &inc, nil
}

// Get returns an incident by ID.
func (s *IncidentStore) Get(id string) (*Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	return inc, ok
}

// List returns all incidents, newest first.
func (s *IncidentStore) List() []*Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Incident
	for _, inc := range s.incidents {
		result = append(result, inc)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})
	return result
}

// Update persists changes to an existing incident with fsync.
func (s *IncidentStore) Update(inc *Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}
	path := fmt.Sprintf("%s/%s.json", s.dataDir, inc.ID)
	if err := writeFileSync(path, data, 0640); err != nil {
		return fmt.Errorf("write incident: %w", err)
	}

	s.incidents[inc.ID] = inc
	return nil
}

// writeFileSync writes data to a file and fsyncs before closing.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ---------------------------------------------------------------------------
// Case bundle packaging
// ---------------------------------------------------------------------------

// computeIntegrity computes a SHA-256 digest over all event hashes.
func computeIntegrity(events []Event) string {
	h := sha256.New()
	for _, e := range events {
		h.Write([]byte(e.Hash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PackageBundle creates a signed, redacted case bundle for an incident.
// The privacy profile controls what gets redacted and whether hostname is stripped.
func PackageBundle(inc *Incident, events []Event, profile PrivacyProfileConfig, keyPath string) (*CaseBundle, error) {
	// Apply redaction to a copy of events.
	var bundleEvents []Event
	var stats RedactionStats
	if profile.Redact {
		bundleEvents, stats = RedactEvents(events, profile.Patterns)
	} else {
		bundleEvents = make([]Event, len(events))
		copy(bundleEvents, events)
		stats = RedactionStats{Counts: make(map[string]int)}
	}

	hostname, _ := os.Hostname()
	if profile.StripHostname {
		hostname = "[REDACTED]"
	}

	bundle := &CaseBundle{
		Version:    "1",
		IncidentID: inc.ID,
		Title:      inc.Title,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Hostname:   hostname,
		Incident:   *inc,
		Events:     bundleEvents,
		Timeline:   BuildTimeline(bundleEvents),
		Redaction:  stats,
		Integrity:  computeIntegrity(events), // integrity over ORIGINAL hashes
	}

	// Sign if key is available.
	if keyPath != "" {
		if err := signBundle(bundle, keyPath); err != nil {
			return bundle, fmt.Errorf("sign bundle: %w", err)
		}
	}

	return bundle, nil
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification
// ---------------------------------------------------------------------------

// signableBundlePayload returns the canonical bytes for signing a bundle.
func signableBundlePayload(bundle CaseBundle) ([]byte, error) {
	clean := bundle
	clean.Signature = ""
	clean.PublicKey = ""
	clean.SignedAt = ""
	return json.Marshal(clean)
}

func signBundle(bundle *CaseBundle, keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return fmt.Errorf("decode signing key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	payload, err := signableBundlePayload(*bundle)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)
	bundle.Signature = base64.StdEncoding.EncodeToString(sig)
	bundle.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	bundle.SignedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// VerifyBundle checks integrity and signature of a case bundle.
func VerifyBundle(bundle *CaseBundle, pubKeyPath string) error {
	// Verify event hash chain.
	if err := verifyEventChain(bundle.Events); err != nil {
		return fmt.Errorf("event chain: %w", err)
	}

	// Verify signature if present.
	if bundle.Signature == "" {
		return nil // unsigned bundle, chain verified
	}

	var pubBytes []byte
	if pubKeyPath != "" {
		data, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("read public key: %w", err)
		}
		var decErr error
		pubBytes, decErr = base64.StdEncoding.DecodeString(string(data))
		if decErr != nil {
			return fmt.Errorf("decode public key file: %w", decErr)
		}
	} else if bundle.PublicKey != "" {
		var err error
		pubBytes, err = base64.StdEncoding.DecodeString(bundle.PublicKey)
		if err != nil {
			return fmt.Errorf("decode embedded public key: %w", err)
		}
	} else {
		return fmt.Errorf("no public key available for signature verification")
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	payload, err := signableBundlePayload(*bundle)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		return fmt.Errorf("signature verification FAILED — bundle may have been tampered with")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Key generation (same as runtime-attestor)
// ---------------------------------------------------------------------------

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

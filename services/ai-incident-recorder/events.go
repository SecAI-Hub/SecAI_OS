package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

// Event is a single timestamped occurrence in the system.
// Events are chained via Hash/PrevHash for tamper-evident storage.
type Event struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	SessionID string                 `json:"session_id"`
	Source    string                 `json:"source"`              // originating service
	Type      string                 `json:"type"`                // event classification
	Severity  string                 `json:"severity"`            // info, warning, alert, critical
	Actor     string                 `json:"actor,omitempty"`     // who/what triggered
	Data      map[string]interface{} `json:"data,omitempty"`      // event-specific payload
	Hash      string                 `json:"hash"`                // SHA-256 of canonical event
	PrevHash  string                 `json:"prev_hash,omitempty"` // previous event hash (chain)
}

// SessionSummary describes a recording session.
type SessionSummary struct {
	SessionID  string   `json:"session_id"`
	EventCount int      `json:"event_count"`
	FirstEvent string   `json:"first_event"`
	LastEvent  string   `json:"last_event"`
	Sources    []string `json:"sources"`
}

// EventFilter specifies query criteria.
type EventFilter struct {
	SessionID string
	Source    string
	Type      string
	Severity  string
	After     string // RFC3339 timestamp
	Before    string // RFC3339 timestamp
	Limit     int
}

// ---------------------------------------------------------------------------
// Event ID generation
// ---------------------------------------------------------------------------

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

// ---------------------------------------------------------------------------
// Event hash chain
// ---------------------------------------------------------------------------

// computeEventHash returns the SHA-256 hex digest of the canonical event.
// All fields except Hash are included; PrevHash IS included to link the chain.
func computeEventHash(e Event) string {
	canonical := struct {
		ID        string                 `json:"id"`
		Timestamp string                 `json:"timestamp"`
		SessionID string                 `json:"session_id"`
		Source    string                 `json:"source"`
		Type      string                 `json:"type"`
		Severity  string                 `json:"severity"`
		Actor     string                 `json:"actor,omitempty"`
		Data      map[string]interface{} `json:"data,omitempty"`
		PrevHash  string                 `json:"prev_hash,omitempty"`
	}{
		ID:        e.ID,
		Timestamp: e.Timestamp,
		SessionID: e.SessionID,
		Source:    e.Source,
		Type:      e.Type,
		Severity:  e.Severity,
		Actor:     e.Actor,
		Data:      e.Data,
		PrevHash:  e.PrevHash,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// verifyEventChain checks the integrity of an ordered event sequence.
func verifyEventChain(events []Event) error {
	for i, e := range events {
		// Verify prev_hash linkage.
		if i == 0 {
			if e.PrevHash != "" {
				// First event may have a prev_hash from a prior session; skip linkage check.
			}
		} else {
			if e.PrevHash != events[i-1].Hash {
				return fmt.Errorf("chain broken at event %d (%s): prev_hash mismatch", i, e.ID)
			}
		}

		// Verify the event's own hash.
		expected := computeEventHash(e)
		if e.Hash != expected {
			return fmt.Errorf("hash mismatch at event %d (%s): expected %s, got %s", i, e.ID, expected, e.Hash)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Event store (JSONL file-backed, in-memory indexed)
// ---------------------------------------------------------------------------

// EventStore manages event persistence and querying.
type EventStore struct {
	mu        sync.RWMutex
	events    []Event
	sessions  map[string][]int // session_id -> event indices
	filePath  string
	file      *os.File
	lastHash  string
	retention RetentionConfig
}

// NewEventStore creates or opens an event store at the given data directory.
func NewEventStore(dataDir string, retention RetentionConfig) (*EventStore, error) {
	eventsDir := dataDir
	if err := os.MkdirAll(eventsDir, 0750); err != nil {
		return nil, fmt.Errorf("create events dir: %w", err)
	}

	filePath := eventsDir + "/events.jsonl"

	store := &EventStore{
		sessions:  make(map[string][]int),
		filePath:  filePath,
		retention: retention,
	}

	// Load existing events (corruption-tolerant: skip bad lines).
	if data, err := os.ReadFile(filePath); err == nil {
		for lineNum, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e Event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				log.Printf("warning: skipping corrupt event at line %d: %v", lineNum+1, err)
				continue
			}
			idx := len(store.events)
			store.events = append(store.events, e)
			store.sessions[e.SessionID] = append(store.sessions[e.SessionID], idx)
			store.lastHash = e.Hash
		}
	}

	// Open file for appending.
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open events file: %w", err)
	}
	store.file = f

	return store, nil
}

// Record adds an event to the store with ID, timestamp, and hash chain.
// Enforces retention limits (max_events_per_session, max_sessions).
func (s *EventStore) Record(e Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce retention: max events per session.
	if s.retention.MaxEventsPerSession > 0 {
		if len(s.sessions[e.SessionID]) >= s.retention.MaxEventsPerSession {
			return Event{}, fmt.Errorf("session %q at max events (%d)", e.SessionID, s.retention.MaxEventsPerSession)
		}
	}

	// Enforce retention: max sessions.
	if s.retention.MaxSessions > 0 && e.SessionID != "" {
		if _, exists := s.sessions[e.SessionID]; !exists {
			if len(s.sessions) >= s.retention.MaxSessions {
				return Event{}, fmt.Errorf("max sessions reached (%d)", s.retention.MaxSessions)
			}
		}
	}

	// Assign metadata.
	if e.ID == "" {
		e.ID = generateID()
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Severity == "" {
		e.Severity = "info"
	}

	// Chain linkage.
	e.PrevHash = s.lastHash
	e.Hash = computeEventHash(e)

	// Persist to file.
	data, err := json.Marshal(e)
	if err != nil {
		return e, fmt.Errorf("marshal event: %w", err)
	}
	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return e, fmt.Errorf("write event: %w", err)
	}
	// fsync to ensure durability.
	if err := s.file.Sync(); err != nil {
		return e, fmt.Errorf("sync event file: %w", err)
	}

	// Update in-memory index.
	idx := len(s.events)
	s.events = append(s.events, e)
	s.sessions[e.SessionID] = append(s.sessions[e.SessionID], idx)
	s.lastHash = e.Hash

	return e, nil
}

// Query returns events matching the filter criteria.
// Time filtering uses parsed timestamps for correctness across formats.
func (s *EventStore) Query(filter EventFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Event

	// Parse filter timestamps once (outside the loop).
	var afterTime, beforeTime time.Time
	var hasAfter, hasBefore bool
	if filter.After != "" {
		if t, ok := parseTimestamp(filter.After); ok {
			afterTime = t
			hasAfter = true
		}
	}
	if filter.Before != "" {
		if t, ok := parseTimestamp(filter.Before); ok {
			beforeTime = t
			hasBefore = true
		}
	}

	// If filtering by session, use the index.
	var candidates []Event
	if filter.SessionID != "" {
		indices, ok := s.sessions[filter.SessionID]
		if !ok {
			return nil
		}
		for _, idx := range indices {
			candidates = append(candidates, s.events[idx])
		}
	} else {
		candidates = s.events
	}

	for _, e := range candidates {
		if filter.Source != "" && e.Source != filter.Source {
			continue
		}
		if filter.Type != "" && e.Type != filter.Type {
			continue
		}
		if filter.Severity != "" && e.Severity != filter.Severity {
			continue
		}
		if hasAfter {
			if et, ok := parseTimestamp(e.Timestamp); ok {
				if et.Before(afterTime) {
					continue
				}
			}
		}
		if hasBefore {
			if et, ok := parseTimestamp(e.Timestamp); ok {
				if et.After(beforeTime) {
					continue
				}
			}
		}
		results = append(results, e)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results
}

// Sessions returns a summary of all recorded sessions.
func (s *EventStore) Sessions() []SessionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var summaries []SessionSummary
	for sid, indices := range s.sessions {
		if len(indices) == 0 {
			continue
		}

		sourceSet := make(map[string]bool)
		first := s.events[indices[0]].Timestamp
		last := s.events[indices[len(indices)-1]].Timestamp

		for _, idx := range indices {
			sourceSet[s.events[idx].Source] = true
		}

		var sources []string
		for src := range sourceSet {
			sources = append(sources, src)
		}
		sort.Strings(sources)

		summaries = append(summaries, SessionSummary{
			SessionID:  sid,
			EventCount: len(indices),
			FirstEvent: first,
			LastEvent:  last,
			Sources:    sources,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].LastEvent > summaries[j].LastEvent
	})
	return summaries
}

// EventCount returns the total number of stored events.
func (s *EventStore) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Close closes the event store file.
func (s *EventStore) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

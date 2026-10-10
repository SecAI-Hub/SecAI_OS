package main

import (
	"strings"
	"sync"
	"time"
)

// TaintEntry records the origin of a taint label.
type TaintEntry struct {
	Label     string    `json:"label"`
	Source    string    `json:"source"` // e.g. "server/tool"
	AppliedAt time.Time `json:"applied_at"`
}

// TaintState tracks taint labels per session.
type TaintState struct {
	mu          sync.Mutex
	sessions    map[string][]TaintEntry
	lastSeen    map[string]time.Time
	lastPrune   time.Time
	maxSessions int
	ttl         time.Duration
	unavailable bool
}

// NewTaintState creates an empty taint tracker.
func NewTaintState() *TaintState {
	return &TaintState{
		sessions:    make(map[string][]TaintEntry),
		lastSeen:    make(map[string]time.Time),
		maxSessions: 10_000,
		ttl:         24 * time.Hour,
	}
}

// Add applies a taint label to a session.
func (ts *TaintState) Add(sessionID, label, source string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := time.Now()
	ts.pruneLocked(now)
	if _, exists := ts.sessions[sessionID]; !exists && len(ts.sessions) >= ts.maxSessions {
		ts.unavailable = true
		return false
	}
	ts.lastSeen[sessionID] = now

	// Don't add duplicate labels
	for _, e := range ts.sessions[sessionID] {
		if e.Label == label {
			return true
		}
	}
	if len(ts.sessions[sessionID]) >= 128 {
		ts.unavailable = true
		return false
	}

	ts.sessions[sessionID] = append(ts.sessions[sessionID], TaintEntry{
		Label:     label,
		Source:    source,
		AppliedAt: now,
	})
	return true
}

const legacyTaintContext = "principal:legacy-unattributed"

func principalTaintContext(identity string) string { return "principal:" + identity }

func (ts *TaintState) Available() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return !ts.unavailable
}

// Labels returns the active taint label names for a session.
func (ts *TaintState) Labels(sessionID string) []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := time.Now()
	ts.expireSessionLocked(sessionID, now)
	if _, ok := ts.sessions[sessionID]; ok {
		ts.lastSeen[sessionID] = now
	}

	entries := ts.sessions[sessionID]
	if len(entries) == 0 {
		return nil
	}

	labels := make([]string, len(entries))
	for i, e := range entries {
		labels[i] = e.Label
	}
	return labels
}

// Entries returns all taint entries for a session.
func (ts *TaintState) Entries(sessionID string) []TaintEntry {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := time.Now()
	ts.expireSessionLocked(sessionID, now)
	if _, ok := ts.sessions[sessionID]; ok {
		ts.lastSeen[sessionID] = now
	}

	entries := ts.sessions[sessionID]
	out := make([]TaintEntry, len(entries))
	copy(out, entries)
	return out
}

// Clear removes all taint for a session.
func (ts *TaintState) Clear(sessionID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.sessions, sessionID)
	delete(ts.lastSeen, sessionID)
}

// HasTaint checks if a session has a specific taint label.
func (ts *TaintState) HasTaint(sessionID, label string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := time.Now()
	ts.expireSessionLocked(sessionID, now)
	if _, ok := ts.sessions[sessionID]; ok {
		ts.lastSeen[sessionID] = now
	}

	for _, e := range ts.sessions[sessionID] {
		if e.Label == label {
			return true
		}
	}
	return false
}

func (ts *TaintState) expireSessionLocked(sessionID string, now time.Time) {
	if strings.HasPrefix(sessionID, "principal:") {
		return
	}
	if seen, ok := ts.lastSeen[sessionID]; ok && now.Sub(seen) > ts.ttl {
		delete(ts.sessions, sessionID)
		delete(ts.lastSeen, sessionID)
	}
}

func (ts *TaintState) pruneLocked(now time.Time) {
	if !ts.lastPrune.IsZero() && now.Sub(ts.lastPrune) < time.Minute {
		return
	}
	for sessionID, seen := range ts.lastSeen {
		if strings.HasPrefix(sessionID, "principal:") {
			continue
		}
		if now.Sub(seen) > ts.ttl {
			delete(ts.sessions, sessionID)
			delete(ts.lastSeen, sessionID)
		}
	}
	ts.lastPrune = now
}

func (ts *TaintState) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for sessionID, seen := range ts.lastSeen {
		if oldestID == "" || seen.Before(oldest) {
			oldestID = sessionID
			oldest = seen
		}
	}
	if oldestID != "" {
		delete(ts.sessions, oldestID)
		delete(ts.lastSeen, oldestID)
	}
}

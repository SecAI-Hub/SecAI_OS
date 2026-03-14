package main

import (
	"sync"
	"time"
)

// TaintEntry records the origin of a taint label.
type TaintEntry struct {
	Label     string    `json:"label"`
	Source    string    `json:"source"`    // e.g. "server/tool"
	AppliedAt time.Time `json:"applied_at"`
}

// TaintState tracks taint labels per session.
type TaintState struct {
	mu       sync.Mutex
	sessions map[string][]TaintEntry
}

// NewTaintState creates an empty taint tracker.
func NewTaintState() *TaintState {
	return &TaintState{
		sessions: make(map[string][]TaintEntry),
	}
}

// Add applies a taint label to a session.
func (ts *TaintState) Add(sessionID, label, source string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Don't add duplicate labels
	for _, e := range ts.sessions[sessionID] {
		if e.Label == label {
			return
		}
	}

	ts.sessions[sessionID] = append(ts.sessions[sessionID], TaintEntry{
		Label:     label,
		Source:    source,
		AppliedAt: time.Now(),
	})
}

// Labels returns the active taint label names for a session.
func (ts *TaintState) Labels(sessionID string) []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

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
}

// HasTaint checks if a session has a specific taint label.
func (ts *TaintState) HasTaint(sessionID, label string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, e := range ts.sessions[sessionID] {
		if e.Label == label {
			return true
		}
	}
	return false
}

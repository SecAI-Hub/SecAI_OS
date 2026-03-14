package main

import (
	"sync"
	"time"
)

// Severity thresholds for composite anomaly scores.
const (
	ThresholdNormal   = 0.3
	ThresholdWarning  = 0.7
	ThresholdCritical = 0.9
)

// Verdict is the overall integrity assessment.
type Verdict string

const (
	VerdictHealthy  Verdict = "healthy"
	VerdictWarning  Verdict = "warning"
	VerdictCritical Verdict = "critical"
	VerdictUnknown  Verdict = "unknown"
)

// ScoreEntry records a single scoring event.
type ScoreEntry struct {
	Timestamp      time.Time              `json:"timestamp"`
	CompositeScore float64                `json:"composite_score"`
	Verdict        Verdict                `json:"verdict"`
	ProbeScores    map[string]float64     `json:"probe_scores"`
	ProbeStatuses  map[string]ProbeStatus `json:"probe_statuses"`
}

// ScoringEngine computes composite anomaly scores and tracks history.
type ScoringEngine struct {
	mu       sync.Mutex
	history  []ScoreEntry
	maxHist  int
	weights  map[ProbeType]float64
}

// NewScoringEngine creates a scoring engine with configured weights and history size.
func NewScoringEngine(weights map[ProbeType]float64, maxHistory int) *ScoringEngine {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	if weights == nil {
		weights = map[ProbeType]float64{
			ProbeTensorHash:        1.0,
			ProbeSentinelInfer:     1.0,
			ProbeReferenceDrift:    0.8,
			ProbeECCStatus:         0.6,
			ProbeDriverFingerprint: 1.0,
			ProbeDeviceAllowlist:   0.8,
		}
	}
	return &ScoringEngine{
		weights: weights,
		maxHist: maxHistory,
	}
}

// Score computes the composite anomaly score from probe results and records it.
func (s *ScoringEngine) Score(results []ProbeResult) ScoreEntry {
	entry := ScoreEntry{
		Timestamp:     time.Now(),
		ProbeScores:   make(map[string]float64),
		ProbeStatuses: make(map[string]ProbeStatus),
	}

	var weightedSum float64
	var totalWeight float64

	for _, r := range results {
		if r.Status == StatusSkip {
			continue
		}
		entry.ProbeScores[r.Probe] = r.Score
		entry.ProbeStatuses[r.Probe] = r.Status

		w := s.weights[r.Type]
		if w == 0 {
			w = 1.0
		}
		weightedSum += r.Score * w
		totalWeight += w
	}

	if totalWeight > 0 {
		entry.CompositeScore = weightedSum / totalWeight
	}

	entry.Verdict = classifyVerdict(entry.CompositeScore, results)

	s.mu.Lock()
	s.history = append(s.history, entry)
	if len(s.history) > s.maxHist {
		s.history = s.history[len(s.history)-s.maxHist:]
	}
	s.mu.Unlock()

	return entry
}

// classifyVerdict determines the verdict from score and probe statuses.
func classifyVerdict(composite float64, results []ProbeResult) Verdict {
	// Any fail probe -> critical regardless of score
	for _, r := range results {
		if r.Status == StatusFail {
			return VerdictCritical
		}
	}

	switch {
	case composite >= ThresholdCritical:
		return VerdictCritical
	case composite >= ThresholdNormal:
		return VerdictWarning
	default:
		return VerdictHealthy
	}
}

// History returns a copy of the score history.
func (s *ScoringEngine) History() []ScoreEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ScoreEntry, len(s.history))
	copy(out, s.history)
	return out
}

// Latest returns the most recent score entry, or nil if none.
func (s *ScoringEngine) Latest() *ScoreEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.history) == 0 {
		return nil
	}
	e := s.history[len(s.history)-1]
	return &e
}

// Trend computes the score trend over the last N entries.
// Returns positive values for increasing scores (worsening), negative for improving.
func (s *ScoringEngine) Trend(window int) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.history) < 2 {
		return 0.0
	}

	if window <= 0 || window > len(s.history) {
		window = len(s.history)
	}

	start := len(s.history) - window
	entries := s.history[start:]

	if len(entries) < 2 {
		return 0.0
	}

	// Simple linear trend: difference between avg of second half and first half
	mid := len(entries) / 2
	var firstHalf, secondHalf float64
	for i, e := range entries {
		if i < mid {
			firstHalf += e.CompositeScore
		} else {
			secondHalf += e.CompositeScore
		}
	}
	firstHalf /= float64(mid)
	secondHalf /= float64(len(entries) - mid)

	return secondHalf - firstHalf
}

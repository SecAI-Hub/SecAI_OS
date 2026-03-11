package main

import "time"

// ---------------------------------------------------------------------------
// Comparison / scoring engine
// ---------------------------------------------------------------------------

// AttestationResult aggregates all collector results into a single verdict.
type AttestationResult struct {
	Verdict    string            `json:"verdict"` // pass, drift, fail
	Score      float64           `json:"score"`   // 0.0 (total failure) to 1.0 (all pass)
	Collectors []CollectorResult `json:"collectors"`
	Timestamp  string            `json:"timestamp"`
}

// criticalCollectors are collectors whose errors are treated as hard failures
// rather than soft drift, because they guard integrity-sensitive state.
var criticalCollectors = map[string]bool{
	"model":  true,
	"policy": true,
}

// compare evaluates all collector results and produces a scored attestation.
//
// Scoring:
//   - Each collector that ran (not skipped) contributes equally.
//   - "pass" = 1.0, "drift" = 0.5, "error" = 0.0, "fail" findings downgrade.
//   - Overall verdict: all pass → "pass", any drift → "drift", any fail → "fail".
//   - Critical collectors (model, policy): errors escalate to "fail" instead of "drift".
func compare(results []CollectorResult) AttestationResult {
	att := AttestationResult{
		Collectors: results,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	var scored int
	var total float64

	worstStatus := "pass"

	for _, r := range results {
		if r.Status == "skipped" {
			continue
		}
		scored++

		switch r.Status {
		case "pass":
			total += 1.0
		case "drift":
			total += 0.5
			if worstStatus == "pass" {
				worstStatus = "drift"
			}
		case "error":
			// Critical collectors: error → hard fail
			if criticalCollectors[r.Name] {
				worstStatus = "fail"
			} else if worstStatus != "fail" {
				worstStatus = "drift"
			}
		}

		// Check individual findings for hard failures.
		for _, f := range r.Findings {
			if f.Status == "fail" {
				worstStatus = "fail"
			}
		}
	}

	if scored > 0 {
		att.Score = total / float64(scored)
	} else {
		att.Score = 1.0 // nothing to check → clean
	}

	att.Verdict = worstStatus
	return att
}

package main

import (
	"fmt"
	"time"
)

// Recovery indexes are independent of the display-history ring. Receipts live
// for at most ten minutes and can only be issued within one minute of append.
// Taint is monotonic for a credential identity, including failed or unreported
// executions; changing a connection or restarting never declassifies data.
func (al *AuditLog) checkIndexCapacity(entry AuditEntry) error {
	if entry.Decision == nil || entry.Event != "evaluate" {
		return nil
	}
	now := time.Now()
	for sequence, evidence := range al.decisions {
		if !now.Before(evidence.expires) {
			delete(al.decisions, sequence)
		}
	}
	stamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid decision timestamp")
	}
	if stamp.After(now.Add(time.Minute)) {
		return fmt.Errorf("decision timestamp is in the future")
	}
	if now.Before(stamp.Add(11*time.Minute)) && len(al.decisions) >= 20_000 {
		return fmt.Errorf("pending decision index is at capacity")
	}
	if entry.Decision.Action != "allow" || len(entry.Decision.TaintApplied) == 0 {
		return nil
	}
	scope := principalTaintContext(entry.Identity)
	if entry.Identity == "" {
		scope = legacyTaintContext
	}
	labels := al.taints[scope]
	if labels == nil && len(al.taints) >= 10_000 {
		return fmt.Errorf("taint identity index is at capacity")
	}
	count := len(labels)
	for _, label := range entry.Decision.TaintApplied {
		if !labels[label] {
			count++
		}
	}
	if count > 128 {
		return fmt.Errorf("taint label index is at capacity")
	}
	return nil
}

func (al *AuditLog) indexEntry(entry AuditEntry) error {
	if err := al.checkIndexCapacity(entry); err != nil {
		return err
	}
	if entry.Decision == nil || entry.Event != "evaluate" {
		return nil
	}
	stamp, _ := time.Parse(time.RFC3339Nano, entry.Timestamp)
	expires := stamp.Add(11 * time.Minute)
	if time.Now().Before(expires) {
		al.decisions[entry.Sequence] = decisionEvidence{entry.Hash, expires}
	}
	if entry.Decision.Action != "allow" || len(entry.Decision.TaintApplied) == 0 {
		return nil
	}
	scope := principalTaintContext(entry.Identity)
	if entry.Identity == "" {
		scope = legacyTaintContext
	}
	if al.taints[scope] == nil {
		al.taints[scope] = make(map[string]bool)
	}
	for _, label := range entry.Decision.TaintApplied {
		al.taints[scope][label] = true
	}
	return nil
}

func (al *AuditLog) RestoreTaint(state *TaintState) error {
	al.mu.Lock()
	defer al.mu.Unlock()
	for scope, labels := range al.taints {
		for label := range labels {
			if !state.Add(scope, label, "durable-evaluation-intent") {
				return fmt.Errorf("taint recovery capacity exhausted")
			}
		}
	}
	return nil
}

func reserveDecisionTaint(state *TaintState, identity string, decision Decision) bool {
	if decision.Action != "allow" {
		return true
	}
	for _, label := range decision.TaintApplied {
		if !state.Add(principalTaintContext(identity), label, decision.Server+"/"+decision.Tool) {
			return false
		}
	}
	return true
}

func (al *AuditLog) Ready() bool {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.writeErr == nil && al.validateLiveFileLocked(0) == nil
}

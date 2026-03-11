package main

import (
	"fmt"
	"sort"
	"strings"
)

// DiffResult describes differences between two BOMs.
type DiffResult struct {
	Summary       string         `json:"summary"`
	TrustRelevant bool           `json:"trust_relevant"`
	Changes       []DiffChange   `json:"changes"`
}

// DiffChange is a single difference between two BOMs.
type DiffChange struct {
	Category string `json:"category"` // component, hash, license, trust, quantization, evidence, metadata
	Severity string `json:"severity"` // info, warning, critical
	Field    string `json:"field"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	Message  string `json:"message"`
}

// DiffBOMs compares two model BOMs and returns trust-relevant differences.
func DiffBOMs(old, new *ModelBOM) DiffResult {
	result := DiffResult{}

	// Index components by bom-ref or name
	oldComps := indexComponents(old.Components)
	newComps := indexComponents(new.Components)

	// Find removed components
	for ref, comp := range oldComps {
		if _, exists := newComps[ref]; !exists {
			result.Changes = append(result.Changes, DiffChange{
				Category: "component",
				Severity: "warning",
				Field:    "component",
				OldValue: comp.Name,
				Message:  fmt.Sprintf("component removed: %s", comp.Name),
			})
		}
	}

	// Find added components
	for ref, comp := range newComps {
		if _, exists := oldComps[ref]; !exists {
			result.Changes = append(result.Changes, DiffChange{
				Category: "component",
				Severity: "info",
				Field:    "component",
				NewValue: comp.Name,
				Message:  fmt.Sprintf("component added: %s", comp.Name),
			})
		}
	}

	// Compare matching components
	for ref, oldComp := range oldComps {
		newComp, exists := newComps[ref]
		if !exists {
			continue
		}
		changes := diffComponents(oldComp, newComp)
		result.Changes = append(result.Changes, changes...)
	}

	// Check metadata changes
	if old.Version != new.Version {
		result.Changes = append(result.Changes, DiffChange{
			Category: "metadata",
			Severity: "info",
			Field:    "bom_version",
			OldValue: fmt.Sprintf("%d", old.Version),
			NewValue: fmt.Sprintf("%d", new.Version),
			Message:  "BOM version changed",
		})
	}

	// Determine trust relevance
	for _, c := range result.Changes {
		if c.Severity == "critical" || c.Category == "hash" || c.Category == "trust" {
			result.TrustRelevant = true
			break
		}
	}

	result.Summary = buildDiffSummary(result.Changes)
	return result
}

// diffComponents compares two components field by field.
func diffComponents(old, new Component) []DiffChange {
	var changes []DiffChange
	prefix := old.Name

	// Hash comparison (trust-critical)
	oldHash := extractHash(old.Hashes)
	newHash := extractHash(new.Hashes)
	if oldHash != "" && newHash != "" && oldHash != newHash {
		changes = append(changes, DiffChange{
			Category: "hash",
			Severity: "critical",
			Field:    prefix + ".hash",
			OldValue: oldHash[:16] + "...",
			NewValue: newHash[:16] + "...",
			Message:  fmt.Sprintf("%s: content hash changed (model binary differs)", prefix),
		})
	}

	// License changes
	oldLic := extractLicense(old.Licenses)
	newLic := extractLicense(new.Licenses)
	if oldLic != newLic {
		sev := "warning"
		if oldLic != "" && newLic != "" {
			sev = "critical"
		}
		changes = append(changes, DiffChange{
			Category: "license",
			Severity: sev,
			Field:    prefix + ".license",
			OldValue: oldLic,
			NewValue: newLic,
			Message:  fmt.Sprintf("%s: license changed", prefix),
		})
	}

	// Model card changes
	if old.ModelCard != nil && new.ModelCard != nil {
		changes = append(changes, diffModelCards(prefix, old.ModelCard, new.ModelCard)...)
	} else if old.ModelCard == nil && new.ModelCard != nil {
		changes = append(changes, DiffChange{
			Category: "metadata",
			Severity: "info",
			Field:    prefix + ".model_card",
			Message:  fmt.Sprintf("%s: model card added", prefix),
		})
	}

	// Evidence changes
	oldEvCount := len(old.Evidence)
	newEvCount := len(new.Evidence)
	if oldEvCount != newEvCount {
		changes = append(changes, DiffChange{
			Category: "evidence",
			Severity: "info",
			Field:    prefix + ".evidence",
			OldValue: fmt.Sprintf("%d items", oldEvCount),
			NewValue: fmt.Sprintf("%d items", newEvCount),
			Message:  fmt.Sprintf("%s: evidence count changed", prefix),
		})
	}

	return changes
}

// diffModelCards compares model card fields.
func diffModelCards(prefix string, old, new *ModelCard) []DiffChange {
	var changes []DiffChange

	if old.BaseModel != new.BaseModel {
		changes = append(changes, DiffChange{
			Category: "trust",
			Severity: "critical",
			Field:    prefix + ".base_model",
			OldValue: old.BaseModel,
			NewValue: new.BaseModel,
			Message:  fmt.Sprintf("%s: base model changed", prefix),
		})
	}

	if old.PromotionStatus != new.PromotionStatus {
		changes = append(changes, DiffChange{
			Category: "trust",
			Severity: "warning",
			Field:    prefix + ".promotion_status",
			OldValue: old.PromotionStatus,
			NewValue: new.PromotionStatus,
			Message:  fmt.Sprintf("%s: promotion status changed", prefix),
		})
	}

	if old.Quantization != nil && new.Quantization != nil {
		if old.Quantization.Method != new.Quantization.Method {
			changes = append(changes, DiffChange{
				Category: "quantization",
				Severity: "warning",
				Field:    prefix + ".quantization",
				OldValue: old.Quantization.Method,
				NewValue: new.Quantization.Method,
				Message:  fmt.Sprintf("%s: quantization method changed", prefix),
			})
		}
	}

	oldLabels := strings.Join(sorted(old.TrustLabels), ",")
	newLabels := strings.Join(sorted(new.TrustLabels), ",")
	if oldLabels != newLabels {
		changes = append(changes, DiffChange{
			Category: "trust",
			Severity: "warning",
			Field:    prefix + ".trust_labels",
			OldValue: oldLabels,
			NewValue: newLabels,
			Message:  fmt.Sprintf("%s: trust labels changed", prefix),
		})
	}

	return changes
}

// ---------- helpers ----------

func indexComponents(comps []Component) map[string]Component {
	idx := make(map[string]Component)
	for _, c := range comps {
		key := c.BOMRef
		if key == "" {
			key = c.Name
		}
		idx[key] = c
	}
	return idx
}

func extractHash(hashes []Hash) string {
	for _, h := range hashes {
		if h.Algorithm == "SHA-256" {
			return h.Content
		}
	}
	if len(hashes) > 0 {
		return hashes[0].Content
	}
	return ""
}

func extractLicense(lics []License) string {
	if len(lics) == 0 {
		return ""
	}
	if lics[0].ID != "" {
		return lics[0].ID
	}
	return lics[0].Name
}

func sorted(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

func buildDiffSummary(changes []DiffChange) string {
	if len(changes) == 0 {
		return "no changes detected"
	}

	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Severity]++
	}

	parts := []string{fmt.Sprintf("%d changes", len(changes))}
	if n := counts["critical"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", n))
	}
	if n := counts["warning"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d warning", n))
	}
	return strings.Join(parts, ", ")
}

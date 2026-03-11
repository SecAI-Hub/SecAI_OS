package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------- metadata validation ----------

// ValidationIssue describes a problem found during validation.
type ValidationIssue struct {
	Field    string `json:"field"`
	Severity string `json:"severity"` // error, warning
	Message  string `json:"message"`
}

// ValidateMetadata checks user-supplied metadata for correctness.
func ValidateMetadata(meta *ModelMetadata) []ValidationIssue {
	if meta == nil {
		return nil
	}

	var issues []ValidationIssue

	if meta.SourceURL != "" {
		if !isValidURL(meta.SourceURL) {
			issues = append(issues, ValidationIssue{
				Field: "source_url", Severity: "error",
				Message: fmt.Sprintf("invalid URL: %q", meta.SourceURL),
			})
		}
	}

	if meta.License != "" {
		if !isKnownSPDX(meta.License) {
			issues = append(issues, ValidationIssue{
				Field: "license", Severity: "warning",
				Message: fmt.Sprintf("license %q is not a recognized SPDX identifier", meta.License),
			})
		}
	}

	if meta.PromotionStatus != "" {
		if !isValidPromotionStatus(meta.PromotionStatus) {
			issues = append(issues, ValidationIssue{
				Field: "promotion_status", Severity: "error",
				Message: fmt.Sprintf("invalid promotion status %q; expected one of: quarantine, pending, approved, rejected, revoked", meta.PromotionStatus),
			})
		}
	}

	if meta.QuantizedAt != "" {
		if !isValidRFC3339(meta.QuantizedAt) {
			issues = append(issues, ValidationIssue{
				Field: "quantized_at", Severity: "error",
				Message: fmt.Sprintf("invalid RFC3339 timestamp: %q", meta.QuantizedAt),
			})
		}
	}

	// Deduplicate trust labels
	if len(meta.TrustLabels) > 0 {
		seen := map[string]bool{}
		var deduped []string
		for _, l := range meta.TrustLabels {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			if seen[l] {
				issues = append(issues, ValidationIssue{
					Field: "trust_labels", Severity: "warning",
					Message: fmt.Sprintf("duplicate trust label: %q", l),
				})
				continue
			}
			seen[l] = true
			deduped = append(deduped, l)
		}
		meta.TrustLabels = deduped
	}

	return issues
}

// ---------- BOM validation ----------

// ValidateBOM checks a generated BOM for structural issues.
func ValidateBOM(bom *ModelBOM) []ValidationIssue {
	if bom == nil {
		return []ValidationIssue{{Field: "bom", Severity: "error", Message: "BOM is nil"}}
	}

	var issues []ValidationIssue

	if bom.BOMFormat != "CycloneDX" {
		issues = append(issues, ValidationIssue{
			Field: "bomFormat", Severity: "error",
			Message: fmt.Sprintf("expected CycloneDX, got %q", bom.BOMFormat),
		})
	}

	if bom.SerialNumber == "" {
		issues = append(issues, ValidationIssue{
			Field: "serialNumber", Severity: "error",
			Message: "missing serial number",
		})
	}

	// Unique bom-ref validation
	refs := map[string]int{}
	for _, comp := range bom.Components {
		if comp.BOMRef != "" {
			refs[comp.BOMRef]++
		}
	}
	for ref, count := range refs {
		if count > 1 {
			issues = append(issues, ValidationIssue{
				Field: "bom-ref", Severity: "error",
				Message: fmt.Sprintf("duplicate bom-ref: %q (appears %d times)", ref, count),
			})
		}
	}

	// Component-level validation
	for _, comp := range bom.Components {
		if comp.Name == "" {
			issues = append(issues, ValidationIssue{
				Field: "component.name", Severity: "error",
				Message: "component has empty name",
			})
		}

		for _, lic := range comp.Licenses {
			if lic.ID != "" && !isKnownSPDX(lic.ID) {
				issues = append(issues, ValidationIssue{
					Field: "component.license", Severity: "warning",
					Message: fmt.Sprintf("license ID %q is not a recognized SPDX identifier", lic.ID),
				})
			}
		}

		for _, ref := range comp.ExternalRefs {
			if ref.URL != "" && !isValidURL(ref.URL) {
				issues = append(issues, ValidationIssue{
					Field: "component.externalReferences.url", Severity: "warning",
					Message: fmt.Sprintf("invalid URL in external reference: %q", ref.URL),
				})
			}
		}

		for _, ev := range comp.Evidence {
			issues = append(issues, validateEvidenceItem(ev)...)
		}
	}

	return issues
}

// validateEvidenceItem checks a single evidence item.
func validateEvidenceItem(ev EvidenceItem) []ValidationIssue {
	var issues []ValidationIssue

	if ev.Type == "" {
		issues = append(issues, ValidationIssue{
			Field: "evidence.type", Severity: "error",
			Message: "evidence item has empty type",
		})
	} else {
		validTypes := map[string]bool{"scan": true, "test": true, "attestation": true, "review": true}
		if !validTypes[ev.Type] {
			issues = append(issues, ValidationIssue{
				Field: "evidence.type", Severity: "warning",
				Message: fmt.Sprintf("unknown evidence type: %q", ev.Type),
			})
		}
	}

	if ev.Result != "" {
		validResults := map[string]bool{"pass": true, "fail": true, "warning": true, "info": true}
		if !validResults[ev.Result] {
			issues = append(issues, ValidationIssue{
				Field: "evidence.result", Severity: "error",
				Message: fmt.Sprintf("invalid evidence result: %q; expected pass, fail, warning, or info", ev.Result),
			})
		}
	}

	if ev.Timestamp != "" && !isValidRFC3339(ev.Timestamp) {
		issues = append(issues, ValidationIssue{
			Field: "evidence.timestamp", Severity: "warning",
			Message: fmt.Sprintf("evidence timestamp is not valid RFC3339: %q", ev.Timestamp),
		})
	}

	return issues
}

// ---------- helpers ----------

func isValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isValidRFC3339(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func isValidPromotionStatus(s string) bool {
	valid := map[string]bool{
		"quarantine": true,
		"pending":    true,
		"approved":   true,
		"rejected":   true,
		"revoked":    true,
	}
	return valid[strings.ToLower(s)]
}

// Common SPDX license identifiers (not exhaustive, covers the most common ones).
var knownSPDX = map[string]bool{
	"Apache-2.0": true, "MIT": true, "GPL-2.0-only": true, "GPL-2.0-or-later": true,
	"GPL-3.0-only": true, "GPL-3.0-or-later": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"ISC": true, "MPL-2.0": true, "LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
	"LGPL-3.0-only": true, "LGPL-3.0-or-later": true, "AGPL-3.0-only": true,
	"Unlicense": true, "CC0-1.0": true, "CC-BY-4.0": true, "CC-BY-SA-4.0": true,
	"CC-BY-NC-4.0": true, "CC-BY-NC-SA-4.0": true, "WTFPL": true, "Zlib": true,
	"0BSD": true, "ECL-2.0": true, "AFL-3.0": true, "Artistic-2.0": true,
	"BSL-1.0": true, "PostgreSQL": true, "OFL-1.1": true, "EUPL-1.2": true,
	// Llama-specific community licenses
	"Llama-2": true, "Llama-3": true, "Llama-3.1": true, "Gemma": true,
}

var reSPDXLike = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]+$`)

func isKnownSPDX(s string) bool {
	if knownSPDX[s] {
		return true
	}
	// Accept anything that looks like a valid SPDX expression
	return reSPDXLike.MatchString(s)
}

// deduplicateStrings removes duplicates and sorts.
func deduplicateStrings(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

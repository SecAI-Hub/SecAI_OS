package main

import "fmt"

var (
	validSensitivities = map[string]bool{
		"public": true, "internal": true, "confidential": true, "restricted": true,
	}
	validTrustLevels = map[string]bool{
		"verified": true, "unverified": true, "untrusted": true,
	}
	validRequesterTypes = map[string]bool{
		"user": true, "tool": true, "system": true,
	}
	validSessionTrusts = map[string]bool{
		"high": true, "medium": true, "low": true,
	}
)

// validateIngestRequest checks structural validity before document ingestion.
func validateIngestRequest(req IngestRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.Content == "" {
		return fmt.Errorf("content is required")
	}
	if req.SensitivityLabel != "" && !validSensitivities[req.SensitivityLabel] {
		return fmt.Errorf("invalid sensitivity_label: %s (must be public, internal, confidential, or restricted)", req.SensitivityLabel)
	}
	if req.TrustLevel != "" && !validTrustLevels[req.TrustLevel] {
		return fmt.Errorf("invalid trust_level: %s (must be verified, unverified, or untrusted)", req.TrustLevel)
	}
	return nil
}

// validateRetrievalRequest checks structural validity of a retrieval request.
func validateRetrievalRequest(req RetrievalRequest) error {
	if req.RequesterType != "" && !validRequesterTypes[req.RequesterType] {
		return fmt.Errorf("invalid requester_type: %s (must be user, tool, or system)", req.RequesterType)
	}
	if req.SessionTrust != "" && !validSessionTrusts[req.SessionTrust] {
		return fmt.Errorf("invalid session_trust: %s (must be high, medium, or low)", req.SessionTrust)
	}
	return nil
}

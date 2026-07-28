package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// =========================================================================
// Recovery ceremony — explicit acknowledgment + re-attestation
// =========================================================================

const (
	recoveryStateVersion     = 1
	maxRecoveryStateFileSize = 4 << 20
	maxAttestationBodySize   = 1 << 20
)

// RecoveryAttestationEvidence is the security-relevant subset of a freshly
// generated runtime-attestor bundle. The incident recorder fetches this
// evidence directly from the authenticated loopback service; callers cannot
// submit their own bundle.
type RecoveryAttestationEvidence struct {
	RequestedAt             string `json:"requested_at"`
	Timestamp               string `json:"timestamp"`
	State                   string `json:"state"`
	AssuranceMode           string `json:"assurance_mode"`
	EvidenceVerified        bool   `json:"evidence_verified"`
	SecureBootEnabled       bool   `json:"secure_boot_enabled"`
	TPMAvailable            bool   `json:"tpm_available"`
	TPMMeasurementsVerified bool   `json:"tpm_measurements_verified"`
	TPMQuoteVerified        bool   `json:"tpm_quote_verified"`
	DeploymentVerified      bool   `json:"deployment_verified"`
	ReleaseBaselineVerified bool   `json:"release_baseline_verified"`
	DeploymentDigest        string `json:"deployment_digest"`
	PolicyDigest            string `json:"policy_digest"`
	TPMAKPublicKeySHA256    string `json:"tpm_ak_public_key_sha256"`
	BundleHMAC              string `json:"bundle_hmac"`
	BundleHMACVerified      bool   `json:"bundle_hmac_verified"`
	RequestNonce            string `json:"request_nonce"`
	RecoveryBinding         string `json:"recovery_binding"`
}

// RecoveryRequirement defines what must happen before returning to trusted
// mode. ContainmentBinding binds the ceremony to the exact incident class,
// severity, actions, and per-action results. A changed containment transaction
// therefore invalidates previous acknowledgment and attestation evidence.
type RecoveryRequirement struct {
	IncidentID             string                       `json:"incident_id"`
	IncidentClass          IncidentClass                `json:"incident_class"`
	Severity               IncidentSeverity             `json:"severity"`
	RequiredAfter          string                       `json:"required_after"`
	ContainmentActions     []string                     `json:"containment_actions,omitempty"`
	ContainmentResults     []ContainmentResult          `json:"containment_results,omitempty"`
	ContainmentBinding     string                       `json:"containment_binding"`
	ContainmentLatchActive bool                         `json:"containment_latch_active"`
	RequireAck             bool                         `json:"require_ack"`
	RequireReattest        bool                         `json:"require_reattest"`
	AckedAt                string                       `json:"acked_at,omitempty"`
	AckedBy                string                       `json:"acked_by,omitempty"`
	ReAttestedAt           string                       `json:"re_attested_at,omitempty"`
	AttestationEvidence    *RecoveryAttestationEvidence `json:"attestation_evidence,omitempty"`
	RecoveryGateReleasedAt string                       `json:"recovery_gate_released_at,omitempty"`
	RecoveryComplete       bool                         `json:"recovery_complete"`
}

// RecoveryManager tracks recovery ceremonies for contained incidents.
type RecoveryManager struct {
	mu           sync.RWMutex
	path         string
	requirements map[string]*RecoveryRequirement // incident_id → requirement
}

func NewRecoveryManager() *RecoveryManager {
	return NewRecoveryManagerWithPath("")
}

func NewRecoveryManagerWithPath(path string) *RecoveryManager {
	return &RecoveryManager{
		path:         strings.TrimSpace(path),
		requirements: make(map[string]*RecoveryRequirement),
	}
}

// RequireRecovery creates a recovery requirement for an incident.
// This compatibility helper is used by unit tests and callers that do not have
// a complete Incident value. Production creation/reconciliation uses
// RequireRecoveryForIncident so containment actions and results are bound.
func (rm *RecoveryManager) RequireRecovery(incidentID string, severity IncidentSeverity, class IncidentClass) {
	inc := Incident{
		ID:        incidentID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Class:     class,
		Severity:  severity,
	}
	if err := rm.RequireRecoveryForIncident(inc); err != nil {
		log.Printf("recovery: cannot create requirement for %s: %v", incidentID, err)
	}
}

type containmentBindingPayload struct {
	IncidentID         string              `json:"incident_id"`
	IncidentClass      IncidentClass       `json:"incident_class"`
	Severity           IncidentSeverity    `json:"severity"`
	ContainmentActions []string            `json:"containment_actions"`
	ContainmentResults []ContainmentResult `json:"containment_results"`
}

func containmentBindingForIncident(inc Incident) (string, error) {
	payload := containmentBindingPayload{
		IncidentID:         inc.ID,
		IncidentClass:      inc.Class,
		Severity:           inc.Severity,
		ContainmentActions: append([]string(nil), inc.ContainmentActions...),
		ContainmentResults: append([]ContainmentResult(nil), inc.ContainmentResults...),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode containment binding: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func recoveryRequiredAfter(inc Incident) (time.Time, error) {
	requiredAfter, err := time.Parse(time.RFC3339Nano, inc.CreatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("incident %s has invalid created_at: %w", inc.ID, err)
	}
	for _, result := range inc.ContainmentResults {
		completedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
		if err != nil {
			return time.Time{}, fmt.Errorf(
				"incident %s has invalid containment completion time: %w", inc.ID, err,
			)
		}
		if completedAt.After(requiredAfter) {
			requiredAfter = completedAt
		}
	}
	return requiredAfter.UTC(), nil
}

func incidentRequiresRecovery(inc Incident) bool {
	return inc.Severity == SeverityCritical ||
		IsLatched(inc.Class) ||
		len(inc.ContainmentActions) > 0 ||
		len(inc.ContainmentResults) > 0 ||
		inc.State == StateContained ||
		inc.State == StateContainmentFailed
}

func (rm *RecoveryManager) ensureRequirementLocked(inc Incident) (bool, error) {
	if strings.TrimSpace(inc.ID) == "" {
		return false, fmt.Errorf("incident id is required")
	}
	binding, err := containmentBindingForIncident(inc)
	if err != nil {
		return false, err
	}
	requiredAfter, err := recoveryRequiredAfter(inc)
	if err != nil {
		return false, err
	}

	requireReattest := inc.Severity == SeverityCritical ||
		IsLatched(inc.Class) ||
		len(inc.ContainmentActions) > 0 ||
		len(inc.ContainmentResults) > 0
	latchBound := IsLatched(inc.Class) ||
		len(inc.ContainmentActions) > 0 ||
		len(inc.ContainmentResults) > 0

	existing, ok := rm.requirements[inc.ID]
	if ok && existing.ContainmentBinding == binding {
		changed := false
		if !existing.RequireAck {
			existing.RequireAck = true
			changed = true
		}
		if requireReattest && !existing.RequireReattest {
			existing.RequireReattest = true
			existing.ReAttestedAt = ""
			existing.AttestationEvidence = nil
			existing.RecoveryComplete = false
			existing.RecoveryGateReleasedAt = ""
			changed = true
		}
		if latchBound && existing.RecoveryComplete {
			// checkCompleteLocked below will release the logical gate again only
			// if the persisted evidence remains semantically valid.
			existing.ContainmentLatchActive = true
		}
		existing.IncidentClass = inc.Class
		existing.Severity = inc.Severity
		existing.RequiredAfter = requiredAfter.Format(time.RFC3339Nano)
		existing.ContainmentActions = append([]string(nil), inc.ContainmentActions...)
		existing.ContainmentResults = append([]ContainmentResult(nil), inc.ContainmentResults...)
		beforeComplete := existing.RecoveryComplete
		rm.checkCompleteLocked(existing)
		return changed || beforeComplete != existing.RecoveryComplete, nil
	}

	req := &RecoveryRequirement{
		IncidentID:             inc.ID,
		IncidentClass:          inc.Class,
		Severity:               inc.Severity,
		RequiredAfter:          requiredAfter.Format(time.RFC3339Nano),
		ContainmentActions:     append([]string(nil), inc.ContainmentActions...),
		ContainmentResults:     append([]ContainmentResult(nil), inc.ContainmentResults...),
		ContainmentBinding:     binding,
		ContainmentLatchActive: latchBound,
		RequireAck:             true,
		RequireReattest:        requireReattest,
	}
	rm.requirements[inc.ID] = req
	return true, nil
}

// RequireRecoveryForIncident creates or strengthens a durable ceremony bound
// to the current containment transaction.
func (rm *RecoveryManager) RequireRecoveryForIncident(inc Incident) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	previous := cloneRequirement(rm.requirements[inc.ID])
	changed, err := rm.ensureRequirementLocked(inc)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err := rm.persistLocked(); err != nil {
		if previous == nil {
			delete(rm.requirements, inc.ID)
		} else {
			rm.requirements[inc.ID] = previous
		}
		return err
	}
	req := rm.requirements[inc.ID]
	log.Printf(
		"recovery: ceremony required for incident %s (ack=%v reattest=%v binding=%s)",
		inc.ID, req.RequireAck, req.RequireReattest, req.ContainmentBinding,
	)
	return nil
}

// Acknowledge records an operator acknowledgment for an incident.
func (rm *RecoveryManager) Acknowledge(incidentID, operator string) (bool, string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	req, ok := rm.requirements[incidentID]
	if !ok {
		return false, "no recovery requirement for incident"
	}
	operator = strings.TrimSpace(operator)
	if operator == "" || len(operator) > 256 {
		return false, "a valid operator identity is required"
	}

	previous := cloneRequirement(req)
	req.AckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	req.AckedBy = operator
	rm.checkCompleteLocked(req)
	if err := rm.persistLocked(); err != nil {
		rm.requirements[incidentID] = previous
		return false, fmt.Sprintf("cannot persist recovery acknowledgment: %v", err)
	}
	return true, "acknowledged"
}

func validateRecoveryEvidence(req *RecoveryRequirement, evidence RecoveryAttestationEvidence) error {
	requestedAt, err := time.Parse(time.RFC3339Nano, evidence.RequestedAt)
	if err != nil {
		return fmt.Errorf("runtime attestation request time is invalid")
	}
	attestedAt, err := time.Parse(time.RFC3339Nano, evidence.Timestamp)
	if err != nil {
		return fmt.Errorf("runtime attestation timestamp is invalid")
	}
	requiredAfter, err := time.Parse(time.RFC3339Nano, req.RequiredAfter)
	if err != nil {
		return fmt.Errorf("recovery freshness boundary is invalid")
	}
	now := time.Now().UTC()
	if attestedAt.Before(requestedAt) {
		return fmt.Errorf("runtime attestation predates the refresh request")
	}
	if !attestedAt.After(requiredAfter) {
		return fmt.Errorf("runtime attestation is not newer than the containment transaction")
	}
	if attestedAt.After(now.Add(5 * time.Second)) {
		return fmt.Errorf("runtime attestation timestamp is in the future")
	}
	if evidence.State != "attested" ||
		evidence.AssuranceMode != "hardware" ||
		!evidence.EvidenceVerified ||
		!evidence.SecureBootEnabled ||
		!evidence.TPMAvailable ||
		!evidence.TPMMeasurementsVerified ||
		!evidence.TPMQuoteVerified ||
		!evidence.DeploymentVerified ||
		!evidence.ReleaseBaselineVerified ||
		!evidence.BundleHMACVerified {
		return fmt.Errorf("runtime attestation does not contain verified hardware trust evidence")
	}
	if !canonicalSHA256String(evidence.RequestNonce) {
		return fmt.Errorf("runtime attestation lacks a verified request nonce")
	}
	if !canonicalSHA256String(evidence.TPMAKPublicKeySHA256) {
		return fmt.Errorf("runtime attestation lacks a pinned AK public-key digest")
	}
	return nil
}

func canonicalSHA256String(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// RecordVerifiedAttestation records evidence only after freshness and all
// hardware/software trust assertions have been checked.
func (rm *RecoveryManager) RecordVerifiedAttestation(
	incidentID string,
	evidence RecoveryAttestationEvidence,
) (bool, string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	req, ok := rm.requirements[incidentID]
	if !ok {
		return false, "no recovery requirement for incident"
	}
	if !req.RequireReattest {
		return false, "re-attestation is not required for this incident"
	}
	if err := validateRecoveryEvidence(req, evidence); err != nil {
		return false, err.Error()
	}

	previous := cloneRequirement(req)
	evidence.RecoveryBinding = req.ContainmentBinding
	req.ReAttestedAt = evidence.Timestamp
	req.AttestationEvidence = &evidence
	rm.checkCompleteLocked(req)
	if err := rm.persistLocked(); err != nil {
		rm.requirements[incidentID] = previous
		return false, fmt.Sprintf("cannot persist verified attestation: %v", err)
	}
	return true, "re-attestation recorded"
}

func (rm *RecoveryManager) checkCompleteLocked(req *RecoveryRequirement) {
	acked := !req.RequireAck || req.AckedAt != ""
	reattested := !req.RequireReattest
	if req.RequireReattest && req.AttestationEvidence != nil &&
		req.AttestationEvidence.RecoveryBinding == req.ContainmentBinding &&
		validateRecoveryEvidence(req, *req.AttestationEvidence) == nil {
		reattested = true
	}
	req.RecoveryComplete = acked && reattested
	if req.RecoveryComplete {
		req.ContainmentLatchActive = false
		if req.RecoveryGateReleasedAt == "" {
			req.RecoveryGateReleasedAt = time.Now().UTC().Format(time.RFC3339Nano)
			log.Printf("recovery: ceremony complete for incident %s", req.IncidentID)
		}
	} else {
		req.RecoveryGateReleasedAt = ""
		if IsLatched(req.IncidentClass) ||
			len(req.ContainmentActions) > 0 ||
			len(req.ContainmentResults) > 0 {
			req.ContainmentLatchActive = true
		}
	}
}

// IsRecoveryComplete checks if a recovery ceremony is fully satisfied.
func (rm *RecoveryManager) IsRecoveryComplete(incidentID string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	req, ok := rm.requirements[incidentID]
	if !ok {
		return true // No requirement = no ceremony needed
	}
	return req.RecoveryComplete
}

// CanReleaseIncident is the fail-closed lifecycle gate. Unlike
// IsRecoveryComplete, a missing requirement blocks every incident whose class,
// severity, state, or containment transaction requires a ceremony.
func (rm *RecoveryManager) CanReleaseIncident(inc Incident) (bool, string) {
	if !incidentRequiresRecovery(inc) {
		return true, ""
	}
	binding, err := containmentBindingForIncident(inc)
	if err != nil {
		return false, "cannot verify containment binding"
	}
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	req, ok := rm.requirements[inc.ID]
	if !ok {
		return false, "recovery requirement is missing"
	}
	if req.ContainmentBinding != binding {
		return false, "containment transaction changed; a new recovery ceremony is required"
	}
	if !req.RecoveryComplete || req.ContainmentLatchActive {
		return false, "recovery ceremony is incomplete"
	}
	return true, ""
}

// GetRequirement returns the recovery requirement for an incident.
func (rm *RecoveryManager) GetRequirement(incidentID string) *RecoveryRequirement {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	req, ok := rm.requirements[incidentID]
	if !ok {
		return nil
	}
	return cloneRequirement(req)
}

// PendingRecoveries returns all incomplete recovery ceremonies.
func (rm *RecoveryManager) PendingRecoveries() []*RecoveryRequirement {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	var pending []*RecoveryRequirement
	for _, req := range rm.requirements {
		if !req.RecoveryComplete {
			pending = append(pending, cloneRequirement(req))
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].IncidentID < pending[j].IncidentID
	})
	return pending
}

func cloneRequirement(req *RecoveryRequirement) *RecoveryRequirement {
	if req == nil {
		return nil
	}
	copyReq := *req
	copyReq.ContainmentActions = append([]string(nil), req.ContainmentActions...)
	copyReq.ContainmentResults = append([]ContainmentResult(nil), req.ContainmentResults...)
	if req.AttestationEvidence != nil {
		copyEvidence := *req.AttestationEvidence
		copyReq.AttestationEvidence = &copyEvidence
	}
	return &copyReq
}

type recoveryStateFile struct {
	Version      int                    `json:"version"`
	Requirements []*RecoveryRequirement `json:"requirements"`
}

func (rm *RecoveryManager) persistLocked() error {
	if rm.path == "" {
		return nil
	}
	requirements := make([]*RecoveryRequirement, 0, len(rm.requirements))
	for _, req := range rm.requirements {
		requirements = append(requirements, cloneRequirement(req))
	}
	sort.Slice(requirements, func(i, j int) bool {
		return requirements[i].IncidentID < requirements[j].IncidentID
	})
	state := recoveryStateFile{
		Version:      recoveryStateVersion,
		Requirements: requirements,
	}

	dirPath := filepath.Dir(rm.path)
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return fmt.Errorf("create recovery state directory: %w", err)
	}
	file, err := os.CreateTemp(dirPath, ".recovery-requirements-*.json")
	if err != nil {
		return fmt.Errorf("create recovery state: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0640); err != nil {
		file.Close()
		return fmt.Errorf("secure recovery state: %w", err)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(state); err != nil {
		file.Close()
		return fmt.Errorf("encode recovery state: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync recovery state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close recovery state: %w", err)
	}
	if err := os.Rename(tempPath, rm.path); err != nil {
		return fmt.Errorf("publish recovery state: %w", err)
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("open recovery state directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync recovery state directory: %w", err)
	}
	return nil
}

func validRecoveryIncidentID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Load restores durable requirements. Semantically derived fields are
// recomputed instead of trusting booleans from disk.
func (rm *RecoveryManager) Load() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.path == "" {
		return nil
	}
	info, err := os.Lstat(rm.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect recovery state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("recovery state is not a regular file")
	}
	if info.Size() > maxRecoveryStateFileSize {
		return fmt.Errorf("recovery state exceeds %d bytes", maxRecoveryStateFileSize)
	}
	data, err := os.ReadFile(rm.path)
	if err != nil {
		return fmt.Errorf("read recovery state: %w", err)
	}
	var state recoveryStateFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode recovery state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode recovery state: %w", err)
	}
	if state.Version != recoveryStateVersion {
		return fmt.Errorf("unsupported recovery state version %d", state.Version)
	}
	loaded := make(map[string]*RecoveryRequirement, len(state.Requirements))
	for _, req := range state.Requirements {
		if req == nil || !validRecoveryIncidentID(req.IncidentID) {
			return fmt.Errorf("recovery state contains an invalid incident id")
		}
		if _, duplicate := loaded[req.IncidentID]; duplicate {
			return fmt.Errorf("recovery state contains duplicate incident %s", req.IncidentID)
		}
		if !canonicalSHA256String(req.ContainmentBinding) {
			return fmt.Errorf("recovery state contains an invalid containment binding")
		}
		if _, err := time.Parse(time.RFC3339Nano, req.RequiredAfter); err != nil {
			return fmt.Errorf("recovery state contains an invalid freshness boundary")
		}
		copyReq := cloneRequirement(req)
		rm.checkCompleteLocked(copyReq)
		loaded[copyReq.IncidentID] = copyReq
	}
	rm.requirements = loaded
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

// Reconcile creates missing gates for persisted incidents and invalidates any
// ceremony whose containment binding changed.
func (rm *RecoveryManager) Reconcile(all []Incident) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	changed := false
	for _, inc := range all {
		if !incidentRequiresRecovery(inc) {
			continue
		}
		requirementChanged, err := rm.ensureRequirementLocked(inc)
		if err != nil {
			return err
		}
		changed = changed || requirementChanged
	}
	if changed {
		return rm.persistLocked()
	}
	return nil
}

func recoveryStatePath() string {
	if path := strings.TrimSpace(os.Getenv("INCIDENT_RECOVERY_STATE_PATH")); path != "" {
		return path
	}
	return "/var/lib/secure-ai/data/recovery-requirements.json"
}

func initializeRecoveryState() error {
	manager := NewRecoveryManagerWithPath(recoveryStatePath())
	if err := manager.Load(); err != nil {
		return err
	}
	if err := manager.Reconcile(getIncidents()); err != nil {
		return err
	}
	recoveryMgr = manager
	return nil
}

type runtimeBootMeasurements struct {
	SecureBootEnabled bool              `json:"secure_boot_enabled"`
	PCRValues         map[string]string `json:"pcr_values,omitempty"`
	MeasuredAt        string            `json:"measured_at"`
}

// Keep this schema in exact lockstep with runtime-attestor's
// RuntimeStateBundle. The HMAC covers every field, not merely the recovery
// subset.
type runtimeAttestationResponse struct {
	Timestamp               string                  `json:"timestamp"`
	State                   string                  `json:"state"`
	AssuranceMode           string                  `json:"assurance_mode"`
	EvidenceVerified        bool                    `json:"evidence_verified"`
	RequestNonce            string                  `json:"request_nonce"`
	BootMeasurements        runtimeBootMeasurements `json:"boot_measurements"`
	DeploymentDigest        string                  `json:"deployment_digest"`
	DeploymentVerified      bool                    `json:"deployment_verified"`
	ReleaseSourceCommit     string                  `json:"release_source_commit"`
	ReleaseBaselineVerified bool                    `json:"release_baseline_verified"`
	ServiceDigests          map[string]string       `json:"service_digests"`
	PolicyDigest            string                  `json:"policy_digest"`
	RegistryManifestHash    string                  `json:"registry_manifest_hash"`
	KernelCmdline           string                  `json:"kernel_cmdline"`
	KernelLockdown          string                  `json:"kernel_lockdown"`
	TPMAvailable            bool                    `json:"tpm_available"`
	TPMMeasurementsVerified bool                    `json:"tpm_measurements_verified"`
	TPMQuoteVerified        bool                    `json:"tpm_quote_verified"`
	TPMAKPublicKeySHA256    string                  `json:"tpm_ak_public_key_sha256"`
	TPMQuotePCRSelection    string                  `json:"tpm_quote_pcr_selection"`
	Failures                []string                `json:"failures,omitempty"`
	BundleHMAC              string                  `json:"bundle_hmac"`
}

var (
	runtimeAttestorToken         string
	runtimeAttestationHMACKey    []byte
	fetchFreshRuntimeAttestation = requestFreshRuntimeAttestation
)

func loadRuntimeAttestorToken() error {
	token, err := readRequiredToken("RUNTIME_ATTESTOR_TOKEN_PATH")
	if err != nil {
		return err
	}
	runtimeAttestorToken = token
	return nil
}

func loadRuntimeAttestationHMACKey() error {
	path := strings.TrimSpace(os.Getenv("ATTESTATION_HMAC_KEY_PATH"))
	if path == "" {
		return fmt.Errorf("ATTESTATION_HMAC_KEY_PATH is not configured")
	}
	_, decoded, err := readCanonicalCredentialFile(path, "attestation HMAC key")
	if err != nil {
		return err
	}
	runtimeAttestationHMACKey = append(runtimeAttestationHMACKey[:0], decoded...)
	return nil
}

func verifyRuntimeAttestationHMAC(bundle runtimeAttestationResponse) error {
	if len(runtimeAttestationHMACKey) != sha256.Size {
		return fmt.Errorf("runtime attestation HMAC verification key is unavailable")
	}
	if !canonicalSHA256String(bundle.BundleHMAC) {
		return fmt.Errorf("runtime attestation bundle HMAC is malformed")
	}
	provided, err := hex.DecodeString(bundle.BundleHMAC)
	if err != nil {
		return fmt.Errorf("decode runtime attestation bundle HMAC: %w", err)
	}
	bundle.BundleHMAC = ""
	payload, err := canonicalRuntimeAttestationJSON(bundle)
	if err != nil {
		return fmt.Errorf("marshal canonical runtime attestation bundle: %w", err)
	}
	mac := hmac.New(sha256.New, runtimeAttestationHMACKey)
	if _, err := mac.Write(payload); err != nil {
		return fmt.Errorf("compute runtime attestation bundle HMAC: %w", err)
	}
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return fmt.Errorf("runtime attestation bundle HMAC verification failed")
	}
	return nil
}

func canonicalRuntimeAttestationJSON(bundle runtimeAttestationResponse) ([]byte, error) {
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	object["bundle_hmac"] = ""
	return json.Marshal(object)
}

func runtimeAttestorRefreshURL() (string, error) {
	base := strings.TrimSpace(os.Getenv("RUNTIME_ATTESTOR_URL"))
	if base == "" {
		base = "http://127.0.0.1:8505"
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse runtime-attestor URL: %w", err)
	}
	if parsed.Scheme != "http" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("runtime-attestor URL must be an unauthenticated HTTP loopback origin")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("runtime-attestor URL must use a numeric loopback address")
	}
	if parsed.Port() == "" {
		return "", fmt.Errorf("runtime-attestor URL must include an explicit port")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/refresh"
	return parsed.String(), nil
}

func requestFreshRuntimeAttestation(ctx context.Context) (RecoveryAttestationEvidence, error) {
	var evidence RecoveryAttestationEvidence
	if strings.TrimSpace(runtimeAttestorToken) == "" {
		return evidence, fmt.Errorf("runtime-attestor authentication is unavailable")
	}
	nonceBytes := make([]byte, sha256.Size)
	if _, err := rand.Read(nonceBytes); err != nil {
		return evidence, fmt.Errorf("generate runtime attestation request nonce: %w", err)
	}
	requestNonce := hex.EncodeToString(nonceBytes)
	requestBody, err := json.Marshal(map[string]string{"request_nonce": requestNonce})
	if err != nil {
		return evidence, fmt.Errorf("encode runtime attestation refresh request: %w", err)
	}
	refreshURL, err := runtimeAttestorRefreshURL()
	if err != nil {
		return evidence, err
	}
	requestedAt := time.Now().UTC()
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		refreshURL,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return evidence, fmt.Errorf("create runtime-attestor refresh request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+runtimeAttestorToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 35 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return evidence, fmt.Errorf("request fresh runtime attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return evidence, fmt.Errorf("runtime-attestor refresh returned status %d", resp.StatusCode)
	}

	var bundle runtimeAttestationResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxAttestationBodySize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return evidence, fmt.Errorf("decode runtime attestation: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return evidence, fmt.Errorf("decode runtime attestation: %w", err)
	}
	if err := verifyRuntimeAttestationHMAC(bundle); err != nil {
		return evidence, err
	}
	if !hmac.Equal([]byte(bundle.RequestNonce), []byte(requestNonce)) {
		return evidence, fmt.Errorf("runtime attestation response is not bound to the refresh request")
	}
	evidence = RecoveryAttestationEvidence{
		RequestedAt:             requestedAt.Format(time.RFC3339Nano),
		Timestamp:               bundle.Timestamp,
		State:                   bundle.State,
		AssuranceMode:           bundle.AssuranceMode,
		EvidenceVerified:        bundle.EvidenceVerified,
		SecureBootEnabled:       bundle.BootMeasurements.SecureBootEnabled,
		TPMAvailable:            bundle.TPMAvailable,
		TPMMeasurementsVerified: bundle.TPMMeasurementsVerified,
		TPMQuoteVerified:        bundle.TPMQuoteVerified,
		DeploymentVerified:      bundle.DeploymentVerified,
		ReleaseBaselineVerified: bundle.ReleaseBaselineVerified,
		DeploymentDigest:        bundle.DeploymentDigest,
		PolicyDigest:            bundle.PolicyDigest,
		TPMAKPublicKeySHA256:    bundle.TPMAKPublicKeySHA256,
		BundleHMAC:              bundle.BundleHMAC,
		BundleHMACVerified:      true,
		RequestNonce:            bundle.RequestNonce,
	}
	return evidence, nil
}

// =========================================================================
// Latched degraded states
// =========================================================================

// LatchedClasses are incident classes that remain in degraded state
// until explicit manual review. They cannot be auto-resolved.
var LatchedClasses = map[IncidentClass]bool{
	ClassAttestationFailure: true,
	ClassIntegrityViolation: true,
	ClassUnauthorizedAccess: true,
	ClassManifestMismatch:   true,
}

// IsLatched returns true if the incident class requires manual review
// before leaving degraded state.
func IsLatched(class IncidentClass) bool {
	return LatchedClasses[class]
}

// =========================================================================
// Severity escalation — repeated events escalate automatically
// =========================================================================

// EscalationRule defines when repeated events trigger severity escalation.
type EscalationRule struct {
	Class      IncidentClass    `yaml:"class"`
	Count      int              `yaml:"count"`       // events within window
	WindowSecs int              `yaml:"window_secs"` // time window
	EscalateTo IncidentSeverity `yaml:"escalate_to"`
}

// DefaultEscalationRules returns the built-in escalation rules.
func DefaultEscalationRules() []EscalationRule {
	return []EscalationRule{
		{Class: ClassPromptInjection, Count: 3, WindowSecs: 300, EscalateTo: SeverityCritical},
		{Class: ClassToolCallBurst, Count: 5, WindowSecs: 60, EscalateTo: SeverityHigh},
		{Class: ClassPolicyBypass, Count: 2, WindowSecs: 600, EscalateTo: SeverityCritical},
		{Class: ClassForbiddenAirlock, Count: 5, WindowSecs: 300, EscalateTo: SeverityHigh},
		{Class: ClassModelAnomaly, Count: 3, WindowSecs: 900, EscalateTo: SeverityCritical},
	}
}

// EscalationTracker watches for repeated incidents and escalates severity.
type EscalationTracker struct {
	mu    sync.Mutex
	rules []EscalationRule
	// class → list of timestamps
	history map[IncidentClass][]time.Time
}

func NewEscalationTracker(rules []EscalationRule) *EscalationTracker {
	return &EscalationTracker{
		rules:   rules,
		history: make(map[IncidentClass][]time.Time),
	}
}

// Record records a new incident and returns the escalated severity if
// escalation rules trigger, or empty string if no escalation.
func (et *EscalationTracker) Record(class IncidentClass, severity IncidentSeverity) IncidentSeverity {
	et.mu.Lock()
	defer et.mu.Unlock()

	now := time.Now()
	et.history[class] = append(et.history[class], now)

	for _, rule := range et.rules {
		if rule.Class != class {
			continue
		}
		window := now.Add(-time.Duration(rule.WindowSecs) * time.Second)
		// Count events in window
		count := 0
		var recent []time.Time
		for _, t := range et.history[class] {
			if t.After(window) {
				count++
				recent = append(recent, t)
			}
		}
		// Trim old entries
		et.history[class] = recent

		if count >= rule.Count {
			// Only escalate if the new severity is higher
			if severityRank(rule.EscalateTo) > severityRank(severity) {
				log.Printf("escalation: %s — %d events in %ds triggers escalation to %s",
					class, count, rule.WindowSecs, rule.EscalateTo)
				return rule.EscalateTo
			}
		}
	}
	return ""
}

// =========================================================================
// Forensic bundle export
// =========================================================================

// ForensicBundle is a signed export package for offline review.
type ForensicBundle struct {
	ExportedAt       string            `json:"exported_at"`
	Incidents        []Incident        `json:"incidents"`
	AuditEntries     []string          `json:"audit_entries"` // JSONL lines
	SystemState      map[string]string `json:"system_state"`
	PolicyDigest     string            `json:"policy_digest"`
	CanonicalPayload string            `json:"canonical_payload"`
	BundleHash       string            `json:"bundle_hash"`
	Signature        string            `json:"signature"`
}

type forensicPayload struct {
	ExportedAt   string            `json:"exported_at"`
	Incidents    []Incident        `json:"incidents"`
	AuditEntries []string          `json:"audit_entries"`
	SystemState  map[string]string `json:"system_state"`
	PolicyDigest string            `json:"policy_digest"`
}

const (
	minForensicHMACKeyBytes = 32
	maxForensicPayloadBytes = 128 << 20
)

var forensicHMACKey []byte

func loadForensicHMACKey() error {
	keyPath := strings.TrimSpace(os.Getenv("FORENSIC_HMAC_KEY_PATH"))
	if keyPath == "" {
		keyPath = "/run/secure-ai/forensic-hmac-key"
	}
	encoded, _, err := readCanonicalCredentialFile(keyPath, "forensic HMAC key")
	if err != nil {
		return err
	}
	// Preserve the established forensic-bundle wire format: the independent
	// local verifier uses the canonical hexadecimal credential bytes as the
	// HMAC key. Runtime-attestation HMACs use decoded key bytes in both peers.
	forensicHMACKey = append(forensicHMACKey[:0], []byte(encoded)...)
	return nil
}

func payloadForBundle(bundle *ForensicBundle) forensicPayload {
	return forensicPayload{
		ExportedAt:   bundle.ExportedAt,
		Incidents:    bundle.Incidents,
		AuditEntries: bundle.AuditEntries,
		SystemState:  bundle.SystemState,
		PolicyDigest: bundle.PolicyDigest,
	}
}

// ExportForensicBundle creates a mandatory HMAC-authenticated forensic bundle
// from current state. CanonicalPayload is the base64 encoding of the exact
// encoding/json bytes that BundleHash and Signature cover, so independent
// verifiers never need to reproduce Go's map serialization rules.
func ExportForensicBundle(
	incidents []Incident,
	auditLog []string,
	systemState map[string]string,
	policyDigest string,
	signingKey []byte,
) (*ForensicBundle, error) {
	if len(signingKey) < minForensicHMACKeyBytes {
		return nil, fmt.Errorf("forensic signing key must contain at least %d bytes", minForensicHMACKeyBytes)
	}
	bundle := &ForensicBundle{
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		Incidents:    incidents,
		AuditEntries: auditLog,
		SystemState:  systemState,
		PolicyDigest: policyDigest,
	}

	hashData, err := json.Marshal(payloadForBundle(bundle))
	if err != nil {
		return nil, fmt.Errorf("marshal forensic payload: %w", err)
	}
	if len(hashData) > maxForensicPayloadBytes {
		return nil, fmt.Errorf("forensic payload exceeds %d-byte limit", maxForensicPayloadBytes)
	}
	bundle.CanonicalPayload = base64.StdEncoding.EncodeToString(hashData)
	h := sha256.Sum256(hashData)
	bundle.BundleHash = hex.EncodeToString(h[:])

	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(h[:])
	bundle.Signature = hex.EncodeToString(mac.Sum(nil))

	return bundle, nil
}

// VerifyForensicBundle checks the integrity and authenticity of a forensic bundle.
func VerifyForensicBundle(bundle *ForensicBundle, signingKey []byte) (bool, string) {
	if bundle == nil {
		return false, "bundle is nil"
	}
	if len(signingKey) < minForensicHMACKeyBytes {
		return false, "forensic verification key is unavailable or too short"
	}
	if bundle.CanonicalPayload == "" ||
		len(bundle.CanonicalPayload) > base64.StdEncoding.EncodedLen(maxForensicPayloadBytes) {
		return false, "canonical payload is missing or oversized"
	}
	hashData, err := base64.StdEncoding.Strict().DecodeString(bundle.CanonicalPayload)
	if err != nil {
		return false, "canonical payload is not valid base64"
	}

	var decoded forensicPayload
	if err := json.Unmarshal(hashData, &decoded); err != nil {
		return false, "canonical payload is not valid JSON"
	}
	canonicalDecoded, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(hashData, canonicalDecoded) {
		return false, "canonical payload is not in canonical form"
	}
	canonicalOuter, err := json.Marshal(payloadForBundle(bundle))
	if err != nil || !bytes.Equal(hashData, canonicalOuter) {
		return false, "canonical payload does not match exposed bundle fields"
	}

	h := sha256.Sum256(hashData)
	expected := hex.EncodeToString(h[:])

	if bundle.BundleHash != expected {
		return false, "bundle hash mismatch — content may have been tampered"
	}

	signature, err := hex.DecodeString(bundle.Signature)
	if err != nil || len(signature) != sha256.Size {
		return false, "bundle signature is missing or malformed"
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(h[:])
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false, "bundle signature mismatch"
	}

	return true, "valid"
}

// =========================================================================
// HTTP handlers for recovery, escalation, and forensic export
// =========================================================================

func handleRecoveryAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
		Operator   string `json:"operator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ok, msg := recoveryMgr.Acknowledge(req.IncidentID, req.Operator)
	if !ok {
		status := http.StatusConflict
		if msg == "no recovery requirement for incident" {
			status = http.StatusNotFound
		}
		if strings.HasPrefix(msg, "cannot persist") {
			status = http.StatusInternalServerError
		}
		http.Error(w, msg, status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": msg})
}

func handleRecoveryReattest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IncidentID string `json:"incident_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	requirement := recoveryMgr.GetRequirement(req.IncidentID)
	if requirement == nil {
		http.Error(w, "no recovery requirement for incident", http.StatusNotFound)
		return
	}
	if !requirement.RequireReattest {
		http.Error(w, "re-attestation is not required for this incident", http.StatusConflict)
		return
	}

	evidence, err := fetchFreshRuntimeAttestation(r.Context())
	if err != nil {
		log.Printf("recovery: fresh attestation unavailable for incident %s: %v", req.IncidentID, err)
		http.Error(w, "fresh runtime attestation is unavailable", http.StatusServiceUnavailable)
		return
	}
	ok, msg := recoveryMgr.RecordVerifiedAttestation(req.IncidentID, evidence)
	if !ok {
		status := http.StatusConflict
		if strings.HasPrefix(msg, "cannot persist") {
			status = http.StatusInternalServerError
		}
		http.Error(w, msg, status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": msg})
}

func handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pending := recoveryMgr.PendingRecoveries()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_recoveries": pending,
		"count":              len(pending),
	})
}

func handleForensicExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	incidentsMu.RLock()
	allIncidents := make([]Incident, 0, len(incidents))
	for _, inc := range incidents {
		allIncidents = append(allIncidents, inc)
	}
	incidentsMu.RUnlock()

	// Read audit log tail (last 1000 entries)
	auditEntries := readAuditLogTail(1000)
	if auditEntries == nil {
		auditEntries = []string{}
	}

	// Compute policy digest from loaded containment policy
	pol := getContainmentPolicy()
	polData, _ := json.Marshal(pol)
	polHash := sha256.Sum256(polData)
	policyDigest := hex.EncodeToString(polHash[:])

	openInc := getOpenIncidents()

	bundle, err := ExportForensicBundle(
		allIncidents,
		auditEntries,
		map[string]string{
			"export_time":     time.Now().UTC().Format(time.RFC3339),
			"service":         "incident-recorder",
			"total_incidents": fmt.Sprintf("%d", len(allIncidents)),
			"open_incidents":  fmt.Sprintf("%d", len(openInc)),
		},
		policyDigest,
		forensicHMACKey,
	)
	if err != nil {
		log.Printf("forensic export failed: %v", err)
		http.Error(w, `{"error":"forensic signing unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	ts := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=forensic-bundle-%s.json", ts))
	json.NewEncoder(w).Encode(bundle)
}

// Global recovery manager and escalation tracker (initialised in main or test setup)
var recoveryMgr = NewRecoveryManager()
var escalationTracker = NewEscalationTracker(DefaultEscalationRules())

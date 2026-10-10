package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
)

const gpuRequestLimit = evidence.RequestLimit
const gpuResponseLimit = evidence.ResponseLimit
const gpuExchangeTimeout = evidence.ExchangeTimeout
const gpuEvidencePath = evidence.Path

type GPUChallenge = evidence.Challenge
type GPUAuthenticatedEvidence = evidence.Evidence
type GPUConsumerPolicy = evidence.Policy

func canonicalGPUEvidence(value any) ([]byte, error) { return evidence.Canonical(value) }
func gpuMAC(key []byte, domain string, value any) (string, error) {
	return evidence.MAC(key, domain, value)
}
func gpuRequestMAC(key []byte, request GPUChallenge) (string, error) {
	return evidence.RequestMAC(key, request)
}
func gpuResponseMAC(key []byte, response GPUAuthenticatedEvidence) (string, error) {
	return evidence.ResponseMAC(key, response)
}
func equalGPUMAC(supplied, expected string) bool { return evidence.EqualMAC(supplied, expected) }
func gpuFoldKey(key string) string               { return evidence.FoldKey(key) }
func strictGPUJSON(data []byte, value any) error { return evidence.StrictJSON(data, value) }
func exactGPUFields(data []byte, fields []string, nullable string) (map[string]json.RawMessage, error) {
	return evidence.ExactFields(data, fields, nullable)
}
func decodeGPUChallenge(data []byte) (GPUChallenge, error) { return evidence.DecodeChallenge(data) }
func decodeGPUResponse(data []byte) (GPUAuthenticatedEvidence, error) {
	return evidence.DecodeResponse(data)
}
func validateGPUEnvelopeShape(response GPUAuthenticatedEvidence) error {
	return evidence.ValidateEnvelopeShape(response)
}
func validateGPUCompletedEvidence(response GPUAuthenticatedEvidence, policy GPUConsumerPolicy, now time.Time) error {
	return evidence.Validate(response, policy, now)
}
func gpuEvidenceURL(origin string) (string, error) { return evidence.URL(origin) }
func fetchGPUEvidence(ctx context.Context, origin, scope, nonce string, key []byte) (GPUAuthenticatedEvidence, error) {
	return evidence.Fetch(ctx, origin, scope, nonce, key)
}

func (p *gpuEvidencePublisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != gpuEvidencePath || r.URL.RawQuery != "" {
		http.Error(w, "invalid evidence endpoint", http.StatusBadRequest)
		return
	}
	deadline := time.Now().Add(gpuExchangeTimeout)
	controller := http.NewResponseController(w)
	// Native net/http supports these deadlines. In-memory response recorders
	// have no connection; the enclosing server also retains its own timeouts.
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	select {
	case p.requests <- struct{}{}:
		defer func() { <-p.requests }()
	default:
		http.Error(w, "evidence request capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, gpuRequestLimit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "evidence request exceeds bounds", http.StatusRequestEntityTooLarge)
		return
	}
	request, err := decodeGPUChallenge(data)
	if err != nil {
		http.Error(w, "invalid evidence request schema", http.StatusBadRequest)
		return
	}
	expected, err := gpuRequestMAC(p.key, request)
	if err != nil || request.SchemaVersion != 1 || request.Scope != p.scope || !gpuHex64.MatchString(request.RequestNonce) || !equalGPUMAC(request.RequestMAC, expected) {
		http.Error(w, "evidence request authentication failed", http.StatusUnauthorized)
		return
	}
	state := p.readState()
	response := GPUAuthenticatedEvidence{SchemaVersion: 1, Scope: p.scope, RequestNonce: request.RequestNonce, ProducerInstance: p.instance, LatestSequence: state.sequence, Availability: state.availability, Reason: state.reason, Snapshot: state.snapshot}
	if err := validateGPUEnvelopeShape(response); err != nil {
		http.Error(w, "evidence state unavailable", http.StatusServiceUnavailable)
		return
	}
	response.ResponseMAC, err = gpuResponseMAC(p.key, response)
	if err != nil {
		http.Error(w, "evidence signing unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := json.Marshal(response)
	if err != nil || len(body) > gpuResponseLimit {
		http.Error(w, "evidence encoding unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// Only the dedicated challenge handler bypasses monitoring bearer middleware;
// it performs its own MAC authentication. Neither credential authorizes the
// other interface, and snapshot reads never invoke probes or actions.
func gpuDaemonEvidenceHandler(monitoring http.Handler, publisher *gpuEvidencePublisher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == gpuEvidencePath {
			publisher.ServeHTTP(w, r)
			return
		}
		monitoring.ServeHTTP(w, r)
	})
}

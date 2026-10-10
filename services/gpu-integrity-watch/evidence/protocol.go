// Package evidence implements the authenticated, bounded GPU evidence wire protocol.
package evidence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const gpuRequestLimit = 4 << 10
const gpuResponseLimit = 64 << 10
const gpuExchangeTimeout = 5 * time.Second
const gpuEvidencePath = "/v1/attest-state"

type Challenge struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	RequestNonce  string `json:"request_nonce"`
	RequestMAC    string `json:"request_mac"`
}

type Evidence struct {
	SchemaVersion    int       `json:"schema_version"`
	Scope            string    `json:"scope"`
	RequestNonce     string    `json:"request_nonce"`
	ProducerInstance string    `json:"producer_instance"`
	LatestSequence   uint64    `json:"latest_sequence"`
	Availability     string    `json:"availability"`
	Reason           string    `json:"reason"`
	Snapshot         *Snapshot `json:"snapshot"`
	ResponseMAC      string    `json:"response_mac"`
}

func canonicalGPUEvidence(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var obj any
	if err := d.Decode(&obj); err != nil {
		return nil, err
	}
	return json.Marshal(obj) // Recursively sorted string keys; preserve numbers.
}

func gpuMAC(key []byte, domain string, value any) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("GPU evidence key unavailable")
	}
	data, err := canonicalGPUEvidence(value)
	if err != nil {
		return "", fmt.Errorf("GPU evidence cannot be encoded")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func gpuRequestMAC(key []byte, request Challenge) (string, error) {
	request.RequestMAC = ""
	return gpuMAC(key, "SecAI GPU evidence request v1", request)
}

func gpuResponseMAC(key []byte, response Evidence) (string, error) {
	response.ResponseMAC = ""
	return gpuMAC(key, "SecAI GPU evidence response v1", response)
}

func equalGPUMAC(supplied, expected string) bool {
	if !gpuHex64.MatchString(supplied) || !gpuHex64.MatchString(expected) {
		return false
	}
	return hmac.Equal([]byte(supplied), []byte(expected))
}

func gpuFoldKey(key string) string {
	var out strings.Builder
	for _, r := range key {
		small := r
		for n := unicode.SimpleFold(r); n != r; n = unicode.SimpleFold(n) {
			if n < small {
				small = n
			}
		}
		out.WriteRune(small)
	}
	return out.String()
}

func strictGPUJSON(data []byte, value any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return fmt.Errorf("JSON depth exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := token.(string)
					if !ok {
						return fmt.Errorf("invalid member")
					}
					key = gpuFoldKey(key)
					if seen[key] {
						return fmt.Errorf("duplicate member")
					}
					seen[key] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

func exactGPUFields(data []byte, fields []string, nullable string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil || len(object) != len(fields) {
		return nil, fmt.Errorf("GPU schema fields missing or unexpected")
	}
	for _, key := range fields {
		value, ok := object[key]
		if !ok || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && key != nullable) {
			return nil, fmt.Errorf("GPU required field missing or null")
		}
	}
	return object, nil
}

func decodeChallenge(data []byte) (Challenge, error) {
	var request Challenge
	if err := strictGPUJSON(data, &request); err != nil {
		return request, err
	}
	_, err := exactGPUFields(data, []string{"schema_version", "scope", "request_nonce", "request_mac"}, "")
	return request, err
}

func decodeGPUResponse(data []byte) (Evidence, error) {
	var response Evidence
	if err := strictGPUJSON(data, &response); err != nil {
		return response, err
	}
	obj, err := exactGPUFields(data, []string{"schema_version", "scope", "request_nonce", "producer_instance", "latest_sequence", "availability", "reason", "snapshot", "response_mac"}, "snapshot")
	if err != nil {
		return response, err
	}
	if response.Snapshot != nil {
		snapshot, err := exactGPUFields(obj["snapshot"], []string{"sequence", "started_at", "completed_at", "profile_sha256", "baseline_sha256", "baseline_state", "verdict", "composite_score", "probes"}, "")
		if err != nil {
			return response, err
		}
		var probes []json.RawMessage
		if err := json.Unmarshal(snapshot["probes"], &probes); err != nil || len(probes) == 0 || len(probes) > maxGPUProbes {
			return response, fmt.Errorf("invalid GPU probe count")
		}
		for _, probe := range probes {
			if _, err := exactGPUFields(probe, []string{"id", "type", "status", "score", "reason"}, ""); err != nil {
				return response, err
			}
		}
	}
	return response, validateGPUEnvelopeShape(response)
}

func validateGPUEnvelopeShape(response Evidence) error {
	bad := func() error { return fmt.Errorf("invalid GPU evidence value schema") }
	if response.SchemaVersion != 1 || (response.Scope != "bootstrap" && response.Scope != "runtime") || !gpuHex64.MatchString(response.RequestNonce) || !gpuHex64.MatchString(response.ProducerInstance) {
		return bad()
	}
	if response.Snapshot == nil {
		if response.Availability != "unavailable" {
			return bad()
		}
		switch response.Reason {
		case "no_completed_cycle":
			if response.LatestSequence != 0 {
				return bad()
			}
		case "invalid_cycle", "cycle_aborted", "sequence_exhausted":
			if response.LatestSequence == 0 {
				return bad()
			}
		default:
			return bad()
		}
		return nil
	}
	s := response.Snapshot
	if s.Sequence == 0 || s.Sequence != response.LatestSequence || !gpuHex64.MatchString(s.ProfileSHA256) || (s.BaselineSHA256 != "" && !gpuHex64.MatchString(s.BaselineSHA256)) || math.IsNaN(s.CompositeScore) || math.IsInf(s.CompositeScore, 0) || s.CompositeScore < 0 || s.CompositeScore > 1 || len(s.Probes) == 0 || len(s.Probes) > maxGPUProbes {
		return bad()
	}
	start, err := time.Parse(time.RFC3339Nano, s.StartedAt)
	if err != nil || start.IsZero() || start.UTC().Format(time.RFC3339Nano) != s.StartedAt {
		return bad()
	}
	end, err := time.Parse(time.RFC3339Nano, s.CompletedAt)
	if err != nil || end.Before(start) || end.UTC().Format(time.RFC3339Nano) != s.CompletedAt {
		return bad()
	}
	switch s.BaselineState {
	case "missing", "not_required":
	case "loaded":
		if s.BaselineSHA256 == "" {
			return bad()
		}
	default:
		return bad()
	}
	switch response.Availability {
	case "complete":
		if response.Reason != "completed_cycle" || s.BaselineState == "missing" {
			return bad()
		}
	case "unverified":
		if response.Reason != "required_baseline_missing" || s.BaselineState != "missing" || (s.Verdict != VerdictUnknown && s.Verdict != VerdictCritical) {
			return bad()
		}
	default:
		return bad()
	}
	var results []Probe
	last := ""
	for _, probe := range s.Probes {
		if !gpuProbeID.MatchString(probe.ID) || !knownGPUProbe(probe.Type) || probe.ID <= last || math.IsNaN(probe.Score) || math.IsInf(probe.Score, 0) || probe.Score < 0 || probe.Score > 1 {
			return bad()
		}
		if response.Scope == "bootstrap" && probe.Type != ProbeECCStatus && probe.Type != ProbeDriverFingerprint && probe.Type != ProbeDeviceAllowlist {
			return bad()
		}
		reason, ok := map[ProbeStatus]string{StatusPass: "probe_pass", StatusDrift: "probe_drift", StatusFail: "probe_failure", StatusSkip: "probe_skipped", StatusError: "probe_error"}[probe.Status]
		if !ok || probe.Reason != reason {
			return bad()
		}
		last = probe.ID
		results = append(results, Probe{Status: probe.Status, Score: probe.Score})
	}
	if response.Availability == "complete" && s.Verdict != classifyVerdict(s.CompositeScore, results) {
		return bad()
	}
	return nil
}

// Explicit caller policy is separate from source authentication. These inputs
// must come from protected, independently approved policy, never the reply.
type Policy struct {
	Scope            string
	ProfileSHA256    string
	BaselineSHA256   string
	RequiredProbes   map[string]ProbeType
	MaxAge           time.Duration
	MaxCycleDuration time.Duration
}

func validateGPUCompletedEvidence(response Evidence, policy Policy, now time.Time) error {
	if err := ValidatePolicy(policy); err != nil {
		return err
	}
	requiresBaseline := false
	for _, kind := range policy.RequiredProbes {
		if kind != ProbeECCStatus {
			requiresBaseline = true
		}
	}

	if response.SchemaVersion != 1 || response.Scope != policy.Scope || response.Availability != "complete" || response.Reason != "completed_cycle" || response.Snapshot == nil || response.LatestSequence == 0 {
		return fmt.Errorf("completed GPU evidence unavailable or unverified")
	}
	snapshot := response.Snapshot
	if snapshot.Sequence != response.LatestSequence || snapshot.ProfileSHA256 != policy.ProfileSHA256 || snapshot.BaselineSHA256 != policy.BaselineSHA256 {
		return fmt.Errorf("GPU source policy/cycle binding mismatch")
	}
	if (requiresBaseline && snapshot.BaselineState != "loaded") || (!requiresBaseline && snapshot.BaselineState != "not_required") {
		return fmt.Errorf("GPU baseline evidence is not usable")
	}
	start, err := time.Parse(time.RFC3339Nano, snapshot.StartedAt)
	if err != nil || start.UTC().Format(time.RFC3339Nano) != snapshot.StartedAt {
		return fmt.Errorf("invalid GPU cycle start")
	}
	end, err := time.Parse(time.RFC3339Nano, snapshot.CompletedAt)
	if err != nil || end.UTC().Format(time.RFC3339Nano) != snapshot.CompletedAt {
		return fmt.Errorf("invalid GPU cycle completion")
	}
	if now.IsZero() || start.IsZero() || end.Before(start) || end.Sub(start) > policy.MaxCycleDuration || start.After(now.Add(5*time.Second)) || end.After(now.Add(5*time.Second)) || now.Sub(start) > policy.MaxAge || now.Sub(end) > policy.MaxAge {
		return fmt.Errorf("GPU cycle is stale, future or too long")
	}
	if snapshot.Verdict != VerdictHealthy || math.IsNaN(snapshot.CompositeScore) || math.IsInf(snapshot.CompositeScore, 0) || snapshot.CompositeScore < 0 || snapshot.CompositeScore >= ThresholdNormal || len(snapshot.Probes) != len(policy.RequiredProbes) {
		return fmt.Errorf("GPU cycle is not healthy or complete")
	}
	seen := map[string]bool{}
	for _, probe := range snapshot.Probes {
		kind, ok := policy.RequiredProbes[probe.ID]
		if !ok || kind != probe.Type || seen[probe.ID] || probe.Status != StatusPass || probe.Reason != "probe_pass" || math.IsNaN(probe.Score) || math.IsInf(probe.Score, 0) || probe.Score < 0 || probe.Score > 1 {
			return fmt.Errorf("required GPU probe is missing, unhealthy or inconsistent")
		}
		seen[probe.ID] = true
	}
	return nil
}

func gpuEvidenceURL(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawPath != "" || u.ForceQuery || u.RawQuery != "" || strings.Contains(origin, "#") {
		return "", fmt.Errorf("GPU evidence origin must be a numeric loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("GPU evidence origin requires numeric loopback and explicit port")
	}
	return origin + gpuEvidencePath, nil
}

// A successful exchange authenticates the source only; scope policy, baseline
// approval and freshness must be verified separately before trust decisions.
func fetchGPUEvidence(ctx context.Context, origin, scope, nonce string, key []byte) (Evidence, error) {
	var response Evidence
	endpoint, err := gpuEvidenceURL(origin)
	if err != nil {
		return response, err
	}
	if (scope != "runtime" && scope != "bootstrap") || !gpuHex64.MatchString(nonce) || len(key) != 32 {
		return response, fmt.Errorf("invalid GPU challenge identity")
	}
	challenge := Challenge{SchemaVersion: 1, Scope: scope, RequestNonce: nonce}
	challenge.RequestMAC, err = gpuRequestMAC(key, challenge)
	if err != nil {
		return response, err
	}
	body, err := json.Marshal(challenge)
	if err != nil {
		return response, err
	}
	ctx, cancel := context.WithTimeout(ctx, gpuExchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return response, err
	}
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("GPU evidence redirects forbidden") }}
	resp, err := client.Do(req)
	if err != nil {
		return response, fmt.Errorf("GPU evidence exchange failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return response, fmt.Errorf("GPU evidence endpoint returned unsuccessful response")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, gpuResponseLimit+1))
	if err != nil || len(data) > gpuResponseLimit {
		return response, fmt.Errorf("GPU evidence response incomplete or oversized")
	}
	response, err = decodeGPUResponse(data)
	if err != nil {
		return Evidence{}, fmt.Errorf("GPU evidence response schema invalid")
	}
	expected, err := gpuResponseMAC(key, response)
	if err != nil || response.SchemaVersion != 1 || response.Scope != scope || response.RequestNonce != nonce || !gpuHex64.MatchString(response.ProducerInstance) || !equalGPUMAC(response.ResponseMAC, expected) {
		return Evidence{}, fmt.Errorf("GPU response authentication failed")
	}
	return response, nil
}

const maxGPUProbes = 64

var gpuHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gpuProbeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// No raw findings, model paths, prompts, outputs, driver strings or credentials
// are allowed in these DTOs. Probe IDs/types come from the protected profile.
type Probe struct {
	ID     string      `json:"id"`
	Type   ProbeType   `json:"type"`
	Status ProbeStatus `json:"status"`
	Score  float64     `json:"score"`
	Reason string      `json:"reason"`
}

type Snapshot struct {
	Sequence       uint64  `json:"sequence"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    string  `json:"completed_at"`
	ProfileSHA256  string  `json:"profile_sha256"`
	BaselineSHA256 string  `json:"baseline_sha256"`
	BaselineState  string  `json:"baseline_state"`
	Verdict        Verdict `json:"verdict"`
	CompositeScore float64 `json:"composite_score"`
	Probes         []Probe `json:"probes"`
}

func knownGPUProbe(t ProbeType) bool {
	switch t {
	case ProbeTensorHash, ProbeSentinelInfer, ProbeReferenceDrift, ProbeECCStatus, ProbeDriverFingerprint, ProbeDeviceAllowlist:
		return true
	}
	return false
}

// ProbeType identifies the kind of integrity probe.
type ProbeType string

const (
	ProbeTensorHash        ProbeType = "tensor_hash"
	ProbeSentinelInfer     ProbeType = "sentinel_inference"
	ProbeReferenceDrift    ProbeType = "reference_drift"
	ProbeECCStatus         ProbeType = "ecc_status"
	ProbeDriverFingerprint ProbeType = "driver_fingerprint"
	ProbeDeviceAllowlist   ProbeType = "device_allowlist"
)

// ProbeStatus is the outcome of a single probe run.
type ProbeStatus string

const (
	StatusPass  ProbeStatus = "pass"
	StatusDrift ProbeStatus = "drift"
	StatusFail  ProbeStatus = "fail"
	StatusSkip  ProbeStatus = "skip"
	StatusError ProbeStatus = "error"
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

// classifyVerdict determines the verdict from score and probe statuses.
func classifyVerdict(composite float64, results []Probe) Verdict {
	// Any fail probe -> critical regardless of score
	for _, r := range results {
		if r.Status == StatusFail {
			return VerdictCritical
		}
	}
	if len(results) == 0 || math.IsNaN(composite) || math.IsInf(composite, 0) {
		return VerdictUnknown
	}
	hasDrift := false
	for _, r := range results {
		switch r.Status {
		case StatusPass:
		case StatusDrift:
			hasDrift = true
		default:
			return VerdictUnknown
		}
		if math.IsNaN(r.Score) || math.IsInf(r.Score, 0) || r.Score < 0 || r.Score > 1 {
			return VerdictUnknown
		}
	}

	switch {
	case composite >= ThresholdCritical:
		return VerdictCritical
	case composite >= ThresholdNormal:
		return VerdictWarning
	case hasDrift:
		return VerdictWarning
	default:
		return VerdictHealthy
	}
}

// Fetch authenticates a source response. Call Validate with independently approved policy before trusting it.
func Fetch(ctx context.Context, origin, scope, nonce string, key []byte) (Evidence, error) {
	return fetchGPUEvidence(ctx, origin, scope, nonce, key)
}
func Validate(response Evidence, policy Policy, now time.Time) error {
	return validateGPUCompletedEvidence(response, policy, now)
}
func DecodeResponse(data []byte) (Evidence, error)              { return decodeGPUResponse(data) }
func DecodeChallenge(data []byte) (Challenge, error)            { return decodeChallenge(data) }
func ResponseMAC(key []byte, response Evidence) (string, error) { return gpuResponseMAC(key, response) }
func RequestMAC(key []byte, request Challenge) (string, error)  { return gpuRequestMAC(key, request) }
func Canonical(value any) ([]byte, error)                       { return canonicalGPUEvidence(value) }
func StrictJSON(data []byte, value any) error                   { return strictGPUJSON(data, value) }
func ExactFields(data []byte, fields []string, nullable string) (map[string]json.RawMessage, error) {
	return exactGPUFields(data, fields, nullable)
}
func ValidateEnvelopeShape(response Evidence) error            { return validateGPUEnvelopeShape(response) }
func EqualMAC(supplied, expected string) bool                  { return equalGPUMAC(supplied, expected) }
func MAC(key []byte, domain string, value any) (string, error) { return gpuMAC(key, domain, value) }
func URL(origin string) (string, error)                        { return gpuEvidenceURL(origin) }
func FoldKey(key string) string                                { return gpuFoldKey(key) }
func KnownProbe(kind ProbeType) bool                           { return knownGPUProbe(kind) }
func ClassifyVerdict(composite float64, probes []Probe) Verdict {
	return classifyVerdict(composite, probes)
}

const (
	RequestLimit    = gpuRequestLimit
	ResponseLimit   = gpuResponseLimit
	ExchangeTimeout = gpuExchangeTimeout
	Path            = gpuEvidencePath
	MaxProbes       = maxGPUProbes
)

// ValidatePolicy checks independently approved scope, pins, probes and time bounds.
func ValidatePolicy(policy Policy) error {
	if (policy.Scope != "bootstrap" && policy.Scope != "runtime") || !gpuHex64.MatchString(policy.ProfileSHA256) || len(policy.RequiredProbes) == 0 || len(policy.RequiredProbes) > maxGPUProbes || policy.MaxAge <= 0 || policy.MaxAge > 10*time.Minute || policy.MaxCycleDuration <= 0 || policy.MaxCycleDuration > policy.MaxAge {
		return fmt.Errorf("invalid GPU verification policy")
	}
	requiresBaseline := false
	for id, kind := range policy.RequiredProbes {
		if !gpuProbeID.MatchString(id) || !knownGPUProbe(kind) {
			return fmt.Errorf("invalid required GPU probe")
		}
		if kind != ProbeECCStatus {
			requiresBaseline = true
		}
		if policy.Scope == "bootstrap" && kind != ProbeECCStatus && kind != ProbeDriverFingerprint && kind != ProbeDeviceAllowlist {
			return fmt.Errorf("dependent probe cannot satisfy bootstrap scope")
		}
	}
	if (requiresBaseline && !gpuHex64.MatchString(policy.BaselineSHA256)) || (policy.BaselineSHA256 != "" && !gpuHex64.MatchString(policy.BaselineSHA256)) {
		return fmt.Errorf("required GPU baseline approval is missing")
	}
	return nil
}

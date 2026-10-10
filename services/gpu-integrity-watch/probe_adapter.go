package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/SecAI-Hub/gpu-integrity-watch/evidence"
	"gopkg.in/yaml.v3"
)

const (
	nativeProbeOrigin    = "http://127.0.0.1:8497"
	nativeProbePolicy    = "/etc/secure-ai/policy/attestation.yaml"
	nativeProbeProfile   = "/etc/secure-ai/gpu-integrity/default-profile.yaml"
	nativeProbeBaseline  = "/etc/secure-ai/gpu-integrity/runtime-baseline.yaml"
	probeExchangeTimeout = 5 * time.Second
	maxProbeOutput       = 16 << 10
	maxProbeBody         = 64 << 10
	probeRequestDomain   = "SecAI GPU probe request v1\n"
	probeResponseDomain  = "SecAI GPU probe response v1\n"
)

type gpuProbeRequest struct {
	SchemaVersion int    `json:"schema_version"`
	ReferenceID   string `json:"reference_id"`
	RequestNonce  string `json:"request_nonce"`
	RequestMAC    string `json:"request_mac"`
}

// ExpectedModelSHA256 is the approved baseline identity, not a measurement of
// loaded memory. Pre/post backend checks authenticate the reported alias only;
// the separate tensor-hash probe measures enrolled disk bytes.
type gpuProbeResponse struct {
	SchemaVersion       int    `json:"schema_version"`
	ReferenceID         string `json:"reference_id"`
	RequestNonce        string `json:"request_nonce"`
	ProfileSHA256       string `json:"profile_sha256"`
	BaselineSHA256      string `json:"baseline_sha256"`
	ModelAlias          string `json:"model_alias"`
	ExpectedModelSHA256 string `json:"expected_model_sha256"`
	Output              string `json:"output"`
	ResponseMAC         string `json:"response_mac"`
}

func probeMAC(domain string, value any, key []byte) string {
	data, err := evidence.Canonical(value)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
func requestProbeMAC(r gpuProbeRequest, key []byte) string {
	return probeMAC(probeRequestDomain, map[string]any{"schema_version": r.SchemaVersion, "reference_id": r.ReferenceID, "request_nonce": r.RequestNonce}, key)
}
func responseProbeMAC(r gpuProbeResponse, key []byte) string {
	return probeMAC(probeResponseDomain, map[string]any{"schema_version": r.SchemaVersion, "reference_id": r.ReferenceID, "request_nonce": r.RequestNonce, "profile_sha256": r.ProfileSHA256, "baseline_sha256": r.BaselineSHA256, "model_alias": r.ModelAlias, "expected_model_sha256": r.ExpectedModelSHA256, "output": r.Output}, key)
}
func verifyProbeMAC(got, want string) bool {
	return gpuHex64.MatchString(got) && want != "" && hmac.Equal([]byte(got), []byte(want))
}

// Exact member names, duplicate rejection, UTF-8 and null rejection are part of
// the wire contract; encoding/json's case-insensitive struct matching is not.
func decodeProbeJSON(data []byte, into any, fields ...string) error {
	if err := evidence.StrictJSON(data, into); err != nil {
		return fmt.Errorf("invalid probe JSON")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil || len(obj) != len(fields) {
		return fmt.Errorf("invalid probe members")
	}
	for _, name := range fields {
		v, ok := obj[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("invalid probe member")
		}
	}
	return nil
}

var gpuProbeModelFilename = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*\.gguf$`)

func validProbeReference(ref SentinelRef, b *Baseline) bool {
	name := ref.ModelFilename
	return gpuProbeID.MatchString(ref.Name) && utf8.ValidString(ref.Input) && utf8.ValidString(ref.Expected) && len(ref.Input) > 0 && len(ref.Input) <= 4096 && len(ref.Expected) > 0 && len(ref.Expected) <= maxProbeOutput &&
		gpuProbeModelFilename.MatchString(name) && len(name) <= 255 && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\,\x00\r\n") && strings.HasSuffix(name, ".gguf") && utf8.ValidString(name) && gpuHex64.MatchString(ref.ModelSHA256) && b != nil && b.TensorHashes[name] == ref.ModelSHA256
}
func probeReferences(b *Baseline) (map[string]SentinelRef, error) {
	if !baselineCoversGPUProbe(b, ProbeSentinelInfer) {
		return nil, fmt.Errorf("approved probe baseline unavailable")
	}
	refs := make(map[string]SentinelRef, len(b.SentinelRefs))
	for _, r := range b.SentinelRefs {
		if _, ok := refs[r.Name]; ok {
			return nil, fmt.Errorf("duplicate reference identity")
		}
		refs[r.Name] = r
	}
	return refs, nil
}

// Policy root fields unrelated to GPU are deliberately ignored. All YAML nodes
// still undergo duplicate, alias, depth, and document checks before extraction.
func decodeGPUProbePolicySubset(data []byte) (string, string, string, error) {
	if !utf8.Valid(data) {
		return "", "", "", fmt.Errorf("invalid protected policy")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if dec.Decode(&doc) != nil || len(doc.Content) != 1 {
		return "", "", "", fmt.Errorf("invalid protected policy")
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return "", "", "", fmt.Errorf("multiple policy documents")
	}
	var walk func(*yaml.Node, int) bool
	walk = func(n *yaml.Node, depth int) bool {
		if depth > 16 || n.Kind == yaml.AliasNode {
			return false
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] {
					return false
				}
				seen[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&doc, 0) {
		return "", "", "", fmt.Errorf("invalid protected policy nodes")
	}
	get := func(n *yaml.Node, key string) *yaml.Node {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
		return nil
	}
	scalar := func(n *yaml.Node) string {
		if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
			return ""
		}
		return n.Value
	}
	root := doc.Content[0]
	ver := get(root, "version")
	gpu := get(root, "gpu")
	runtime := get(gpu, "runtime")
	mode := scalar(get(gpu, "mode"))
	ph := scalar(get(runtime, "profile_sha256"))
	bh := scalar(get(runtime, "baseline_sha256"))
	if ver == nil || ver.Tag != "!!int" || ver.Value != "1" || (mode != "required" && mode != "optional" && mode != "no_gpu") {
		return "", "", "", fmt.Errorf("GPU probe policy unavailable or not applicable")
	}
	return mode, ph, bh, nil
}
func decodeGPUProbePolicy(data []byte) (string, string, string, error) {
	mode, ph, bh, err := decodeGPUProbePolicySubset(data)
	if err != nil || mode == "no_gpu" || !gpuHex64.MatchString(ph) || !gpuHex64.MatchString(bh) {
		return "", "", "", fmt.Errorf("GPU probe policy unavailable or not applicable")
	}
	return mode, ph, bh, nil
}
func cmdPolicyEnabled() {
	data, err := readGPUEvidenceFile(nativeProbePolicy, 64<<10, false)
	if err != nil {
		os.Exit(255)
	}
	mode, _, _, err := decodeGPUProbePolicySubset(data)
	if err != nil {
		os.Exit(255)
	}
	if mode == "no_gpu" {
		os.Exit(1)
	}
}

func loadGPUProbePins() (string, string, error) {
	data, err := readGPUEvidenceFile(nativeProbePolicy, 64<<10, false)
	if err != nil {
		return "", "", err
	}
	_, ph, bh, err := decodeGPUProbePolicy(data)
	return ph, bh, err
}

// NewGPUProbeClient carries only the shared monitor-adapter key. The backend
// credential is absent from this type and never crosses the probe protocol.
type GPUProbeClient struct {
	endpoint                  string
	key                       []byte
	profileHash, baselineHash string
	refs                      map[string]SentinelRef
	http                      *http.Client
}

func NewGPUProbeClient(endpoint, profileHash, baselineHash string, b *Baseline, key []byte) (*GPUProbeClient, error) {
	if endpoint != nativeProbeOrigin {
		return nil, fmt.Errorf("GPU probe origin is not the native adapter")
	}
	return newGPUProbeClient(endpoint, profileHash, baselineHash, b, key)
}
func newGPUProbeClient(endpoint, ph, bh string, b *Baseline, key []byte) (*GPUProbeClient, error) {
	if !numericLoopbackOrigin(endpoint) || !gpuHex64.MatchString(ph) || !gpuHex64.MatchString(bh) || len(key) != 32 {
		return nil, fmt.Errorf("invalid GPU probe client identity")
	}
	refs, err := probeReferences(b)
	if err != nil {
		return nil, err
	}
	return &GPUProbeClient{endpoint: endpoint, key: append([]byte(nil), key...), profileHash: ph, baselineHash: bh, refs: refs, http: boundedProbeHTTP()}, nil
}
func numericLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.ForceQuery {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func boundedProbeHTTP() *http.Client {
	return &http.Client{Timeout: probeExchangeTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: probeExchangeTimeout, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}}
}
func (c *GPUProbeClient) Probe(ctx context.Context, referenceID string) (string, error) {
	ref, ok := c.refs[referenceID]
	if !ok {
		return "", fmt.Errorf("unapproved reference")
	}
	ctx, cancel := context.WithTimeout(ctx, probeExchangeTimeout)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("probe entropy unavailable")
	}
	req := gpuProbeRequest{SchemaVersion: 1, ReferenceID: referenceID, RequestNonce: hex.EncodeToString(nonce)}
	req.RequestMAC = requestProbeMAC(req, c.key)
	data, _ := json.Marshal(req)
	raw, err := boundedProbeRequest(ctx, c.http, http.MethodPost, c.endpoint+"/v1/probe", "", data, maxProbeBody)
	if err != nil {
		return "", err
	}
	var response gpuProbeResponse
	if decodeProbeJSON(raw, &response, "schema_version", "reference_id", "request_nonce", "profile_sha256", "baseline_sha256", "model_alias", "expected_model_sha256", "output", "response_mac") != nil || response.SchemaVersion != 1 || response.ReferenceID != referenceID || response.RequestNonce != req.RequestNonce || response.ProfileSHA256 != c.profileHash || response.BaselineSHA256 != c.baselineHash || response.ModelAlias != ref.ModelFilename || response.ExpectedModelSHA256 != ref.ModelSHA256 || len(response.Output) > maxProbeOutput || !verifyProbeMAC(response.ResponseMAC, responseProbeMAC(response, c.key)) {
		return "", fmt.Errorf("GPU probe source or binding invalid")
	}
	return response.Output, nil
}
func boundedProbeRequest(ctx context.Context, client *http.Client, method, endpoint, token string, data []byte, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("probe request unavailable")
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probe exchange unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return nil, fmt.Errorf("probe endpoint refused exchange")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, fmt.Errorf("probe response exceeds bounds or is incomplete")
	}
	return body, nil
}
func configureNativeGPUProbeClient(r *ProbeRunner, ph, bh string) error {
	live := false
	for _, pc := range r.profile.Probes {
		if pc.Enabled && (pc.Type == ProbeSentinelInfer || pc.Type == ProbeReferenceDrift) {
			live = true
		}
	}
	if !live {
		return nil
	}
	approvedPH, approvedBH, err := loadGPUProbePins()
	if err != nil {
		return err
	}
	if ph != approvedPH || bh != approvedBH || r.profile.BaselineFile != nativeProbeBaseline {
		return fmt.Errorf("GPU probe protected inputs are not approved")
	}
	for _, pc := range r.profile.Probes {
		if pc.Enabled && (pc.Type == ProbeSentinelInfer || pc.Type == ProbeReferenceDrift) && pc.Settings["inference_url"] != "" && pc.Settings["inference_url"] != nativeProbeOrigin {
			return fmt.Errorf("GPU probe override is not approved")
		}
	}
	key, err := loadGPUAttestationKey(os.Getenv("GPU_PROBE_KEY_PATH"))
	if err != nil {
		return err
	}
	r.probeClient, err = NewGPUProbeClient(r.profile.InferenceURL, ph, bh, r.baseline, key)
	return err
}

type gpuProbeServer struct {
	key                         []byte
	profileHash, baselineHash   string
	refs                        map[string]SentinelRef
	backendOrigin, backendToken string
	http                        *http.Client
	requests                    chan struct{}
	mu                          sync.Mutex
	nonces                      map[string]time.Time
	now                         func() time.Time
}

func newGPUProbeServer(ph, bh string, b *Baseline, key []byte, token string) (*gpuProbeServer, error) {
	if !gpuHex64.MatchString(ph) || !gpuHex64.MatchString(bh) || len(key) != 32 || !gpuHex64.MatchString(token) {
		return nil, fmt.Errorf("invalid probe server credentials or identity")
	}
	backendKey, _ := hex.DecodeString(token)
	if hmac.Equal(key, backendKey) {
		return nil, fmt.Errorf("probe and backend credentials must be distinct")
	}
	refs, err := probeReferences(b)
	if err != nil {
		return nil, err
	}
	return &gpuProbeServer{key: append([]byte(nil), key...), profileHash: ph, baselineHash: bh, refs: refs, backendOrigin: "http://127.0.0.1:8465", backendToken: token, http: boundedProbeHTTP(), requests: make(chan struct{}, 2), nonces: map[string]time.Time{}, now: time.Now}, nil
}
func (s *gpuProbeServer) reserve(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, t := range s.nonces {
		if now.Sub(t) >= 5*time.Minute {
			delete(s.nonces, k)
		}
	}
	if _, seen := s.nonces[nonce]; seen || len(s.nonces) >= 256 {
		return false
	}
	s.nonces[nonce] = now
	return true
}
func (s *gpuProbeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/probe" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	var req gpuProbeRequest
	if err != nil || decodeProbeJSON(data, &req, "schema_version", "reference_id", "request_nonce", "request_mac") != nil || req.SchemaVersion != 1 || !gpuProbeID.MatchString(req.ReferenceID) || !gpuHex64.MatchString(req.RequestNonce) || !verifyProbeMAC(req.RequestMAC, requestProbeMAC(req, s.key)) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ref, ok := s.refs[req.ReferenceID]
	if !ok {
		http.Error(w, "unapproved reference", http.StatusBadRequest)
		return
	}
	if !s.reserve(req.RequestNonce) {
		http.Error(w, "probe budget unavailable", http.StatusTooManyRequests)
		return
	}
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		http.Error(w, "probe busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), probeExchangeTimeout)
	defer cancel()
	output, err := s.complete(ctx, ref)
	if err != nil {
		http.Error(w, "probe unavailable", http.StatusServiceUnavailable)
		return
	}
	response := gpuProbeResponse{SchemaVersion: 1, ReferenceID: req.ReferenceID, RequestNonce: req.RequestNonce, ProfileSHA256: s.profileHash, BaselineSHA256: s.baselineHash, ModelAlias: ref.ModelFilename, ExpectedModelSHA256: ref.ModelSHA256, Output: output}
	response.ResponseMAC = responseProbeMAC(response, s.key)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
func (s *gpuProbeServer) checkModel(ctx context.Context, ref SentinelRef) error {
	data, err := boundedProbeRequest(ctx, s.http, http.MethodGet, s.backendOrigin+"/v1/models", s.backendToken, nil, maxProbeBody)
	if err != nil {
		return err
	}
	// Backend model objects contain provider metadata; validate JSON structure and
	// duplicates first, then extract the sole exact enrolled alias.
	var all map[string]json.RawMessage
	if evidence.StrictJSON(data, &all) != nil {
		return fmt.Errorf("backend model identity unavailable")
	}
	var models struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &models) != nil || len(models.Data) != 1 || models.Data[0].ID != ref.ModelFilename {
		return fmt.Errorf("backend model identity mismatch")
	}
	return nil
}
func (s *gpuProbeServer) complete(ctx context.Context, ref SentinelRef) (string, error) {
	if err := s.checkModel(ctx, ref); err != nil {
		return "", err
	}
	data, _ := json.Marshal(map[string]any{"prompt": ref.Input, "n_predict": 64, "temperature": 0, "seed": 42, "stream": false})
	raw, err := boundedProbeRequest(ctx, s.http, http.MethodPost, s.backendOrigin+"/completion", s.backendToken, data, maxProbeBody)
	if err != nil {
		return "", err
	}
	var obj map[string]json.RawMessage
	if evidence.StrictJSON(raw, &obj) != nil {
		return "", fmt.Errorf("backend completion unavailable")
	}
	content, ok := obj["content"]
	var output string
	if !ok || bytes.Equal(bytes.TrimSpace(content), []byte("null")) || json.Unmarshal(content, &output) != nil || len(output) > maxProbeOutput {
		return "", fmt.Errorf("backend output invalid")
	}
	if err := s.checkModel(ctx, ref); err != nil {
		return "", err
	}
	return output, nil
}
func cmdProbeServer() {
	approvedPH, approvedBH, err := loadGPUProbePins()
	if err != nil {
		log.Fatal("GPU probe approved policy unavailable")
	}
	profile, baseline, ph, bh, err := loadGPUProducerInputs(nativeProbeProfile)
	if err != nil || profile == nil || profile.Version != 1 || profile.BaselineFile != nativeProbeBaseline || profile.InferenceURL != nativeProbeOrigin || ph != approvedPH || bh != approvedBH {
		log.Fatal("GPU probe protected enrollment unavailable")
	}
	key, err := loadGPUAttestationKey(os.Getenv("GPU_PROBE_KEY_PATH"))
	if err != nil {
		log.Fatal("GPU probe shared credential unavailable")
	}
	tokenData, err := readGPUEvidenceFile(os.Getenv("INFERENCE_PROBE_TOKEN_PATH"), 65, true)
	if err != nil {
		log.Fatal("GPU probe backend credential unavailable")
	}
	token := strings.TrimSuffix(string(tokenData), "\n")
	if len(tokenData) != 64 && len(tokenData) != 65 {
		log.Fatal("GPU probe backend credential invalid")
	}
	handler, err := newGPUProbeServer(ph, bh, baseline, key, token)
	if err != nil {
		log.Fatal("GPU probe server unavailable")
	}
	server := &http.Server{Addr: "127.0.0.1:8497", Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("GPU probe listener unavailable")
	}
}

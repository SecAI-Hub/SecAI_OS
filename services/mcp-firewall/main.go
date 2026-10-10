package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- metrics ----------

var (
	metricEvals          atomic.Int64
	metricAllowed        atomic.Int64
	metricDenied         atomic.Int64
	metricRedacted       atomic.Int64
	metricApproval       atomic.Int64
	metricHTTPReqs       atomic.Int64
	errCompletionReceipt = errors.New("receipt is not executable")
	errCompletionSession = errors.New("session binding is invalid")
	errCompletionAudit   = errors.New("completion audit failed")
)

type firewallRuntime struct {
	policy *FirewallPolicy
	engine *PolicyEngine
	digest string
}

// ---------- main ----------

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe()
	case "evaluate":
		cmdEvaluate()
	case "validate":
		cmdValidate()
	case "audit":
		cmdAudit()
	case "keygen":
		cmdKeygen()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mcp-firewall — default-deny MCP security gateway

Usage:
  mcp-firewall serve      [-policy FILE]    Run as HTTP daemon
  mcp-firewall evaluate   [-policy FILE]    Evaluate request from stdin
  mcp-firewall validate   [-policy FILE]    Validate policy file
  mcp-firewall audit      [-log FILE]       Verify audit chain integrity
  mcp-firewall keygen     [-out PREFIX]     Generate Ed25519 signing keypair

Environment:
  MCP_FIREWALL_POLICY    Path to policy YAML (default: policies/default-policy.yaml)
  SERVICE_TOKEN_PATH     Compatibility evaluator+observer token file
  ADMIN_TOKEN_PATH       Compatibility administrator-only token file
  CREDENTIALS_CONFIG_PATH  Optional absolute scoped-credential YAML path
  BIND_ADDR              Loopback listen address (default: policy daemon.bind_addr)
  AUDIT_LOG              Path to JSONL audit log
  SIGNING_KEY_PATH       Path to base64-encoded Ed25519 private key
`)
}

// ---------- config helpers ----------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func policyPath() string {
	path := envOr("MCP_FIREWALL_POLICY", "policies/default-policy.yaml")
	args := os.Args[2:]
	for i, arg := range args {
		if arg == "-policy" && i+1 < len(args) {
			path = args[i+1]
		}
	}
	return path
}

func loadSigningKey(configuredPath string) (ed25519.PrivateKey, error) {
	path := envOr("SIGNING_KEY_PATH", configuredPath)
	if path == "" {
		return nil, fmt.Errorf("signing key path is not configured")
	}
	data, err := readTrustedCredentialFile(path, "signing key", 4096, 0o077)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	keyText := strings.TrimSpace(string(data))
	// Native appliances provision canonical 256-bit seeds alongside other
	// credentials. The existing base64 private-key format remains supported.
	if seed, err := hex.DecodeString(keyText); err == nil && len(seed) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(seed), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key is not a valid Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func loadTokenCredential(envName, fallbackPath, label string) (string, error) {
	path := envOr(envName, fallbackPath)
	data, err := readTrustedCredentialFile(path, label, 4096, 0o077)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s is empty", label)
	}
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("%s must be at least 32 bytes without whitespace", label)
	}
	return token, nil
}

func loadServiceToken() (string, error) {
	return loadTokenCredential("SERVICE_TOKEN_PATH", "/run/secure-ai/service-token", "service token")
}

func loadAdminToken() (string, error) {
	return loadTokenCredential("ADMIN_TOKEN_PATH", "/run/secure-ai/admin-token", "admin token")
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	return requireRole(w, r, roleAdministrator)
}

// ---------- CLI commands ----------

func cmdServe() {
	policy, err := LoadPolicy(policyPath())
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	policyDigest, err := computePolicyDigest(policy)
	if err != nil {
		log.Fatalf("failed to digest policy: %v", err)
	}
	var runtime atomic.Pointer[firewallRuntime]
	runtime.Store(&firewallRuntime{policy: policy, engine: NewPolicyEngine(policy), digest: policyDigest})
	taintState := NewTaintState()
	var privKey ed25519.PrivateKey
	if policy.Audit.SignReports {
		privKey, err = loadSigningKey(policy.Audit.KeyPath)
		if err != nil {
			log.Fatalf("signed audit receipts unavailable: %v", err)
		}
	}
	credentials, err := loadCredentialSet()
	if err != nil {
		log.Fatalf("credential authentication unavailable: %v", err)
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Fatalf("session key generation failed: %v", err)
	}
	sessions, err := NewSessionBindingManager(sessionKey)
	if err != nil {
		log.Fatalf("session manager unavailable: %v", err)
	}
	var receiptVerifier *ReceiptVerifier
	if len(privKey) == ed25519.PrivateKeySize {
		receiptVerifier, err = NewReceiptVerifier(privKey.Public().(ed25519.PublicKey), policy.Audit.ReceiptAudience, policyDigest)
		if err != nil {
			log.Fatalf("receipt verifier unavailable: %v", err)
		}
	}

	auditPath := envOr("AUDIT_LOG", policy.Audit.LogPath)
	auditLog, err := NewAuditLog(auditPath, privKey, 1000)
	if err != nil {
		log.Fatalf("failed to init audit log: %v", err)
	}
	defer auditLog.Close()
	if err := auditLog.RestoreTaint(taintState); err != nil {
		log.Fatalf("security context recovery failed: %v", err)
	}
	if receiptVerifier != nil {
		if err := receiptVerifier.SeedConsumed(auditLog.ConsumedReceipts()); err != nil {
			log.Fatalf("receipt replay recovery failed: %v", err)
		}
	}

	if _, err := auditLog.RecordContext("startup", nil, nil, fmt.Sprintf("policy loaded from %s", filepath.Base(policyPath())), AuditContext{PolicyDigest: policyDigest}); err != nil {
		log.Fatalf("failed to write startup audit event: %v", err)
	}

	mux := newMCPFirewallMux(mcpHTTPDependencies{
		runtime:         &runtime,
		policyTxnMu:     &sync.RWMutex{},
		taintState:      taintState,
		privateKey:      privKey,
		sessions:        sessions,
		receiptVerifier: receiptVerifier,
		auditLog:        auditLog,
	})
	runMCPFirewallServer(policy, credentials, mux)
}

type mcpHTTPDependencies struct {
	runtime         *atomic.Pointer[firewallRuntime]
	policyTxnMu     *sync.RWMutex
	taintState      *TaintState
	privateKey      ed25519.PrivateKey
	sessions        *SessionBindingManager
	receiptVerifier *ReceiptVerifier
	auditLog        *AuditLog
	loadPolicy      func() (*FirewallPolicy, error)
}

// newMCPFirewallMux is the single production route/handler constructor used by
// both the daemon and authorization tests.
func newMCPFirewallMux(dependencies mcpHTTPDependencies) *http.ServeMux {
	runtime := dependencies.runtime
	policyTxnMu := dependencies.policyTxnMu
	if policyTxnMu == nil {
		policyTxnMu = &sync.RWMutex{}
	}
	taintState := dependencies.taintState
	privKey := dependencies.privateKey
	sessions := dependencies.sessions
	receiptVerifier := dependencies.receiptVerifier
	auditLog := dependencies.auditLog
	loadPolicy := dependencies.loadPolicy
	if loadPolicy == nil {
		loadPolicy = func() (*FirewallPolicy, error) { return LoadPolicy(policyPath()) }
	}

	mux := http.NewServeMux()
	// A decision and its conservative taint reservation form one transaction.
	// This also prevents parallel batches from evaluating against clean context.
	var evaluationMu sync.Mutex
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !auditLog.Ready() || !taintState.Available() {
			http.Error(w, `{"status":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		writeJSONResponse(w, map[string]string{"status": "ready"})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleEvaluator) {
			return
		}

		var req EvalRequest
		if err := decodeStrictJSON(w, r, &req, 1<<20); err != nil {
			status := http.StatusBadRequest
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, `{"error":"invalid request body"}`, status)
			return
		}

		if ok, _ := sessions.Validate(req.SessionID, req.Server, req.SessionToken); !ok {
			http.Error(w, `{"error":"invalid or expired session binding"}`, http.StatusUnauthorized)
			return
		}
		evaluationMu.Lock()
		defer evaluationMu.Unlock()
		req.taintContext = principalTaintContext(authenticatedIdentity(r))
		policyTxnMu.RLock()
		defer policyTxnMu.RUnlock()
		state := runtime.Load()
		decision := state.engine.Evaluate(req, taintState)
		metricEvals.Add(1)
		countDecision(decision.Action)

		auditReq := sanitizeRequestForAudit(req)
		auditEntry, err := auditLog.RecordContext("evaluate", &decision, &auditReq, "", requestAuditContext(r, state.digest))
		if err != nil {
			log.Printf("audit write failed: %v", err)
			http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
			return
		}

		resp := map[string]interface{}{
			"decision": decision,
		}
		if !reserveDecisionTaint(taintState, authenticatedIdentity(r), decision) {
			http.Error(w, `{"error":"security context unavailable"}`, http.StatusServiceUnavailable)
			return
		}

		if state.policy.Audit.SignReports && privKey != nil {
			receipt, err := auditLog.SignReceipt(decision, req, auditEntry, ReceiptOptions{
				Audience: state.policy.Audit.ReceiptAudience, PolicyDigest: state.digest,
				TTL: time.Duration(state.policy.Audit.ReceiptTTLSeconds) * time.Second, BatchSize: 1,
			})
			if err != nil {
				http.Error(w, `{"error":"receipt service unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			resp["receipt"] = receipt
		}

		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, resp)
	})

	mux.HandleFunc("/v1/evaluate/batch", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleEvaluator) {
			return
		}

		var reqs []EvalRequest
		if err := decodeStrictJSON(w, r, &reqs, 4<<20); err != nil {
			status := http.StatusBadRequest
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, `{"error":"invalid request body"}`, status)
			return
		}
		if len(reqs) == 0 || len(reqs) > 100 {
			http.Error(w, `{"error":"batch must contain 1 to 100 requests"}`, http.StatusBadRequest)
			return
		}
		if ok, _ := sessions.ValidateBatch(reqs); !ok {
			http.Error(w, `{"error":"invalid or expired session binding"}`, http.StatusUnauthorized)
			return
		}
		evaluationMu.Lock()
		defer evaluationMu.Unlock()

		policyTxnMu.RLock()
		defer policyTxnMu.RUnlock()
		state := runtime.Load()
		decisions := make([]Decision, 0, len(reqs))
		receipts := make([]DecisionReceipt, 0, len(reqs))
		batchID, err := newOpaqueID(24)
		if err != nil {
			http.Error(w, `{"error":"receipt service unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		for index, req := range reqs {
			req.taintContext = principalTaintContext(authenticatedIdentity(r))
			d := state.engine.Evaluate(req, taintState)
			metricEvals.Add(1)
			countDecision(d.Action)
			auditReq := sanitizeRequestForAudit(req)
			auditEntry, err := auditLog.RecordContext("evaluate", &d, &auditReq, "batch="+batchID, requestAuditContext(r, state.digest))
			if err != nil {
				log.Printf("audit write failed: %v", err)
				http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			decisions = append(decisions, d)
			if !reserveDecisionTaint(taintState, authenticatedIdentity(r), d) {
				http.Error(w, `{"error":"security context unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			if state.policy.Audit.SignReports {
				receipt, err := auditLog.SignReceipt(d, req, auditEntry, ReceiptOptions{
					Audience: state.policy.Audit.ReceiptAudience, PolicyDigest: state.digest,
					TTL:     time.Duration(state.policy.Audit.ReceiptTTLSeconds) * time.Second,
					BatchID: batchID, BatchIndex: index, BatchSize: len(reqs),
				})
				if err != nil {
					http.Error(w, `{"error":"receipt service unavailable"}`, http.StatusServiceUnavailable)
					return
				}
				receipts = append(receipts, receipt)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]interface{}{"batch_id": batchID, "decisions": decisions, "receipts": receipts})
	})

	mux.HandleFunc("/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleEvaluator) {
			return
		}
		var input struct {
			Server     string `json:"server"`
			MaxCalls   int64  `json:"max_calls,omitempty"`
			TTLSeconds int64  `json:"ttl_seconds,omitempty"`
		}
		if err := decodeStrictJSON(w, r, &input, 16<<10); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, requestDecodeStatus(err))
			return
		}
		policyTxnMu.RLock()
		defer policyTxnMu.RUnlock()
		state := runtime.Load()
		if !safePathIdentifier(input.Server) || state.engine.serverIndex[input.Server] == nil {
			http.Error(w, `{"error":"unknown server"}`, http.StatusBadRequest)
			return
		}
		if input.MaxCalls == 0 {
			input.MaxCalls = 100
		}
		if input.TTLSeconds == 0 {
			input.TTLSeconds = 900
		}
		if input.MaxCalls < 1 || input.MaxCalls > 10_000 || input.TTLSeconds < 30 || input.TTLSeconds > 86400 {
			http.Error(w, `{"error":"session limits out of range"}`, http.StatusBadRequest)
			return
		}
		binding, err := sessions.Create(input.Server, input.MaxCalls, input.TTLSeconds)
		if err != nil {
			http.Error(w, `{"error":"session service unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		if _, err := auditLog.RecordContext("session-created", nil, nil,
			fmt.Sprintf("session=%s server=%s", auditFingerprint(binding.SessionID), sanitizeAuditText(binding.ServerName)),
			requestAuditContext(r, state.digest)); err != nil {
			sessions.Revoke(binding.SessionID)
			http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		writeJSONResponse(w, binding)
	})

	mux.HandleFunc("/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		sessionID := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
		if !safePathIdentifier(sessionID) {
			http.Error(w, `{"error":"invalid session identifier"}`, http.StatusBadRequest)
			return
		}
		policyTxnMu.RLock()
		defer policyTxnMu.RUnlock()
		state := runtime.Load()
		if _, err := auditLog.RecordContext("session-revoked", nil, nil, "session="+auditFingerprint(sessionID), requestAuditContext(r, state.digest)); err != nil {
			http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		sessions.Revoke(sessionID)
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]string{"status": "revoked"})
	})

	mux.HandleFunc("/v1/executions/complete", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleEvaluator) {
			return
		}
		var input struct {
			Receipt      DecisionReceipt `json:"receipt"`
			SessionToken string          `json:"session_token"`
			Success      bool            `json:"success"`
		}
		if err := decodeStrictJSON(w, r, &input, 512<<10); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, requestDecodeStatus(err))
			return
		}
		policyTxnMu.RLock()
		defer policyTxnMu.RUnlock()
		state := runtime.Load()
		applied, err := completeExecution(input.Receipt, input.SessionToken, input.Success, state.digest,
			sessions, receiptVerifier, auditLog, taintState, authenticatedIdentity(r))
		if err != nil {
			switch {
			case errors.Is(err, errCompletionSession):
				http.Error(w, `{"error":"invalid or expired session binding"}`, http.StatusUnauthorized)
			case errors.Is(err, errCompletionAudit):
				http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
			default:
				http.Error(w, `{"error":"invalid, expired, or replayed receipt"}`, http.StatusForbidden)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]any{"status": "recorded", "taint_applied": applied})
	})

	mux.HandleFunc("/v1/servers", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		type serverSummary struct {
			Name       string   `json:"name"`
			TrustLevel string   `json:"trust_level"`
			Tools      []string `json:"tools"`
		}

		state := runtime.Load()
		servers := make([]serverSummary, 0, len(state.policy.Servers))
		for _, s := range state.policy.Servers {
			ss := serverSummary{Name: s.Name, TrustLevel: s.TrustLevel}
			for _, t := range s.AllowedTools {
				ss.Tools = append(ss.Tools, t.Name)
			}
			servers = append(servers, ss)
		}

		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, servers)
	})

	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		state := runtime.Load()
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]interface{}{
			"version":          state.policy.Version,
			"policy_digest":    state.digest,
			"default_action":   state.policy.DefaultAction,
			"servers":          len(state.policy.Servers),
			"global_rules":     len(state.policy.GlobalRules),
			"taint_rules":      len(state.policy.TaintRules),
			"redaction":        state.policy.Redaction.Enabled,
			"receipt_audience": state.policy.Audit.ReceiptAudience,
			"receipt_key_id":   receiptKeyID(privKey.Public().(ed25519.PublicKey)),
		})
	})

	mux.HandleFunc("/v1/taint/", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		sessionID := strings.TrimPrefix(r.URL.Path, "/v1/taint/")
		if !safePathIdentifier(sessionID) {
			http.Error(w, `{"error":"session_id required"}`, http.StatusBadRequest)
			return
		}

		if r.Method == http.MethodDelete {
			if !requireAdmin(w, r) {
				return
			}
			http.Error(w, `{"error":"taint is monotonic; provision a distinct trusted identity for a new security context"}`, http.StatusConflict)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		entries := taintState.Entries(principalTaintContext(authenticatedIdentity(r)))
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]interface{}{
			"session_id": sessionID,
			"scope":      "credential-identity",
			"taint":      entries,
		})
	})

	mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		entries := auditLog.Entries(100)
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, entries)
	})

	mux.HandleFunc("/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		entries := auditLog.Entries(0)
		valid, failIdx := VerifyChain(entries)

		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]interface{}{
			"valid":      valid,
			"entries":    len(entries),
			"fail_index": failIdx,
		})
	})

	mux.HandleFunc("/v1/reload", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireAdmin(w, r) {
			return
		}

		newPolicy, err := loadPolicy()
		if err != nil {
			log.Printf("policy reload failed: %v", err)
			http.Error(w, `{"error":"reload failed"}`, http.StatusInternalServerError)
			return
		}
		newDigest, err := computePolicyDigest(newPolicy)
		if err != nil {
			http.Error(w, `{"error":"reload failed"}`, http.StatusInternalServerError)
			return
		}

		// The transition record and state publication are one exclusive
		// transaction. Evaluations hold the shared side through their own audit
		// append, so audit order always describes the active digest exactly.
		policyTxnMu.Lock()
		defer policyTxnMu.Unlock()
		currentState := runtime.Load()
		current := currentState.policy
		if newPolicy.Audit.LogPath != current.Audit.LogPath ||
			newPolicy.Audit.SignReports != current.Audit.SignReports ||
			newPolicy.Audit.KeyPath != current.Audit.KeyPath ||
			newPolicy.Audit.ReceiptAudience != current.Audit.ReceiptAudience ||
			newPolicy.Audit.ReceiptTTLSeconds != current.Audit.ReceiptTTLSeconds {
			http.Error(w, `{"error":"audit configuration changes require restart"}`, http.StatusConflict)
			return
		}
		if _, err := auditLog.RecordContext("reload", nil, nil, "policy reloaded", AuditContext{
			Identity: authenticatedIdentity(r), OldPolicyDigest: currentState.digest, NewPolicyDigest: newDigest,
		}); err != nil {
			log.Printf("audit write failed: %v", err)
			http.Error(w, `{"error":"audit service unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		runtime.Store(&firewallRuntime{policy: newPolicy, engine: NewPolicyEngine(newPolicy), digest: newDigest})

		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]string{"status": "policy reloaded"})
	})

	mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, roleObserver) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSONResponse(w, map[string]int64{
			"evaluations_total":     metricEvals.Load(),
			"allowed_total":         metricAllowed.Load(),
			"denied_total":          metricDenied.Load(),
			"redacted_total":        metricRedacted.Load(),
			"approval_needed_total": metricApproval.Load(),
			"http_requests_total":   metricHTTPReqs.Load(),
		})
	})

	return mux
}

func runMCPFirewallServer(policy *FirewallPolicy, credentials *credentialSet, mux *http.ServeMux) {
	addr := os.Getenv("BIND_ADDR")
	if addr == "" {
		addr = policy.Daemon.BindAddr
	}
	if addr == "" {
		addr = "127.0.0.1:8510"
	}
	if err := validateBindAddress(addr); err != nil {
		log.Fatalf("invalid bind address: %v", err)
	}

	log.Printf("mcp-firewall listener started (default-deny policy, servers=%d)", len(policy.Servers))

	server := &http.Server{
		Addr:              addr,
		Handler:           authenticatedCredentialHandler(mux, credentials),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down mcp-firewall...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("mcp-firewall stopped")
}

func cmdEvaluate() {
	policy, err := LoadPolicy(policyPath())
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	engine := NewPolicyEngine(policy)
	taintState := NewTaintState()

	var req EvalRequest
	if err := decodeStrictReader(os.Stdin, &req, 1<<20); err != nil {
		log.Fatalf("invalid request: %v", err)
	}

	decision := engine.Evaluate(req, taintState)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]interface{}{"decision": decision}); err != nil {
		log.Fatalf("encode decision: %v", err)
	}

	if decision.Action == "deny" {
		os.Exit(2)
	}
	if decision.Action == "require-approval" {
		os.Exit(3)
	}
}

func cmdValidate() {
	policy, err := LoadPolicy(policyPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}

	issues := validatePolicy(policy)
	if len(issues) > 0 {
		fmt.Println("Policy validation warnings:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
	}

	fmt.Printf("Policy valid: version=%d servers=%d global_rules=%d taint_rules=%d default=%s\n",
		policy.Version, len(policy.Servers), len(policy.GlobalRules),
		len(policy.TaintRules), policy.DefaultAction)
}

func cmdAudit() {
	logPath := envOr("AUDIT_LOG", "")
	args := os.Args[2:]
	for i, arg := range args {
		if arg == "-log" && i+1 < len(args) {
			logPath = args[i+1]
		}
	}

	if logPath == "" {
		log.Fatal("audit log path required (use -log or AUDIT_LOG env)")
	}

	_, count, _, err := loadAuditEntries(logPath, 1)
	if err != nil {
		fmt.Printf("CHAIN BROKEN: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("Audit chain valid: %d entries\n", count)
}

func cmdKeygen() {
	prefix := "mcp-firewall"
	args := os.Args[2:]
	for i, arg := range args {
		if arg == "-out" && i+1 < len(args) {
			prefix = args[i+1]
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen failed: %v", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	privatePath := prefix + ".key"
	publicPath := prefix + ".pub"
	if err := writeExclusiveKey(privatePath, []byte(privB64+"\n"), 0o600); err != nil {
		log.Fatalf("write private key: %v", err)
	}
	if err := writeExclusiveKey(publicPath, []byte(pubB64+"\n"), 0o644); err != nil {
		if removeErr := os.Remove(privatePath); removeErr != nil { // #nosec G703 -- path was created exclusively by this command
			log.Printf("warning: remove incomplete private key: %v", removeErr)
		}
		log.Fatalf("write public key: %v", err)
	}

	fmt.Printf("Keys written: %s.key (private), %s.pub (public)\n", prefix, prefix)
	fmt.Printf("Set SIGNING_KEY_PATH=%s for signed receipts\n", privatePath)
}

func writeExclusiveKey(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304,G703 -- explicit local CLI output, exclusive creation prevents overwrite
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path) // #nosec G703 -- removes only the file this function just created exclusively
		}
	}()
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// ---------- helpers ----------

func writeJSONResponse(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("response encoding failed")
	}
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func requestDecodeStatus(err error) int {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func decodeStrictReader(reader io.Reader, dst any, limit int64) error {
	limited := &io.LimitedReader{R: reader, N: limit + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("input exceeds %d-byte limit", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("input must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func sanitizeRequestForAudit(req EvalRequest) EvalRequest {
	clean := req
	clean.SessionToken = ""
	clean.Server = auditFingerprint(clean.Server)
	if !contains([]string{"tools/call", "tools/list", "resources/read", "resources/list", "prompts/list"}, clean.Method) {
		clean.Method = "invalid"
	}
	clean.Tool = auditFingerprint(clean.Tool)
	if clean.ServerFingerprint != "" {
		clean.ServerFingerprint = fmt.Sprintf("[redacted len=%d sha256=%s]", len(clean.ServerFingerprint), auditFingerprint(clean.ServerFingerprint))
	}
	if req.SessionID != "" {
		clean.SessionID = auditFingerprint(req.SessionID)
	}
	if req.RequestID != "" {
		clean.RequestID = auditFingerprint(req.RequestID)
	}
	if req.Resource != "" {
		clean.Resource = fmt.Sprintf("[redacted len=%d]", len(req.Resource))
	}
	if len(req.Arguments) > 0 {
		keys := make([]string, 0, len(req.Arguments))
		for key := range req.Arguments {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 128 {
			keys = keys[:128]
		}
		clean.Arguments = make(map[string]string, len(keys))
		for index, key := range keys {
			value := req.Arguments[key]
			clean.Arguments[fmt.Sprintf("argument_%d", index)] = fmt.Sprintf("[redacted len=%d]", len(value))
		}
	}
	return clean
}

func sanitizeDecisionForAudit(decision Decision) Decision {
	clean := decision
	clean.Action = sanitizeAuditText(clean.Action)
	clean.Server = auditFingerprint(clean.Server)
	clean.Tool = auditFingerprint(clean.Tool)
	if clean.Resource != "" {
		clean.Resource = fmt.Sprintf("[redacted len=%d]", len(clean.Resource))
	}
	clean.Rule = auditFingerprint(clean.Rule)
	clean.Reason = ""
	if clean.SessionID != "" {
		clean.SessionID = auditFingerprint(clean.SessionID)
	}
	if clean.RequestID != "" {
		clean.RequestID = auditFingerprint(clean.RequestID)
	}
	clean.Evidence = nil
	// Labels come from validated administrator policy, never from request data.
	// Keep their exact identity so restart recovery enforces the same rule.
	clean.TaintApplied = append([]string(nil), decision.TaintApplied...)
	clean.TaintActive = append([]string(nil), decision.TaintActive...)
	clean.RedactedArgs = nil
	return clean
}

func sanitizeAuditStrings(values []string, limit int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	clean := make([]string, len(values))
	for i, value := range values {
		clean[i] = sanitizeAuditText(value)
	}
	return clean
}

func sanitizeAuditText(value string) string {
	const maxAuditString = 4096
	value = redactString(value, []string{"all"})
	if len(value) > maxAuditString {
		value = value[:maxAuditString] + "[TRUNCATED]"
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, value)
}

func auditFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func newOpaqueID(size int) (string, error) {
	if size < 16 || size > 64 {
		return "", fmt.Errorf("opaque identifier size out of range")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func computePolicyDigest(policy *FirewallPolicy) (string, error) {
	data, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("mcp-firewall/policy/v1\x00"), data...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func safePathIdentifier(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n/\\")
}

func validateBindAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback && os.Getenv("ALLOW_REMOTE_BIND") != "true" {
		return fmt.Errorf("non-loopback bind requires ALLOW_REMOTE_BIND=true and an authenticated TLS reverse proxy")
	}
	return nil
}

func countDecision(action string) {
	switch action {
	case "allow":
		metricAllowed.Add(1)
	case "deny":
		metricDenied.Add(1)
	case "redact":
		metricRedacted.Add(1)
	case "require-approval":
		metricApproval.Add(1)
	}
}

func completeExecution(receipt DecisionReceipt, sessionToken string, success bool, policyDigest string,
	sessions *SessionBindingManager, verifier *ReceiptVerifier, auditLog *AuditLog, taintState *TaintState, actors ...string,
) ([]string, error) {
	if sessions == nil || verifier == nil || auditLog == nil || taintState == nil ||
		receipt.Decision.Action != "allow" || !auditLog.ContainsDecision(receipt.AuditSequence, receipt.AuditHash) {
		return nil, errCompletionReceipt
	}
	actor := ""
	if len(actors) > 0 {
		actor = actors[0]
	}
	// Version 2 receipts carry a signed binding-token digest and identity, so a
	// legitimate completion can survive a daemon restart without resurrecting an
	// execution capability. The consumed-nonce journal still rejects replay.
	if subtle.ConstantTimeCompare([]byte(receipt.SessionTokenHash), []byte(receiptReplayKey(sessionToken))) != 1 || receipt.Identity != actor {
		return nil, errCompletionSession
	}
	reservation, err := verifier.ReserveForPolicy(receipt, policyDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCompletionReceipt, err)
	}
	if _, err := auditLog.RecordCompletion(receipt, success, actors...); err != nil {
		verifier.Release(reservation)
		return nil, fmt.Errorf("%w: %v", errCompletionAudit, err)
	}
	verifier.Commit(reservation)
	applied := []string(nil)
	if success {
		for _, label := range receipt.Decision.TaintApplied {
			contextID := principalTaintContext(actor)
			if actor == "" {
				contextID = receipt.Decision.SessionID
			}
			taintState.Add(contextID, label, receipt.Decision.Server+"/"+receipt.Decision.Tool)
			applied = append(applied, label)
		}
	}
	return applied, nil
}

func validatePolicy(policy *FirewallPolicy) []string {
	var issues []string

	if policy.Version == 0 {
		issues = append(issues, "version not set")
	}
	if policy.DefaultAction != "deny" && policy.DefaultAction != "allow" {
		issues = append(issues, fmt.Sprintf("unusual default_action: %q (expected deny or allow)", policy.DefaultAction))
	}
	if policy.DefaultAction == "allow" {
		issues = append(issues, "default_action=allow violates deny-by-default principle")
	}
	if len(policy.Servers) == 0 {
		issues = append(issues, "no servers defined; all MCP traffic will hit default action")
	}

	for _, s := range policy.Servers {
		if s.TrustLevel == "" {
			issues = append(issues, fmt.Sprintf("server %q has no trust_level", s.Name))
		}
		for _, t := range s.AllowedTools {
			if t.Action == "" {
				issues = append(issues, fmt.Sprintf("server %q tool %q has no action", s.Name, t.Name))
			}
		}
	}

	return issues
}

// Unused but kept for interface parity with other services.
var _ = time.Now

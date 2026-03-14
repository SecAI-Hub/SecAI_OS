package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- metrics ----------

var (
	metricEvals      atomic.Int64
	metricAllowed    atomic.Int64
	metricDenied     atomic.Int64
	metricRedacted   atomic.Int64
	metricApproval   atomic.Int64
	metricHTTPReqs   atomic.Int64
)

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
  SERVICE_TOKEN          Bearer token for protected endpoints
  AUDIT_LOG              Path to JSONL audit log
  SIGNING_KEY            Base64-encoded Ed25519 private key
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
	for i, arg := range os.Args[2:] {
		if arg == "-policy" && i+1 < len(os.Args[2:])-1 {
			path = os.Args[i+3]
		}
	}
	return path
}

func loadSigningKey() ed25519.PrivateKey {
	keyStr := os.Getenv("SIGNING_KEY")
	if keyStr == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.PrivateKey(data)
}

// ---------- CLI commands ----------

func cmdServe() {
	policy, err := LoadPolicy(policyPath())
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	engine := NewPolicyEngine(policy)
	taintState := NewTaintState()
	privKey := loadSigningKey()
	token := os.Getenv("SERVICE_TOKEN")

	auditPath := envOr("AUDIT_LOG", policy.Audit.LogPath)
	auditLog, err := NewAuditLog(auditPath, privKey, 1000)
	if err != nil {
		log.Fatalf("failed to init audit log: %v", err)
	}
	defer auditLog.Close()

	auditLog.Record("startup", nil, nil, fmt.Sprintf("policy loaded from %s", policyPath()))

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req EvalRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		decision := engine.Evaluate(req, taintState)
		metricEvals.Add(1)
		countDecision(decision.Action)

		auditLog.Record("evaluate", &decision, &req, "")

		resp := map[string]interface{}{
			"decision": decision,
		}

		if policy.Audit.SignReports && privKey != nil {
			receipt := auditLog.SignReceipt(decision, req)
			resp["receipt"] = receipt
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/evaluate/batch", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var reqs []EvalRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&reqs); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		var decisions []Decision
		for _, req := range reqs {
			d := engine.Evaluate(req, taintState)
			metricEvals.Add(1)
			countDecision(d.Action)
			auditLog.Record("evaluate", &d, &req, "batch")
			decisions = append(decisions, d)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"decisions": decisions})
	})

	mux.HandleFunc("/v1/servers", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		type serverSummary struct {
			Name       string   `json:"name"`
			TrustLevel string   `json:"trust_level"`
			Tools      []string `json:"tools"`
		}

		var servers []serverSummary
		for _, s := range policy.Servers {
			ss := serverSummary{Name: s.Name, TrustLevel: s.TrustLevel}
			for _, t := range s.AllowedTools {
				ss.Tools = append(ss.Tools, t.Name)
			}
			servers = append(servers, ss)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(servers)
	})

	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":        policy.Version,
			"default_action": policy.DefaultAction,
			"servers":        len(policy.Servers),
			"global_rules":   len(policy.GlobalRules),
			"taint_rules":    len(policy.TaintRules),
			"redaction":      policy.Redaction.Enabled,
		})
	})

	mux.HandleFunc("/v1/taint/", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		sessionID := strings.TrimPrefix(r.URL.Path, "/v1/taint/")
		if sessionID == "" {
			http.Error(w, `{"error":"session_id required"}`, http.StatusBadRequest)
			return
		}

		if r.Method == http.MethodDelete {
			taintState.Clear(sessionID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
			return
		}

		entries := taintState.Entries(sessionID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id": sessionID,
			"taint":      entries,
		})
	})

	mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		entries := auditLog.Entries(100)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	mux.HandleFunc("/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		entries := auditLog.Entries(0)
		valid, failIdx := VerifyChain(entries)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
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
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		newPolicy, err := LoadPolicy(policyPath())
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"reload failed: %v"}`, err), http.StatusInternalServerError)
			return
		}

		*engine = *NewPolicyEngine(newPolicy)
		*policy = *newPolicy

		auditLog.Record("reload", nil, nil, fmt.Sprintf("policy reloaded by %s", r.RemoteAddr))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
	})

	mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"evaluations_total":     metricEvals.Load(),
			"allowed_total":         metricAllowed.Load(),
			"denied_total":          metricDenied.Load(),
			"redacted_total":        metricRedacted.Load(),
			"approval_needed_total": metricApproval.Load(),
			"http_requests_total":   metricHTTPReqs.Load(),
		})
	})

	addr := policy.Daemon.BindAddr
	if addr == "" {
		addr = "127.0.0.1:8510"
	}

	log.Printf("mcp-firewall serving on %s (default_action=%s, servers=%d)",
		addr, policy.DefaultAction, len(policy.Servers))

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
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
	server.Shutdown(shutdownCtx)
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
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		log.Fatalf("invalid request: %v", err)
	}

	decision := engine.Evaluate(req, taintState)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{"decision": decision})

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
	for i, arg := range os.Args[2:] {
		if arg == "-log" && i+1 < len(os.Args[2:])-1 {
			logPath = os.Args[i+3]
		}
	}

	if logPath == "" {
		log.Fatal("audit log path required (use -log or AUDIT_LOG env)")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		log.Fatalf("cannot read audit log: %v", err)
	}

	var entries []AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			log.Printf("warning: skipping malformed entry: %v", err)
			continue
		}
		entries = append(entries, entry)
	}

	valid, failIdx := VerifyChain(entries)
	if valid {
		fmt.Printf("Audit chain valid: %d entries\n", len(entries))
	} else {
		fmt.Printf("CHAIN BROKEN at entry %d of %d\n", failIdx, len(entries))
		os.Exit(2)
	}
}

func cmdKeygen() {
	prefix := "mcp-firewall"
	for i, arg := range os.Args[2:] {
		if arg == "-out" && i+1 < len(os.Args[2:])-1 {
			prefix = os.Args[i+3]
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen failed: %v", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	os.WriteFile(prefix+".key", []byte(privB64+"\n"), 0o600)
	os.WriteFile(prefix+".pub", []byte(pubB64+"\n"), 0o644)

	fmt.Printf("Keys written: %s.key (private), %s.pub (public)\n", prefix, prefix)
	fmt.Printf("Set SIGNING_KEY=%s for signed receipts\n", privB64)
}

// ---------- helpers ----------

func checkToken(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	provided := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
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

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type FirewallPolicy struct {
	Version       int             `yaml:"version"`
	DefaultAction string          `yaml:"default_action"`
	Rules         []Rule          `yaml:"rules"`
	Scanner       ScannerConfig   `yaml:"scanner"`
	DataDir       string          `yaml:"data_dir"`
	Daemon        DaemonConfig    `yaml:"daemon"`
	RateLimit     RateLimitCfg    `yaml:"rate_limit"`
	Retention     RetentionConfig `yaml:"retention"`
}

type DaemonConfig struct {
	BindAddr        string `yaml:"bind_addr"`
	ReadTimeoutSec  int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSec  int    `yaml:"idle_timeout_seconds"`
}

type RateLimitCfg struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   FirewallPolicy
	engine   *PolicyEngine

	docStore *DocumentStore

	auditFile     *os.File
	auditMu       sync.Mutex
	auditPath     string
	auditLastHash string

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests    atomic.Int64
	ingestRequests   atomic.Int64
	retrieveRequests atomic.Int64

	serviceToken string
)

const (
	defaultPolicyPath  = "/etc/secure-ai/policy/rag-firewall.yaml"
	defaultTokenPath   = "/run/secure-ai/service-token"
	defaultAuditPath   = "/var/lib/secure-ai/logs/rag-firewall-audit.jsonl"
	defaultDataDir     = "/var/lib/secure-ai/rag"
	defaultBindAddr    = "127.0.0.1:8500"
	defaultRPM         = 120
	maxRequestBodySize = 10 << 20 // 10 MiB (documents can be large)
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func loadPolicy() error {
	data, err := os.ReadFile(policyFilePath())
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p FirewallPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	policyMu.Lock()
	policy = p
	engine = NewPolicyEngine(p.DefaultAction, p.Rules)
	policyMu.Unlock()

	log.Printf("policy loaded: default=%s rules=%d", p.DefaultAction, len(p.Rules))
	return nil
}

func getPolicy() FirewallPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

func getEngine() *PolicyEngine {
	policyMu.RLock()
	e := engine
	policyMu.RUnlock()
	return e
}

func getDataDir() string {
	p := getPolicy()
	if p.DataDir != "" {
		return p.DataDir
	}
	return defaultDataDir
}

// ---------------------------------------------------------------------------
// Tamper-evident audit logging (hash chain)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Allowed   int    `json:"allowed,omitempty"`
	Denied    int    `json:"denied,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Hash      string `json:"hash"`
	PrevHash  string `json:"prev_hash,omitempty"`
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	idx := strings.LastIndex(auditPath, "/")
	if idx > 0 {
		os.MkdirAll(auditPath[:idx], 0750)
	}

	// Load last hash from existing audit log for chain continuity.
	if data, err := os.ReadFile(auditPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if lines[i] == "" {
				continue
			}
			var entry AuditEntry
			if err := json.Unmarshal([]byte(lines[i]), &entry); err == nil {
				auditLastHash = entry.Hash
				break
			}
		}
	}

	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: cannot open audit log: %v", err)
		return
	}
	auditFile = f
}

// computeAuditHash returns a SHA-256 digest over all fields except Hash.
func computeAuditHash(entry AuditEntry) string {
	canonical := struct {
		Timestamp string `json:"timestamp"`
		Action    string `json:"action"`
		Allowed   int    `json:"allowed,omitempty"`
		Denied    int    `json:"denied,omitempty"`
		Detail    string `json:"detail,omitempty"`
		PrevHash  string `json:"prev_hash,omitempty"`
	}{
		Timestamp: entry.Timestamp,
		Action:    entry.Action,
		Allowed:   entry.Allowed,
		Denied:    entry.Denied,
		Detail:    entry.Detail,
		PrevHash:  entry.PrevHash,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func writeAudit(entry AuditEntry) {
	if auditFile == nil {
		return
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	entry.PrevHash = auditLastHash
	entry.Hash = computeAuditHash(entry)
	auditLastHash = entry.Hash

	data, _ := json.Marshal(entry)
	auditMu.Lock()
	defer auditMu.Unlock()
	auditFile.Write(append(data, '\n'))
	auditFile.Sync()
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("service token not loaded (dev mode): %v", err)
		return
	}
	serviceToken = strings.TrimSpace(string(data))
	log.Printf("service token loaded")
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, "forbidden: invalid service token", http.StatusForbidden)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			jsonError(w, "forbidden: invalid service token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Consistent JSON error responses
// ---------------------------------------------------------------------------

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"service":   "rag-data-firewall",
		"documents": docStore.DocumentCount(),
		"chunks":    docStore.ChunkCount(),
	})
}

func handleIngest(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	ingestRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkRateLimit() {
		jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateIngestRequest(req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	pol := getPolicy()
	doc, chunks, err := docStore.Ingest(req, pol.Scanner)
	if err != nil {
		log.Printf("ingest error: %v", err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Count flagged chunks.
	flagged := 0
	for _, c := range chunks {
		if c.Scan.PromptInjection || c.Scan.RiskScore >= pol.Scanner.MinRiskToFlag {
			flagged++
		}
	}

	writeAudit(AuditEntry{
		Action: "ingest",
		Detail: fmt.Sprintf("doc=%s chunks=%d flagged=%d", doc.ID, len(chunks), flagged),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"document": doc,
		"chunks":   len(chunks),
		"flagged":  flagged,
	})
}

func handleRetrieve(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	retrieveRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkRateLimit() {
		jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req RetrievalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := validateRetrievalRequest(req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.RequesterType == "" {
		req.RequesterType = "user"
	}
	if req.SessionTrust == "" {
		req.SessionTrust = "medium"
	}

	// Gather candidate chunks with tightened scoping.
	var candidates []Chunk
	if len(req.ChunkIDs) > 0 {
		for _, cid := range req.ChunkIDs {
			if c, ok := docStore.GetChunk(cid); ok {
				candidates = append(candidates, c)
			}
		}
	} else if len(req.DocumentIDs) > 0 {
		for _, did := range req.DocumentIDs {
			candidates = append(candidates, docStore.QueryChunks(ChunkFilter{DocumentID: did})...)
		}
	} else if req.RequesterType == "system" {
		// Only system-trust callers may retrieve all chunks (unscoped).
		candidates = docStore.AllChunks()
	} else {
		jsonError(w, "retrieval requires explicit chunk_ids or document_ids", http.StatusBadRequest)
		return
	}

	// Build doc source lookup.
	docSourceMap := make(map[string]string)
	for _, c := range candidates {
		if _, seen := docSourceMap[c.DocumentID]; !seen {
			if doc, ok := docStore.GetDocument(c.DocumentID); ok {
				docSourceMap[c.DocumentID] = doc.Source
			}
		}
	}

	eng := getEngine()
	resp := eng.Evaluate(candidates, docSourceMap, req)

	writeAudit(AuditEntry{
		Action:  "retrieve",
		Allowed: resp.Summary.Allowed,
		Denied:  resp.Summary.Denied,
		Detail:  fmt.Sprintf("requester=%s tool=%s chunks=%d", req.RequesterType, req.Tool, resp.Summary.TotalChunks),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		jsonError(w, "content is required", http.StatusBadRequest)
		return
	}

	result := ScanContent(req.Content, getPolicy().Scanner)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"documents": docStore.ListDocuments(),
		})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			jsonError(w, "id parameter is required", http.StatusBadRequest)
			return
		}
		if err := docStore.DeleteDocument(id); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		writeAudit(AuditEntry{
			Action: "delete",
			Detail: fmt.Sprintf("doc=%s", id),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "id": id})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleListChunks(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filter := ChunkFilter{
		DocumentID:       q.Get("document_id"),
		SensitivityLabel: q.Get("sensitivity"),
		TrustLevel:       q.Get("trust"),
	}

	chunks := docStore.QueryChunks(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(chunks),
		"chunks": chunks,
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadPolicy(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests":    totalRequests.Load(),
		"ingest_requests":   ingestRequests.Load(),
		"retrieve_requests": retrieveRequests.Load(),
		"documents":         int64(docStore.DocumentCount()),
		"chunks":            int64(docStore.ChunkCount()),
	})
}

// ---------------------------------------------------------------------------
// Mux builder (exported for testability)
// ---------------------------------------------------------------------------

func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/ingest", requireServiceToken(handleIngest))
	mux.HandleFunc("/v1/retrieve", requireServiceToken(handleRetrieve))
	mux.HandleFunc("/v1/scan", requireServiceToken(handleScan))
	mux.HandleFunc("/v1/documents", requireServiceToken(handleDocuments))
	mux.HandleFunc("/v1/chunks", requireServiceToken(handleListChunks))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string) {
	loadServiceToken()
	initAuditLog()

	pol := getPolicy()
	readTimeout := 30
	writeTimeout := 60
	idleTimeout := 120
	if pol.Daemon.ReadTimeoutSec > 0 {
		readTimeout = pol.Daemon.ReadTimeoutSec
	}
	if pol.Daemon.WriteTimeoutSec > 0 {
		writeTimeout = pol.Daemon.WriteTimeoutSec
	}
	if pol.Daemon.IdleTimeoutSec > 0 {
		idleTimeout = pol.Daemon.IdleTimeoutSec
	}

	srv := &http.Server{
		Addr:         bindAddr,
		Handler:      buildMux(),
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
		IdleTimeout:  time.Duration(idleTimeout) * time.Second,
	}

	log.Printf("rag-data-firewall serving on %s (docs=%d chunks=%d)",
		bindAddr, docStore.DocumentCount(), docStore.ChunkCount())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdServe(policyPath, bindAddr string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening store: %v\n", err)
		return 1
	}
	defer docStore.Close()

	if bindAddr == "" {
		bindAddr = pol.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}

	runDaemon(bindAddr)
	return 0
}

func cmdIngest(policyPath, filePath, name, sensitivity, trust, source string, labels map[string]string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		return 1
	}

	if name == "" {
		name = filePath
	}

	req := IngestRequest{
		Name:             name,
		Content:          string(content),
		Source:           source,
		SensitivityLabel: sensitivity,
		TrustLevel:       trust,
		Labels:           labels,
	}

	doc, chunks, err := docStore.Ingest(req, pol.Scanner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	flagged := 0
	for _, c := range chunks {
		if c.Scan.PromptInjection {
			flagged++
		}
	}

	fmt.Printf("ingested: %s\n  id:          %s\n  chunks:      %d\n  flagged:     %d\n  sensitivity: %s\n  trust:       %s\n",
		doc.Name, doc.ID, len(chunks), flagged, doc.SensitivityLabel, doc.TrustLevel)
	return 0
}

func cmdScan(policyPath, content string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	result := ScanContent(content, getPolicy().Scanner)
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))

	if result.PromptInjection {
		return 2
	}
	return 0
}

func cmdQuery(policyPath, requesterType, sessionTrust, tool string, chunkIDs, docIDs []string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	req := RetrievalRequest{
		RequesterType: requesterType,
		SessionTrust:  sessionTrust,
		Tool:          tool,
		ChunkIDs:      chunkIDs,
		DocumentIDs:   docIDs,
	}

	var candidates []Chunk
	if len(req.ChunkIDs) > 0 {
		for _, cid := range req.ChunkIDs {
			if c, ok := docStore.GetChunk(cid); ok {
				candidates = append(candidates, c)
			}
		}
	} else if len(req.DocumentIDs) > 0 {
		for _, did := range req.DocumentIDs {
			candidates = append(candidates, docStore.QueryChunks(ChunkFilter{DocumentID: did})...)
		}
	} else {
		candidates = docStore.AllChunks()
	}

	docSourceMap := make(map[string]string)
	for _, c := range candidates {
		if _, seen := docSourceMap[c.DocumentID]; !seen {
			if doc, ok := docStore.GetDocument(c.DocumentID); ok {
				docSourceMap[c.DocumentID] = doc.Source
			}
		}
	}

	resp := getEngine().Evaluate(candidates, docSourceMap, req)
	data, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(data))
	return 0
}

func cmdList(policyPath, what string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	pol := getPolicy()
	var err error
	docStore, err = NewDocumentStore(getDataDir(), pol.Retention)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer docStore.Close()

	switch what {
	case "documents", "docs":
		docs := docStore.ListDocuments()
		if len(docs) == 0 {
			fmt.Println("no documents ingested")
			return 0
		}
		for _, d := range docs {
			fmt.Printf("  %-30s  [%s] trust=%s  chunks=%d  source=%s\n",
				d.ID, d.SensitivityLabel, d.TrustLevel, d.ChunkCount, d.Source)
		}
	case "chunks":
		chunks := docStore.AllChunks()
		if len(chunks) == 0 {
			fmt.Println("no chunks")
			return 0
		}
		for _, c := range chunks {
			flag := " "
			if c.Scan.PromptInjection {
				flag = "!"
			}
			fmt.Printf("  %s %-30s  [%s] trust=%s  risk=%.2f  %s\n",
				flag, c.ID, c.SensitivityLabel, c.TrustLevel, c.Scan.RiskScore,
				truncate(c.Content, 60))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown: %s (use 'documents' or 'chunks')\n", what)
		return 1
	}
	return 0
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdServe(*policyPath, *bind))

	case "ingest":
		fs := flag.NewFlagSet("ingest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		filePath := fs.String("file", "", "file to ingest")
		name := fs.String("name", "", "document name")
		sensitivity := fs.String("sensitivity", "internal", "sensitivity label")
		trust := fs.String("trust", "unverified", "trust level")
		source := fs.String("source", "upload", "source origin")
		fs.Parse(os.Args[2:])
		if *filePath == "" {
			fmt.Fprintf(os.Stderr, "error: -file is required\n")
			os.Exit(1)
		}
		os.Exit(cmdIngest(*policyPath, *filePath, *name, *sensitivity, *trust, *source, nil))

	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		content := fs.String("content", "", "content to scan")
		file := fs.String("file", "", "file to scan")
		fs.Parse(os.Args[2:])
		text := *content
		if *file != "" {
			data, err := os.ReadFile(*file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			text = string(data)
		}
		if text == "" {
			fmt.Fprintf(os.Stderr, "error: -content or -file required\n")
			os.Exit(1)
		}
		os.Exit(cmdScan(*policyPath, text))

	case "query":
		fs := flag.NewFlagSet("query", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		requesterType := fs.String("requester", "user", "requester type (user, tool, system)")
		sessionTrust := fs.String("session-trust", "medium", "session trust level")
		tool := fs.String("tool", "", "requesting tool name")
		fs.Parse(os.Args[2:])
		os.Exit(cmdQuery(*policyPath, *requesterType, *sessionTrust, *tool, nil, nil))

	case "list":
		fs := flag.NewFlagSet("list", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		fs.Parse(os.Args[2:])
		what := "documents"
		if fs.NArg() > 0 {
			what = fs.Arg(0)
		}
		os.Exit(cmdList(*policyPath, what))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `rag-data-firewall — OPA-style policy engine for secure RAG

Usage:
  rag-data-firewall <command> [options]

Commands:
  serve     Start policy engine daemon (HTTP API on :8500)
  ingest    Ingest a document with sensitivity labels and scanning
  scan      Scan content for prompt injection and PII
  query     Evaluate retrieval policy against stored chunks
  list      List documents or chunks

Policy actions: allow, deny, redact, require-approval
Every decision includes evidence explaining why a chunk was allowed or blocked.

Use "rag-data-firewall <command> -h" for command-specific options.
`)
}

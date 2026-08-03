package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type Policy struct {
	Version    int            `yaml:"version"`
	Defaults   PolicyDefaults `yaml:"defaults"`
	Models     yaml.Node      `yaml:"models"`
	Quarantine yaml.Node      `yaml:"quarantine"`
	GGUFGuard  yaml.Node      `yaml:"gguf_guard"`
	Tools      ToolsPolicy    `yaml:"tools"`
	Search     yaml.Node      `yaml:"search"`
	Airlock    yaml.Node      `yaml:"airlock"`
}

type PolicyDefaults struct {
	Network struct {
		RuntimeEgress string `yaml:"runtime_egress"`
	} `yaml:"network"`
	Logging struct {
		StoreRawPrompts   bool `yaml:"store_raw_prompts"`
		StoreRawResponses bool `yaml:"store_raw_responses"`
	} `yaml:"logging"`
}

type ToolsPolicy struct {
	Default   string      `yaml:"default"`
	Allow     []ToolEntry `yaml:"allow"`
	Deny      []ToolEntry `yaml:"deny"`
	RateLimit RateConfig  `yaml:"rate_limit"`
}

type ToolEntry struct {
	Name           string        `yaml:"name"`
	PathsAllowlist []string      `yaml:"paths_allowlist"`
	PathsDenylist  []string      `yaml:"paths_denylist"`
	ArgsBlacklist  []string      `yaml:"args_blocklist"`
	ArgRules       []ToolArgRule `yaml:"args"`
	MaxArgLength   int           `yaml:"max_arg_length"`
}

// ToolArgRule defines the expected JSON type and constraints for one
// argument. When a tool declares argument rules, they form a complete
// allowlist for that tool's parameters.
type ToolArgRule struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	Required  bool   `yaml:"required"`
	MaxLength int    `yaml:"max_length"`
	Pattern   string `yaml:"pattern"`
	Redact    bool   `yaml:"redact"`
}

type RateConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	BurstSize         int `yaml:"burst_size"`
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

type ToolCallRequest struct {
	Tool   string            `json:"tool"`
	Params map[string]string `json:"params"`
	// TypedParams retains the original bounded JSON values received over HTTP.
	// Params remains for compatibility with existing in-process callers.
	TypedParams map[string]any `json:"-"`
}

type toolCallRequestWire struct {
	Tool   string         `json:"tool"`
	Params map[string]any `json:"params"`
	Args   map[string]any `json:"args,omitempty"` // legacy alias accepted for compatibility
}

type ToolCallResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   Policy

	auditFile *os.File
	auditMu   sync.Mutex
	auditPath string

	// Rate limiting: process-wide token bucket.
	rateMu     sync.Mutex
	rateTokens float64
	rateLast   time.Time
	rateRPM    int
	rateBurst  int

	// Stats
	totalRequests  atomic.Int64
	deniedRequests atomic.Int64
)

var (
	serviceTokenDigest [sha256.Size]byte
	serviceTokenLoaded bool
)

const (
	defaultMaxArgLength   = 4096
	defaultRequestsPerMin = 120
	defaultBurstSize      = 20
	maxRequestBodySize    = 64 * 1024 // 64 KB
	maxPolicySize         = 1 << 20   // 1 MiB
	minTokenSize          = 32
	maxTokenSize          = 4096
	maxAuditSize          = 256 << 20 // 256 MiB; logrotate normally rotates at 50 MiB
	maxArgumentNodes      = 10_000
	maxArgumentDepth      = 32
)

// loadServiceToken reads the service-to-service auth token from disk.
func loadServiceToken() error {
	serviceTokenDigest = [sha256.Size]byte{}
	serviceTokenLoaded = false
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		// #nosec G101 -- this is a credential file location, never credential material.
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := readCredentialFile(tokenPath, maxTokenSize)
	if err != nil {
		return fmt.Errorf("read service token %s: %w", tokenPath, err)
	}
	token := bytes.TrimSpace(data)
	if len(token) < minTokenSize || len(token) > maxTokenSize {
		for i := range data {
			data[i] = 0
		}
		return fmt.Errorf("service token must contain between %d and %d bytes", minTokenSize, maxTokenSize)
	}
	serviceTokenDigest = sha256.Sum256(token)
	serviceTokenLoaded = true
	for i := range data {
		data[i] = 0
	}
	log.Print("service token loaded")
	return nil
}

// requireServiceToken wraps a handler to enforce Bearer token auth on mutating endpoints.
func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !serviceTokenLoaded {
			http.Error(w, `{"error":"service authentication unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		candidateDigest := sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
		if subtle.ConstantTimeCompare(candidateDigest[:], serviceTokenDigest[:]) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	p := os.Getenv("POLICY_PATH")
	if p == "" {
		p = "/etc/secure-ai/policy/policy.yaml"
	}
	return p
}

func loadPolicy() error {
	data, err := readRegularFile(policyFilePath(), maxPolicySize)
	if err != nil {
		return err
	}
	var p Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("policy must contain exactly one YAML document")
		}
		return fmt.Errorf("parse trailing policy data: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return err
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded: default=%s allow=%d deny=%d",
		p.Tools.Default, len(p.Tools.Allow), len(p.Tools.Deny))
	return nil
}

// readRegularFile reads a policy only when it is not writable by group/other
// and is owned by root or the service account.
func readRegularFile(path string, limit int64) ([]byte, error) {
	return readTrustedRegularFile(path, limit, 0o022)
}

// readCredentialFile applies the stronger owner-only requirement used for
// systemd-delivered service credentials.
func readCredentialFile(path string, limit int64) ([]byte, error) {
	return readTrustedRegularFile(path, limit, 0o077)
}

func inspectExplicitFile(path string) (os.FileInfo, error) {
	// #nosec G703 -- caller verifies the explicit policy/credential path's type,
	// identity, owner, permissions, and size before consuming any content.
	return os.Lstat(path)
}

func openExplicitFile(path string) (*os.File, error) {
	// #nosec G304,G703 -- caller performs pre/open/post identity and metadata
	// verification for the explicit operator-selected path.
	return os.Open(path)
}

func readTrustedRegularFile(path string, limit int64, disallowedPermissions os.FileMode) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("file size limit must be positive")
	}
	before, err := inspectExplicitFile(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symbolic links are not allowed")
	}
	if err := validateTrustedFileMetadata(before, limit, disallowedPermissions); err != nil {
		return nil, err
	}

	f, err := openExplicitFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := inspectExplicitFile(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("file changed while opening or is a symbolic link")
	}
	if err := validateTrustedFileMetadata(opened, limit, disallowedPermissions); err != nil {
		return nil, err
	}
	if err := validateTrustedFileMetadata(after, limit, disallowedPermissions); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	finalOpened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	finalPath, err := inspectExplicitFile(path)
	if err != nil {
		return nil, err
	}
	if finalPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, finalOpened) ||
		!os.SameFile(finalOpened, finalPath) {
		return nil, errors.New("file changed while reading or is a symbolic link")
	}
	if err := validateTrustedFileMetadata(finalOpened, limit, disallowedPermissions); err != nil {
		return nil, err
	}
	if err := validateTrustedFileMetadata(finalPath, limit, disallowedPermissions); err != nil {
		return nil, err
	}
	return data, nil
}

func validateTrustedFileMetadata(info os.FileInfo, limit int64, disallowedPermissions os.FileMode) error {
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if info.Mode().Perm()&disallowedPermissions != 0 {
		return errors.New("file permissions are too broad")
	}
	owner, ok := fileOwnerID(info)
	euid := os.Geteuid()
	if euid < 0 {
		return errors.New("cannot determine service account owner")
	}
	// #nosec G115 -- Geteuid was checked non-negative before conversion.
	serviceOwner := uint64(euid)
	if !ok || (owner != 0 && owner != serviceOwner) {
		return errors.New("file is not owned by root or the service account")
	}
	if info.Size() > limit {
		return fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return nil
}

func validatePolicy(p Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	if p.Tools.Default != "deny" {
		return errors.New("tools.default must be \"deny\"")
	}
	if p.Tools.RateLimit.RequestsPerMinute < 0 || p.Tools.RateLimit.RequestsPerMinute > 1_000_000 {
		return errors.New("requests_per_minute must be between 0 and 1000000")
	}
	if p.Tools.RateLimit.BurstSize < 0 || p.Tools.RateLimit.BurstSize > 1_000_000 {
		return errors.New("burst_size must be between 0 and 1000000")
	}
	for _, entry := range p.Tools.Allow {
		if entry.MaxArgLength < 0 || entry.MaxArgLength > maxRequestBodySize {
			return fmt.Errorf("tool %q max_arg_length must be between 0 and %d", entry.Name, maxRequestBodySize)
		}
		if len(entry.ArgRules) > 128 {
			return fmt.Errorf("tool %q has too many argument rules", entry.Name)
		}
		seen := make(map[string]struct{}, len(entry.ArgRules))
		for _, rule := range entry.ArgRules {
			if rule.Name == "" || len(rule.Name) > 256 || strings.TrimSpace(rule.Name) != rule.Name ||
				strings.ContainsAny(rule.Name, "\x00\r\n") {
				return fmt.Errorf("tool %q has invalid argument rule name", entry.Name)
			}
			if _, exists := seen[rule.Name]; exists {
				return fmt.Errorf("tool %q has duplicate argument rule %q", entry.Name, rule.Name)
			}
			seen[rule.Name] = struct{}{}
			switch rule.Type {
			case "string", "boolean", "number", "integer", "object", "array":
			default:
				return fmt.Errorf("tool %q argument %q has invalid type %q", entry.Name, rule.Name, rule.Type)
			}
			if rule.MaxLength < 0 || rule.MaxLength > maxRequestBodySize {
				return fmt.Errorf("tool %q argument %q has invalid max_length", entry.Name, rule.Name)
			}
			if len(rule.Pattern) > 4096 || (rule.Pattern != "" && rule.Type != "string") {
				return fmt.Errorf("tool %q argument %q has invalid pattern", entry.Name, rule.Name)
			}
			if rule.Pattern != "" {
				if _, err := regexp.Compile(rule.Pattern); err != nil {
					return fmt.Errorf("tool %q argument %q has invalid pattern: %w", entry.Name, rule.Name, err)
				}
			}
			if isPathParameter(rule.Name) && rule.Type != "string" {
				return fmt.Errorf("tool %q path argument %q must have type string", entry.Name, rule.Name)
			}
		}
	}
	return nil
}

func getPolicy() Policy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policy
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string         `json:"timestamp"`
	Tool      string         `json:"tool"`
	Params    map[string]any `json:"params,omitempty"`
	Allowed   bool           `json:"allowed"`
	Reason    string         `json:"reason,omitempty"`
}

var sensitiveAuditKeys = map[string]struct{}{
	"args":          {},
	"authorization": {},
	"body":          {},
	"content":       {},
	"context":       {},
	"credential":    {},
	"instruction":   {},
	"input":         {},
	"message":       {},
	"messages":      {},
	"password":      {},
	"payload":       {},
	"prompt":        {},
	"query":         {},
	"response":      {},
	"result":        {},
	"secret":        {},
	"text":          {},
	"token":         {},
}

func redactAuditValue(value string) string {
	return fmt.Sprintf("[redacted len=%d]", len(value))
}

func redactAuditCredential() string {
	// Credential fingerprints can become offline verification oracles for
	// low-entropy values, so credential redactions intentionally expose no hash.
	return "[redacted credential]"
}

func compactAuditKey(name string) string {
	var compact strings.Builder
	compact.Grow(len(name))
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			compact.WriteRune(unicode.ToLower(r))
		}
	}
	return compact.String()
}

func isCredentialAuditKey(name string) bool {
	compact := compactAuditKey(name)
	if compact == "auth" || compact == "key" {
		return true
	}
	for _, marker := range []string{
		"password", "passwd", "passphrase", "secret", "token", "credential",
		"authorization", "apikey", "privatekey", "sshkey", "signingkey", "accesskey",
		"sessionkey", "clientkey", "encryptionkey", "decryptionkey", "keymaterial",
		"bearer", "cookie",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}

func sanitizeAuditParams(params any, pol Policy) map[string]any {
	var root map[string]any
	switch values := params.(type) {
	case map[string]any:
		root = values
	case map[string]string:
		root = make(map[string]any, len(values))
		for key, value := range values {
			root[key] = value
		}
	default:
		return nil
	}
	if len(root) == 0 {
		return nil
	}

	nodes := 0
	clean, ok := sanitizeAuditMap(root, pol, 0, &nodes)
	if !ok {
		return map[string]any{"payload": "[redacted: audit structure limit exceeded]"}
	}
	return clean
}

func sanitizeToolAuditParams(params map[string]any, pol Policy, toolName string) map[string]any {
	clean := sanitizeAuditParams(params, pol)
	if clean == nil {
		return nil
	}
	for _, entry := range pol.Tools.Allow {
		if entry.Name != toolName {
			continue
		}
		for _, rule := range entry.ArgRules {
			if rule.Redact {
				if _, exists := params[rule.Name]; exists {
					clean[rule.Name] = redactAuditCredential()
				}
			}
		}
		break
	}
	return clean
}

func sanitizeAuditMap(values map[string]any, pol Policy, depth int, nodes *int) (map[string]any, bool) {
	if depth > maxArgumentDepth || len(values) > 128 {
		return nil, false
	}
	clean := make(map[string]any, len(values))
	for key, value := range values {
		(*nodes)++
		if *nodes > maxArgumentNodes {
			return nil, false
		}
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		canonicalKey := normalizeArgumentName(lowerKey)
		compactKey := compactAuditKey(key)
		_, promptLikeKey := sensitiveAuditKeys[lowerKey]
		promptLikeKey = promptLikeKey || containsAuditCategory(canonicalKey,
			"args", "body", "content", "context", "instruction", "input", "message", "messages",
			"payload", "prompt", "query", "text")
		promptLikeKey = promptLikeKey || containsCompactAuditCategory(compactKey,
			"args", "body", "content", "context", "instruction", "input", "message",
			"payload", "prompt", "query", "text")
		responseKey := containsCompactAuditCategory(compactKey, "response", "result", "output")

		if isCredentialAuditKey(key) {
			clean[key] = redactAuditCredential()
			continue
		}
		if (promptLikeKey && !pol.Defaults.Logging.StoreRawPrompts) ||
			(responseKey && !pol.Defaults.Logging.StoreRawResponses) {
			clean[key] = redactAuditAny(value)
			continue
		}
		sanitized, ok := sanitizeAuditNode(value, pol, depth+1, nodes)
		if !ok {
			return nil, false
		}
		clean[key] = sanitized
	}
	return clean, true
}

func containsCompactAuditCategory(name string, categories ...string) bool {
	for _, category := range categories {
		if strings.Contains(name, category) {
			return true
		}
	}
	return false
}

func containsAuditCategory(name string, categories ...string) bool {
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '_' })
	for _, part := range parts {
		for _, category := range categories {
			if part == category {
				return true
			}
		}
	}
	return false
}

func sanitizeAuditNode(value any, pol Policy, depth int, nodes *int) (any, bool) {
	if depth > maxArgumentDepth {
		return nil, false
	}
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeAuditMap(typed, pol, depth, nodes)
	case []any:
		if len(typed) > 4096 {
			return nil, false
		}
		out := make([]any, len(typed))
		for i, item := range typed {
			(*nodes)++
			if *nodes > maxArgumentNodes {
				return nil, false
			}
			clean, ok := sanitizeAuditNode(item, pol, depth+1, nodes)
			if !ok {
				return nil, false
			}
			out[i] = clean
		}
		return out, true
	case string:
		if len(typed) > 512 {
			return redactAuditValue(typed), true
		}
		return typed, true
	case nil, bool, json.Number, float64:
		return typed, true
	default:
		return redactAuditAny(typed), true
	}
}

func redactAuditAny(value any) string {
	if text, ok := value.(string); ok {
		return redactAuditValue(text)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "[redacted]"
	}
	return redactAuditValue(string(data))
}

func initAuditLog() {
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/secure-ai/logs/tool-firewall-audit.jsonl"
	}
	f, err := openAuditLog(auditPath)
	if err != nil {
		log.Printf("warning: cannot open audit log %s: %v", auditPath, err)
		return
	}
	auditFile = f
}

func openAuditLog(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("audit log path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}
	parent, err := os.Lstat(dir)
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o002 != 0 {
		return nil, errors.New("audit log directory must be a non-symlink directory not writable by others")
	}

	var before os.FileInfo
	flags := os.O_APPEND | os.O_WRONLY
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("audit log must be a regular, non-symlink file")
		}
		before = info
	} else if os.IsNotExist(statErr) {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		return nil, fmt.Errorf("inspect audit log: %w", statErr)
	}

	// #nosec G304,G302 -- path is absolute and identity/type checked; 0640 is
	// required by SecAI_OS's secure-ai-logs group and existing logrotate contract.
	f, err := os.OpenFile(path, flags, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("inspect opened audit log: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm()&0o007 != 0 ||
		fileLinkCount(opened) != 1 || opened.Size() > maxAuditSize ||
		(before != nil && !os.SameFile(before, opened)) {
		_ = f.Close()
		return nil, fmt.Errorf("audit log must retain identity as a non-world-accessible, single-link regular file under %d bytes", maxAuditSize)
	}
	return f, nil
}

func writeAudit(entry AuditEntry) error {
	if auditFile == nil {
		return errors.New("audit log unavailable")
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	auditMu.Lock()
	defer auditMu.Unlock()

	line := append(data, '\n')
	opened, statErr := auditFile.Stat()
	current, pathErr := os.Lstat(auditFile.Name())
	if statErr != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, current) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o007 != 0 ||
		fileLinkCount(opened) != 1 || opened.Size()+int64(len(line)) > maxAuditSize {
		return errors.New("audit log identity, permissions, link count, or size limit changed")
	}
	for len(line) > 0 {
		n, writeErr := auditFile.Write(line)
		if writeErr != nil {
			return writeErr
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		line = line[n:]
	}
	return nil
}

func fileLinkCount(info os.FileInfo) uint64 {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	if field.Kind() >= reflect.Uint && field.Kind() <= reflect.Uint64 {
		return field.Uint()
	}
	if field.Kind() >= reflect.Int && field.Kind() <= reflect.Int64 {
		links := field.Int()
		if links > 0 {
			return uint64(links)
		}
	}
	return 0
}

func fileOwnerID(info os.FileInfo) (uint64, bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, false
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, false
	}
	field := value.FieldByName("Uid")
	if !field.IsValid() {
		return 0, false
	}
	if field.Kind() >= reflect.Uint && field.Kind() <= reflect.Uint64 {
		return field.Uint(), true
	}
	if field.Kind() >= reflect.Int && field.Kind() <= reflect.Int64 {
		owner := field.Int()
		if owner >= 0 {
			return uint64(owner), true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit(pol Policy) bool {
	rpm := pol.Tools.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRequestsPerMin
	}

	burst := pol.Tools.RateLimit.BurstSize
	if burst <= 0 {
		burst = defaultBurstSize
	}

	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if rateLast.IsZero() || rateRPM != rpm || rateBurst != burst {
		rateLast = now
		rateTokens = float64(burst)
		rateRPM = rpm
		rateBurst = burst
	} else {
		rateTokens += now.Sub(rateLast).Seconds() * float64(rpm) / 60
		if rateTokens > float64(burst) {
			rateTokens = float64(burst)
		}
		rateLast = now
	}
	if rateTokens < 1 {
		return false
	}
	rateTokens--
	return true
}

// ---------------------------------------------------------------------------
// Path security
// ---------------------------------------------------------------------------

// cleanAndResolvePath canonicalizes a path, catching traversal attempts.
func cleanAndResolvePath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	// Reject null bytes (path injection via null terminator)
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("path contains null byte")
	}
	decoded, err := decodePath(raw)
	if err != nil {
		return "", err
	}
	if containsUnicodePathConfusable(decoded) {
		return "", fmt.Errorf("path contains unicode path confusable")
	}
	if !filepath.IsAbs(decoded) {
		return "", fmt.Errorf("path must be absolute")
	}
	cleaned := filepath.Clean(decoded)
	// Resolve to absolute to catch ../../../etc/shadow style attacks
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	return resolvePath(abs)
}

func decodePath(raw string) (string, error) {
	decoded := raw
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", fmt.Errorf("path contains invalid percent-encoding")
		}
		if next == decoded {
			return decoded, nil
		}
		if strings.ContainsRune(next, 0) {
			return "", fmt.Errorf("path contains null byte")
		}
		decoded = next
	}
	return "", fmt.Errorf("path is percent-encoded too deeply")
}

func containsUnicodePathConfusable(raw string) bool {
	for _, r := range raw {
		switch r {
		case '\u2044', '\u2215', '\u2216', '\u29f8', '\uff0e', '\uff0f', '\uff3c', '\ufffd':
			return true
		}
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
			return true
		}
	}
	return false
}

func resolvePath(abs string) (string, error) {
	// Resolve symlinks for the deepest existing prefix so allowlist checks
	// apply to the real target, not just the lexical path.
	cursor := abs
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(cursor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("cannot resolve path: %w", err)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			// Nothing existed on disk; fall back to the canonical absolute path.
			return filepath.Clean(abs), nil
		}
		suffix = append(suffix, filepath.Base(cursor))
		cursor = parent
	}
}

func normalizeMatchPath(raw string) string {
	clean := filepath.Clean(raw)
	slash := filepath.ToSlash(clean)
	if vol := filepath.VolumeName(clean); vol != "" {
		slash = strings.ToLower(filepath.ToSlash(vol)) + strings.TrimPrefix(slash, vol)
	}
	return slash
}

func pathMatchCandidates(raw string) []string {
	norm := normalizeMatchPath(raw)
	candidates := []string{norm}
	if vol := filepath.VolumeName(filepath.Clean(raw)); vol != "" {
		volNorm := strings.ToLower(filepath.ToSlash(vol))
		trimmed := strings.TrimPrefix(norm, volNorm)
		if trimmed != "" {
			candidates = append(candidates, trimmed)
		}
	}
	return candidates
}

func hasPathPrefix(path, prefix string) bool {
	prefixNorm := normalizeMatchPath(prefix)
	for _, candidate := range pathMatchCandidates(path) {
		if candidate == prefixNorm || strings.HasPrefix(candidate, prefixNorm+"/") {
			return true
		}
	}
	return false
}

// matchesGlob checks if a path matches an allowlist pattern.
// Supports trailing ** for recursive match (prefix match) and exact prefix match.
func matchesGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = filepath.Clean(prefix)
		return hasPathPrefix(path, prefix)
	}
	if strings.HasSuffix(pattern, "**") {
		prefix := strings.TrimSuffix(pattern, "**")
		prefix = filepath.Clean(prefix)
		return hasPathPrefix(path, prefix)
	}
	return hasPathPrefix(path, pattern)
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

func effectiveTypedParams(req ToolCallRequest) map[string]any {
	if req.TypedParams != nil {
		return req.TypedParams
	}
	values := make(map[string]any, len(req.Params))
	for key, value := range req.Params {
		values[key] = value
	}
	return values
}

func encodeArgumentForInspection(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func argumentTreeContainsPattern(value any, pattern string, depth int, nodes *int) (bool, error) {
	if depth > maxArgumentDepth {
		return false, errors.New("argument tree exceeds the depth limit")
	}
	(*nodes)++
	if *nodes > maxArgumentNodes {
		return false, errors.New("argument tree exceeds the node limit")
	}
	contains := func(text string) bool {
		return strings.Contains(strings.ToLower(text), pattern)
	}

	switch typed := value.(type) {
	case nil:
		return false, nil
	case string:
		return contains(typed), nil
	case json.Number:
		return contains(string(typed)), nil
	case float64:
		return contains(strconv.FormatFloat(typed, 'g', -1, 64)), nil
	case bool:
		return contains(strconv.FormatBool(typed)), nil
	case map[string]any:
		if len(typed) > 128 {
			return false, errors.New("argument object exceeds the member limit")
		}
		for key, nested := range typed {
			if contains(key) {
				return true, nil
			}
			matched, err := argumentTreeContainsPattern(nested, pattern, depth+1, nodes)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	case []any:
		if len(typed) > 4096 {
			return false, errors.New("argument array exceeds the item limit")
		}
		for _, nested := range typed {
			matched, err := argumentTreeContainsPattern(nested, pattern, depth+1, nodes)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported argument value type %T", value)
	}
}

func validateArgs(req ToolCallRequest, entry ToolEntry) (bool, string) {
	params := effectiveTypedParams(req)
	maxLen := entry.MaxArgLength
	if maxLen <= 0 {
		maxLen = defaultMaxArgLength
	}

	rules := make(map[string]ToolArgRule, len(entry.ArgRules))
	for _, rule := range entry.ArgRules {
		rules[rule.Name] = rule
	}
	for key, val := range params {
		rule, declared := rules[key]
		if entry.ArgRules != nil && !declared {
			return false, fmt.Sprintf("argument %q is not declared by this tool policy", key)
		}
		if !declared && dangerousArgumentName(key) && !(isPathParameter(key) &&
			(len(entry.PathsAllowlist) > 0 || len(entry.PathsDenylist) > 0)) {
			return false, fmt.Sprintf("dangerous argument %q requires an explicit typed policy rule", key)
		}

		encoded, err := encodeArgumentForInspection(val)
		if err != nil {
			return false, fmt.Sprintf("argument %q cannot be encoded", key)
		}
		// Length check
		valueLength := len(encoded)
		if text, ok := val.(string); ok {
			valueLength = len(text)
		}
		if valueLength > maxLen {
			return false, fmt.Sprintf("argument %q exceeds max length (%d > %d)", key, valueLength, maxLen)
		}

		// Blocked argument patterns (e.g., shell injection attempts)
		for _, blocked := range entry.ArgsBlacklist {
			blockedLower := strings.ToLower(blocked)
			nodes := 0
			nestedMatch, inspectErr := argumentTreeContainsPattern(val, blockedLower, 0, &nodes)
			if inspectErr != nil {
				return false, fmt.Sprintf("argument %q cannot be safely inspected", key)
			}
			if nestedMatch || strings.Contains(strings.ToLower(string(encoded)), blockedLower) {
				return false, fmt.Sprintf("argument %q contains blocked pattern %q", key, blocked)
			}
		}
		if declared {
			if ok, reason := validateTypedArgument(key, val, rule); !ok {
				return false, reason
			}
		}
	}
	for _, rule := range entry.ArgRules {
		if _, exists := params[rule.Name]; rule.Required && !exists {
			return false, fmt.Sprintf("required argument %q is missing", rule.Name)
		}
	}
	return true, ""
}

func validateTypedArgument(name string, value any, rule ToolArgRule) (bool, string) {
	typeOK := false
	switch rule.Type {
	case "string":
		_, typeOK = value.(string)
	case "boolean":
		_, typeOK = value.(bool)
	case "number":
		switch value.(type) {
		case json.Number, float64:
			typeOK = true
		}
	case "integer":
		switch typed := value.(type) {
		case json.Number:
			_, err := strconv.ParseInt(string(typed), 10, 64)
			typeOK = err == nil
		case float64:
			typeOK = typed == float64(int64(typed))
		}
	case "object":
		_, typeOK = value.(map[string]any)
	case "array":
		_, typeOK = value.([]any)
	}
	if !typeOK {
		return false, fmt.Sprintf("argument %q must have JSON type %s", name, rule.Type)
	}
	if rule.MaxLength < 0 {
		return false, fmt.Sprintf("argument %q has an invalid typed max_length", name)
	}
	if rule.MaxLength > 0 {
		length := 0
		switch typed := value.(type) {
		case string:
			length = len(typed)
		case []any:
			length = len(typed)
		case map[string]any:
			length = len(typed)
		default:
			encoded, _ := json.Marshal(value)
			length = len(encoded)
		}
		if length > rule.MaxLength {
			return false, fmt.Sprintf("argument %q exceeds typed max_length %d", name, rule.MaxLength)
		}
	}
	if rule.Pattern != "" {
		valueString, ok := value.(string)
		if !ok {
			return false, fmt.Sprintf("argument %q pattern requires JSON type string", name)
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil || !compiled.MatchString(valueString) {
			return false, fmt.Sprintf("argument %q does not match its required pattern", name)
		}
	}
	return true, ""
}

func dangerousArgumentName(name string) bool {
	if isCredentialAuditKey(name) {
		return true
	}
	canonical := normalizeArgumentName(name)
	switch canonical {
	case "cmd", "command", "shell", "exec", "executable", "script", "code", "program",
		"url", "uri", "endpoint", "host", "headers", "authorization", "env", "environment",
		"cwd", "working_directory", "workingdirectory", "body", "payload", "content", "template",
		"shellcommand", "execargs", "requesturl", "httpheaders":
		return true
	}
	for _, part := range strings.FieldsFunc(canonical, func(r rune) bool { return r == '_' }) {
		switch part {
		case "cmd", "command", "shell", "exec", "executable", "script", "code", "program",
			"url", "uri", "endpoint", "host", "headers", "authorization", "env", "environment",
			"cwd", "body", "payload", "content", "template":
			return true
		}
	}
	return isPathParameter(name)
}

func normalizeArgumentName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var normalized strings.Builder
	normalized.Grow(len(name))
	lastSeparator := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			normalized.WriteRune(r)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			normalized.WriteByte('_')
			lastSeparator = true
		}
	}
	return strings.Trim(normalized.String(), "_")
}

func validateToolCall(req ToolCallRequest) (bool, string) {
	if req.Tool == "" || len(req.Tool) > 256 || strings.TrimSpace(req.Tool) != req.Tool ||
		strings.ContainsAny(req.Tool, "\x00\r\n") {
		return false, "invalid tool name"
	}
	params := effectiveTypedParams(req)
	if len(params) > 128 {
		return false, "too many parameters"
	}
	for key := range params {
		if key == "" || len(key) > 256 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00\r\n") {
			return false, "invalid parameter name"
		}
	}
	nodes := 0
	if !validateArgumentTree(params, 0, &nodes) {
		return false, "invalid or excessively nested parameter value"
	}
	return true, ""
}

func validateArgumentTree(value any, depth int, nodes *int) bool {
	if depth > maxArgumentDepth {
		return false
	}
	(*nodes)++
	if *nodes > maxArgumentNodes {
		return false
	}
	switch typed := value.(type) {
	case nil, bool, string:
		return true
	case json.Number:
		_, err := strconv.ParseFloat(string(typed), 64)
		return err == nil
	case float64:
		return true
	case map[string]any:
		if len(typed) > 128 {
			return false
		}
		for key, nested := range typed {
			if key == "" || len(key) > 256 || strings.TrimSpace(key) != key ||
				strings.ContainsAny(key, "\x00\r\n") || !validateArgumentTree(nested, depth+1, nodes) {
				return false
			}
		}
		return true
	case []any:
		if len(typed) > 4096 {
			return false
		}
		for _, nested := range typed {
			if !validateArgumentTree(nested, depth+1, nodes) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isPathParameter(key string) bool {
	switch normalizeArgumentName(key) {
	case "path", "file", "filepath", "file_path", "filename", "directory", "dir", "root", "cwd",
		"target", "destination", "source", "input_path", "output_path", "source_path", "destination_path",
		"inputpath", "outputpath", "sourcepath", "destinationpath", "workingdirectory", "working_directory":
		return true
	default:
		return false
	}
}

func checkPathConstraints(params map[string]string, entry ToolEntry) (bool, string) {
	found := false
	for key, raw := range params {
		if !isPathParameter(key) {
			continue
		}
		if raw == "" {
			return false, "path parameter must not be empty"
		}
		found = true
		resolved, err := cleanAndResolvePath(raw)
		if err != nil {
			return false, "invalid path: " + err.Error()
		}
		for _, denied := range entry.PathsDenylist {
			if matchesGlob(resolved, denied) {
				return false, "path matches denylist"
			}
		}
		if len(entry.PathsAllowlist) > 0 {
			allowed := false
			for _, pattern := range entry.PathsAllowlist {
				if matchesGlob(resolved, pattern) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false, "path not in allowlist"
			}
		}
	}
	if (len(entry.PathsAllowlist) > 0 || len(entry.PathsDenylist) > 0) && !found {
		return false, "required path parameter missing"
	}
	return true, ""
}

func normalizeParams(raw map[string]any) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(raw))
	for key, val := range raw {
		switch typed := val.(type) {
		case nil:
			normalized[key] = ""
		case string:
			normalized[key] = typed
		case bool, float64, json.Number:
			normalized[key] = fmt.Sprint(typed)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				normalized[key] = fmt.Sprint(typed)
				continue
			}
			normalized[key] = string(encoded)
		}
	}
	return normalized
}

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

func evaluateTool(req ToolCallRequest) ToolCallResponse {
	pol := getPolicy()
	if ok, reason := validateToolCall(req); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}

	// Rate limit check
	if !checkRateLimit(pol) {
		return ToolCallResponse{Allowed: false, Reason: "rate limit exceeded"}
	}

	// Check deny list first (deny always wins)
	for _, denied := range pol.Tools.Deny {
		if denied.Name == req.Tool {
			return ToolCallResponse{Allowed: false, Reason: "tool is explicitly denied"}
		}
	}

	// loadPolicy rejects anything but default-deny. Keep evaluation fail-closed
	// if an invalid policy is ever injected in memory by a future refactor.
	if pol.Tools.Default != "deny" {
		return ToolCallResponse{Allowed: false, Reason: "invalid policy default"}
	}
	var matched *ToolEntry
	for i, allowed := range pol.Tools.Allow {
		if allowed.Name == req.Tool {
			matched = &pol.Tools.Allow[i]
			break
		}
	}
	if matched == nil {
		return ToolCallResponse{Allowed: false, Reason: "tool not in allowlist"}
	}
	if ok, reason := validateArgs(req, *matched); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}
	if ok, reason := checkPathConstraints(normalizeParams(effectiveTypedParams(req)), *matched); !ok {
		return ToolCallResponse{Allowed: false, Reason: reason}
	}

	return ToolCallResponse{Allowed: true}
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var wire toolCallRequestWire
	if err := decodeRequestJSON(w, r, &wire, maxRequestBodySize); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	rawParams := wire.Params
	if wire.Params != nil && wire.Args != nil {
		http.Error(w, "params and args cannot both be supplied", http.StatusBadRequest)
		return
	}
	if rawParams == nil && wire.Args != nil {
		rawParams = wire.Args
	}
	req := ToolCallRequest{
		Tool:        wire.Tool,
		Params:      normalizeParams(rawParams),
		TypedParams: rawParams,
	}

	totalRequests.Add(1)
	resp := evaluateTool(req)

	if !resp.Allowed {
		deniedRequests.Add(1)
	}

	// Structured logging
	log.Printf("tool-firewall: tool=%s allowed=%t reason=%q", req.Tool, resp.Allowed, resp.Reason)

	// Audit log
	if err := writeAudit(AuditEntry{
		Tool:    req.Tool,
		Params:  sanitizeToolAuditParams(req.TypedParams, getPolicy(), req.Tool),
		Allowed: resp.Allowed,
		Reason:  resp.Reason,
	}); err != nil {
		log.Printf("tool-firewall: audit write failed: %v", err)
		if resp.Allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "audit service unavailable"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func decodeRequestJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"total_requests":  totalRequests.Load(),
		"denied_requests": deniedRequests.Load(),
	})
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := loadPolicy(); err != nil {
		log.Printf("policy reload failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	log.Printf("policy reloaded successfully")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	pol := getPolicy()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"default_action":  pol.Tools.Default,
		"allowed_tools":   len(pol.Tools.Allow),
		"denied_tools":    len(pol.Tools.Deny),
		"total_requests":  totalRequests.Load(),
		"denied_requests": deniedRequests.Load(),
	})
}

func newToolFirewallMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/evaluate", requireServiceToken(handleEvaluate))
	mux.HandleFunc("/v1/stats", requireServiceToken(handleStats))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	return mux
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if err := loadPolicy(); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	initAuditLog()
	if err := loadServiceToken(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8475"
	}

	log.Print("secure-ai-tool-firewall starting configured listener")
	server := &http.Server{
		Addr:              bind,
		Handler:           newToolFirewallMux(),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
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
	log.Println("shutting down tool-firewall...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("tool-firewall shutdown failed: %v", err)
	}
	log.Println("tool-firewall stopped")
}

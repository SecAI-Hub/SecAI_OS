package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// =========================================================================
// Per-MCP-server trust tier enforcement
// =========================================================================

// TrustTier defines the trust level for an MCP server with enforced restrictions.
type TrustTier int

const (
	TrustUntrusted TrustTier = iota // Most restricted: rate-limited, no write, no sensitive
	TrustVerified                   // Medium: rate-limited, write with approval, some sensitive
	TrustTrusted                    // Least restricted: full access per policy
)

// TrustEnforcement maps trust levels to concrete restrictions.
type TrustEnforcement struct {
	MaxRatePerMinute  int      // Calls per minute cap
	AllowWrite        bool     // Can write to filesystem
	AllowSensitive    bool     // Can access sensitive data
	AllowNetwork      bool     // Can make network calls
	RequireApproval   bool     // Every call needs user approval
	AllowedNamespaces []string // Filesystem namespace restrictions
}

// Create issues an unpredictable server-generated session identifier and
// binding token. HTTP callers cannot choose or overwrite session identities.
func (sbm *SessionBindingManager) Create(serverName string, maxCalls, ttlSeconds int64) (*SessionBinding, error) {
	for attempts := 0; attempts < 4; attempts++ {
		randomID := make([]byte, 24)
		if _, err := rand.Read(randomID); err != nil {
			return nil, fmt.Errorf("generate session identifier: %w", err)
		}
		sessionID := base64.RawURLEncoding.EncodeToString(randomID)
		binding, err := sbm.Bind(sessionID, serverName, maxCalls, ttlSeconds)
		if err == nil {
			return binding, nil
		}
	}
	return nil, fmt.Errorf("could not allocate a unique session")
}

// DefaultTrustEnforcement returns enforcement rules for each trust tier.
func DefaultTrustEnforcement() map[string]*TrustEnforcement {
	return map[string]*TrustEnforcement{
		"trusted": {
			MaxRatePerMinute:  120,
			AllowWrite:        true,
			AllowSensitive:    true,
			AllowNetwork:      false,
			RequireApproval:   false,
			AllowedNamespaces: []string{"/var/lib/secure-ai/vault/**"},
		},
		"verified": {
			MaxRatePerMinute:  60,
			AllowWrite:        true,
			AllowSensitive:    false,
			AllowNetwork:      false,
			RequireApproval:   false,
			AllowedNamespaces: []string{"/var/lib/secure-ai/vault/outputs/**"},
		},
		"untrusted": {
			MaxRatePerMinute:  30,
			AllowWrite:        false,
			AllowSensitive:    false,
			AllowNetwork:      true,
			RequireApproval:   true,
			AllowedNamespaces: []string{}, // No filesystem access
		},
	}
}

// EnforceTrustTier checks if a request is allowed by the server's trust tier.
func EnforceTrustTier(serverTrust string, toolAction string, hasWriteArg bool, hasSensitiveArg bool) (bool, string) {
	rules := DefaultTrustEnforcement()
	enforcement, ok := rules[serverTrust]
	if !ok {
		return false, fmt.Sprintf("unknown trust level %q", serverTrust)
	}

	// Check write restriction
	if hasWriteArg && !enforcement.AllowWrite {
		return false, fmt.Sprintf("trust tier %q does not allow write operations", serverTrust)
	}

	// Check sensitive data restriction
	if hasSensitiveArg && !enforcement.AllowSensitive {
		return false, fmt.Sprintf("trust tier %q does not allow sensitive data access", serverTrust)
	}
	if enforcement.RequireApproval && toolAction != "require-approval" {
		return false, fmt.Sprintf("trust tier %q requires approval", serverTrust)
	}

	return true, "trust tier check passed"
}

// =========================================================================
// Per-tool isolation profiles
// =========================================================================

// ToolIsolationProfile defines syscall and filesystem restrictions per tool.
type ToolIsolationProfile struct {
	ToolName           string   `yaml:"tool_name" json:"tool_name"`
	AllowedSyscalls    []string `yaml:"allowed_syscalls" json:"allowed_syscalls"`
	BlockedSyscalls    []string `yaml:"blocked_syscalls" json:"blocked_syscalls"`
	AllowedPaths       []string `yaml:"allowed_paths" json:"allowed_paths"`
	BlockedPaths       []string `yaml:"blocked_paths" json:"blocked_paths"`
	MaxMemoryMB        int      `yaml:"max_memory_mb" json:"max_memory_mb"`
	MaxCPUSeconds      int      `yaml:"max_cpu_seconds" json:"max_cpu_seconds"`
	AllowNetworkAccess bool     `yaml:"allow_network" json:"allow_network"`
}

// DefaultToolProfiles returns built-in isolation profiles for common MCP tools.
func DefaultToolProfiles() map[string]*ToolIsolationProfile {
	return map[string]*ToolIsolationProfile{
		"read_file": {
			ToolName:        "read_file",
			AllowedSyscalls: []string{"read", "open", "openat", "stat", "fstat", "close"},
			BlockedSyscalls: []string{"write", "unlink", "rename", "execve"},
			AllowedPaths:    []string{"/var/lib/secure-ai/vault/**"},
			BlockedPaths:    []string{"/etc/shadow", "/etc/passwd", "/run/secure-ai/**"},
			MaxMemoryMB:     256,
			MaxCPUSeconds:   5,
		},
		"write_file": {
			ToolName:        "write_file",
			AllowedSyscalls: []string{"read", "write", "open", "openat", "stat", "fstat", "close", "fsync"},
			BlockedSyscalls: []string{"execve", "unlink", "rename"},
			AllowedPaths:    []string{"/var/lib/secure-ai/vault/outputs/**"},
			BlockedPaths:    []string{"/etc/**", "/run/**", "/usr/**"},
			MaxMemoryMB:     256,
			MaxCPUSeconds:   10,
		},
		"list_directory": {
			ToolName:        "list_directory",
			AllowedSyscalls: []string{"read", "open", "openat", "getdents64", "stat", "fstat", "close"},
			BlockedSyscalls: []string{"write", "unlink", "rename", "execve"},
			AllowedPaths:    []string{"/var/lib/secure-ai/vault/**"},
			BlockedPaths:    []string{"/etc/shadow", "/run/secure-ai/**"},
			MaxMemoryMB:     128,
			MaxCPUSeconds:   3,
		},
		"search": {
			ToolName:           "search",
			AllowedSyscalls:    []string{"read", "write", "socket", "connect", "sendto", "recvfrom"},
			BlockedSyscalls:    []string{"execve", "open", "openat", "unlink"},
			AllowedPaths:       []string{}, // No filesystem access
			BlockedPaths:       []string{"/**"},
			MaxMemoryMB:        512,
			MaxCPUSeconds:      30,
			AllowNetworkAccess: true,
		},
	}
}

// GetToolProfile returns the isolation profile for a tool, or a restrictive
// default if no specific profile exists.
func GetToolProfile(toolName string) *ToolIsolationProfile {
	profiles := DefaultToolProfiles()
	if p, ok := profiles[toolName]; ok {
		return p
	}
	// Default: most restrictive profile
	return &ToolIsolationProfile{
		ToolName:        toolName,
		AllowedSyscalls: []string{"read", "close"},
		BlockedSyscalls: []string{"write", "execve", "unlink", "rename", "socket"},
		AllowedPaths:    []string{},
		BlockedPaths:    []string{"/**"},
		MaxMemoryMB:     64,
		MaxCPUSeconds:   3,
	}
}

// =========================================================================
// Session binding — hard token and session binding for MCP actions
// =========================================================================

// SessionBinding binds an MCP session to a specific context that cannot
// be reused across sessions or replayed.
type SessionBinding struct {
	SessionID    string `json:"session_id"`
	ServerName   string `json:"server_name"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	BindingToken string `json:"binding_token"` // HMAC over session context
	CallCount    int64  `json:"call_count"`
	MaxCalls     int64  `json:"max_calls"`
}

// SessionBindingManager tracks and validates session bindings.
type SessionBindingManager struct {
	mu          sync.RWMutex
	bindings    map[string]*SessionBinding // session_id -> binding
	key         []byte                     // HMAC signing key
	maxBindings int
}

func NewSessionBindingManager(key []byte) (*SessionBindingManager, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("session-binding key must contain at least 32 bytes")
	}
	keyCopy := append([]byte(nil), key...)
	return &SessionBindingManager{
		bindings:    make(map[string]*SessionBinding),
		key:         keyCopy,
		maxBindings: 10_000,
	}, nil
}

// Bind creates a new session binding, or returns the existing one.
func (sbm *SessionBindingManager) Bind(sessionID, serverName string, maxCalls int64, ttlSeconds int64) (*SessionBinding, error) {
	if !safePathIdentifier(sessionID) || !safePathIdentifier(serverName) || maxCalls <= 0 || ttlSeconds <= 0 || ttlSeconds > 86400 {
		return nil, fmt.Errorf("invalid session binding parameters")
	}
	sbm.mu.Lock()
	defer sbm.mu.Unlock()
	sbm.pruneExpiredLocked(time.Now().Unix())

	if existing, ok := sbm.bindings[sessionID]; ok {
		if existing.ServerName != serverName || existing.MaxCalls != maxCalls {
			return nil, fmt.Errorf("session is already bound with different constraints")
		}
		return cloneSessionBinding(existing), nil
	}
	if len(sbm.bindings) >= sbm.maxBindings {
		return nil, fmt.Errorf("session binding capacity exhausted")
	}

	now := time.Now().Unix()
	binding := &SessionBinding{
		SessionID:  sessionID,
		ServerName: serverName,
		CreatedAt:  now,
		ExpiresAt:  now + ttlSeconds,
		MaxCalls:   maxCalls,
	}

	// Compute binding token
	binding.BindingToken = sbm.computeToken(binding)
	sbm.bindings[sessionID] = binding

	log.Printf("session-binding: created for session_hash=%s server=%s maxCalls=%d ttl=%ds",
		auditFingerprint(sessionID), serverName, maxCalls, ttlSeconds)

	return cloneSessionBinding(binding), nil
}

// Validate checks if a request is allowed under the current session binding.
func (sbm *SessionBindingManager) Validate(sessionID, serverName, bindingToken string) (bool, string) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	binding, ok := sbm.bindings[sessionID]
	if !ok {
		return false, "no session binding found — session not initialized"
	}

	// Check server name matches
	if binding.ServerName != serverName {
		return false, fmt.Sprintf("session bound to server %q, not %q", binding.ServerName, serverName)
	}

	// Check expiry
	if time.Now().Unix() >= binding.ExpiresAt {
		delete(sbm.bindings, sessionID)
		return false, "session binding expired"
	}

	// Check call count
	if binding.MaxCalls > 0 && binding.CallCount >= binding.MaxCalls {
		return false, "session call limit exceeded"
	}

	// Verify token integrity
	expected := sbm.computeToken(binding)
	if !hmac.Equal([]byte(binding.BindingToken), []byte(expected)) ||
		!hmac.Equal([]byte(bindingToken), []byte(expected)) {
		return false, "session binding token tampered"
	}

	binding.CallCount++
	return true, "session binding valid"
}

// ValidateBatch atomically validates and reserves the call allowance for every
// request. A bad later element never partially consumes earlier allowances.
func (sbm *SessionBindingManager) ValidateBatch(requests []EvalRequest) (bool, string) {
	if len(requests) == 0 || len(requests) > 100 {
		return false, "invalid session batch"
	}
	sbm.mu.Lock()
	defer sbm.mu.Unlock()
	now := time.Now().Unix()
	sbm.pruneExpiredLocked(now)
	requestedCalls := make(map[string]int64)
	for _, request := range requests {
		binding, ok := sbm.bindings[request.SessionID]
		if !ok || binding.ServerName != request.Server || now >= binding.ExpiresAt {
			return false, "session binding context is invalid"
		}
		expected := sbm.computeToken(binding)
		if !hmac.Equal([]byte(binding.BindingToken), []byte(expected)) ||
			!hmac.Equal([]byte(request.SessionToken), []byte(expected)) {
			return false, "session binding token is invalid"
		}
		requestedCalls[request.SessionID]++
	}
	for sessionID, count := range requestedCalls {
		binding := sbm.bindings[sessionID]
		if binding.MaxCalls > 0 && binding.CallCount+count > binding.MaxCalls {
			return false, "session call limit exceeded"
		}
	}
	for sessionID, count := range requestedCalls {
		sbm.bindings[sessionID].CallCount += count
	}
	return true, "session batch valid"
}

// Check validates a binding without consuming its policy-call allowance. It is
// used only to authenticate execution completion for an already-evaluated call.
func (sbm *SessionBindingManager) Check(sessionID, serverName, bindingToken string) (bool, string) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()
	binding, ok := sbm.bindings[sessionID]
	if !ok {
		return false, "no session binding found"
	}
	if binding.ServerName != serverName || time.Now().Unix() >= binding.ExpiresAt {
		if time.Now().Unix() >= binding.ExpiresAt {
			delete(sbm.bindings, sessionID)
		}
		return false, "session binding context is invalid"
	}
	expected := sbm.computeToken(binding)
	if !hmac.Equal([]byte(binding.BindingToken), []byte(expected)) ||
		!hmac.Equal([]byte(bindingToken), []byte(expected)) {
		return false, "session binding token is invalid"
	}
	return true, "session binding valid"
}

// Revoke removes a session binding.
func (sbm *SessionBindingManager) Revoke(sessionID string) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()
	delete(sbm.bindings, sessionID)
}

func (sbm *SessionBindingManager) computeToken(b *SessionBinding) string {
	payload := fmt.Sprintf("%s:%s:%d:%d:%d", b.SessionID, b.ServerName, b.CreatedAt, b.ExpiresAt, b.MaxCalls)
	mac := hmac.New(sha256.New, sbm.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func cloneSessionBinding(binding *SessionBinding) *SessionBinding {
	if binding == nil {
		return nil
	}
	copy := *binding
	return &copy
}

func (sbm *SessionBindingManager) pruneExpiredLocked(now int64) {
	for sessionID, binding := range sbm.bindings {
		if now >= binding.ExpiresAt {
			delete(sbm.bindings, sessionID)
		}
	}
}

// ActiveBindings returns the count of active session bindings.
func (sbm *SessionBindingManager) ActiveBindings() int {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()
	sbm.pruneExpiredLocked(time.Now().Unix())
	return len(sbm.bindings)
}

// =========================================================================
// Dynamic tool registration denial
// =========================================================================

// DenyDynamicRegistration checks if a tool is attempting to register
// dynamically (not in the pre-configured policy). This is always denied.
func DenyDynamicRegistration(serverName, toolName string, policy *FirewallPolicy) (bool, string) {
	if policy == nil {
		return false, "no policy loaded — all tools denied"
	}

	for _, server := range policy.Servers {
		if server.Name != serverName {
			continue
		}
		for _, tool := range server.AllowedTools {
			if tool.Name == toolName {
				return true, "tool is pre-registered in policy"
			}
		}
		return false, fmt.Sprintf(
			"tool %q is not registered for server %q — dynamic registration denied; "+
				"tools must be promoted through the trusted artifact path",
			toolName, serverName,
		)
	}

	return false, fmt.Sprintf("server %q not in policy — all tools denied", serverName)
}

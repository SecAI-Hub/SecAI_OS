package main

import (
	"testing"
)

// =========================================================================
// Trust tier enforcement tests
// =========================================================================

func TestTrustTier_UntrustedCannotWrite(t *testing.T) {
	ok, reason := EnforceTrustTier("untrusted", "write_file", true, false)
	if ok {
		t.Error("untrusted tier should not allow write")
	}
	t.Logf("deny reason: %s", reason)
}

func TestTrustTier_UntrustedCannotAccessSensitive(t *testing.T) {
	ok, reason := EnforceTrustTier("untrusted", "read_file", false, true)
	if ok {
		t.Error("untrusted tier should not allow sensitive access")
	}
	t.Logf("deny reason: %s", reason)
}

func TestTrustTier_TrustedAllowsWrite(t *testing.T) {
	ok, _ := EnforceTrustTier("trusted", "write_file", true, false)
	if !ok {
		t.Error("trusted tier should allow write")
	}
}

func TestTrustTier_TrustedAllowsSensitive(t *testing.T) {
	ok, _ := EnforceTrustTier("trusted", "read_file", false, true)
	if !ok {
		t.Error("trusted tier should allow sensitive")
	}
}

func TestTrustTier_VerifiedAllowsWrite(t *testing.T) {
	ok, _ := EnforceTrustTier("verified", "write_file", true, false)
	if !ok {
		t.Error("verified tier should allow write")
	}
}

func TestTrustTier_VerifiedDeniesSensitive(t *testing.T) {
	ok, _ := EnforceTrustTier("verified", "read_file", false, true)
	if ok {
		t.Error("verified tier should not allow sensitive access")
	}
}

func TestTrustTier_UnknownTierDenied(t *testing.T) {
	ok, _ := EnforceTrustTier("alien", "read_file", false, false)
	if ok {
		t.Error("unknown trust tier should be denied")
	}
}

// =========================================================================
// Tool profile tests
// =========================================================================

func TestToolProfile_ReadFile(t *testing.T) {
	p := GetToolProfile("read_file")
	if p.AllowNetworkAccess {
		t.Error("read_file should not allow network access")
	}
	if len(p.BlockedPaths) == 0 {
		t.Error("read_file should have blocked paths")
	}
}

func TestToolProfile_Search(t *testing.T) {
	p := GetToolProfile("search")
	if !p.AllowNetworkAccess {
		t.Error("search should allow network access")
	}
	if len(p.AllowedPaths) > 0 {
		t.Error("search should have no filesystem access")
	}
}

func TestToolProfile_UnknownToolGetsRestrictive(t *testing.T) {
	p := GetToolProfile("unknown_tool_xyz")
	if p.AllowNetworkAccess {
		t.Error("unknown tool should not allow network")
	}
	if p.MaxMemoryMB > 64 {
		t.Errorf("unknown tool should have low memory limit, got %d", p.MaxMemoryMB)
	}
}

func TestToolProfile_WriteFile(t *testing.T) {
	p := GetToolProfile("write_file")
	if p.AllowNetworkAccess {
		t.Error("write_file should not allow network access")
	}
	if len(p.AllowedPaths) == 0 {
		t.Error("write_file should have allowed paths")
	}
}

// =========================================================================
// Session binding tests
// =========================================================================

func TestSessionBinding_CreateAndValidate(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	sbm.Bind("session-001", "filesystem", 100, 3600)

	ok, reason := sbm.Validate("session-001", "filesystem")
	if !ok {
		t.Fatalf("valid session should pass: %s", reason)
	}
}

func TestSessionBinding_WrongServerDenied(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	sbm.Bind("session-002", "filesystem", 100, 3600)

	ok, _ := sbm.Validate("session-002", "web-search")
	if ok {
		t.Error("wrong server should be denied")
	}
}

func TestSessionBinding_ExpiredSessionDenied(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	sbm.Bind("session-003", "filesystem", 100, -1) // Already expired

	ok, _ := sbm.Validate("session-003", "filesystem")
	if ok {
		t.Error("expired session should be denied")
	}
}

func TestSessionBinding_CallLimitExceeded(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	sbm.Bind("session-004", "filesystem", 2, 3600)

	sbm.Validate("session-004", "filesystem") // call 1
	sbm.Validate("session-004", "filesystem") // call 2

	ok, _ := sbm.Validate("session-004", "filesystem") // call 3 (over limit)
	if ok {
		t.Error("call limit exceeded should be denied")
	}
}

func TestSessionBinding_UnknownSessionDenied(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	ok, _ := sbm.Validate("unknown-session", "filesystem")
	if ok {
		t.Error("unknown session should be denied")
	}
}

func TestSessionBinding_Revoke(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	sbm.Bind("session-005", "filesystem", 100, 3600)
	sbm.Revoke("session-005")

	ok, _ := sbm.Validate("session-005", "filesystem")
	if ok {
		t.Error("revoked session should be denied")
	}
}

func TestSessionBinding_ActiveCount(t *testing.T) {
	sbm := NewSessionBindingManager([]byte("test-key"))
	if sbm.ActiveBindings() != 0 {
		t.Fatal("should start with 0 active bindings")
	}
	sbm.Bind("session-A", "filesystem", 100, 3600)
	sbm.Bind("session-B", "web-search", 50, 1800)
	if sbm.ActiveBindings() != 2 {
		t.Fatalf("expected 2 active bindings, got %d", sbm.ActiveBindings())
	}
}

// =========================================================================
// Dynamic registration denial tests
// =========================================================================

// isolationTestPolicy returns a FirewallPolicy for isolation tests.
func isolationTestPolicy() *FirewallPolicy {
	return &FirewallPolicy{
		Version:       1,
		DefaultAction: "deny",
		Servers: []ServerPolicy{
			{
				Name:       "filesystem",
				TrustLevel: "trusted",
				AllowedTools: []ToolPolicy{
					{Name: "read_file", Action: "allow"},
					{Name: "write_file", Action: "allow"},
					{Name: "list_directory", Action: "allow"},
				},
			},
			{
				Name:       "web-search",
				TrustLevel: "untrusted",
				AllowedTools: []ToolPolicy{
					{Name: "search", Action: "allow", TaintLabel: "external-data"},
				},
			},
		},
	}
}

func TestDenyDynamicRegistration_RegisteredToolAllowed(t *testing.T) {
	pol := isolationTestPolicy()
	ok, _ := DenyDynamicRegistration("filesystem", "read_file", pol)
	if !ok {
		t.Error("registered tool should be allowed")
	}
}

func TestDenyDynamicRegistration_UnregisteredToolDenied(t *testing.T) {
	pol := isolationTestPolicy()
	ok, reason := DenyDynamicRegistration("filesystem", "delete_all", pol)
	if ok {
		t.Error("unregistered tool should be denied")
	}
	if reason == "" {
		t.Error("should have a reason for denial")
	}
}

func TestDenyDynamicRegistration_UnknownServerDenied(t *testing.T) {
	pol := isolationTestPolicy()
	ok, _ := DenyDynamicRegistration("evil-server", "any_tool", pol)
	if ok {
		t.Error("unknown server should be denied")
	}
}

func TestDenyDynamicRegistration_NilPolicyDenied(t *testing.T) {
	ok, _ := DenyDynamicRegistration("filesystem", "read_file", nil)
	if ok {
		t.Error("nil policy should deny all tools")
	}
}

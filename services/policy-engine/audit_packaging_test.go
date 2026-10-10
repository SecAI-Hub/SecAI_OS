package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeAuditOwnerPersistsAcrossRestarts(t *testing.T) {
	name := "policy-engine"
	dir := filepath.Join("..", "..", "files", "system", "usr", "lib")
	unit, err := os.ReadFile(filepath.Join(dir, "systemd", "system", "secure-ai-"+name+".service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"User=secure-ai-" + name, "Group=secure-ai-" + name, "UMask=0077", "SupplementaryGroups=secure-ai-logs", "ProtectSystem=strict", "ReadWritePaths=/var/lib/secure-ai/logs"} {
		if !strings.Contains(string(unit), required) {
			t.Fatal("missing audit owner/isolation contract", required)
		}
	}
	if strings.Contains(string(unit), "DynamicUser=yes") {
		t.Fatal("ephemeral audit owner")
	}
	users, err := os.ReadFile(filepath.Join(dir, "sysusers.d", "secure-ai.conf"))
	if err != nil || !strings.Contains(string(users), "u secure-ai-"+name+" - ") {
		t.Fatal("missing stable audit identity", err)
	}
}

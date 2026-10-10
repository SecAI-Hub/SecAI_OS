"""The packaged gateway must use the reviewed source and persistent credentials."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "services/mcp-firewall"


def test_embedded_mcp_source_matches_reviewed_helper_snapshot():
    manifest = json.loads((COMPONENT / "UPSTREAM_SYNC.json").read_text())
    assert manifest["schema_version"] == 1
    assert len(manifest["base_commit"]) == 40
    assert "remediation_test.go" in manifest["files"]
    for relative, digest in manifest["files"].items():
        assert hashlib.sha256((COMPONENT / relative).read_bytes()).hexdigest() == digest
    builder = (ROOT / "files/scripts/build-services.sh").read_text()
    source_selection = builder.split("if locate_source mcp-firewall", 1)[1].split("; then", 1)[0]
    assert "/tmp/services/mcp-firewall" in source_selection
    assert "/tmp/upstreams" not in source_selection


def test_native_gateway_keeps_recovery_state_and_separates_authorities():
    system = ROOT / "files/system"
    unit = (system / "usr/lib/systemd/system/secure-ai-mcp-firewall.service").read_text()
    provisioner = (system / "usr/libexec/secure-ai/provision-service-credentials.sh").read_text()
    for name, destination in (("mcp-firewall-admin.token", "admin-token"), ("mcp-firewall-signing.key", "signing-key")):
        assert f"validate_or_create {name}" in provisioner
        assert f"LoadCredential={destination}:/var/lib/secure-ai/credentials/{name}" in unit
    assert "Environment=ADMIN_TOKEN_PATH=%d/admin-token" in unit
    assert "Environment=SIGNING_KEY_PATH=%d/signing-key" in unit
    assert "User=secure-ai-mcp" in unit
    tmpfiles = (system / "usr/lib/tmpfiles.d/secure-ai.conf").read_text()
    assert "mcp-firewall-audit.jsonl 0600 secure-ai-mcp secure-ai-mcp" in tmpfiles
    assert "3770 root secure-ai-logs" in tmpfiles
    profile = json.loads((system / "etc/secure-ai/config/service-profile.json").read_text())
    assert next(s for s in profile["services"] if s["id"] == "mcp-firewall")["health_url"].endswith("/ready")

"""Execute the wizard's TPM status and enrollment flow with private peers."""

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WIZARD = ROOT / "files/scripts/secai-setup-wizard.sh"
SOURCE = WIZARD.read_text()
FUNCTIONS = SOURCE[SOURCE.index("read_tpm_state() {"):SOURCE.index("\n# Preamble")]
STEP = SOURCE[SOURCE.index("TPM2_STATE=not_checked\n"):SOURCE.index('# Step 6:')]
SUMMARY = SOURCE[SOURCE.index("# TPM2\n"):SOURCE.index("# Cosign key")]
ENROLLED = {
    "schema_version": 1,
    "tpm2_available": True,
    "enrolled": True,
    "crypttab_tpm2_enabled": True,
    "assurance": "pcr_bound",
    "virtualization": "none",
    "token_count": 1,
    "pcr_binding": "sha256:0,2,4,7",
}


def peer(tmp_path, response, status=0, after=None, seal_status=0):
    (tmp_path / "response").write_text(response)
    (tmp_path / "after").write_text(response if after is None else after)
    path = tmp_path / "tpm-peer"
    path.write_text(f'''#!/bin/bash
set -eu
printf '%s\\n' "$1" >> "$PEER_DIR/calls"
if [ "$1" = status ]; then
    cat "$PEER_DIR/response"
    exit {status}
fi
if [ "$1" = seal ]; then
    cp "$PEER_DIR/after" "$PEER_DIR/response"
    exit {seal_status}
fi
exit 1
''')
    path.chmod(0o700)
    return path


def run(tmp_path, path, body):
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + FUNCTIONS + '\nTPM2_SEAL="$TPM_PEER"\n' + body],
        env={**os.environ, "TPM_PEER": str(path), "PEER_DIR": str(tmp_path)},
        capture_output=True, text=True, timeout=5, check=False,
    )


@pytest.mark.parametrize("change,status,expected", [
    ({}, 0, "enrolled"),
    ({}, 1, "unverified"),
    ({}, 2, "unverified"),
    ({}, 3, "error"),
    ({"schema_version": True}, 0, "error"),
    ({"enrolled": 1}, 0, "error"),
    ({"enrolled": "true"}, 0, "error"),
    ({"tpm2_available": False}, 0, "unavailable"),
    ({"assurance": "virtual_tpm_host_controlled", "virtualization": "kvm"}, 2, "unverified"),
    ({"assurance": "secure_boot_not_verified"}, 2, "unverified"),
    ({"virtualization": "unknown"}, 0, "unverified"),
    ({"crypttab_tpm2_enabled": False}, 0, "unverified"),
    ({"token_count": True}, 0, "unverified"),
    ({"token_count": 2}, 0, "unverified"),
    ({"pcr_binding": "sha256:7"}, 0, "unverified"),
    ({"enrolled": False, "crypttab_tpm2_enabled": False, "assurance": "not_enrolled"}, 1, "not_enrolled"),
])
def test_wizard_requires_current_exact_enrollment(tmp_path, change, status, expected):
    path = peer(tmp_path, json.dumps({**ENROLLED, **change}), status)
    result = run(tmp_path, path, "read_tpm_state")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize("response", ["", "{}", "invalid", "[]", '"text"', "x" * 16385])
def test_wizard_invalid_tpm_status_cannot_pass(tmp_path, response):
    path = peer(tmp_path, response)
    result = run(tmp_path, path, "read_tpm_state")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "error"


@pytest.mark.parametrize("after,seal_status,expected_errors,reported", [
    (json.dumps(ENROLLED), 0, 0, True),
    ("invalid", 0, 1, False),
    (json.dumps({**ENROLLED, "assurance": "secure_boot_not_verified"}), 0, 1, False),
    (json.dumps(ENROLLED), 1, 1, False),
])
def test_wizard_rechecks_after_enrollment(tmp_path, after, seal_status, expected_errors, reported):
    initial = json.dumps({**ENROLLED, "enrolled": False, "crypttab_tpm2_enabled": False,
                          "assurance": "not_enrolled"})
    path = peer(tmp_path, initial, after=after, seal_status=seal_status)
    body = '''
ERRORS=0; WARNINGS=0; VAULT_READY=true
pass() { printf 'PASS %s\\n' "$*"; }
info() { printf 'INFO %s\\n' "$*"; }
fail() { printf 'FAIL %s\\n' "$*"; ERRORS=$((ERRORS + 1)); }
warn_msg() { WARNINGS=$((WARNINGS + 1)); }
ask_yes_no() { return 0; }
''' + STEP + '\nprintf "errors=%s\\n" "$ERRORS"\n'
    result = run(tmp_path, path, body)
    assert result.returncode == 0, result.stderr
    assert f"errors={expected_errors}" in result.stdout
    assert ("PASS Vault TPM2 enrollment:" in result.stdout) is reported
    if reported:
        assert "Automatic unlock and recovery passphrase still require" in result.stdout
    calls = (tmp_path / "calls").read_text().splitlines()
    assert calls == (["status", "seal", "status"] if seal_status == 0 else ["status", "seal"])


def test_wizard_does_not_use_legacy_sealed_file_for_enrollment():
    assert "vault-key.sealed" not in SOURCE
    assert '"$TPM2_STATE" = enrolled' in SUMMARY

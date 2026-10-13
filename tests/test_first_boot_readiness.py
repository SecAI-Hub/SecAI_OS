"""Readiness rejects unavailable or contradictory native service evidence."""

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "files/scripts/first-boot-check.sh"
SOURCE = SCRIPT.read_text()
FUNCTIONS = SOURCE[SOURCE.index("security_reply() {"):SOURCE.index('echo "=============================================="')]
SECURITY = SOURCE[SOURCE.index("# Check attestation state"):SOURCE.index("# 4. Filesystem")]
ATTESTED = {
    "schema_version": 2, "verification_scope": "runtime", "assurance_mode": "hardware",
    "gpu_mode": "required", "gpu_policy_satisfied": True, "policy_satisfied": True,
    "verified": True, "evidence_verified": True, "state": "attested",
}
INTEGRITY = {"state": "trusted", "scan_count": 1, "violation_count": 0}


def invoke(body, data="", env=None):
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + FUNCTIONS + body],
                          input=data, capture_output=True, text=True, timeout=5,
                          env={**os.environ, **(env or {})}, check=False)


@pytest.mark.parametrize("kind,data,accepted", [
    ("attestation", ATTESTED, True),
    ("attestation", {**ATTESTED, "schema_version": True}, False),
    ("attestation", {**ATTESTED, "verification_scope": "bootstrap"}, False),
    ("attestation", {**ATTESTED, "assurance_mode": "evaluation"}, False),
    ("attestation", {**ATTESTED, "gpu_policy_satisfied": False}, False),
    ("attestation", {**ATTESTED, "verified": 1}, False),
    ("attestation", {**ATTESTED, "evidence_verified": False}, False),
    ("attestation", {**ATTESTED, "policy_satisfied": False}, False),
    ("attestation", {**ATTESTED, "state": "pending"}, False),
    ("attestation", {**ATTESTED, "gpu_mode": "auto"}, False),
    ("integrity", INTEGRITY, True),
    ("integrity", {**INTEGRITY, "state": "recovery_required"}, False),
    ("integrity", {**INTEGRITY, "scan_count": 0}, False),
    ("integrity", {**INTEGRITY, "scan_count": True}, False),
    ("integrity", {**INTEGRITY, "violation_count": 1}, False),
    ("incidents", {"open_incidents": 0}, True),
    ("incidents", {"open_incidents": 2}, True),
    ("incidents", {}, False),
    ("incidents", {"open_incidents": False}, False),
    ("incidents", {"open_incidents": -1}, False),
    ("incidents", {"open_incidents": "0"}, False),
])
def test_readiness_requires_exact_security_evidence(kind, data, accepted):
    result = invoke(f"security_reply {kind}\n", json.dumps(data))
    assert (result.returncode == 0) is accepted, result.stderr


@pytest.mark.parametrize("data", ["", "garbage", "null", "[]", '{"open_incidents":1,"open_incidents":0}',
                                 '{"open_incidents":0}\n{"open_incidents":0}'])
def test_malformed_or_duplicate_incident_evidence_is_not_clean(data):
    assert invoke("security_reply incidents\n", data).returncode != 0


@pytest.mark.parametrize("incident,expected,clean", [
    (json.dumps({"open_incidents": 0}), "errors=0 warnings=0", True),
    (json.dumps({"open_incidents": 1}), "errors=0 warnings=1", False),
    ("", "errors=1 warnings=0", False),
    ("invalid", "errors=1 warnings=0", False),
])
def test_unavailable_incident_service_cannot_report_no_incidents(tmp_path, incident, expected, clean):
    for name, data in [("attestation", ATTESTED), ("integrity", INTEGRITY)]:
        (tmp_path / name).write_text(json.dumps(data))
    (tmp_path / "incidents").write_text(incident)
    body = '''
ERRORS=0; WARNINGS=0
info() { printf 'OK %s\\n' "$*"; }
warn() { printf 'WARN %s\\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf 'FAIL %s\\n' "$*"; ERRORS=$((ERRORS + 1)); }
credential_get() {
    case "$1" in
        runtime-attestor.token) name=attestation ;;
        integrity-monitor.token) name=integrity ;;
        incident-read.token) name=incidents ;;
        *) return 1 ;;
    esac
    [ -s "$PEER_DIR/$name" ] || return 1
    cat "$PEER_DIR/$name"
}
''' + SECURITY + '\nprintf "errors=%s warnings=%s\\n" "$ERRORS" "$WARNINGS"\n'
    result = invoke(body, env={"PEER_DIR": str(tmp_path)})
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert ("OK No open incidents" in result.stdout) is clean


@pytest.mark.parametrize("change,accepted", [
    ({}, True),
    ({"services": []}, False),
    ({"version": True}, False),
    ({"services": [{"id": "agent", "unit": "secure-ai-agent.service", "required": False}]}, False),
    ({"services": [{"id": "agent", "unit": "secure-ai-agent.service", "required": "true"}]}, False),
    ({"services": [{"id": "agent", "unit": "secure-ai-agent.service", "required": True,
                    "health_url": "http://example.com/health"}]}, False),
    ({"services": [{"id": "agent", "unit": "secure-ai-agent.service", "required": True,
                    "health_url": "http://127.0.0.1:8480/health\n"}]}, False),
    ({"services": [{"id": "agent", "unit": "secure-ai-agent.service", "required": True,
                    "inbound_credential": "../../other-secret"}]}, False),
])
def test_profile_validation_cannot_silently_skip_required_checks(tmp_path, change, accepted):
    profile = json.loads((ROOT / "files/system/etc/secure-ai/config/service-profile.json").read_text())
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({**profile, **change}))
    result = invoke("load_service_profile\n", env={"SERVICE_PROFILE": str(path)})
    assert (result.returncode == 0) is accepted, result.stderr


def test_native_unix_health_endpoint_is_probed(tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": 1, "services": [{"id": "agent", "required": True,
                        "unit": "secure-ai-agent.service", "health_url": "unix:///run/secure-ai/agent/agent.sock"}]}))
    body = '''
ERRORS=0
info() { :; }
fail() { ERRORS=$((ERRORS + 1)); }
curl() { printf '%s\\n' "$@" > "$CURL_ARGS"; }
PROFILE_JSON=$(load_service_profile)
''' + SOURCE[SOURCE.index("mapfile -t HEALTH_ENDPOINTS"):SOURCE.index("# 3. Security")]
    args = tmp_path / "curl-args"
    result = invoke(body, env={"SERVICE_PROFILE": str(profile), "CURL_ARGS": str(args)})
    assert result.returncode == 0, result.stderr
    called = args.read_text().splitlines()
    assert called[called.index("--unix-socket") + 1] == "/run/secure-ai/agent/agent.sock"
    assert "http://localhost/health" in called
    assert called[called.index("--max-time") + 1] == "5"

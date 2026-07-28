"""Native credential wiring for UI sessions and containment capabilities."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT_DIR = (
    REPO_ROOT / "files/system/usr/lib/systemd/system"
)
PROVISIONER = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/provision-service-credentials.sh"
)


def _unit(name: str) -> str:
    return (UNIT_DIR / name).read_text(encoding="utf-8")


def test_ui_has_persistent_flask_and_agent_control_credentials():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    unit = _unit("secure-ai-ui.service")

    assert "validate_or_create ui-flask-session.key" in provisioner
    assert "validate_or_create agent-ui.token" in provisioner
    assert (
        "LoadCredential=flask-session-key:"
        "/var/lib/secure-ai/credentials/ui-flask-session.key"
    ) in unit
    assert "Environment=FLASK_SECRET_KEY_PATH=%d/flask-session-key" in unit
    assert (
        "LoadCredential=agent-ui-token:"
        "/var/lib/secure-ai/credentials/agent-ui.token"
    ) in unit
    assert "Environment=AGENT_TOKEN_PATH=%d/agent-ui-token" in unit


def test_incident_recorder_uses_scoped_inbound_and_containment_capabilities():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    recorder = _unit("secure-ai-incident-recorder.service")
    agent = _unit("secure-ai-agent.service")
    airlock = _unit("secure-ai-airlock.service")
    registry = _unit("secure-ai-registry.service")

    for name in (
        "agent-containment.token",
        "airlock-containment.token",
        "registry-containment.token",
    ):
        assert f"validate_or_create {name}" in provisioner

    assert "AGENT_CONTAINMENT_TOKEN_PATH=%d/agent-containment-token" in recorder
    assert "AIRLOCK_CONTAINMENT_TOKEN_PATH=%d/airlock-containment-token" in recorder
    assert "REGISTRY_CONTAINMENT_TOKEN_PATH=%d/registry-containment-token" in recorder
    assert "credentials/agent.token" not in recorder
    assert "credentials/airlock.token" not in recorder
    assert "credentials/registry.token" not in recorder

    assert "AGENT_UI_TOKEN_PATH=%d/ui-control-token" in agent
    assert "AGENT_CONTAINMENT_TOKEN_PATH=%d/containment-token" in agent
    assert "credentials/agent-ui.token" in agent
    assert "credentials/agent-containment.token" in agent
    assert "credentials/airlock-containment.token" in airlock
    assert "credentials/registry-containment.token" in registry

    profile = json.loads(
        (
            REPO_ROOT / "files/system/etc/secure-ai/config/service-profile.json"
        ).read_text(encoding="utf-8")
    )
    by_id = {service["id"]: service for service in profile["services"]}
    assert by_id["agent"]["inbound_credential"] == "agent-ui.token"
    assert by_id["agent"]["containment_credential"] == "agent-containment.token"
    assert by_id["airlock"]["containment_credential"] == "airlock-containment.token"
    assert by_id["registry"]["containment_credential"] == "registry-containment.token"


def test_registry_native_callers_receive_only_their_required_scope():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    registry = _unit("secure-ai-registry.service")
    agent = _unit("secure-ai-agent.service")
    watcher = _unit("secure-ai-quarantine-watcher.service")
    health = _unit("secure-ai-health-check.service")
    integrity = _unit("secure-ai-integrity.service")
    ui = _unit("secure-ai-ui.service")

    for scope in ("read", "verify", "promote", "admin"):
        assert f"validate_or_create registry-{scope}.token" in provisioner
        assert (
            f"/var/lib/secure-ai/credentials/registry-{scope}.token"
        ) in registry
    assert "credentials/registry-read.token" in agent
    assert "credentials/registry-promote.token" in watcher
    assert "credentials/registry-verify.token" in health
    assert "credentials/registry-verify.token" in integrity
    assert "credentials/registry-admin.token" in ui
    for unit in (registry, agent, watcher, health, integrity, ui):
        assert "credentials/registry.token" not in unit


def test_incident_reporters_and_operators_are_source_scoped():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    recorder = _unit("secure-ai-incident-recorder.service")
    reporter_units = {
        "canary": _unit("secure-ai-canary.service"),
        "gpu-integrity": _unit("secure-ai-gpu-integrity-watch.service"),
        "integrity-monitor": _unit("secure-ai-integrity-monitor.service"),
        "runtime-attestor": _unit("secure-ai-runtime-attestor.service"),
    }

    for source, unit in reporter_units.items():
        credential = f"incident-reporter-{source}.token"
        assert f"validate_or_create {credential}" in provisioner
        assert f"credentials/{credential}" in recorder
        assert f"credentials/{credential}" in unit
        assert "credentials/incident-read.token" not in unit
        assert "credentials/incident-operator.token" not in unit
        assert "credentials/incident-recovery-admin.token" not in unit
        assert "credentials/incident-forensic.token" not in unit

    ui = _unit("secure-ai-ui.service")
    health = _unit("secure-ai-health-check.service")
    assert "credentials/incident-read.token" in ui
    assert "credentials/incident-operator.token" in ui
    assert "credentials/incident-read.token" in health
    assert "credentials/incident-forensic.token" not in ui
    assert "credentials/incident-recovery-admin.token" not in ui

    forensic = (
        REPO_ROOT / "files/system/usr/libexec/secure-ai/secai-forensic.sh"
    ).read_text(encoding="utf-8")
    assert "/var/lib/secure-ai/credentials/incident-forensic.token" in forensic
    assert "incident-recorder.token" not in forensic


def test_agent_has_persistent_signing_credential_and_no_missing_legacy_path():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    agent = _unit("secure-ai-agent.service")
    policy = (
        REPO_ROOT / "files/system/etc/secure-ai/policy/keystore.yaml"
    ).read_text(encoding="utf-8")

    assert "validate_or_create agent-signing.key" in provisioner
    assert "validate_or_create agent.token" not in provisioner
    assert (
        "LoadCredential=signing-key:"
        "/var/lib/secure-ai/credentials/agent-signing.key"
    ) in agent
    assert "Environment=AGENT_SIGNING_KEY_PATH=%d/signing-key" in agent
    assert "/run/secure-ai/token-secret" not in agent
    assert "/run/secure-ai/token-secret" not in policy
    assert (
        "default_key_path: "
        "/run/credentials/secure-ai-agent.service/signing-key"
    ) in policy


def test_credential_provisioner_rejects_tampered_sources_instead_of_repairing():
    provisioner = PROVISIONER.read_text(encoding="utf-8")
    unit = _unit("secure-ai-credentials.service")

    assert "'%F:%u:%g:%a:%h:%s'" in provisioner
    assert "canonical 256-bit secret" in provisioner
    assert "ln --" in provisioner
    assert "mv -f --" not in provisioner
    assert 'chown root:root "$path"' not in provisioner
    assert 'chmod 0600 "$path"' not in provisioner
    assert "CapabilityBoundingSet=\n" in unit
    assert "/usr/libexec/secure-ai/verify-host-state-encryption.py" in provisioner
    assert "SECURE_AI_REQUIRE_ENCRYPTED_HOST_STATE:-true" in provisioner


def test_vault_consumers_are_conditioned_and_ui_remains_setup_capable():
    for name in (
        "secure-ai-registry.service",
        "secure-ai-quarantine-watcher.service",
        "secure-ai-agent.service",
        "secure-ai-integrity-monitor.service",
        "secure-ai-integrity.service",
    ):
        unit = _unit(name)
        assert "ConditionPathExists=/var/lib/secure-ai/vault/.initialized" in unit
        assert "Requires=" in unit and "secure-ai-vault-mounted.service" in unit
        assert "After=" in unit and "secure-ai-vault-mounted.service" in unit

    ui = _unit("secure-ai-ui.service")
    requires_line = next(
        line for line in ui.splitlines() if line.startswith("Requires=")
    )
    assert requires_line == "Requires=secure-ai-credentials.service"
    assert "Wants=secure-ai-registry.service" in ui
    assert "InaccessiblePaths=-/var/lib/secure-ai/vault" in ui

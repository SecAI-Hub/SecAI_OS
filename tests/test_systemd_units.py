"""Structural checks for production systemd unit naming and startup semantics."""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
SYSTEM_ROOT = REPO_ROOT / "files" / "system"


def _mount_unit_name(where: str) -> str:
    escaped = where.strip("/").replace("-", r"\x2d").replace("/", "-")
    return f"{escaped}.mount"


def test_mount_unit_filenames_match_where_paths():
    mount_units = list(UNIT_DIR.glob("*.mount"))
    assert mount_units
    for unit in mount_units:
        where_lines = [
            line.split("=", 1)[1].strip()
            for line in unit.read_text(encoding="utf-8").splitlines()
            if line.startswith("Where=")
        ]
        assert len(where_lines) == 1
        assert unit.name == _mount_unit_name(where_lines[0])


def test_all_systemd_execution_targets_exist_in_assembly_model():
    checker = REPO_ROOT / ".github" / "scripts" / "check-assembled-execstart.py"
    result = subprocess.run(
        [sys.executable, str(checker)],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "absolute systemd execution targets" in result.stdout


def test_attestor_waits_for_exec_before_credentialed_start_gate():
    content = (UNIT_DIR / "secure-ai-runtime-attestor.service").read_text(
        encoding="utf-8"
    )
    assert "Type=exec" in content
    assert (
        "ExecStartPost=/usr/libexec/secure-ai/attestation-gate.sh %d/service-token"
        in content
    )


def test_integrity_monitor_waits_for_authenticated_firstboot_baseline():
    content = (UNIT_DIR / "secure-ai-integrity-monitor.service").read_text(
        encoding="utf-8"
    )
    requires = next(
        line for line in content.splitlines() if line.startswith("Requires=")
    )
    after = next(line for line in content.splitlines() if line.startswith("After="))
    assert "secure-ai-firstboot.service" in requires.split("=", 1)[1].split()
    assert "secure-ai-firstboot.service" in after.split("=", 1)[1].split()


def test_searxng_uses_private_credential_and_loopback_only_egress():
    unit = (UNIT_DIR / "secure-ai-searxng.service").read_text(encoding="utf-8")
    settings = (
        SYSTEM_ROOT / "etc" / "secure-ai" / "searxng" / "settings.yml"
    ).read_text(encoding="utf-8")
    wrapper = (
        SYSTEM_ROOT / "usr" / "libexec" / "secure-ai" / "start-searxng.sh"
    ).read_text(encoding="utf-8")

    assert "LoadCredential=searxng-secret:" in unit
    assert "ExecStart=/usr/libexec/secure-ai/start-searxng.sh" in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=localhost" in unit
    assert 'secret_key: "secai-local-only-key"' not in settings
    assert "prepare-searxng-settings.py" in wrapper
    assert "export SEARXNG_SECRET=" not in wrapper
    assert (
        "exec /usr/lib/secure-ai/python3.12-venv/bin/python3.12 -m searx.webapp"
        in wrapper
    )


def test_quarantine_uses_scanners_from_locked_python312_runtime():
    unit = (UNIT_DIR / "secure-ai-quarantine-watcher.service").read_text(
        encoding="utf-8"
    )
    runtime_bin = "/usr/lib/secure-ai/python3.12-venv/bin"
    assert f"Environment=FICKLING_BIN={runtime_bin}/fickling" in unit
    assert f"Environment=MODELAUDIT_BIN={runtime_bin}/modelaudit" in unit
    assert f"Environment=MODELSCAN_BIN={runtime_bin}/modelscan" in unit
    assert "Environment=GGUF_GUARD_BIN=/usr/bin/gguf-guard" in unit
    assert "Environment=MODELSCAN_BIN=/usr/local/bin/modelscan" not in unit
    assert "Environment=GGUF_GUARD_BIN=/usr/local/bin/gguf-guard" not in unit


def test_boot_karg_sync_does_not_swallow_update_failures():
    script = (
        SYSTEM_ROOT / "usr" / "libexec" / "secure-ai" / "sync-boot-kargs.sh"
    ).read_text(encoding="utf-8")
    unit = (UNIT_DIR / "secure-ai-boot-kargs.service").read_text(encoding="utf-8")

    assert 'append_karg "rd.driver.blacklist=nouveau" || true' not in script
    assert 'delete_karg "$stale" || true' not in script
    assert "ProtectSystem=strict" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit


def test_firstboot_does_not_mark_complete_after_critical_control_failure():
    script = (SYSTEM_ROOT / "usr" / "libexec" / "secure-ai" / "firstboot.sh").read_text(
        encoding="utf-8"
    )

    assert "swapoff -a 2>/dev/null || true" not in script
    assert 'fatal "failed to load firewall rules"' in script
    assert 'fatal "boot chain verification failed"' in script
    assert 'fatal "canary placement failed"' in script
    assert 'fatal "initial canary check failed"' in script
    assert 'fatal "securectl is missing or not executable"' in script
    assert 'fatal "update-verify.sh is missing or not executable"' in script


def test_host_firewall_does_not_publish_the_loopback_ui():
    rules = (SYSTEM_ROOT / "etc" / "nftables" / "secure-ai.nft").read_text(
        encoding="utf-8"
    )
    assert "tcp dport 8480" not in rules
    assert "chain input" in rules
    assert "type filter hook input priority 0; policy drop;" in rules


def test_first_boot_readiness_rejects_warnings_and_public_listeners():
    script = (REPO_ROOT / "files" / "scripts" / "first-boot-check.sh").read_text(
        encoding="utf-8"
    )
    assert "ss -H -tlnp" in script
    assert "PASS with warnings" not in script
    assert '[[ "$token" =~ ^[0-9a-f]{64}$ ]]' in script
    assert "--proto '=http' --proto-redir '=http' --noproxy '*'" in script
    assert "--max-filesize 1048576" in script
    warning_branch = script.split("if [ $WARNINGS -gt 0 ]; then", 1)[1].split(
        "\nfi", 1
    )[0]
    assert "exit 1" in warning_branch


def test_vault_watchdog_can_persist_ui_activity_under_its_sandbox():
    unit = (UNIT_DIR / "secure-ai-vault-watchdog.service").read_text(encoding="utf-8")
    assert "After=local-fs.target secure-ai-ui.service" in unit
    assert "ReadWritePaths=-/run/secure-ai-ui" in unit
    assert "SupplementaryGroups=secure-ai-ui-control" in unit

    tmpfiles = (
        SYSTEM_ROOT / "usr" / "lib" / "tmpfiles.d" / "secure-ai.conf"
    ).read_text(encoding="utf-8")
    assert (
        "d /run/secure-ai-ui                          2730 root secure-ai-ui-control"
    ) in tmpfiles


def test_vault_consumers_require_exact_mount_gate_and_setup_condition():
    consumers = (
        "secure-ai-registry.service",
        "secure-ai-quarantine-watcher.service",
        "secure-ai-inference.service",
        "secure-ai-diffusion.service",
        "secure-ai-agent.service",
        "secure-ai-tool-firewall.service",
        "secure-ai-mcp-firewall.service",
        "secure-ai-integrity-monitor.service",
        "secure-ai-integrity.service",
    )
    for name in consumers:
        unit = (UNIT_DIR / name).read_text(encoding="utf-8")
        assert "ConditionPathExists=/var/lib/secure-ai/vault/.initialized" in unit
        assert "secure-ai-vault-mounted.service" in unit

    gate = (UNIT_DIR / "secure-ai-vault-mounted.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/libexec/secure-ai/verify-vault-mount.py" in gate
    assert "ConditionPathExists=/var/lib/secure-ai/vault/.initialized" in gate

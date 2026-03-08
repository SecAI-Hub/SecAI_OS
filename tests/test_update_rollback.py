"""Tests for M24 — Update Verification + Auto-Rollback.

Validates:
- Greenboot health check script exists and is executable
- Health check validates critical services, registry, firewall, scripts
- Max rollback counter prevents infinite rollback loops
- Update verification script exists with check/stage/apply/rollback/status
- Cosign signature verification before applying updates
- Staged update workflow (check → stage → apply)
- Systemd units: health-check service, update-check timer
- UI update endpoints (status, check, stage, apply, rollback, health)
- Greenboot package in recipe.yml
- appliance.yaml updates config section
- firstboot.sh references M24 tools
"""

import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
GREENBOOT_DIR = REPO_ROOT / "files" / "system" / "etc" / "greenboot" / "check" / "required.d"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"
UI_APP_PATH = REPO_ROOT / "services" / "ui" / "ui" / "app.py"


class TestGreenbootHealthCheck:
    def test_script_exists(self):
        assert (GREENBOOT_DIR / "01-secure-ai-health.sh").exists()

    def test_script_executable(self):
        assert os.access(GREENBOOT_DIR / "01-secure-ai-health.sh", os.X_OK)

    def test_has_shebang(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert content.startswith("#!/usr/bin/env bash")

    def test_set_euo_pipefail(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "set -euo pipefail" in content

    def test_mentions_m24(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "M24" in content


class TestHealthCheckServices:
    def test_checks_nftables(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "nftables" in content

    def test_checks_registry(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "registry" in content

    def test_checks_firewall_rules(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "secure_ai" in content
        assert "nft" in content

    def test_checks_integrity_scripts(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "securectl" in content
        assert "canary-check.sh" in content

    def test_checks_vault_config(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "crypttab" in content


class TestRollbackProtection:
    def test_max_rollback_counter(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "MAX_ROLLBACKS" in content

    def test_max_rollbacks_is_2(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "MAX_ROLLBACKS=2" in content

    def test_rollback_counter_file(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "rollback-count" in content

    def test_clears_counter_on_success(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "rm -f" in content
        assert "ROLLBACK_COUNTER" in content

    def test_halts_on_max_rollbacks(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "max rollback" in content.lower() or "halting" in content


class TestHealthCheckOutput:
    def test_writes_json_result(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "health-check.json" in content

    def test_includes_boot_id(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "boot_id" in content

    def test_includes_hash(self):
        content = (GREENBOOT_DIR / "01-secure-ai-health.sh").read_text()
        assert "sha256" in content


class TestUpdateVerifyScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "update-verify.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "update-verify.sh", os.X_OK)

    def test_has_shebang(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert content.startswith("#!/usr/bin/env bash")

    def test_mentions_m24(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "M24" in content

    def test_check_command(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "check)" in content or "check_updates" in content

    def test_stage_command(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "stage)" in content or "stage_update" in content

    def test_apply_command(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "apply)" in content or "apply_update" in content

    def test_rollback_command(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "rollback)" in content or "do_rollback" in content

    def test_status_command(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "status)" in content or "show_status" in content


class TestCosignVerification:
    def test_uses_cosign(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "cosign" in content

    def test_verifies_signature(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "verify_signature" in content or "cosign verify" in content

    def test_uses_public_key(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "cosign.pub" in content

    def test_rejects_bad_signature(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "FAILED" in content or "failed" in content

    def test_graceful_no_cosign(self):
        """Should warn but not fail if cosign is not installed."""
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "cosign not installed" in content or "not found" in content


class TestStagedUpdates:
    def test_download_only(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "download-only" in content

    def test_rpm_ostree_upgrade(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "rpm-ostree upgrade" in content

    def test_rpm_ostree_rollback(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "rpm-ostree rollback" in content

    def test_reboot_on_apply(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "systemctl reboot" in content

    def test_writes_update_state(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "update-state.json" in content


class TestUpdateAuditLogging:
    def test_audit_function(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "audit_update" in content

    def test_audit_log_path(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "update-audit.jsonl" in content

    def test_audit_hash_chain(self):
        content = (SCRIPTS_DIR / "update-verify.sh").read_text()
        assert "sha256" in content


class TestUpdateSystemdUnits:
    def test_update_check_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-update-check.service").exists()

    def test_update_check_timer_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-update-check.timer").exists()

    def test_health_check_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-health-check.service").exists()

    def test_check_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-update-check.service").read_text()
        assert "Type=oneshot" in content

    def test_check_service_uses_script(self):
        content = (SYSTEMD_DIR / "secure-ai-update-check.service").read_text()
        assert "update-verify.sh" in content

    def test_timer_6h_interval(self):
        content = (SYSTEMD_DIR / "secure-ai-update-check.timer").read_text()
        assert "OnUnitActiveSec=6h" in content

    def test_timer_persistent(self):
        content = (SYSTEMD_DIR / "secure-ai-update-check.timer").read_text()
        assert "Persistent=true" in content

    def test_health_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-health-check.service").read_text()
        assert "Type=oneshot" in content

    def test_health_service_timeout(self):
        content = (SYSTEMD_DIR / "secure-ai-health-check.service").read_text()
        assert "TimeoutStartSec=300" in content

    def test_health_service_uses_greenboot_script(self):
        content = (SYSTEMD_DIR / "secure-ai-health-check.service").read_text()
        assert "01-secure-ai-health.sh" in content

    def test_check_service_has_core_dump_disabled(self):
        content = (SYSTEMD_DIR / "secure-ai-update-check.service").read_text()
        assert "LimitCORE=0" in content

    def test_health_service_has_core_dump_disabled(self):
        content = (SYSTEMD_DIR / "secure-ai-health-check.service").read_text()
        assert "LimitCORE=0" in content


class TestUIUpdateEndpoints:
    def test_update_status_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/status" in content

    def test_update_check_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/check" in content

    def test_update_stage_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/stage" in content

    def test_update_apply_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/apply" in content

    def test_update_rollback_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/rollback" in content

    def test_update_health_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/update/health" in content

    def test_apply_requires_confirm(self):
        content = UI_APP_PATH.read_text()
        assert "confirm" in content

    def test_rollback_requires_confirm(self):
        content = UI_APP_PATH.read_text()
        # Both apply and rollback require confirm
        assert content.count('"confirm"') >= 2

    def test_calls_update_verify(self):
        content = UI_APP_PATH.read_text()
        assert "update-verify.sh" in content


class TestApplianceConfig:
    def test_updates_section_exists(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "updates" in config

    def test_cosign_verify_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["updates"]["cosign_verify"] is True

    def test_auto_check_interval(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["updates"]["auto_check_interval"] == 6

    def test_max_rollback_attempts(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["updates"]["max_rollback_attempts"] == 2

    def test_health_check_timeout(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["updates"]["health_check_timeout"] == 300

    def test_staged_updates_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["updates"]["staged_updates"] is True


class TestFirstbootM24:
    def test_mentions_update_verify(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "update-verify.sh" in content

    def test_mentions_greenboot(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "greenboot" in content.lower() or "health check" in content.lower()

    def test_mentions_m24(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "M24" in content


class TestRecipeConfig:
    def test_greenboot_package(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        rpm_module = next(m for m in recipe["modules"] if m.get("type") == "rpm-ostree")
        assert "greenboot" in rpm_module["install"]

    def test_update_check_timer_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-update-check.timer" in enabled

    def test_health_check_service_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-health-check.service" in enabled

    def test_greenboot_service_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "greenboot-healthcheck.service" in enabled

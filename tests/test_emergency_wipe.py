"""Tests for M23 — Emergency Wipe (securectl).

Validates:
- securectl script exists and is executable
- Three panic levels with correct actions
- Passphrase verification for levels 2+
- Countdown and --no-countdown flag
- Audit logging of panic events
- Panic state file written to /run/secure-ai/
- Panic systemd service unit
- UI emergency endpoints
- firstboot.sh checks for securectl
- appliance.yaml emergency config
- recipe.yml does not auto-enable panic service (manual only)
"""

import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"
UI_APP_PATH = REPO_ROOT / "services" / "ui" / "ui" / "app.py"


class TestSecurectlScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "securectl").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "securectl", os.X_OK)

    def test_has_shebang(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert content.startswith("#!/usr/bin/env bash")

    def test_set_euo_pipefail(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "set -euo pipefail" in content

    def test_mentions_m23(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "M23" in content


class TestPanicLevel1:
    def test_stops_inference(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "secure-ai-inference.service" in content

    def test_stops_diffusion(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "secure-ai-diffusion.service" in content

    def test_stops_registry(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "secure-ai-registry.service" in content

    def test_stops_tool_firewall(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "secure-ai-tool-firewall.service" in content

    def test_kills_llama_server(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "llama-server" in content

    def test_kills_diffusion_worker(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "diffusion-worker" in content

    def test_locks_vault(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "cryptsetup close" in content

    def test_umounts_vault(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "umount" in content

    def test_syncs_before_umount(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        # sync should appear before umount
        assert content.index("sync") < content.index("umount")

    def test_invalidates_sessions(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "sessions" in content

    def test_writes_panic_state(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "panic-state.json" in content
        assert "panic_active" in content


class TestPanicLevel2:
    def test_calls_level1(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "panic_level_1" in content

    def test_shreds_luks_header(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "luks-header-backup" in content
        assert "shred" in content

    def test_deletes_cosign_keys(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "*.key" in content
        assert "*.pem" in content

    def test_deletes_tpm2_keys(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "tpm2" in content

    def test_deletes_mok_key(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "/etc/secure-ai" in content

    def test_shred_3_passes_for_keys(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "shred -vfz -n 3" in content


class TestPanicLevel3:
    def test_calls_level2(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "panic_level_2" in content

    def test_reencrypts_vault(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "luksErase" in content

    def test_uses_random_key(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "/dev/urandom" in content

    def test_drops_caches(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "drop_caches" in content

    def test_deletes_logs(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "*.jsonl" in content
        assert "*.log" in content

    def test_deletes_registry(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "registry" in content

    def test_deletes_auth_data(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "AUTH_DIR" in content

    def test_deletes_canary_db(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "canary-db.json" in content

    def test_removes_firstboot_marker(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert ".firstboot-done" in content or ".initialized" in content

    def test_shred_1_pass_for_logs(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "shred -vfz -n 1" in content


class TestPassphraseVerification:
    def test_requires_passphrase_level2(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "--confirm" in content

    def test_verify_function_exists(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "verify_passphrase" in content

    def test_uses_scrypt(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "scrypt" in content

    def test_level1_no_passphrase(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        # Level 1 should not require passphrase (ge 2 check)
        assert "ge 2" in content


class TestCountdown:
    def test_countdown_function(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "countdown" in content

    def test_no_countdown_flag(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "--no-countdown" in content

    def test_ctrl_c_cancel(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "Ctrl+C" in content

    def test_5_second_default(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "5" in content


class TestAuditLogging:
    def test_audit_function(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "audit_panic" in content

    def test_audit_log_path(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "panic-audit.jsonl" in content

    def test_audit_critical_severity(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "CRITICAL" in content

    def test_audit_hash_chain(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "sha256" in content


class TestStatusCommand:
    def test_status_subcommand(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "status)" in content

    def test_shows_panic_state(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "show_status" in content or "PANIC_STATE" in content

    def test_returns_json(self):
        content = (SCRIPTS_DIR / "securectl").read_text()
        assert "panic_active" in content


class TestPanicSystemdService:
    def test_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-panic.service").exists()

    def test_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-panic.service").read_text()
        assert "Type=oneshot" in content

    def test_uses_securectl(self):
        content = (SYSTEMD_DIR / "secure-ai-panic.service").read_text()
        assert "securectl" in content

    def test_has_core_dump_disabled(self):
        content = (SYSTEMD_DIR / "secure-ai-panic.service").read_text()
        assert "LimitCORE=0" in content

    def test_remain_after_exit(self):
        content = (SYSTEMD_DIR / "secure-ai-panic.service").read_text()
        assert "RemainAfterExit=yes" in content


class TestUIEmergencyEndpoints:
    def test_emergency_status_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/emergency/status" in content

    def test_emergency_panic_endpoint(self):
        content = UI_APP_PATH.read_text()
        assert "/api/emergency/panic" in content

    def test_panic_level_validation(self):
        content = UI_APP_PATH.read_text()
        assert "level" in content
        assert "1, 2, or 3" in content or "(1, 2, 3)" in content

    def test_passphrase_required_for_level2(self):
        content = UI_APP_PATH.read_text()
        assert "passphrase" in content

    def test_audit_log_on_panic(self):
        content = UI_APP_PATH.read_text()
        assert "emergency_panic" in content

    def test_calls_securectl(self):
        content = UI_APP_PATH.read_text()
        assert "securectl" in content


class TestFirstbootEmergency:
    def test_mentions_securectl(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "securectl" in content

    def test_mentions_m23(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "M23" in content or "Emergency" in content or "emergency" in content


class TestApplianceConfig:
    def test_emergency_section_exists(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "emergency" in config

    def test_countdown_seconds(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["emergency"]["countdown_seconds"] == 5

    def test_require_passphrase_level2(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["emergency"]["require_passphrase_level2"] is True

    def test_audit_log_path(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "panic-audit.jsonl" in config["emergency"]["audit_log"]


class TestRecipeConfig:
    def test_panic_service_not_auto_enabled(self):
        """Panic service should NOT be auto-enabled — it's manual/emergency only."""
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-panic.service" not in enabled

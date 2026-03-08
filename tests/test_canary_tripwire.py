"""Tests for M22 — Canary / Tripwire System.

Validates:
- Canary placement script exists and creates files in correct locations
- Canary check script exists and verifies integrity
- Tripwire trigger actions (vault lock, worker kill, audit log)
- inotify watch mode
- Timer and service units
- Canary watch service for real-time detection
- firstboot.sh runs canary placement and initial check
- appliance.yaml has canary config
- recipe.yml enables canary timer + watch service + inotify-tools
"""

import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"


class TestCanaryPlaceScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "canary-place.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "canary-place.sh", os.X_OK)

    def test_places_vault_canary(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "vault/.canary" in content

    def test_places_registry_canary(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "registry/.canary" in content

    def test_places_keys_canary(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "keys/.canary" in content

    def test_places_config_canary(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "/etc/secure-ai/.canary" in content

    def test_generates_unique_tokens(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "urandom" in content or "generate_token" in content

    def test_hashes_tokens(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "sha256" in content

    def test_writes_integrity_database(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "canary-db.json" in content

    def test_sets_readonly_permissions(self):
        content = (SCRIPTS_DIR / "canary-place.sh").read_text()
        assert "chmod 444" in content or "chmod 400" in content


class TestCanaryCheckScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "canary-check.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "canary-check.sh", os.X_OK)

    def test_check_mode(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "check)" in content or "run_check" in content

    def test_watch_mode(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "watch)" in content or "run_watch" in content

    def test_verifies_token_hash(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "sha256" in content
        assert "token_hash" in content or "expected_hash" in content

    def test_checks_permissions(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "permissions" in content or "perms" in content

    def test_checks_ownership(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "owner" in content

    def test_checks_file_existence(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "missing" in content or "! -f" in content


class TestTripwireTrigger:
    def test_locks_vault(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "cryptsetup close" in content or "lock" in content.lower()

    def test_kills_workers(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "llama-server" in content
        assert "diffusion" in content

    def test_writes_audit_log(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "canary-audit.jsonl" in content or "AUDIT_LOG" in content
        assert "CRITICAL" in content

    def test_writes_alert_file(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "canary-alert.json" in content or "ALERT_FILE" in content

    def test_stops_services(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "systemctl stop" in content

    def test_trigger_on_missing_file(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "canary file missing" in content

    def test_trigger_on_modified_token(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "canary token modified" in content

    def test_trigger_on_permission_change(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "permissions changed" in content


class TestInotifyWatch:
    def test_uses_inotifywait(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "inotifywait" in content

    def test_watches_modify_delete_attrib(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "modify" in content
        assert "delete" in content
        assert "attrib" in content

    def test_graceful_fallback(self):
        """If inotifywait is unavailable, should fall back to timer-based."""
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "not available" in content or "fallback" in content.lower()

    def test_monitors_config_files(self):
        content = (SCRIPTS_DIR / "canary-check.sh").read_text()
        assert "appliance.yaml" in content
        assert "policy.yaml" in content


class TestCanarySystemdUnits:
    def test_timer_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-canary.timer").exists()

    def test_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-canary.service").exists()

    def test_watch_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-canary-watch.service").exists()

    def test_timer_interval_5min(self):
        content = (SYSTEMD_DIR / "secure-ai-canary.timer").read_text()
        assert "OnUnitActiveSec=5min" in content

    def test_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-canary.service").read_text()
        assert "Type=oneshot" in content

    def test_watch_is_simple(self):
        content = (SYSTEMD_DIR / "secure-ai-canary-watch.service").read_text()
        assert "Type=simple" in content

    def test_watch_restarts_on_failure(self):
        content = (SYSTEMD_DIR / "secure-ai-canary-watch.service").read_text()
        assert "Restart=on-failure" in content

    def test_service_has_core_dump_disabled(self):
        content = (SYSTEMD_DIR / "secure-ai-canary.service").read_text()
        assert "LimitCORE=0" in content

    def test_watch_has_core_dump_disabled(self):
        content = (SYSTEMD_DIR / "secure-ai-canary-watch.service").read_text()
        assert "LimitCORE=0" in content


class TestFirstbootCanary:
    def test_runs_canary_place(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "canary-place.sh" in content

    def test_runs_initial_check(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "canary-check.sh" in content

    def test_mentions_m22(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "M22" in content or "Canary" in content or "canary" in content


class TestApplianceConfig:
    def test_canary_section_exists(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "canary" in config

    def test_check_interval(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["canary"]["check_interval"] == 5

    def test_inotify_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["canary"]["inotify_enabled"] is True

    def test_locations_configured(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        locs = config["canary"]["locations"]
        assert len(locs) == 4
        assert any("vault" in l for l in locs)
        assert any("registry" in l for l in locs)
        assert any("keys" in l for l in locs)
        assert any("/etc/secure-ai" in l for l in locs)


class TestRecipeIncludes:
    def test_canary_timer_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-canary.timer" in enabled

    def test_canary_watch_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-canary-watch.service" in enabled

    def test_inotify_tools_installed(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        rpm_module = next(m for m in recipe["modules"] if m.get("type") == "rpm-ostree")
        packages = rpm_module["install"]
        assert "inotify-tools" in packages

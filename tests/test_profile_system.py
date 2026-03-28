"""Tests for Epic 4/5 — Secure-by-Default Profile System.

Validates:
- Profile definitions in appliance.yaml are well-formed
- Service lists map to real systemd unit files
- Default profile is offline_private (safest)
- Agent has no outbound path in offline_private
- apply-profile.sh exists and is well-formed
- Systemd path/service units for profile changes exist
- Profile API endpoints exist in app.py
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
POLICY_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "policy" / "policy.yaml"
AGENT_POLICY_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "policy" / "agent.yaml"
APP_PY = REPO_ROOT / "services" / "ui" / "ui" / "app.py"

VALID_PROFILES = {"offline_private", "research", "full_lab"}
REQUIRED_DEFINITION_KEYS = {"description", "mode", "session_mode", "agent_mode", "rationale",
                            "services_enabled", "services_disabled"}


def _load_config():
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


def _load_profile_definitions():
    config = _load_config()
    return config.get("profile", {}).get("definitions", {})


class TestProfileDefinitions:
    def test_profile_section_exists(self):
        config = _load_config()
        assert "profile" in config, "appliance.yaml must have a 'profile' section"

    def test_default_is_offline_private(self):
        config = _load_config()
        assert config["profile"]["default"] == "offline_private"

    def test_all_three_profiles_defined(self):
        defs = _load_profile_definitions()
        assert set(defs.keys()) == VALID_PROFILES

    def test_each_profile_has_required_keys(self):
        defs = _load_profile_definitions()
        for name, defn in defs.items():
            missing = REQUIRED_DEFINITION_KEYS - set(defn.keys())
            assert not missing, f"Profile '{name}' missing keys: {missing}"

    def test_rationale_is_nonempty(self):
        defs = _load_profile_definitions()
        for name, defn in defs.items():
            rationale = defn.get("rationale", "").strip()
            assert len(rationale) > 10, (
                f"Profile '{name}' must have a meaningful rationale"
            )

    def test_services_enabled_are_lists(self):
        defs = _load_profile_definitions()
        for name, defn in defs.items():
            assert isinstance(defn["services_enabled"], list), (
                f"Profile '{name}' services_enabled must be a list"
            )
            assert isinstance(defn["services_disabled"], list), (
                f"Profile '{name}' services_disabled must be a list"
            )


class TestServiceListsMatchUnits:
    """Every service referenced in profile definitions must have a real unit file."""

    def _all_referenced_services(self):
        defs = _load_profile_definitions()
        services = set()
        for defn in defs.values():
            services.update(defn.get("services_enabled", []))
            services.update(defn.get("services_disabled", []))
        return services

    def test_all_services_have_unit_files(self):
        for svc in self._all_referenced_services():
            unit_path = SYSTEMD_DIR / svc
            assert unit_path.exists(), (
                f"Profile references '{svc}' but no unit file at {unit_path}"
            )


class TestOfflinePrivateAgentSafety:
    """Verify the agent has no outbound path in offline_private profile."""

    def test_agent_mode_is_offline_only(self):
        defs = _load_profile_definitions()
        assert defs["offline_private"]["agent_mode"] == "offline_only"

    def test_agent_offline_only_has_no_outbound_tools(self):
        """Agent offline_only mode must not include network-capable tools."""
        content = AGENT_POLICY_PATH.read_text(encoding="utf-8")
        agent_config = yaml.safe_load(content)
        modes = agent_config.get("operating_modes", {})
        offline = modes.get("offline_only", {})
        allowed_tools = offline.get("allowed_tools", [])
        # None of the allowed tools should be network-related
        network_tools = {"network.fetch", "http.request", "web.search"}
        overlap = network_tools & set(allowed_tools)
        assert not overlap, (
            f"offline_only agent mode must not allow network tools: {overlap}"
        )

    def test_policy_default_deny_egress(self):
        """policy.yaml network.runtime_egress must be 'deny'."""
        content = POLICY_PATH.read_text(encoding="utf-8")
        policy = yaml.safe_load(content)
        defaults = policy.get("defaults", {})
        egress = defaults.get("network", {}).get("runtime_egress", "")
        assert egress == "deny", (
            f"policy.yaml network.runtime_egress must be 'deny', got '{egress}'"
        )


class TestApplyProfileScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "apply-profile.sh").exists()

    def test_validates_profile_names(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        assert "offline_private" in content
        assert "research" in content
        assert "full_lab" in content
        # Must have an allowlist validation
        assert "validate_profile" in content or "VALID_PROFILES" in content

    def test_atomic_writes(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        # Must use rename for atomic writes
        assert ".tmp" in content

    def test_fallback_to_offline_private(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        assert "DEFAULT_PROFILE" in content
        assert "offline_private" in content

    def test_uses_flock(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        assert "flock" in content

    def test_writes_audit_entries(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        assert "write_audit" in content or "audit" in content.lower()

    def test_rollback_on_failure(self):
        content = (SCRIPTS_DIR / "apply-profile.sh").read_text(encoding="utf-8")
        assert "rollback" in content.lower() or "rolled_back" in content


class TestProfileSystemdUnits:
    def test_path_unit_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-apply-profile.path").exists()

    def test_service_unit_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-apply-profile.service").exists()

    def test_path_watches_correct_file(self):
        content = (SYSTEMD_DIR / "secure-ai-apply-profile.path").read_text(encoding="utf-8")
        assert "/run/secure-ai-ui/profile-request" in content

    def test_service_runs_apply_profile(self):
        content = (SYSTEMD_DIR / "secure-ai-apply-profile.service").read_text(encoding="utf-8")
        assert "apply-profile.sh" in content

    def test_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-apply-profile.service").read_text(encoding="utf-8")
        assert "Type=oneshot" in content

    def test_service_has_hardening(self):
        content = (SYSTEMD_DIR / "secure-ai-apply-profile.service").read_text(encoding="utf-8")
        assert "ProtectHome=yes" in content
        assert "PrivateTmp=yes" in content

    def test_service_cleans_up_request(self):
        content = (SYSTEMD_DIR / "secure-ai-apply-profile.service").read_text(encoding="utf-8")
        assert "ExecStopPost" in content
        assert "profile-request" in content


class TestProfileAPIEndpoints:
    def test_get_profile_endpoint_exists(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert '/api/profile"' in content or "/api/profile'" in content

    def test_preview_endpoint_exists(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert "/api/profile/preview" in content

    def test_select_endpoint_exists(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert "/api/profile/select" in content

    def test_status_endpoint_exists(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert "/api/profile/status" in content

    def test_select_uses_request_file_pattern(self):
        """Profile select must use the path-unit request file, not direct subprocess."""
        content = APP_PY.read_text(encoding="utf-8")
        assert "profile-request" in content
        assert "O_CREAT" in content
        assert "O_EXCL" in content

    def test_select_checks_operator_override(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert "operator_override" in content or "PROFILE_OVERRIDE_PATH" in content

    def test_select_validates_profile_name(self):
        content = APP_PY.read_text(encoding="utf-8")
        assert "VALID_PROFILES" in content


class TestRecipeIncludesProfilePathUnit:
    def test_apply_profile_path_in_recipe(self):
        recipe = yaml.safe_load(
            (REPO_ROOT / "recipes" / "recipe.yml").read_text(encoding="utf-8")
        )
        systemd_module = next(
            m for m in recipe["modules"] if m.get("type") == "systemd"
        )
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-apply-profile.path" in enabled

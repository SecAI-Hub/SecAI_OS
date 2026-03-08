"""Tests for M21 — Clipboard Isolation.

Validates:
- Clipboard isolation script exists and detects VM clipboard agents
- Clipboard auto-clear script and systemd timer/service
- PrivateUsers=yes on all non-UI services (not on UI)
- firstboot.sh runs clipboard isolation
- appliance.yaml has clipboard config
- recipe.yml enables clipboard-clear timer
"""

import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"

# Services that MUST have PrivateUsers=yes (all non-UI core services)
PRIVATE_USERS_SERVICES = [
    "secure-ai-inference.service",
    "secure-ai-diffusion.service",
    "secure-ai-registry.service",
    "secure-ai-tool-firewall.service",
    "secure-ai-quarantine-watcher.service",
    "secure-ai-airlock.service",
    "secure-ai-search-mediator.service",
    "secure-ai-searxng.service",
    "secure-ai-tor.service",
]

# Service that must NOT have PrivateUsers (needs user session for clipboard)
NO_PRIVATE_USERS_SERVICE = "secure-ai-ui.service"


class TestClipboardIsolateScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "clipboard-isolate.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "clipboard-isolate.sh", os.X_OK)

    def test_detects_spice_vdagent(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert "spice-vdagent" in content

    def test_detects_vmware(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert "vmware" in content.lower() or "vmtoolsd" in content

    def test_detects_vbox(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert "VBoxClient" in content

    def test_detects_wayland(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert "WAYLAND_DISPLAY" in content or "wayland" in content.lower()

    def test_writes_env_file(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert "clipboard.env" in content
        assert "CLIPBOARD_ISOLATED" in content

    def test_disables_agents(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        # Should mask/disable services, not just detect them
        assert "systemctl" in content
        assert "mask" in content or "disable" in content


class TestClipboardClearScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "clipboard-clear.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "clipboard-clear.sh", os.X_OK)

    def test_supports_wayland(self):
        content = (SCRIPTS_DIR / "clipboard-clear.sh").read_text()
        assert "wl-copy" in content or "wl-paste" in content

    def test_supports_x11(self):
        content = (SCRIPTS_DIR / "clipboard-clear.sh").read_text()
        assert "xclip" in content or "xsel" in content

    def test_clears_primary_selection(self):
        content = (SCRIPTS_DIR / "clipboard-clear.sh").read_text()
        assert "primary" in content


class TestClipboardClearTimer:
    def test_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-clipboard-clear.service").exists()

    def test_timer_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-clipboard-clear.timer").exists()

    def test_timer_interval(self):
        content = (SYSTEMD_DIR / "secure-ai-clipboard-clear.timer").read_text()
        assert "OnUnitActiveSec=60s" in content

    def test_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-clipboard-clear.service").read_text()
        assert "Type=oneshot" in content

    def test_service_sandboxed(self):
        content = (SYSTEMD_DIR / "secure-ai-clipboard-clear.service").read_text()
        assert "NoNewPrivileges=yes" in content
        assert "PrivateNetwork=yes" in content
        assert "LimitCORE=0" in content


class TestPrivateUsersIsolation:
    def test_non_ui_services_have_private_users(self):
        for svc in PRIVATE_USERS_SERVICES:
            path = SYSTEMD_DIR / svc
            assert path.exists(), f"{svc} does not exist"
            content = path.read_text()
            assert "PrivateUsers=yes" in content, f"{svc} missing PrivateUsers=yes"

    def test_ui_service_no_private_users(self):
        path = SYSTEMD_DIR / NO_PRIVATE_USERS_SERVICE
        content = path.read_text()
        assert "PrivateUsers=yes" not in content, \
            "UI service should NOT have PrivateUsers=yes"

    def test_private_users_comment_mentions_clipboard(self):
        """The PrivateUsers directive should have a comment explaining it's for clipboard isolation."""
        for svc in PRIVATE_USERS_SERVICES[:3]:  # spot check first 3
            content = (SYSTEMD_DIR / svc).read_text()
            # Find the line before PrivateUsers
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "PrivateUsers=yes" in line:
                    # Check preceding comment
                    if i > 0:
                        prev = lines[i - 1]
                        assert "clipboard" in prev.lower() or "M21" in prev, \
                            f"{svc}: PrivateUsers missing clipboard comment"
                    break


class TestFirstbootClipboard:
    def test_runs_clipboard_isolate(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "clipboard-isolate.sh" in content

    def test_logs_clipboard_results(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "clipboard.env" in content
        assert "CLIPBOARD_ISOLATED" in content

    def test_logs_disabled_agents(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "CLIP_AGENTS_DISABLED" in content


class TestApplianceConfig:
    def test_clipboard_section_exists(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "clipboard" in config

    def test_isolate_vm_clipboard(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["clipboard"]["isolate_vm_clipboard"] is True

    def test_auto_clear_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["clipboard"]["auto_clear_enabled"] is True

    def test_auto_clear_interval(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["clipboard"]["auto_clear_interval"] == 60

    def test_private_users_config(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["clipboard"]["private_users_non_ui"] is True


class TestRecipeIncludes:
    def test_clipboard_clear_timer_enabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-clipboard-clear.timer" in enabled

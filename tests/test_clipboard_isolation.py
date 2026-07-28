"""Security tests for VM clipboard isolation and per-session auto-clear."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_SYSTEM_DIR = (
    REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
)
SYSTEMD_USER_DIR = (
    REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "user"
)
CONFIG_PATH = (
    REPO_ROOT
    / "files"
    / "system"
    / "etc"
    / "secure-ai"
    / "config"
    / "appliance.yaml"
)
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"
FIRSTBOOT_PATH = SCRIPTS_DIR / "firstboot.sh"
ISOLATION_HELPER_PATH = SCRIPTS_DIR / "secure-clipboard-isolate.py"
CLEAR_PATH = SCRIPTS_DIR / "clipboard-clear.sh"


def load_isolation_helper():
    spec = importlib.util.spec_from_file_location(
        "secure_clipboard_isolate", ISOLATION_HELPER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestClipboardIsolation:
    def test_entrypoint_and_helper_are_executable(self):
        for path in (
            SCRIPTS_DIR / "clipboard-isolate.sh",
            ISOLATION_HELPER_PATH,
        ):
            assert path.exists()
            assert os.access(path, os.X_OK)

    def test_entrypoint_execs_fixed_helper_as_root(self):
        content = (SCRIPTS_DIR / "clipboard-isolate.sh").read_text()
        assert 'if [ "$(id -u)" -ne 0 ]' in content
        assert "exec /usr/libexec/secure-ai/secure-clipboard-isolate.py" in content
        assert "source " not in content
        assert "eval " not in content

    def test_vm_state_never_claims_guest_only_isolation(self):
        module = load_isolation_helper()
        verified = module.Control(
            name="spice-vdagentd.service",
            detected=True,
            attempted=True,
            verified=True,
            detail="verified",
        )
        state = module.build_state(
            "kvm", [verified], checked_at="2026-07-27T00:00:00+00:00"
        )
        assert state["status"] == "requires_hypervisor_verification"
        assert state["isolated"] is False
        assert state["guest_controls_verified"] is True
        assert state["host_verification_required"] is True

    def test_failed_guest_control_fails_closed(self):
        module = load_isolation_helper()
        failed = module.Control(
            name="spice-vdagentd.service",
            detected=True,
            attempted=True,
            verified=False,
            detail="failed",
        )
        state = module.build_state("kvm", [failed])
        assert state["status"] == "failed"
        assert state["isolated"] is False
        assert state["guest_controls_verified"] is False

    def test_bare_metal_is_not_applicable(self):
        module = load_isolation_helper()
        state = module.build_state("none", [])
        assert state["status"] == "not_applicable"
        assert state["isolated"] is True
        assert state["host_verification_required"] is False

    def test_host_policies_are_explicit_and_not_faked(self):
        content = ISOLATION_HELPER_PATH.read_text()
        assert "isolation.tools.copy.disable" in content
        assert "Shared Clipboard and Drag and Drop to Disabled" in content
        assert "requires_hypervisor_verification" in content
        assert "pkill" not in content
        assert "killall" not in content

    def test_state_is_atomic_root_only_json(self):
        content = ISOLATION_HELPER_PATH.read_text()
        assert "os.fchmod(descriptor, 0o600)" in content
        assert "os.fsync" in content
        assert "os.replace" in content
        assert "path.is_symlink()" in content
        assert "json.dump" in content
        assert "clipboard.env" not in content


def make_command(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


def command_path(tmp_path: Path) -> str:
    return f"{tmp_path}:/usr/bin:/bin"


class TestClipboardClear:
    def test_script_is_executable(self):
        assert CLEAR_PATH.exists()
        assert os.access(CLEAR_PATH, os.X_OK)

    def test_wayland_clears_both_selections(self, tmp_path: Path):
        calls = tmp_path / "calls"
        make_command(
            tmp_path,
            "wl-copy",
            f'printf "%s\\n" "$*" >> "{calls}"',
        )
        result = subprocess.run(
            [str(CLEAR_PATH)],
            check=False,
            env={
                "PATH": command_path(tmp_path),
                "WAYLAND_DISPLAY": "wayland-0",
            },
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0
        assert calls.read_text().splitlines() == [
            "--clear",
            "--primary --clear",
        ]

    def test_wayland_failure_is_not_silenced(self, tmp_path: Path):
        make_command(
            tmp_path,
            "wl-copy",
            '[ "$1" != "--primary" ]',
        )
        result = subprocess.run(
            [str(CLEAR_PATH)],
            check=False,
            env={
                "PATH": command_path(tmp_path),
                "WAYLAND_DISPLAY": "wayland-0",
            },
            text=True,
            capture_output=True,
        )
        assert result.returncode != 0
        assert "cleared" not in result.stderr

    def test_x11_uses_clear_primitive_for_both_selections(self, tmp_path: Path):
        calls = tmp_path / "calls"
        make_command(
            tmp_path,
            "xsel",
            f'printf "%s\\n" "$*" >> "{calls}"',
        )
        result = subprocess.run(
            [str(CLEAR_PATH)],
            check=False,
            env={"PATH": command_path(tmp_path), "DISPLAY": ":0"},
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0
        assert calls.read_text().splitlines() == [
            "--clipboard --clear",
            "--primary --clear",
        ]

    def test_no_session_fails_truthfully(self, tmp_path: Path):
        result = subprocess.run(
            [str(CLEAR_PATH)],
            check=False,
            env={"PATH": command_path(tmp_path)},
            text=True,
            capture_output=True,
        )
        assert result.returncode == 2
        assert "no graphical clipboard session" in result.stderr


class TestPerUserTimer:
    def test_units_are_user_scoped_only(self):
        assert (SYSTEMD_USER_DIR / "secure-ai-clipboard-clear.service").exists()
        assert (SYSTEMD_USER_DIR / "secure-ai-clipboard-clear.timer").exists()
        assert not (
            SYSTEMD_SYSTEM_DIR / "secure-ai-clipboard-clear.service"
        ).exists()
        assert not (
            SYSTEMD_SYSTEM_DIR / "secure-ai-clipboard-clear.timer"
        ).exists()

    def test_timer_is_bound_to_graphical_session(self):
        content = (
            SYSTEMD_USER_DIR / "secure-ai-clipboard-clear.timer"
        ).read_text()
        assert "OnUnitActiveSec=60s" in content
        assert "WantedBy=graphical-session.target" in content
        assert "PartOf=graphical-session.target" in content
        assert "Persistent=false" in content

    def test_user_service_is_tightly_sandboxed(self):
        content = (
            SYSTEMD_USER_DIR / "secure-ai-clipboard-clear.service"
        ).read_text()
        for directive in (
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX",
            "RestrictSUIDSGID=yes",
            "LimitCORE=0",
        ):
            assert directive in content

    def test_recipe_enables_user_timer_not_system_timer(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(
            module
            for module in recipe["modules"]
            if module.get("type") == "systemd"
        )
        assert "secure-ai-clipboard-clear.timer" not in systemd_module[
            "system"
        ]["enabled"]
        assert "secure-ai-clipboard-clear.timer" in systemd_module[
            "user"
        ]["enabled"]


class TestFirstbootClipboardState:
    def test_firstboot_reads_json_without_sourcing_state(self):
        content = FIRSTBOOT_PATH.read_text()
        assert "clipboard.json" in content
        assert "clipboard.env" not in content
        assert 'source "${SECURE_AI_ROOT}/clipboard' not in content

    def test_firstboot_does_not_claim_unverified_vm_isolation(self):
        content = FIRSTBOOT_PATH.read_text()
        assert "requires_hypervisor_verification" in content


class TestApplianceConfig:
    def test_clipboard_configuration_is_truthful(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())["clipboard"]
        assert config["isolate_vm_clipboard"] is True
        assert config["host_verification_required"] is True
        assert config["auto_clear_enabled"] is True
        assert config["auto_clear_interval"] == 60
        assert config["auto_clear_scope"] == "graphical_user_session"
        assert config["private_users_non_ui"] is True

"""Fail-closed emergency containment and vault erasure tests."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = (
    REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
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
AUDIT_MANIFEST = (
    REPO_ROOT
    / "files"
    / "system"
    / "etc"
    / "secure-ai"
    / "config"
    / "audit-log-formats.json"
)
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"
UI_APP_PATH = REPO_ROOT / "services" / "ui" / "ui" / "app.py"
PANIC_HELPER = SCRIPTS_DIR / "secure-panic.py"


def load_panic():
    # secure-panic imports the sibling secure_luks module.
    luks_spec = importlib.util.spec_from_file_location(
        "secure_luks", SCRIPTS_DIR / "secure_luks.py"
    )
    assert luks_spec is not None and luks_spec.loader is not None
    luks_module = importlib.util.module_from_spec(luks_spec)
    sys.modules["secure_luks"] = luks_module
    luks_spec.loader.exec_module(luks_module)

    spec = importlib.util.spec_from_file_location("secure_panic", PANIC_HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["secure_panic"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def secure_panic():
    return load_panic()


class TestEmergencyEntrypoints:
    def test_entrypoints_and_helpers_are_executable(self):
        for path in (
            SCRIPTS_DIR / "securectl",
            SCRIPTS_DIR / "panic.sh",
            PANIC_HELPER,
            SCRIPTS_DIR / "secure_luks.py",
        ):
            assert path.exists()
            assert os.access(path, os.X_OK)

    def test_wrappers_only_exec_fixed_helpers(self):
        securectl = (SCRIPTS_DIR / "securectl").read_text()
        compatibility = (SCRIPTS_DIR / "panic.sh").read_text()
        assert "exec /usr/libexec/secure-ai/secure-panic.py" in securectl
        assert 'exec /usr/libexec/secure-ai/securectl panic 1 --no-countdown' in compatibility
        for content in (securectl, compatibility):
            assert "eval " not in content
            assert "source " not in content

    def test_legacy_unsafe_primitives_are_removed(self):
        content = PANIC_HELPER.read_text()
        for unsafe in (
            "pkill",
            "killall",
            "rm -rf",
            "shred",
            "drop_caches",
            "nft flush ruleset",
            "ip route flush",
        ):
            assert unsafe not in content


class TestCommandAuthentication:
    def test_old_passphrase_in_argv_option_is_rejected(self, secure_panic):
        with pytest.raises(SystemExit):
            secure_panic.parse_args(
                ["panic", "2", "--confirm", "secret-on-command-line"]
            )

    def test_destructive_levels_use_stdin_or_local_tty(self, secure_panic):
        args = secure_panic.parse_args(
            [
                "panic",
                "3",
                "--passphrase-stdin",
                "--destructive-confirmation",
                "DESTROY-VAULT-uuid",
            ]
        )
        assert args.passphrase_stdin is True
        assert args.destructive_confirmation == "DESTROY-VAULT-uuid"

    def test_non_root_panic_is_rejected_before_action(
        self, secure_panic, monkeypatch
    ):
        monkeypatch.setattr(secure_panic.os, "geteuid", lambda: 1000)
        assert secure_panic.main(["panic", "1", "--no-countdown"]) == 1

    def test_luks_passphrase_is_not_put_in_argv(
        self, secure_panic, monkeypatch
    ):
        captured: dict[str, object] = {}

        def fake_run(args, *, input_data=None, timeout=0):
            captured["args"] = tuple(args)
            captured["input"] = input_data
            captured["timeout"] = timeout
            return subprocess.CompletedProcess(args, 0, b"", b"")

        monkeypatch.setattr(secure_panic, "run_command", fake_run)
        secure_panic._verify_luks_passphrase(
            Path("/dev/fake"), "correct horse"
        )
        assert b"correct horse" == captured["input"].rstrip()
        assert "correct horse" not in captured["args"]
        assert "--test-passphrase" in captured["args"]

    def test_uuid_bound_confirmation_fails_closed(self, secure_panic):
        with pytest.raises(secure_panic.PanicError):
            secure_panic._confirm_destruction(
                "DESTROY-VAULT-abc", "DESTROY-VAULT-other"
            )


class TestKeyedPanicAudit:
    def test_binary_audit_key_boundary_whitespace_is_not_trimmed(
        self, secure_panic, tmp_path: Path, monkeypatch
    ):
        key_path = tmp_path / "panic.key"
        key = b"\x20" + b"\x00" * 30 + b"\x0a"
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        real_fstat = os.fstat

        def root_owned_fstat(descriptor):
            values = list(real_fstat(descriptor))
            values[4] = 0
            return os.stat_result(values)

        monkeypatch.setattr(secure_panic.os, "fstat", root_owned_fstat)

        assert secure_panic._load_audit_key(key_path) == key

    def test_chain_detects_content_tampering(self, secure_panic):
        key = b"k" * 32
        timestamp = "2026-07-27T00:00:00+00:00"
        data = {"level": 1}
        digest = secure_panic._audit_hash(
            "", "emergency_panic_started", data, timestamp, key
        )
        entry = {
            "timestamp": timestamp,
            "event": "emergency_panic_started",
            "data": data,
            "prev_hash": "",
            "entry_hash": digest,
            "algorithm": "hmac-sha256",
        }
        raw = (json.dumps(entry) + "\n").encode()
        assert secure_panic._verify_audit_bytes(raw, key) == (1, digest)
        entry["data"] = {"level": 3}
        with pytest.raises(secure_panic.PanicError, match="HMAC"):
            secure_panic._verify_audit_bytes(
                (json.dumps(entry) + "\n").encode(), key
            )

    def test_checkpoint_prevents_log_truncation(
        self, secure_panic, tmp_path: Path, monkeypatch
    ):
        audit = tmp_path / "panic-audit.jsonl"
        key = b"a" * 32
        monkeypatch.setattr(secure_panic, "AUDIT_LOG", audit)
        monkeypatch.setattr(
            secure_panic, "AUDIT_KEY", tmp_path / "panic.key"
        )
        monkeypatch.setattr(secure_panic, "_load_audit_key", lambda _path: key)
        monkeypatch.setattr(
            secure_panic, "_group_id", lambda _name: os.getgid()
        )
        monkeypatch.setattr(secure_panic.os, "fchown", lambda *_args: None)
        real_fstat = os.fstat

        def root_owned_fstat(descriptor):
            values = list(real_fstat(descriptor))
            values[4] = 0
            return os.stat_result(values)

        monkeypatch.setattr(secure_panic.os, "fstat", root_owned_fstat)

        secure_panic.append_audit("first", {"level": 1})
        secure_panic.append_audit("second", {"level": 1})
        lines = audit.read_text().splitlines()
        audit.write_text(lines[-1] + "\n")
        with pytest.raises(secure_panic.PanicError):
            secure_panic.append_audit("third", {"level": 1})

    def test_manifest_enrolls_panic_log_as_keyed(self):
        manifest = json.loads(AUDIT_MANIFEST.read_text())
        entry = next(
            item
            for item in manifest["logs"]
            if item["file"] == "panic-audit.jsonl"
        )
        assert entry["format"] == "python-hmac-chain"
        assert entry["security_class"] == "keyed-tamper-evident"
        assert entry["key_file"] == "panic-audit-hmac-key"


class TestVerifiedContainment:
    def test_services_are_runtime_masked_and_verified(
        self, secure_panic, monkeypatch
    ):
        monkeypatch.setattr(secure_panic, "_unit_loaded", lambda _unit: True)

        def fake_run(args, **_kwargs):
            if "is-active" in args:
                return subprocess.CompletedProcess(args, 3, b"inactive\n", b"")
            if "is-enabled" in args:
                return subprocess.CompletedProcess(
                    args, 1, b"masked-runtime\n", b""
                )
            return subprocess.CompletedProcess(args, 0, b"", b"")

        monkeypatch.setattr(secure_panic, "run_command", fake_run)
        results = secure_panic.contain_services()
        assert len(results) == len(secure_panic.PANIC_SERVICES)
        assert all(item["success"] for item in results)
        assert all(item["action"] == "runtime_mask_service" for item in results)

    def test_failed_containment_never_reports_locked(
        self, secure_panic, monkeypatch
    ):
        states: list[str] = []
        monkeypatch.setattr(secure_panic, "append_audit", lambda *_args: None)
        monkeypatch.setattr(
            secure_panic,
            "write_state",
            lambda _level, status, *_args, **_kwargs: states.append(status),
        )
        monkeypatch.setattr(
            secure_panic,
            "lockdown",
            lambda: [{"action": "unmount", "success": False}],
        )
        result = secure_panic.execute_panic(
            1,
            no_countdown=True,
            passphrase_stdin=False,
            destructive_confirmation=None,
        )
        assert result == 1
        assert states[-1] == "failed"
        assert "locked" not in states

    def test_symlink_purge_root_is_refused(
        self, secure_panic, tmp_path: Path, monkeypatch
    ):
        appliance = tmp_path / "secure-ai"
        appliance.mkdir()
        real = appliance / "real"
        real.mkdir()
        link = appliance / "link"
        link.symlink_to(real, target_is_directory=True)
        monkeypatch.setattr(secure_panic, "SECURE_AI_ROOT", appliance)
        with pytest.raises(secure_panic.PanicError, match="not a real directory"):
            secure_panic._purge_directory_contents(link)

    def test_full_wipe_claim_is_cryptographic_and_verified(self):
        content = PANIC_HELPER.read_text()
        assert '("cryptsetup", "luksErase", "--batch-mode"' in content
        assert "remaining LUKS keyslots" in content
        assert "flash/COW media overwrite is not claimed" in content
        assert "keyed panic evidence preserved" in content


class TestPanicService:
    def test_level1_service_has_required_real_unmount_boundary(self):
        content = (SYSTEMD_DIR / "secure-ai-panic.service").read_text()
        assert "Type=oneshot" in content
        assert "securectl panic 1 --no-countdown" in content
        assert "CAP_SYS_ADMIN" in content
        assert "DeviceAllow=/dev/mapper/control rw" in content
        # These create a private mount namespace and would make umount fake.
        for directive in (
            "ProtectSystem=",
            "ProtectHome=",
            "PrivateTmp=",
            "ReadWritePaths=",
            "ReadOnlyPaths=",
            "PrivateDevices=",
        ):
            assert directive not in content

    def test_panic_service_is_manual_only(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(
            module
            for module in recipe["modules"]
            if module.get("type") == "systemd"
        )
        assert "secure-ai-panic.service" not in systemd_module[
            "system"
        ]["enabled"]


class TestProductContract:
    def test_ui_never_executes_root_securectl_directly(self):
        content = UI_APP_PATH.read_text()
        route = content[content.index('("/api/emergency/panic"') :]
        route = route[: route.index("# ---------------------------------------------------------------------------", 1)]
        assert "subprocess.run" not in route
        assert "local root console" in route
        assert "passphrases are never accepted" in route

    def test_configuration_describes_real_semantics(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())["emergency"]
        assert config["level2_action"] == "remove_hardware_unlock"
        assert config["level3_action"] == "cryptographic_vault_erase"
        assert config["destructive_local_console_only"] is True
        assert config["media_overwrite_guaranteed"] is False

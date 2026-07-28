"""Tests for the vault auto-lock watchdog module."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_scripts_dir = (
    Path(__file__).parent.parent
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
)
_luks_spec = importlib.util.spec_from_file_location(
    "secure_luks",
    str(_scripts_dir / "secure_luks.py"),
)
assert _luks_spec is not None and _luks_spec.loader is not None
_secure_luks = importlib.util.module_from_spec(_luks_spec)
sys.modules["secure_luks"] = _secure_luks
_luks_spec.loader.exec_module(_secure_luks)

_spec = importlib.util.spec_from_file_location(
    "vault_watchdog",
    str(_scripts_dir / "vault-watchdog.py"),
)
assert _spec is not None and _spec.loader is not None
vw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vw)


class TestActivityTracking:
    def test_touch_activity_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            activity_file = Path(tmp) / "last-activity"
            with patch.object(vw, "ACTIVITY_FILE", str(activity_file)):
                vw.touch_activity()
                assert activity_file.exists()
                ts = float(activity_file.read_text().strip())
                assert abs(ts - time.time()) < 2

    def test_read_last_activity_returns_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            activity_file = Path(tmp) / "last-activity"
            now = time.time()
            activity_file.write_text(str(now))
            with patch.object(vw, "ACTIVITY_FILE", str(activity_file)):
                result = vw.read_last_activity()
                assert abs(result - now) < 0.01

    def test_read_last_activity_missing_file(self):
        with patch.object(vw, "ACTIVITY_FILE", "/nonexistent/path"):
            assert vw.read_last_activity() == 0.0

    def test_read_last_activity_invalid_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            activity_file = Path(tmp) / "last-activity"
            activity_file.write_text("not-a-number")
            with patch.object(vw, "ACTIVITY_FILE", str(activity_file)):
                assert vw.read_last_activity() == 0.0
                assert vw.activity_timestamp()[0] == "invalid"

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf", "-1"])
    def test_non_finite_or_negative_activity_is_invalid(self, value):
        with tempfile.TemporaryDirectory() as tmp:
            activity_file = Path(tmp) / "last-activity"
            activity_file.write_text(value)
            with patch.object(vw, "ACTIVITY_FILE", str(activity_file)):
                assert vw.activity_timestamp()[0] == "invalid"


class TestStateManagement:
    def test_write_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            with patch.object(vw, "STATE_FILE", str(state_file)):
                vw.write_state("locked", "idle_timeout")
                data = json.loads(state_file.read_text())
                assert data["state"] == "locked"
                assert data["detail"] == "idle_timeout"
                assert "timestamp" in data

    def test_read_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            state_file.write_text(json.dumps({
                "state": "unlocked",
                "timestamp": time.time(),
                "detail": "",
            }))
            with patch.object(vw, "STATE_FILE", str(state_file)):
                result = vw.read_state()
                assert result["state"] == "unlocked"

    def test_read_state_missing_file(self):
        with patch.object(vw, "STATE_FILE", "/nonexistent/path"):
            result = vw.read_state()
            assert result["state"] == "unknown"

    def test_read_state_corrupt_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            state_file.write_text("not json")
            with patch.object(vw, "STATE_FILE", str(state_file)):
                result = vw.read_state()
                assert result["state"] == "unknown"


class TestVaultDetection:
    @patch("subprocess.run")
    def test_is_vault_mounted_true(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/dev/mapper/secure-ai-vault\n",
        )
        assert vw.is_vault_mounted() is True

    @patch("subprocess.run")
    def test_is_vault_mounted_false(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert vw.is_vault_mounted() is False

    @patch("subprocess.run")
    def test_similarly_named_mapper_is_not_the_vault(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/dev/mapper/not-secure-ai-vault\n",
        )
        assert vw.is_vault_mounted() is False

    @patch("subprocess.run", side_effect=OSError("fail"))
    def test_is_vault_mounted_error(self, mock_run):
        assert vw.is_vault_mounted() is False

    def test_is_mapper_open(self):
        # /dev/mapper/secure-ai-vault won't exist in test env
        assert vw.is_mapper_open() is False


class TestLockVault:
    @patch("subprocess.run")
    def test_lock_vault_success(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            audit_log = Path(tmp) / "vault-audit.jsonl"
            with patch.object(vw, "STATE_FILE", str(state_file)), \
                 patch.object(vw, "AUDIT_LOG", str(audit_log)), \
                 patch.object(vw, "vault_mount_state", return_value=("absent", "")), \
                 patch.object(vw, "is_mapper_open", return_value=False), \
                 patch.object(vw, "vault_has_configuration", return_value=True):
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                result = vw.lock_vault("idle_timeout")
                assert result is True
                state = json.loads(state_file.read_text())
                assert state["state"] == "locked"

    @patch("subprocess.run")
    def test_unconfigured_vault_is_never_reported_as_locked(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            with patch.object(vw, "STATE_FILE", str(state_file)), \
                 patch.object(vw, "AUDIT_LOG", str(Path(tmp) / "audit.jsonl")), \
                 patch.object(vw, "vault_mount_state", return_value=("absent", "")), \
                 patch.object(vw, "is_mapper_open", return_value=False), \
                 patch.object(vw, "vault_has_configuration", return_value=False):
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                assert vw.lock_vault("operator_request") is True
                assert json.loads(state_file.read_text())["state"] == "setup_required"

    @patch("subprocess.run")
    def test_lock_vault_cryptsetup_failure(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            audit_log = Path(tmp) / "vault-audit.jsonl"
            def command_result(command, **_kwargs):
                if command[:2] == ["cryptsetup", "close"]:
                    return MagicMock(returncode=1, stderr="Device busy")
                return MagicMock(returncode=0, stderr="")

            with patch.object(vw, "STATE_FILE", str(state_file)), \
                 patch.object(vw, "AUDIT_LOG", str(audit_log)), \
                 patch.object(
                     vw,
                     "vault_mount_state",
                     side_effect=[
                         ("expected", "/dev/mapper/secure-ai-vault"),
                         ("absent", ""),
                     ],
                 ), \
                 patch.object(vw, "is_mapper_open", return_value=True):
                # Dispatch by command rather than service count so adding a
                # newly discovered vault consumer cannot accidentally move
                # the simulated failure to an unrelated systemctl call.
                mock_run.side_effect = command_result
                result = vw.lock_vault("idle_timeout")
                assert result is False
                state = json.loads(state_file.read_text())
                assert state["state"] == "error"
                assert any(
                    call.args[0][:2] == ["cryptsetup", "close"]
                    for call in mock_run.call_args_list
                )

    @patch("subprocess.run")
    def test_unexpected_mount_never_reports_locked(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            with patch.object(vw, "STATE_FILE", str(state_file)), \
                 patch.object(vw, "AUDIT_LOG", str(Path(tmp) / "audit.jsonl")), \
                 patch.object(
                     vw,
                     "vault_mount_state",
                     return_value=("unexpected", "/dev/sda1"),
                 ), \
                 patch.object(vw, "stop_services", return_value=True):
                assert vw.lock_vault("idle_timeout") is False
                assert json.loads(state_file.read_text())["state"] == "error"


class TestUnlockVault:
    @patch("subprocess.run")
    def test_unlock_vault_already_mounted(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/dev/mapper/secure-ai-vault\n",
        )
        result = vw.unlock_vault("password", "/dev/sda3")
        assert result["success"] is True
        assert "already" in result.get("detail", "")

    def test_preexisting_mount_must_pass_exact_verification(self):
        with patch.object(
            vw,
            "vault_mount_state",
            return_value=("expected", "/dev/mapper/secure-ai-vault"),
        ), patch.object(
            vw, "exact_vault_mount_verified", return_value=False
        ), patch.object(vw, "lock_vault", return_value=True) as relock:
            result = vw.unlock_vault("password")

        assert result["success"] is False
        relock.assert_called_once_with("preexisting_mount_verification_failed")

    @patch("subprocess.run")
    def test_unlock_vault_no_partition(self, mock_run_sub):
        # Not mounted
        mock_run_sub.return_value = MagicMock(returncode=1, stdout="")
        with patch.object(vw, "is_mapper_open", return_value=False), \
             patch.object(vw, "_find_partition_from_crypttab", return_value=""):
            result = vw.unlock_vault("password")
            assert result["success"] is False
            assert "partition" in result["error"]

    @patch("subprocess.run")
    def test_mount_failure_closes_mapper_opened_by_unlock(self, mock_run):
        def command_result(command, **_kwargs):
            if command[0] == "cryptsetup" and command[1] == "open":
                return MagicMock(returncode=0, stderr=b"")
            if command[0] == "mount":
                raise subprocess.CalledProcessError(32, command)
            if command[:2] == ["cryptsetup", "close"]:
                return MagicMock(returncode=0, stderr="")
            raise AssertionError(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(vw, "MOUNT_POINT", str(Path(tmp) / "vault")), \
             patch.object(vw, "STATE_FILE", str(Path(tmp) / "state")), \
             patch.object(vw, "AUDIT_LOG", str(Path(tmp) / "audit.jsonl")), \
             patch.object(vw, "vault_mount_state", return_value=("absent", "")), \
             patch.object(vw, "is_mapper_open", side_effect=[False, False]), \
             patch.object(vw, "resolve_device", return_value=Path("/dev/test-vault")):
            mock_run.side_effect = command_result
            result = vw.unlock_vault("not-on-the-command-line", "/dev/test-vault")

        assert result["success"] is False
        open_call = next(
            call for call in mock_run.call_args_list
            if call.args[0][:2] == ["cryptsetup", "open"]
        )
        assert "not-on-the-command-line" not in open_call.args[0]
        assert open_call.kwargs["input"] == b"not-on-the-command-line"
        assert any(
            call.args[0][:2] == ["cryptsetup", "close"]
            for call in mock_run.call_args_list
        )

    @patch("subprocess.run")
    def test_start_services_only_starts_enabled_units(self, mock_run):
        enabled_service = vw.SERVICES_TO_STOP[0]

        def command_result(command, **_kwargs):
            if command[:3] == ["systemctl", "is-enabled", "--quiet"]:
                return MagicMock(returncode=0 if command[3] == enabled_service else 1)
            if command[:2] == ["systemctl", "start"]:
                return MagicMock(returncode=0, stderr="")
            raise AssertionError(f"unexpected command: {command}")

        mock_run.side_effect = command_result
        success, failures = vw.start_services()

        assert success is True
        assert failures == []
        starts = [
            call.args[0]
            for call in mock_run.call_args_list
            if call.args[0][:2] == ["systemctl", "start"]
        ]
        assert starts == [["systemctl", "start", enabled_service]]


class TestCrypttab:
    def test_find_partition_basic(self):
        with patch.object(
            vw, "configured_device", return_value=Path("/dev/sda3")
        ):
            result = vw._find_partition_from_crypttab()
            assert result == "/dev/sda3"

    def test_find_partition_no_match(self):
        with patch.object(
            vw,
            "configured_device",
            side_effect=vw.LUKSError("no exact vault entry"),
        ):
            result = vw._find_partition_from_crypttab()
            assert result == ""

    def test_find_partition_no_file(self):
        with patch.object(vw, "configured_device", side_effect=OSError("not found")):
            result = vw._find_partition_from_crypttab()
            assert result == ""


def test_vault_consumer_list_keeps_observers_alive_and_resets_gate():
    assert "secure-ai-ui.service" not in vw.SERVICES_TO_STOP
    assert "secure-ai-gpu-integrity-watch.service" not in vw.SERVICES_TO_STOP
    assert "secure-ai-vault-mounted.service" in vw.SERVICES_TO_STOP


class TestAuditEvent:
    def test_audit_event_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "vault-audit.jsonl"
            with patch.object(vw, "AUDIT_LOG", str(audit_log)):
                vw.audit_event("test_event", key="value")
                lines = audit_log.read_text().strip().split("\n")
                assert len(lines) == 1
                entry = json.loads(lines[0])
                assert entry["event"] == "test_event"
                assert entry["key"] == "value"
                assert "timestamp" in entry

    def test_audit_event_no_crash_on_error(self):
        with patch.object(vw, "AUDIT_LOG", "/nonexistent/deep/path/audit.jsonl"):
            # Should not raise
            vw.audit_event("test")

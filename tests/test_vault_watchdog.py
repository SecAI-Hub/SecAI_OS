"""Tests for the vault auto-lock watchdog module."""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "vault_watchdog",
    str(Path(__file__).parent.parent / "files" / "system" / "usr" / "libexec" / "secure-ai" / "vault-watchdog.py"),
)
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
        mock_run.return_value = MagicMock(stdout="/dev/mapper/secure-ai-vault\n")
        assert vw.is_vault_mounted() is True

    @patch("subprocess.run")
    def test_is_vault_mounted_false(self, mock_run):
        mock_run.return_value = MagicMock(stdout="")
        assert vw.is_vault_mounted() is False

    @patch("subprocess.run", side_effect=Exception("fail"))
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
                 patch.object(vw, "AUDIT_LOG", str(audit_log)):
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                result = vw.lock_vault("idle_timeout")
                assert result is True
                state = json.loads(state_file.read_text())
                assert state["state"] == "locked"

    @patch("subprocess.run")
    def test_lock_vault_cryptsetup_failure(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "vault-state"
            audit_log = Path(tmp) / "vault-audit.jsonl"
            with patch.object(vw, "STATE_FILE", str(state_file)), \
                 patch.object(vw, "AUDIT_LOG", str(audit_log)):
                # First calls (stop services, sync, umount) succeed
                # Last call (cryptsetup close) fails
                mock_run.side_effect = [
                    MagicMock(returncode=0),  # stop service 1
                    MagicMock(returncode=0),  # stop service 2
                    MagicMock(returncode=0),  # stop service 3
                    MagicMock(returncode=0),  # sync
                    MagicMock(returncode=0),  # umount
                    MagicMock(returncode=1, stderr="Device busy"),  # cryptsetup close
                ]
                result = vw.lock_vault("idle_timeout")
                assert result is False
                state = json.loads(state_file.read_text())
                assert state["state"] == "error"


class TestUnlockVault:
    @patch("subprocess.run")
    def test_unlock_vault_already_mounted(self, mock_run):
        mock_run.return_value = MagicMock(stdout="/dev/mapper/secure-ai-vault\n")
        result = vw.unlock_vault("password", "/dev/sda3")
        assert result["success"] is True
        assert "already" in result.get("detail", "")

    @patch("subprocess.run")
    def test_unlock_vault_no_partition(self, mock_run_sub):
        # Not mounted
        mock_run_sub.return_value = MagicMock(stdout="")
        with patch.object(vw, "_find_partition_from_crypttab", return_value=""):
            result = vw.unlock_vault("password")
            assert result["success"] is False
            assert "partition" in result["error"]


class TestCrypttab:
    def test_find_partition_basic(self):
        crypttab_content = "# comment\nsecure-ai-vault  /dev/sda3  none  luks,discard\n"
        mock_path = MagicMock()
        mock_path.read_text.return_value = crypttab_content
        with patch.object(vw, "Path", return_value=mock_path):
            result = vw._find_partition_from_crypttab()
            assert result == "/dev/sda3"

    def test_find_partition_no_match(self):
        crypttab_content = "other-volume  /dev/sda3  none  luks\n"
        mock_path = MagicMock()
        mock_path.read_text.return_value = crypttab_content
        with patch.object(vw, "Path", return_value=mock_path):
            result = vw._find_partition_from_crypttab()
            assert result == ""

    def test_find_partition_no_file(self):
        mock_path = MagicMock()
        mock_path.read_text.side_effect = OSError("not found")
        with patch.object(vw, "Path", return_value=mock_path):
            result = vw._find_partition_from_crypttab()
            assert result == ""


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

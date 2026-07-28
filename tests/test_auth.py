"""Tests for the authentication module."""

import sys
import tempfile
import time
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from common.auth import AuthManager, hash_passphrase, verify_passphrase


class TestPassphraseHashing:
    def test_hash_returns_required_fields(self):
        result = hash_passphrase("testpassword")
        assert "salt" in result
        assert "hash" in result
        assert "algorithm" in result
        assert result["algorithm"] == "scrypt"
        assert len(result["salt"]) == 64  # 32 bytes hex
        assert len(result["hash"]) == 128  # 64 bytes hex

    def test_verify_correct_passphrase(self):
        stored = hash_passphrase("mysecretpass")
        assert verify_passphrase("mysecretpass", stored) is True

    def test_verify_wrong_passphrase(self):
        stored = hash_passphrase("mysecretpass")
        assert verify_passphrase("wrongpass", stored) is False

    def test_different_salts_produce_different_hashes(self):
        h1 = hash_passphrase("samepass")
        h2 = hash_passphrase("samepass")
        assert h1["salt"] != h2["salt"]
        assert h1["hash"] != h2["hash"]


class TestAuthManagerSetup:
    def test_not_configured_initially(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.is_configured() is False

    def test_setup_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.setup_passphrase("valid-passphrase-123") is True
            assert auth.is_configured() is True

    def test_setup_rejects_short_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.setup_passphrase("short") is False
            assert auth.is_configured() is False

    def test_setup_only_works_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.setup_passphrase("first-passphrase-123") is True
            assert auth.setup_passphrase("second-passphrase-123") is False

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows does not enforce POSIX file modes")
    def test_credentials_file_permissions(self):
        import os
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            creds_path = Path(tmp) / "auth.json"
            mode = os.stat(creds_path).st_mode
            assert stat.S_IMODE(mode) == 0o660


class TestAuthManagerLogin:
    def test_login_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            assert result["success"] is True
            assert "token" in result
            assert len(result["token"]) == 64  # 32 bytes hex

    def test_login_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("wrongpass")
            assert result["success"] is False

    def test_login_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            result = auth.login("anypass")
            assert result["success"] is False

    def test_lockout_after_max_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp, max_attempts=3, lockout_duration=10)
            auth.setup_passphrase("test-passphrase-123")

            for _ in range(3):
                auth.login("wrong")

            result = auth.login("test-passphrase-123")  # correct but locked
            assert result["success"] is False
            assert result.get("locked") is True


class TestAuthManagerSessions:
    def test_validate_valid_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            token = result["token"]
            assert auth.validate_session(token) is True

    def test_validate_invalid_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.validate_session("nonexistent") is False

    def test_validate_empty_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            assert auth.validate_session("") is False
            assert auth.validate_session(None) is False

    def test_session_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp, session_timeout=1)  # 1 second timeout
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            token = result["token"]

            time.sleep(1.5)
            assert auth.validate_session(token) is False

    def test_logout_invalidates_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            token = result["token"]

            auth.logout(token)
            assert auth.validate_session(token) is False

    def test_validate_without_refresh_preserves_idle_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            token = result["token"]

            before = auth._sessions[token]["last_active"]
            time.sleep(0.01)
            assert auth.validate_session(token, refresh=False) is True
            after = auth._sessions[token]["last_active"]
            assert after == before

    def test_session_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("test-passphrase-123")
            result = auth.login("test-passphrase-123")
            token = result["token"]

            info = auth.get_session_info(token)
            assert info["active"] is True
            assert "age_seconds" in info
            assert "idle_seconds" in info

    def test_cleanup_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp, session_timeout=1)
            auth.setup_passphrase("test-passphrase-123")
            auth.login("test-passphrase-123")

            time.sleep(1.5)
            auth.cleanup_expired()
            assert len(auth._sessions) == 0


class TestAuthManagerChangePassphrase:
    def test_change_passphrase_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("old-passphrase-123")
            result = auth.change_passphrase("old-passphrase-123", "new-passphrase-456")
            assert result["success"] is True

            # Old passphrase should not work
            assert auth.login("old-passphrase-123")["success"] is False
            # New one should
            assert auth.login("new-passphrase-456")["success"] is True

    def test_change_rejects_wrong_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("old-passphrase-123")
            result = auth.change_passphrase("wrongcurrent", "new-passphrase-456")
            assert result["success"] is False

    def test_change_rejects_short_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("old-passphrase-123")
            result = auth.change_passphrase("old-passphrase-123", "short")
            assert result["success"] is False

    def test_change_invalidates_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = AuthManager(tmp)
            auth.setup_passphrase("old-passphrase-123")
            login_result = auth.login("old-passphrase-123")
            token = login_result["token"]

            auth.change_passphrase("old-passphrase-123", "new-passphrase-456")
            assert auth.validate_session(token) is False

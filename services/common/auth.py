"""
Secure AI Appliance - Local Authentication Module

Provides passphrase-based authentication with:
- scrypt password hashing (memory-hard KDF)
- Cryptographically random session tokens
- Rate limiting with progressive lockout
- Session timeout management

No external auth server required. All state is local.
"""

import hashlib
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger("auth")

# Scrypt parameters (memory-hard: ~128MB per hash at these settings)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64

# Defaults (overridable via config)
DEFAULT_SESSION_TIMEOUT = 1800  # 30 minutes in seconds
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_DURATION = 60  # seconds
DEFAULT_ESCALATED_LOCKOUT = 900  # 15 minutes
DEFAULT_ESCALATION_THRESHOLD = 15


def hash_passphrase(passphrase: str, salt: bytes | None = None) -> dict:
    """Hash a passphrase using scrypt. Returns {salt, hash} as hex strings."""
    if salt is None:
        salt = secrets.token_bytes(32)
    dk = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
    )
    return {
        "salt": salt.hex(),
        "hash": dk.hex(),
        "algorithm": "scrypt",
        "params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
    }


def verify_passphrase(passphrase: str, stored: dict) -> bool:
    """Verify a passphrase against a stored hash."""
    salt = bytes.fromhex(stored["salt"])
    expected = stored["hash"]
    dk = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=stored.get("params", {}).get("n", SCRYPT_N),
        r=stored.get("params", {}).get("r", SCRYPT_R),
        p=stored.get("params", {}).get("p", SCRYPT_P),
        dklen=SCRYPT_DKLEN,
    )
    return secrets.compare_digest(dk.hex(), expected)


class AuthManager:
    """Manages passphrase storage, sessions, and rate limiting."""

    def __init__(self, data_dir: str, session_timeout: int = DEFAULT_SESSION_TIMEOUT,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 lockout_duration: int = DEFAULT_LOCKOUT_DURATION):
        self._data_dir = Path(data_dir)
        self._creds_path = self._data_dir / "auth.json"
        self._session_timeout = session_timeout
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration
        self._lock = threading.Lock()

        # In-memory state
        self._sessions: dict[str, dict[str, float]] = {}  # token -> {"created": ts, "last_active": ts}
        self._failed_attempts = 0
        self._last_failed = 0.0
        self._lockout_until = 0.0

    def _write_creds(self, creds: dict) -> None:
        """Persist credentials atomically with restrictive permissions."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".auth.",
            suffix=".tmp",
            dir=str(self._data_dir),
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(creds, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self._creds_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def is_configured(self) -> bool:
        """Check if a passphrase has been set."""
        return self._creds_path.exists()

    def setup_passphrase(self, passphrase: str) -> bool:
        """Set the initial passphrase. Only works if not already configured."""
        if self.is_configured():
            return False

        if len(passphrase) < 8:
            return False

        creds = hash_passphrase(passphrase)
        creds["created_at"] = time.time()

        try:
            self._write_creds(creds)
            log.info("passphrase configured successfully")
            return True
        except OSError as e:
            log.error("failed to save credentials: %s", e)
            return False

    def change_passphrase(self, current: str, new_passphrase: str) -> dict:
        """Change the passphrase. Requires current passphrase for verification."""
        if not self.is_configured():
            return {"success": False, "error": "not configured"}

        if not self._verify_stored(current):
            return {"success": False, "error": "current passphrase incorrect"}

        if len(new_passphrase) < 8:
            return {"success": False, "error": "new passphrase must be at least 8 characters"}

        creds = hash_passphrase(new_passphrase)
        creds["created_at"] = time.time()

        try:
            self._write_creds(creds)

            # Invalidate all existing sessions
            with self._lock:
                self._sessions.clear()

            log.info("passphrase changed successfully")
            return {"success": True}
        except OSError as e:
            return {"success": False, "error": str(e)}

    def login(self, passphrase: str) -> dict:
        """Attempt login. Returns {success, token} or {success, error, locked_until}."""
        with self._lock:
            now = time.time()

            # Check lockout
            if now < self._lockout_until:
                remaining = int(self._lockout_until - now)
                return {
                    "success": False,
                    "error": f"account locked, try again in {remaining}s",
                    "locked_until": self._lockout_until,
                    "locked": True,
                }

        if not self.is_configured():
            return {"success": False, "error": "passphrase not configured"}

        if self._verify_stored(passphrase):
            with self._lock:
                self._failed_attempts = 0
                token = secrets.token_hex(32)
                now = time.time()
                self._sessions[token] = {"created": now, "last_active": now}
            log.info("login successful")
            return {"success": True, "token": token}

        # Failed login
        with self._lock:
            self._failed_attempts += 1
            self._last_failed = time.time()

            if self._failed_attempts >= DEFAULT_ESCALATION_THRESHOLD:
                self._lockout_until = time.time() + DEFAULT_ESCALATED_LOCKOUT
                log.warning("login failed %d times, escalated lockout %ds",
                            self._failed_attempts, DEFAULT_ESCALATED_LOCKOUT)
            elif self._failed_attempts >= self._max_attempts:
                self._lockout_until = time.time() + self._lockout_duration
                log.warning("login failed %d times, locked out for %ds",
                            self._failed_attempts, self._lockout_duration)

        return {"success": False, "error": "incorrect passphrase"}

    def validate_session(self, token: str, refresh: bool = True) -> bool:
        """Check if a session token is valid and not expired.

        When ``refresh`` is False, validation does not extend the session's
        idle timeout. This is useful for passive polling endpoints.
        """
        if not token:
            return False

        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return False

            now = time.time()
            if now - session["last_active"] > self._session_timeout:
                del self._sessions[token]
                return False

            if refresh:
                session["last_active"] = now
            return True

    def logout(self, token: str):
        """Invalidate a session."""
        with self._lock:
            self._sessions.pop(token, None)

    def get_session_info(self, token: str) -> dict:
        """Get session metadata."""
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return {}
            now = time.time()
            return {
                "active": True,
                "age_seconds": int(now - session["created"]),
                "idle_seconds": int(now - session["last_active"]),
                "timeout": self._session_timeout,
            }

    def cleanup_expired(self):
        """Remove expired sessions."""
        with self._lock:
            now = time.time()
            expired = [
                t for t, s in self._sessions.items()
                if now - s["last_active"] > self._session_timeout
            ]
            for t in expired:
                del self._sessions[t]

    def _verify_stored(self, passphrase: str) -> bool:
        """Verify passphrase against stored credentials."""
        try:
            with open(self._creds_path) as f:
                stored = json.load(f)
            return verify_passphrase(passphrase, stored)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            log.error("failed to read credentials: %s", e)
            return False

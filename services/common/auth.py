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
import re
import secrets
import stat
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger("auth")

# Scrypt parameters (memory-hard: ~128 MiB per hash at these settings)
SCRYPT_N = 131072
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_MAXMEM = 256 * 1024 * 1024
LEGACY_SCRYPT_N = 16384
MIN_PASSPHRASE_LENGTH = 15
MAX_PASSPHRASE_LENGTH = 256
MAX_AUTH_FILE_BYTES = 64 * 1024
try:
    _MAX_CONCURRENT_KDFS = int(os.getenv("AUTH_MAX_CONCURRENT_KDFS", "2"))
except ValueError:
    _MAX_CONCURRENT_KDFS = 2
_KDF_SEMAPHORE = threading.BoundedSemaphore(
    max(1, min(_MAX_CONCURRENT_KDFS, 4))
)
_COMPROMISED_PASSPHRASES = frozenset({
    "123456789012345",
    "adminadminadmin",
    "changemechangeme",
    "letmeinletmein",
    "passwordpassword",
    "qwertyqwertyqwerty",
    "welcome123456789",
})

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
    with _KDF_SEMAPHORE:
        dk = hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )
    return {
        "salt": salt.hex(),
        "hash": dk.hex(),
        "algorithm": "scrypt",
        "params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
    }


def verify_passphrase(passphrase: str, stored: dict) -> bool:
    """Verify a passphrase against a stored hash."""
    try:
        if not isinstance(stored, dict) or stored.get("algorithm") != "scrypt":
            return False
        salt_hex = stored.get("salt")
        expected = stored.get("hash")
        params = stored.get("params")
        if (
            not isinstance(salt_hex, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", salt_hex) is None
            or not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-fA-F]{128}", expected) is None
            or not isinstance(params, dict)
        ):
            return False
        n = params.get("n")
        r = params.get("r")
        p = params.get("p")
        if n not in {LEGACY_SCRYPT_N, SCRYPT_N} or r != SCRYPT_R or p != SCRYPT_P:
            return False
        salt = bytes.fromhex(salt_hex)
        with _KDF_SEMAPHORE:
            dk = hashlib.scrypt(
                passphrase.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=SCRYPT_DKLEN,
                maxmem=SCRYPT_MAXMEM,
            )
        return secrets.compare_digest(dk.hex(), expected.lower())
    except (KeyError, TypeError, ValueError, OverflowError, MemoryError):
        return False


def validate_new_passphrase(passphrase: object) -> str | None:
    """Return a policy error for a new passphrase, otherwise ``None``."""
    if not isinstance(passphrase, str):
        return "passphrase must be a string"
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        return f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters"
    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        return f"passphrase must be at most {MAX_PASSPHRASE_LENGTH} characters"
    if passphrase.casefold() in _COMPROMISED_PASSPHRASES:
        return "passphrase appears in the bundled compromised-password blocklist"
    return None


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
        # Rate limits are keyed by the directly connected client. A single
        # unauthenticated caller must not lock every local operator out.
        self._login_states: dict[str, dict[str, float | int]] = {}

    def _write_creds(self, creds: dict, *, exclusive: bool = False) -> None:
        """Persist credentials atomically using the stable auth group."""
        self._data_dir.mkdir(mode=0o2770, parents=True, exist_ok=True)
        try:
            self._data_dir.chmod(0o2770)
        except OSError:
            pass
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
            os.chmod(tmp_path, 0o660)
            if exclusive:
                # link(2) is an atomic create-if-absent operation on the same
                # filesystem. It prevents two workers from both winning the
                # unauthenticated first-boot setup race.
                os.link(tmp_path, self._creds_path)
                os.unlink(tmp_path)
            else:
                os.replace(tmp_path, self._creds_path)
            os.chmod(self._creds_path, 0o660)
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
        if validate_new_passphrase(passphrase):
            return False

        creds = hash_passphrase(passphrase)
        creds["created_at"] = time.time()

        with self._lock:
            if self.is_configured():
                return False
            try:
                self._write_creds(creds, exclusive=True)
                log.info("passphrase configured successfully")
                return True
            except FileExistsError:
                log.warning("passphrase setup lost concurrent setup race")
                return False
            except OSError:
                log.error("failed to save credentials")
                return False

    def change_passphrase(self, current: str, new_passphrase: str) -> dict:
        """Change the passphrase. Requires current passphrase for verification."""
        if not self.is_configured():
            return {"success": False, "error": "not configured"}

        if not self._verify_stored(current):
            return {"success": False, "error": "current passphrase incorrect"}

        policy_error = validate_new_passphrase(new_passphrase)
        if policy_error:
            return {"success": False, "error": policy_error}

        creds = hash_passphrase(new_passphrase)
        creds["created_at"] = time.time()

        try:
            self._write_creds(creds)

            # Invalidate all existing sessions
            with self._lock:
                self._sessions.clear()

            log.info("passphrase changed successfully")
            return {"success": True}
        except OSError:
            log.exception("failed to change passphrase")
            return {"success": False, "error": "failed to change passphrase"}

    def login(self, passphrase: str, client_id: str = "local") -> dict:
        """Attempt login. Returns {success, token} or {success, error, locked_until}."""
        client_key = str(client_id or "local")[:200]
        with self._lock:
            now = time.time()
            state = self._login_states.setdefault(
                client_key,
                {"failed_attempts": 0, "last_failed": 0.0, "lockout_until": 0.0},
            )

            # Check lockout
            lockout_until = float(state["lockout_until"])
            if now < lockout_until:
                remaining = int(lockout_until - now)
                return {
                    "success": False,
                    "error": f"account locked, try again in {remaining}s",
                    "locked_until": lockout_until,
                    "locked": True,
                }

        if not self.is_configured():
            return {"success": False, "error": "passphrase not configured"}

        if self._verify_stored(passphrase):
            self._upgrade_legacy_hash(passphrase)
            with self._lock:
                self._login_states.pop(client_key, None)
                token = secrets.token_hex(32)
                now = time.time()
                self._sessions[token] = {"created": now, "last_active": now}
            log.info("login successful")
            return {"success": True, "token": token}

        # Failed login
        with self._lock:
            state = self._login_states.setdefault(
                client_key,
                {"failed_attempts": 0, "last_failed": 0.0, "lockout_until": 0.0},
            )
            state["failed_attempts"] = int(state["failed_attempts"]) + 1
            state["last_failed"] = time.time()
            attempts = int(state["failed_attempts"])

            if attempts >= DEFAULT_ESCALATION_THRESHOLD:
                state["lockout_until"] = time.time() + DEFAULT_ESCALATED_LOCKOUT
                log.warning("login failed %d times, escalated lockout %ds",
                            attempts, DEFAULT_ESCALATED_LOCKOUT)
            elif attempts >= self._max_attempts:
                state["lockout_until"] = time.time() + self._lockout_duration
                log.warning("login failed %d times, locked out for %ds",
                            attempts, self._lockout_duration)

            # Bound memory if callers continually rotate source addresses.
            if len(self._login_states) > 4096:
                cutoff = time.time() - DEFAULT_ESCALATED_LOCKOUT
                self._login_states = {
                    key: value
                    for key, value in self._login_states.items()
                    if float(value["last_failed"]) >= cutoff
                }

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
            stored = self._read_stored()
            return verify_passphrase(passphrase, stored)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            log.error("failed to read credentials")
            return False

    def _read_stored(self) -> dict:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._creds_path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_AUTH_FILE_BYTES:
                raise ValueError("unsafe credential file")
            raw = os.read(descriptor, MAX_AUTH_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid credential schema")
        return value

    def _upgrade_legacy_hash(self, passphrase: str) -> None:
        """Upgrade a verified legacy hash without overwriting a concurrent change."""
        try:
            stored = self._read_stored()
            params = stored.get("params")
            if not isinstance(params, dict) or params.get("n") == SCRYPT_N:
                return
            old_hash = stored.get("hash")
            upgraded = hash_passphrase(passphrase)
            upgraded["created_at"] = stored.get("created_at", time.time())
            upgraded["upgraded_at"] = time.time()
            with self._lock:
                current = self._read_stored()
                if current.get("hash") != old_hash:
                    return
                self._write_creds(upgraded)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            log.error("failed to upgrade legacy passphrase hash")

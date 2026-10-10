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
import threading
import math
import time
from pathlib import Path

from . import runtime_clock
from .bounded_state import StateCapacity, StateUnavailable, open_directory
from .session_store import MAX_CLIENTS, MAX_SESSIONS, SessionStore, credential_fingerprint, token_digest

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
    """Passphrase credentials and durable, process-shared session metadata."""

    def __init__(self, data_dir: str, session_timeout: int = DEFAULT_SESSION_TIMEOUT,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 lockout_duration: int = DEFAULT_LOCKOUT_DURATION,
                 *, runtime_dir: str | None = None, absolute_timeout: float | None = None):
        self._data_dir = Path(data_dir)
        self._creds_path = self._data_dir / "auth.json"
        self._session_timeout = session_timeout
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration
        absolute = float(absolute_timeout if absolute_timeout is not None else os.getenv("SESSION_ABSOLUTE_TIMEOUT", "43200"))
        if not math.isfinite(absolute) or not 1 <= absolute <= 7 * 86400:
            raise ValueError("invalid absolute session timeout")
        if not isinstance(session_timeout, (int, float)) or not 0 < session_timeout <= 86400:
            raise ValueError("invalid idle session timeout")
        # UI passes an explicit /run path. Standalone/test instances keep their
        # runtime namespace in the caller-owned fixture directory.
        runtime = Path(runtime_dir) if runtime_dir else self._data_dir / ".session-runtime"
        self._store = SessionStore(self._data_dir, runtime, idle=session_timeout, absolute=absolute)

    def _write_creds(self, creds: dict, *, exclusive: bool = False) -> None:
        directory = open_directory(self._data_dir, create=True)
        temporary = ".auth." + secrets.token_hex(12)
        descriptor = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 0o660, dir_fd=directory)
            os.fchmod(descriptor, 0o660)
            raw = (json.dumps(creds, sort_keys=True, allow_nan=False) + "\n").encode()
            if len(raw) > MAX_AUTH_FILE_BYTES or os.write(descriptor, raw) != len(raw):
                raise StateUnavailable("credential write incomplete")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if exclusive:
                os.link(temporary, "auth.json", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                os.unlink(temporary, dir_fd=directory)
            else:
                os.replace(temporary, "auth.json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    def is_configured(self) -> bool:
        return self._creds_path.exists()

    def setup_passphrase(self, passphrase: str) -> bool:
        if validate_new_passphrase(passphrase):
            return False
        creds = hash_passphrase(passphrase)
        creds["created_at"] = time.time()
        try:
            with self._store.state.transaction(write=True) as state:
                self._store.current(state)
                if self.is_configured():
                    return False
                self._write_creds(creds, exclusive=True)
            return True
        except OSError:
            log.error("failed to save credentials")
            return False

    def change_passphrase(self, current: str, new_passphrase: str) -> dict:
        if not self.is_configured():
            return {"success": False, "error": "not configured"}
        policy_error = validate_new_passphrase(new_passphrase)
        if policy_error:
            return {"success": False, "error": policy_error}
        with self._store.state.transaction() as state:
            expected = self._read_stored()
        if not verify_passphrase(current, expected):
            return {"success": False, "error": "current passphrase incorrect"}
        creds = hash_passphrase(new_passphrase)
        creds["created_at"] = time.time()
        with self._store.state.transaction(write=True) as state:
            self._store.current(state)
            if credential_fingerprint(self._read_stored()) != credential_fingerprint(expected):
                return {"success": False, "error": "credentials changed; sign in again"}
            self._write_creds(creds)
            state["sessions"].clear()
            state["clients"].clear()
        return {"success": True}

    def _prune(self, state, now):
        state["sessions"] = {key: row for key, row in state["sessions"].items()
                             if self._store.valid(row, row["credential"], now=now)}
        state["clients"] = {key: row for key, row in state["clients"].items()
                            if now - row["last_failed"] <= DEFAULT_ESCALATED_LOCKOUT or now < row["lockout_until"]}

    def _lockout(self, row, now):
        until = row.get("lockout_until", 0) if row else 0
        if now < until:
            return {"success": False, "error": f"account locked, try again in {int(until - now)}s",
                    "locked_until": time.time() + until - now, "locked": True}
        return None

    def login(self, passphrase: str, client_id: str = "local") -> dict:
        if not self.is_configured():
            return {"success": False, "error": "passphrase not configured"}
        client = hashlib.sha256(str(client_id or "local")[:200].encode()).hexdigest()
        self._store.require_current_epoch()
        with self._store.state.transaction(write=True) as state:
            self._store.current(state)
            now = runtime_clock.now()
            self._prune(state, now)
            locked = self._lockout(state["clients"].get(client), now)
            if locked:
                return locked
            if client not in state["clients"] and len(state["clients"]) >= MAX_CLIENTS:
                raise StateCapacity("authentication admission capacity reached")
            expected = self._read_stored()
        verified = verify_passphrase(passphrase, expected)
        upgraded = None
        if verified and expected.get("params", {}).get("n") != SCRYPT_N:
            upgraded = hash_passphrase(passphrase)
            upgraded["created_at"] = expected.get("created_at", time.time())
            upgraded["upgraded_at"] = time.time()
        with self._store.state.transaction(write=True) as state:
            self._store.current(state)
            now = runtime_clock.now()
            self._prune(state, now)
            if credential_fingerprint(self._read_stored()) != credential_fingerprint(expected):
                return {"success": False, "error": "credentials changed; sign in again"}
            locked = self._lockout(state["clients"].get(client), now)
            if locked:
                return locked
            if verified:
                if len(state["sessions"]) >= MAX_SESSIONS:
                    raise StateCapacity("session admission capacity reached")
                if upgraded is not None:
                    self._write_creds(upgraded)
                    expected = upgraded
                    state["sessions"].clear()
                state["clients"].pop(client, None)
                token = secrets.token_hex(32)
                state["sessions"][token_digest(token)] = {
                    "created": now, "last_active": now, "credential": credential_fingerprint(expected),
                }
            else:
                if client not in state["clients"] and len(state["clients"]) >= MAX_CLIENTS:
                    raise StateCapacity("authentication admission capacity reached")
                row = state["clients"].setdefault(client, {"failed_attempts": 0, "last_failed": 0.0, "lockout_until": 0.0})
                row["failed_attempts"] = min(row["failed_attempts"] + 1, 1000000)
                row["last_failed"] = now
                if row["failed_attempts"] >= DEFAULT_ESCALATION_THRESHOLD:
                    row["lockout_until"] = now + DEFAULT_ESCALATED_LOCKOUT
                elif row["failed_attempts"] >= self._max_attempts:
                    row["lockout_until"] = now + self._lockout_duration
        return {"success": True, "token": token} if verified else {"success": False, "error": "incorrect passphrase"}

    def validate_session(self, token: str, refresh: bool = True) -> bool:
        digest = token_digest(token)
        return bool(digest and self.is_configured() and self.validate_grant(digest, refresh=refresh))

    def validate_grant(self, digest: str, *, refresh: bool = False, epoch: str | None = None,
                       credential: str | None = None) -> bool:
        """Internal executor check; digest alone is never an HTTP bearer token."""
        self._store.require_current_epoch()
        with self._store.state.transaction(write=refresh) as state:
            self._store.current(state)
            if epoch is not None and epoch != self._store.epoch:
                return False
            current = credential_fingerprint(self._read_stored())
            if credential is not None and credential != current:
                return False
            row = state["sessions"].get(digest)
            if not self._store.valid(row, current):
                if refresh:
                    state["sessions"].pop(digest, None)
                return False
            if refresh:
                row["last_active"] = runtime_clock.now()
            return True

    def grant(self, token: str) -> dict:
        digest = token_digest(token)
        self._store.require_current_epoch()
        with self._store.state.transaction() as state:
            self._store.current(state)
            row = state["sessions"].get(digest)
            current = credential_fingerprint(self._read_stored())
            valid = bool(digest and self._store.valid(row, current))
            grant = {"session": digest, "epoch": self._store.epoch, "credential": current}
        if not valid:
            raise PermissionError("authentication required")
        return grant

    def logout(self, token: str):
        digest = token_digest(token)
        if digest:
            with self._store.state.transaction(write=True) as state:
                self._store.current(state)
                state["sessions"].pop(digest, None)

    def get_session_info(self, token: str) -> dict:
        digest = token_digest(token)
        if not digest or not self.validate_grant(digest):
            return {}
        with self._store.state.transaction() as state:
            row = state["sessions"].get(digest)
            if not self._store.valid(row, credential_fingerprint(self._read_stored())):
                return {}
            now = runtime_clock.now()
            return {"active": True, "age_seconds": int(now - row["created"]),
                    "idle_seconds": int(now - row["last_active"]), "timeout": self._session_timeout,
                    "absolute_timeout": self._store.absolute,
                    "remaining_seconds": max(0, int(min(self._store.idle - now + row["last_active"],
                                                        self._store.absolute - now + row["created"])))}

    def cleanup_expired(self):
        with self._store.state.transaction(write=True) as state:
            self._store.current(state)
            self._prune(state, runtime_clock.now())

    def _verify_stored(self, passphrase: str) -> bool:
        try:
            return verify_passphrase(passphrase, self._read_stored())
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False

    def _read_stored(self) -> dict:
        directory = open_directory(self._data_dir)
        descriptor = None
        try:
            descriptor = os.open("auth.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_AUTH_FILE_BYTES
                    or stat.S_IMODE(info.st_mode) not in {0o600, 0o660}):
                raise ValueError("unsafe credential file")
            raw = os.read(descriptor, MAX_AUTH_FILE_BYTES + 1)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid credential schema")
        return value

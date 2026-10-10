"""Protected session metadata; bearer secrets never enter persistent state."""
from __future__ import annotations

import hashlib
import math
import re
import secrets
from pathlib import Path

from . import runtime_clock
from .bounded_state import BoundedState, StateUnavailable

DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_SESSIONS = 128
MAX_CLIENTS = 1024
MAX_STATE_BYTES = 1024 * 1024


def token_digest(token: str) -> str:
    if not isinstance(token, str) or not DIGEST.fullmatch(token):
        return ""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def credential_fingerprint(credentials: dict) -> str:
    # A legacy KDF upgrade deliberately changes this generation too.
    raw = str(credentials.get("salt", "")) + ":" + str(credentials.get("hash", ""))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def runtime_epoch(directory: Path) -> str:
    def valid(state):
        if not isinstance(state, dict) or set(state) != {"version", "epoch", "clock"} or type(state["version"]) is not int or state["version"] != 2 or state["clock"] != runtime_clock.DOMAIN or not DIGEST.fullmatch(str(state["epoch"])):
            raise ValueError("invalid session runtime epoch")
    store = BoundedState(directory / "epoch.json", lambda: {"version": 2, "clock": runtime_clock.DOMAIN, "epoch": secrets.token_hex(32)}, valid, max_bytes=256)
    # A create/read transaction prevents two simultaneous starts choosing epochs.
    with store.transaction(initialize=True) as value:
        return value["epoch"]


def validate_state(value):
    if not isinstance(value, dict) or set(value) != {"version", "clock", "epoch", "sessions", "clients"} or type(value["version"]) is not int or value["version"] != 2 or value["clock"] != runtime_clock.DOMAIN:
        raise ValueError("invalid session state schema")
    if not DIGEST.fullmatch(str(value["epoch"])):
        raise ValueError("invalid session epoch")
    for name, maximum in (("sessions", MAX_SESSIONS), ("clients", MAX_CLIENTS)):
        records = value[name]
        if not isinstance(records, dict) or len(records) > maximum:
            raise ValueError("invalid session state count")
        for key, record in records.items():
            if not isinstance(key, str) or not DIGEST.fullmatch(key) or not isinstance(record, dict):
                raise ValueError("invalid session record")
            expected = {"created", "last_active", "credential"} if name == "sessions" else {"failed_attempts", "last_failed", "lockout_until"}
            if set(record) != expected:
                raise ValueError("invalid session fields")
            for field, number in record.items():
                if field == "credential":
                    if not isinstance(number, str) or not DIGEST.fullmatch(number):
                        raise ValueError("invalid credential generation")
                elif isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
                    raise ValueError("invalid session timestamp")
            if name == "clients" and (not isinstance(record["failed_attempts"], int) or record["failed_attempts"] > 1000000):
                raise ValueError("invalid attempt counter")


class SessionStore:
    def __init__(self, directory: Path, runtime: Path, *, idle: float, absolute: float):
        self.directory = Path(directory)
        self.runtime = Path(runtime)
        self.idle = idle
        self.absolute = absolute
        self._epoch = None
        self.state = BoundedState(self.directory / "sessions.json", self._empty, validate_state,
                                  max_bytes=MAX_STATE_BYTES)

    @property
    def epoch(self):
        if self._epoch is None:
            self._epoch = runtime_epoch(self.runtime)
        return self._epoch

    def _empty(self):
        return {"version": 2, "clock": runtime_clock.DOMAIN, "epoch": self.epoch, "sessions": {}, "clients": {}}

    def current(self, state):
        if state["epoch"] != self.epoch:
            state.clear()
            state.update(self._empty())

    def valid(self, record, credential, *, now=None):
        now = runtime_clock.now() if now is None else now
        return (record is not None and record["credential"] == credential
                and 0 <= now - record["last_active"] <= self.idle
                and 0 <= now - record["created"] <= self.absolute)

    def snapshot(self):
        with self.state.transaction() as state:
            self.current(state)
            return state

    @property
    def healthy(self):
        return not self.state.failed

    def require_current_epoch(self):
        runtime_clock.now()  # Readiness cannot silently accept an unavailable clock.
        if runtime_epoch(self.runtime) != self.epoch:
            self.state.failed = True
            raise StateUnavailable("session runtime changed")

"""Durable bounded catalog queue. Records are operational state, not audit proof."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from pathlib import Path

from common import runtime_clock
from common.bounded_state import BoundedState, StateCapacity, StateRejected

CLOCK_DOMAIN = runtime_clock.DOMAIN
MAX_ACTIVE = 16
MAX_HISTORY = 256
MAX_JOBS = MAX_ACTIVE + MAX_HISTORY
MAX_RECORD_BYTES = 4096
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_ATTEMPTS = 3
MAX_DOWNLOAD_BYTES = 64 * 1024**3
MAX_JOB_SECONDS = 30 * 60
DIGEST = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[0-9a-f]{32}")
REVISION = re.compile(r"[0-9a-f]{40}")
ACTIVE = {"queued", "running", "verified", "publishing"}
PUBLISHED = {"publishing", "quarantined", "handoff_unknown"}
STATES = ACTIVE | {"quarantined", "handoff_unknown", "paused", "failed", "cancelled", "cleanup_required"}
ERRORS = {"", "authentication_required", "policy_changed", "catalog_changed", "transfer_failed",
          "interrupted", "deadline", "cancelled", "handoff_unknown", "storage_unavailable"}


class JobConflict(StateRejected):
    """A reviewed state change or reconciliation is required."""


def entry_digest(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _hex(value, pattern=DIGEST):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _name(value, maximum=200):
    return (isinstance(value, str) and value.isascii() and 1 <= len(value) <= maximum
            and value not in {".", ".."} and not any(c in value for c in "/\\\x00")
            and '"' not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def identity_pins(entry):
    pins = {"revision": entry.get("expected_revision", ""), "sha256": entry.get("expected_sha256", ""),
            "manifest_sha256": entry.get("expected_manifest_sha256", "")}
    if not valid_pins(pins):
        raise JobConflict("catalog immutable pins are unavailable")
    return pins


def valid_pins(value):
    return (isinstance(value, dict) and set(value) == {"revision", "sha256", "manifest_sha256"}
            and _hex(value["revision"], REVISION)
            and ((_hex(value["sha256"]) and value["manifest_sha256"] == "")
                 or (_hex(value["manifest_sha256"]) and value["sha256"] == "")))


def validate_state(value):
    if not isinstance(value, dict) or set(value) != {"version", "clock", "jobs"} or type(value["version"]) is not int or value["version"] != 2 or value["clock"] != CLOCK_DOMAIN:
        raise ValueError("invalid catalog queue schema")
    jobs = value["jobs"]
    if not isinstance(jobs, dict) or len(jobs) > MAX_JOBS:
        raise ValueError("invalid catalog queue count")
    for identifier, row in jobs.items():
        if not _hex(identifier, IDENTIFIER) or not isinstance(row, dict) or set(row) != {
            "filename", "catalog_digest", "pins", "grant", "profile", "status", "error", "attempt",
            "created", "updated", "started", "deadline", "size", "downloaded", "cancel", "owned",
        }:
            raise ValueError("invalid catalog job record")
        if not _name(row["filename"]) or not _hex(row["catalog_digest"]) or not valid_pins(row["pins"]):
            raise ValueError("invalid catalog identity")
        if row["status"] not in STATES or row["error"] not in ERRORS or type(row["cancel"]) is not bool:
            raise ValueError("invalid catalog status")
        if not _integer(row["attempt"], MAX_ATTEMPTS):
            raise ValueError("invalid catalog attempt")
        if not _integer(row["created"], 10**21):
            raise ValueError("invalid catalog creation sequence")
        for field in ("updated", "started", "deadline"):
            if not _integer(row[field], 10**12):
                raise ValueError("invalid catalog clock")
        if not _integer(row["size"], MAX_DOWNLOAD_BYTES) or row["size"] == 0 or not _integer(row["downloaded"], row["size"]):
            raise ValueError("invalid catalog size")
        grant = row["grant"]
        if not isinstance(grant, dict) or set(grant) != {"session", "epoch", "credential"} or not all(_hex(item) for item in grant.values()):
            raise ValueError("invalid catalog authorization")
        profile = row["profile"]
        if (not isinstance(profile, dict) or set(profile) != {"profile", "mode", "generation", "session"}
                or profile["profile"] not in {"research", "full_lab"} or profile["mode"] not in {"appliance", "sandbox"}
                or any(item != "" and not _hex(item) for item in (profile["generation"], profile["session"]))):
            raise ValueError("invalid catalog policy binding")
        if not isinstance(row["owned"], dict) or len(row["owned"]) > 6:
            raise ValueError("invalid partial inventory")
        for name, identity in row["owned"].items():
            if (not _name(name, 255) or not name.startswith(".") or not isinstance(identity, list)
                    or len(identity) != 3 or not all(_integer(n, 2**64 - 1) for n in identity[:2])
                    or identity[2] not in {"file", "directory"}):
                raise ValueError("invalid partial identity")
        if len(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()) > MAX_RECORD_BYTES:
            raise ValueError("catalog record exceeds reserved size")


class CatalogJobs:
    def __init__(self, directory: Path):
        self.state = BoundedState(Path(directory) / "jobs.json", lambda: {"version": 2, "clock": CLOCK_DOMAIN, "jobs": {}},
                                  validate_state, max_bytes=MAX_STATE_BYTES)

    def snapshot(self):
        with self.state.transaction() as value:
            return value["jobs"]

    def admit(self, entry, grant, profile, *, free_bytes: int, reserve_bytes: int):
        name = entry.get("filename")
        size = entry.get("expected_size_bytes")
        if not _name(name) or not _integer(size, MAX_DOWNLOAD_BYTES) or not size:
            raise JobConflict("catalog entry is not eligible")
        pins = identity_pins(entry)
        with self.state.transaction(write=True) as value:
            jobs = value["jobs"]
            for identifier, row in jobs.items():
                if row["filename"] == name:
                    if row["status"] in ACTIVE and row["catalog_digest"] == entry_digest(entry):
                        return identifier
                    raise JobConflict("existing job requires retry or reconciliation")
            active = [row for row in jobs.values() if row["status"] in ACTIVE]
            # Reserve a worst-case final record for every admitted job. No history
            # deletion or safety transition depends on free admission capacity.
            if len(jobs) >= MAX_HISTORY or len(active) >= MAX_ACTIVE:
                raise StateCapacity("catalog queue requires reviewed maintenance")
            if (len(jobs) + 1) * (MAX_RECORD_BYTES + 64) + 64 > self.state.max_bytes:
                raise StateCapacity("catalog byte capacity requires maintenance")
            if size + sum(row["size"] for row in active) + reserve_bytes > free_bytes:
                raise StateCapacity("insufficient reserved quarantine capacity")
            identifier = secrets.token_hex(16)
            now = int(time.time())
            jobs[identifier] = {"filename": name, "catalog_digest": entry_digest(entry), "pins": pins, "grant": dict(grant),
                                "profile": dict(profile), "status": "queued", "error": "", "attempt": 0,
                                "created": max(time.time_ns(), max((row["created"] for row in jobs.values()), default=0) + 1),
                                "updated": now, "started": 0, "deadline": 0,
                                "size": size, "downloaded": 0, "cancel": False, "owned": {}}
        return identifier

    def update(self, identifier, *, statuses=None, **changes):
        with self.state.transaction(write=True) as value:
            row = value["jobs"].get(identifier)
            if row is None or (statuses is not None and row["status"] not in statuses):
                raise JobConflict("catalog job changed")
            row.update(changes)
            row["updated"] = int(time.time())
            return dict(row)

    def claim(self):
        with self.state.transaction(write=True) as value:
            if any(row["status"] in {"running", "verified", "publishing"} for row in value["jobs"].values()):
                return None
            for identifier, row in sorted(value["jobs"].items(), key=lambda item: (item[1]["created"], item[0])):
                if row["status"] == "queued":
                    row.update(status="running", attempt=row["attempt"] + 1, started=int(runtime_clock.now()),
                               deadline=int(runtime_clock.now()) + MAX_JOB_SECONDS, error="", updated=int(time.time()))
                    return identifier
        return None

    def cancel(self, identifier):
        with self.state.transaction(write=True) as value:
            row = value["jobs"].get(identifier)
            if row is None:
                raise JobConflict("unknown catalog job")
            if row["status"] == "queued":
                row.update(status="cancelled", error="cancelled", cancel=True)
            elif row["status"] in ACTIVE:
                row["cancel"] = True
            # Published and terminal states stay explicit and idempotent.
            row["updated"] = int(time.time())

    def retry(self, identifier, entry, grant, profile, *, free_bytes, reserve_bytes):
        with self.state.transaction(write=True) as value:
            jobs = value["jobs"]
            row = jobs.get(identifier)
            if (row is None or row["status"] not in {"paused", "failed", "cancelled"} or row["owned"]
                    or row["attempt"] != 0 or row["catalog_digest"] != entry_digest(entry)):
                raise JobConflict("started attempts require separately qualified maintenance; retry is unavailable")
            active = [other for other in jobs.values() if other["status"] in ACTIVE]
            if len(active) >= MAX_ACTIVE or row["size"] + sum(other["size"] for other in active) + reserve_bytes > free_bytes:
                raise StateCapacity("catalog retry admission unavailable")
            row.update(status="queued", error="", cancel=False, downloaded=0, grant=dict(grant), profile=dict(profile),
                       updated=int(time.time()), started=0, deadline=0)

    def public(self):
        return {row["filename"]: {"job_id": identifier, "status": row["status"], "error": row["error"],
                                   "progress": round(100 * row["downloaded"] / row["size"], 1),
                                   "attempt": row["attempt"], "updated_at": row["updated"],
                                   "cleanup_required": row["status"] in {"paused", "failed", "cancelled", "cleanup_required"}
                                   and (row["status"] == "cleanup_required" or row["attempt"] > 0 or bool(row["owned"])),
                                   "retry_available": row["status"] in {"paused", "failed", "cancelled"}
                                   and not row["owned"] and row["attempt"] == 0}
                for identifier, row in self.snapshot().items()}


def sanitized_history(snapshot):
    """Export-only format; caller must first stop and reap all queue processes.

    This pure transformation neither proves quiescence nor restores authority.
    Its output is deliberately incompatible with the live queue loader.
    """
    validate_state(snapshot)
    rows = {}
    for identifier, row in snapshot["jobs"].items():
        result = {key: row[key] for key in ("filename", "catalog_digest", "pins", "size", "downloaded",
                                          "created", "updated", "attempt", "status", "error")}
        result["pins"] = dict(row["pins"])
        result["requires_reconciliation"] = row["status"] in ACTIVE | PUBLISHED | {"cleanup_required"} or bool(row["owned"])
        if row["status"] in PUBLISHED:
            result.update(status="handoff_unknown", error="handoff_unknown")
        elif row["status"] in ACTIVE:
            result.update(status="interrupted", error="interrupted")
        rows[identifier] = result
    return {"version": 1, "kind": "catalog-history", "jobs": rows}

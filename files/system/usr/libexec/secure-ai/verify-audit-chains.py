#!/usr/bin/env python3
"""Verify explicitly enrolled Secure AI audit-log formats.

Not every service historically emitted the same format. This verifier never
pretends a plain JSONL stream is hash-chained: the root-owned manifest assigns
each filename a verifier and a truthful security class.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SERVICES_DIR = os.getenv("SERVICES_DIR", "/usr/libexec/secure-ai/services")
sys.path.insert(0, SERVICES_DIR)
for _parent in Path(__file__).resolve().parents:
    _candidate = _parent / "services" / "common" / "audit_chain.py"
    if _candidate.is_file():
        sys.path.insert(0, str(_parent / "services"))
        break

from common.audit_chain import AuditChain  # noqa: E402

logging.basicConfig(level=logging.INFO, format="[audit-verify] %(message)s")
log = logging.getLogger("audit-verify")

LOGS_DIR = Path(os.getenv("AUDIT_LOGS_DIR", "/var/lib/secure-ai/logs"))
RESULT_FILE = LOGS_DIR / "audit-verify-last.json"
STATE_DIR = Path(os.getenv("AUDIT_VERIFIER_STATE_DIR", "/var/lib/secure-ai/audit-verifier"))
STATE_FILE = STATE_DIR / "enrollment.json"
MAX_LOG_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
MANIFEST_PATH = Path(os.getenv(
    "AUDIT_FORMAT_MANIFEST",
    "/etc/secure-ai/config/audit-log-formats.json",
))
KEY_DIR = Path(os.getenv("AUDIT_HMAC_KEY_DIR", "/run/credentials"))
MAX_LINE_BYTES = 1024 * 1024
MCP_VERIFY_BIN = os.getenv(
    "MCP_AUDIT_VERIFY_BIN",
    "/usr/libexec/secure-ai/mcp-firewall",
)
SUPPORTED_FORMATS = {
    "python-hmac-chain",
    "mcp-sha256-chain",
    "structured-jsonl",
}


def _safe_basename(value: object, field: str) -> str:
    name = value if isinstance(value, str) else ""
    if (
        not name
        or name != os.path.basename(name)
        or name in {".", ".."}
        or "\x00" in name
    ):
        raise ValueError(f"{field} must be a basename")
    return name


def load_manifest() -> list[dict[str, object]]:
    data = _read_regular(MANIFEST_PATH, MAX_STATE_BYTES, trusted=True)
    if len(data) > 1024 * 1024:
        raise ValueError("audit format manifest exceeds size limit")
    payload = json.loads(data)
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] not in {1, 2}:
        raise ValueError("audit format manifest must have version 1 or 2")
    entries = payload.get("logs")
    if not isinstance(entries, list) or not entries:
        raise ValueError("audit format manifest has no log entries")
    enrolled: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError("audit manifest entry must be an object")
        filename = _safe_basename(raw.get("file"), "file")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.jsonl", filename):
            raise ValueError("audit filename must be a literal JSONL basename")
        if filename in seen:
            raise ValueError(f"duplicate audit manifest entry: {filename}")
        seen.add(filename)
        log_format = str(raw.get("format", ""))
        if log_format not in SUPPORTED_FORMATS:
            raise ValueError(f"unsupported audit format for {filename}: {log_format}")
        key_file = raw.get("key_file")
        if log_format == "python-hmac-chain":
            _safe_basename(key_file, "key_file")
        elif key_file:
            raise ValueError(f"{filename} specifies an unused key")
        security_class = raw.get("security_class")
        expected_class = {
            "python-hmac-chain": "keyed-tamper-evident",
            "mcp-sha256-chain": "unkeyed-hash-linked",
            "structured-jsonl": "structured-only",
        }[log_format]
        if security_class != expected_class:
            raise ValueError(f"incorrect security class for {filename}")
        if "required" in raw and not isinstance(raw["required"], bool):
            raise ValueError("required must be a boolean")
        services = raw.get("services", [])
        if not isinstance(services, list) or any(
            not isinstance(unit, str)
            or not re.fullmatch(r"secure-ai-[a-z0-9-]+\.service", unit)
            for unit in services
        ) or len(set(services)) != len(services):
            raise ValueError("services must contain unique Secure AI unit names")
        if payload["version"] == 2 and "services" not in raw:
            raise ValueError("version 2 requires explicit services (empty for event-only logs)")
        enrolled.append({
            "file": filename,
            "format": log_format,
            "key_file": key_file,
            "required": raw.get("required") is True,
            "security_class": security_class,
            "services": services,
        })
    return enrolled


def _structured_jsonl(path: Path) -> dict[str, object]:
    count = 0
    try:
        with path.open("rb") as handle:
            for line_number, raw in enumerate(iter(lambda: handle.readline(MAX_LINE_BYTES + 1), b""), start=1):
                if len(raw) > MAX_LINE_BYTES:
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "JSONL line exceeds size limit",
                    }
                if not raw.endswith(b"\n"):
                    return {"valid": False, "entries": count, "broken_at": line_number,
                            "detail": "incomplete JSONL tail"}
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "invalid JSON",
                    }
                if not isinstance(value, dict):
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "JSONL entry is not an object",
                    }
                count += 1
    except OSError as exc:
        return {
            "valid": False,
            "entries": count,
            "broken_at": None,
            "detail": f"read error: {exc}",
        }
    return {
        "valid": True,
        "entries": count,
        "broken_at": None,
        "detail": "structured JSONL syntax valid; no tamper-evidence claim",
    }


def _mcp_hash(entry: dict[str, object]) -> str:
    canonical = {
        "sequence": entry.get("sequence"),
        "timestamp": entry.get("timestamp"),
        "prev_hash": entry.get("prev_hash"),
        "event": entry.get("event"),
        "decision": entry.get("decision"),
        "request": entry.get("request"),
        "detail": entry.get("detail"),
    }
    # Go encoding/json sorts string map keys and emits compact JSON.
    data = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _mcp_sha256_chain(path: Path) -> dict[str, object]:
    count = 0
    previous = "genesis"
    try:
        with path.open("rb") as handle:
            for line_number, raw in enumerate(iter(lambda: handle.readline(MAX_LINE_BYTES + 1), b""), start=1):
                if len(raw) > MAX_LINE_BYTES:
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "line exceeds size limit",
                    }
                if not raw.endswith(b"\n"):
                    return {"valid": False, "entries": count, "broken_at": line_number,
                            "detail": "incomplete JSONL tail"}
                if not raw.strip():
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "invalid JSON",
                    }
                if (
                    not isinstance(entry, dict)
                    or entry.get("sequence") != count + 1
                    or entry.get("prev_hash") != previous
                ):
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number,
                        "detail": "sequence or chain linkage mismatch",
                    }
                expected = _mcp_hash(entry)
                stored = str(entry.get("hash", ""))
                if not hmac.compare_digest(stored, expected):
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "entry hash mismatch",
                    }
                previous = stored
                count += 1
    except OSError as exc:
        return {
            "valid": False, "entries": count,
            "broken_at": None, "detail": f"read error: {exc}",
        }
    return {
        "valid": True, "entries": count, "broken_at": None,
        "detail": "unkeyed SHA-256 linkage valid; privileged writers can forge entries",
    }


def _read_regular(path: Path, limit: int, *, trusted: bool = False) -> bytes:
    with _open_regular(path, trusted=trusted) as handle:
        data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"{path.name} exceeds size limit")
        return data


def _check_parents(path: Path) -> None:
    for parent in path.absolute().parents:
        if parent.is_symlink():
            raise ValueError("symlinked evidence directory")


def _open_regular(path: Path, *, trusted: bool = False, write: bool = False):
    _check_parents(path)
    flags = (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"{path.name} must be a single-link regular file")
        if trusted and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022):
            raise ValueError(f"{path.name} has unsafe owner or permissions")
        return os.fdopen(descriptor, "r+b" if write else "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _service_states(manifest: list[dict[str, object]]) -> dict[str, str]:
    states = {}
    for unit in sorted({unit for entry in manifest for unit in entry["services"]}):
        try:
            completed = subprocess.run(
                ["/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState,ActiveState", unit],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=5, check=False,
            )
            fields = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
            active = fields.get("ActiveState")
            loaded = fields.get("LoadState")
            if completed.returncode != 0 or loaded not in {"loaded", "not-found", "masked"}:
                raise ValueError("service state unavailable")
            if active not in {"active", "activating", "reloading", "deactivating", "inactive", "failed"}:
                raise ValueError("service state unknown")
            states[unit] = active
        except (OSError, ValueError, subprocess.SubprocessError):
            states[unit] = "unknown"
    return states


def _evidence_paths(path: Path, log_format: str) -> list[Path]:
    paths = [path]
    if log_format == "python-hmac-chain":
        paths.extend(sorted(path.parent.glob(f"{path.stem}.*{path.suffix}")))
        checkpoint = path.with_suffix(path.suffix + ".checkpoint")
        if os.path.lexists(checkpoint):
            paths.append(checkpoint)
    if len(paths) > 128:
        raise ValueError("too many audit archives")
    return paths


class SnapshotChanged(ValueError):
    """A concurrent append prevented a stable verification snapshot."""


def _copy_evidence(path: Path, target: Path, previous: dict | None) -> dict:
    with _open_regular(path) as source, target.open("xb") as destination:
        before = os.fstat(source.fileno())
        if before.st_size > MAX_LOG_BYTES:
            raise ValueError("audit evidence exceeds size limit")
        if previous and (previous["device"], previous["inode"]) != (before.st_dev, before.st_ino):
            raise ValueError("enrolled audit file was replaced; rotation requires reviewed reconciliation")
        if previous and before.st_size < previous["size"]:
            raise ValueError("enrolled audit file was truncated")
        digest = hashlib.sha256()
        prefix = hashlib.sha256()
        copied = 0
        while chunk := source.read(min(1024 * 1024, before.st_size - copied + 1)):
            if copied + len(chunk) > before.st_size:
                raise SnapshotChanged("audit file changed while being copied; retry verification")
            if previous:
                prefix.update(chunk[:max(0, previous["size"] - copied)])
            digest.update(chunk)
            destination.write(chunk)
            copied += len(chunk)
        after = os.fstat(source.fileno())
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("audit file was replaced while being copied")
        if after.st_size > before.st_size or current.st_size > before.st_size:
            raise SnapshotChanged("audit append overlapped snapshot; retry verification")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or copied != before.st_size:
            raise ValueError("audit file was rewritten or truncated while being copied")
        if previous and not hmac.compare_digest(prefix.hexdigest(), previous["sha256"]):
            raise ValueError("enrolled audit prefix changed")
        return {"device": before.st_dev, "inode": before.st_ino,
                "size": copied, "sha256": digest.hexdigest(),
                "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns}


def _verify_snapshot(entry: dict[str, object], directory: Path) -> dict[str, object]:
    path = directory / str(entry["file"])
    log_format = entry["format"]
    if log_format == "python-hmac-chain":
        key_path = KEY_DIR / str(entry["key_file"])
        key = _read_regular(key_path, 4096, trusted=True)
        if stat.S_IMODE(key_path.lstat().st_mode) not in {0o400, 0o600}:
            raise ValueError("audit key must have mode 0400 or 0600")
        local_key = directory / ".verification-key"
        local_key.write_bytes(key)
        local_key.chmod(0o600)
        for record_path in _evidence_paths(path, str(log_format)):
            if record_path.suffix != ".jsonl":
                continue
            syntax = _structured_jsonl(record_path)
            if not syntax["valid"]:
                return syntax
            with record_path.open("rb") as handle:
                for raw in handle:
                    if raw.strip() and json.loads(raw).get("algorithm") != "hmac-sha256":
                        raise ValueError("keyed log contains an unauthenticated record")
        # AuditChain's legacy empty-chain success does not authenticate its key.
        from common.audit_chain import _load_key
        if _load_key(str(local_key)) is None:
            raise ValueError("audit HMAC key unavailable")
        result = AuditChain.verify(str(path), key_path=str(local_key))
        if not result["entries"] and path.with_suffix(path.suffix + ".checkpoint").exists():
            raise ValueError("checkpoint exists but audit chain is empty")
        return result
    if log_format == "mcp-sha256-chain":
        syntax = _structured_jsonl(path)
        if not syntax["valid"]:
            return syntax
        try:
            completed = subprocess.run(
                [MCP_VERIFY_BIN, "audit", "-log", str(path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30, check=False,
            )
            return {"valid": completed.returncode == 0, "entries": syntax["entries"],
                    "broken_at": None, "detail": completed.stdout.strip()[:1024]}
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("MCP audit verifier unavailable") from exc
    return _structured_jsonl(path)


def verify_entry(entry: dict[str, object], enrolled: dict | None = None,
                 service_states: dict[str, str] | None = None) -> dict[str, object]:
    enrolled = enrolled if enrolled is not None else {"required": False, "files": {}}
    states = service_states if service_states is not None else _service_states([entry])
    path = LOGS_DIR / str(entry["file"])
    try:
        paths = _evidence_paths(path, str(entry["format"]))
        activity = [states.get(unit, "unknown") for unit in entry.get("services", [])]
        present = os.path.lexists(path)
        enrolled["required"] = bool(enrolled["required"] or entry["required"] or present
                                    or len(paths) > 1 or any(state not in {"inactive", "unknown"} for state in activity))
        if not present:
            if enrolled["required"] or enrolled["files"]:
                raise ValueError("required or previously enrolled audit log is missing")
            if "unknown" in activity:
                raise ValueError("service activity unavailable; absence cannot be marked not applicable")
            return {"valid": True, "entries": 0, "broken_at": None, "status": "not_applicable",
                    "detail": "no observed enrollment or active service; applicability before enrollment and between polls is unknown"}
        if "unknown" in activity:
            raise ValueError("service activity unavailable")
        old_files = enrolled["files"]
        if set(old_files) - {item.name for item in paths}:
            raise ValueError("previously enrolled audit evidence is missing")
        with tempfile.TemporaryDirectory(prefix="verify-", dir=STATE_DIR) as temp:
            directory = Path(temp)
            fingerprints = {}
            total = 0
            for source in paths:
                # Writer checkpoints are replaced on every append. They remain verified by
                # their HMAC; the independent ledger pins the actual log bytes instead.
                previous = old_files.get(source.name) if source.suffix != ".checkpoint" else None
                metadata = _copy_evidence(source, directory / source.name, previous)
                total += metadata["size"]
                if total > MAX_SNAPSHOT_BYTES:
                    raise ValueError("audit snapshot exceeds total size limit")
                if source.suffix != ".checkpoint":
                    fingerprints[source.name] = metadata
            result = _verify_snapshot(entry, directory)
            # A writer may append during format verification. Replacement or deletion
            # must still fail even when the open snapshot itself verifies successfully.
            for source in paths:
                if source.suffix != ".checkpoint":
                    current = source.lstat()
                    saved = fingerprints[source.name]
                    if (current.st_dev, current.st_ino) != (saved["device"], saved["inode"]):
                        raise ValueError("audit evidence changed during verification: replacement")
                    if current.st_size > saved["size"]:
                        raise SnapshotChanged("audit append overlapped verification; retry verification")
                    if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                        saved["size"], saved["mtime_ns"], saved["ctime_ns"]
                    ):
                        raise ValueError("audit evidence changed during verification: rewrite or truncation")
            if result["valid"]:
                enrolled["files"] = fingerprints
            return result
    except SnapshotChanged as exc:
        return {"valid": False, "entries": 0, "broken_at": None, "status": "unavailable",
                "retryable": True, "detail": str(exc)}
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as exc:
        return {"valid": False, "entries": 0, "broken_at": None, "status": "broken", "detail": str(exc)}


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_state(state: dict) -> None:
    data = _json_bytes(state)
    if len(data) > MAX_STATE_BYTES:
        raise ValueError("enrollment state exceeds size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=".enrollment-", dir=STATE_DIR)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
        _sync_directory(STATE_DIR)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _publish_result(result: dict) -> bytes:
    data = _json_bytes(result)
    # The unit grants write access only to this fixed inode, never the logs
    # directory. Partial writes are invalid JSON, and cannot assert readiness.
    with _open_regular(RESULT_FILE, trusted=True, write=True) as handle:
        metadata = os.fstat(handle.fileno())
        if stat.S_IMODE(metadata.st_mode) != 0o640 or metadata.st_gid != LOGS_DIR.stat().st_gid:
            raise ValueError("public verifier result must be mode 0640 in the logs group")
        handle.seek(0)
        handle.truncate()
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return data


def _load_state() -> dict:
    state = json.loads(_read_regular(STATE_FILE, MAX_STATE_BYTES, trusted=True))
    if not isinstance(state, dict) or type(state.get("version")) is not int or state["version"] != 1 or not isinstance(state.get("logs"), dict):
        raise ValueError("invalid enrollment state")
    if not isinstance(state.get("evidence_lost"), bool):
        raise ValueError("invalid evidence status")
    for name, record in state["logs"].items():
        _safe_basename(name, "state log")
        if not isinstance(record, dict) or not isinstance(record.get("required"), bool) or not isinstance(record.get("files"), dict):
            raise ValueError("invalid enrolled log state")
        for filename, saved in record["files"].items():
            _safe_basename(filename, "state evidence")
            if not isinstance(saved, dict) or any(type(saved.get(key)) is not int or saved[key] < 0 for key in ("device", "inode", "size")):
                raise ValueError("invalid evidence fingerprint")
            if not isinstance(saved.get("sha256"), str) or not re.fullmatch("[a-f0-9]{64}", saved["sha256"]):
                raise ValueError("invalid evidence digest")
    for field in ("manifest_sha256", "result_sha256"):
        if not isinstance(state.get(field), str) or not re.fullmatch("[a-f0-9]{64}", state[field]):
            raise ValueError("invalid enrollment digest")
    return state


def _manifest_digest(manifest: list[dict[str, object]]) -> str:
    return hashlib.sha256(_json_bytes({"logs": manifest})).hexdigest()


def _check_state_directory() -> None:
    _check_parents(STATE_DIR)
    metadata = STATE_DIR.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("enrollment directory must be verifier-owned mode 0700")


def _run_locked(initialize: bool) -> int:
    manifest = load_manifest()
    if initialize:
        if any(path.name != "verifier.lock" for path in STATE_DIR.iterdir()):
            raise ValueError("initialization requires an empty state directory; never reset existing enrollment")
        if not os.path.lexists(RESULT_FILE):
            descriptor = os.open(RESULT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            os.fchmod(descriptor, 0o640)
            os.close(descriptor)
            _sync_directory(LOGS_DIR)
        else:
            # Preserve prior public verification evidence during an explicit upgrade.
            previous = _read_regular(RESULT_FILE, MAX_STATE_BYTES, trusted=True)
            backup = STATE_DIR / "pre-enrollment-result.json"
            with backup.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(previous)
                handle.flush()
                os.fsync(handle.fileno())
        with _open_regular(RESULT_FILE, trusted=True, write=True) as handle:
            os.fchmod(handle.fileno(), 0o640)
            if os.fstat(handle.fileno()).st_gid != LOGS_DIR.stat().st_gid:
                raise ValueError("historical result needs reviewed administrator group ownership correction")
            os.fsync(handle.fileno())
        state = {"version": 1, "manifest_sha256": _manifest_digest(manifest),
                 "logs": {}, "evidence_lost": False, "result_sha256": "0" * 64}
    else:
        state = _load_state()  # Never infer a fresh installation from missing state.
        if state["manifest_sha256"] != _manifest_digest(manifest):
            raise ValueError("manifest changed; preserve enrollment and perform reviewed offline reconciliation")
        try:
            previous = _read_regular(RESULT_FILE, MAX_STATE_BYTES, trusted=True)
            if hashlib.sha256(previous).hexdigest() != state["result_sha256"]:
                state["evidence_lost"] = True
        except (OSError, ValueError):
            state["evidence_lost"] = True
        # Persist evidence-loss before publishing any replacement report.
        if state["evidence_lost"]:
            _write_state(state)
    _publish_result({"status": "checking", "ready": False, "checked_at": datetime.now(timezone.utc).isoformat()})
    details = []
    service_states = _service_states(manifest)
    for entry in manifest:
        record = state["logs"].setdefault(str(entry["file"]), {"required": False, "files": {}})
        result = verify_entry(entry, record, service_states)
        valid = result.get("valid") is True
        details.append({"file": entry["file"], "format": entry["format"],
                        "security_class": entry["security_class"],
                        "status": result.pop("status", "ok" if valid else "broken"), **result})
    known = {str(entry["file"]) for entry in manifest}
    candidates = {path.name for pattern in ("*-audit.jsonl", "audit.jsonl") for path in LOGS_DIR.glob(pattern)}
    for filename in sorted(candidates - known):
        details.append({"file": filename, "status": "unmanaged", "valid": False,
                        "security_class": "unverified", "detail": "audit log is absent from the format manifest"})
    if state["evidence_lost"]:
        details.append({"file": RESULT_FILE.name, "status": "broken", "valid": False,
                        "detail": "previous verifier evidence missing or changed; offline reconciliation required"})
    failures = sum(item.get("valid") is not True for item in details)
    result = {"status": "failed" if failures else "ok", "ready": failures == 0,
              "logs_checked": len(manifest), "failures": failures, "details": details,
              "service_states": service_states, "checked_at": datetime.now(timezone.utc).isoformat()}
    state["result_sha256"] = hashlib.sha256(_json_bytes(result)).hexdigest()
    # A crash between these durable writes produces a mismatch on restart and
    # degrades readiness; it never silently rolls back the enrollment ledger.
    _write_state(state)
    _publish_result(result)
    return int(bool(failures))


def main(*, initialize: bool = False) -> int:
    try:
        if initialize:
            STATE_DIR.mkdir(mode=0o700, parents=False, exist_ok=True)
        _check_state_directory()
        lock_path = STATE_DIR / "verifier.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1 or lock_stat.st_uid != os.geteuid() or stat.S_IMODE(lock_stat.st_mode) != 0o600:
                raise ValueError("unsafe verifier lock")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                log.critical("another verification holds the private lock")
                return 1
            if initialize and STATE_FILE.exists():
                log.critical("already enrolled; initialization cannot reset state")
                return 1
            return _run_locked(initialize)
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        log.critical("verification unavailable: %s", exc)
        try:
            _publish_result({"status": "failed", "ready": False, "failures": 1,
                             "details": [{"status": "broken", "valid": False, "detail": str(exc)}],
                             "checked_at": datetime.now(timezone.utc).isoformat()})
        except (OSError, ValueError):
            log.critical("unable to publish failed verification status")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initialize", action="store_true", help="explicitly enroll existing evidence; requires empty private state")
    raise SystemExit(main(initialize=parser.parse_args().initialize))

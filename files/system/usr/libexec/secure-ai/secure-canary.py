#!/usr/bin/env python3
"""Authenticated placement and verification for SecAI OS canary files."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FORMAT_VERSION = 2
MAX_CANARIES = 32
MAX_CANARY_BYTES = 4096
MAX_DATABASE_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CanaryError(RuntimeError):
    """Canary state is unsafe, unauthenticated, or inconsistent."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_regular(path: Path, *, required: bool, private: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise CanaryError(f"required file is missing: {path}")
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CanaryError(f"file must be regular and not a symbolic link: {path}")
    if os.geteuid() == 0 and metadata.st_uid != 0:
        raise CanaryError(f"file must be owned by root: {path}")
    if metadata.st_mode & 0o022:
        raise CanaryError(f"file must not be writable by group or other users: {path}")
    if private and metadata.st_mode & 0o077:
        raise CanaryError(f"private file must be mode 0600 or stricter: {path}")
    return True


def _read_file_no_follow(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CanaryError(f"path is not a regular file: {path}")
        if metadata.st_size <= 0 or metadata.st_size > maximum:
            raise CanaryError(f"file has an invalid size: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size or len(data) > maximum:
            raise CanaryError(f"file changed while being read: {path}")
        return data, metadata
    finally:
        os.close(descriptor)


def _load_key(path: Path) -> bytes:
    _safe_regular(path, required=True, private=True)
    key, _metadata = _read_file_no_follow(path, 4096)
    key = key.strip()
    if len(key) < 32:
        raise CanaryError("canary HMAC key must contain at least 32 bytes")
    return key


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign(unsigned: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanaryError(f"duplicate database key: {key}")
        result[key] = value
    return result


def _validate_location(path: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > 4096
        or "\x00" in path
        or "\n" in path
        or "\r" in path
    ):
        raise CanaryError(f"invalid canary path: {path!r}")
    normalized = os.path.normpath(path)
    if normalized != path or Path(path).name != ".canary":
        raise CanaryError(f"non-canonical canary path: {path!r}")
    return path


def _validate_unsigned(unsigned: object) -> dict[str, Any]:
    if not isinstance(unsigned, dict):
        raise CanaryError("canary database payload must be an object")
    required = {
        "format",
        "format_version",
        "created_at",
        "canaries",
        "pending_locations",
    }
    if set(unsigned) != required:
        raise CanaryError("canary database payload has an unexpected schema")
    if unsigned["format"] != "secai-canary" or unsigned["format_version"] != FORMAT_VERSION:
        raise CanaryError("unsupported canary database format")
    if not isinstance(unsigned["created_at"], str) or len(unsigned["created_at"]) > 128:
        raise CanaryError("invalid canary database creation time")
    records = unsigned["canaries"]
    pending = unsigned["pending_locations"]
    if not isinstance(records, list) or len(records) > MAX_CANARIES:
        raise CanaryError("canary record list is invalid")
    if not isinstance(pending, list) or len(pending) > MAX_CANARIES:
        raise CanaryError("pending canary list is invalid")

    seen: set[str] = set()
    for record in records:
        fields = {"path", "sha256", "size", "mode", "uid", "gid", "created_at"}
        if not isinstance(record, dict) or set(record) != fields:
            raise CanaryError("canary record has an unexpected schema")
        path = _validate_location(record["path"])
        if path in seen:
            raise CanaryError(f"duplicate canary record: {path}")
        seen.add(path)
        if not isinstance(record["sha256"], str) or not SHA256_RE.fullmatch(
            record["sha256"]
        ):
            raise CanaryError(f"invalid canary digest: {path}")
        if (
            isinstance(record["size"], bool)
            or not isinstance(record["size"], int)
            or not 0 < record["size"] <= MAX_CANARY_BYTES
        ):
            raise CanaryError(f"invalid canary size: {path}")
        for field in ("mode", "uid", "gid"):
            if isinstance(record[field], bool) or not isinstance(record[field], int):
                raise CanaryError(f"invalid canary metadata field {field}: {path}")
        expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
        expected_gid = 0 if os.geteuid() == 0 else os.getegid()
        if (
            record["mode"] != 0o400
            or record["uid"] != expected_uid
            or record["gid"] != expected_gid
        ):
            raise CanaryError(f"canary DAC metadata is not root-only: {path}")
        if not isinstance(record["created_at"], str):
            raise CanaryError(f"invalid canary creation time: {path}")

    pending_seen: set[str] = set()
    for raw_path in pending:
        path = _validate_location(raw_path)
        if path in seen or path in pending_seen:
            raise CanaryError(f"duplicate pending canary location: {path}")
        pending_seen.add(path)
    return unsigned


def load_database(path: Path, key: bytes) -> dict[str, Any]:
    _safe_regular(path, required=True, private=True)
    raw, _metadata = _read_file_no_follow(path, MAX_DATABASE_BYTES)
    try:
        database = json.loads(
            raw,
            object_pairs_hook=_unique_json,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CanaryError(f"non-finite JSON value: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryError(f"invalid canary database JSON: {exc}") from exc
    if not isinstance(database, dict) or set(database) != {"payload", "signature"}:
        raise CanaryError("canary database envelope has an unexpected schema")
    unsigned = _validate_unsigned(database["payload"])
    signature = database["signature"]
    if not isinstance(signature, str) or not SHA256_RE.fullmatch(signature):
        raise CanaryError("canary database signature is invalid")
    expected = _sign(unsigned, key)
    if not hmac.compare_digest(signature, expected):
        raise CanaryError("canary database HMAC verification failed")
    return unsigned


def _atomic_database(path: Path, unsigned: dict[str, Any], key: bytes) -> None:
    _validate_unsigned(unsigned)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise CanaryError(f"database parent is unsafe: {path.parent}")
    if path.exists() or path.is_symlink():
        _safe_regular(path, required=True, private=True)
    envelope = {"payload": unsigned, "signature": _sign(unsigned, key)}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o600)
            if os.geteuid() == 0:
                os.fchown(handle.fileno(), 0, 0)
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _verify_record(record: dict[str, Any]) -> str | None:
    path = Path(record["path"])
    try:
        _safe_regular(path, required=True, private=True)
        content, metadata = _read_file_no_follow(path, MAX_CANARY_BYTES)
    except (CanaryError, OSError) as exc:
        return str(exc)
    actual = {
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    for field, value in actual.items():
        if value != record[field]:
            return f"{path}: {field} mismatch"
    return None


def check_canaries(database_path: Path, key_path: Path) -> dict[str, Any]:
    key = _load_key(key_path)
    try:
        unsigned = load_database(database_path, key)
    except (CanaryError, OSError) as exc:
        reason = f"canary database validation failed: {exc}"
        return {
            "status": "violation",
            "violations": [{"path": str(database_path), "reason": reason}],
            "pending_locations": [],
            "fingerprint": hashlib.sha256(reason.encode()).hexdigest(),
        }

    violations: list[dict[str, str]] = []
    for record in unsigned["canaries"]:
        reason = _verify_record(record)
        if reason:
            violations.append({"path": record["path"], "reason": reason})
    fingerprint = hashlib.sha256(_canonical(violations)).hexdigest()
    status = "violation" if violations else (
        "pending" if unsigned["pending_locations"] else "ok"
    )
    return {
        "status": status,
        "violations": violations,
        "pending_locations": unsigned["pending_locations"],
        "fingerprint": fingerprint,
    }


def _safe_parent(path: Path) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CanaryError(f"canary parent is not a real directory: {parent}")
    if os.geteuid() == 0 and metadata.st_uid != 0:
        raise CanaryError(f"canary parent must be owned by root: {parent}")


def _create_canary(path: Path) -> dict[str, Any]:
    _safe_parent(path)
    if path.exists() or path.is_symlink():
        raise CanaryError(f"refusing to bless an existing untracked canary: {path}")
    created_at = _now()
    content = (
        "# SecAI OS authenticated canary - do not modify\n"
        f"token={secrets.token_hex(32)}\n"
        f"created_at={created_at}\n"
    ).encode("ascii")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o400)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        if os.geteuid() == 0:
            os.fchown(descriptor, 0, 0)
        metadata = os.fstat(descriptor)
    except Exception:
        os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "created_at": created_at,
    }


def place_canaries(
    database_path: Path,
    key_path: Path,
    locations: list[Path],
    vault_mount: Path,
    *,
    mount_checker=os.path.ismount,
) -> dict[str, Any]:
    if not locations or len(locations) > MAX_CANARIES:
        raise CanaryError("invalid canary location count")
    normalized = [_validate_location(str(path)) for path in locations]
    if len(set(normalized)) != len(normalized):
        raise CanaryError("duplicate canary location")
    key = _load_key(key_path)

    existing_records: dict[str, dict[str, Any]] = {}
    if database_path.exists() or database_path.is_symlink():
        unsigned = load_database(database_path, key)
        check = check_canaries(database_path, key_path)
        if check["status"] == "violation":
            raise CanaryError("existing canary state is invalid; refusing to re-baseline")
        existing_records = {
            record["path"]: record for record in unsigned["canaries"]
        }

    vault_mounted = mount_checker(vault_mount)
    records: list[dict[str, Any]] = []
    pending: list[str] = []
    for location in normalized:
        path = Path(location)
        try:
            within_vault = path.is_relative_to(vault_mount)
        except AttributeError:  # pragma: no cover - Python 3.8 compatibility
            within_vault = str(path).startswith(f"{vault_mount}/")
        if within_vault and not vault_mounted:
            pending.append(location)
            continue
        if location in existing_records:
            records.append(existing_records.pop(location))
        else:
            records.append(_create_canary(path))
    if existing_records:
        raise CanaryError("database contains canaries outside the configured location set")

    unsigned = {
        "format": "secai-canary",
        "format_version": FORMAT_VERSION,
        "created_at": _now(),
        "canaries": sorted(records, key=lambda item: item["path"]),
        "pending_locations": sorted(pending),
    }
    _atomic_database(database_path, unsigned, key)
    return {
        "status": "pending" if pending else "ok",
        "enrolled": len(records),
        "pending_locations": pending,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("place", "check", "paths"):
        command = subparsers.add_parser(name)
        command.add_argument("--database", type=Path, required=True)
        command.add_argument("--key", type=Path, required=True)
        if name == "place":
            command.add_argument("--vault-mount", type=Path, required=True)
            command.add_argument("--location", type=Path, action="append", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if os.geteuid() != 0:
            raise CanaryError("canary management must run as root")
        if args.command == "place":
            result = place_canaries(
                args.database,
                args.key,
                args.location,
                args.vault_mount,
            )
        elif args.command == "check":
            result = check_canaries(args.database, args.key)
        else:
            key = _load_key(args.key)
            unsigned = load_database(args.database, key)
            for record in unsigned["canaries"]:
                print(record["path"])
            return 0
        print(json.dumps(result, separators=(",", ":")))
        return 1 if result["status"] == "violation" else 0
    except (CanaryError, OSError) as exc:
        print(f"secure-canary: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Quarantine watcher: monitors the quarantine drop directory for new artifacts,
runs the verification/scanning pipeline, and promotes passing artifacts to
the trusted registry via its HTTP API.

Supports:
- Single-file LLM models (.gguf, .safetensors)
- Multi-file diffusion model directories (containing model_index.json)

Everything is fully automatic. Users drop files into quarantine (via UI or CLI)
and the watcher handles scanning, verification, and promotion with zero
manual intervention.
"""

import hashlib
import json
import logging
import os
import re
import resource
import signal
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import sys

# Add services/ to path so we can import common.audit_chain
_services_root = str(Path(__file__).resolve().parent.parent.parent)
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from common.audit_chain import AuditChain  # noqa: E402

log = logging.getLogger("quarantine")

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/quarantine"))
PROCESSING_DIR = Path(
    os.getenv("PROCESSING_DIR", "/var/lib/secure-ai/quarantine/processing")
)
PROMOTION_STAGING_DIR = Path(
    os.getenv("PROMOTION_STAGING_DIR", "/var/lib/secure-ai/promotion-staging")
)
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
POLICY_PATH = Path(os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml"))
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/quarantine-audit.jsonl"))
REGISTRY_TOKEN_PATH = Path(os.getenv(
    "REGISTRY_TOKEN_PATH",
    os.getenv("SERVICE_TOKEN_PATH", "/run/secure-ai/credentials/registry.token"),
))
SCANNER_WORKER_BIN = os.getenv(
    "SCANNER_WORKER_BIN",
    "/usr/libexec/secure-ai/quarantine-scanner",
)
LANDLOCK_APPLY_BIN = os.getenv(
    "LANDLOCK_APPLY_BIN",
    "/usr/libexec/secure-ai/landlock-apply.py",
)
BWRAP_BIN = os.getenv("BWRAP_BIN", "/usr/bin/bwrap")
_scanner_job_dir = os.getenv("SCANNER_JOB_DIR", "").strip()
SCANNER_JOB_DIR = Path(_scanner_job_dir) if _scanner_job_dir else None
SCANNER_WORKER_TIMEOUT = int(os.getenv("SCANNER_WORKER_TIMEOUT", "1800"))
SCANNER_WORKER_MAX_OUTPUT = int(
    os.getenv("SCANNER_WORKER_MAX_OUTPUT", str(8 * 1024 * 1024))
)
SOURCE_METADATA_MAX_BYTES = 4096
CLAIM_STATE_MAX_BYTES = 4096
CLAIM_VERSION = 1
MAX_LOGICAL_NAME_BYTES = 255
MAX_CLAIM_FILES = 25_000
MAX_CLAIM_PATH_BYTES = 4096
CLAIM_FREE_SPACE_RESERVE = 2 * 1024 * 1024 * 1024
SIDECAR_SUFFIXES = (".source", ".hf-manifest.json")
DIFFUSION_MAX_FILES = 20_000
DIFFUSION_MAX_ENTRIES = 25_000
DIFFUSION_MAX_DEPTH = 32
DIFFUSION_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
DIFFUSION_MAX_FILE_BYTES = 50 * 1024 * 1024 * 1024

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
DENIED_EXTENSIONS = {".pkl", ".pickle", ".pt", ".bin"}

# Hash-chained audit log instance
_audit_chain = AuditChain(str(AUDIT_LOG_PATH))


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKey(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _decode_strict_json_object(raw: bytes) -> dict:
    """Decode a finite JSON object without duplicate keys or NaN constants."""
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise ValueError("malformed JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


class ScannerBoundaryError(RuntimeError):
    """Requires a full systemd service restart to reap the scanner cgroup."""


@dataclass(frozen=True)
class QuarantineClaim:
    """A private, stable snapshot claimed from the importer-writable inbox."""

    root: Path
    artifact_path: Path
    logical_name: str
    directory: bool


def audit_log(event: str, filename: str, **kwargs):
    """Append a hash-chained audit entry to the quarantine audit log."""
    _audit_chain.append(event, {"filename": filename, **kwargs})


def _fsync_directory(path: Path) -> None:
    """Persist directory-entry changes when the filesystem supports it."""
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_logical_name(name: str) -> str:
    """Validate a single inbox basename without normalising it."""
    if (
        not name
        or name in {".", ".."}
        or Path(name).name != name
        or name.startswith(".")
        or len(name.encode("utf-8")) > MAX_LOGICAL_NAME_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise ValueError("artifact name is not a safe quarantine basename")
    return name


def _atomic_write_claim_state(
    claim_root: Path,
    *,
    logical_name: str,
    directory: bool,
    state: str,
) -> None:
    state_path = claim_root / ".claim.json"
    payload = {
        "version": CLAIM_VERSION,
        "logical_name": logical_name,
        "directory": directory,
        "state": state,
    }
    encoded = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > CLAIM_STATE_MAX_BYTES:
        raise ValueError("claim state exceeds safety limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".claim.",
        suffix=".tmp",
        dir=claim_root,
    )
    try:
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, state_path)
        _fsync_directory(claim_root)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _read_claim_state(claim_root: Path) -> dict[str, object]:
    state_path = claim_root / ".claim.json"
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(state_path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > CLAIM_STATE_MAX_BYTES
        ):
            raise ValueError("claim state is not a bounded single-link regular file")
        raw = handle.read(CLAIM_STATE_MAX_BYTES + 1)
    try:
        state = _decode_strict_json_object(raw)
    except ValueError as exc:
        raise ValueError("claim state is malformed") from exc
    if (
        set(state) != {"version", "logical_name", "directory", "state"}
        or state.get("version") != CLAIM_VERSION
        or type(state.get("directory")) is not bool
        or state.get("state") not in {"claiming", "snapshotting", "ready"}
    ):
        raise ValueError("claim state has invalid fields")
    logical_name = state.get("logical_name")
    if not isinstance(logical_name, str):
        raise ValueError("claim state has no logical name")
    _validate_logical_name(logical_name)
    return state


def _copy_regular_file_snapshot(
    source: Path,
    destination: Path,
    *,
    max_bytes: int | None = None,
) -> None:
    """Copy one untrusted inode into a new private, read-only snapshot inode."""
    before = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ValueError("claim contains a link or special file")
    if before.st_nlink != 1:
        raise ValueError("hard-linked claim files are not accepted")
    if max_bytes is not None and before.st_size > max_bytes:
        raise ValueError("claim file exceeds safety limit")
    filesystem = os.statvfs(destination.parent)
    available_bytes = filesystem.f_bavail * filesystem.f_frsize
    if before.st_size > max(0, available_bytes - CLAIM_FREE_SPACE_RESERVE):
        raise ValueError("insufficient reserved disk capacity for claim snapshot")

    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    source_descriptor = os.open(source, source_flags)
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o440,
    )
    try:
        opened = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise ValueError("claim file changed while it was being opened")
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1 << 20)
            if not chunk:
                break
            copied += len(chunk)
            if max_bytes is not None and copied > max_bytes:
                raise ValueError("claim file exceeds safety limit")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if copied != opened.st_size or any(
            getattr(opened, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise ValueError("claim file changed while it was snapshotted")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)


def _copy_directory_snapshot(source: Path, destination: Path) -> None:
    """Copy an untrusted tree without retaining links or special files."""
    entries_seen = 0
    total_bytes = 0

    def copy_tree(
        source_dir: Path,
        destination_dir: Path,
        relative: Path,
        depth: int,
    ) -> None:
        nonlocal entries_seen, total_bytes
        if depth > DIFFUSION_MAX_DEPTH:
            raise ValueError("claim directory exceeds maximum depth")
        metadata = source_dir.lstat()
        if source_dir.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("claim directory contains a link or special entry")
        destination_dir.mkdir(mode=0o2770)
        os.chmod(destination_dir, 0o2770)
        entries: list[os.DirEntry] = []
        with os.scandir(source_dir) as iterator:
            for entry in iterator:
                entries_seen += 1
                if entries_seen > MAX_CLAIM_FILES:
                    raise ValueError("claim directory contains too many entries")
                entries.append(entry)
        entries.sort(key=lambda item: os.fsencode(item.name))
        try:
            for entry in entries:
                if (
                    not entry.name
                    or entry.name in {".", ".."}
                    or any(
                        ord(character) < 0x20 or ord(character) == 0x7F
                        for character in entry.name
                    )
                ):
                    raise ValueError("claim directory contains an unsafe name")
                relative_entry = relative / entry.name
                if len(relative_entry.as_posix().encode("utf-8")) > MAX_CLAIM_PATH_BYTES:
                    raise ValueError("claim directory path exceeds safety limit")
                source_entry = source_dir / entry.name
                destination_entry = destination_dir / entry.name
                entry_metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(entry_metadata.st_mode):
                    copy_tree(
                        source_entry,
                        destination_entry,
                        relative_entry,
                        depth + 1,
                    )
                elif stat.S_ISREG(entry_metadata.st_mode):
                    if entry_metadata.st_size > DIFFUSION_MAX_FILE_BYTES:
                        raise ValueError("claim file exceeds size limit")
                    total_bytes += entry_metadata.st_size
                    if total_bytes > DIFFUSION_MAX_TOTAL_BYTES:
                        raise ValueError("claim directory exceeds total size limit")
                    _copy_regular_file_snapshot(
                        source_entry,
                        destination_entry,
                        max_bytes=DIFFUSION_MAX_FILE_BYTES,
                    )
                else:
                    raise ValueError(
                        "claim directory contains a link or special entry"
                    )
            after = source_dir.lstat()
            if (
                after.st_dev != metadata.st_dev
                or after.st_ino != metadata.st_ino
                or after.st_mtime_ns != metadata.st_mtime_ns
                or after.st_ctime_ns != metadata.st_ctime_ns
            ):
                raise ValueError("claim directory changed while it was snapshotted")
            os.chmod(destination_dir, 0o2770)
            _fsync_directory(destination_dir)
        finally:
            entries.clear()

    copy_tree(source, destination, Path(), 0)


def _snapshot_claim(
    claim_root: Path,
    *,
    logical_name: str,
    directory: bool,
) -> QuarantineClaim:
    source_root = claim_root / "source"
    snapshot_root = claim_root / "snapshot"
    source_artifact = source_root / logical_name
    snapshot_artifact = snapshot_root / logical_name
    temporary_snapshot = snapshot_root / f".{uuid.uuid4().hex}.tmp"

    snapshot_root.mkdir(mode=0o2770, exist_ok=True)
    os.chmod(snapshot_root, 0o2770)
    if snapshot_artifact.exists() or snapshot_artifact.is_symlink():
        if snapshot_artifact.is_dir() and not snapshot_artifact.is_symlink():
            shutil.rmtree(snapshot_artifact)
        else:
            snapshot_artifact.unlink(missing_ok=True)
    if temporary_snapshot.exists():
        shutil.rmtree(temporary_snapshot, ignore_errors=True)

    _atomic_write_claim_state(
        claim_root,
        logical_name=logical_name,
        directory=directory,
        state="snapshotting",
    )
    try:
        if directory:
            _copy_directory_snapshot(source_artifact, temporary_snapshot)
        else:
            _copy_regular_file_snapshot(
                source_artifact,
                temporary_snapshot,
                max_bytes=DIFFUSION_MAX_TOTAL_BYTES,
            )
        os.rename(temporary_snapshot, snapshot_artifact)

        for suffix in SIDECAR_SUFFIXES:
            sidecar_source = source_root / f".{logical_name}{suffix}"
            try:
                sidecar_source.lstat()
            except FileNotFoundError:
                continue
            sidecar_destination = snapshot_root / sidecar_source.name
            maximum = (
                SOURCE_METADATA_MAX_BYTES
                if suffix == ".source"
                else 4 * 1024 * 1024
            )
            _copy_regular_file_snapshot(
                sidecar_source,
                sidecar_destination,
                max_bytes=maximum,
            )
        _fsync_directory(snapshot_root)
        _atomic_write_claim_state(
            claim_root,
            logical_name=logical_name,
            directory=directory,
            state="ready",
        )
    except Exception:
        if temporary_snapshot.is_dir() and not temporary_snapshot.is_symlink():
            shutil.rmtree(temporary_snapshot, ignore_errors=True)
        else:
            temporary_snapshot.unlink(missing_ok=True)
        raise

    # The importer may still hold an open descriptor to the renamed source.
    # Scanners only receive the independent snapshot inode/tree.
    try:
        shutil.rmtree(source_root)
    except OSError as exc:
        log.warning(
            "private source cleanup deferred for claim %s: %s",
            claim_root.name,
            exc,
        )
    _fsync_directory(claim_root)
    return QuarantineClaim(
        root=claim_root,
        artifact_path=snapshot_artifact,
        logical_name=logical_name,
        directory=directory,
    )


def _move_claim_sidecars(logical_name: str, source_root: Path) -> None:
    """Individually claim any sidecars that existed after the artifact rename."""
    for suffix in SIDECAR_SUFFIXES:
        incoming = QUARANTINE_DIR / f".{logical_name}{suffix}"
        destination = source_root / incoming.name
        try:
            os.rename(incoming, destination)
        except FileNotFoundError:
            continue


def _claim_incoming_artifact(entry: Path) -> QuarantineClaim | None:
    """Atomically remove an artifact from the importer-writable inbox.

    The artifact inode is renamed first, then copied into a private snapshot.
    Replacement paths or later writes through an importer-held descriptor cannot
    affect the bytes handed to scanners.
    """
    logical_name = _validate_logical_name(entry.name)
    incoming_metadata = entry.lstat()
    directory = stat.S_ISDIR(incoming_metadata.st_mode)
    if entry.is_symlink() or not (
        directory or stat.S_ISREG(incoming_metadata.st_mode)
    ):
        raise ValueError("inbox artifact must be a regular file or directory")

    PROCESSING_DIR.mkdir(parents=True, mode=0o2770, exist_ok=True)
    claim_root = PROCESSING_DIR / uuid.uuid4().hex
    claim_root.mkdir(mode=0o2770)
    os.chmod(claim_root, 0o2770)
    source_root = claim_root / "source"
    source_root.mkdir(mode=0o2770)
    os.chmod(source_root, 0o2770)
    _atomic_write_claim_state(
        claim_root,
        logical_name=logical_name,
        directory=directory,
        state="claiming",
    )
    try:
        os.rename(entry, source_root / logical_name)
    except FileNotFoundError:
        shutil.rmtree(claim_root, ignore_errors=True)
        return None
    try:
        _fsync_directory(QUARANTINE_DIR)
        _move_claim_sidecars(logical_name, source_root)
        _fsync_directory(source_root)
        return _snapshot_claim(
            claim_root,
            logical_name=logical_name,
            directory=directory,
        )
    except Exception:
        # Once the artifact has left the shared inbox, retain the private claim
        # for safe recovery rather than moving mutable content back.
        if not (source_root / logical_name).exists():
            shutil.rmtree(claim_root, ignore_errors=True)
        raise


def _recover_claim(claim_root: Path) -> QuarantineClaim | None:
    state = _read_claim_state(claim_root)
    logical_name = str(state["logical_name"])
    directory = bool(state["directory"])
    snapshot_artifact = claim_root / "snapshot" / logical_name
    source_artifact = claim_root / "source" / logical_name

    if state["state"] == "ready" and (
        snapshot_artifact.exists() or snapshot_artifact.is_symlink()
    ):
        snapshot_metadata = snapshot_artifact.lstat()
        if snapshot_artifact.is_symlink() or (
            directory != stat.S_ISDIR(snapshot_metadata.st_mode)
        ):
            raise ValueError("ready claim artifact type does not match claim state")
        if not directory and (
            not stat.S_ISREG(snapshot_metadata.st_mode)
            or snapshot_metadata.st_nlink != 1
        ):
            raise ValueError("ready claim file is not a single-link regular file")
        source_root = claim_root / "source"
        if source_root.exists():
            try:
                shutil.rmtree(source_root)
            except OSError as exc:
                log.warning(
                    "private source cleanup remains pending for claim %s: %s",
                    claim_root.name,
                    exc,
                )
        return QuarantineClaim(
            root=claim_root,
            artifact_path=snapshot_artifact,
            logical_name=logical_name,
            directory=directory,
        )
    if source_artifact.exists() or source_artifact.is_symlink():
        snapshot_root = claim_root / "snapshot"
        if snapshot_root.exists():
            shutil.rmtree(snapshot_root)
        return _snapshot_claim(
            claim_root,
            logical_name=logical_name,
            directory=directory,
        )
    raise ValueError("incomplete claim has neither a source nor a ready snapshot")


def _ready_claims() -> list[QuarantineClaim]:
    """Resume private claims before accepting more importer-controlled paths."""
    if not PROCESSING_DIR.exists():
        return []
    claims: list[QuarantineClaim] = []
    for claim_root in sorted(PROCESSING_DIR.iterdir()):
        if (
            not claim_root.is_dir()
            or claim_root.is_symlink()
            or not all(character in "0123456789abcdef" for character in claim_root.name)
            or len(claim_root.name) != 32
        ):
            log.error("ignoring unexpected processing entry: %r", claim_root.name)
            continue
        try:
            claim = _recover_claim(claim_root)
        except ValueError as exc:
            log.warning("discarding unsafe quarantine claim %r: %s", claim_root.name, exc)
            shutil.rmtree(claim_root, ignore_errors=True)
            continue
        except OSError:
            log.exception("could not recover quarantine claim %r", claim_root.name)
            continue
        if claim is not None:
            claims.append(claim)
    return claims


def _finish_claim(claim: QuarantineClaim) -> None:
    """Remove only a validated direct child of the processing root."""
    if claim.root.parent != PROCESSING_DIR or len(claim.root.name) != 32:
        raise ValueError("refusing to remove an invalid claim path")
    shutil.rmtree(claim.root)
    _fsync_directory(PROCESSING_DIR)


def inspect_directory_files(artifact_dir: Path) -> list[Path]:
    """Bound and enumerate a private directory snapshot without following links."""
    root_metadata = artifact_dir.lstat()
    if artifact_dir.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("artifact directory must be a real directory")

    files: list[Path] = []
    pending: list[tuple[Path, int]] = [(artifact_dir, 0)]
    entries_seen = 0
    total_bytes = 0
    while pending:
        directory, parent_depth = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise ValueError(
                f"cannot inspect artifact directory {directory.name!r}"
            ) from exc
        with entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > DIFFUSION_MAX_ENTRIES:
                    raise ValueError("artifact directory contains too many entries")
                path = Path(entry.path)
                relative = path.relative_to(artifact_dir)
                if any(part.startswith(".") for part in relative.parts):
                    raise ValueError("hidden artifact paths are not allowed")
                relative_bytes = relative.as_posix().encode("utf-8")
                if len(relative_bytes) > MAX_CLAIM_PATH_BYTES:
                    raise ValueError("artifact contains an overlong path")
                depth = parent_depth + 1
                if depth > DIFFUSION_MAX_DEPTH:
                    raise ValueError("artifact directory exceeds maximum depth")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("symbolic links are not allowed")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((path, depth))
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("special files are not allowed")
                if metadata.st_nlink != 1:
                    raise ValueError("hard-linked files are not allowed")
                if metadata.st_size > DIFFUSION_MAX_FILE_BYTES:
                    raise ValueError("artifact file exceeds size limit")
                total_bytes += metadata.st_size
                if total_bytes > DIFFUSION_MAX_TOTAL_BYTES:
                    raise ValueError("artifact directory exceeds total size limit")
                files.append(path)
                if len(files) > DIFFUSION_MAX_FILES:
                    raise ValueError("artifact directory contains too many files")
    return sorted(
        files,
        key=lambda path: path.relative_to(artifact_dir).as_posix().encode("utf-8"),
    )


def sha256_of_directory(dir_path: Path) -> str:
    """Compute the registry-compatible digest without importing parser code."""
    digest = hashlib.sha256()
    digest.update(b"SecAI-Directory-Hash-v1\0")
    for path in inspect_directory_files(dir_path):
        relative_bytes = path.relative_to(dir_path).as_posix().encode("utf-8")
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("directory snapshot changed before hashing")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
            ):
                raise ValueError("directory snapshot changed while hashing")
            digest.update(struct.pack(">Q", len(relative_bytes)))
            digest.update(relative_bytes)
            digest.update(struct.pack(">Q", opened.st_size))
            bytes_read = 0
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                bytes_read += len(chunk)
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            if (
                bytes_read != opened.st_size
                or opened.st_size != after.st_size
                or opened.st_mtime_ns != after.st_mtime_ns
                or opened.st_ctime_ns != after.st_ctime_ns
            ):
                raise ValueError("directory snapshot changed while hashing")
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("artifact must be a regular file, not a link or special file")
    if metadata.st_nlink != 1:
        raise ValueError("hard-linked artifacts are not accepted")

    h = hashlib.sha256()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as f:
        opened = os.fstat(f.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise ValueError("artifact changed while it was being opened")
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def model_name_from_filename(filename: str) -> str:
    """Derive a human-readable model name from filename."""
    stem = Path(filename).stem
    for suffix in [".Q4_K_M", ".Q5_K_M", ".Q8_0", ".Q4_0", ".Q6_K", ".f16", ".f32"]:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def _read_source_metadata(artifact_path: Path) -> str:
    """Read source URL from .source metadata file if present.

    When a model is downloaded via the UI's one-click download, a companion
    .source file is written alongside containing the origin URL. This lets
    the pipeline verify the source against the allowlist.
    """
    source_file = artifact_path.parent / f".{artifact_path.name}.source"
    try:
        metadata = source_file.lstat()
    except FileNotFoundError:
        return ""
    if source_file.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("source metadata must be a regular file")
    if metadata.st_nlink != 1:
        raise ValueError("hard-linked source metadata is not accepted")
    if metadata.st_size > SOURCE_METADATA_MAX_BYTES:
        raise ValueError("source metadata exceeds safety limit")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(source_file, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise ValueError("source metadata changed while it was being opened")
        raw = handle.read(SOURCE_METADATA_MAX_BYTES + 1)
    try:
        source_url = raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("source metadata is not valid UTF-8") from exc
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in source_url):
        raise ValueError("source metadata contains control characters")
    return source_url


def _cleanup_artifact_metadata(artifact_path: Path) -> None:
    """Remove hidden metadata files associated with a quarantined artifact."""
    for suffix in (".source", ".hf-manifest.json"):
        metadata_file = artifact_path.parent / f".{artifact_path.name}{suffix}"
        metadata_file.unlink(missing_ok=True)


def _quarantine_status_marker(artifact_path: Path) -> Path:
    """Return the hidden status marker path for a quarantined artifact."""
    return artifact_path.parent / f".{artifact_path.name}.status.json"


def _write_quarantine_status_marker(artifact_path: Path, **payload) -> None:
    """Record that a quarantined artifact was already handled despite cleanup issues."""
    marker = _quarantine_status_marker(artifact_path)
    data = {
        "artifact": artifact_path.name,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **payload,
    }
    marker.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{marker.name}.",
        suffix=".tmp",
        dir=marker.parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        encoded = (json.dumps(data, indent=2) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, marker)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _scanner_worker_environment(scanner_root: Path | None = None) -> dict[str, str]:
    """Pass only scanner/runtime settings, never promotion credentials."""
    allowed_names = {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PYTHONPATH",
        "QUARANTINE_DIR",
        "MODELS_LOCK_PATH",
        "DIFFUSION_MODELS_LOCK_PATH",
        "SOURCES_ALLOWLIST_PATH",
        "LLAMA_SERVER_BIN",
        "GGUF_GUARD_BIN",
        "COSIGN_BIN",
        "FICKLING_BIN",
        "MODELAUDIT_BIN",
        "MODELSCAN_BIN",
        "GARAK_BIN",
        "SMOKE_TEST_TIMEOUT",
        "YARA_RULES_DIR",
        "YARA_SCAN_TIMEOUT",
        "LANDLOCK_POLICY_PATH",
    }
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in allowed_names
    }
    environment["QUARANTINE_DIR"] = str(scanner_root or QUARANTINE_DIR)
    return environment


def _limit_scanner_worker_output() -> None:
    """Bound regular-file output before executing the untrusted scanner stack."""
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (SCANNER_WORKER_MAX_OUTPUT, SCANNER_WORKER_MAX_OUTPUT),
    )


def _terminate_scanner_process_group(process: subprocess.Popen) -> None:
    """Kill descendants even when the scanner's direct child exited cleanly."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _read_bounded_broker_json(path: Path) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > SCANNER_WORKER_MAX_OUTPUT
        ):
            raise ScannerBoundaryError("scanner broker result is not a bounded file")
        raw = handle.read(SCANNER_WORKER_MAX_OUTPUT + 1)
    try:
        result = _decode_strict_json_object(raw)
    except ValueError as exc:
        raise ScannerBoundaryError("scanner broker result is malformed") from exc
    return result


def _create_broker_request(path: Path, payload: dict) -> None:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > 16 * 1024:
        raise ScannerBoundaryError("scanner broker request exceeds safety limit")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o640,
        )
    except FileExistsError:
        existing = _read_bounded_broker_json(path)
        if existing != payload:
            raise ScannerBoundaryError("stale scanner request does not match claim")
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def _request_broker_cancellation(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o640,
        )
    except FileExistsError:
        return
    os.close(descriptor)
    _fsync_directory(path.parent)


def _run_scanner_via_broker(
    artifact_path: Path,
    artifact_hash: str,
    *,
    source_url: str,
    directory: bool,
) -> dict:
    """Use the no-network scanner sidecar in the Compose deployment."""
    if SCANNER_JOB_DIR is None:
        raise ScannerBoundaryError("scanner broker directory is not configured")
    SCANNER_JOB_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    candidate_id = artifact_path.parent.parent.name
    job_id = (
        candidate_id
        if re.fullmatch(r"[0-9a-f]{32}", candidate_id)
        else uuid.uuid4().hex
    )
    request_path = SCANNER_JOB_DIR / f"{job_id}.request.json"
    active_path = SCANNER_JOB_DIR / f"{job_id}.active.json"
    result_path = SCANNER_JOB_DIR / f"{job_id}.result.json"
    cancel_path = SCANNER_JOB_DIR / f"{job_id}.cancel"
    request_payload = {
        "version": 1,
        "artifact": str(artifact_path),
        "sha256": artifact_hash,
        "source_url": source_url,
        "directory": directory,
    }

    if not result_path.exists() and not active_path.exists():
        _create_broker_request(request_path, request_payload)

    deadline = time.monotonic() + SCANNER_WORKER_TIMEOUT
    while not result_path.exists():
        if time.monotonic() >= deadline:
            _request_broker_cancellation(cancel_path)
            raise ScannerBoundaryError("credentialless scanner broker timed out")
        time.sleep(0.1)

    envelope = _read_bounded_broker_json(result_path)
    for path in (request_path, active_path, result_path, cancel_path):
        path.unlink(missing_ok=True)
    _fsync_directory(SCANNER_JOB_DIR)
    if (
        envelope.get("version") != 1
        or envelope.get("status") != "ok"
        or not isinstance(envelope.get("result"), dict)
        or not isinstance(envelope["result"].get("passed"), bool)
    ):
        raise ScannerBoundaryError("credentialless scanner broker failed")
    return envelope["result"]


_REQUIRED_POLICY_COMPONENTS = {
    "policy.yaml",
    "models.lock.yaml",
    "diffusion-models.lock.yaml",
    "sources.allowlist.yaml",
}
_HF_REPO_COMPONENT = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?"
_HF_REPO_ID_RE = re.compile(rf"{_HF_REPO_COMPONENT}/{_HF_REPO_COMPONENT}")
_DIRECTORY_MANIFEST_KEYS = {
    "passed",
    "available",
    "trust",
    "manifest_sha256",
    "revision",
    "repo_id",
    "variant",
    "files_checked",
    "total_size_bytes",
    "sha256_files_checked",
    "git_blob_files_checked",
}
_DIRECTORY_HASH_PIN_KEYS = {
    "passed",
    "pinned",
    "match",
    "mechanism",
    "manifest_sha256",
    "revision",
    "directory_hash_pin",
    "huggingface_manifest",
}


def _validated_policy_bundle_evidence(value: object) -> dict[str, object]:
    """Validate and independently recompute the scanner's policy-bundle ID."""
    if not isinstance(value, dict) or set(value) != {
        "version",
        "sha256",
        "components",
    }:
        raise ScannerBoundaryError("scanner policy evidence has an invalid schema")
    digest = value.get("sha256")
    components = value.get("components")
    if (
        type(value.get("version")) is not int
        or value.get("version") != 1
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(components, dict)
        or not 5 <= len(components) <= 1024
        or not _REQUIRED_POLICY_COMPONENTS.issubset(components)
    ):
        raise ScannerBoundaryError("scanner policy evidence is invalid")

    yara_names: list[str] = []
    for name, component_digest in components.items():
        if (
            not isinstance(name, str)
            or not isinstance(component_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", component_digest)
        ):
            raise ScannerBoundaryError("scanner policy component is invalid")
        if name in _REQUIRED_POLICY_COMPONENTS:
            continue
        if not re.fullmatch(r"yara/[A-Za-z0-9._-]+\.yar", name):
            raise ScannerBoundaryError("scanner policy component name is invalid")
        yara_names.append(name)
    if not yara_names:
        raise ScannerBoundaryError("scanner policy evidence contains no YARA rules")

    ordered_names = [
        "policy.yaml",
        "models.lock.yaml",
        "diffusion-models.lock.yaml",
        "sources.allowlist.yaml",
        *sorted(yara_names),
    ]
    calculated = hashlib.sha256()
    calculated.update(b"SecAI-Policy-Bundle-v1\0")
    for name in ordered_names:
        name_bytes = name.encode("utf-8")
        calculated.update(len(name_bytes).to_bytes(8, "big"))
        calculated.update(name_bytes)
        calculated.update(bytes.fromhex(components[name]))
    if calculated.hexdigest() != digest:
        raise ScannerBoundaryError("scanner policy bundle digest is inconsistent")
    return {
        "version": 1,
        "sha256": digest,
        "components": {
            name: components[name]
            for name in ordered_names
        },
    }


def _validated_directory_provenance(
    pipeline_details: object,
) -> dict[str, object]:
    """Extract only typed immutable provenance from a passing directory scan."""
    if not isinstance(pipeline_details, dict):
        raise ScannerBoundaryError("directory scan details are invalid")
    pin = pipeline_details.get("hash_pin")
    if not isinstance(pin, dict) or set(pin) != _DIRECTORY_HASH_PIN_KEYS:
        raise ScannerBoundaryError("directory hash-pin evidence is incomplete")
    if (
        pin.get("passed") is not True
        or pin.get("pinned") is not True
        or pin.get("match") is not True
        or pin.get("mechanism") != "image-owned-huggingface-manifest"
    ):
        raise ScannerBoundaryError("directory is not bound to an image-owned manifest")

    original_pin = pin.get("directory_hash_pin")
    if not isinstance(original_pin, dict) or type(original_pin.get("passed")) is not bool:
        raise ScannerBoundaryError("directory whole-tree pin evidence is invalid")
    if original_pin.get("passed") is False:
        if original_pin != {
            "passed": False,
            "reason": "remote artifact has no pinned hash",
        }:
            raise ScannerBoundaryError("a contradictory directory hash pin was bypassed")
    elif (
        set(original_pin) != {"passed", "pinned", "match"}
        or original_pin.get("pinned") is not True
        or original_pin.get("match") is not True
    ):
        raise ScannerBoundaryError("directory whole-tree pin evidence is inconsistent")

    manifest = pin.get("huggingface_manifest")
    if not isinstance(manifest, dict) or set(manifest) != _DIRECTORY_MANIFEST_KEYS:
        raise ScannerBoundaryError("directory manifest evidence has an invalid schema")
    manifest_sha256 = manifest.get("manifest_sha256")
    revision = manifest.get("revision")
    repo_id = manifest.get("repo_id")
    variant = manifest.get("variant")
    files_checked = manifest.get("files_checked")
    total_size = manifest.get("total_size_bytes")
    sha256_files = manifest.get("sha256_files_checked")
    git_blob_files = manifest.get("git_blob_files_checked")
    if (
        manifest.get("passed") is not True
        or manifest.get("available") is not True
        or manifest.get("trust") != "image-owned-manifest-pin"
        or not isinstance(manifest_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
        or not isinstance(revision, str)
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
        or not isinstance(repo_id, str)
        or not _HF_REPO_ID_RE.fullmatch(repo_id)
        or (variant is not None and variant != "fp16")
        or isinstance(files_checked, bool)
        or not isinstance(files_checked, int)
        or not 1 <= files_checked <= DIFFUSION_MAX_FILES
        or isinstance(total_size, bool)
        or not isinstance(total_size, int)
        or not 1 <= total_size <= DIFFUSION_MAX_TOTAL_BYTES
        or isinstance(sha256_files, bool)
        or not isinstance(sha256_files, int)
        or not 0 <= sha256_files <= files_checked
        or isinstance(git_blob_files, bool)
        or not isinstance(git_blob_files, int)
        or not 0 <= git_blob_files <= files_checked
        or sha256_files + git_blob_files != files_checked
        or pin.get("manifest_sha256") != manifest_sha256
        or pin.get("revision") != revision
    ):
        raise ScannerBoundaryError("directory manifest evidence is inconsistent")
    return {
        "trust": "image-owned-manifest-pin",
        "manifest_sha256": manifest_sha256,
        "revision": revision,
        "repo_id": repo_id,
        "variant": variant,
        "files_checked": files_checked,
        "total_size_bytes": total_size,
        "sha256_files_checked": sha256_files,
        "git_blob_files_checked": git_blob_files,
    }


def _validate_required_stage_result(
    result: dict,
    *,
    artifact_hash: str,
    directory: bool,
    suffix: str,
    source_url: str,
) -> dict:
    """Accept only a typed, complete result assembled by the coordinator."""
    if not isinstance(result, dict) or type(result.get("passed")) is not bool:
        raise ScannerBoundaryError("scanner result has an invalid root schema")
    details = result.get("details")
    if not isinstance(details, dict):
        raise ScannerBoundaryError("scanner result details are invalid")
    if not result["passed"]:
        if not isinstance(result.get("reason"), str):
            raise ScannerBoundaryError("scanner rejection has no typed reason")
        return result
    if result.get("reason") != "all_checks_passed":
        raise ScannerBoundaryError("passing scanner result has an invalid reason")

    required_stages = {
        "source_policy",
        "format_gate",
        "hash_pin",
        "provenance",
        "static_scan",
        "smoke_test",
    }
    if directory:
        required_stages.add("diffusion_deep_scan")
    expected_keys = required_stages | {"hash", "policy_bundle"}
    if set(details) != expected_keys:
        raise ScannerBoundaryError("passing scanner result omits a required stage")
    for stage in required_stages:
        stage_result = details[stage]
        if not isinstance(stage_result, dict) or stage_result.get("passed") is not True:
            raise ScannerBoundaryError("passing scanner result has an invalid stage")
    if not directory and suffix == ".gguf":
        smoke_note = details["smoke_test"].get("note")
        if smoke_note is not None and "not applicable" in str(smoke_note).lower():
            raise ScannerBoundaryError("GGUF behavioral stage was not executed")

    hash_evidence = details["hash"]
    if (
        not isinstance(hash_evidence, dict)
        or hash_evidence.get("sha256") != artifact_hash
    ):
        raise ScannerBoundaryError("scanner hash evidence does not match claim")
    _validated_policy_bundle_evidence(details["policy_bundle"])
    if directory:
        directory_provenance = _validated_directory_provenance(details)
        if not _source_matches_directory_provenance(
            source_url,
            directory_provenance,
        ):
            raise ScannerBoundaryError(
                "directory source does not match its manifest evidence"
            )
    else:
        pin = details["hash_pin"]
        if not isinstance(pin, dict) or pin.get("passed") is not True:
            raise ScannerBoundaryError("file hash-pin evidence is invalid")
        if source_url:
            if (
                set(pin) != {"passed", "pinned", "match"}
                or pin.get("pinned") is not True
                or pin.get("match") is not True
            ):
                raise ScannerBoundaryError(
                    "remote file is not bound to an immutable hash pin"
                )
        elif pin.get("pinned") is True:
            if set(pin) != {"passed", "pinned", "match"} or pin.get("match") is not True:
                raise ScannerBoundaryError("local file pin evidence is inconsistent")
        elif pin != {
            "passed": True,
            "pinned": False,
            "note": (
                "first-install trust: hash recorded, must be pinned "
                "before next promotion"
            ),
        }:
            raise ScannerBoundaryError("local file trust evidence is invalid")
    return result


def _run_scanner_worker(
    artifact_path: Path,
    artifact_hash: str,
    *,
    source_url: str,
    directory: bool,
) -> dict:
    """Run parsers in a credentialless private network/PID namespace.

    Bubblewrap gives each scan a new network namespace containing only its own
    loopback.  The worker can therefore start and probe a local llama-server,
    but cannot reach the host's Tor, SearXNG, registry, or other localhost
    deputies.  The independent PID namespace plus process-group cleanup also
    bounds descendants to this scan's lifetime.
    """
    if SCANNER_JOB_DIR is not None:
        broker_result = _run_scanner_via_broker(
            artifact_path,
            artifact_hash,
            source_url=source_url,
            directory=directory,
        )
        return _validate_required_stage_result(
            broker_result,
            artifact_hash=artifact_hash,
            directory=directory,
            suffix=artifact_path.suffix.lower(),
            source_url=source_url,
        )

    scanner_root = artifact_path.parent
    worker_command = [
        LANDLOCK_APPLY_BIN,
        "--require",
        "quarantine_scanner",
        "--",
        SCANNER_WORKER_BIN,
        "--artifact",
        str(artifact_path),
        "--sha256",
        artifact_hash,
        "--policy",
        str(POLICY_PATH),
    ]
    if source_url:
        # Use argparse's joined form so an attacker-controlled source string
        # beginning with "-" cannot be reinterpreted as a worker option.
        worker_command.append(f"--source-url={source_url}")
    if directory:
        worker_command.append("--directory")

    command = [
        BWRAP_BIN,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/",
        "--setenv",
        "QUARANTINE_DIR",
        str(scanner_root),
        "--",
        *worker_command,
    ]

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=_scanner_worker_environment(scanner_root),
                close_fds=True,
                start_new_session=True,
                preexec_fn=_limit_scanner_worker_output,
            )
        except OSError as exc:
            raise ScannerBoundaryError(
                "credentialless scanner worker could not start"
            ) from exc

        try:
            return_code = process.wait(timeout=SCANNER_WORKER_TIMEOUT)
        except subprocess.TimeoutExpired:
            _terminate_scanner_process_group(process)
            raise ScannerBoundaryError(
                "credentialless scanner worker timed out"
            ) from None
        else:
            # A parser may deliberately daemonize or leave a helper behind.
            # Always destroy the scan process group after the namespace leader
            # exits, including on a nominally successful scan.
            _terminate_scanner_process_group(process)

        stdout_file.seek(0)
        raw_output = stdout_file.read(SCANNER_WORKER_MAX_OUTPUT + 1)
        if len(raw_output) > SCANNER_WORKER_MAX_OUTPUT:
            raise ScannerBoundaryError(
                "credentialless scanner worker exceeded its output limit"
            )
        try:
            result = _decode_strict_json_object(raw_output)
        except ValueError as exc:
            raise ScannerBoundaryError(
                "credentialless scanner worker returned invalid JSON"
            ) from exc
        if (
            return_code != 0
            or not isinstance(result, dict)
            or not isinstance(result.get("passed"), bool)
        ):
            # Do not copy raw stderr into an audit result. Exiting the watcher
            # lets systemd KillMode=control-group reap any escaped descendants
            # before Restart=always creates a fresh boundary.
            raise ScannerBoundaryError(
                "credentialless scanner worker failed"
            )
        return _validate_required_stage_result(
            result,
            artifact_hash=artifact_hash,
            directory=directory,
            suffix=artifact_path.suffix.lower(),
            source_url=source_url,
        )


def _cleanup_quarantine_directory(artifact_dir: Path, *, state: str, artifact_hash: str) -> None:
    """Best-effort cleanup after handling a directory import.

    If the watcher cannot remove the original directory (for example because an
    external tool copied it in with a different owner), write a hidden marker so
    future scan loops skip the already-handled artifact instead of retrying
    forever.
    """
    try:
        shutil.rmtree(artifact_dir)
    except OSError as e:
        _write_quarantine_status_marker(
            artifact_dir,
            state=state,
            sha256=artifact_hash,
            cleanup_error=str(e),
        )
        log.warning(
            "could not remove quarantine directory %s after %s; wrote status marker: %s",
            artifact_dir.name,
            state,
            e,
        )


def _extract_scanner_versions(scan_results: dict) -> dict:
    """Extract scanner version info from pipeline scan result details."""
    versions = {}
    for key, value in scan_results.items():
        if isinstance(value, dict):
            ver = value.get("scanner_version")
            if ver:
                versions[key] = ver
        elif isinstance(value, str):
            # Try to parse stringified dicts (from {k: str(v)} conversions)
            pass
    return versions


def _policy_version_id(pipeline_details: dict | None) -> str:
    """Return the exact policy-bundle digest attested by the scanner worker."""
    if not isinstance(pipeline_details, dict):
        return ""
    try:
        evidence = _validated_policy_bundle_evidence(
            pipeline_details.get("policy_bundle"),
        )
    except ScannerBoundaryError:
        return ""
    return str(evidence["sha256"])


def _source_matches_directory_provenance(
    source_url: str,
    provenance: dict[str, object],
) -> bool:
    """Bind a directory's canonical source URL to its trusted repository ID."""
    try:
        parsed = urlparse(source_url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "huggingface.co"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
        and parsed.path == f"/{provenance['repo_id']}"
    )


def _stage_artifact_for_promotion(artifact_path: Path) -> str:
    """Copy a verified artifact into the untrusted promotion inbox.

    The registry independently opens, copies, validates, hashes, and commits
    this basename. Quarantine never writes the trusted registry filesystem.
    """
    PROMOTION_STAGING_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    suffix = artifact_path.suffix.lower() if artifact_path.is_file() else ""
    staged_name = f"{uuid.uuid4().hex}{suffix}"
    staged_path = PROMOTION_STAGING_DIR / staged_name

    if artifact_path.is_symlink():
        raise ValueError("symlink artifacts cannot be promoted")
    if artifact_path.is_file():
        shutil.copy2(artifact_path, staged_path, follow_symlinks=False)
    elif artifact_path.is_dir():
        for entry in artifact_path.rglob("*"):
            if entry.is_symlink():
                raise ValueError("symlinks inside model directories cannot be promoted")
        shutil.copytree(
            artifact_path,
            staged_path,
            copy_function=shutil.copy2,
        )
    else:
        raise ValueError("artifact must be a regular file or directory")
    return staged_name


def _discard_staged_artifact(staged_name: str) -> None:
    staged_path = PROMOTION_STAGING_DIR / staged_name
    try:
        if staged_path.is_dir():
            shutil.rmtree(staged_path)
        else:
            staged_path.unlink(missing_ok=True)
    except OSError:
        log.warning("could not clean failed promotion staging item %s", staged_name)


def _service_headers() -> dict[str, str]:
    """Return inter-service auth headers when a token is configured."""
    try:
        token = REGISTRY_TOKEN_PATH.read_text().strip()
    except OSError:
        return {"Content-Type": "application/json"}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _http_urlopen(target, timeout: int = 30):
    """Open only HTTP(S) URLs for registry service calls."""
    raw_url = target.full_url if isinstance(target, Request) else str(target)
    scheme = urlparse(raw_url).scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLError(f"unsupported URL scheme: {scheme or 'none'}")
    return urlopen(target, timeout=timeout)  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected


def promote_to_registry(filename: str, file_hash: str, size_bytes: int,
                        scan_results: dict, model_type: str = "llm",
                        source_url: str = "",
                        pipeline_details: dict | None = None,
                        staged_filename: str = "") -> bool:
    """Call the registry's promote endpoint to register the artifact."""
    name = model_name_from_filename(filename)

    # Extract scanner versions from full pipeline details if available
    scanner_versions = {}
    if pipeline_details:
        scanner_versions = _extract_scanner_versions(pipeline_details)
    try:
        policy_evidence = _validated_policy_bundle_evidence(
            pipeline_details.get("policy_bundle")
            if isinstance(pipeline_details, dict)
            else None,
        )
    except ScannerBoundaryError:
        log.error("refusing promotion without scanner-attested policy evidence")
        return False
    policy_version = str(policy_evidence["sha256"])

    source_revision = ""
    directory_provenance: dict[str, object] | None = None
    if model_type == "diffusion":
        try:
            directory_provenance = _validated_directory_provenance(
                pipeline_details,
            )
        except ScannerBoundaryError as exc:
            log.error("refusing directory promotion: %s", exc)
            return False
        if (
            not _source_matches_directory_provenance(
                source_url,
                directory_provenance,
            )
            or size_bytes != directory_provenance["total_size_bytes"]
        ):
            log.error(
                "refusing directory promotion with inconsistent source/size evidence"
            )
            return False
        source_revision = str(directory_provenance["revision"])
    elif source_url:
        try:
            parsed_source = urlparse(source_url)
            source_port = parsed_source.port
        except ValueError:
            return False
        if parsed_source.hostname == "huggingface.co":
            rev_match = re.search(r"/resolve/([0-9a-f]{40})/", parsed_source.path)
            if (
                parsed_source.scheme != "https"
                or source_port not in {None, 443}
                or parsed_source.username is not None
                or parsed_source.password is not None
                or parsed_source.query
                or parsed_source.fragment
                or rev_match is None
            ):
                log.error(
                    "refusing Hugging Face promotion without an immutable revision"
                )
                return False
            source_revision = rev_match.group(1)

    payload = {
        "name": name,
        "filename": filename,
        "staged_filename": staged_filename,
        "sha256": file_hash,
        "size_bytes": size_bytes,
        "scan_results": {k: str(v) for k, v in scan_results.items()},
        "source": source_url,
        "source_revision": source_revision,
        "scanner_versions": scanner_versions,
        "policy_version": policy_version,
        "policy_bundle": policy_evidence,
    }
    if directory_provenance is not None:
        payload["directory_provenance"] = directory_provenance

    try:
        req = Request(
            f"{REGISTRY_URL}/v1/model/promote",
            data=json.dumps(payload).encode(),
            headers=_service_headers(),
            method="POST",
        )
        with _http_urlopen(req, timeout=30) as resp:
            raw_response = resp.read(1024 * 1024 + 1)
            if len(raw_response) > 1024 * 1024:
                raise ValueError("registry response exceeds safety limit")
            result = _decode_strict_json_object(raw_response)
            log.info("registry promotion response: %r", result)
            return resp.status == 201
    except URLError as e:
        log.error("failed to contact registry for promotion: %s", e)
        return False
    except Exception as e:
        log.error("unexpected error during promotion: %s", e)
        return False


def process_artifact(artifact_path: Path) -> bool:
    """Run the full pipeline on a single-file artifact. Returns True if promoted."""
    log.info("processing: %r", artifact_path.name)

    ext = artifact_path.suffix.lower()
    if ext in DENIED_EXTENSIONS:
        log.warning("REJECTED (denied format): %r", artifact_path.name)
        audit_log("rejected", artifact_path.name, reason="denied_format", extension=ext)
        artifact_path.unlink()
        return False

    if ext not in ALLOWED_EXTENSIONS:
        log.warning("REJECTED (unknown format): %r", artifact_path.name)
        audit_log("rejected", artifact_path.name, reason="unknown_format", extension=ext)
        artifact_path.unlink()
        return False

    try:
        file_hash = sha256_file(artifact_path)
        file_size = artifact_path.stat().st_size
    except (OSError, ValueError) as exc:
        log.warning("REJECTED (unsafe artifact): %r: %s", artifact_path.name, exc)
        audit_log("rejected", artifact_path.name, reason="unsafe_artifact")
        artifact_path.unlink(missing_ok=True)
        return False
    try:
        source_url = _read_source_metadata(artifact_path)
    except (OSError, ValueError) as exc:
        log.warning("REJECTED (unsafe source metadata): %r: %s", artifact_path.name, exc)
        audit_log("rejected", artifact_path.name, reason="unsafe_source_metadata")
        artifact_path.unlink(missing_ok=True)
        _cleanup_artifact_metadata(artifact_path)
        return False
    log.info("sha256: %s  size: %d bytes  source: %s", file_hash, file_size, source_url or "local")

    try:
        result = _run_scanner_worker(
            artifact_path,
            file_hash,
            source_url=source_url,
            directory=False,
        )
    except ScannerBoundaryError:
        audit_log(
            "scanner_boundary_failure",
            artifact_path.name,
            sha256=file_hash,
        )
        raise

    try:
        after_scan_hash = sha256_file(artifact_path)
    except (OSError, ValueError):
        after_scan_hash = "unavailable"
    if after_scan_hash != file_hash:
        result = {
            "passed": False,
            "reason": "artifact_changed_during_scan",
            "details": {},
        }

    if not result["passed"]:
        log.warning("REJECTED (%s): %r", result["reason"], artifact_path.name)
        audit_log(
            "rejected", artifact_path.name,
            reason=result["reason"],
            sha256=file_hash,
            size_bytes=file_size,
            scan_summary=_build_scan_summary(result.get("details", {})),
        )
        artifact_path.unlink()
        _cleanup_artifact_metadata(artifact_path)
        return False

    # Collect scan result summary
    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)

    staged_name = ""
    try:
        staged_name = _stage_artifact_for_promotion(artifact_path)
    except (OSError, ValueError) as exc:
        log.error("could not stage verified artifact for registry transaction: %s", exc)
        audit_log(
            "promotion_failed",
            artifact_path.name,
            sha256=file_hash,
            reason="staging_failed",
        )
        return False

    if promote_to_registry(
        artifact_path.name,
        file_hash,
        file_size,
        scan_summary,
        source_url=source_url,
        pipeline_details=details,
        staged_filename=staged_name,
    ):
        log.info("PROMOTED: %r (registered in manifest)", artifact_path.name)
        audit_log("promoted", artifact_path.name, sha256=file_hash,
                  size_bytes=file_size, scan_summary=scan_summary)
        artifact_path.unlink()
        _cleanup_artifact_metadata(artifact_path)
        return True

    _discard_staged_artifact(staged_name)
    log.error("registry transaction failed; source remains quarantined: %r", artifact_path.name)
    audit_log(
        "promotion_failed",
        artifact_path.name,
        sha256=file_hash,
        size_bytes=file_size,
        note="registry transaction rejected; quarantine source retained",
    )
    return False


def process_directory(artifact_dir: Path) -> bool:
    """Run the full pipeline on a multi-file diffusion model directory.
    Returns True if promoted.
    """
    log.info("processing directory: %r", artifact_dir.name)

    # Reject links, hard links, special files, and pathological file trees
    # before any scanner follows or parses an entry.
    try:
        artifact_files = inspect_directory_files(artifact_dir)
        dir_hash = sha256_of_directory(artifact_dir)
    except (OSError, ValueError) as exc:
        log.warning("REJECTED (unsafe directory): %r: %s", artifact_dir.name, exc)
        audit_log("rejected", artifact_dir.name, reason="unsafe_directory")
        _cleanup_quarantine_directory(
            artifact_dir,
            state="rejected",
            artifact_hash="unavailable",
        )
        return False
    try:
        source_url = _read_source_metadata(artifact_dir)
    except (OSError, ValueError) as exc:
        log.warning("REJECTED (unsafe source metadata): %r: %s", artifact_dir.name, exc)
        audit_log("rejected", artifact_dir.name, reason="unsafe_source_metadata")
        _cleanup_quarantine_directory(
            artifact_dir,
            state="rejected",
            artifact_hash=dir_hash,
        )
        _cleanup_artifact_metadata(artifact_dir)
        return False
    log.info("directory hash: %s  source: %s", dir_hash, source_url or "local")

    # Calculate total size
    total_size = sum(f.lstat().st_size for f in artifact_files)

    try:
        result = _run_scanner_worker(
            artifact_dir,
            dir_hash,
            source_url=source_url,
            directory=True,
        )
    except ScannerBoundaryError:
        audit_log(
            "scanner_boundary_failure",
            artifact_dir.name,
            sha256=dir_hash,
            model_type="diffusion",
        )
        raise

    try:
        after_scan_hash = sha256_of_directory(artifact_dir)
    except (OSError, ValueError):
        after_scan_hash = "unavailable"
    if after_scan_hash != dir_hash:
        result = {
            "passed": False,
            "reason": "artifact_changed_during_scan",
            "details": {},
        }

    if not result["passed"]:
        log.warning("REJECTED (%s): %r", result["reason"], artifact_dir.name)
        audit_log(
            "rejected", artifact_dir.name,
            reason=result["reason"],
            sha256=dir_hash,
            size_bytes=total_size,
            model_type="diffusion",
            scan_summary=_build_scan_summary(result.get("details", {})),
        )
        _cleanup_quarantine_directory(
            artifact_dir,
            state="rejected",
            artifact_hash=dir_hash,
        )
        _cleanup_artifact_metadata(artifact_dir)
        return False

    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)
    scan_summary["model_type"] = "diffusion"

    staged_name = ""
    try:
        staged_name = _stage_artifact_for_promotion(artifact_dir)
    except (OSError, ValueError) as exc:
        log.error("could not stage verified directory for registry transaction: %s", exc)
        audit_log(
            "promotion_failed",
            artifact_dir.name,
            sha256=dir_hash,
            model_type="diffusion",
            reason="staging_failed",
        )
        return False

    if promote_to_registry(
        artifact_dir.name,
        dir_hash,
        total_size,
        scan_summary,
        model_type="diffusion",
        source_url=source_url,
        pipeline_details=details,
        staged_filename=staged_name,
    ):
        log.info("PROMOTED: %r (diffusion model registered)", artifact_dir.name)
        audit_log("promoted", artifact_dir.name, sha256=dir_hash,
                  size_bytes=total_size, model_type="diffusion", scan_summary=scan_summary)
        _cleanup_artifact_metadata(artifact_dir)
        _cleanup_quarantine_directory(
            artifact_dir,
            state="promoted",
            artifact_hash=dir_hash,
        )
        return True

    _discard_staged_artifact(staged_name)
    log.error("registry transaction failed; source remains quarantined: %r", artifact_dir.name)
    audit_log(
        "promotion_failed",
        artifact_dir.name,
        sha256=dir_hash,
        size_bytes=total_size,
        model_type="diffusion",
        note="registry transaction rejected; quarantine source retained",
    )
    return False


def _build_scan_summary(details: dict) -> dict[str, object]:
    """Build a summary dict from pipeline details for the registry manifest."""
    summary: dict[str, object] = {}
    scanner_versions: dict[str, str] = {}
    if "source_policy" in details:
        summary["source_policy"] = "pass" if details["source_policy"].get("passed") else "fail"
    if "format_gate" in details:
        summary["format_gate"] = "pass" if details["format_gate"].get("passed") else "fail"
    if "provenance" in details:
        summary["provenance"] = details["provenance"].get("provenance", "unknown")
        ver = details["provenance"].get("scanner_version")
        if ver:
            scanner_versions["cosign"] = ver
    if "static_scan" in details:
        scan = details["static_scan"]
        summary["static_scan"] = scan.get("scanner", "unknown")
        # Extract modelscan version from nested details
        ms_details = scan.get("details", {})
        ms_info = ms_details.get("modelscan", {}) if isinstance(ms_details, dict) else {}
        ver = ms_info.get("scanner_version") if isinstance(ms_info, dict) else None
        if ver:
            scanner_versions["modelscan"] = ver
    if "smoke_test" in details:
        summary["smoke_test"] = str(details["smoke_test"].get("score", "n/a"))
        ver = details["smoke_test"].get("scanner_version")
        if ver:
            scanner_versions["llama-server"] = ver
    if "diffusion_deep_scan" in details:
        summary["diffusion_deep_scan"] = "pass" if details["diffusion_deep_scan"].get("passed") else "fail"
    try:
        directory_provenance = _validated_directory_provenance(details)
    except ScannerBoundaryError:
        directory_provenance = None
    if directory_provenance is not None:
        summary.update({
            "directory_trust": directory_provenance["trust"],
            "directory_manifest_sha256": directory_provenance["manifest_sha256"],
            "source_revision": directory_provenance["revision"],
            "source_repo": directory_provenance["repo_id"],
            "files_checked": directory_provenance["files_checked"],
            "total_size_bytes": directory_provenance["total_size_bytes"],
        })
    if scanner_versions:
        summary["scanner_versions"] = scanner_versions
    return summary


def _process_claim(claim: QuarantineClaim) -> None:
    """Process one ready claim and remove terminal claims from private storage."""
    if claim.directory:
        if not (claim.artifact_path / "model_index.json").is_file():
            log.warning(
                "REJECTED (directory is not a diffusion model): %r",
                claim.logical_name,
            )
            audit_log(
                "rejected",
                claim.logical_name,
                reason="unsupported_directory",
            )
            _finish_claim(claim)
            return
        promoted = process_directory(claim.artifact_path)
    else:
        promoted = process_artifact(claim.artifact_path)

    # A terminal rejection or successful promotion removes the snapshot
    # artifact. A registry outage deliberately retains it for a future retry.
    if promoted or not claim.artifact_path.exists():
        _finish_claim(claim)


def _discard_rejected_inbox_entry(entry: Path) -> None:
    """Remove only the exact direct inbox entry that failed safe claiming."""
    if entry.parent != QUARANTINE_DIR:
        raise ValueError("refusing to discard a path outside the inbox")
    try:
        metadata = entry.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(metadata.st_mode) and not entry.is_symlink():
        shutil.rmtree(entry)
    else:
        entry.unlink(missing_ok=True)
    _fsync_directory(QUARANTINE_DIR)


def scan_directory():
    """One-shot scan of the quarantine directory."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)

    for claim in _ready_claims():
        _process_claim(claim)

    for entry in sorted(QUARANTINE_DIR.iterdir()):
        if entry.name.startswith("."):
            continue
        if entry == PROCESSING_DIR:
            continue
        try:
            initial_metadata = entry.lstat()
        except FileNotFoundError:
            continue

        try:
            claim = _claim_incoming_artifact(entry)
            if claim is not None:
                _process_claim(claim)
        except ScannerBoundaryError:
            raise
        except ValueError as exc:
            # Malformed artifacts are ordinary terminal rejections, not service
            # failures that can pin the watcher in systemd's restart limiter.
            log.warning("REJECTED (unsafe claim): %r: %s", entry.name, exc)
            audit_log("rejected", entry.name, reason="unsafe_claim")
            try:
                current_metadata = entry.lstat()
                if (
                    current_metadata.st_dev == initial_metadata.st_dev
                    and current_metadata.st_ino == initial_metadata.st_ino
                ):
                    _discard_rejected_inbox_entry(entry)
            except FileNotFoundError:
                pass
            except OSError:
                log.exception("could not discard rejected inbox entry %r", entry.name)
        except Exception:
            log.exception("error processing %r", entry.name)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log.info("quarantine watcher starting")
    log.info("watching: %s", QUARANTINE_DIR)
    log.info("private processing: %s", PROCESSING_DIR)
    log.info("promotion staging: %s", PROMOTION_STAGING_DIR)
    log.info("registry API: %s", REGISTRY_URL)

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSING_DIR.mkdir(parents=True, exist_ok=True)
    PROMOTION_STAGING_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        scan_directory()
        time.sleep(5)


if __name__ == "__main__":
    main()

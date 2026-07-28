#!/usr/bin/env python3
"""Manage sandbox ready-generation/session state for the locked launchers.

This is an internal launcher helper. Mutating operations are supported only
while a SecAI sandbox launcher holds ``runtime/launcher.lock``.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import stat
from pathlib import Path

_GENERATION_RE = re.compile(r"[0-9a-f]{64}")
_GENERATION_MARKER_NAME = "ready-generation"
_SESSION_MARKER_NAME = "ready-session"
_CONTROL_SESSION_NAME = "control-server-session"
_STATUS_DIRECTORY_NAME = "generation-status"
_TEMP_RE = re.compile(
    r"\.(?:ready-generation|ready-session)\.[0-9]+\.[0-9a-f]{16}\.tmp"
)
_WINDOWS_REPARSE_POINT = 0x400


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & _WINDOWS_REPARSE_POINT
    )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("ready-generation write made no progress")
        view = view[written:]


def _validate_real_directory(
    path: Path,
    *,
    description: str,
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{description} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(
            f"{description} must be a real directory, not a link"
        )
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise RuntimeError(f"{description} must be owned by the launcher user")
    if os.name != "nt" and metadata.st_mode & 0o022:
        raise RuntimeError(
            f"{description} must not be writable by group or other users"
        )
    return metadata


def _ensure_status_directory(runtime_dir: Path) -> Path:
    _validate_real_directory(
        runtime_dir,
        description="sandbox runtime directory",
    )
    status_dir = runtime_dir / _STATUS_DIRECTORY_NAME
    try:
        os.mkdir(status_dir, 0o755)
        _fsync_directory(runtime_dir)
    except FileExistsError:
        pass
    _validate_real_directory(
        status_dir,
        description="sandbox generation-status directory",
    )
    if os.name != "nt":
        status_dir.chmod(0o755)
    return status_dir


def _validate_unchanged_directory(
    path: Path,
    before: os.stat_result,
    *,
    operation: str,
) -> None:
    after = _validate_real_directory(
        path,
        description="sandbox generation-status directory",
    )
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeError(
            "sandbox generation-status directory changed during "
            f"{operation}"
        )


def _validate_safe_marker_metadata(
    path: Path,
    *,
    expected_links: int = 1,
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError("sandbox ready-state marker is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_nlink != expected_links
        or (
            hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        )
        or (os.name != "nt" and metadata.st_mode & 0o022)
    ):
        raise RuntimeError(
            "sandbox ready-state marker must be an owner-controlled, "
            "singly linked regular file"
        )
    return metadata


def _read_marker(path: Path) -> str:
    metadata = _validate_safe_marker_metadata(path)
    if metadata.st_size != 64:
        raise RuntimeError(
            "sandbox ready-state marker must contain exactly 64 bytes"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or opened.st_size != 64
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or (
                hasattr(os, "geteuid")
                and opened.st_uid != os.geteuid()
            )
            or (os.name != "nt" and opened.st_mode & 0o022)
        ):
            raise RuntimeError(
                "sandbox ready-state marker changed during validation"
            )
        payload = bytearray()
        while len(payload) <= 64:
            chunk = os.read(descriptor, 65 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        generation = bytes(payload).decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "sandbox ready-state marker is not ASCII"
        ) from exc
    if not _GENERATION_RE.fullmatch(generation):
        raise RuntimeError(
            "sandbox ready-state marker must be exactly 64 lowercase "
            "hexadecimal characters"
        )
    return generation


def _read_control_session(runtime_dir: Path) -> str:
    path = runtime_dir / _CONTROL_SESSION_NAME
    metadata = _validate_safe_marker_metadata(path)
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise RuntimeError(
            "sandbox control-server session must be owner-private"
        )
    session_id = _read_marker(path)
    final_metadata = os.lstat(path)
    if (
        (final_metadata.st_dev, final_metadata.st_ino)
        != (metadata.st_dev, metadata.st_ino)
        or (
            os.name != "nt"
            and final_metadata.st_mode & 0o077
        )
    ):
        raise RuntimeError(
            "sandbox control-server session changed during validation"
        )
    return session_id


def _clean_temporary_entries(status_dir: Path) -> None:
    removed = False
    with os.scandir(status_dir) as iterator:
        entries = list(iterator)
    for entry in entries:
        if entry.name in {
            _GENERATION_MARKER_NAME,
            _SESSION_MARKER_NAME,
        }:
            continue
        if not _TEMP_RE.fullmatch(entry.name):
            raise RuntimeError(
                "sandbox generation-status directory contains an "
                "unexpected entry"
            )
        temporary = status_dir / entry.name
        _validate_safe_marker_metadata(temporary)
        temporary.unlink()
        removed = True
    if removed:
        _fsync_directory(status_dir)


def _remove_marker(status_dir: Path, marker_name: str) -> bool:
    marker = status_dir / marker_name
    try:
        _validate_safe_marker_metadata(marker)
    except FileNotFoundError:
        return False
    marker.unlink()
    _fsync_directory(status_dir)
    try:
        os.lstat(marker)
    except FileNotFoundError:
        return True
    raise RuntimeError(
        f"sandbox {marker_name} invalidation was not durable"
    )


def invalidate_ready_state(runtime_dir: Path) -> bool:
    """Atomically make the sandbox generation/session pair unready."""
    status_dir = _ensure_status_directory(runtime_dir)
    status_before = _validate_real_directory(
        status_dir,
        description="sandbox generation-status directory",
    )
    _clean_temporary_entries(status_dir)
    # Generation is the commit marker. Remove it first so every interrupted
    # invalidation is already fail-closed, then remove the session marker.
    generation_removed = _remove_marker(
        status_dir,
        _GENERATION_MARKER_NAME,
    )
    session_removed = _remove_marker(
        status_dir,
        _SESSION_MARKER_NAME,
    )
    _validate_unchanged_directory(
        status_dir,
        status_before,
        operation="invalidation",
    )
    return generation_removed or session_removed


def _publish_marker(
    status_dir: Path,
    marker_name: str,
    value: str,
) -> bool:
    marker = status_dir / marker_name
    try:
        current = _read_marker(marker)
    except FileNotFoundError:
        current = ""
    if current == value:
        return False

    temporary = status_dir / (
        f".{marker_name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        _write_all(descriptor, value.encode("ascii"))
        if os.name != "nt":
            os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if _read_marker(temporary) != value:
            raise RuntimeError(
                f"sandbox {marker_name} temporary failed validation"
            )
        os.replace(temporary, marker)
        _fsync_directory(status_dir)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if _read_marker(marker) != value:
        raise RuntimeError(
            f"sandbox {marker_name} publication was not durable"
        )
    return True


def publish_ready_state(runtime_dir: Path, generation: str) -> bool:
    """Publish a health-verified generation bound to this controller session."""
    if not _GENERATION_RE.fullmatch(generation):
        raise RuntimeError(
            "ready generation must be exactly 64 lowercase hexadecimal "
            "characters"
        )
    _validate_real_directory(
        runtime_dir,
        description="sandbox runtime directory",
    )
    session_id = _read_control_session(runtime_dir)
    status_dir = _ensure_status_directory(runtime_dir)
    status_before = _validate_real_directory(
        status_dir,
        description="sandbox generation-status directory",
    )
    _clean_temporary_entries(status_dir)
    # The session marker is installed first. The generation marker is the
    # commit point, so a crash between the two remains unready.
    session_changed = _publish_marker(
        status_dir,
        _SESSION_MARKER_NAME,
        session_id,
    )
    generation_changed = _publish_marker(
        status_dir,
        _GENERATION_MARKER_NAME,
        generation,
    )
    _validate_unchanged_directory(
        status_dir,
        status_before,
        operation="publication",
    )
    if _read_control_session(runtime_dir) != session_id:
        raise RuntimeError(
            "sandbox control-server session changed during publication"
        )
    if read_ready_state(runtime_dir) != (generation, session_id):
        raise RuntimeError("sandbox ready state was not published durably")
    return session_changed or generation_changed


def read_ready_state(runtime_dir: Path) -> tuple[str, str]:
    """Safely read a stable ready generation/session pair."""
    _validate_real_directory(
        runtime_dir,
        description="sandbox runtime directory",
    )
    status_dir = runtime_dir / _STATUS_DIRECTORY_NAME
    before = _validate_real_directory(
        status_dir,
        description="sandbox generation-status directory",
    )
    generation = _read_marker(
        status_dir / _GENERATION_MARKER_NAME
    )
    session_id = _read_marker(status_dir / _SESSION_MARKER_NAME)
    if (
        _read_marker(status_dir / _GENERATION_MARKER_NAME) != generation
        or _read_marker(status_dir / _SESSION_MARKER_NAME) != session_id
    ):
        raise RuntimeError(
            "sandbox ready state changed during validation"
        )
    after = _validate_real_directory(
        status_dir,
        description="sandbox generation-status directory",
    )
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeError(
            "sandbox generation-status directory changed during validation"
        )
    return generation, session_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("invalidate")
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--generation", required=True)
    subparsers.add_parser("read")
    args = parser.parse_args()

    runtime_dir = Path(os.path.abspath(args.runtime_dir))
    if args.action == "invalidate":
        changed = invalidate_ready_state(runtime_dir)
        print("invalidated" if changed else "already-invalid")
        return 0
    if args.action == "publish":
        changed = publish_ready_state(runtime_dir, args.generation)
        print("published" if changed else "already-ready")
        return 0
    generation, session_id = read_ready_state(runtime_dir)
    print(f"{generation} {session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

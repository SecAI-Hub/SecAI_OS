#!/usr/bin/env python3
"""Provision and validate the sandbox control token without following links."""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import secrets
import stat
import time
from pathlib import Path

_TOKEN_BYTES = 64
_WINDOWS_REPARSE_POINT = 0x400


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
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
            raise OSError("control-token write made no progress")
        view = view[written:]


def _validate_runtime_directory(runtime_dir: Path) -> None:
    metadata = os.lstat(runtime_dir)
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(
            "sandbox runtime path must be a real directory, not a link"
        )
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise RuntimeError(
            "sandbox runtime directory must be owned by the launcher user"
        )


def validate_control_token(
    path: Path,
    *,
    expected_links: int = 1,
) -> tuple[tuple[int, int], bytes]:
    """Validate the exact token file and set its POSIX bind-mount mode."""
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size != _TOKEN_BYTES
        or metadata.st_nlink != expected_links
        or (
            hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        )
    ):
        raise RuntimeError(
            "sandbox control token must be an owner-controlled, correctly "
            "linked, real 64-byte regular file"
        )

    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or opened.st_size != _TOKEN_BYTES
            or opened.st_nlink != expected_links
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or (
                hasattr(os, "geteuid")
                and opened.st_uid != os.geteuid()
            )
        ):
            raise RuntimeError(
                "sandbox control token changed during validation"
            )
        payload = os.read(descriptor, _TOKEN_BYTES + 1)
        if (
            len(payload) != _TOKEN_BYTES
            or any(octet not in b"0123456789abcdef" for octet in payload)
        ):
            raise RuntimeError(
                "sandbox control token must contain exactly 64 lowercase "
                "hexadecimal characters"
            )
        if os.name != "nt":
            # The 0700 runtime parent prevents host traversal. The direct bind
            # mount needs an other-readable bit for the fixed non-root UI UID.
            os.fchmod(descriptor, 0o604)
            os.fsync(descriptor)
        return (opened.st_dev, opened.st_ino), payload
    finally:
        os.close(descriptor)


def _windows_process_exists(pid: int) -> bool:
    process_query_limited_information = 0x1000
    synchronize = 0x00100000
    wait_object_0 = 0x00000000
    wait_timeout = 0x00000102
    error_access_denied = 5
    error_invalid_parameter = 87
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        return True
    kernel32 = loader("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(
        process_query_limited_information | synchronize,
        0,
        pid,
    )
    if not handle:
        error = ctypes.get_last_error()
        if error == error_invalid_parameter:
            return False
        if error == error_access_denied:
            return True
        return True
    try:
        wait_result = kernel32.WaitForSingleObject(handle, 0)
        if wait_result == wait_object_0:
            return False
        if wait_result == wait_timeout:
            return True
        return True
    finally:
        kernel32.CloseHandle(handle)


def _pid_is_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    if os.name == "nt":
        return _windows_process_exists(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _recover_control_token_temps(
    runtime_dir: Path,
    token_path: Path,
) -> bool:
    """Recover only verified pre-link or post-link control-token temporaries."""
    try:
        target_metadata = os.lstat(token_path)
    except FileNotFoundError:
        target_metadata = None
    pattern = re.compile(
        r"\.control-token\.(?P<pid>[0-9]+)\.[0-9a-f]{16}\.tmp"
    )
    linked_candidates: list[
        tuple[Path, tuple[int, int], bytes]
    ] = []
    removed_orphan = False
    with os.scandir(runtime_dir) as iterator:
        entries = list(iterator)
    for entry in entries:
        if not entry.name.startswith(".control-token."):
            continue
        match = pattern.fullmatch(entry.name)
        if match is None:
            raise RuntimeError(
                "sandbox control-token temporary name is malformed"
            )
        candidate = runtime_dir / entry.name
        metadata = os.lstat(candidate)
        if metadata.st_nlink == 1:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or _is_reparse_point(metadata)
                or (
                    hasattr(os, "geteuid")
                    and metadata.st_uid != os.geteuid()
                )
            ):
                raise RuntimeError(
                    "sandbox control-token temporary is unsafe"
                )
            if _pid_is_alive(int(match.group("pid"))):
                continue
            candidate.unlink()
            removed_orphan = True
            continue
        if metadata.st_nlink != 2:
            raise RuntimeError(
                "sandbox control-token temporary has an unsafe link count"
            )
        inode, payload = validate_control_token(
            candidate,
            expected_links=2,
        )
        linked_candidates.append((candidate, inode, payload))
    if removed_orphan:
        _fsync_directory(runtime_dir)

    if target_metadata is None:
        if linked_candidates:
            raise RuntimeError(
                "sandbox control-token temporary has an unknown second link"
            )
        return False
    if target_metadata.st_nlink != 2:
        if linked_candidates:
            raise RuntimeError(
                "sandbox control-token temporary does not match target state"
            )
        return False

    target_inode, target_payload = validate_control_token(
        token_path,
        expected_links=2,
    )
    matches = [
        candidate
        for candidate, inode, payload in linked_candidates
        if inode == target_inode and payload == target_payload
    ]
    if len(matches) != 1 or len(linked_candidates) != 1:
        raise RuntimeError(
            "sandbox control-token hardlink state is not a uniquely "
            "recoverable interrupted install"
        )
    matches[0].unlink()
    _fsync_directory(runtime_dir)
    validate_control_token(token_path)
    return True


def provision_control_token(runtime_dir: Path, token_path: Path) -> bool:
    """Create the token once atomically, or validate an existing token."""
    _validate_runtime_directory(runtime_dir)
    if token_path.parent != runtime_dir:
        raise RuntimeError("sandbox control token must be inside the runtime directory")

    _recover_control_token_temps(runtime_dir, token_path)
    try:
        os.lstat(token_path)
    except FileNotFoundError:
        pass
    else:
        validate_control_token(token_path)
        return False

    temporary = runtime_dir / (
        f".control-token.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = -1
    installed = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        _write_all(descriptor, secrets.token_hex(32).encode("ascii"))
        if os.name != "nt":
            os.fchmod(descriptor, 0o604)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        try:
            os.link(temporary, token_path)
            installed = True
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            _fsync_directory(runtime_dir)
        except FileExistsError:
            # A concurrent first writer wins. Never rotate it implicitly.
            for _ in range(100):
                winner = os.lstat(token_path)
                if winner.st_nlink == 1:
                    break
                if winner.st_nlink != 2:
                    break
                time.sleep(0.001)
            _recover_control_token_temps(runtime_dir, token_path)
            validate_control_token(token_path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    if installed:
        validate_control_token(token_path)
    return installed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--token-path", required=True)
    args = parser.parse_args()

    # Do not resolve either argument: resolution would follow an attacker-
    # controlled final symlink before the no-follow checks can reject it.
    runtime_dir = Path(os.path.abspath(args.runtime_dir))
    token_path = Path(os.path.abspath(args.token_path))
    created = provision_control_token(runtime_dir, token_path)
    print("created" if created else "existing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

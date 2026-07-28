#!/usr/bin/env python3
"""Internal launcher helper for sandbox runtime generations.

Mutating mode is supported only when a SecAI sandbox launcher invokes this
helper while holding ``runtime/launcher.lock`` after quiescing the project.
Direct or concurrent mutating invocation is unsupported. ``--read-active`` is
the read-only inspection mode.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

TARGET_CREDENTIALS = (
    "airlock",
    "agent",
    "agent-audit",
    "agent-signing",
    "diffusion",
    "policy-engine",
    "registry",
    "quarantine-audit",
    "search-mediator",
    "search-mediator-audit",
    "searxng",
    "tool-firewall",
    "ui-audit",
    "ui-flask",
    "ui-setup",
)
_CREDENTIAL_BYTES = 64
_WINDOWS_REPARSE_POINT = 0x400
_GENERATION_RE = re.compile(r"[0-9a-f]{64}")
_STAGE_RE = re.compile(r"\.render-stage-[0-9]+-[0-9a-f]{16}")
_ACTIVE_TEMP_RE = re.compile(
    r"\.active-generation\.[0-9]+\.[0-9a-f]{16}\.tmp"
)
_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_TREE_BYTES = 32 * 1024 * 1024
_GENERATION_FORMAT = 1


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


def _validate_real_directory(
    path: Path,
    *,
    description: str,
    require_owner: bool = False,
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{description} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(
            f"{description} must be a real directory, not a link"
        )
    if (
        require_owner
        and hasattr(os, "geteuid")
        and metadata.st_uid != os.geteuid()
    ):
        raise RuntimeError(f"{description} must be owned by the launcher user")
    return metadata


def _read_verified_regular(
    path: Path,
    *,
    description: str,
    maximum_size: int = _MAX_SOURCE_FILE_BYTES,
    require_owner: bool = False,
    require_single_link: bool = False,
) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{description} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size > maximum_size
        or (require_single_link and metadata.st_nlink != 1)
        or (
            require_owner
            and hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        )
    ):
        raise RuntimeError(
            f"{description} must be a bounded, real regular file"
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
            or opened.st_size > maximum_size
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or (require_single_link and opened.st_nlink != 1)
            or (
                require_owner
                and hasattr(os, "geteuid")
                and opened.st_uid != os.geteuid()
            )
        ):
            raise RuntimeError(f"{description} changed during validation")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_size:
            chunk = os.read(
                descriptor,
                min(65536, maximum_size + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_size:
            raise RuntimeError(f"{description} exceeds the size limit")
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or (after.st_dev, after.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(f"{description} changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise RuntimeError(f"{description} could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_source_tree(root: Path, *, label: str) -> dict[str, bytes]:
    """Read only real regular files from a verified source directory."""
    _validate_real_directory(root, description=label)
    files: dict[str, bytes] = {}
    total = 0

    def visit(directory: Path, relative: Path) -> None:
        nonlocal total
        before = _validate_real_directory(
            directory,
            description=f"{label} directory",
        )
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise RuntimeError(f"{label} directory could not be listed") from exc
        for entry in entries:
            if entry.name in {"", ".", ".."}:
                raise RuntimeError(f"{label} contains an invalid path")
            child = directory / entry.name
            child_relative = relative / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(
                    f"{label} entry is unavailable: {child_relative.as_posix()}"
                ) from exc
            if _is_reparse_point(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(
                    f"{label} must not contain links: "
                    f"{child_relative.as_posix()}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                visit(child, child_relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    f"{label} contains a non-regular entry: "
                    f"{child_relative.as_posix()}"
                )
            payload = _read_verified_regular(
                child,
                description=(
                    f"{label} file {child_relative.as_posix()}"
                ),
            )
            total += len(payload)
            if total > _MAX_SOURCE_TREE_BYTES:
                raise RuntimeError(f"{label} exceeds the total size limit")
            files[child_relative.as_posix()] = payload
        after = os.lstat(directory)
        if (
            not stat.S_ISDIR(after.st_mode)
            or _is_reparse_point(after)
            or (after.st_dev, after.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"{label} changed while being read")

    visit(root, Path())
    if not files:
        raise RuntimeError(f"{label} must contain at least one regular file")
    return files


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("credential write made no progress")
        view = view[written:]


def _validate_existing_credential(
    path: Path,
    *,
    expected_links: int = 1,
) -> tuple[tuple[int, int], bytes]:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"credential path is unavailable: {path.name}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size != _CREDENTIAL_BYTES
        or metadata.st_nlink != expected_links
        or (
            hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        )
    ):
        raise RuntimeError(
            "credential must be an owner-controlled, correctly linked, real "
            f"64-byte regular file: {path.name}"
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
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_nlink != expected_links
            or (
                hasattr(os, "geteuid")
                and opened.st_uid != os.geteuid()
            )
        ):
            raise RuntimeError(
                f"credential changed during validation: {path.name}"
            )
        payload = os.read(descriptor, _CREDENTIAL_BYTES + 1)
        if (
            len(payload) != _CREDENTIAL_BYTES
            or any(octet not in b"0123456789abcdef" for octet in payload)
        ):
            raise RuntimeError(
                "credential must contain exactly 64 lowercase hexadecimal "
                f"characters: {path.name}"
            )
        if os.name != "nt":
            os.fchmod(descriptor, 0o644)
        return (opened.st_dev, opened.st_ino), payload
    except OSError as exc:
        raise RuntimeError(f"credential could not be read safely: {path.name}") from exc
    finally:
        if descriptor >= 0:
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
    except (OSError, PermissionError):
        return True
    return True


def _recover_credential_temps(
    credentials_dir: Path,
    target: Path,
) -> bool:
    """Recover only verified pre-link or post-link credential temporaries."""
    try:
        target_metadata = os.lstat(target)
    except FileNotFoundError:
        target_metadata = None
    pattern = re.compile(
        rf"\.{re.escape(target.name)}\.(?P<pid>[0-9]+)\."
        r"[0-9a-f]{16}\.tmp"
    )
    prefix = f".{target.name}."
    linked_candidates: list[
        tuple[Path, tuple[int, int], bytes]
    ] = []
    removed_orphan = False
    with os.scandir(credentials_dir) as iterator:
        entries = list(iterator)
    for entry in entries:
        if not entry.name.startswith(prefix):
            continue
        match = pattern.fullmatch(entry.name)
        if match is None:
            raise RuntimeError(
                f"credential temporary name is malformed: {target.name}"
            )
        candidate = credentials_dir / entry.name
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
                    f"credential temporary is unsafe: {target.name}"
                )
            if _pid_is_alive(int(match.group("pid"))):
                continue
            candidate.unlink()
            removed_orphan = True
            continue
        if metadata.st_nlink != 2:
            raise RuntimeError(
                f"credential temporary has an unsafe link count: {target.name}"
            )
        inode, payload = _validate_existing_credential(
            candidate,
            expected_links=2,
        )
        linked_candidates.append((candidate, inode, payload))
    if removed_orphan:
        _fsync_directory(credentials_dir)

    if target_metadata is None:
        if linked_candidates:
            raise RuntimeError(
                "credential temporary has a second unknown hardlink: "
                f"{target.name}"
            )
        return False
    if target_metadata.st_nlink != 2:
        if linked_candidates:
            raise RuntimeError(
                "credential temporary does not match the target link state: "
                f"{target.name}"
            )
        return False

    target_inode, target_payload = _validate_existing_credential(
        target,
        expected_links=2,
    )
    matches = [
        candidate
        for candidate, inode, payload in linked_candidates
        if inode == target_inode and payload == target_payload
    ]
    if len(matches) != 1 or len(linked_candidates) != 1:
        raise RuntimeError(
            "credential hardlink state is not a uniquely recoverable "
            f"interrupted install: {target.name}"
        )
    matches[0].unlink()
    _fsync_directory(credentials_dir)
    _validate_existing_credential(target)
    return True


def _create_credential_atomic(credentials_dir: Path, target: Path) -> None:
    payload = secrets.token_hex(32).encode("ascii")
    temporary = credentials_dir / (
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
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
        _write_all(descriptor, payload)
        if os.name != "nt":
            os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if os.name == "nt":
            temporary.chmod(0o644)

        try:
            os.link(temporary, target)
            installed = True
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            _fsync_directory(credentials_dir)
        except FileExistsError:
            # A first-writer race must never rotate a credential. Validate the
            # winner rather than treating any non-empty file as trustworthy.
            # Give an active winner a short window to remove its install link
            # before invoking interrupted-install recovery.
            for _ in range(100):
                winner = os.lstat(target)
                if winner.st_nlink == 1:
                    break
                if winner.st_nlink != 2:
                    break
                time.sleep(0.001)
            _recover_credential_temps(credentials_dir, target)
            _validate_existing_credential(target)
    except OSError as exc:
        raise RuntimeError(
            f"credential could not be created atomically: {target.name}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    if installed:
        _validate_existing_credential(target)


def _provision_target_credentials(runtime_dir: Path) -> None:
    """Create independent service credentials without rotating existing ones."""
    credentials_dir = runtime_dir / "credentials"
    try:
        metadata = os.lstat(credentials_dir)
    except FileNotFoundError:
        try:
            os.mkdir(credentials_dir, 0o700)
        except FileExistsError:
            pass
        metadata = os.lstat(credentials_dir)
        _fsync_directory(credentials_dir.parent)
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError(
            "sandbox credentials path must be a real directory"
        )
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise RuntimeError(
            "sandbox credentials directory must be owned by the launcher user"
        )
    credentials_dir.chmod(0o700)

    seen_inodes: dict[tuple[int, int], str] = {}
    seen_payloads: dict[bytes, str] = {}
    for service in TARGET_CREDENTIALS:
        target = credentials_dir / f"{service}.token"
        _recover_credential_temps(credentials_dir, target)
        try:
            os.lstat(target)
        except FileNotFoundError:
            _create_credential_atomic(credentials_dir, target)
        # The parent credentials directory is 0700 on POSIX. The file itself
        # must be readable by the fixed non-root UID in the one container where
        # Compose bind-mounts it directly. Windows launchers apply an explicit
        # owner-only DACL to the directory and each credential after rendering.
        inode, payload = _validate_existing_credential(target)
        if inode in seen_inodes:
            raise RuntimeError(
                "sandbox credentials must use distinct files: "
                f"{service}.token aliases {seen_inodes[inode]}.token"
            )
        if payload in seen_payloads:
            raise RuntimeError(
                "sandbox credentials must contain independent values: "
                f"{service}.token duplicates {seen_payloads[payload]}.token"
            )
        seen_inodes[inode] = service
        seen_payloads[payload] = service


def _generation_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(b"SecAI_OS sandbox runtime generation v1\0")
    for relative_path in sorted(files):
        encoded_path = relative_path.encode("utf-8")
        payload = files[relative_path]
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _generation_manifest(
    generation: str,
    files: dict[str, bytes],
) -> bytes:
    manifest = {
        "files": [
            {
                "path": relative_path,
                "sha256": hashlib.sha256(files[relative_path]).hexdigest(),
                "size": len(files[relative_path]),
            }
            for relative_path in sorted(files)
        ],
        "generation": generation,
        "version": _GENERATION_FORMAT,
    }
    return (
        json.dumps(
            manifest,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _expected_directories(files: dict[str, bytes]) -> set[str]:
    directories: set[str] = set()
    for relative_path in files:
        parts = Path(relative_path).parts
        if (
            not parts
            or Path(relative_path).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RuntimeError(
                f"runtime generation contains an invalid path: {relative_path}"
            )
        for length in range(1, len(parts)):
            directories.add(Path(*parts[:length]).as_posix())
    return directories


def _validate_generation_structure(files: dict[str, bytes]) -> None:
    if (
        "policy/policy.yaml" not in files
        or "config/appliance.yaml" not in files
        or "model-catalog.yaml" not in files
        or "profile.json" not in files
    ):
        raise RuntimeError(
            "runtime generation is missing a required policy, config, "
            "catalog, or profile file"
        )
    for relative_path in files:
        if relative_path in {"model-catalog.yaml", "profile.json"}:
            continue
        if not (
            relative_path.startswith("policy/")
            or relative_path.startswith("config/")
        ):
            raise RuntimeError(
                f"runtime generation contains an unexpected path: {relative_path}"
            )
    _expected_directories(files)


def _safe_remove_stage_tree(path: Path) -> None:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse_point(metadata)
        or (
            hasattr(os, "geteuid")
            and metadata.st_uid != os.geteuid()
        )
    ):
        raise RuntimeError(
            f"abandoned render stage is not safe to remove: {path.name}"
        )
    if os.name != "nt":
        path.chmod(0o700)
    with os.scandir(path) as iterator:
        entries = list(iterator)
    for entry in entries:
        child = path / entry.name
        child_metadata = entry.stat(follow_symlinks=False)
        if _is_reparse_point(child_metadata) or stat.S_ISLNK(
            child_metadata.st_mode
        ):
            raise RuntimeError(
                f"abandoned render stage contains a link: {path.name}"
            )
        if (
            hasattr(os, "geteuid")
            and child_metadata.st_uid != os.geteuid()
        ):
            raise RuntimeError(
                f"abandoned render stage contains an unowned entry: {path.name}"
            )
        if stat.S_ISDIR(child_metadata.st_mode):
            _safe_remove_stage_tree(child)
        elif stat.S_ISREG(child_metadata.st_mode):
            child.unlink()
        else:
            raise RuntimeError(
                f"abandoned render stage contains a special entry: {path.name}"
            )
    path.rmdir()


def _clean_abandoned_stages(runtime_dir: Path) -> None:
    with os.scandir(runtime_dir) as iterator:
        entries = list(iterator)
    for entry in entries:
        if _STAGE_RE.fullmatch(entry.name):
            _safe_remove_stage_tree(runtime_dir / entry.name)
        elif _ACTIVE_TEMP_RE.fullmatch(entry.name):
            temporary = runtime_dir / entry.name
            metadata = os.lstat(temporary)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or _is_reparse_point(metadata)
                or metadata.st_nlink != 1
                or (
                    hasattr(os, "geteuid")
                    and metadata.st_uid != os.geteuid()
                )
            ):
                raise RuntimeError(
                    "abandoned active-generation temporary is unsafe"
                )
            temporary.unlink()
    _fsync_directory(runtime_dir)


def _clean_abandoned_generation_stages(generations_dir: Path) -> None:
    with os.scandir(generations_dir) as iterator:
        entries = list(iterator)
    for entry in entries:
        if _STAGE_RE.fullmatch(entry.name):
            _safe_remove_stage_tree(generations_dir / entry.name)
    _fsync_directory(generations_dir)


def _ensure_real_directory(
    path: Path,
    *,
    mode: int,
    description: str,
) -> None:
    try:
        os.mkdir(path, mode)
        _fsync_directory(path.parent)
    except FileExistsError:
        pass
    _validate_real_directory(
        path,
        description=description,
        require_owner=True,
    )
    if os.name != "nt":
        path.chmod(mode)


def _write_stage_file(path: Path, payload: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        _write_all(descriptor, payload)
        if os.name != "nt":
            os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _scan_generation(path: Path) -> tuple[set[str], dict[str, bytes]]:
    _validate_real_directory(
        path,
        description=f"runtime generation {path.name}",
        require_owner=True,
    )
    directories: set[str] = set()
    files: dict[str, bytes] = {}

    def visit(directory: Path, relative: Path) -> None:
        before = _validate_real_directory(
            directory,
            description=f"runtime generation directory {relative.as_posix()}",
            require_owner=True,
        )
        if os.name != "nt" and before.st_mode & 0o222:
            raise RuntimeError(
                f"runtime generation directory is writable: "
                f"{relative.as_posix()}"
            )
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            child = directory / entry.name
            child_relative = relative / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if _is_reparse_point(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(
                    "runtime generation must not contain links: "
                    f"{child_relative.as_posix()}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(child_relative.as_posix())
                visit(child, child_relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    "runtime generation contains a special entry: "
                    f"{child_relative.as_posix()}"
                )
            if os.name != "nt" and metadata.st_mode & 0o222:
                raise RuntimeError(
                    "runtime generation file is writable: "
                    f"{child_relative.as_posix()}"
                )
            files[child_relative.as_posix()] = _read_verified_regular(
                child,
                description=(
                    "runtime generation file "
                    f"{child_relative.as_posix()}"
                ),
                require_owner=True,
                require_single_link=True,
            )
        after = os.lstat(directory)
        if (
            not stat.S_ISDIR(after.st_mode)
            or _is_reparse_point(after)
            or (after.st_dev, after.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError("runtime generation changed during validation")

    visit(path, Path())
    return directories, files


def _validate_existing_generation(
    generation_dir: Path,
    expected: dict[str, bytes],
) -> None:
    expected_directories = _expected_directories(expected)
    actual_directories, actual_files = _scan_generation(generation_dir)
    if actual_directories != expected_directories:
        raise RuntimeError(
            f"runtime generation has stale or missing directories: "
            f"{generation_dir.name}"
        )
    if actual_files.keys() != expected.keys():
        raise RuntimeError(
            f"runtime generation has stale or missing files: "
            f"{generation_dir.name}"
        )
    for relative_path, expected_payload in expected.items():
        if actual_files[relative_path] != expected_payload:
            raise RuntimeError(
                "runtime generation content does not match its digest: "
                f"{generation_dir.name}"
            )


def _stage_generation(
    generations_dir: Path,
    generation: str,
    files: dict[str, bytes],
) -> Path:
    expected = dict(files)
    expected["generation.json"] = _generation_manifest(generation, files)
    destination = generations_dir / generation
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        _validate_existing_generation(destination, expected)
        return destination

    stage = generations_dir / (
        f".render-stage-{os.getpid()}-{secrets.token_hex(8)}"
    )
    os.mkdir(stage, 0o700)
    try:
        directories = _expected_directories(expected)
        for relative_directory in sorted(
            directories,
            key=lambda value: (len(Path(value).parts), value),
        ):
            os.mkdir(stage / relative_directory, 0o755)
        for relative_path in sorted(expected):
            _write_stage_file(stage / relative_path, expected[relative_path])
        if os.name != "nt":
            for relative_directory in sorted(
                directories,
                key=lambda value: len(Path(value).parts),
                reverse=True,
            ):
                (stage / relative_directory).chmod(0o555)
            stage.chmod(0o555)
        for directory in {stage, *(stage / value for value in directories)}:
            _fsync_directory(directory)

        try:
            os.rename(stage, destination)
        except OSError:
            try:
                os.lstat(destination)
            except FileNotFoundError:
                raise
            _validate_existing_generation(destination, expected)
            _safe_remove_stage_tree(stage)
        _fsync_directory(generations_dir)
    except BaseException:
        try:
            os.lstat(stage)
        except FileNotFoundError:
            pass
        else:
            _safe_remove_stage_tree(stage)
        raise

    _validate_existing_generation(destination, expected)
    return destination


def read_active_generation(runtime_dir: Path) -> str:
    path = runtime_dir / "active-generation"
    payload = _read_verified_regular(
        path,
        description="sandbox active-generation pointer",
        maximum_size=64,
        require_owner=True,
        require_single_link=True,
    )
    try:
        generation = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "sandbox active-generation pointer is not ASCII"
        ) from exc
    if not _GENERATION_RE.fullmatch(generation):
        raise RuntimeError(
            "sandbox active-generation pointer must be exactly 64 lowercase "
            "hexadecimal characters"
        )
    return generation


def _publish_active_generation(runtime_dir: Path, generation: str) -> None:
    active_path = runtime_dir / "active-generation"
    try:
        os.lstat(active_path)
    except FileNotFoundError:
        current = ""
    else:
        current = read_active_generation(runtime_dir)
    if current == generation:
        return

    temporary = runtime_dir / (
        f".active-generation.{os.getpid()}.{secrets.token_hex(8)}.tmp"
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
        _write_all(descriptor, generation.encode("ascii"))
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, active_path)
        _fsync_directory(runtime_dir)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if read_active_generation(runtime_dir) != generation:
        raise RuntimeError("sandbox active-generation publication was not durable")


def _reject_legacy_render_links(runtime_dir: Path) -> None:
    state_dir = runtime_dir / "state"
    try:
        state_metadata = os.lstat(state_dir)
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISDIR(state_metadata.st_mode)
            or _is_reparse_point(state_metadata)
        ):
            raise RuntimeError(
                "sandbox runtime state path must be a real directory"
            )
    for relative_path in (
        "policy",
        "config",
        "model-catalog.yaml",
        "state/profile.json",
    ):
        path = runtime_dir / relative_path
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise RuntimeError(
                "legacy sandbox runtime output must not be a link: "
                f"{relative_path}"
            )


_BLOCK_MAPPING_RE = re.compile(
    r"^(?P<indent> *)(?P<key>"
    r'"(?:\\.|[^"])*"|'
    r"'(?:''|[^'])*'|"
    r"[A-Za-z0-9_-]+"
    r")\s*:(?P<value>.*)$"
)


def _decoded_yaml_key(raw_key: str) -> str:
    if raw_key.startswith('"'):
        try:
            decoded = json.loads(raw_key)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid double-quoted YAML mapping key") from exc
        return decoded if isinstance(decoded, str) else ""
    if raw_key.startswith("'"):
        return raw_key[1:-1].replace("''", "'")
    return raw_key


def _reject_ambiguous_yaml_key_features(lines: list[str]) -> None:
    """Reject YAML key features that can alias or retag protected keys."""
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # The packaged runtime documents do not need tags, anchors, aliases,
        # merge keys, or explicit/complex mapping keys. Those features can
        # construct a duplicate semantic key that a line-oriented renderer
        # cannot safely disambiguate without a full duplicate-preserving parser.
        code = line.split("#", 1)[0]
        if (
            re.search(r"(^|[\s:\-\[,])[&*][A-Za-z0-9_-]+", code)
            or "!" in code
            or re.match(r"^\s*\?", code)
            or re.search(r"(^|\s)<<\s*:", code)
        ):
            raise ValueError(
                "runtime YAML must not use tags, anchors, aliases, merge "
                "keys, or explicit mapping keys"
            )


def _target_mapping_location(
    lines: list[str],
    section: str,
    key: str,
) -> int:
    _reject_ambiguous_yaml_key_features(lines)
    section_matches: list[tuple[int, re.Match[str]]] = []
    for index, line in enumerate(lines):
        if (
            line
            and not line.startswith((" ", "\t", "#"))
            and not _BLOCK_MAPPING_RE.match(line)
        ):
            raise ValueError(
                f"{section}.{key} requires a plain block-mapping document"
            )
        match = _BLOCK_MAPPING_RE.match(line)
        if match and not match.group("indent"):
            if _decoded_yaml_key(match.group("key")) == section:
                section_matches.append((index, match))
        elif re.match(
            rf"^\?\s*(?:{re.escape(section)}|"
            rf"'{re.escape(section)}'|\"{re.escape(section)}\")\s*$",
            line,
        ):
            raise ValueError(
                f"{section}.{key} must use an unquoted block mapping"
            )
    if len(section_matches) != 1:
        raise ValueError(
            f"{section}.{key} requires exactly one top-level {section} section"
        )
    section_index, section_match = section_matches[0]
    if (
        lines[section_index] != f"{section}:"
        or section_match.group("value")
    ):
        raise ValueError(
            f"{section}.{key} must use an unquoted block-style section"
        )

    child_matches: list[tuple[int, re.Match[str]]] = []
    for index in range(section_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            break
        match = _BLOCK_MAPPING_RE.match(line)
        if (
            match
            and len(match.group("indent")) == 2
            and _decoded_yaml_key(match.group("key")) == key
        ):
            child_matches.append((index, match))
    if len(child_matches) != 1:
        raise ValueError(
            f"{section}.{key} requires exactly one direct child key"
        )
    child_index, child_match = child_matches[0]
    if not lines[child_index].startswith(f"  {key}:"):
        raise ValueError(
            f"{section}.{key} must use an unquoted direct child key"
        )
    existing_value = child_match.group("value").lstrip()
    if not existing_value or existing_value.startswith(
        ("|", ">", "{", "[", "&", "*", "!")
    ):
        raise ValueError(
            f"{section}.{key} must use an unambiguous scalar value"
        )
    return child_index


def _replace_in_section(text: str, section: str, key: str, value: str) -> str:
    lines = text.splitlines()
    target_index = _target_mapping_location(lines, section, key)
    lines[target_index] = f"  {key}: {value}"
    rendered = "\n".join(lines) + "\n"

    # Validate the rendered form again. This catches duplicate or ambiguous
    # structures before the generation digest can make them authoritative.
    rendered_lines = rendered.splitlines()
    verified_index = _target_mapping_location(
        rendered_lines,
        section,
        key,
    )
    if rendered_lines[verified_index] != f"  {key}: {value}":
        raise ValueError(f"failed to verify rendered {section}.{key}")
    return rendered


def _derive_profile(*, enable_search: bool, enable_airlock: bool, enable_diffusion: bool) -> str:
    """Map the selected compose features to the closest supported profile."""
    if enable_diffusion:
        return "full_lab"
    if enable_search or enable_airlock:
        return "research"
    return "offline_private"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root")
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--read-active", action="store_true")
    parser.add_argument("--enable-search", action="store_true")
    parser.add_argument("--enable-airlock", action="store_true")
    parser.add_argument("--enable-diffusion", action="store_true")
    args = parser.parse_args()

    # Lexical normalization keeps the final runtime component available for
    # lstat validation. Path.resolve() would follow an attacker-controlled
    # runtime symlink before the renderer could reject it.
    runtime_dir = Path(os.path.abspath(args.runtime_dir))
    _validate_real_directory(
        runtime_dir,
        description="sandbox runtime directory",
        require_owner=True,
    )
    if args.read_active:
        print(read_active_generation(runtime_dir))
        return 0
    if not args.repo_root:
        parser.error("--repo-root is required unless --read-active is used")
    repo_root = Path(os.path.abspath(args.repo_root))

    _reject_legacy_render_links(runtime_dir)
    _clean_abandoned_stages(runtime_dir)

    source_policy = repo_root / "files" / "system" / "etc" / "secure-ai" / "policy"
    source_config = repo_root / "files" / "system" / "etc" / "secure-ai" / "config"
    source_catalog = repo_root / "files" / "system" / "etc" / "secure-ai" / "model-catalog.yaml"

    _provision_target_credentials(runtime_dir)
    policy_source_files = _read_source_tree(
        source_policy,
        label="sandbox policy source",
    )
    config_source_files = _read_source_tree(
        source_config,
        label="sandbox config source",
    )
    catalog_payload = _read_verified_regular(
        source_catalog,
        description="sandbox model catalog source",
    )
    try:
        policy_text = policy_source_files["policy.yaml"].decode("utf-8")
        config_text = config_source_files["appliance.yaml"].decode("utf-8")
    except KeyError as exc:
        raise RuntimeError(
            "sandbox source tree is missing policy.yaml or appliance.yaml"
        ) from exc
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "sandbox policy and appliance config must be valid UTF-8"
        ) from exc
    airlock_enabled = args.enable_airlock or args.enable_search

    policy_text = _replace_in_section(
        policy_text, "search", "enabled", "true" if args.enable_search else "false"
    )
    policy_text = _replace_in_section(
        policy_text, "airlock", "enabled", "true" if airlock_enabled else "false"
    )
    config_text = _replace_in_section(
        config_text,
        "appliance",
        "mode",
        '"online-augmented"' if (args.enable_search or airlock_enabled) else '"local-only"',
    )

    profile = _derive_profile(
        enable_search=args.enable_search,
        enable_airlock=airlock_enabled,
        enable_diffusion=args.enable_diffusion,
    )
    policy_source_files["policy.yaml"] = policy_text.encode("utf-8")
    config_source_files["appliance.yaml"] = config_text.encode("utf-8")

    generation_files = {
        **{
            f"policy/{relative_path}": payload
            for relative_path, payload in policy_source_files.items()
        },
        **{
            f"config/{relative_path}": payload
            for relative_path, payload in config_source_files.items()
        },
        "model-catalog.yaml": catalog_payload,
        "profile.json": (
            json.dumps(
                {"active": profile},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    }
    _validate_generation_structure(generation_files)
    generation = _generation_digest(generation_files)

    generations_dir = runtime_dir / "generations"
    _ensure_real_directory(
        generations_dir,
        mode=0o700,
        description="sandbox runtime generations directory",
    )
    _clean_abandoned_generation_stages(generations_dir)
    _stage_generation(
        generations_dir,
        generation,
        generation_files,
    )
    _publish_active_generation(runtime_dir, generation)
    print(generation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

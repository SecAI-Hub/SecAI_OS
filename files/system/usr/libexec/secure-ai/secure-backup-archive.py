#!/usr/bin/env python3
"""Create, validate, extract, and apply SecAI OS backup archives safely.

The shell-facing backup and restore commands intentionally delegate archive
handling to this module.  In particular, this code never calls ``tar`` to
extract attacker-controlled input: member names and types are validated,
decompressed sizes are bounded, every payload is matched to the signed
manifest, and restored ownership/modes are chosen locally rather than trusted
from the archive.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator


FORMAT_VERSION = 2
MAX_ARCHIVE_BYTES = 64 * 1024**3
MAX_TOTAL_BYTES = 64 * 1024**3
MAX_FILE_BYTES = 16 * 1024**3
MAX_FILES = 50_000
MAX_MANIFEST_BYTES = 8 * 1024**2
COPY_CHUNK = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+@=-]+$")
CATEGORIES = frozenset({"full", "config", "logs", "keys"})


class ArchiveError(RuntimeError):
    """Raised when an archive or restore plan violates the backup format."""


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ArchiveError("archive member has an invalid path length")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise ArchiveError(f"unsafe archive member path: {value!r}")
    path = PurePosixPath(value)
    if str(path) != value:
        raise ArchiveError(f"non-canonical archive member path: {value!r}")
    if len(path.parts) == 0:
        raise ArchiveError("empty archive member path")
    for part in path.parts:
        if part in {"", ".", ".."} or len(part.encode("utf-8")) > 255:
            raise ArchiveError(f"unsafe archive member path: {value!r}")
        if not SEGMENT_RE.fullmatch(part):
            raise ArchiveError(f"unsupported characters in archive path: {value!r}")
    return value


def _iter_source_files(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        raise ArchiveError(f"staging root is not a real directory: {root}")

    count = 0
    total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*dirs, *files]:
            candidate = current_path / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ArchiveError(f"symbolic links are not permitted: {candidate}")
            if name in dirs and not stat.S_ISDIR(metadata.st_mode):
                raise ArchiveError(f"non-directory encountered while walking: {candidate}")

        dirs.sort()
        files.sort()
        for name in files:
            source = current_path / name
            metadata = source.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ArchiveError(f"only regular files may be backed up: {source}")
            relative = _validate_relative_path(source.relative_to(root).as_posix())
            if relative == "manifest.json":
                raise ArchiveError("staging input must not supply manifest.json")
            if metadata.st_size > MAX_FILE_BYTES:
                raise ArchiveError(f"file exceeds per-file limit: {relative}")
            count += 1
            total += metadata.st_size
            if count > MAX_FILES:
                raise ArchiveError("backup exceeds file-count limit")
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError("backup exceeds decompressed-size limit")
            yield relative, source, metadata


class _HashingReader:
    def __init__(self, handle: BinaryIO):
        self.handle = handle
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        data = self.handle.read(size)
        self.digest.update(data)
        self.bytes_read += len(data)
        return data


def _open_source_no_follow(path: Path) -> BinaryIO:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    handle = os.fdopen(descriptor, "rb", closefd=True)
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        handle.close()
        raise ArchiveError(f"source changed to a non-regular file: {path}")
    return handle


def create_archive(root: Path, output: Path, category: str, luks_uuid: str | None) -> dict:
    if category not in CATEGORIES:
        raise ArchiveError(f"unsupported backup category: {category}")
    if luks_uuid is not None and not UUID_RE.fullmatch(luks_uuid):
        raise ArchiveError("invalid LUKS UUID metadata")
    if output.exists() or output.is_symlink():
        raise ArchiveError(f"refusing to overwrite archive: {output}")
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ArchiveError(f"archive parent is not a real directory: {output.parent}")

    sources = list(_iter_source_files(root))
    files_manifest: dict[str, dict[str, int | str]] = {}
    output_fd = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(output_fd, "wb", closefd=True) as raw_output:
            with tarfile.open(fileobj=raw_output, mode="w:gz", compresslevel=9) as archive:
                for relative, source, original_stat in sources:
                    with _open_source_no_follow(source) as source_handle:
                        opened_stat = os.fstat(source_handle.fileno())
                        if (
                            opened_stat.st_dev != original_stat.st_dev
                            or opened_stat.st_ino != original_stat.st_ino
                            or opened_stat.st_size != original_stat.st_size
                        ):
                            raise ArchiveError(f"source changed during backup: {relative}")

                        member = tarfile.TarInfo(relative)
                        member.size = opened_stat.st_size
                        member.mode = 0o600
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mtime = int(opened_stat.st_mtime)
                        reader = _HashingReader(source_handle)
                        archive.addfile(member, reader)
                        if reader.bytes_read != member.size:
                            raise ArchiveError(f"short read while archiving: {relative}")
                        files_manifest[relative] = {
                            "sha256": reader.digest.hexdigest(),
                            "size": reader.bytes_read,
                        }

                manifest = {
                    "format": "secai-backup",
                    "format_version": FORMAT_VERSION,
                    "category": category,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "source_host": os.uname().nodename,
                    "file_count": len(files_manifest),
                    "total_size": sum(int(item["size"]) for item in files_manifest.values()),
                    "luks_header": {
                        "included": "luks-header-backup" in files_manifest,
                        "uuid": luks_uuid or "",
                    },
                    "files": files_manifest,
                }
                encoded_manifest = (
                    json.dumps(
                        manifest,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                    + b"\n"
                )
                if len(encoded_manifest) > MAX_MANIFEST_BYTES:
                    raise ArchiveError("generated manifest exceeds size limit")
                manifest_member = tarfile.TarInfo("manifest.json")
                manifest_member.size = len(encoded_manifest)
                manifest_member.mode = 0o600
                manifest_member.uid = 0
                manifest_member.gid = 0
                manifest_member.uname = ""
                manifest_member.gname = ""
                manifest_member.mtime = int(datetime.now().timestamp())
                from io import BytesIO

                archive.addfile(manifest_member, BytesIO(encoded_manifest))
            raw_output.flush()
            os.fsync(raw_output.fileno())
    except Exception:
        try:
            output.unlink()
        except FileNotFoundError:
            pass
        raise
    os.chmod(output, 0o600)
    return manifest


def _read_member_bounded(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if member.size > MAX_MANIFEST_BYTES:
        raise ArchiveError("manifest exceeds size limit")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ArchiveError(f"could not read archive member: {member.name}")
    data = extracted.read(member.size + 1)
    if len(data) != member.size:
        raise ArchiveError(f"short archive member: {member.name}")
    if len(data) > member.size:
        raise ArchiveError(f"archive member exceeds declared size: {member.name}")
    return data


def _hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> tuple[str, int]:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ArchiveError(f"could not read archive member: {member.name}")
    digest = hashlib.sha256()
    remaining = member.size
    total = 0
    while remaining:
        chunk = extracted.read(min(COPY_CHUNK, remaining))
        if not chunk:
            raise ArchiveError(f"short archive member: {member.name}")
        digest.update(chunk)
        total += len(chunk)
        remaining -= len(chunk)
    if extracted.read(1):
        raise ArchiveError(f"archive member exceeds declared size: {member.name}")
    return digest.hexdigest(), total


def _validate_manifest(manifest: object, actual: dict[str, dict[str, int | str]]) -> dict:
    if not isinstance(manifest, dict):
        raise ArchiveError("manifest must be a JSON object")
    required_top = {
        "format",
        "format_version",
        "category",
        "created_at",
        "source_host",
        "file_count",
        "total_size",
        "luks_header",
        "files",
    }
    if set(manifest) != required_top:
        raise ArchiveError("manifest has missing or unexpected fields")
    if manifest["format"] != "secai-backup" or manifest["format_version"] != FORMAT_VERSION:
        raise ArchiveError("unsupported backup format")
    if manifest["category"] not in CATEGORIES:
        raise ArchiveError("manifest has an invalid backup category")
    if not isinstance(manifest["created_at"], str) or len(manifest["created_at"]) > 128:
        raise ArchiveError("manifest has an invalid creation time")
    if not isinstance(manifest["source_host"], str) or len(manifest["source_host"]) > 255:
        raise ArchiveError("manifest has an invalid source host")

    declared = manifest["files"]
    if not isinstance(declared, dict) or len(declared) > MAX_FILES:
        raise ArchiveError("manifest files field is invalid")
    normalized: dict[str, dict[str, int | str]] = {}
    declared_total = 0
    for raw_path, raw_info in declared.items():
        path = _validate_relative_path(raw_path)
        if path == "manifest.json":
            raise ArchiveError("manifest cannot inventory itself")
        if not isinstance(raw_info, dict) or set(raw_info) != {"sha256", "size"}:
            raise ArchiveError(f"invalid manifest entry for {path}")
        digest = raw_info["sha256"]
        size = raw_info["size"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ArchiveError(f"invalid SHA-256 for {path}")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES:
            raise ArchiveError(f"invalid size for {path}")
        declared_total += size
        if declared_total > MAX_TOTAL_BYTES:
            raise ArchiveError("manifest exceeds decompressed-size limit")
        normalized[path] = {"sha256": digest, "size": size}

    if manifest["file_count"] != len(normalized):
        raise ArchiveError("manifest file count does not match inventory")
    if manifest["total_size"] != declared_total:
        raise ArchiveError("manifest total size does not match inventory")
    if normalized != actual:
        missing = sorted(set(normalized) - set(actual))
        extra = sorted(set(actual) - set(normalized))
        changed = sorted(
            path
            for path in set(normalized) & set(actual)
            if normalized[path] != actual[path]
        )
        raise ArchiveError(
            "archive payload does not match manifest "
            f"(missing={missing[:3]}, extra={extra[:3]}, changed={changed[:3]})"
        )

    luks = manifest["luks_header"]
    if not isinstance(luks, dict) or set(luks) != {"included", "uuid"}:
        raise ArchiveError("manifest LUKS metadata is invalid")
    included = luks["included"]
    luks_uuid = luks["uuid"]
    if not isinstance(included, bool) or not isinstance(luks_uuid, str):
        raise ArchiveError("manifest LUKS metadata types are invalid")
    if included != ("luks-header-backup" in normalized):
        raise ArchiveError("manifest LUKS inclusion flag is inconsistent")
    if included and not UUID_RE.fullmatch(luks_uuid):
        raise ArchiveError("included LUKS header lacks a valid source UUID")
    if not included and luks_uuid:
        raise ArchiveError("manifest has a LUKS UUID without a header")
    return manifest


def verify_archive(archive_path: Path) -> dict:
    archive_stat = archive_path.lstat()
    if archive_path.is_symlink() or not stat.S_ISREG(archive_stat.st_mode):
        raise ArchiveError("archive must be a regular file, not a symbolic link")
    if archive_stat.st_size <= 0 or archive_stat.st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveError("archive has an invalid compressed size")

    actual: dict[str, dict[str, int | str]] = {}
    manifest_data: bytes | None = None
    seen: set[str] = set()
    member_count = 0
    total_size = 0
    try:
        with tarfile.open(archive_path, mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_FILES + 1:
                    raise ArchiveError("archive exceeds member-count limit")
                name = _validate_relative_path(member.name)
                if name in seen:
                    raise ArchiveError(f"duplicate archive member: {name}")
                seen.add(name)
                if not member.isreg():
                    raise ArchiveError(f"non-regular archive member is forbidden: {name}")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise ArchiveError(f"archive member has an invalid size: {name}")
                total_size += member.size
                if total_size > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
                    raise ArchiveError("archive exceeds decompressed-size limit")
                if name == "manifest.json":
                    if manifest_data is not None:
                        raise ArchiveError("archive contains multiple manifests")
                    manifest_data = _read_member_bounded(archive, member)
                else:
                    digest, size = _hash_member(archive, member)
                    actual[name] = {"sha256": digest, "size": size}
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveError(f"invalid compressed archive: {exc}") from exc

    if manifest_data is None:
        raise ArchiveError("archive does not contain manifest.json")
    try:
        manifest = json.loads(manifest_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"manifest is not valid UTF-8 JSON: {exc}") from exc
    return _validate_manifest(manifest, actual)


def extract_archive(archive_path: Path, destination: Path) -> dict:
    manifest = verify_archive(archive_path)
    if destination.is_symlink() or not destination.is_dir():
        raise ArchiveError("extraction destination must be a real directory")
    if any(destination.iterdir()):
        raise ArchiveError("extraction destination must be empty")

    try:
        with tarfile.open(archive_path, mode="r|gz") as archive:
            for member in archive:
                name = _validate_relative_path(member.name)
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                for parent in [target.parent, *target.parents]:
                    if parent == destination.parent:
                        break
                    if parent.is_symlink():
                        raise ArchiveError(f"symbolic link in extraction path: {parent}")
                    if parent == destination:
                        break
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(target, flags, 0o600)
                try:
                    with os.fdopen(descriptor, "wb", closefd=True) as output:
                        source = archive.extractfile(member)
                        if source is None:
                            raise ArchiveError(f"could not extract archive member: {name}")
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(COPY_CHUNK, remaining))
                            if not chunk:
                                raise ArchiveError(f"short archive member: {name}")
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    try:
                        target.unlink()
                    except FileNotFoundError:
                        pass
                    raise
    except (tarfile.TarError, OSError, EOFError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError(f"safe extraction failed: {exc}") from exc
    return manifest


def _selected_for_category(relative: str, category: str) -> bool:
    config = (
        relative.startswith("etc/secure-ai/policy/")
        or relative
        in {
            "etc/secure-ai/config/appliance.yaml",
            "etc/secure-ai/model-catalog.yaml",
        }
    )
    logs = relative == "var/lib/secure-ai/data/incidents.jsonl" or relative.startswith(
        "var/lib/secure-ai/logs/"
    )
    keys = relative.startswith("var/lib/secure-ai/keys/")
    registry = relative == "var/lib/secure-ai/registry/manifest.json"
    if category == "config":
        return config
    if category == "logs":
        return logs
    if category == "keys":
        return keys
    return config or logs or keys or registry


def _target_for(relative: str, etc_root: Path, secure_root: Path) -> Path:
    path = PurePosixPath(relative)
    if path.parts[:2] == ("etc", "secure-ai"):
        return etc_root.joinpath(*path.parts[1:])
    if path.parts[:3] == ("var", "lib", "secure-ai"):
        return secure_root.joinpath(*path.parts[3:])
    raise ArchiveError(f"archive path has no restore target: {relative}")


def _fixed_mode(relative: str) -> int:
    if relative.startswith("var/lib/secure-ai/keys/"):
        return 0o600
    if relative.startswith("var/lib/secure-ai/logs/"):
        return 0o640
    if relative == "var/lib/secure-ai/data/incidents.jsonl":
        return 0o640
    if relative == "var/lib/secure-ai/registry/manifest.json":
        return 0o640
    return 0o644


def _fixed_owner(relative: str) -> tuple[int, int]:
    group_name = "root"
    if relative.startswith("var/lib/secure-ai/logs/"):
        group_name = "secure-ai-logs"
    elif relative == "var/lib/secure-ai/data/incidents.jsonl":
        group_name = "secure-ai-data"
    elif relative == "var/lib/secure-ai/registry/manifest.json":
        group_name = "secure-ai-registry"
    return 0, _group_id(group_name)


def _group_id(group_name: str) -> int:
    try:
        return grp.getgrnam(group_name).gr_gid
    except KeyError as exc:
        # Unit tests exercise a temporary target on non-Linux hosts that do
        # not have the appliance sysusers database. A real restore runs as
        # root and must fail if its DAC groups were not provisioned.
        if os.geteuid() != 0:
            return os.getegid()
        raise ArchiveError(
            f"required local restore group does not exist: {group_name}"
        ) from exc


def _ensure_safe_parent(base: Path, target: Path) -> None:
    base.mkdir(mode=0o755, parents=True, exist_ok=True)
    if base.is_symlink() or not base.is_dir():
        raise ArchiveError(f"restore base is not a real directory: {base}")
    try:
        relative_parent = target.parent.relative_to(base)
    except ValueError as exc:
        raise ArchiveError(f"restore target escapes its base: {target}") from exc
    current = base
    for part in relative_parent.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArchiveError(f"unsafe restore parent: {current}")


def _copy_atomic(source: Path, target: Path, mode: int, uid: int, gid: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise ArchiveError(f"restore source is not a regular file: {source}")
    _ensure_safe_parent(target.parent, target)
    temporary = target.parent / f".{target.name}.restore-{secrets.token_hex(8)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            with _open_source_no_follow(source) as input_handle:
                shutil.copyfileobj(input_handle, output, COPY_CHUNK)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
            if os.geteuid() == 0:
                os.fchown(output.fileno(), uid, gid)
        os.replace(temporary, target)
        parent_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


def _set_directory_policy(
    relative: str,
    target: Path,
    etc_root: Path,
    secure_root: Path,
) -> None:
    if relative.startswith("etc/"):
        base = etc_root
        mode = 0o755
        gid = _group_id("root")
    else:
        base = secure_root
        top_level = PurePosixPath(relative).parts[3]
        if top_level == "keys":
            mode = 0o700
            gid = _group_id("root")
        elif top_level == "logs":
            mode = 0o2770
            gid = _group_id("secure-ai-logs")
        elif top_level == "data":
            mode = 0o2770
            gid = _group_id("secure-ai-data")
        elif top_level == "registry":
            mode = 0o2770
            gid = _group_id("secure-ai-registry")
        else:  # pragma: no cover - restore selection forbids other roots
            raise ArchiveError(f"no directory policy for restore path: {relative}")
        os.chmod(base, 0o711)
        if os.geteuid() == 0:
            os.chown(base, 0, _group_id("root"))

    try:
        parent_relative = target.parent.relative_to(base)
    except ValueError as exc:  # pragma: no cover - checked by target mapping
        raise ArchiveError(f"restore target escapes directory policy base: {target}") from exc
    current = base
    for part in parent_relative.parts:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ArchiveError(f"unsafe restore directory: {current}")
        os.chmod(current, mode)
        if os.geteuid() == 0:
            os.chown(current, 0, gid)


def apply_restore(staging: Path, category: str, etc_root: Path, secure_root: Path) -> int:
    if category not in CATEGORIES:
        raise ArchiveError(f"unsupported restore category: {category}")
    manifest_path = staging / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"cannot read extracted manifest: {exc}") from exc
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ArchiveError("extracted manifest has no file inventory")

    restore_items: list[tuple[str, Path, Path, int]] = []
    for relative in sorted(files):
        relative = _validate_relative_path(relative)
        if not _selected_for_category(relative, category):
            continue
        source = staging.joinpath(*PurePosixPath(relative).parts)
        target = _target_for(relative, etc_root, secure_root)
        base = etc_root if relative.startswith("etc/") else secure_root
        _ensure_safe_parent(base, target)
        if target.exists() or target.is_symlink():
            metadata = target.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ArchiveError(f"refusing to replace non-regular target: {target}")
        restore_items.append((relative, source, target, _fixed_mode(relative)))

    if not restore_items:
        raise ArchiveError(f"archive contains no files for restore category {category}")
    for relative, _source, target, _mode in restore_items:
        _set_directory_policy(relative, target, etc_root, secure_root)

    rollback_root = staging / ".rollback"
    rollback_root.mkdir(mode=0o700)
    rollback: list[tuple[Path, Path | None, int, int, int]] = []
    applied: list[tuple[Path, str]] = []
    try:
        for index, (relative, source, target, mode) in enumerate(restore_items):
            prior: Path | None = None
            prior_mode = 0
            prior_uid = 0
            prior_gid = 0
            if target.exists():
                target_stat = target.lstat()
                prior_mode = stat.S_IMODE(target_stat.st_mode)
                prior_uid = target_stat.st_uid
                prior_gid = target_stat.st_gid
                prior = rollback_root / f"{index:06d}"
                _copy_atomic(target, prior, 0o600, os.geteuid(), os.getegid())
            rollback.append((target, prior, prior_mode, prior_uid, prior_gid))
            uid, gid = _fixed_owner(relative)
            _copy_atomic(source, target, mode, uid, gid)
            applied.append((target, relative))
    except Exception as original_error:
        rollback_errors: list[str] = []
        for target, prior, prior_mode, prior_uid, prior_gid in reversed(rollback):
            try:
                if prior is None:
                    if target.exists() and target.is_file() and not target.is_symlink():
                        target.unlink()
                else:
                    _copy_atomic(prior, target, prior_mode, prior_uid, prior_gid)
            except Exception as rollback_error:  # pragma: no cover - catastrophic path
                rollback_errors.append(f"{target}: {rollback_error}")
        detail = f"restore transaction failed and was rolled back: {original_error}"
        if rollback_errors:
            detail += f"; rollback failures: {rollback_errors}"
        raise ArchiveError(detail) from original_error
    return len(applied)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--category", choices=sorted(CATEGORIES), required=True)
    create.add_argument("--luks-uuid")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--archive", type=Path, required=True)

    extract = subparsers.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--staging", type=Path, required=True)
    apply_parser.add_argument("--category", choices=sorted(CATEGORIES), required=True)
    apply_parser.add_argument("--etc-root", type=Path, default=Path("/etc"))
    apply_parser.add_argument(
        "--secure-root", type=Path, default=Path("/var/lib/secure-ai")
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        if args.command == "create":
            manifest = create_archive(args.root, args.output, args.category, args.luks_uuid)
        elif args.command in {"verify", "inspect"}:
            manifest = verify_archive(args.archive)
        elif args.command == "extract":
            manifest = extract_archive(args.archive, args.destination)
        elif args.command == "apply":
            count = apply_restore(
                args.staging,
                args.category,
                args.etc_root,
                args.secure_root,
            )
            print(json.dumps({"restored_files": count}, separators=(",", ":")))
            return 0
        else:  # pragma: no cover
            raise ArchiveError("unknown command")

        if args.command == "inspect":
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(
                json.dumps(
                    {
                        "category": manifest["category"],
                        "file_count": manifest["file_count"],
                        "total_size": manifest["total_size"],
                        "luks_header": manifest["luks_header"],
                    },
                    separators=(",", ":"),
                )
            )
        return 0
    except (ArchiveError, OSError) as exc:
        print(f"secure-backup-archive: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

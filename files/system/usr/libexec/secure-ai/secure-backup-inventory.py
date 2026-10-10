#!/usr/bin/env python3
"""Native backup inventory and bounded descriptor-based source access.

This is a partial, unquiesced export contract. It supplies no live restore,
producer consistency, credential import, or historical-evidence verification.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class ArchiveError(RuntimeError):
    """A backup trust boundary rejected input."""


class Limits:
    """Finite local ceilings; archive input cannot increase these values."""

    ciphertext: int
    archive: int
    total: int
    file: int
    entries: int
    manifest: int
    depth: int
    component: int
    path: int
    seconds: int
    reserve: int

    def __init__(
        self, *, ciphertext: int = 65 * 1024**3, archive: int = 64 * 1024**3,
        total: int = 64 * 1024**3, file: int = 16 * 1024**3,
        entries: int = 50_000, manifest: int = 8 * 1024**2,
        depth: int = 32, component: int = 240, path: int = 2048,
        seconds: int = 3600, reserve: int = 16 * 1024**2,
    ):
        for name, value in locals().copy().items():
            if name == "self":
                continue
            if type(value) is not int or value <= 0:
                raise ArchiveError("limits must be positive integers")
            setattr(self, name, value)
        if depth > 32 or component > 240 or path > 2048:
            raise ArchiveError("native path bounds cannot be increased")

    @property
    def tar_bytes(self) -> int:
        # Regular-file headers, per-file padding, manifest, and final record.
        return self.total + self.manifest + (self.entries + 1) * 1024 + 10240


class Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.deadline = time.monotonic() + limits.seconds
        self.entries = 0
        self.total = 0
        self.manifest_bytes = 0

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise ArchiveError("operation deadline exceeded")

    def add(self, size: int = 0, path: str = "") -> None:
        self.check()
        if type(size) is not int or not 0 <= size <= self.limits.file:
            raise ArchiveError("per-file size limit exceeded")
        self.entries += 1
        self.total += size
        self.manifest_bytes += 512 + len(path.encode("utf-8"))
        if self.entries > self.limits.entries or self.total > self.limits.total:
            raise ArchiveError("inventory count or expanded size limit exceeded")
        if self.manifest_bytes > self.limits.manifest:
            raise ArchiveError("inventory exceeds manifest space budget")


def strict_json(data: bytes, maximum: int) -> object:
    if len(data) > maximum:
        raise ArchiveError("JSON manifest size limit exceeded")
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ArchiveError("JSON nesting limit exceeded")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise ArchiveError("duplicate JSON key")
            result[key] = value
        return result

    def number(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ArchiveError("nonfinite JSON number")
        return parsed

    def constant(_value: str) -> None:
        raise ArchiveError("nonfinite JSON constant")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_float=number, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArchiveError("invalid bounded UTF-8 JSON") from exc


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def relative_name(value: object, limits: Limits, *, root: bool = False) -> str:
    if root and value == "":
        return ""
    if not isinstance(value, str) or not value:
        raise ArchiveError("invalid logical path")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ArchiveError("unsupported filename encoding") from exc
    parts = value.split("/")
    if len(raw) > limits.path or len(parts) > limits.depth:
        raise ArchiveError("logical path length or depth limit exceeded")
    if any(p in {"", ".", ".."} or len(p.encode("utf-8")) > limits.component for p in parts):
        raise ArchiveError("unsafe path component")
    if "\\" in value or any(unicodedata.category(c).startswith("C") for c in value):
        raise ArchiveError("unsupported path character")
    return value


def collision_name(value: str) -> str:
    # Reject ambiguous sets, but preserve every accepted spelling exactly.
    return unicodedata.normalize("NFC", value).casefold()


def identity(metadata: os.stat_result) -> tuple:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_gid, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def mount_id(fd: int) -> int:
    # st_dev alone does not detect a bind mount on the same filesystem.
    try:
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("mnt_id:"):
                    return int(line.split()[1])
    except (OSError, ValueError) as exc:
        raise ArchiveError("native mount identity is unavailable") from exc
    raise ArchiveError("native mount identity is unavailable")


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def open_directory(path: Path) -> int:
    """Open every pathname component without following links."""
    path = path.absolute()
    fd = os.open("/", DIR_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in {".", ".."}:
                raise ArchiveError("directory path must be canonical")
            child = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def pinned_file(path: Path, maximum: int, *, allow_empty: bool = False) -> Iterator[tuple[int, os.stat_result]]:
    parent = open_directory(path.parent)
    fd = -1
    try:
        fd = os.open(path.name, FILE_FLAGS, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ArchiveError("input must be a regular file without links")
        if not (0 if allow_empty else 1) <= before.st_size <= maximum:
            raise ArchiveError("input size limit exceeded")
        yield fd, before
        if identity(before) != identity(os.fstat(fd)):
            raise ArchiveError("input changed during operation")
        if identity(before) != identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
            raise ArchiveError("input pathname changed during operation")
        reopened = open_directory(path.parent)
        try:
            if (os.fstat(parent).st_dev, os.fstat(parent).st_ino, mount_id(parent)) != (
                os.fstat(reopened).st_dev, os.fstat(reopened).st_ino, mount_id(reopened)
            ):
                raise ArchiveError("input parent changed during operation")
        finally:
            os.close(reopened)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def check_space(fd: int, required: int, limits: Limits) -> None:
    available = os.fstatvfs(fd)
    if available.f_bavail * available.f_frsize < required + limits.reserve:
        raise ArchiveError("insufficient staging space including reserve")
    if available.f_favail == 0:
        raise ArchiveError("no staging inodes available")


def check_directory_binding(path: Path, fd: int) -> None:
    reopened = open_directory(path)
    try:
        before, after = os.fstat(fd), os.fstat(reopened)
        if (before.st_dev, before.st_ino, mount_id(fd)) != (after.st_dev, after.st_ino, mount_id(reopened)):
            raise ArchiveError("output directory binding changed")
    finally:
        os.close(reopened)


def check_metadata(fd: int, metadata: os.stat_result) -> None:
    is_file = stat.S_ISREG(metadata.st_mode)
    if not is_file and not stat.S_ISDIR(metadata.st_mode):
        raise ArchiveError("only ordinary files and directories are supported")
    if is_file and (metadata.st_nlink != 1 or metadata.st_mode & 0o7111):
        raise ArchiveError("hardlinks, executable or privilege-bearing files are unsupported")
    if metadata.st_mode & stat.S_ISUID:
        raise ArchiveError("setuid source metadata is unsupported")
    # SELinux labels are target-owned and intentionally not archived. All other
    # xattrs (including ACLs, capabilities and user metadata) need an adapter.
    try:
        if set(os.listxattr(fd)) - {"security.selinux"}:
            raise ArchiveError("unsupported source xattrs or ACL metadata")
    except OSError as exc:
        raise ArchiveError("cannot inspect source metadata") from exc


CLASS_ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
DISPOSITIONS = {"included", "empty", "not_applicable", "reacquire", "excluded_authority"}
PREREQUISITES = ["durable-maintenance-transaction", "producer-adapters",
                 "historical-evidence-enrollment", "rotation-reconciliation"]


def load_inventory(path: Path, *, trusted: bool = False) -> dict:
    with pinned_file(path, 256 * 1024) as (fd, metadata):
        if trusted and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
            raise ArchiveError("installed inventory must be root-owned and immutable to other users")
        value = strict_json(os.read(fd, 256 * 1024 + 1), 256 * 1024)
    if not isinstance(value, dict) or set(value) != {"inventory_version", "adapter", "classes"}:
        raise ArchiveError("invalid installed inventory schema")
    if type(value["inventory_version"]) is not int or value["inventory_version"] != 1:
        raise ArchiveError("unsupported inventory version")
    if value["adapter"] != "native-v1" or not isinstance(value["classes"], list):
        raise ArchiveError("unsupported deployment inventory adapter")
    if not 1 <= len(value["classes"]) <= 128:
        raise ArchiveError("invalid installed class count")
    ids, sources = set(), set()
    for item in value["classes"]:
        if not isinstance(item, dict) or set(item) != {
            "id", "source", "shape", "adapter", "required", "disposition",
            "target", "owner", "group", "file_mode", "directory_mode",
        }:
            raise ArchiveError("invalid installed class record")
        if not isinstance(item["id"], str) or not CLASS_ID.fullmatch(item["id"]):
            raise ArchiveError("invalid class ID")
        source = relative_name(item["source"], Limits())
        if item["id"] in ids or source in sources:
            raise ArchiveError("duplicate installed class")
        ids.add(item["id"])
        sources.add(source)
        if not isinstance(item["shape"], str) or item["shape"] not in {"file", "tree"} or type(item["required"]) is not bool:
            raise ArchiveError("invalid class source contract")
        if not isinstance(item["adapter"], str) or item["adapter"] not in {"bytes-v1", "unsupported", "excluded"}:
            raise ArchiveError("unsupported inventory adapter name")
        if not isinstance(item["disposition"], str) or item["disposition"] not in {"inert-data", "history-only", "excluded-authority"}:
            raise ArchiveError("invalid local recovery disposition")
        relative_name(item["target"], Limits())
        for field in ("owner", "group"):
            if not isinstance(item[field], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item[field]):
                raise ArchiveError("local owners must be symbolic identities")
        if not isinstance(item["file_mode"], str) or item["file_mode"] not in {"0600", "0640", "0644", "0660"}:
            raise ArchiveError("unsupported local data-file policy")
        if not isinstance(item["directory_mode"], str) or item["directory_mode"] not in {"0700", "0711", "0750", "0755", "2750", "2770", "3770"}:
            raise ArchiveError("unsupported local directory policy")
    for a in sources:
        for b in sources:
            if a != b and b.startswith(a + "/"):
                raise ArchiveError("overlapping installed source classes")
    return value


def local_policy(inventory: dict, class_id: str) -> dict:
    item = next((c for c in inventory["classes"] if c["id"] == class_id), None)
    if item is None:
        raise ArchiveError("unknown class has no target mapping")
    if item["adapter"] != "bytes-v1":
        raise ArchiveError("producer-specific target DAC adapter is unavailable")
    return {k: item[k] for k in ("target", "owner", "group", "file_mode", "directory_mode", "disposition")}


class SourceTree:
    """Bounded metadata preflight; files are opened again relative to pinned roots.

    Root mounts are explicitly selected. Traversal never crosses a nested mount,
    symlink or hardlink. Stat/change and directory-binding checks bracket reads;
    they do not provide producer-level consistency or resist malicious root.
    """

    def __init__(self, root: Path, limits: Limits, budget: Budget):
        self.root = root
        self.limits = limits
        self.budget = budget
        self.fd = open_directory(root)
        self.mount = mount_id(self.fd)
        self.records: list[dict] = []
        self.directories: dict[str, tuple] = {}
        try:
            self._scan(self.fd, "")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _scan(self, fd: int, path: str) -> None:
        before = os.fstat(fd)
        check_metadata(fd, before)
        if mount_id(fd) != self.mount:
            raise ArchiveError("unexpected nested source mount")
        self.budget.add(path=path)
        self.directories[path] = identity(before)
        self.records.append({"path": path, "kind": "directory"})
        collisions: set[str] = set()
        # scandir is streamed: a huge directory cannot allocate an unbounded list.
        with os.scandir(fd) as children:
            for child in children:
                name = relative_name(f"{path}/{child.name}" if path else child.name, self.limits)
                key = collision_name(name)
                if key in collisions:
                    raise ArchiveError("filename case or Unicode normalization collision")
                collisions.add(key)
                metadata = child.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode):
                    raise ArchiveError("links and special source objects are unsupported")
                flags = DIR_FLAGS if stat.S_ISDIR(metadata.st_mode) else FILE_FLAGS
                child_fd = os.open(child.name, flags, dir_fd=fd)
                try:
                    if identity(metadata) != identity(os.fstat(child_fd)):
                        raise ArchiveError("source changed during inventory")
                    if mount_id(child_fd) != self.mount:
                        raise ArchiveError("unexpected nested source mount")
                    check_metadata(child_fd, metadata)
                    if stat.S_ISDIR(metadata.st_mode):
                        self._scan(child_fd, name)
                    else:
                        self.budget.add(metadata.st_size, name)
                        self.records.append({"path": name, "kind": "file", "size": metadata.st_size,
                                             "identity": identity(metadata)})
                finally:
                    os.close(child_fd)
        if identity(before) != identity(os.fstat(fd)):
            raise ArchiveError("source directory changed during inventory")

    @contextmanager
    def file(self, record: dict) -> Iterator[int]:
        fd = os.dup(self.fd)
        try:
            parts = record["path"].split("/")
            prefix = ""
            for part in parts[:-1]:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
                prefix = f"{prefix}/{part}" if prefix else part
                if identity(os.fstat(fd)) != self.directories[prefix] or mount_id(fd) != self.mount:
                    raise ArchiveError("source parent changed during capture")
            source = os.open(parts[-1], FILE_FLAGS, dir_fd=fd)
            try:
                if identity(os.fstat(source)) != record["identity"] or mount_id(source) != self.mount:
                    raise ArchiveError("source changed during capture")
                yield source
                if identity(os.fstat(source)) != record["identity"]:
                    raise ArchiveError("source changed during capture")
            finally:
                os.close(source)
        finally:
            os.close(fd)

    def verify(self) -> None:
        other = open_directory(self.root)
        try:
            if identity(os.fstat(other)) != self.directories[""] or mount_id(other) != self.mount:
                raise ArchiveError("source root changed during capture")
        finally:
            os.close(other)
        for path, expected in self.directories.items():
            self.budget.check()
            fd = os.dup(self.fd)
            try:
                for part in path.split("/") if path else []:
                    child = os.open(part, DIR_FLAGS, dir_fd=fd)
                    os.close(fd)
                    fd = child
                if identity(os.fstat(fd)) != expected or mount_id(fd) != self.mount:
                    raise ArchiveError("source directory changed during capture")
            finally:
                os.close(fd)
        for record in self.records:
            if record["kind"] == "file":
                self.budget.check()
                with self.file(record):
                    pass


def inventory_digest(inventory: dict) -> str:
    return hashlib.sha256(encode(inventory)).hexdigest()

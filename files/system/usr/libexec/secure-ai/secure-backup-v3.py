#!/usr/bin/env python3
"""Strict archive/age transport for inert backup inspection and partial export."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


_spec = importlib.util.spec_from_file_location(
    "secure_backup_inventory", Path(__file__).with_name("secure-backup-inventory.py")
)
assert _spec and _spec.loader
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)
ArchiveError = inventory.ArchiveError
Limits = inventory.Limits
Budget = inventory.Budget
CHUNK = 64 * 1024
OBJECT = re.compile(r"objects/[0-9]{8}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class LimitProfile(Protocol):
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

    @property
    def tar_bytes(self) -> int: ...


class TimeBudget(Protocol):
    deadline: float

    def check(self) -> None: ...


class GzipReader:
    """One bounded gzip member; CRC, final stream and all trailing bytes checked."""

    def __init__(self, fd: int, limits: LimitProfile, budget: TimeBudget):
        self.fd, self.limits, self.budget = fd, limits, budget
        self.decoder = zlib.decompressobj(31)
        self.pending = b""
        self.buffer = bytearray()
        self.compressed = self.expanded = 0
        self.done = False

    def read(self, size: int) -> bytes:
        if not 0 <= size <= CHUNK:
            raise ArchiveError("unbounded archive read")
        while len(self.buffer) < size and not self.done:
            self.budget.check()
            data = self.pending or os.read(self.fd, CHUNK)
            if not self.pending:
                self.compressed += len(data)
                if self.compressed > self.limits.archive:
                    raise ArchiveError("compressed archive size limit exceeded")
            if not data:
                raise ArchiveError("truncated gzip stream")
            try:
                output = self.decoder.decompress(data, CHUNK)
            except zlib.error as exc:
                raise ArchiveError("invalid gzip stream") from exc
            self.pending = self.decoder.unconsumed_tail
            self.expanded += len(output)
            if self.expanded > self.limits.tar_bytes:
                raise ArchiveError("expanded tar size limit exceeded")
            self.buffer.extend(output)
            if self.decoder.eof:
                if self.decoder.unused_data or os.read(self.fd, 1):
                    raise ArchiveError("trailing or concatenated gzip stream")
                self.done = True
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def exact(self, size: int) -> bytes:
        value = self.read(size)
        if len(value) != size:
            raise ArchiveError("short tar record")
        return value


class Stage:
    """Private inert files, accessed only relative to the pinned staging root."""

    def __init__(self, destination: Path, limits: LimitProfile, *, empty: bool = True):
        self.path = destination
        self.limits = limits
        self.fd = inventory.open_directory(destination)
        try:
            with os.scandir(self.fd) as children:
                if empty and next(children, None) is not None:
                    raise ArchiveError("extraction destination must be empty")
            metadata = os.fstat(self.fd)
            if metadata.st_uid != os.geteuid():
                raise ArchiveError("staging directory must belong to the caller")
            os.fchmod(self.fd, 0o700)
            self.mount = inventory.mount_id(self.fd)
            self.inode = (metadata.st_dev, metadata.st_ino)
            inventory.check_space(self.fd, limits.manifest, limits)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self) -> None:
        os.close(self.fd)

    def open(self, name: str, size: int) -> int:
        inventory.check_space(self.fd, size, self.limits)
        fd = os.dup(self.fd)
        try:
            parts = name.split("/")
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, inventory.DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
                if inventory.mount_id(fd) != self.mount:
                    raise ArchiveError("unexpected staging mount")
            return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        finally:
            os.close(fd)

    def verify(self, expected: dict, budget: TimeBudget) -> None:
        found = {}
        expected_dirs: set[str] = set()
        for name in expected:
            parts = name.split("/")
            expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))

        def walk(fd: int, prefix: str) -> None:
            with os.scandir(fd) as children:
                for child in children:
                    budget.check()
                    name = prefix + child.name
                    metadata = child.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        inner = os.open(child.name, inventory.DIR_FLAGS, dir_fd=fd)
                        try:
                            if inventory.mount_id(inner) != self.mount:
                                raise ArchiveError("staging mount changed")
                            if name not in expected_dirs:
                                raise ArchiveError("unexpected staged directory")
                            walk(inner, name + "/")
                        finally:
                            os.close(inner)
                        continue
                    if name not in expected or not stat.S_ISREG(metadata.st_mode):
                        raise ArchiveError("unexpected or unsafe staged object")
                    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                        raise ArchiveError("staged object metadata changed")
                    source = os.open(child.name, inventory.FILE_FLAGS, dir_fd=fd)
                    try:
                        digest, count = hashlib.sha256(), 0
                        while data := os.read(source, CHUNK):
                            budget.check()
                            count += len(data)
                            if count > expected[name]["size"]:
                                raise ArchiveError("staged object size changed")
                            digest.update(data)
                        if inventory.identity(metadata) != inventory.identity(os.fstat(source)):
                            raise ArchiveError("staged object changed during validation")
                        found[name] = {"size": count, "sha256": digest.hexdigest()}
                    finally:
                        os.close(source)

        walk(self.fd, "")
        if found != expected:
            raise ArchiveError("staged objects do not match validated manifest")
        other = inventory.open_directory(self.path)
        try:
            metadata = os.fstat(other)
            if (metadata.st_dev, metadata.st_ino) != self.inode or inventory.mount_id(other) != self.mount:
                raise ArchiveError("staging pathname changed")
        finally:
            os.close(other)

    def clear(self) -> None:
        def remove(fd: int) -> None:
            with os.scandir(fd) as children:
                for child in children:
                    if child.is_dir(follow_symlinks=False):
                        inner = os.open(child.name, inventory.DIR_FLAGS, dir_fd=fd)
                        try:
                            if inventory.mount_id(inner) != self.mount:
                                raise ArchiveError("refusing cleanup across staging mount")
                            remove(inner)
                        finally:
                            os.close(inner)
                        os.rmdir(child.name, dir_fd=fd)
                    else:
                        os.unlink(child.name, dir_fd=fd)
        remove(self.fd)


def parse_tar(fd: int, limits: LimitProfile, budget: TimeBudget, validate_name, stage: Stage | None = None) -> tuple:
    """No tar iteration recovery: a malformed late header is always an error."""
    stream = GzipReader(fd, limits, budget)
    actual, seen = {}, set()
    manifest_data = None
    total = 0
    while True:
        block = stream.exact(512)
        if block == bytes(512):
            if stream.exact(512) != bytes(512):
                raise ArchiveError("invalid tar end marker")
            padding = 1024
            while tail := stream.read(CHUNK):
                padding += len(tail)
                if padding > 10240 or any(tail):
                    raise ArchiveError("trailing tar data or excess padding")
            break
        try:
            member = tarfile.TarInfo.frombuf(block, "ascii", "strict")
        except (tarfile.TarError, UnicodeError, ValueError) as exc:
            raise ArchiveError("invalid tar header") from exc
        name = validate_name(member.name)
        if name in seen:
            raise ArchiveError("duplicate archive member")
        seen.add(name)
        if len(seen) > limits.entries + 1:
            raise ArchiveError("archive member-count limit exceeded")
        if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            raise ArchiveError("non-regular archive member or PAX/GNU extension is forbidden")
        if (member.linkname or member.uid != 0 or member.gid != 0 or member.uname or
                member.gname or member.mode != 0o600 or member.devmajor or member.devminor):
            raise ArchiveError("unsupported archive ownership or metadata")
        try:
            canonical = member.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
        except (ValueError, UnicodeError) as exc:
            raise ArchiveError("unsupported tar header encoding") from exc
        if canonical != block:
            raise ArchiveError("noncanonical tar header metadata")
        maximum = limits.manifest if name == "manifest.json" else limits.file
        if not 0 <= member.size <= maximum:
            raise ArchiveError("archive member size limit exceeded")
        if name != "manifest.json":
            total += member.size
            if total > limits.total:
                raise ArchiveError("expanded payload size limit exceeded")
        remaining, digest = member.size, hashlib.sha256()
        data_parts = []
        out = stage.open(name, member.size) if stage else -1
        try:
            while remaining:
                chunk = stream.exact(min(CHUNK, remaining))
                digest.update(chunk)
                if out >= 0:
                    # Buffered file objects are unnecessary; handle short writes.
                    write_all(out, chunk)
                if name == "manifest.json":
                    data_parts.append(chunk)
                remaining -= len(chunk)
            if out >= 0:
                os.fsync(out)
        finally:
            if out >= 0:
                os.close(out)
        if name == "manifest.json":
            manifest_data = b"".join(data_parts)
        else:
            actual[name] = {"sha256": digest.hexdigest(), "size": member.size}
        padding = (-member.size) % 512
        if padding and any(stream.exact(padding)):
            raise ArchiveError("nonzero tar file padding")
    if manifest_data is None:
        raise ArchiveError("archive does not contain manifest.json")
    return actual, manifest_data


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise ArchiveError("short staging write")
        view = view[count:]


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00", value):
        raise ArchiveError("invalid UTC snapshot time")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ArchiveError("invalid snapshot time") from exc


def validate_manifest(value: object, actual: dict, installed: dict, limits: LimitProfile) -> dict:
    top = {"format", "format_version", "inventory_version", "backup_id", "kind", "created_at",
           "snapshot_started_at", "snapshot_finished_at", "source", "inventory_sha256",
           "classes", "objects", "directories", "totals", "consistency", "reacquisition",
           "luks_header", "historical_evidence"}
    if not isinstance(value, dict) or set(value) != top:
        raise ArchiveError("invalid v3 manifest fields")
    if (value["format"] != "secure-ai-backup" or type(value["format_version"]) is not int or
            value["format_version"] != 3 or type(value["inventory_version"]) is not int or
            value["inventory_version"] != 1 or value["kind"] != "partial-export"):
        raise ArchiveError("unsupported format or full restore prerequisites missing")
    try:
        parsed_id = uuid.UUID(value["backup_id"])
        if parsed_id.version != 4 or str(parsed_id) != value["backup_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ArchiveError("invalid backup ID") from exc
    started, finished, created = (_time(value[k]) for k in (
        "snapshot_started_at", "snapshot_finished_at", "created_at"))
    if not started <= finished <= created or (finished - started).total_seconds() > limits.seconds:
        raise ArchiveError("impossible or excessive snapshot interval")
    source = value["source"]
    if (not isinstance(source, dict) or set(source) != {"adapter", "release_sha256", "schemas"} or
            source["adapter"] != "native-v1" or not isinstance(source["release_sha256"], str) or
            not DIGEST.fullmatch(source["release_sha256"]) or not isinstance(source["schemas"], dict) or source["schemas"] != {"bytes": 1} or
            type(source["schemas"].get("bytes")) is not int):
        raise ArchiveError("unsupported source adapter or schema")
    if value["inventory_sha256"] != inventory.inventory_digest(installed):
        raise ArchiveError("installed target inventory differs; migration adapter required")
    if value["consistency"] != {"status": "partial_unquiesced", "active_restore": False,
                                 "missing_prerequisites": inventory.PREREQUISITES}:
        raise ArchiveError("unsupported consistency or authority claim")
    if type(value["consistency"]["active_restore"]) is not bool:
        raise ArchiveError("invalid consistency flag type")
    if value["reacquisition"] != [] or value["luks_header"] is not None or value["historical_evidence"] != {
        "status": "not_verified", "keys": []
    }:
        raise ArchiveError("unsupported producer, header or evidence adapter")
    classes = value["classes"]
    known = {c["id"]: c for c in installed["classes"]}
    if not isinstance(classes, dict) or set(classes) != set(known):
        raise ArchiveError("missing or unknown inventory class")
    for name, record in classes.items():
        if not isinstance(record, dict) or set(record) != {"disposition", "reason", "adapter", "files", "directories", "bytes"}:
            raise ArchiveError("invalid class disposition schema")
        if record["adapter"] != known[name]["adapter"]:
            raise ArchiveError("class adapter mismatch")
        for field in ("files", "directories", "bytes"):
            if type(record[field]) is not int or record[field] < 0:
                raise ArchiveError("invalid class count")
        disposition, reason = record["disposition"], record["reason"]
        if not isinstance(disposition, str) or disposition not in inventory.DISPOSITIONS or not isinstance(reason, str):
            raise ArchiveError("unsupported class disposition")
        if known[name]["adapter"] == "excluded":
            valid = disposition == "excluded_authority" and reason == "regenerate_or_reconcile"
        elif disposition in {"included", "empty"}:
            valid = known[name]["adapter"] == "bytes-v1" and reason == "selected_inert_bytes"
        else:
            valid = disposition == "not_applicable" and reason in {
                "not_selected_partial_export", "unsupported_adapter_partial_export"}
            if known[name]["adapter"] == "unsupported":
                valid = valid and reason == "unsupported_adapter_partial_export"
        if not valid:
            raise ArchiveError("class disposition is not supported by its local adapter")
    objects, directories = value["objects"], value["directories"]
    if not isinstance(objects, list) or not isinstance(directories, list) or len(objects) + len(directories) > limits.entries:
        raise ArchiveError("invalid object/directory count")
    counts = {name: {"files": 0, "directories": 0, "bytes": 0} for name in known}
    paths, collision_paths, expected = {}, set(), {}
    for is_dir, records in ((True, directories), (False, objects)):
        for record in records:
            fields = {"class", "path"} if is_dir else {"class", "path", "id", "size", "sha256"}
            if not isinstance(record, dict) or set(record) != fields:
                raise ArchiveError("invalid logical object fields; archived DAC is forbidden")
            name = record["class"]
            if not isinstance(name, str) or name not in known or classes[name]["disposition"] not in {"included", "empty"}:
                raise ArchiveError("object belongs to unknown, excluded or unselected class")
            path = inventory.relative_name(record["path"], limits, root=is_dir)
            key = (name, path)
            collision = (name, inventory.collision_name(path))
            if key in paths or collision in collision_paths:
                raise ArchiveError("duplicate or colliding logical filename")
            paths[key] = is_dir
            collision_paths.add(collision)
            counts[name]["directories" if is_dir else "files"] += 1
            if not is_dir:
                object_id, size, digest = record["id"], record["size"], record["sha256"]
                if not isinstance(object_id, str) or not OBJECT.fullmatch(object_id) or object_id in expected:
                    raise ArchiveError("invalid or duplicate payload object ID")
                if type(size) is not int or not 0 <= size <= limits.file or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                    raise ArchiveError("invalid object size or digest")
                counts[name]["bytes"] += size
                expected[object_id] = {"size": size, "sha256": digest}
    for (name, path), is_dir in paths.items():
        if path:
            parent = path.rpartition("/")[0]
            if paths.get((name, parent)) is not True:
                raise ArchiveError("missing directory or file/directory ancestor conflict")
    for name, count in counts.items():
        if any(classes[name][k] != v for k, v in count.items()):
            raise ArchiveError("class totals differ from object inventory")
        disposition = classes[name]["disposition"]
        if disposition in {"included", "empty"} and not count["directories"]:
            raise ArchiveError("selected class has no verified root directory")
        if disposition == "empty" and (count["files"] or count["directories"] != 1):
            raise ArchiveError("empty disposition is not a verified empty root")
        if disposition == "included" and not count["files"] and count["directories"] == 1:
            raise ArchiveError("included class must distinguish verified empty root")
    totals = value["totals"]
    total = sum(c["bytes"] for c in counts.values())
    if (not isinstance(totals, dict) or set(totals) != {"files", "directories", "bytes"} or
            any(type(v) is not int for v in totals.values()) or
            totals != {"files": len(objects), "directories": len(directories), "bytes": total} or total > limits.total):
        raise ArchiveError("invalid manifest totals")
    if expected != actual:
        raise ArchiveError("archive payload does not match manifest")
    if set(expected) != {f"objects/{i:08d}" for i in range(1, len(objects) + 1)}:
        raise ArchiveError("noncanonical payload object ID sequence")
    return value


def object_name(name: str) -> str:
    if name != "manifest.json" and not OBJECT.fullmatch(name):
        raise ArchiveError("invalid v3 archive object path")
    return name


def read_archive(path: Path, installed: dict, limits: LimitProfile | None = None, destination: Path | None = None) -> dict:
    limits = limits or Limits()
    budget, stage = Budget(limits), None
    try:
        if destination is not None:
            stage = Stage(destination, limits)
        with inventory.pinned_file(path, limits.archive) as (fd, _metadata):
            actual, data = parse_tar(fd, limits, budget, object_name, stage)
            value = validate_manifest(inventory.strict_json(data, limits.manifest), actual, installed, limits)
            if stage:
                stage.verify({**actual, "manifest.json": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}, budget)
        return value
    except (OSError, ValueError) as exc:
        raise ArchiveError("unsafe or invalid archive input") from exc
    finally:
        if stage:
            # Failed validation leaves no successfully usable inert tree.
            import sys
            try:
                if sys.exc_info()[0] is not None:
                    stage.clear()
            finally:
                stage.close()


class BoundedWriter(io.RawIOBase):
    def __init__(self, handle, maximum: int, budget: TimeBudget):
        self.handle, self.maximum, self.budget = handle, maximum, budget
        self.count = 0

    def write(self, data) -> int:
        self.budget.check()
        self.count += len(data)
        if self.count > self.maximum:
            raise ArchiveError("output stream size limit exceeded")
        return self.handle.write(data)

    def flush(self) -> None:
        if not self.handle.closed:
            self.handle.flush()


def _member(archive, name: str, size: int, source) -> None:
    member = tarfile.TarInfo(name)
    member.size, member.mode = size, 0o600
    archive.addfile(member, source)


def scan_native(root: Path, installed: dict, limits: LimitProfile) -> None:
    """Reject unknown branches of managed roots without reading class content."""
    sources = {c["source"] for c in installed["classes"]}
    budget = Budget(limits)

    def walk(fd: int, prefix: str, mount: int) -> None:
        before = inventory.identity(os.fstat(fd))
        with os.scandir(fd) as children:
            for entry in children:
                budget.add()
                path = prefix + "/" + entry.name
                inventory.relative_name(path, limits)
                if path in sources:
                    continue  # Classified roots are scanned only by their adapter.
                if not any(p.startswith(path + "/") for p in sources):
                    raise ArchiveError("unknown managed source root; classification required")
                child = os.open(entry.name, inventory.DIR_FLAGS, dir_fd=fd)
                try:
                    child_mount = inventory.mount_id(child)
                    if child_mount != mount and path != "var/lib/secure-ai/vault":
                        raise ArchiveError("unregistered source mount")
                    walk(child, path, child_mount)
                finally:
                    os.close(child)
        if inventory.identity(os.fstat(fd)) != before:
            raise ArchiveError("managed source namespace changed during inventory")

    for prefix in ("var/lib/secure-ai", "etc/secure-ai"):
        try:
            fd = inventory.open_directory(root / prefix)
        except FileNotFoundError:
            continue
        try:
            walk(fd, prefix, inventory.mount_id(fd))
        finally:
            os.close(fd)


def create_archive(root: Path, output: Path, installed: dict, selected: list[str], release_sha256: str,
                   limits: LimitProfile | None = None, *, kind: str = "partial-export") -> dict:
    limits = limits or Limits()
    if kind != "partial-export":
        raise ArchiveError("full backup requires maintenance, producer, enrollment and rotation prerequisites")
    if not DIGEST.fullmatch(release_sha256):
        raise ArchiveError("a source release digest is required")
    known = {c["id"]: c for c in installed["classes"]}
    if not selected or len(set(selected)) != len(selected) or any(n not in known for n in selected):
        raise ArchiveError("select a nonempty unique set of known classes")
    if any(known[n]["adapter"] != "bytes-v1" or known[n]["shape"] != "tree" for n in selected):
        raise ArchiveError("selected class has an unsupported producer adapter or excluded authority")
    budget, trees = Budget(limits), {}
    budget.manifest_bytes = 2 * len(inventory.encode(installed)) + 4096
    started = datetime.now(timezone.utc).isoformat()
    parent = inventory.open_directory(output.parent)
    created_output = False
    try:
        scan_native(root, installed, limits)
        for name in selected:
            if output.absolute().is_relative_to((root / known[name]["source"]).absolute()):
                raise ArchiveError("output must be outside included source roots")
            tree = inventory.SourceTree(root / known[name]["source"], limits, budget)
            trees[name] = tree
        # Conservative space estimate before the first source byte is copied.
        required = budget.total + budget.entries * 1024 + limits.manifest + 10240
        inventory.check_space(parent, min(required, limits.archive), limits)
        classes: dict = {}
        objects: list[dict] = []
        directories: list[dict] = []
        for name, local in known.items():
            adapter = local["adapter"]
            classes[name] = {"adapter": adapter, "files": 0, "directories": 0, "bytes": 0,
                             "disposition": "excluded_authority" if adapter == "excluded" else "not_applicable",
                             "reason": "regenerate_or_reconcile" if adapter == "excluded" else
                             "unsupported_adapter_partial_export" if adapter == "unsupported" else "not_selected_partial_export"}
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        created_output = True
        with os.fdopen(fd, "wb") as handle:
            sink = BoundedWriter(handle, limits.archive, budget)
            with tarfile.open(fileobj=sink, mode="w|gz", format=tarfile.USTAR_FORMAT) as archive:
                for name, tree in trees.items():
                    record = classes[name]
                    record.update(disposition="empty" if len(tree.records) == 1 else "included", reason="selected_inert_bytes")
                    for item in sorted(tree.records, key=lambda r: r["path"]):
                        budget.check()
                        if item["kind"] == "directory":
                            directories.append({"class": name, "path": item["path"]})
                            record["directories"] += 1
                            continue
                        object_id = f"objects/{len(objects) + 1:08d}"
                        with tree.file(item) as source_fd:
                            digest = hashlib.sha256()

                            class HashReader:
                                def read(self, size: int) -> bytes:
                                    budget.check()
                                    data = os.read(source_fd, size)
                                    digest.update(data)
                                    return data

                            _member(archive, object_id, item["size"], HashReader())
                        objects.append({"class": name, "path": item["path"], "id": object_id,
                                        "size": item["size"], "sha256": digest.hexdigest()})
                        record["files"] += 1
                        record["bytes"] += item["size"]
                for tree in trees.values():
                    tree.verify()
                scan_native(root, installed, limits)
                finished = datetime.now(timezone.utc).isoformat()
                value = {"format": "secure-ai-backup", "format_version": 3, "inventory_version": 1,
                         "backup_id": str(uuid.uuid4()), "kind": kind, "created_at": finished,
                         "snapshot_started_at": started, "snapshot_finished_at": finished,
                         "source": {"adapter": "native-v1", "release_sha256": release_sha256, "schemas": {"bytes": 1}},
                         "inventory_sha256": inventory.inventory_digest(installed), "classes": classes,
                         "objects": objects, "directories": directories,
                         "totals": {"files": len(objects), "directories": len(directories), "bytes": budget.total},
                         "consistency": {"status": "partial_unquiesced", "active_restore": False,
                                         "missing_prerequisites": inventory.PREREQUISITES},
                         "reacquisition": [], "luks_header": None,
                         "historical_evidence": {"status": "not_verified", "keys": []}}
                data = inventory.encode(value)
                if len(data) > limits.manifest:
                    raise ArchiveError("generated manifest size limit exceeded")
                validate_manifest(value, {o["id"]: {"size": o["size"], "sha256": o["sha256"]} for o in objects}, installed, limits)
                _member(archive, "manifest.json", len(data), io.BytesIO(data))
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent)
        inventory.check_directory_binding(output.parent, parent)
        return value
    except BaseException:
        if created_output:
            os.unlink(output.name, dir_fd=parent)
        raise
    finally:
        for tree in trees.values():
            tree.close()
        os.close(parent)


def age_transform(source: Path, output: Path, *, decrypt: bool, identity: Path | None = None,
                  recipient: str | None = None, expected_sha256: str | None = None,
                  transport_sha256: str | None = None,
                  age_binary: str = "age", limits: LimitProfile | None = None) -> dict:
    """Bounded private-pipe child; its final exit must pass before result publication.

    expected_sha256 is a digest from an independently held recovery receipt. A
    digest discovered beside the ciphertext is only transport information. Keys
    are passed as inherited descriptors; no credential bytes enter argv or logs.
    """
    limits = limits or Limits()
    budget = Budget(limits)
    executable = shutil.which(age_binary)
    if executable is None:
        raise ArchiveError("age executable is unavailable")
    if expected_sha256 is not None and not DIGEST.fullmatch(expected_sha256):
        raise ArchiveError("invalid trusted receipt digest")
    if transport_sha256 is not None and not DIGEST.fullmatch(transport_sha256):
        raise ArchiveError("invalid transport digest")
    if decrypt and (identity is None or recipient is not None):
        raise ArchiveError("bounded decryption requires an explicit unencrypted age identity file")
    if not decrypt and (identity is not None or not isinstance(recipient, str) or
                        not re.fullmatch(r"age1[0-9a-z]{58}", recipient)):
        raise ArchiveError("bounded export requires a native X25519 public recipient")
    parent = inventory.open_directory(output.parent)
    temporary = ".age-partial-" + uuid.uuid4().hex
    out, proc, identity_fd = -1, None, -1
    created_output = False
    try:
        parent_stat = os.fstat(parent)
        if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise ArchiveError("age staging parent must be private and caller-owned")
        maximum = limits.ciphertext if decrypt else limits.archive
        with inventory.pinned_file(source, maximum) as (source_fd, source_stat):
            digest = hashlib.sha256()
            read_count = 0
            while chunk := os.read(source_fd, CHUNK):
                budget.check()
                read_count += len(chunk)
                if read_count > source_stat.st_size:
                    raise ArchiveError("age input size changed")
                digest.update(chunk)
            if read_count != source_stat.st_size:
                raise ArchiveError("age input size changed")
            if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
                raise ArchiveError("trusted recovery receipt digest mismatch")
            if transport_sha256 is not None and digest.hexdigest() != transport_sha256:
                raise ArchiveError("transport digest mismatch")
            os.lseek(source_fd, 0, os.SEEK_SET)
            # Age output is at most input for decrypt; conservatively budget
            # X25519 encryption overhead without relying on compression savings.
            maximum_output = limits.archive if decrypt else limits.ciphertext
            needed = min(maximum_output, source_stat.st_size if decrypt else source_stat.st_size + source_stat.st_size // 4096 + 1024 * 1024)
            inventory.check_space(parent, needed, limits)
            args, inherited = [str(Path(executable).absolute())], []
            if decrypt:
                assert identity is not None
                # Restrict native identity data to avoid plugin/SSH/password
                # helpers, prompts, arbitrary subprocesses and unbounded reads.
                with inventory.pinned_file(identity, 4096) as (key_fd, key_stat):
                    if key_stat.st_uid != os.geteuid() or key_stat.st_mode & 0o077:
                        raise ArchiveError("identity must be private and caller-owned")
                    key_data = os.read(key_fd, 4097)
                    lines = [line for line in key_data.splitlines() if line and not line.startswith(b"#")]
                    if len(lines) != 1 or not re.fullmatch(rb"AGE-SECRET-KEY-1[0-9A-Z]{58}", lines[0]):
                        raise ArchiveError("unsupported identity adapter; native age key required")
                    identity_fd = os.memfd_create("backup-age-identity", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                    write_all(identity_fd, lines[0] + b"\n")
                    os.lseek(identity_fd, 0, os.SEEK_SET)
                    import fcntl
                    # Linux UAPI constants (linux/fcntl.h). Some packaged
                    # CPython builds omit their symbolic exports.
                    fcntl.fcntl(identity_fd, 1033, 0x000F)  # F_ADD_SEALS, all four immutable seals
                    if fcntl.fcntl(identity_fd, 1034) & 0x000F != 0x000F:
                        raise ArchiveError("identity memory descriptor could not be sealed")
                args += ["-d", "-i", f"/proc/self/fd/{identity_fd}"]
                inherited.append(identity_fd)
            else:
                assert isinstance(recipient, str)
                args += ["-r", recipient]
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=parent)
            # Source is pinned stdin, never a pathname reopened by age. Stderr
            # is deliberately discarded to avoid secret-bearing tool diagnostics.
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, pass_fds=tuple(inherited),
                                    start_new_session=True, close_fds=True,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            assert proc.stdout is not None and proc.stdin is not None
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stdin.fileno(), False)
            count, output_digest = 0, hashlib.sha256()
            input_count, stream_digest, pending = 0, hashlib.sha256(), b""
            input_complete = False
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                selector.register(proc.stdin, selectors.EVENT_WRITE)
                eof = False
                while not eof:
                    budget.check()
                    for key, _event in selector.select(min(0.1, max(0, budget.deadline - time.monotonic()))):
                        if key.fileobj is proc.stdin:
                            if not pending:
                                pending = os.read(source_fd, min(CHUNK, source_stat.st_size - input_count + 1))
                                input_count += len(pending)
                                if input_count > source_stat.st_size:
                                    raise ArchiveError("age input size changed")
                                stream_digest.update(pending)
                                if not pending:
                                    selector.unregister(proc.stdin)
                                    proc.stdin.close()
                                    input_complete = True
                                    continue
                            try:
                                written = os.write(proc.stdin.fileno(), pending)
                            except BrokenPipeError as exc:
                                raise ArchiveError("age integrity/decryption or encryption failed") from exc
                            pending = pending[written:]
                            continue
                        chunk = os.read(proc.stdout.fileno(), CHUNK)
                        if not chunk:
                            eof = True
                            break
                        count += len(chunk)
                        if count > maximum_output:
                            raise ArchiveError("age output size limit exceeded")
                        inventory.check_space(parent, len(chunk), limits)
                        write_all(out, chunk)
                        output_digest.update(chunk)
                try:
                    status = proc.wait(timeout=max(0.001, budget.deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    raise ArchiveError("age deadline exceeded") from exc
            if status != 0 or not count or not input_complete:
                raise ArchiveError("age integrity/decryption or encryption failed")
            # Rehash the same pinned bytes: the trusted receipt must describe
            # exactly the stream age consumed even if an input writer raced it.
            if stream_digest.digest() != digest.digest() or input_count != source_stat.st_size:
                raise ArchiveError("age input changed during operation")
            os.fsync(out)
            os.close(out)
            out = -1
        inventory.check_directory_binding(output.parent, parent)
        # Link is atomic no-replace publication on the same staging filesystem.
        os.link(temporary, output.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        created_output = True
        os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)
        inventory.check_directory_binding(output.parent, parent)
        return {"sha256": output_digest.hexdigest(), "bytes": count,
                "input_sha256": digest.hexdigest(), "integrity": "age_verified" if decrypt else "created_not_restore_verified",
                "origin": "trusted_receipt_match" if decrypt and expected_sha256 else "origin_unverified",
                "freshness": "not_established", "active_restore": False}
    except BaseException:
        if created_output:
            os.unlink(output.name, dir_fd=parent)
        raise
    finally:
        if proc is not None:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()  # Always reap; no subprocess may retain plaintext pipes.
            if proc.stdout:
                proc.stdout.close()
            if proc.stdin:
                proc.stdin.close()
        if out >= 0:
            os.close(out)
        if identity_fd >= 0:
            os.close(identity_fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def copy_legacy_source(source: Path, destination: Path, limits: LimitProfile | None = None) -> None:
    """Bounded replacement for legacy shell cp -a; never follows source links.

    This only stages the old explicit path selection. It cannot add consistency,
    completeness, source authenticity or portable authority to a v2 archive.
    """
    limits = limits or Limits()
    budget = Budget(limits)
    prior = inventory.SourceTree(destination, limits, budget)
    prior.close()
    metadata = source.lstat()
    directory = stat.S_ISDIR(metadata.st_mode)
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise ArchiveError("legacy source is a link or special object")
    tree = inventory.SourceTree(source if directory else source.parent, limits, budget)
    stage = None
    try:
        stage = Stage(destination, limits, empty=False)
        chosen = [r for r in tree.records if directory or r["path"] == source.name]
        inventory.check_space(stage.fd, sum(r.get("size", 0) for r in chosen), limits)
        for record in chosen:
            budget.check()
            if record["kind"] == "directory":
                continue  # v2 cannot represent empty directories.
            origin = (source if directory else source.parent) / record["path"]
            relative = origin.absolute().relative_to("/").as_posix()
            # Legacy tar names retain their stricter ASCII-only contract.
            if not re.fullmatch(r"[A-Za-z0-9._+@=/-]+", relative):
                raise ArchiveError("legacy filenames require ASCII without spaces")
            target = stage.open(relative, record["size"])
            try:
                with tree.file(record) as fd:
                    remaining = record["size"]
                    while remaining:
                        budget.check()
                        chunk = os.read(fd, min(CHUNK, remaining))
                        if not chunk:
                            raise ArchiveError("short legacy source read")
                        write_all(target, chunk)
                        remaining -= len(chunk)
                os.fsync(target)
            finally:
                os.close(target)
        tree.verify()
    finally:
        tree.close()
        if stage:
            stage.close()

#!/usr/bin/python3 -IB
"""Internal native incoming-tree materialization; no restore or mutation CLI.

Trusted calling code selects pinned private source/component directories and a
fixed documents/outputs class. It must authenticate and verify the inert source
before calling and exclude source writers and policy updates. This does not validate archive trust,
bind live namespaces, supply an installed backend, or reopen admission. Source
metadata never supplies target ownership, permissions, labels or destinations.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Protocol, TypedDict

_spec = importlib.util.spec_from_file_location(
    "stage_native_metadata", Path(__file__).with_name("secure-native-generation-metadata.py"))
assert _spec and _spec.loader
metadata = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(metadata)
guard, inventory = metadata.guard, metadata.inventory
Error = guard.RecoveryError


class StageError(guard.RecoveryError):  # type: ignore[name-defined]  # Runtime-loaded guard exception.
    """A failed operation may retain private work or a complete published tree."""

    def __init__(self, message: str, *, published: bool | None = False,
                 workspace: str | None = None, cleanup_error: str | None = None):
        super().__init__(message)
        self.published = published
        self.durability_confirmed = False
        self.workspace = workspace
        self.cleanup_error = cleanup_error


class PinnedDirectory(Protocol):
    path: Path
    fd: int

    def check(self) -> None: ...


class Deadline(Protocol):
    def check(self) -> None: ...


class _Content(TypedDict):
    bytes: int
    sha256: str


class _Budget:
    def __init__(self, limits, deadline: Deadline):
        self.local, self.operation = inventory.Budget(limits), deadline

    def check(self) -> None:
        self.operation.check()
        self.local.check()

    def add(self, size: int = 0, path: str = "") -> None:
        self.check()
        self.local.add(size, path)


def _require_root() -> None:
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise Error("native incoming materialization requires Linux root authority")


def _limits(requested):
    ceiling = inventory.Limits()
    values = vars(requested or ceiling).copy()
    if (set(values) != set(vars(ceiling)) or
            any(type(value) is not int or not 0 < value <= getattr(ceiling, key)
                for key, value in values.items())):
        raise Error("native staging limits cannot exceed installed finite ceilings")
    return inventory.Limits(**values)


def _private_pin(directory: PinnedDirectory) -> None:
    directory.check()
    info = os.fstat(directory.fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Error("staging requires pinned caller-owned private directories")


def _owned_id(fd: int) -> tuple:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise Error("unproven staging object ownership")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid


def _workspace(parent: PinnedDirectory, name: str, fd: int, identity: dict) -> None:
    parent.check()
    if guard.directory_id(fd) != identity or identity["uid"] != os.geteuid() or identity["mode"] != 0o700:
        raise Error("private staging workspace changed")
    entry = os.open(name, inventory.DIR_FLAGS, dir_fd=parent.fd)
    try:
        if guard.directory_id(entry) != identity:
            raise Error("staging workspace pathname changed; cleanup is ambiguous")
    finally:
        os.close(entry)


def _open_owned(root: int, path: str, created: dict, mount: int) -> int:
    fd = os.open(".", inventory.DIR_FLAGS, dir_fd=root)
    prefix = ""
    try:
        for part in path.split("/") if path else []:
            prefix = prefix + "/" + part if prefix else part
            child = os.open(part, inventory.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            if _owned_id(fd) != created[prefix] or inventory.mount_id(fd) != mount:
                raise Error("staged directory binding changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _hash(fd: int, size: int, budget: _Budget) -> str:
    digest, count = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        budget.check()
        chunk = os.read(fd, min(65536, size + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        if count > size:
            raise Error("staged content grew")
        digest.update(chunk)
    if count != size:
        raise Error("staged content length differs")
    return digest.hexdigest()


def _verify_metadata(fd: int, relative: str, directory: bool, policy, budget: _Budget) -> dict:
    budget.check()
    expected = policy.target_metadata(relative, directory=directory, check=budget.check)
    budget.check()
    actual = metadata.snapshot_existing(fd)
    budget.check()
    context = expected["selinux"].encode("ascii")
    if (actual["kind"] != ("directory" if directory else "file") or
            any(actual[key] != expected[key] for key in ("uid", "gid", "mode")) or
            bytes.fromhex(actual["selinux_hex"] or "") not in (context, context + b"\0")):
        raise Error("materialized metadata differs from installed policy")
    return actual


def _apply(fd: int, relative: str, directory: bool, policy, budget: _Budget) -> None:
    budget.check()
    expected = policy.target_metadata(relative, directory=directory, check=budget.check)
    budget.check()
    os.fchown(fd, expected["uid"], expected["gid"])
    os.fchmod(fd, expected["mode"])
    os.setxattr(fd, "security.selinux", expected["selinux"].encode("ascii") + b"\0")
    _verify_metadata(fd, relative, directory, policy, budget)
    os.fsync(fd)
    budget.check()


def _publication_state(parent: int, work: int, created: dict) -> bool | None:
    """Account for an exception from a trusted post-rename IO hook as well."""
    for directory, name, published in ((parent, "incoming", True), (work, "tree", False)):
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            return None
        identity = info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid
        if identity == created["tree"]:
            return published
    return None


def _census(root, expected, mount, check):
    def walk(fd, prefix):
        check()
        allowed = {key[len(prefix):].split("/")[0] for key in expected
                   if key.startswith(prefix) and key != prefix.rstrip("/")}
        if guard.names(fd, len(expected) + 1) != allowed:
            raise Error("unknown staging entries; cleanup is ambiguous")
        for basename in sorted(allowed):
            check()
            path = prefix + basename
            info = os.stat(basename, dir_fd=fd, follow_symlinks=False)
            flags = inventory.DIR_FLAGS if stat.S_ISDIR(info.st_mode) else inventory.FILE_FLAGS
            child = os.open(basename, flags, dir_fd=fd)
            try:
                if (_owned_id(child) != expected[path] or inventory.mount_id(child) != mount
                        or (stat.S_ISREG(info.st_mode) and os.fstat(child).st_nlink != 1)):
                    raise Error("staging object changed; cleanup is ambiguous")
                if stat.S_ISDIR(info.st_mode):
                    walk(child, path + "/")
            finally:
                os.close(child)

    walk(root, "")


def _cleanup(parent, name, work, identity, created, published):
    """Only known owned work is removable; ambiguous namespaces remain intact."""
    deadline = guard.Deadline(guard.LinuxClock(), 5)
    _workspace(parent, name, work, identity)
    expected = {} if published else created
    _census(work, expected, identity["mount"], deadline.check)
    for path in sorted(expected, key=lambda value: (value.count("/"), value), reverse=True):
        deadline.check()
        prefix, _, basename = path.rpartition("/")
        directory = _open_owned(work, prefix, expected, identity["mount"])
        try:
            info = os.stat(basename, dir_fd=directory, follow_symlinks=False)
            current = info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid
            if current != expected[path]:
                raise Error("staging object changed before cleanup")
            if stat.S_ISDIR(info.st_mode):
                os.rmdir(basename, dir_fd=directory)
            else:
                os.unlink(basename, dir_fd=directory)
        finally:
            os.close(directory)
    deadline.check()
    _workspace(parent, name, work, identity)
    os.rmdir(name, dir_fd=parent.fd)
    os.fsync(parent.fd)


def materialize_incoming(parent: PinnedDirectory, source: PinnedDirectory, class_id: str,
                         *, limits=None, deadline: Deadline | None = None, io=None) -> dict:
    """Copy a caller-verified inert tree to fixed parent/incoming without clobber.

    Source is one selected, verified class-relative logical tree, not the v3
    object envelope. Manifest-to-logical-tree mapping belongs to its caller.
    A StageError with published=True means the complete tree was renamed but its
    final durability is unconfirmed. published=None means the rename outcome
    cannot be established; neither incoming nor private work is cleaned then.
    Caller-owned pinned directory handles remain open and are never rewritten.
    """
    return _materialize(parent, source, class_id, limits=limits, deadline=deadline, io=io)


def materialize_archive_incoming(parent: PinnedDirectory, source: PinnedDirectory, class_id: str,
                                 *, verified_manifest_sha256: str, limits=None,
                                 deadline: Deadline | None = None, io=None) -> dict:
    """Map an authenticated v3 extracted object envelope to private incoming.

    The digest is the canonical manifest SHA-256 retained from the caller's
    authenticated archive verification. A digest from the writable envelope
    alone establishes no origin or freshness. All envelope objects are verified
    against that manifest; selected file bytes are checked again while copying.
    The installed policy supplies all target metadata. No CLI invokes this path.
    """
    return _materialize(parent, source, class_id, limits=limits, deadline=deadline, io=io,
                        object_archive=True, verified_manifest_sha256=verified_manifest_sha256)


def _materialize(parent: PinnedDirectory, source: PinnedDirectory, class_id: str, *, limits=None,
                 deadline: Deadline | None = None, io=None, object_archive: bool = False,
                 verified_manifest_sha256: str | None = None) -> dict:
    _require_root()
    limits = _limits(limits)
    deadline = deadline or guard.Deadline(guard.LinuxClock(), limits.seconds)
    budget = _Budget(limits, deadline)
    tree = None
    work = -1
    name = None
    identity = None
    created: dict = {}
    published: bool | None = False
    try:
        budget.check()
        _private_pin(parent)
        _private_pin(source)
        if parent.path.is_relative_to(source.path):
            raise Error("destination cannot be inside the verified source tree")
        policy = metadata.installed_incoming_policy(class_id)
        budget.check()
        try:
            os.stat("incoming", dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Error("incoming already exists")
        if object_archive:
            spec = importlib.util.spec_from_file_location(
                "stage_archive_class", Path(__file__).with_name("secure-backup-class-tree.py"))
            assert spec and spec.loader
            archive_class = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(archive_class)
            installed = inventory.load_inventory(metadata.INVENTORY, trusted=True)
            tree = archive_class.ClassTree(source.path, class_id, verified_manifest_sha256,
                                           installed, limits, budget)
            if tree.inventory_sha256 != policy.inventory_sha256:
                raise Error("archive and installed incoming policy differ")
        else:
            tree = inventory.SourceTree(source.path, limits, budget)
        if (inventory.identity(os.fstat(tree.fd)) != inventory.identity(os.fstat(source.fd))
                or tree.mount != inventory.mount_id(source.fd)):
            raise Error("verified source binding changed")
        for record in tree.records:
            budget.check()
            value = tree.directories[record["path"]] if record["kind"] == "directory" else record["identity"]
            if value[4] != os.geteuid() or stat.S_IMODE(value[2]) != (0o700 if record["kind"] == "directory" else 0o600):
                raise Error("verified source is not a private inert tree")
        inventory.check_space(parent.fd, budget.local.total + budget.local.manifest_bytes, limits)
        candidate = ".secai-native-stage-" + secrets.token_hex(16)
        os.mkdir(candidate, 0o700, dir_fd=parent.fd)
        name = candidate
        work = os.open(name, inventory.DIR_FLAGS, dir_fd=parent.fd)
        identity = guard.directory_id(work)
        _workspace(parent, name, work, identity)
        hashes: dict[str, _Content] = {}
        for record in tree.records:
            budget.check()
            relative = record["path"]
            target = "tree" + ("/" + relative if relative else "")
            prefix, _, basename = target.rpartition("/")
            destination = _open_owned(work, prefix, created, identity["mount"])
            out = -1
            try:
                if record["kind"] == "directory":
                    os.mkdir(basename, 0o700, dir_fd=destination)
                    out = os.open(basename, inventory.DIR_FLAGS, dir_fd=destination)
                    created[target] = _owned_id(out)
                else:
                    inventory.check_space(destination, record["size"], limits)
                    out = os.open(basename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=destination)
                    created[target] = _owned_id(out)
                    digest, count = hashlib.sha256(), 0
                    with tree.file(record) as origin:
                        while True:
                            budget.check()
                            chunk = os.read(origin, min(65536, record["size"] + 1 - count))
                            if not chunk:
                                break
                            count += len(chunk)
                            if count > record["size"]:
                                raise Error("verified source grew during materialization")
                            digest.update(chunk)
                            remaining = memoryview(chunk)
                            while remaining:
                                budget.check()
                                written = os.write(out, remaining)
                                if written <= 0:
                                    raise Error("short native staging write")
                                remaining = remaining[written:]
                    if (count != record["size"] or _hash(out, count, budget) != digest.hexdigest()
                            or ("sha256" in record and digest.hexdigest() != record["sha256"])):
                        raise Error("copied bytes differ from verified source")
                    hashes[relative] = {"bytes": count, "sha256": digest.hexdigest()}
                    _apply(out, relative, False, policy, budget)
            finally:
                if out >= 0:
                    os.close(out)
                os.close(destination)
        for path in sorted((key for key in created if created[key][2] == stat.S_IFDIR),
                           key=lambda value: (value.count("/"), value), reverse=True):
            budget.check()
            fd = _open_owned(work, path, created, identity["mount"])
            try:
                _apply(fd, path[5:] if path != "tree" else "", True, policy, budget)
            finally:
                os.close(fd)
        for path in sorted(created):
            budget.check()
            prefix, _, basename = path.rpartition("/")
            directory = _open_owned(work, prefix, created, identity["mount"])
            fd = -1
            try:
                is_directory = created[path][2] == stat.S_IFDIR
                fd = os.open(basename, inventory.DIR_FLAGS if is_directory else inventory.FILE_FLAGS,
                             dir_fd=directory)
                if _owned_id(fd) != created[path] or inventory.mount_id(fd) != identity["mount"]:
                    raise Error("materialized object binding changed")
                relative = path[5:] if path != "tree" else ""
                _verify_metadata(fd, relative, is_directory, policy, budget)
                if not is_directory and _hash(fd, hashes[relative]["bytes"], budget) != hashes[relative]["sha256"]:
                    raise Error("materialized bytes changed before publication")
            finally:
                if fd >= 0:
                    os.close(fd)
                os.close(directory)
        _workspace(parent, name, work, identity)
        _census(work, created, identity["mount"], budget.check)
        tree.verify()
        budget.check()
        _private_pin(source)
        _private_pin(parent)
        if metadata.installed_incoming_policy(class_id) != policy:
            raise Error("installed native policy changed during materialization")
        budget.check()
        _workspace(parent, name, work, identity)
        root = _open_owned(work, "tree", created, identity["mount"])
        try:
            _verify_metadata(root, "", True, policy, budget)
        finally:
            os.close(root)
        os.fsync(work)
        budget.check()
        try:
            (io or guard.DurableIO()).no_replace(work, "tree", parent.fd, "incoming", "native-stage:publish")
        except BaseException:
            published = _publication_state(parent.fd, work, created)
            raise
        published = True
        os.fsync(work)
        os.fsync(parent.fd)
        budget.check()
        tree.verify()
        _private_pin(source)
        _private_pin(parent)
        _cleanup(parent, name, work, identity, created, True)
        name = None
        budget.check()
        return {"class": class_id, "entries": len(tree.records),
                "bytes": sum(record["size"] for record in tree.records if record["kind"] == "file"),
                "content_sha256": hashlib.sha256(guard.encode(hashes)).hexdigest(),
                "inventory_sha256": policy.inventory_sha256, "published": True, "durability_confirmed": True}
    except BaseException as exc:
        cleanup_error = None
        if name is not None:
            try:
                if published is None or work < 0 or identity is None:
                    raise Error("workspace ownership unverified; cleanup is ambiguous")
                _cleanup(parent, name, work, identity, created, published)
                name = None
            except Exception as cleanup:
                cleanup_error = str(cleanup)
        if not isinstance(exc, Exception):
            raise
        raise StageError(str(exc), published=published,
                         workspace=str(parent.path / name) if name is not None else None,
                         cleanup_error=cleanup_error) from exc
    finally:
        if tree is not None:
            tree.close()
        if work >= 0:
            os.close(work)


if __name__ == "__main__":
    raise SystemExit("internal native incoming materializer; active restore remains unavailable")

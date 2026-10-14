#!/usr/bin/env python3
"""Maintenance primitives. Native lease/exec integration is unavailable.

The library operates only with paths and mappings supplied by trusted calling
code. B1's concrete backend lives in tests; no CLI accepts fixture paths or
executes a command. A future installed adapter must also prove writer cgroups,
triggers, mount semantics and emergency coordination.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Protocol

_spec = importlib.util.spec_from_file_location(
    "maintenance_inventory", Path(__file__).with_name("secure-backup-inventory.py"))
assert _spec and _spec.loader
_inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_inventory)

encode = _inventory.encode
open_directory = _inventory.open_directory
mount_id = _inventory.mount_id
DIR_FLAGS = _inventory.DIR_FLAGS
FILE_FLAGS = _inventory.FILE_FLAGS
DOMAIN = "linux-clock-boottime-v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
JOURNAL_FIELDS = {"version", "transaction", "revision", "previous_sha256", "plan_sha256", "phase", "intent",
                  "origin_boot", "execution_boot", "clock_domain", "deadline_ns", "reserved_slots", "reserved_bytes"}
JOURNAL_PHASES = {"created", "quiesced", "preparing", "prepared", "publishing", "published",
                  "validated", "committed", "rolling_back", "rolled_back"}
JOURNAL_ACTIONS = {"none", "prepare-new", "old-to-rollback", "new-to-active", "new-to-stage", "old-to-active"}


class RecoveryError(RuntimeError):
    """An operation remains closed pending safe recovery."""


def strict_json(data: bytes, maximum: int) -> object:
    try:
        return _inventory.strict_json(data, maximum)
    except _inventory.ArchiveError as exc:
        raise RecoveryError("invalid bounded control JSON") from exc


class Clock(Protocol):
    domain: str

    def boot_id(self) -> str: ...

    def now_ns(self) -> int: ...


def valid_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


class LinuxClock:
    domain = DOMAIN

    def boot_id(self) -> str:
        with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as handle:
            value = handle.read(64).strip()
        if not valid_uuid(value):
            raise RecoveryError("kernel boot identity unavailable")
        return value

    def now_ns(self) -> int:
        if not hasattr(time, "CLOCK_BOOTTIME"):
            raise RecoveryError("CLOCK_BOOTTIME unavailable; no clock fallback")
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class Deadline:
    def __init__(self, clock: Clock, seconds: int, *, boot: str | None = None, end: int | None = None):
        if type(seconds) is not int or not 1 <= seconds <= 3600:
            raise RecoveryError("invalid finite operation deadline")
        self.clock = clock
        self.boot = boot or clock.boot_id()
        self.last = -1
        now = self.sample()
        self.end = now + seconds * 1_000_000_000 if end is None else end
        if type(self.end) is not int or not 0 <= self.end <= 2**63 - 1:
            raise RecoveryError("invalid deadline value")

    def sample(self) -> int:
        if self.clock.domain != DOMAIN or not valid_uuid(self.boot) or self.clock.boot_id() != self.boot:
            raise RecoveryError("boot or clock domain changed")
        now = self.clock.now_ns()
        if type(now) is not int or not 0 <= now <= 2**63 - 1 or now < self.last:
            raise RecoveryError("invalid or regressed BOOTTIME clock")
        self.last = now
        return now

    def check(self) -> None:
        if self.sample() >= self.end:
            raise RecoveryError("operation deadline expired; admission remains closed")


def directory_id(fd: int) -> dict:
    metadata = os.fstat(fd)
    return {"device": metadata.st_dev, "inode": metadata.st_ino, "mount": mount_id(fd),
            "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}


def file_id(fd: int) -> dict:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RecoveryError("control file must be regular and singly linked")
    return {"device": metadata.st_dev, "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}


def private_directory(path: Path) -> int:
    fd = open_directory(path)
    metadata = os.fstat(fd)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(fd)
        raise RecoveryError("B1 library requires a private caller-owned directory")
    return fd


class BoundDirectory:
    def __init__(self, path: Path):
        self.path = path.absolute()
        self.fd = private_directory(self.path)
        self.identity = directory_id(self.fd)

    def check(self, *, allow_mount_rebind: bool = False) -> None:
        reopened = private_directory(self.path)
        try:
            current = directory_id(reopened)
            opened = directory_id(self.fd)
            keys = set(self.identity) - ({"mount"} if allow_mount_rebind else set())
            if any(current[k] != self.identity[k] or opened[k] != self.identity[k] for k in keys):
                raise RecoveryError("directory or mount binding changed")
        finally:
            os.close(reopened)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class DurableIO:
    """Hooks are trusted-code test instrumentation, never parsed input."""

    def __init__(self, hook: Callable[[str], None] | None = None):
        self.hook = hook or (lambda _event: None)
        self.libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(self.libc, "renameat2", None)
        if rename is None:
            raise RecoveryError("atomic no-replace rename unavailable")
        self.rename = rename
        self.rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        self.rename.restype = ctypes.c_int

    def sync(self, fd: int, event: str) -> None:
        self.hook(event + ":before-fsync")
        os.fsync(fd)
        self.hook(event + ":after-fsync")

    def no_replace(self, source_fd: int, source: str, target_fd: int, target: str, event: str) -> None:
        self.hook(event + ":before-rename")
        if self.rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "no-replace rename failed")
        self.hook(event + ":after-rename")

    def create(self, parent: int, name: str, data: bytes, event: str) -> None:
        self.hook(event + ":before-create")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            for offset in range(0, len(data), 4096):
                remaining = memoryview(data)[offset:offset + 4096]
                while remaining:
                    count = os.write(fd, remaining)
                    if count <= 0:
                        raise RecoveryError("short control-record write")
                    remaining = remaining[count:]
                    self.hook(event + ":after-write")
            self.sync(fd, event)
        finally:
            os.close(fd)

    def replace_json(self, parent: int, name: str, value: dict, event: str, maximum: int = 4096) -> None:
        data = encode(value)
        if len(data) > maximum:
            raise RecoveryError("control record exceeds logical metadata limit")
        temporary = ".next-" + name
        self.create(parent, temporary, data, event + ":temporary")
        self.hook(event + ":before-replace")
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        self.hook(event + ":after-replace")
        self.sync(parent, event + ":directory")

    def promote_json(self, parent: int, name: str, expected: dict, event: str) -> None:
        """Finish an exact known pending control write, never arbitrary debris."""
        if read_json(parent, ".next-" + name) != expected:
            raise RecoveryError("pending control record differs from verified transition")
        self.hook(event + ":before-replace")
        os.replace(".next-" + name, name, src_dir_fd=parent, dst_dir_fd=parent)
        self.hook(event + ":after-replace")
        self.sync(parent, event + ":directory")


def read_bytes(parent: int, name: str, maximum: int) -> bytes:
    fd = os.open(name, FILE_FLAGS, dir_fd=parent)
    try:
        identity = file_id(fd)
        metadata = os.fstat(fd)
        if identity["uid"] != os.geteuid() or identity["mode"] != 0o600 or not 0 < metadata.st_size <= maximum:
            raise RecoveryError("unsafe control-record metadata or size")
        data = bytearray()
        while chunk := os.read(fd, min(4096, maximum + 1 - len(data))):
            data.extend(chunk)
            if len(data) > maximum:
                raise RecoveryError("control record grew beyond limit")
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (_inventory.identity(metadata) != _inventory.identity(after) or
                _inventory.identity(metadata) != _inventory.identity(current)):
            raise RecoveryError("control record changed during read")
        return bytes(data)
    finally:
        os.close(fd)


def read_json(parent: int, name: str, maximum: int = 4096) -> dict:
    try:
        value = strict_json(read_bytes(parent, name, maximum), maximum)
    except _inventory.ArchiveError as exc:
        raise RecoveryError("invalid bounded control JSON") from exc
    if not isinstance(value, dict):
        raise RecoveryError("control record must be an object")
    return value


def names(fd: int, maximum: int) -> set[str]:
    # Retained descriptions can omit entries replaced since their first read
    # (observed on Btrfs). dup() shares that view; open "." independently while
    # remaining anchored to the exact pinned directory, not its pathname.
    identity = directory_id(fd)
    fresh = os.open(".", DIR_FLAGS, dir_fd=fd)
    try:
        if directory_id(fresh) != identity or directory_id(fd) != identity:
            raise RecoveryError("control directory identity changed")
        found = set()
        with os.scandir(fresh) as iterator:
            for entry in iterator:
                found.add(entry.name)
                if len(found) > maximum:
                    raise RecoveryError("control namespace count exceeded")
        if directory_id(fresh) != identity or directory_id(fd) != identity:
            raise RecoveryError("control directory changed during enumeration")
        return found
    finally:
        os.close(fresh)


class StableLock:
    def __init__(self, directory: BoundDirectory, name: str, expected: dict):
        self.directory, self.name, self.expected = directory, name, expected
        self.fd = os.open(name, FILE_FLAGS, dir_fd=directory.fd)
        try:
            self.check()
        except BaseException:
            os.close(self.fd)
            raise

    def check(self) -> None:
        self.directory.check()
        if file_id(self.fd) != self.expected:
            raise RecoveryError("stable lock identity changed")
        other = os.open(self.name, FILE_FLAGS, dir_fd=self.directory.fd)
        try:
            if file_id(other) != self.expected:
                raise RecoveryError("stable lock pathname was replaced")
        finally:
            os.close(other)

    def acquire(self, exclusive: bool, deadline: Deadline) -> None:
        for _attempt in range(250):
            deadline.check()
            self.check()
            try:
                fcntl.flock(self.fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                self.check()
                return
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
            time.sleep(0.02)
        raise RecoveryError("stable lock busy; no process is killed to force admission")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class Gate:
    """Private B1 library gate; native installation/privilege adapters are absent."""

    def __init__(self, root: Path, runtime: Path, clock: Clock | None = None, io: DurableIO | None = None):
        self.root = BoundDirectory(root)
        try:
            self.runtime = BoundDirectory(runtime)
        except BaseException:
            self.root.close()
            raise
        try:
            self.clock = clock or LinuxClock()
            self.io = io or DurableIO()
            self.layout = read_json(self.root.fd, "layout.json")
            if set(self.layout) != {"version", "root", "admission", "operation"} or type(self.layout["version"]) is not int or self.layout["version"] != 1:
                raise RecoveryError("invalid gate layout")
            self.check(allow_pending=True)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def initialize(root: Path, runtime: Path, clock: Clock | None = None, io: DurableIO | None = None) -> None:
        clock, io = clock or LinuxClock(), io or DurableIO()
        Deadline(clock, 5).check()
        directory = BoundDirectory(root)
        running = None
        try:
            running = BoundDirectory(runtime)
            if names(directory.fd, 16) or names(running.fd, 16):
                raise RecoveryError("initialization requires known empty directories; never resets state")
            os.mkdir("transactions", 0o700, dir_fd=directory.fd)
            io.sync(directory.fd, "initialize:transactions")
            layout = {"version": 1, "root": directory_id(directory.fd)}
            for name in ("admission", "operation"):
                io.create(directory.fd, name + ".lock", b"stable\n", "initialize:" + name)
                fd = os.open(name + ".lock", FILE_FLAGS, dir_fd=directory.fd)
                try:
                    layout[name] = file_id(fd)
                finally:
                    os.close(fd)
            io.create(directory.fd, "layout.json", encode(layout), "initialize:layout")
            io.sync(directory.fd, "initialize:layout-parent")
            gate = {"version": 1, "state": "open", "transaction": None, "history": [], "epoch": str(uuid.uuid4())}
            io.replace_json(directory.fd, "gate.json", gate, "initialize:gate")
            io.replace_json(running.fd, "ready.json", {"version": 1, "epoch": gate["epoch"], "boot": clock.boot_id(), "domain": DOMAIN}, "initialize:ready")
        finally:
            directory.close()
            if running is not None:
                running.close()

    def check(self, *, allow_pending: bool = False) -> None:
        self.root.check()
        self.runtime.check()
        if read_json(self.root.fd, "layout.json") != self.layout or directory_id(self.root.fd) != self.layout["root"]:
            raise RecoveryError("gate layout binding changed")
        allowed = {"layout.json", "gate.json", "admission.lock", "operation.lock", "transactions"}
        root_names = names(self.root.fd, 16)
        runtime_names = names(self.runtime.fd, 4)
        if allow_pending:
            valid = allowed.issubset(root_names) and not root_names - allowed - {".next-gate.json"}
            valid = valid and not runtime_names - {"ready.json", ".next-ready.json"}
        else:
            valid = root_names == allowed and runtime_names == {"ready.json"}
        if not valid:
            raise RecoveryError("unknown or incomplete gate metadata")
        for name in ("admission", "operation"):
            lock = StableLock(self.root, name + ".lock", self.layout[name])
            lock.close()

    @staticmethod
    def validate_state(value: dict) -> dict:
        if (set(value) != {"version", "state", "transaction", "history", "epoch"} or
                type(value["version"]) is not int or value["version"] != 1 or
                value["state"] not in ("open", "closed") or not valid_uuid(value["epoch"]) or
                not isinstance(value["history"], list) or len(value["history"]) > 8 or
                any(not valid_uuid(x) for x in value["history"]) or len(set(value["history"])) != len(value["history"])):
            raise RecoveryError("invalid gate schema")
        if value["state"] == "closed" and not valid_uuid(value["transaction"]):
            raise RecoveryError("closed gate has no valid transaction")
        if value["state"] == "open" and value["transaction"] is not None:
            raise RecoveryError("open gate has active transaction")
        return value

    def state(self, *, recovery: bool = False) -> dict:
        self.check(allow_pending=recovery)
        return self.validate_state(read_json(self.root.fd, "gate.json"))

    def require_open(self) -> None:
        value = self.state()
        ready = read_json(self.runtime.fd, "ready.json")
        if type(ready.get("version")) is not int or value["state"] != "open" or ready != {"version": 1, "epoch": value["epoch"], "boot": self.clock.boot_id(), "domain": DOMAIN}:
            raise RecoveryError("maintenance or fresh boot recovery required")
        metadata_deadline = Deadline(self.clock, 5)
        metadata_deadline.check()
        transactions = os.open("transactions", DIR_FLAGS, dir_fd=self.root.fd)
        try:
            if names(transactions, 9) != set(value["history"]):
                raise RecoveryError("unknown transaction debris blocks admission")
            for identifier in value["history"]:
                metadata_deadline.check()
                child = os.open(identifier, DIR_FLAGS, dir_fd=transactions)
                try:
                    if names(child, 8) != {"plan.json", "records", "head.json", "terminal.json"}:
                        raise RecoveryError("unknown retained transaction metadata")
                    terminal = read_json(child, "terminal.json")
                    if set(terminal) != {"version", "transaction", "outcome", "head_sha256"} or type(terminal["version"]) is not int or terminal["version"] != 1 or terminal["transaction"] != identifier or terminal["outcome"] not in ("committed", "rolled_back") or not isinstance(terminal["head_sha256"], str) or not HEX.fullmatch(terminal["head_sha256"]):
                        raise RecoveryError("unresolved retained transaction")
                    head = read_json(child, "head.json")
                    if (set(head) != {"version", "transaction", "revision", "sha256"} or
                            type(head["version"]) is not int or head["version"] != 1 or
                            type(head["revision"]) is not int or not 1 <= head["revision"] <= 4096 or
                            head["sha256"] != terminal["head_sha256"] or head["transaction"] != identifier):
                        raise RecoveryError("retained terminal head changed")
                    self._verify_history(child, identifier, head, terminal, metadata_deadline)
                finally:
                    os.close(child)
        finally:
            os.close(transactions)

    def _validate_retained_plan(self, plan: object) -> dict:
        """Default admission accepts only B1 plans, never native metadata authority."""
        if (not isinstance(plan, dict) or set(plan) != {"version", "kind", "mapping", "components", "clock_domain", "limits_sha256"} or
                type(plan["version"]) is not int or plan["version"] != 1 or plan["kind"] != "inert-components" or
                plan["clock_domain"] != DOMAIN or not isinstance(plan["components"], dict) or
                not 1 <= len(plan["components"]) <= 128 or any(not isinstance(key, str) or not ID.fullmatch(key) for key in plan["components"])):
            raise RecoveryError("invalid retained plan")
        return plan

    def _verify_history(self, directory: int, identifier: str, head: dict, terminal: dict, deadline: Deadline) -> None:
        """Scrub bounded control evidence; never re-hash live application data."""
        raw_plan = read_bytes(directory, "plan.json", 16 * 1024**2)
        plan = strict_json(raw_plan, 16 * 1024**2)
        plan = self._validate_retained_plan(plan)
        plan_hash = hashlib.sha256(raw_plan).hexdigest()
        records = os.open("records", DIR_FLAGS, dir_fd=directory)
        try:
            if mount_id(records) != mount_id(directory) or names(records, 4096) != {f"{i:08d}.json" for i in range(1, head["revision"] + 1)}:
                raise RecoveryError("unknown or missing retained journal record")
            previous, total, origin, reserve = "0" * 64, 0, None, None
            last_record = None
            for revision in range(1, head["revision"] + 1):
                deadline.check()
                data = read_bytes(records, f"{revision:08d}.json", 1024 * 1024)
                total += len(data)
                if total > 32 * 1024**2:
                    raise RecoveryError("retained journal byte limit exceeded")
                record = strict_json(data, 1024 * 1024)
                if (not isinstance(record, dict) or set(record) != JOURNAL_FIELDS or type(record["version"]) is not int or
                        record["version"] != 1 or type(record["revision"]) is not int or record["revision"] != revision or
                        record["transaction"] != identifier or record["previous_sha256"] != previous or record["plan_sha256"] != plan_hash or
                        not isinstance(record["phase"], str) or record["phase"] not in JOURNAL_PHASES or
                        not valid_uuid(record["origin_boot"]) or not valid_uuid(record["execution_boot"]) or record["clock_domain"] != DOMAIN or
                        type(record["deadline_ns"]) is not int or not 0 <= record["deadline_ns"] <= 2**63 - 1 or
                        type(record["reserved_slots"]) is not int or not 1 <= record["reserved_slots"] <= 520 or
                        type(record["reserved_bytes"]) is not int or not 1 <= record["reserved_bytes"] <= 32 * 1024**2):
                    raise RecoveryError("retained journal chain or schema is corrupt")
                intent = record["intent"]
                if not isinstance(intent, dict) or set(intent) != {"action", "component"} or not isinstance(intent["action"], str) or intent["action"] not in JOURNAL_ACTIONS:
                    raise RecoveryError("unknown retained journal intent")
                if (intent["action"] == "none" and intent["component"] is not None) or (intent["action"] != "none" and (not isinstance(intent["component"], str) or intent["component"] not in plan["components"])):
                    raise RecoveryError("retained journal component is unknown")
                if origin is None:
                    origin = record["origin_boot"]
                    reserve = (record["reserved_slots"], record["reserved_bytes"])
                if record["origin_boot"] != origin or (record["reserved_slots"], record["reserved_bytes"]) != reserve:
                    raise RecoveryError("retained journal identity or reservation changed")
                previous = hashlib.sha256(data).hexdigest()
                last_record = record
            if last_record is None or previous != head["sha256"] or last_record["phase"] != terminal["outcome"] or last_record["intent"] != {"action": "none", "component": None}:
                raise RecoveryError("retained head does not authenticate its referenced record bytes")
        finally:
            os.close(records)

    def lease(self) -> StableLock:
        self.check()
        lock = StableLock(self.root, "admission.lock", self.layout["admission"])
        try:
            lock.acquire(False, Deadline(self.clock, 1))
            self.require_open()
            return lock
        except BaseException:
            lock.close()
            raise

    def operation(self) -> StableLock:
        self.check(allow_pending=True)
        lock = StableLock(self.root, "operation.lock", self.layout["operation"])
        try:
            lock.acquire(True, Deadline(self.clock, 5))
            return lock
        except BaseException:
            lock.close()
            raise

    def close_for(self, identifier: str) -> dict:
        value = self.state()
        self.require_open()
        if not valid_uuid(identifier) or identifier in value["history"] or len(value["history"]) >= 8:
            raise RecoveryError("transaction retention or identifier limit")
        closed = {**value, "state": "closed", "transaction": identifier}
        self.io.replace_json(self.root.fd, "gate.json", closed, "gate:close")
        return closed

    def close(self) -> None:
        self.root.close()
        self.runtime.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", nargs="?", choices=("status", "initialize", "lease-exec"), default="status")
    parser.parse_args()
    print('{"status":"unavailable","native_adapter":false,"reason":"installed maintenance adapter and B2 qualification required"}', file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

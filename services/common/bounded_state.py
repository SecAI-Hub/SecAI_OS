"""Small protected JSON snapshots for session and catalog operational state.

Cooperating processes serialize through an immutable lock inode. Publication is
atomic and durable; this is not an audit chain or an external rollback anchor.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import secrets
import stat
import threading
import time
from pathlib import Path


class StateUnavailable(OSError):
    """Operational state cannot safely authorize work."""


class StateCapacity(ValueError):
    """New state exceeds the configured admission bound."""


class StateBusy(StateUnavailable):
    """Another healthy writer currently holds the bounded transaction lock."""


class StateRejected(Exception):
    """Explicit caller rejection before any external mutation or publication."""


def finite_json(raw: bytes):
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite state number")
        return result
    def constant(value):
        raise ValueError("invalid state number")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate state field")
            result[key] = value
        return result
    return json.loads(raw, parse_float=number, parse_constant=constant,
                      object_pairs_hook=pairs)


def open_directory(path: Path, *, create: bool = False) -> int:
    """Walk absolute components without following a substituted symlink."""
    path = Path(os.path.abspath(path))
    path_only = getattr(os, "O_PATH", os.O_RDONLY)
    descriptor = os.open("/", path_only | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, component in enumerate(path.parts[1:]):
            final = index == len(path.parts) - 2
            made = False
            if create:
                try:
                    os.mkdir(component, 0o770, dir_fd=descriptor)
                    made = True
                    sync_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=descriptor)
                    try:
                        os.fsync(sync_fd)
                    finally:
                        os.close(sync_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(component, (os.O_RDONLY if final or made else path_only)
                              | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            if made:
                # Provisioned native roots retain inherited setgid. Do not
                # request S_ISGID through chmod under RestrictSUIDSGID.
                mode = stat.S_IMODE(os.fstat(next_fd).st_mode)
                if mode & stat.S_ISGID:
                    if mode & 0o070 != 0o070:
                        raise StateUnavailable("state directory requires provisioned group access")
                else:
                    os.fchmod(next_fd, 0o770)
                os.fsync(next_fd)
            os.close(descriptor)
            descriptor = next_fd
        info = os.fstat(descriptor)
        if info.st_mode & 0o002:
            raise StateUnavailable("state directory is world writable")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_file(info, directory_info) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o660}
            or info.st_gid != directory_info.st_gid):
        raise StateUnavailable("unsafe state file")


def stable_lock(directory: int, name: str, *, state_name: str | None = None) -> int:
    """An inode-bound lock cannot be silently replaced by a fresh empty file."""
    created = False
    try:
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                             0o660, dir_fd=directory)
        created = True
    except FileExistsError:
        descriptor = os.open(name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        if created:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fchmod(descriptor, 0o660)
            # A missing lock beside an existing snapshot is recovery, not initialization.
            if state_name is not None:
                try:
                    os.stat(state_name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise StateUnavailable("state lock disappeared")
            info = os.fstat(descriptor)
            identity = f"{info.st_dev}:{info.st_ino}\n".encode("ascii")
            if os.write(descriptor, identity) != len(identity):
                raise StateUnavailable("short lock write")
            os.fsync(descriptor)
            os.fsync(directory)
        # Concurrent first startup can observe the exclusive creator between
        # open/fchmod/write. It must not permanently poison a healthy peer.
        deadline = time.monotonic() + .25
        while not created and os.fstat(descriptor).st_size == 0 and time.monotonic() < deadline:
            time.sleep(.005)
        private_file(os.fstat(descriptor), os.fstat(directory))
        info = os.fstat(descriptor)
        expected = f"{info.st_dev}:{info.st_ino}\n".encode("ascii")
        # A concurrent exclusive creator may not have finished publishing its
        # identity. Fail closed; a retry can read the complete initialized lock.
        if os.pread(descriptor, 128, 0) != expected:
            raise StateUnavailable("state lock identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class BoundedState:
    def __init__(self, path: Path, factory, validate, *, max_bytes: int):
        self.path = Path(path)
        self.factory = factory
        self.validate = validate
        self.max_bytes = max_bytes
        self.failed = False
        self._mutex = threading.RLock()
        self._directory_identity: tuple[int, int] | None = None
        self._lock_identity: tuple[int, int] | None = None

    @contextlib.contextmanager
    def transaction(self, *, write: bool = False, initialize: bool = False):
        with self._mutex:
            if self.failed:
                raise StateUnavailable("state requires recovery")
            directory = lock = None
            fenced = False
            try:
                directory = open_directory(self.path.parent, create=True)
                info = os.fstat(directory)
                identity = (info.st_dev, info.st_ino)
                if self._directory_identity not in (None, identity):
                    raise StateUnavailable("state directory changed")
                self._directory_identity = identity
                lock_name = self.path.name + ".lock"
                lock = stable_lock(directory, lock_name, state_name=self.path.name)
                lock_info = os.fstat(lock)
                lock_identity = (lock_info.st_dev, lock_info.st_ino)
                if self._lock_identity not in (None, lock_identity):
                    raise StateUnavailable("state lock changed")
                self._lock_identity = lock_identity
                deadline = time.monotonic() + 2
                while True:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise StateBusy("state transaction busy") from None
                        time.sleep(.01)
                self._same_inode(directory, lock_name, os.fstat(lock))
                self._check_directory(directory)
                try:
                    os.stat(self.path.name + ".pending", dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise StateUnavailable("unfinished state transaction requires recovery")
                state, previous = self._read(directory, info)
                self.validate(state)
                # Fence before yielding because credential mutation occurs inside
                # this lock too. A killed writer leaves a visible, durable fence.
                if write:
                    self._fence(directory)
                    fenced = True
                yield state
                if write or (initialize and previous is None):
                    self.validate(state)
                    raw = (json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
                    if len(raw) > self.max_bytes:
                        raise StateCapacity("state admission capacity reached")
                    self._same_inode(directory, lock_name, os.fstat(lock))
                    self._check_directory(directory)
                    self._same_inode(directory, self.path.name, previous)
                    if not write:
                        self._fence(directory)
                        fenced = True
                    self._publish(directory, raw)
                    self._unfence(directory)
                    fenced = False
            except (StateCapacity, StateBusy):
                if directory is not None and fenced:
                    self._unfence(directory)
                raise
            except (OSError, ValueError, TypeError, RecursionError) as error:
                self.failed = True
                raise StateUnavailable("state is unavailable; recovery required") from error
            except StateRejected:
                if directory is not None and fenced:
                    self._unfence(directory)
                raise
            except Exception as error:
                # Unknown exceptions may follow credential publication or
                # another external side effect. Never infer a safe rollback.
                self.failed = True
                raise StateUnavailable("unconfirmed state mutation requires recovery") from error
            finally:
                if lock is not None:
                    os.close(lock)
                if directory is not None:
                    os.close(directory)

    def _check_directory(self, directory):
        current = open_directory(self.path.parent)
        try:
            a, b = os.fstat(directory), os.fstat(current)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise StateUnavailable("state directory path changed")
        finally:
            os.close(current)

    def _fence(self, directory):
        fd = os.open(self.path.name + ".pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     0o660, dir_fd=directory)
        try:
            os.fchmod(fd, 0o660)
            os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)

    def _unfence(self, directory):
        try:
            os.unlink(self.path.name + ".pending", dir_fd=directory)
        except FileNotFoundError:
            return
        try:
            os.fsync(directory)
        except OSError:
            # Best effort re-establishment after an uncertain final sync. The
            # in-process latch still closes even if the device rejects this too.
            self.failed = True
            self._fence(directory)
            raise

    def _same_inode(self, directory, name, previous):
        try:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            if previous is not None:
                raise StateUnavailable("state inode disappeared") from None
        else:
            if previous is None or (current.st_dev, current.st_ino) != (previous.st_dev, previous.st_ino):
                raise StateUnavailable("state inode changed")

    def _read(self, directory, info):
        try:
            descriptor = os.open(self.path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 dir_fd=directory)
        except FileNotFoundError:
            return self.factory(), None
        try:
            metadata = os.fstat(descriptor)
            private_file(metadata, info)
            if not 1 <= metadata.st_size <= self.max_bytes:
                raise StateUnavailable("state size is invalid")
            raw = bytearray()
            while len(raw) <= self.max_bytes:
                chunk = os.read(descriptor, min(65536, self.max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) != metadata.st_size:
                raise StateUnavailable("state changed while reading")
            return finite_json(raw), metadata
        finally:
            os.close(descriptor)

    def _publish(self, directory, raw):
        temporary = "." + self.path.name + "." + secrets.token_hex(12)
        descriptor = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 0o660, dir_fd=directory)
            os.fchmod(descriptor, 0o660)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written != len(raw) - offset:
                    raise StateUnavailable("short state write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

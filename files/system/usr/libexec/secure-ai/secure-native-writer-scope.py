#!/usr/bin/python3 -IB
"""Internal B2 writer coordination; not a recovery adapter or mutation CLI.

Only trusted installed code supplies the complete writer/trigger set and the
durable closed-admission predicate. Archive, journal and command-line data must
never select units. This proves only the selected scope, not global quiescence.
Native metadata, boot rebind and emergency-containment qualification remain
separate prerequisites; nothing here reopens admission or starts services.
"""
from __future__ import annotations

import fcntl
import importlib.util
import os
from pathlib import Path
import re
import time
from typing import Callable, Protocol

_spec = importlib.util.spec_from_file_location(
    "native_admission", Path(__file__).with_name("secure-native-admission.py"))
assert _spec and _spec.loader
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
Error = native.Error
_vault_spec = importlib.util.spec_from_file_location(
    "writer_vault_operation", Path(__file__).with_name("vault-operation-lock.py"))
assert _vault_spec and _vault_spec.loader
vault_operation = importlib.util.module_from_spec(_vault_spec)
_vault_spec.loader.exec_module(vault_operation)
_INSTALLER_PATH = Path("/var/lib/secure-ai/.diffusion-install.lock")
_INSTALLER_OWNER_UID = _INSTALLER_OWNER_GID = 0
_INSTALLER_ACQUIRE_SECONDS = 10.0
CGROUP_PARENT = Path("/sys/fs/cgroup/system.slice")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,190}\.(service|timer|path)")


class _Pin(Protocol):
    def empty(self) -> bool: ...
    def close(self) -> None: ...


class WriterScope:
    """A trusted-code capability with no public arbitrary-unit interface."""

    def __init__(self, writers: tuple[str, ...], triggers: tuple[str, ...],
                 closed: Callable[[], bool]):
        if (type(writers) is not tuple or type(triggers) is not tuple or not writers
                or len(writers) + len(triggers) > 128 or not callable(closed)):
            raise Error("invalid trusted writer scope")
        units = writers + triggers
        if (any(type(name) is not str or not NAME.fullmatch(name) for name in units)
                or len(set(units)) != len(units)
                or any(not name.endswith(".service") for name in writers)
                or any(name.endswith(".service") for name in triggers)):
            raise Error("ambiguous or unsupported writer activation scope")
        self.writers, self.triggers, self.closed = writers, triggers, closed
        self.pins: dict[str, _Pin] = {}
        self.masked = False
        self.finished = False
        self.deadline = None

    def _closed(self) -> None:
        if self.finished or self.closed() is not True:
            raise Error("durable closed admission required")

    def _check(self) -> None:
        self._closed()
        if self.deadline is not None:
            self.deadline.check()

    def _show(self, name: str) -> dict[str, str]:
        self._check()
        value = native.show(name)
        self._check()
        return value

    def _manager(self, *args: str) -> None:
        self._check()
        native.manager(*args)
        self._check()

    def _empty(self, pin) -> bool:
        self._check()
        value = pin.empty()
        self._check()
        return value is True

    def _writer(self, name: str) -> dict[str, str]:
        value = self._show(name)
        path = "/system.slice/" + name
        if value.get("ControlGroup") not in ("", path):
            raise Error("writer escaped its fixed cgroup binding")
        if value["LoadState"] == "loaded":
            expected = {"KillMode": "control-group", "Delegate": "no",
                        "ProtectControlGroups": "yes"}
            if any(value.get(key) != expected_value for key, expected_value in expected.items()):
                raise Error("writer containment properties differ")
        elif not native.inactive(value):
            raise Error("active masked writer containment unavailable")
        return value

    def quiescent(self) -> bool:
        self._check()
        if not self.masked or set(self.pins) != set(self.writers):
            return False
        for name in self.writers:
            value = self._writer(name)
            if (value["LoadState"] != "masked" or not native.inactive(value)
                    or not self._empty(self.pins[name])):
                return False
        for name in self.triggers:
            value = self._show(name)
            if value["LoadState"] != "masked" or not native.inactive(value):
                return False
        self._check()
        return True

    def stop_writers(self, deadline) -> None:
        native.root_only()
        self._closed()
        if self.deadline is not None or self.pins or self.masked:
            raise Error("writer scope closure is single-use")
        self.deadline = deadline
        self._check()
        for name in self.writers:
            self._writer(name)
        for name in self.triggers:
            self._show(name)
        # Preserve loaded stop policy until all processes and jobs are gone.
        self._manager("mask", "--runtime", "--no-reload", *self.triggers, *self.writers)
        self.masked = True
        self._closed()
        for name in self.writers:
            self._check()
            self.pins[name] = native.Cgroup(required=False, trusted_path=CGROUP_PARENT / name)
            self._check()
        self._manager("stop", "--no-block", *self.triggers, *self.writers)
        while True:
            deadline.check()
            self._check()
            writers = [self._writer(name) for name in self.writers]
            triggers = [self._show(name) for name in self.triggers]
            if (all(native.inactive(value) for value in writers + triggers)
                    and all(self._empty(pin) for pin in self.pins.values())):
                break
            time.sleep(0.05)
        self._manager("daemon-reload")
        if not self.quiescent():
            raise Error("writer or activation reappeared after closure")
        self._check()

    def close(self) -> None:
        # Closing handles is not reopening authority; runtime masks remain.
        for pin in self.pins.values():
            pin.close()
        self.pins.clear()
        self.finished = True



class _InstallerLock:
    """The direct installer's same empty inode; never truncate or unlink it."""

    def __init__(self):
        self.parent = self.fd = -1
        self.acquired = False

    @staticmethod
    def _directory(fd):
        value = native.guard.directory_id(fd)
        if (value["uid"] != _INSTALLER_OWNER_UID or value["gid"] != _INSTALLER_OWNER_GID
                or value["mode"] & 0o022):
            raise Error("unsafe diffusion installer lock parent")
        return value

    @staticmethod
    def _file(fd):
        value = native.guard.file_id(fd)  # Regular, single-link inode only.
        if (value["uid"] != _INSTALLER_OWNER_UID or value["gid"] != _INSTALLER_OWNER_GID
                or value["mode"] not in (0o600, 0o640, 0o644) or os.fstat(fd).st_size != 0):
            raise Error("unsafe diffusion installer lock")
        value["mount"] = native.guard.mount_id(fd)
        # exec9> in the installed shell touches mtime/ctime BEFORE a losing
        # flock attempt. Those timestamps are not part of this empty lock's identity.
        return value

    def _binding(self):
        current = native.guard.open_directory(_INSTALLER_PATH.parent)
        other = -1
        try:
            if self._directory(self.parent) != self.directory or self._directory(current) != self.directory:
                raise Error("diffusion installer lock parent changed")
            other = os.open(_INSTALLER_PATH.name, native.guard.FILE_FLAGS, dir_fd=current)
            if self._file(self.fd) != self.identity or self._file(other) != self.identity:
                raise Error("diffusion installer lock identity changed")
        finally:
            if other >= 0:
                os.close(other)
            os.close(current)

    def acquire(self):
        end = time.monotonic() + _INSTALLER_ACQUIRE_SECONDS
        try:
            self.parent = native.guard.open_directory(_INSTALLER_PATH.parent)
            self.directory = self._directory(self.parent)
            try:
                self.fd = os.open(_INSTALLER_PATH.name, native.guard.FILE_FLAGS, dir_fd=self.parent)
            except FileNotFoundError:
                try:
                    self.fd = os.open(_INSTALLER_PATH.name,
                                      native.guard.FILE_FLAGS | os.O_CREAT | os.O_EXCL,
                                      0o600, dir_fd=self.parent)
                except FileExistsError:
                    self.fd = os.open(_INSTALLER_PATH.name, native.guard.FILE_FLAGS, dir_fd=self.parent)
            self.identity = self._file(self.fd)
            while True:
                self._binding()
                if time.monotonic() >= end:
                    raise Error("diffusion installer exclusion deadline expired")
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.acquired = True
                    break
                except BlockingIOError:
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise Error("diffusion installer is busy") from None
                    time.sleep(min(0.05, remaining))
            self.check()
            if time.monotonic() >= end:
                raise Error("diffusion installer exclusion acquisition expired")
        except BaseException:
            self.close()
            raise

    def check(self):
        if not self.acquired or self.fd < 0 or self.parent < 0:
            raise Error("diffusion installer exclusion is closed")
        self._binding()

    def close(self):
        self.acquired = False
        try:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
        finally:
            if self.parent >= 0:
                os.close(self.parent)
                self.parent = -1


class DocumentsOutputsInterlocks:
    """Root-only, fixed runtime exclusions for trusted maintenance callers.

    Hold this context through the entire fixed-scope operation. No arbitrary
    paths, units or commands are accepted; this is not persistent admission or
    a guarantee against owner death, boot activation or noncooperating root.
    """

    def __init__(self):
        self._installer = _InstallerLock()
        self._vault = vault_operation.operation()
        self._used = self._active = False

    def __enter__(self):
        if self._used:
            raise Error("fixed maintenance exclusions are single-use")
        self._used = True
        try:
            native.root_only()
            # A consistent order avoids holding vault exclusion while waiting
            # for a long-running direct installer to finish.
            self._installer.acquire()
            self._vault.__enter__()
            self._active = True
            self.check()
            return self
        except (OSError, vault_operation.VaultOperationError) as exc:
            self.close()
            raise Error("fixed maintenance exclusions unavailable") from exc
        except BaseException:
            self.close()
            raise

    def _require_active(self):
        if not self._active:
            raise Error("fixed maintenance exclusions are closed or invalid")

    def installer_held(self) -> bool:
        self._require_active()
        try:
            self._installer.check()
        except OSError as exc:
            self._active = False
            raise Error("diffusion installer exclusion changed") from exc
        except BaseException:
            self._active = False
            raise
        return True

    def vault_mount_held(self) -> bool:
        self._require_active()
        try:
            self._vault.check()
        except (OSError, vault_operation.VaultOperationError) as exc:
            self._active = False
            raise Error("vault operation exclusion changed") from exc
        except BaseException:
            self._active = False
            raise
        return True

    def check(self) -> None:
        self.installer_held()
        self.vault_mount_held()

    def scope(self, closed: Callable[[], bool]) -> WriterScope:
        self.check()
        return documents_outputs_scope(closed, installer_interlock=self.installer_held,
                                       vault_mount_interlock=self.vault_mount_held)

    def close(self) -> None:
        self._active = False
        try:
            self._vault.close()
        finally:
            self._installer.close()

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.check()
        finally:
            self.close()

def documents_outputs_scope(closed: Callable[[], bool], *,
                            installer_interlock: Callable[[], bool],
                            vault_mount_interlock: Callable[[], bool]) -> WriterScope:
    """Fixed installed documents/outputs scope, not a native recovery backend.

    Trusted calling code must first hold exclusion against direct/root diffusion
    installers (including /var/lib/secure-ai/.diffusion-install.lock) and vault
    setup/unlock/relock/mount changes. These read-only predicates revalidate
    already-held exclusions throughout closure; they do not acquire them. A
    systemd mask cannot prove exclusion against commands outside these units.

    Startup/fresh-boot admission and external interlocks remain separate required
    integration. DynamicUser identities are preserved; no unit is reopened or
    started here, and quiescence covers only the fixed installed scope below.
    """
    if not all(callable(check) for check in (closed, installer_interlock, vault_mount_interlock)):
        raise Error("trusted closed-admission and external interlock predicates required")

    def admitted_closed() -> bool:
        if closed() is not True:
            return False
        if installer_interlock() is not True:
            raise Error("external diffusion installer exclusion is not held")
        if vault_mount_interlock() is not True:
            raise Error("external vault mount exclusion is not held")
        return True

    return WriterScope(
        ("secure-ai-agent.service", "secure-ai-diffusion.service",
         "secure-ai-enable-diffusion.service", "secure-ai-apply-profile.service",
         "secure-ai-integrity.service"),
        ("secure-ai-enable-diffusion.path", "secure-ai-apply-profile.path",
         "secure-ai-integrity.timer"),
        admitted_closed,
    )


if __name__ == "__main__":
    raise SystemExit("internal B2 coordination library; native restore remains unavailable")

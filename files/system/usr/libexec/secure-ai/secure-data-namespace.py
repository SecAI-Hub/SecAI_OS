#!/usr/bin/python3 -IB
"""Fixed root prehook namespace/clock bindings; neither admission nor recovery.

Only trusted installed code selects one of five fixed roles. Gate/NativeDataGate
must still perform all private state, readiness and retained-history validation.
No CLI, provisioning, unit changes, lease transfer or durable writes occur here.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

_spec = importlib.util.spec_from_file_location(
    "data_namespace_native", Path(__file__).with_name("secure-native-admission.py")
)
assert _spec and _spec.loader
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
guard, Error = native.guard, native.Error
_OWNER_UID = _OWNER_GID = 0
_ALT_BOOT = Path("/run/secure-ai-data-boot-id")
_ORIGINAL_BOOT = Path("/proc/sys/kernel/random/boot_id")
_MOUNTINFO = Path("/proc/self/mountinfo")
_SELF_CGROUP = Path("/proc/self/cgroup")
_SECONDS = 10.0
_ID_FIELDS = {"device", "inode", "mount", "mode", "uid", "gid"}
_COMMON = {
    "LoadState": "loaded",
    "ActiveState": "activating",
    "SubState": "start-pre",
    "MainPID": "0",
    "KillMode": "control-group",
    "Delegate": "no",
    "ProtectControlGroups": "yes",
    "ProtectHome": "yes",
    "ProtectKernelTunables": "yes",
    "SourcePath": "",
}
# Exact existing installed roles, not caller-selected units or commands. Only
# effective values relevant to this capability are queried; root operator unit
# replacement/modification is outside this trusted installed-code boundary.
_ROLES = {
    "agent": {
        "Type": "simple",
        "DynamicUser": "yes",
        "ProcSubset": "pid",
        "ProtectProc": "invisible",
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
    },
    "diffusion": {
        "Type": "simple",
        "DynamicUser": "yes",
        "ProcSubset": "pid",
        "ProtectProc": "invisible",
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
    },
    "enable-diffusion": {
        "Type": "oneshot",
        "DynamicUser": "no",
        "ProcSubset": "all",
        "ProtectProc": "default",
        "ProtectSystem": "no",
        "NoNewPrivileges": "no",
    },
    "apply-profile": {
        "Type": "oneshot",
        "DynamicUser": "no",
        "ProcSubset": "pid",
        "ProtectProc": "invisible",
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "cap_net_admin",
    },
    "integrity": {
        "Type": "oneshot",
        "DynamicUser": "no",
        "ProcSubset": "all",
        "ProtectProc": "default",
        "ProtectSystem": "strict",
        "NoNewPrivileges": "yes",
    },
}

_UNITS = {role: "secure-ai-" + role + ".service" for role in _ROLES}
_FRAGMENTS = {role: "/usr/lib/systemd/system/" + unit for role, unit in _UNITS.items()}


def _bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise Error("namespace evidence exceeded bound")
    return value


def _unescape(value: str) -> str:
    result = re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)
    if "\\" in result:
        raise Error("unsupported kernel mount pathname")
    return result


def _mount(fd: int, path: Path) -> tuple:
    identifier = guard.mount_id(fd)
    matches = []
    for line in _bounded(_MOUNTINFO, 262144).decode("utf-8", "strict").splitlines():
        before, separator, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not fields or fields[0] != str(identifier):
            continue
        if not separator or len(fields) < 6 or len(tail) != 3:
            raise Error("invalid kernel mount record")
        root, point = _unescape(fields[3]), _unescape(fields[4])
        options = fields[5].split(",")
        device = f"{os.major(os.fstat(fd).st_dev)}:{os.minor(os.fstat(fd).st_dev)}"
        if fields[2] != device or tail[0] != "proc" or tail[1] != "proc":
            raise Error("boot source is not a proc mount")
        if path == _ALT_BOOT:
            if "ro" not in options or "rw" in options:
                raise Error("delegated boot source is not read-only")
            valid = point == str(path) and root == "/sys/kernel/random/boot_id"
        else:
            try:
                relative = PurePosixPath(str(path)).relative_to(point)
            except ValueError:
                raise Error("boot source mount pathname differs") from None
            valid = str(PurePosixPath(root) / relative) == "/sys/kernel/random/boot_id"
        if not valid:
            raise Error("boot source is not the kernel boot-id entry")
        matches.append((identifier, line))
    if len(matches) != 1:
        raise Error("boot source mount identity unavailable or ambiguous")
    return matches[0]


def _kernel_file(fd: int) -> tuple:
    value = os.fstat(fd)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != _OWNER_UID
        or value.st_gid != _OWNER_GID
        or stat.S_IMODE(value.st_mode) != 0o444
    ):
        raise Error("unsafe kernel boot-id file")
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
    )


def _read_kernel(path: Path) -> str:
    parent = guard.open_directory(path.parent)
    fd = other = current = -1
    try:
        fd = os.open(path.name, guard.FILE_FLAGS, dir_fd=parent)
        identity, mount = _kernel_file(fd), _mount(fd, path)
        raw = os.read(fd, 65)
        value = (raw[:-1] if raw.endswith(b"\n") else raw).decode("ascii", "strict")
        if not guard.valid_uuid(value):
            raise Error("invalid kernel boot UUID")
        current = guard.open_directory(path.parent)
        other = os.open(path.name, guard.FILE_FLAGS, dir_fd=current)
        if (
            _kernel_file(fd) != identity
            or _kernel_file(other) != identity
            or _mount(fd, path) != mount
            or _mount(other, path) != mount
        ):
            raise Error("kernel boot source binding changed")
        return value
    finally:
        for descriptor in (other, current, fd, parent):
            if descriptor >= 0:
                os.close(descriptor)


class _Clock(guard.LinuxClock):  # type: ignore[name-defined]  # Fixed sibling loaded dynamically.
    def __init__(self, capability):
        self._capability = capability

    def boot_id(self) -> str:
        self._capability.check()
        try:
            value = _read_kernel(_ALT_BOOT)  # No ordinary-file/placeholder fallback.
            try:
                original = _read_kernel(_ORIGINAL_BOOT)
            except FileNotFoundError:
                original = None  # ProcSubset=pid hides this path.
            if original is not None and original != value:
                raise Error("visible kernel boot sources disagree")
            self._capability.check()
            return value
        except BaseException:
            self._capability.close()
            raise


class _PrehookNamespace:
    def __init__(self, role: str):
        if type(role) is not str or role not in _ROLES:
            raise Error("unknown fixed data writer role")
        self._unit = _UNITS[role]
        self._fragment = _FRAGMENTS[role]
        self._expected = {**_COMMON, **_ROLES[role]}
        self._end = time.monotonic() + _SECONDS
        self._valid = True
        try:
            self._initial = self._snapshot()
            self.check()
        except BaseException:
            self.close()
            raise
        self.clock = _Clock(self)

    def _snapshot(self) -> tuple:
        native.root_only()
        if time.monotonic() >= self._end:
            raise Error("prehook namespace verification expired")
        properties = set(self._expected) | {
            "Id",
            "ControlPID",
            "ControlGroup",
            "InvocationID",
            "FragmentPath",
            "PrivateTmp",
        }
        text = native.manager(
            "show", self._unit, "--property=" + ",".join(sorted(properties))
        )
        rows = {}
        for line in text.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in rows:
                raise Error("invalid fixed service property response")
            rows[key] = value
        invocation = os.environ.get("INVOCATION_ID", "")
        cgroup = "/system.slice/" + self._unit
        if (
            set(rows) != properties
            or any(rows.get(key) != value for key, value in self._expected.items())
            or rows["Id"] != self._unit
            or rows["ControlPID"] != str(os.getpid())
            or rows["ControlGroup"] != cgroup
            or rows["InvocationID"] != invocation
            or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
            or rows["FragmentPath"] != self._fragment
            or rows["PrivateTmp"] not in ("yes", "disconnected")
        ):
            raise Error("fixed root prehook binding differs")
        if _bounded(_SELF_CGROUP, 4096).decode("ascii", "strict").splitlines() != [
            "0::" + cgroup
        ]:
            raise Error("prehook is outside its fixed kernel cgroup")
        namespace = os.stat("/proc/self/ns/mnt")
        native.root_only()
        if time.monotonic() >= self._end:
            raise Error("prehook namespace verification expired")
        return tuple(sorted(rows.items())), (namespace.st_dev, namespace.st_ino)

    def check(self) -> None:
        if not self._valid:
            raise Error("prehook namespace capability is invalid")
        try:
            if self._snapshot() != self._initial:
                raise Error("prehook binding changed")
        except BaseException:
            self.close()
            raise

    def trusted_root_rebind(self, historical: dict, current: dict) -> bool:
        self.check()
        for value in (historical, current):
            if (
                not isinstance(value, dict)
                or set(value) != _ID_FIELDS
                or any(
                    type(item) is not int or not 0 <= item <= 2**64 - 1
                    for item in value.values()
                )
                or value["uid"] != _OWNER_UID
                or value["gid"] != _OWNER_GID
                or value["mode"] != 0o700
                or value["mount"] == 0
            ):
                self.close()
                return False
        if historical["mount"] == current["mount"] or any(
            historical[key] != current[key] for key in _ID_FIELDS - {"mount"}
        ):
            self.close()
            return False
        self.check()
        return True

    def close(self) -> None:
        self._valid = False


def prehook_namespace(role: str):
    """Trusted-code factory; role is a fixed literal, never archive/CLI authority."""
    return _PrehookNamespace(role)


if __name__ == "__main__":
    raise SystemExit("internal namespace binding only; no admission or recovery CLI")

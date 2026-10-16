#!/usr/bin/python3 -IB
"""Fixed data writer admission handoff, not provisioning or a restore backend.

Unit hooks/authority/bootstrap are deliberately not installed here. Root prehook
validates NativeDataGate; the normal service UID receives only its shared lease.
PID1 must keep its duplicate through control-group teardown on helper failure.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location(
    "data_admission_namespace", Path(__file__).with_name("secure-data-namespace.py")
)
assert _spec and _spec.loader
namespace = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(namespace)
_transaction_spec = importlib.util.spec_from_file_location(
    "data_admission_transaction",
    Path(__file__).with_name("secure-recovery-transaction.py"),
)
assert _transaction_spec and _transaction_spec.loader
transaction = importlib.util.module_from_spec(_transaction_spec)
_transaction_spec.loader.exec_module(transaction)
native, Error = namespace.native, namespace.Error
_ROOT = Path("/var/lib/secure-ai-data-admission")
_RUNTIME = Path("/run/secure-ai-data-admission")
_NATIVE_CLASSES = ("user-documents", "user-outputs")
_CGROUP_PARENT = Path("/sys/fs/cgroup/system.slice")
_SELF_CGROUP = Path("/proc/self/cgroup")
_OWNER_UID = _OWNER_GID = 0
_LEASE_FD = 3
_NAME_PREFIX = "secai-data-lease-"
_POLL_SECONDS = 0.05
_COMMANDS = {
    "agent": ("/usr/libexec/secure-ai/agent",),
    "enable-diffusion": (
        "/usr/libexec/secure-ai/secai-enable-diffusion.sh",
        "--progress-file",
        "/run/secure-ai/diffusion-progress.json",
    ),
    "apply-profile": ("/usr/libexec/secure-ai/apply-profile.sh",),
    "integrity": ("/usr/libexec/secure-ai/integrity-check.sh",),
}
_STORE = {
    "FileDescriptorStoreMax": "1",
    "FileDescriptorStorePreserve": "no",
    "NotifyAccess": "exec",
}


def _role(role: str) -> str:
    if type(role) is not str or role not in _COMMANDS:
        raise Error(
            "unsupported fixed data writer role; diffusion supervision is unavailable"
        )
    return namespace._UNITS[role]


def _invocation() -> str:
    value = os.environ.get("INVOCATION_ID", "")
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise Error("service invocation identity unavailable")
    return value


def _show(unit: str, properties: set[str]) -> dict[str, str]:
    text = native.manager("show", unit, "--property=" + ",".join(sorted(properties)))
    value = {}
    for line in text.splitlines():
        name, separator, content = line.partition("=")
        if not separator or name not in properties or name in value:
            raise Error("invalid fixed data service response")
        value[name] = content
    if set(value) != properties or value.get("Id") != unit:
        raise Error("fixed data service identity differs")
    return value


def _store_policy(unit: str, count: str) -> None:
    value = _show(unit, set(_STORE) | {"Id", "NFileDescriptorStore"})
    if (
        any(value[key] != expected for key, expected in _STORE.items())
        or value["NFileDescriptorStore"] != count
    ):
        raise Error("PID1 lease storage policy or acknowledgement differs")


def _notify(fd: int, name: str) -> None:
    library = ctypes.CDLL("libsystemd.so.0", use_errno=True)
    library.sd_pid_notify_with_fds.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
    ]
    library.sd_pid_notify_with_fds.restype = ctypes.c_int
    library.sd_notify_barrier.argtypes = [ctypes.c_int, ctypes.c_uint64]
    library.sd_notify_barrier.restype = ctypes.c_int
    descriptors = (ctypes.c_int * 1)(fd)
    if (
        library.sd_pid_notify_with_fds(
            0, 0, ("FDSTORE=1\nFDNAME=" + name).encode("ascii"), descriptors, 1
        )
        <= 0
    ):
        raise Error("PID1 lease transfer failed")
    if library.sd_notify_barrier(0, 2_000_000) <= 0:
        raise Error("PID1 lease transfer acknowledgement failed")


def prehook(role: str) -> int:
    unit = _role(
        role
    )  # Reject unsupported modes before namespace/gate/notification effects.
    capability = namespace.prehook_namespace(role)
    gate = lease = None
    try:
        if os.environ.get("LISTEN_FDS", "0") != "0":
            raise Error("prehook received unexpected activation descriptors")
        _store_policy(unit, "0")
        capability.check()
        gate = transaction.NativeDataGate(
            _ROOT,
            _RUNTIME,
            native_classes=_NATIVE_CLASSES,
            clock=capability.clock,
            trusted_root_rebind=capability.trusted_root_rebind,
        )
        lease = gate.lease()  # Includes current readiness and retained history.
        gate.metadata_contract()  # Revalidate both installed policies before handoff.
        capability.check()
        _notify(lease.fd, _NAME_PREFIX + _invocation())
        capability.check()
        _store_policy(unit, "1")
        capability.check()
        return 0
    finally:
        # StableLock.close closes our OFD reference, never LOCK_UN; PID1 owns
        # its duplicate even if post-transfer validation reports failure.
        try:
            if lease is not None:
                lease.close()
        finally:
            try:
                if gate is not None:
                    gate.close()
            finally:
                capability.close()


def _credentials() -> tuple:
    return os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(os.getgroups())


def _binding(role: str) -> tuple:
    unit = _role(role)
    credentials = _credentials()
    if role == "agent":
        if (
            credentials[0] == 0
            or credentials[0] != credentials[1]
            or credentials[2] == 0
            or credentials[2] != credentials[3]
        ):
            raise Error("agent supervisor must keep its DynamicUser credentials")
    elif credentials[:4] != (0, 0, 0, 0):
        raise Error(
            "fixed privileged supervisor requires its installed root credentials"
        )
    expected = {
        **namespace._COMMON,
        **namespace._ROLES[role],
        **_STORE,
        "MainPID": str(os.getpid()),
        "ControlPID": "0",
        "NFileDescriptorStore": "1",
    }
    expected.pop("ActiveState")
    expected.pop("SubState")
    properties = set(expected) | {
        "Id",
        "ActiveState",
        "SubState",
        "InvocationID",
        "ControlGroup",
        "FragmentPath",
        "PrivateTmp",
    }
    value = _show(unit, properties)
    phase = ("active", "running") if role == "agent" else ("activating", "start")
    if (
        any(value[key] != content for key, content in expected.items())
        or (value["ActiveState"], value["SubState"]) != phase
        or value["InvocationID"] != _invocation()
        or value["ControlGroup"] != "/system.slice/" + unit
        or value["FragmentPath"] != namespace._FRAGMENTS[role]
        or value["PrivateTmp"] not in ("yes", "disconnected")
    ):
        raise Error("fixed supervisor main-role binding differs")
    with _SELF_CGROUP.open("rb") as handle:
        group = handle.read(4097)
    if group != ("0::/system.slice/" + unit + "\n").encode("ascii"):
        raise Error("supervisor is outside its fixed kernel cgroup")
    return _invocation(), credentials


class _Lease:
    def __init__(self, invocation: str):
        self.fd = -1
        if (
            os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != _NAME_PREFIX + invocation
        ):
            raise Error("exact invocation-bound PID1 lease descriptor required")
        self.fd = _LEASE_FD
        try:
            os.set_inheritable(self.fd, False)
            self.identity = self._identity()
            self.check()
        except BaseException:
            self.close()
            raise

    def _identity(self) -> tuple:
        value = os.fstat(self.fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_uid != _OWNER_UID
            or value.st_gid != _OWNER_GID
            or value.st_nlink != 1
            or value.st_size != 7
            or fcntl.fcntl(self.fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or os.pread(self.fd, 8, 0) != b"stable\n"
        ):
            raise Error("unsafe handed-off stable lease descriptor")
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            native.guard.mount_id(self.fd),
        )

    def check(self) -> None:
        if self.fd < 0 or self._identity() != self.identity:
            raise Error("handed-off lease descriptor changed")

    def close(self) -> None:
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)


def _status(code: int, received: int) -> int:
    if received:
        return 128 + received
    return 128 - code if code < 0 else code


def supervise(role: str) -> int:
    unit = _role(role)
    before = _binding(role)
    lease = _Lease(before[0])
    pin = child = None
    previous = {}
    received = [0]
    forwarded = False

    def record(number, _frame):
        if not received[0]:
            received[0] = number

    try:
        pin = native.Cgroup(required=True, trusted_path=_CGROUP_PARENT / unit)
        if _binding(role) != before:
            raise Error("supervisor identity changed before command launch")
        lease.check()
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[number] = signal.signal(number, record)
        environment = os.environ.copy()
        for name in (
            "LISTEN_PID",
            "LISTEN_FDS",
            "LISTEN_FDNAMES",
            "FDSTORE",
            "NOTIFY_SOCKET",
        ):
            environment.pop(name, None)
        if received[0]:
            return _status(0, received[0])
        child = subprocess.Popen(_COMMANDS[role], close_fds=True, env=environment)
        while True:
            child.poll()  # Reap direct child, never infer whole-cgroup completion.
            if received[0] and not forwarded:
                child.send_signal(received[0])
                forwarded = True
            if _credentials() != before[1]:
                raise Error("supervisor credentials changed")
            lease.check()
            if not pin.other_processes():
                if child.poll() is None:
                    raise Error("live child is outside the pinned cgroup census")
                break
            time.sleep(_POLL_SECONDS)
        lease.check()
        return _status(child.wait(), received[0])
    except BaseException:
        if child is not None:
            try:
                child.send_signal(signal.SIGTERM)
            except OSError:
                pass  # Preserve the primary unconfirmed-failure result.
        # Failure is not cgroup-empty proof. CLI exits nonzero; validated PID1
        # KillMode/control-group + FDSTORE policy must drain remaining children
        # before its last lease reference is released, as separately qualified.
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        try:
            if pin is not None:
                pin.close()
        finally:
            lease.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prehook", "supervise"))
    parser.add_argument("role")
    args = parser.parse_args()
    try:
        return (
            prehook(args.role) if args.operation == "prehook" else supervise(args.role)
        )
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "error": "fixed data admission failed; completion unconfirmed",
                    "global_quiescence": False,
                    "native_recovery_adapter": False,
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/python3 -IB
"""Root admission for update-check only; not a native recovery backend.

The supervisor owns a lease using B1 lock primitives, never passing it into the writer. Kernel cgroup
membership, not the writer PID/exit status, bounds normal admission lifetime.
A dead supervisor is NOT evidence of quiescence: closure masks activation and
independently checks the pinned cgroup before taking the exclusive stable lock.
All other writers and emergency services are outside this narrow boundary.
"""
from __future__ import annotations

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

_spec = importlib.util.spec_from_file_location("maintenance_guard", Path(__file__).with_name("secure-maintenance-guard.py"))
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)
Error = guard.RecoveryError
ROOT = Path("/var/lib/secure-ai-native-admission")
RUNTIME = Path("/run/secure-ai-native-admission")
UNIT = "secure-ai-update-check.service"
TIMER = "secure-ai-update-check.timer"
CGROUP = Path("/sys/fs/cgroup/system.slice") / UNIT
COMMAND = ["/usr/libexec/secure-ai/update-verify.sh", "check"]
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "ControlGroup", "MainPID", "InvocationID", "Job",
              "KillMode", "Delegate", "ProtectControlGroups", "User", "Group")



KIND = "native-update-check-admission-v1"


def persistent_identity(fd: int) -> dict:
    # Service mount namespaces create different bind-mount IDs for the same
    # protected storage. Persist exact storage identity, while BoundDirectory
    # independently pins and checks THIS invocation's mount identity.
    identity = guard.directory_id(fd)
    del identity["mount"]
    return identity


def control_names(fd: int, maximum: int) -> set[str]:
    # A retained directory description can omit an atomically replaced entry
    # from later enumeration (observed on Btrfs). A dup shares that description;
    # open "." independently against the pinned directory, retaining identity.
    identity = guard.directory_id(fd)
    fresh = os.open(".", guard.DIR_FLAGS, dir_fd=fd)
    try:
        if guard.directory_id(fresh) != identity or guard.directory_id(fd) != identity:
            raise Error("native control directory identity changed")
        found = guard.names(fresh, maximum)
        if guard.directory_id(fresh) != identity or guard.directory_id(fd) != identity:
            raise Error("native control directory changed during enumeration")
        return found  # Full bounded names; unknown/pending metadata is not hidden.
    finally:
        os.close(fresh)


class NativeGate:
    """Fixed writer authority; deliberately NOT the B1 transaction Gate/schema."""
    def __init__(self, root: Path, runtime: Path, *, allow_missing_runtime: bool = False):
        self.root = guard.BoundDirectory(root)
        self.runtime = None
        try:
            try:
                self.runtime = guard.BoundDirectory(runtime)
            except FileNotFoundError:
                if not allow_missing_runtime:
                    raise
        except BaseException:
            self.root.close()
            raise
        self.clock, self.io = guard.LinuxClock(), guard.DurableIO()
        try:
            self.layout = guard.read_json(self.root.fd, "layout.json")
            self.check(allow_unready=True)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def provision(root: Path, runtime: Path) -> None:
        directory, running = guard.BoundDirectory(root), guard.BoundDirectory(runtime)
        io, clock = guard.DurableIO(), guard.LinuxClock()
        try:
            if control_names(directory.fd, 16) or control_names(running.fd, 4):
                raise Error("new native authority requires empty private directories")
            os.mkdir("transactions", 0o700, dir_fd=directory.fd)
            layout = {"version": 1, "kind": KIND, "unit": UNIT, "root": persistent_identity(directory.fd)}
            for name in ("admission", "operation"):
                io.create(directory.fd, name + ".lock", b"stable\n", "native:" + name)
                fd = os.open(name + ".lock", guard.FILE_FLAGS, dir_fd=directory.fd)
                try:
                    layout[name] = guard.file_id(fd)
                finally:
                    os.close(fd)
            io.create(directory.fd, "layout.json", guard.encode(layout), "native:layout")
            io.sync(directory.fd, "native:layout-directory")
            io.replace_json(directory.fd, "gate.json", {
                "version": 1, "kind": KIND, "state": "open", "closure": None, "epoch": str(uuid.uuid4()),
            }, "native:state")
            guard.Deadline(clock, 5).check()
        finally:
            directory.close()
            running.close()

    def check(self, *, allow_unready: bool = False) -> None:
        self.root.check()
        if self.runtime is not None:
            self.runtime.check()
        expected = {"version", "kind", "unit", "root", "admission", "operation"}
        if (set(self.layout) != expected or type(self.layout["version"]) is not int or self.layout["version"] != 1
                or self.layout["kind"] != KIND or self.layout["unit"] != UNIT
                or self.layout["root"] != persistent_identity(self.root.fd)
                or guard.read_json(self.root.fd, "layout.json") != self.layout):
            raise Error("native storage authority changed")
        if control_names(self.root.fd, 16) != {"layout.json", "gate.json", "admission.lock", "operation.lock", "transactions"}:
            raise Error("unknown or incomplete native authority metadata")
        running = set() if self.runtime is None else control_names(self.runtime.fd, 4)
        if (running - {"ready.json"}) or (not allow_unready and running != {"ready.json"}):
            raise Error("unknown or incomplete native boot metadata")
        transactions = os.open("transactions", guard.DIR_FLAGS, dir_fd=self.root.fd)
        try:
            if control_names(transactions, 9):
                raise Error("native authority never admits transactions or journal debris")
        finally:
            os.close(transactions)
        for name in ("admission", "operation"):
            lock = guard.StableLock(self.root, name + ".lock", self.layout[name])
            lock.close()

    def state(self, *, recovery: bool = False) -> dict:
        self.check(allow_unready=recovery)
        value = guard.read_json(self.root.fd, "gate.json")
        if (set(value) != {"version", "kind", "state", "closure", "epoch"}
                or type(value["version"]) is not int or value["version"] != 1 or value["kind"] != KIND
                or value["state"] not in ("open", "closed") or not guard.valid_uuid(value["epoch"])
                or (value["state"] == "open" and value["closure"] is not None)
                or (value["state"] == "closed" and not guard.valid_uuid(value["closure"]))):
            raise Error("invalid native admission state")
        return value

    def ready(self, value: dict) -> dict:
        return {"version": 1, "kind": KIND, "epoch": value["epoch"], "boot": self.clock.boot_id(), "domain": guard.DOMAIN}

    def require_open(self) -> None:
        value = self.state()
        if value["state"] != "open" or guard.read_json(self.runtime.fd, "ready.json") != self.ready(value):
            raise Error("native admission closed or current boot unverified")

    def lease(self):
        self.check()
        lock = guard.StableLock(self.root, "admission.lock", self.layout["admission"])
        try:
            lock.acquire(False, guard.Deadline(self.clock, 1))
            self.require_open()
            return lock
        except BaseException:
            lock.close()
            raise

    def operation(self, *, exclusive: bool = True):
        self.check(allow_unready=True)
        lock = guard.StableLock(self.root, "operation.lock", self.layout["operation"])
        try:
            lock.acquire(exclusive, guard.Deadline(self.clock, 5))
            return lock
        except BaseException:
            lock.close()
            raise

    def close_for(self, identifier: str) -> dict:
        value = self.state(recovery=True)
        if not guard.valid_uuid(identifier) or value["state"] != "open":
            raise Error("invalid native closure transition")
        closed = {**value, "state": "closed", "closure": identifier}
        self.io.replace_json(self.root.fd, "gate.json", closed, "native:close")
        return closed

    def close(self) -> None:
        self.root.close()
        if self.runtime is not None:
            self.runtime.close()


def manager(*args: str) -> str:
    result = subprocess.run(["/usr/bin/systemctl", *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C", "SYSTEMD_PAGER": "cat"})
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 8192:
        raise Error("service-manager operation failed: " + args[0])
    return result.stdout.decode("utf-8", "strict")


def show(unit: str) -> dict[str, str]:
    text = manager("show", unit, "--property=" + ",".join(PROPERTIES))
    rows = {}
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if not sep or name in rows or name not in PROPERTIES:
            raise Error("unknown service-manager property response")
        rows[name] = value
    if rows.get("Id") != unit or rows.get("LoadState") not in ("loaded", "masked"):
        raise Error("unknown unit identity")
    return rows


def root_only() -> None:
    if os.getuid() != 0 or os.geteuid() != 0:
        raise Error("root authority required")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise Error("unified cgroup hierarchy required")


def inactive(value: dict[str, str]) -> bool:
    return (value.get("ActiveState") in ("inactive", "failed") and value.get("MainPID", "0") == "0"
            and value.get("Job") in ("", "0"))


class Cgroup:
    """Pin the manager's exact fixed cgroup, retaining identity after removal."""
    def __init__(self, required: bool):
        self.fd = self.events_fd = self.parent_fd = -1
        self.parent_fd = guard.open_directory(CGROUP.parent)
        self.parent_identity = guard.directory_id(self.parent_fd)
        try:
            self.fd = guard.open_directory(CGROUP)
        except FileNotFoundError:
            if required:
                self.close()
                raise Error("writer cgroup unavailable")
        self.identity = None if self.fd < 0 else guard.directory_id(self.fd)
        if self.fd >= 0:
            try:
                self.events_fd = os.open("cgroup.events", guard.FILE_FLAGS, dir_fd=self.fd)
            except BaseException:
                self.close()
                raise

    def check(self) -> bool:
        parent = guard.open_directory(CGROUP.parent)
        try:
            if guard.directory_id(parent) != self.parent_identity or guard.directory_id(self.parent_fd) != self.parent_identity:
                raise Error("writer cgroup hierarchy was rebound")
        finally:
            os.close(parent)
        try:
            current = guard.open_directory(CGROUP)
        except FileNotFoundError:
            return False
        try:
            if self.identity != guard.directory_id(current) or self.identity != guard.directory_id(self.fd):
                raise Error("writer cgroup was rebound")
        finally:
            os.close(current)
        return True

    def read(self, name: str) -> str:
        fd = os.open(name, guard.FILE_FLAGS, dir_fd=self.fd)
        try:
            data = os.read(fd, 65537)
            if len(data) > 65536:
                raise Error("cgroup census exceeded bound")
            return data.decode("ascii")
        finally:
            os.close(fd)

    def empty(self) -> bool:
        present = self.check()
        if self.fd < 0:
            return True  # Still absent under the unchanged pinned parent.
        try:
            # Retain the kernel event node before stopping; cgroupfs does not
            # use ordinary directory st_nlink semantics after removal.
            os.lseek(self.events_fd, 0, os.SEEK_SET)
            raw = os.read(self.events_fd, 4097)
        except OSError as exc:
            # kernfs returns ENODEV once this exact retained node is offline.
            # Its cgroup can be removed only without live subtree processes.
            if exc.errno == errno.ENODEV and not self.check():
                return True
            raise
        if not present or len(raw) > 4096:
            raise Error("cgroup removal or event population is unverified")
        events = dict(line.split() for line in raw.decode("ascii").splitlines())
        if events.get("populated") not in ("0", "1"):
            raise Error("kernel cgroup population unavailable")
        return events["populated"] == "0"

    def other_processes(self) -> bool:
        if not self.check() or self.fd < 0:
            raise Error("active writer cgroup removed")
        # Delegate=no and ProtectControlGroups=yes prohibit writer subgroups.
        # Reject unexpected children rather than mistake partial census for empty.
        for entry in os.scandir(self.fd):
            if entry.is_dir(follow_symlinks=False):
                raise Error("unexpected writer cgroup child; closure required")
        pids = self.read("cgroup.procs").splitlines()
        if not pids or any(not pid.isdecimal() for pid in pids) or str(os.getpid()) not in pids:
            raise Error("supervisor is not in the pinned writer cgroup")
        return any(int(pid) != os.getpid() for pid in pids)

    def close(self) -> None:
        for name in ("events_fd", "fd", "parent_fd"):
            if getattr(self, name) >= 0:
                os.close(getattr(self, name))
                setattr(self, name, -1)


def binding() -> dict[str, str]:
    value = show(UNIT)
    required = {"ControlGroup": "/system.slice/" + UNIT, "MainPID": str(os.getpid()),
                "KillMode": "control-group", "Delegate": "no", "ProtectControlGroups": "yes",
                "User": "root", "Group": "root"}
    if (any(value.get(k) != v for k, v in required.items()) or
            value.get("ActiveState") not in ("activating", "active") or
            re.fullmatch(r"[0-9a-f]{32}", value.get("InvocationID", "")) is None):
        raise Error("fixed root writer service authority differs")
    return value


def initialize() -> dict:
    # systemd creates both directories root:root0700. Never repair unknown data.
    with_gate = ROOT / "layout.json"
    if not with_gate.exists():
        NativeGate.provision(ROOT, RUNTIME)
    gate = NativeGate(ROOT, RUNTIME)
    operation = None
    cgroup = None
    try:
        operation = gate.operation()
        if not control_names(gate.runtime.fd, 4):
            # Only this separate, transaction-free native-update gate may rebind.
            # A queued start is safe only behind our initializing dependency.
            value = gate.state(recovery=True)
            if value["state"] != "open":
                raise Error("closed or historical gate cannot rebind at boot")
            transactions = os.open("transactions", guard.DIR_FLAGS, dir_fd=gate.root.fd)
            try:
                if control_names(transactions, 9):
                    raise Error("transaction debris prevents boot rebind")
            finally:
                os.close(transactions)
            writer = show(UNIT)
            if writer.get("ActiveState") != "inactive" or writer.get("MainPID") != "0":
                raise Error("writer must be inactive for boot rebind")
            if writer.get("Job") not in ("", "0"):
                initializer = show("secure-ai-native-admission.service")
                if initializer.get("MainPID") != str(os.getpid()) or initializer.get("ActiveState") != "activating":
                    raise Error("pending writer job is not held behind initialization")
            cgroup = Cgroup(required=False)
            if not cgroup.empty():
                raise Error("writer descendants prevent boot rebind")
            gate.io.replace_json(gate.runtime.fd, "ready.json", gate.ready(value), "native-update:boot-ready")
        gate.require_open()
    finally:
        if cgroup is not None:
            cgroup.close()
        if operation is not None:
            operation.close()
        gate.close()
    return {"scope": UNIT, "admission": "open", "global_quiescence": False}


def supervise() -> int:
    before = binding()
    cgroup = Cgroup(required=True)
    gate = NativeGate(ROOT, RUNTIME)
    lease = None
    try:
        lease = gate.lease()
        if binding()["InvocationID"] != before["InvocationID"]:
            raise Error("writer invocation changed during admission")
        child = subprocess.Popen(COMMAND, close_fds=True)
        while True:
            child.poll()  # Reap direct child, but never treat its exit as quiescence.
            if not cgroup.other_processes():
                break
            lease.check()
            time.sleep(0.05)
        return child.wait()
    finally:
        if lease is not None:
            lease.close()
        gate.close()
        cgroup.close()


def close_admission(gate, operation) -> str:
    """Caller retains the operation lock through the entire drain decision."""
    operation.check()
    value = gate.state(recovery=True)
    if value["state"] == "open":
        value = gate.close_for(str(uuid.uuid4()))
    return value["closure"]


def drain() -> dict:
    gate = NativeGate(ROOT, RUNTIME)
    cgroup = None
    exclusive = None
    operation = None
    try:
        operation = gate.operation()
        identifier = close_admission(gate, operation)
        deadline = guard.Deadline(gate.clock, 30)
        # Close first: every queued/manual start must pass the closed gate.
        # Stage masks WITHOUT reload until stopped. Reloading an active masked
        # unit discards its configured stop timeout. Retain the loaded unit's
        # sandbox/KillMode/timeout while stopping the fixed timer and writer.
        manager("mask", "--runtime", "--no-reload", TIMER, UNIT)
        cgroup = Cgroup(required=False)
        manager("stop", "--no-block", TIMER, UNIT)
        while True:
            deadline.check()
            units = [show(UNIT), show(TIMER)]
            if units[0].get("ControlGroup") not in ("", "/system.slice/" + UNIT):
                raise Error("manager writer cgroup binding is ambiguous")
            if all(inactive(value) for value in units) and cgroup.empty():
                break
            time.sleep(0.05)
        manager("daemon-reload")
        exclusive = guard.StableLock(gate.root, "admission.lock", gate.layout["admission"])
        exclusive.acquire(True, deadline)
        units = [show(unit) for unit in (UNIT, TIMER)]
        if (not cgroup.empty() or units[0].get("ControlGroup") not in ("", "/system.slice/" + UNIT)
                or not all(inactive(value) and value["LoadState"] == "masked" for value in units)):
            raise Error("writer or activation reappeared")
        return {"scope": UNIT, "trigger": TIMER, "closure": identifier,
                "boot": gate.clock.boot_id(), "scoped_quiescence": True, "global_quiescence": False,
                "native_recovery_adapter": False, "admission": "closed"}
    finally:
        if exclusive is not None:
            exclusive.close()
        if cgroup is not None:
            cgroup.close()
        if operation is not None:
            operation.close()
        gate.close()


def boot_binding(gate, value: dict) -> str:
    if gate.runtime is None or not control_names(gate.runtime.fd, 4):
        return "unbound"
    ready = guard.read_json(gate.runtime.fd, "ready.json")
    expected = gate.ready(value)
    if (set(ready) != set(expected) or not guard.valid_uuid(ready.get("boot"))
            or any(ready[key] != expected[key] for key in expected if key != "boot")
            or type(ready["version"]) is not int):
        raise Error("unknown native boot authority")
    return "current" if ready["boot"] == expected["boot"] else "stale"


def status() -> dict:
    """Read control metadata only; do not initialize, repair, or infer health."""
    base = {"scope": UNIT, "trigger": TIMER, "global_quiescence": False, "native_recovery_adapter": False}
    empty = []
    for path in (ROOT, RUNTIME):
        directory = None
        try:
            try:
                directory = guard.BoundDirectory(path)
            except FileNotFoundError:
                empty.append(True)
                continue
            empty.append(not control_names(directory.fd, 16))
        finally:
            if directory is not None:
                directory.close()
    if empty[0]:
        if not empty[1]:
            raise Error("runtime metadata without native storage authority")
        return {**base, "initialized": False, "admission": "uninitialized", "boot_binding": "unbound", "closure": None}
    gate = NativeGate(ROOT, RUNTIME, allow_missing_runtime=True)
    operation = None
    try:
        operation = gate.operation(exclusive=False)
        value = gate.state(recovery=True)
        binding_state = boot_binding(gate, value)
        admission = "closed" if value["state"] == "closed" else ("open" if binding_state == "current" else "unbound")
        return {**base, "initialized": True, "admission": admission, "persisted_state": value["state"],
                "boot_binding": binding_state, "closure": value["closure"]}
    finally:
        if operation is not None:
            operation.close()
        gate.close()


def require_idle_scope(cgroup, *, loaded: bool = False) -> None:
    units = [show(unit) for unit in (UNIT, TIMER)]
    if (units[0].get("MainPID") != "0" or units[0].get("ControlGroup") not in ("", "/system.slice/" + UNIT)
            or not all(inactive(value) for value in units)
            or (loaded and any(value["LoadState"] != "loaded" for value in units))
            or not cgroup.empty()):
        raise Error("fixed writer/trigger must be inactive with an empty verified cgroup")


def reopen(identifier: str) -> dict:
    """Explicit root authorization for this closure only; never start a unit.

    Keep the epoch: ready is persisted while closed, then one atomic gate write
    commits reopening. A crash before that commit leaves closed admission even
    if already unmasked. Pending metadata is never repaired automatically. A
    crash after publication may have committed; inspect read-only status.
    """
    if not guard.valid_uuid(identifier):
        raise Error("exact current closure UUID required")
    gate = NativeGate(ROOT, RUNTIME, allow_missing_runtime=True)
    operation = exclusive = cgroup = None
    try:
        operation = gate.operation()
        value = gate.state(recovery=True)
        if value["state"] != "closed" or value["closure"] != identifier:
            raise Error("closure is stale or admission is not closed")
        boot_binding(gate, value)  # Refuse unknown readiness before any mutation.
        cgroup = Cgroup(required=False)
        require_idle_scope(cgroup)
        exclusive = guard.StableLock(gate.root, "admission.lock", gate.layout["admission"])
        exclusive.acquire(True, guard.Deadline(gate.clock, 30))
        require_idle_scope(cgroup)
        # Admission remains durably closed throughout manager changes.
        manager("unmask", "--runtime", "--no-reload", TIMER, UNIT)
        manager("daemon-reload")
        require_idle_scope(cgroup, loaded=True)
        if gate.runtime is None:
            # The fixed /run directory can be absent after boot. No existing
            # directory is chmodded, reset, or accepted without private binding.
            try:
                os.mkdir(RUNTIME, 0o700)
            except FileExistsError:
                pass
            gate.runtime = guard.BoundDirectory(RUNTIME)
            gate.check(allow_unready=True)
            boot_binding(gate, value)
        if boot_binding(gate, value) != "current":
            gate.io.replace_json(gate.runtime.fd, "ready.json", gate.ready(value), "native:resume-ready")
        require_idle_scope(cgroup, loaded=True)
        if gate.state(recovery=True) != value:
            raise Error("closure changed during explicit reopening")
        opened = {**value, "state": "open", "closure": None}
        gate.io.replace_json(gate.root.fd, "gate.json", opened, "native:resume-open")
        gate.require_open()
        return {"scope": UNIT, "trigger": TIMER, "admission": "open", "reopened_closure": identifier,
                "boot": gate.clock.boot_id(), "units_started": False,
                "global_quiescence": False, "native_recovery_adapter": False}
    finally:
        if exclusive is not None:
            exclusive.close()
        if cgroup is not None:
            cgroup.close()
        if operation is not None:
            operation.close()
        gate.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("initialize", "supervise-update-check", "close-update-check", "reopen-update-check", "status"))
    parser.add_argument("--closure", help="exact current closure UUID; required only for reopen-update-check")
    args = parser.parse_args()
    if (args.operation == "reopen-update-check") != (args.closure is not None):
        parser.error("--closure is required only for reopen-update-check")
    try:
        root_only()
        if args.operation == "supervise-update-check":
            return supervise()
        if args.operation == "initialize":
            result = initialize()
        elif args.operation == "close-update-check":
            result = drain()
        elif args.operation == "reopen-update-check":
            result = reopen(args.closure)
        else:
            result = status()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc), "global_quiescence": False, "native_recovery_adapter": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

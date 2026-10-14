#!/usr/bin/env python3
"""Bounded generation journal library; native mutation CLI is disabled.

Trusted calling code supplies component mappings and a quiescence backend.
There is deliberately no installed backend and no fixture CLI. Tests provide
the only concrete backend. This library alone does not qualify native restore,
writer startup/cgroups, mount recovery, SELinux or emergency containment.
Trusted code may select installed document/output metadata contracts for B2
integration. This does not install a native backend or qualify active restore.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Protocol

_spec = importlib.util.spec_from_file_location(
    "transaction_guard", Path(__file__).with_name("secure-maintenance-guard.py"))
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)
RecoveryError = guard.RecoveryError
_metadata_spec = importlib.util.spec_from_file_location(
    "transaction_native_metadata", Path(__file__).with_name("secure-native-generation-metadata.py"))
assert _metadata_spec and _metadata_spec.loader
native_metadata = importlib.util.module_from_spec(_metadata_spec)
_metadata_spec.loader.exec_module(native_metadata)


class Backend(Protocol):
    """Trusted code capability, never constructed from archive/journal JSON."""

    def components(self) -> dict[str, Path]: ...

    def stop_writers(self, deadline) -> None: ...

    def quiescent(self) -> bool: ...

    def permit_boot_rebind(self, old_mapping: dict, current_mapping: dict) -> bool: ...


class Limits:
    def __setattr__(self, name: str, value: object) -> None:
        if self.__dict__.get("_sealed", False):
            raise AttributeError("recovery limits are immutable")
        object.__setattr__(self, name, value)

    def __init__(self, *, components: int = 128, entries: int = 50_000,
                 data_bytes: int = 64 * 1024**3, file_bytes: int = 16 * 1024**3,
                 manifest_bytes: int = 8 * 1024**2, plan_bytes: int = 16 * 1024**2,
                 record_bytes: int = 64 * 1024, records: int = 4096,
                 journal_bytes: int = 32 * 1024**2, seconds: int = 3600,
                 reserve_bytes: int = 16 * 1024**2):
        values = locals().copy()
        values.pop("self")
        for name, value in values.items():
            if type(value) is not int or value <= 0:
                raise RecoveryError("limits must be positive finite integers")
            setattr(self, name, value)
        if components > 128 or records > 4096 or seconds > 3600 or record_bytes > 1024 * 1024:
            raise RecoveryError("unsupported B1 safety ceiling")
        if journal_bytes > 32 * 1024**2 or plan_bytes > 16 * 1024**2 or manifest_bytes > 8 * 1024**2 or data_bytes > 64 * 1024**3 or file_bytes > 16 * 1024**3:
            raise RecoveryError("unsupported B1 byte ceiling")
        object.__setattr__(self, "_sealed", True)

    def profile(self) -> dict:
        return {name: value for name, value in self.__dict__.items() if name != "_sealed"}

    components: int
    entries: int
    data_bytes: int
    file_bytes: int
    manifest_bytes: int
    plan_bytes: int
    record_bytes: int
    records: int
    journal_bytes: int
    seconds: int
    reserve_bytes: int


PHASES = guard.JOURNAL_PHASES
ACTIONS = guard.JOURNAL_ACTIONS
ROOT_NAMES = {"active", "incoming"}
IDENTITY_FIELDS = {"device", "inode", "mode", "uid", "gid"}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _native_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except native_metadata.Error as exc:
        raise RecoveryError(str(exc)) from exc


def _fingerprint_valid(value: object, limits: Limits) -> bool:
    return (isinstance(value, dict) and set(value) == {"root", "sha256", "entries", "bytes"} and
            isinstance(value["root"], dict) and set(value["root"]) == IDENTITY_FIELDS and
            all(_integer(x, 2**64 - 1) for x in value["root"].values()) and
            isinstance(value["sha256"], str) and bool(guard.HEX.fullmatch(value["sha256"])) and
            _integer(value["entries"], limits.entries) and _integer(value["bytes"], limits.data_bytes))


class NativeDataGate(guard.Gate):  # type: ignore[name-defined]  # Loaded from the fixed sibling module.
    """Explicit trusted-code gate for metadata-aware document/output fixtures.

    This does not install writer admission/startup hooks. Default B1 gates still
    reject native plans. A future installed backend must qualify its own use.
    """

    def __init__(self, *args, native_classes: tuple[str, ...], **kwargs):
        if (type(native_classes) is not tuple or not native_classes or
                any(type(key) is not str for key in native_classes) or
                len(set(native_classes)) != len(native_classes)):
            raise RecoveryError("invalid trusted native history classes")
        self.native_policies = {
            key: _native_call(native_metadata.installed_incoming_policy, key) for key in native_classes
        }
        super().__init__(*args, **kwargs)

    def metadata_contract(self) -> dict:
        for key, policy in self.native_policies.items():
            if _native_call(native_metadata.installed_incoming_policy, key) != policy:
                raise RecoveryError("installed native metadata contract changed")
        return {key: policy.profile() for key, policy in self.native_policies.items()}

    def _validate_retained_plan(self, plan: object) -> dict:
        fields = {"version", "kind", "mapping", "components", "clock_domain", "limits_sha256", "native_metadata"}
        if (not isinstance(plan, dict) or set(plan) != fields or type(plan["version"]) is not int or
                plan["version"] != 2 or plan["kind"] != "native-data-components" or plan["clock_domain"] != guard.DOMAIN or
                not isinstance(plan["components"], dict) or set(plan["components"]) != set(self.native_policies) or
                not isinstance(plan["mapping"], dict) or set(plan["mapping"]) != set(self.native_policies) or
                not isinstance(plan["limits_sha256"], str) or not guard.HEX.fullmatch(plan["limits_sha256"])):
            raise RecoveryError("invalid retained native plan")
        if guard.encode(plan["native_metadata"]) != guard.encode(self.metadata_contract()):
            raise RecoveryError("retained native metadata contract changed")
        for mapping in plan["mapping"].values():
            if not isinstance(mapping, dict) or set(mapping) != IDENTITY_FIELDS | {"mount"} or any(not _integer(x, 2**64 - 1) for x in mapping.values()):
                raise RecoveryError("invalid retained native mapping")
        total = 0
        ceiling = Limits()
        for item in plan["components"].values():
            if not isinstance(item, dict) or set(item) != {"old", "new"} or not _fingerprint_valid(item["new"], ceiling) or (item["old"] is not None and not _fingerprint_valid(item["old"], ceiling)):
                raise RecoveryError("invalid retained native fingerprint")
            total += item["new"]["bytes"] + (item["old"]["bytes"] if item["old"] else 0)
        if total > ceiling.data_bytes:
            raise RecoveryError("retained native plan byte ceiling exceeded")
        return plan


class Engine:
    """Filesystem mutations require this explicit trusted-code backend object."""

    def __init__(self, gate, backend: Backend, limits: Limits | None = None, *,
                 native_classes: tuple[str, ...] = ()):
        self.gate, self.backend, self.limits = gate, backend, limits or Limits()
        self.limits_hash = _digest(guard.encode(self.limits.profile()))
        paths = backend.components()
        if not isinstance(paths, dict) or not 1 <= len(paths) <= self.limits.components:
            raise RecoveryError("invalid trusted component mapping")
        if (type(native_classes) is not tuple or
                any(type(item) is not str for item in native_classes) or
                len(set(native_classes)) != len(native_classes) or
                (native_classes and set(native_classes) != set(paths))):
            raise RecoveryError("native contracts must exactly cover trusted components")
        self.native_policies = {
            key: _native_call(native_metadata.installed_incoming_policy, key) for key in native_classes
        }
        if ((self.native_policies and (not isinstance(gate, NativeDataGate) or
                                      gate.metadata_contract() != self._metadata_contract())) or
                (isinstance(gate, NativeDataGate) and not self.native_policies)):
            raise RecoveryError("native journal requires an explicit matching native data gate")
        self.components: dict = {}
        self.operation_lock: Any = None
        self.admission_lock: Any = None
        self.tx_fd = self.records_fd = -1
        self.identifier: Any = None
        self.plan: Any = None
        self.current: Any = None
        self.used_bytes = self.used_records = 0
        self.last_hash = "0" * 64
        self.deadline: Any = None
        self.unheaded = False
        self.pending_head = self.pending_record = False
        self.recovering = False
        try:
            for identifier, path in sorted(paths.items()):
                if not isinstance(identifier, str) or not guard.ID.fullmatch(identifier) or not isinstance(path, Path):
                    raise RecoveryError("trusted component IDs must be fixed logical names")
                self.components[identifier] = guard.BoundDirectory(path)
            identities = [(v.identity["device"], v.identity["inode"]) for v in self.components.values()]
            if len(set(identities)) != len(identities):
                raise RecoveryError("component parents must be distinct")
            for a in self.components.values():
                for b in self.components.values():
                    if a is not b and a.path.is_relative_to(b.path):
                        raise RecoveryError("nested component parents are unsupported")
            self.mapping = {key: copy.deepcopy(value.identity) for key, value in self.components.items()}
            self.mapping_hash = _digest(guard.encode(self.mapping))
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for lock in (self.admission_lock, self.operation_lock):
            if lock is not None:
                lock.close()
        self.admission_lock = self.operation_lock = None
        for name in ("records_fd", "tx_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)
        for component in self.components.values():
            component.close()

    def _space(self, fd: int, required: int) -> None:
        available = os.fstatvfs(fd)
        reserve = max(self.limits.reserve_bytes, (required + 19) // 20)
        if available.f_bavail * available.f_frsize < required + reserve or available.f_favail == 0:
            raise RecoveryError("insufficient recovery space including reserve")

    def _check(self, *, quiescent: bool = False) -> None:
        self._metadata_contract()
        self.gate.check(allow_pending=self.recovering)
        if self.operation_lock is not None:
            self.operation_lock.check()
        if self.admission_lock is not None:
            self.admission_lock.check()
        for component in self.components.values():
            component.check()
        if self.deadline is not None:
            self.deadline.check()
        if quiescent and (self.admission_lock is None or self.backend.quiescent() is not True):
            raise RecoveryError("writer or surviving descendant is not quiescent")

    def _namespace(self) -> None:
        state = self.gate.state(recovery=self.recovering)
        known = set(state["history"])
        if state["transaction"] is not None:
            known.add(state["transaction"])
        for component in self.components.values():
            allowed = ROOT_NAMES | {".secai-recovery-" + identifier for identifier in known}
            if guard.names(component.fd, 16) - allowed:
                raise RecoveryError("unknown component debris; no automatic cleanup")

    def _metadata_contract(self) -> dict:
        for key, policy in self.native_policies.items():
            if _native_call(native_metadata.installed_incoming_policy, key) != policy:
                raise RecoveryError("installed native metadata contract changed")
        return {key: policy.profile() for key, policy in self.native_policies.items()}

    def _fingerprint(self, parent: int, name: str, *, sync: bool = False, label: str = "snapshot",
                     incoming_class: str | None = None) -> dict | None:
        assert self.deadline is not None
        self._metadata_contract()
        if incoming_class is not None and incoming_class not in self.native_policies:
            raise RecoveryError("incoming metadata requires an installed native contract")
        try:
            root = os.open(name, guard.DIR_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            root_id = guard.directory_id(root)
            if root_id["mount"] != guard.mount_id(parent):
                raise RecoveryError("component or generation crosses a mount boundary")
            if self.native_policies and incoming_class is None and self.plan is not None:
                # The original incoming inode keeps its target contract after
                # prepare/publication/rollback renames, including journal replay.
                matches = [key for key, item in self.plan["components"].items()
                           if all(item["new"]["root"][field] == root_id[field] for field in ("device", "inode"))]
                if len(matches) > 1:
                    raise RecoveryError("native incoming generation identities overlap")
                if matches:
                    incoming_class = matches[0]
            records: list[dict[str, Any]] = []
            total = estimated = 0

            def metadata_record(fd: int, relative: str, directory: bool) -> dict:
                nonlocal estimated
                self.deadline.check()
                value = _native_call(native_metadata.snapshot_existing, fd)
                self.deadline.check()
                # Labels are bounded individually and count toward the existing
                # aggregate ceiling before being retained in the manifest.
                estimated += len(guard.encode(value))
                if estimated > self.limits.manifest_bytes:
                    raise RecoveryError("generation metadata/count ceiling exceeded")
                if incoming_class is not None:
                    expected = _native_call(self.native_policies[incoming_class].target_metadata, relative,
                                            directory=directory, check=self.deadline.check)
                    self.deadline.check()
                    label = bytes.fromhex(value["selinux_hex"] or "")
                    context = expected["selinux"].encode("ascii")
                    if (value["uid"] != expected["uid"] or value["gid"] != expected["gid"] or
                            value["mode"] != expected["mode"] or
                            label not in (context, context + b"\0")):
                        raise RecoveryError("incoming generation differs from installed target metadata")
                return value

            def scan(fd: int, relative: str) -> None:
                nonlocal total, estimated
                self.deadline.check()
                before = os.fstat(fd)
                if not self.native_policies and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700):
                    raise RecoveryError("B1 accepts private inert directory metadata only")
                if guard.mount_id(fd) != root_id["mount"]:
                    raise RecoveryError("nested generation mount is unsupported")
                guard._inventory.check_metadata(fd, before)
                directory_metadata = metadata_record(fd, relative, True) if self.native_policies else None
                nodes: list[tuple[str, str, os.stat_result]] = []
                with os.scandir(fd) as children:
                    for child in children:
                        self.deadline.check()
                        path = relative + "/" + child.name if relative else child.name
                        guard._inventory.relative_name(path, guard._inventory.Limits())
                        estimated += 512 + len(path.encode("utf-8"))
                        if estimated > self.limits.manifest_bytes or len(records) + len(nodes) >= self.limits.entries:
                            raise RecoveryError("generation metadata/count ceiling exceeded")
                        metadata = child.stat(follow_symlinks=False)
                        if not stat.S_ISREG(metadata.st_mode) and not stat.S_ISDIR(metadata.st_mode):
                            raise RecoveryError("generation links and special objects are unsupported")
                        nodes.append((path, child.name, metadata))
                keys = [guard._inventory.collision_name(path) for path, _name, _metadata in nodes]
                if len(set(keys)) != len(keys):
                    raise RecoveryError("colliding generation filenames")
                for path, basename, metadata in sorted(nodes):
                    self.deadline.check()
                    is_dir = stat.S_ISDIR(metadata.st_mode)
                    child_fd = os.open(basename, guard.DIR_FLAGS if is_dir else guard.FILE_FLAGS, dir_fd=fd)
                    try:
                        if guard._inventory.identity(metadata) != guard._inventory.identity(os.fstat(child_fd)):
                            raise RecoveryError("generation changed while opening")
                        if guard.mount_id(child_fd) != root_id["mount"]:
                            raise RecoveryError("generation mount changed")
                        if is_dir:
                            scan(child_fd, path)
                        else:
                            guard._inventory.check_metadata(child_fd, metadata)
                            if (metadata.st_size > self.limits.file_bytes or
                                    (not self.native_policies and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600))):
                                raise RecoveryError("B1 accepts bounded private inert files only")
                            file_metadata = metadata_record(child_fd, path, False) if self.native_policies else None
                            total += metadata.st_size
                            if total > self.limits.data_bytes:
                                raise RecoveryError("generation byte ceiling exceeded")
                            digest, count = hashlib.sha256(), 0
                            while chunk := os.read(child_fd, 64 * 1024):
                                self.deadline.check()
                                count += len(chunk)
                                if count > metadata.st_size:
                                    raise RecoveryError("generation file grew")
                                digest.update(chunk)
                            if count != metadata.st_size or guard._inventory.identity(metadata) != guard._inventory.identity(os.fstat(child_fd)):
                                raise RecoveryError("generation file changed")
                            records.append({"path": path, "kind": "file", "device": metadata.st_dev,
                                            "inode": metadata.st_ino, "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid,
                                            "gid": metadata.st_gid, "size": count, "sha256": digest.hexdigest(),
                                            "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns})
                            if file_metadata is not None:
                                if file_metadata != _native_call(native_metadata.snapshot_existing, child_fd):
                                    raise RecoveryError("generation metadata changed while hashing")
                                records[-1]["native_metadata"] = file_metadata
                            if sync:
                                self.gate.io.sync(child_fd, label + ":file")
                    finally:
                        os.close(child_fd)
                if guard._inventory.identity(before) != guard._inventory.identity(os.fstat(fd)):
                    raise RecoveryError("generation directory changed")
                records.append({"path": relative, "kind": "directory", "device": before.st_dev,
                                "inode": before.st_ino, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid})
                if directory_metadata is not None:
                    if directory_metadata != _native_call(native_metadata.snapshot_existing, fd):
                        raise RecoveryError("generation metadata changed while hashing")
                    records[-1]["native_metadata"] = directory_metadata
                if len(records) > self.limits.entries:
                    raise RecoveryError("generation entry ceiling exceeded")
                if sync:
                    self.gate.io.sync(fd, label + ":directory")

            scan(root, "")
            self.deadline.check()
            return {"root": {k: root_id[k] for k in IDENTITY_FIELDS},
                    "sha256": _digest(guard.encode(sorted(records, key=lambda r: r["path"]))),
                    "entries": len(records), "bytes": total}
        finally:
            os.close(root)

    def make_plan(self) -> dict:
        """No input paths: discover only trusted-code active/incoming mappings."""
        self.gate.require_open()
        self.deadline = guard.Deadline(self.gate.clock, self.limits.seconds)
        self._namespace()
        components = {}
        total = 0
        for identifier, directory in self.components.items():
            old = self._fingerprint(directory.fd, "active")
            new = self._fingerprint(directory.fd, "incoming", incoming_class=identifier if self.native_policies else None)
            if new is None:
                raise RecoveryError("trusted component lacks an inert incoming generation")
            if old is not None and old["root"]["inode"] == new["root"]["inode"]:
                raise RecoveryError("old and new generation identities overlap")
            components[identifier] = {"old": old, "new": new}
            total += new["bytes"] + (old["bytes"] if old else 0)
        if total > self.limits.data_bytes:
            raise RecoveryError("plan aggregate byte ceiling exceeded")
        plan = {"version": 1, "kind": "inert-components", "mapping": copy.deepcopy(self.mapping),
                "components": components, "clock_domain": guard.DOMAIN, "limits_sha256": self.limits_hash}
        if self.native_policies:
            plan.update(version=2, kind="native-data-components", native_metadata=self._metadata_contract())
        return self._validate_plan(plan)

    def _validate_plan(self, value: object, *, allow_mount_rebind: bool = False) -> dict:
        fields = {"version", "kind", "mapping", "components", "clock_domain", "limits_sha256"}
        if self.native_policies:
            fields.add("native_metadata")
        if not isinstance(value, dict) or set(value) != fields:
            raise RecoveryError("plan cannot supply destinations, commands or extra fields")
        version, kind = (2, "native-data-components") if self.native_policies else (1, "inert-components")
        if type(value["version"]) is not int or value["version"] != version or value["kind"] != kind or value["clock_domain"] != guard.DOMAIN:
            raise RecoveryError("unsupported plan version or clock domain")
        if self.native_policies and guard.encode(value["native_metadata"]) != guard.encode(self._metadata_contract()):
            raise RecoveryError("plan differs from installed native metadata contract")
        if value["limits_sha256"] != self.limits_hash:
            raise RecoveryError("trusted recovery limit profile changed")
        if (not isinstance(value["mapping"], dict) or set(value["mapping"]) != set(self.components) or
                not isinstance(value["components"], dict) or set(value["components"]) != set(self.components)):
            raise RecoveryError("plan differs from trusted code component mapping")
        for key, mapping in value["mapping"].items():
            if not isinstance(mapping, dict) or set(mapping) != IDENTITY_FIELDS | {"mount"} or any(not _integer(x, 2**64 - 1) for x in mapping.values()):
                raise RecoveryError("invalid trusted mapping metadata types")
            # A validated replay may consider boot-local mount ID changes only.
            # The closed journal and trusted backend must still approve a new
            # boot before quiescence, journal repair, or generation mutation.
            fields = IDENTITY_FIELDS if allow_mount_rebind else IDENTITY_FIELDS | {"mount"}
            if any(mapping[field] != self.mapping[key][field] for field in fields):
                raise RecoveryError("plan differs from trusted code component mapping")
        total = 0
        for item in value["components"].values():
            if not isinstance(item, dict) or set(item) != {"old", "new"} or not _fingerprint_valid(item["new"], self.limits) or (item["old"] is not None and not _fingerprint_valid(item["old"], self.limits)):
                raise RecoveryError("invalid bounded generation fingerprint")
            total += item["new"]["bytes"] + (item["old"]["bytes"] if item["old"] else 0)
        if total > self.limits.data_bytes or len(guard.encode(value)) > self.limits.plan_bytes:
            raise RecoveryError("plan size ceiling exceeded")
        return value

    def _reserve(self) -> tuple[int, int]:
        # Worst-case reverse rename intents/outcomes plus root transitions,
        # terminal bookkeeping and one additional error/recovery transition.
        slots = 4 * len(self.components) + 8
        reserved_bytes = slots * self.limits.record_bytes
        sample = {"version": 1, "transaction": "0" * 36, "revision": self.limits.records,
                  "previous_sha256": "0" * 64, "plan_sha256": "0" * 64, "phase": "rolling_back",
                  "intent": {"action": "old-to-rollback", "component": "x" * 32},
                  "origin_boot": "0" * 36, "execution_boot": "0" * 36, "clock_domain": guard.DOMAIN,
                  "deadline_ns": 2**63 - 1, "reserved_slots": slots, "reserved_bytes": reserved_bytes}
        if len(guard.encode(sample)) > self.limits.record_bytes:
            raise RecoveryError("record limit cannot represent reserved safety transitions")
        if self.limits.records <= slots + 3 or self.limits.journal_bytes <= reserved_bytes + 3 * self.limits.record_bytes:
            raise RecoveryError("journal has no reserved safety-transition capacity")
        return slots, reserved_bytes

    def _check_record(self, value: object, revision: int, previous: str) -> dict:
        fields = guard.JOURNAL_FIELDS
        if not isinstance(value, dict) or set(value) != fields:
            raise RecoveryError("invalid journal fields")
        if (type(value["version"]) is not int or value["version"] != 1 or type(value["revision"]) is not int or
                value["revision"] != revision or value["transaction"] != self.identifier or value["previous_sha256"] != previous or
                value["plan_sha256"] != self.plan_hash or not isinstance(value["phase"], str) or value["phase"] not in PHASES or
                not guard.valid_uuid(value["origin_boot"]) or not guard.valid_uuid(value["execution_boot"]) or value["clock_domain"] != guard.DOMAIN or
                not _integer(value["deadline_ns"], 2**63 - 1)):
            raise RecoveryError("journal identity, clock or phase mismatch")
        reserve = self._reserve()
        if type(value["reserved_slots"]) is not int or type(value["reserved_bytes"]) is not int or (value["reserved_slots"], value["reserved_bytes"]) != reserve:
            raise RecoveryError("journal safety reservation changed")
        intent = value["intent"]
        if not isinstance(intent, dict) or set(intent) != {"action", "component"} or not isinstance(intent["action"], str) or intent["action"] not in ACTIONS:
            raise RecoveryError("unknown journal action")
        if intent["action"] == "none":
            if intent["component"] is not None:
                raise RecoveryError("unexpected journal component")
        elif not isinstance(intent["component"], str) or intent["component"] not in self.components:
            raise RecoveryError("journal action has no trusted component")
        return value

    def _head(self, revision: int, digest: str) -> dict:
        return {"version": 1, "transaction": self.identifier, "revision": revision, "sha256": digest}

    def _append(self, phase: str, *, action: str = "none", component: str | None = None, safety: bool = False) -> None:
        self._check(quiescent=self.admission_lock is not None)
        if self.unheaded:
            raise RecoveryError("unheaded record requires recovery")
        assert self.deadline is not None
        slots, reserved_bytes = self._reserve()
        revision = self.used_records + 1
        value = {"version": 1, "transaction": self.identifier, "revision": revision,
                 "previous_sha256": self.last_hash, "plan_sha256": self.plan_hash,
                 "phase": phase, "intent": {"action": action, "component": component},
                 "origin_boot": self.current["origin_boot"] if self.current else self.deadline.boot,
                 "execution_boot": self.deadline.boot, "clock_domain": guard.DOMAIN, "deadline_ns": self.deadline.end,
                 "reserved_slots": slots, "reserved_bytes": reserved_bytes}
        self._check_record(value, revision, self.last_hash)
        data = guard.encode(value)
        maximum_records = self.limits.records if safety else self.limits.records - slots
        maximum_bytes = self.limits.journal_bytes if safety else self.limits.journal_bytes - reserved_bytes
        if len(data) > self.limits.record_bytes or revision > maximum_records or self.used_bytes + len(data) > maximum_bytes:
            raise RecoveryError("normal journal capacity exhausted; safety reservation preserved" if not safety else "safety journal capacity exhausted")
        self._space(self.records_fd, len(data) + reserved_bytes)
        event = "journal:" + phase + ":" + action
        self.gate.io.create(self.records_fd, ".next-record", data, event)
        self.gate.io.no_replace(self.records_fd, ".next-record", self.records_fd, f"{revision:08d}.json", event)
        self.gate.io.sync(self.records_fd, event + ":records-directory")
        digest = _digest(data)
        self.gate.io.replace_json(self.tx_fd, "head.json", self._head(revision, digest), event + ":head")
        self.current, self.last_hash = value, digest
        self.used_records, self.used_bytes = revision, self.used_bytes + len(data)

    def begin(self, supplied_plan: dict) -> str:
        if self.identifier is not None or self.operation_lock is not None:
            raise RecoveryError("engine already owns a transaction")
        self.operation_lock = self.gate.operation()
        self.gate.require_open()
        self.deadline = guard.Deadline(self.gate.clock, self.limits.seconds)
        self.plan = copy.deepcopy(self._validate_plan(supplied_plan))
        self.plan_hash = _digest(guard.encode(self.plan))
        self._reserve()
        self._space(self.gate.root.fd, self.limits.plan_bytes + self.limits.journal_bytes)
        self._namespace()
        for identifier, directory in self.components.items():
            expected = self.plan["components"][identifier]
            if self._fingerprint(directory.fd, "active") != expected["old"] or self._fingerprint(directory.fd, "incoming") != expected["new"]:
                raise RecoveryError("generation changed since plan review")
            self._space(directory.fd, 16 * 1024)
        self.identifier = str(uuid.uuid4())
        self.gate.close_for(self.identifier)
        transactions = os.open("transactions", guard.DIR_FLAGS, dir_fd=self.gate.root.fd)
        try:
            self.gate.io.hook("transaction:before-mkdir")
            os.mkdir(self.identifier, 0o700, dir_fd=transactions)
            self.gate.io.sync(transactions, "transaction:parent")
            self.tx_fd = os.open(self.identifier, guard.DIR_FLAGS, dir_fd=transactions)
        finally:
            os.close(transactions)
        self.gate.io.create(self.tx_fd, "plan.json", guard.encode(self.plan), "plan")
        self.gate.io.sync(self.tx_fd, "plan:parent")
        os.mkdir("records", 0o700, dir_fd=self.tx_fd)
        self.gate.io.sync(self.tx_fd, "records:parent")
        self.records_fd = os.open("records", guard.DIR_FLAGS, dir_fd=self.tx_fd)
        self._append("created")
        return self.identifier

    def quiesce(self) -> None:
        if self.current is None or self.current["phase"] != "created":
            raise RecoveryError("quiescence requires a created transaction")
        self._acquire_quiescence()
        self._append("quiesced")

    def _acquire_quiescence(self) -> None:
        self._check()
        self.backend.stop_writers(self.deadline)
        if self.admission_lock is None:
            self.admission_lock = guard.StableLock(self.gate.root, "admission.lock", self.gate.layout["admission"])
            self.admission_lock.acquire(True, self.deadline)
        self._check(quiescent=True)

    def _workspace(self, identifier: str, *, create: bool = False) -> int:
        directory = self.components[identifier]
        directory.check()
        name = ".secai-recovery-" + self.identifier
        if create:
            self.gate.io.hook("workspace:" + identifier + ":before-mkdir")
            os.mkdir(name, 0o700, dir_fd=directory.fd)
            self.gate.io.sync(directory.fd, "workspace:" + identifier + ":parent")
        fd = os.open(name, guard.DIR_FLAGS, dir_fd=directory.fd)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700 or guard.mount_id(fd) != guard.mount_id(directory.fd):
                raise RecoveryError("unsafe or changed generation workspace")
            if guard.names(fd, 4) - {"old", "new"}:
                raise RecoveryError("unknown generation workspace debris")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _move(self, identifier: str, source_fd: int, source: str, target_fd: int, target: str, event: str) -> None:
        self._check(quiescent=True)
        self._namespace()
        if guard.mount_id(source_fd) != guard.mount_id(target_fd):
            raise RecoveryError("cross-filesystem publication has no copy fallback")
        self.gate.io.no_replace(source_fd, source, target_fd, target, event + ":" + identifier)
        self.gate.io.sync(source_fd, event + ":" + identifier + ":source-parent")
        if source_fd != target_fd:
            self.gate.io.sync(target_fd, event + ":" + identifier + ":target-parent")
        self._check(quiescent=True)

    def prepare(self) -> None:
        if self.current is None or self.current["phase"] != "quiesced":
            raise RecoveryError("prepare requires quiescence")
        for identifier, directory in self.components.items():
            self._check(quiescent=True)
            expected = self.plan["components"][identifier]
            if self._fingerprint(directory.fd, "active", sync=True, label="prepare-old:" + identifier) != expected["old"] or self._fingerprint(directory.fd, "incoming", sync=True, label="prepare:" + identifier) != expected["new"]:
                raise RecoveryError("generation changed before prepare")
            self._append("preparing", action="prepare-new", component=identifier)
            workspace = self._workspace(identifier, create=True)
            try:
                self._move(identifier, directory.fd, "incoming", workspace, "new", "prepare:new")
                if self._fingerprint(workspace, "new") != expected["new"]:
                    raise RecoveryError("prepared generation identity changed")
            finally:
                os.close(workspace)
        self._append("prepared")

    def publish(self) -> None:
        if self.current is None or self.current["phase"] != "prepared":
            raise RecoveryError("publish requires all components prepared")
        for identifier, directory in self.components.items():
            expected = self.plan["components"][identifier]
            workspace = self._workspace(identifier)
            try:
                if self._fingerprint(directory.fd, "active") != expected["old"] or self._fingerprint(workspace, "new") != expected["new"] or self._fingerprint(workspace, "old") is not None:
                    raise RecoveryError("publication conflicts with planned identities")
                self._append("publishing", action="old-to-rollback", component=identifier)
                if expected["old"] is not None:
                    self._move(identifier, directory.fd, "active", workspace, "old", "publish:old")
                if self._fingerprint(workspace, "old") != expected["old"]:
                    raise RecoveryError("old generation identity changed during rename")
                self._append("publishing", action="new-to-active", component=identifier)
                self._move(identifier, workspace, "new", directory.fd, "active", "publish:new")
                if self._fingerprint(directory.fd, "active") != expected["new"]:
                    raise RecoveryError("new generation identity changed during rename")
            finally:
                os.close(workspace)
        self._append("published")

    def _all_new(self) -> None:
        self._check(quiescent=True)
        self._namespace()
        for identifier, directory in self.components.items():
            expected = self.plan["components"][identifier]
            workspace = self._workspace(identifier)
            try:
                if (self._fingerprint(directory.fd, "active") != expected["new"] or
                        self._fingerprint(workspace, "old") != expected["old"] or
                        self._fingerprint(workspace, "new") is not None or self._fingerprint(directory.fd, "incoming") is not None):
                    raise RecoveryError("published generations differ from plan")
            finally:
                os.close(workspace)

    def validate(self) -> None:
        if self.current is None or self.current["phase"] != "published":
            raise RecoveryError("validation requires publication")
        self._all_new()
        self._append("validated")

    def commit(self) -> None:
        if self.current is None or self.current["phase"] != "validated":
            raise RecoveryError("commit requires inert data validation")
        self._all_new()
        self._append("committed")

    def _load(self, identifier: str) -> None:
        if not guard.valid_uuid(identifier):
            raise RecoveryError("invalid transaction identity")
        self.identifier = identifier
        transactions = os.open("transactions", guard.DIR_FLAGS, dir_fd=self.gate.root.fd)
        try:
            state = self.gate.state(recovery=True)
            closed = state["state"] == "closed" and state["transaction"] == identifier
            interrupted_release = state["state"] == "open" and state["history"] and state["history"][-1] == identifier
            if interrupted_release:
                try:
                    self.gate.require_open()
                except (RecoveryError, OSError):
                    pass
                else:
                    raise RecoveryError("released historical transactions cannot be replayed")
            if not closed and not interrupted_release:
                raise RecoveryError("only the active closed or interrupted release may recover")
            expected_transactions = set(state["history"]) | ({identifier} if closed else set())
            if guard.names(transactions, 9) != expected_transactions:
                raise RecoveryError("unknown transaction namespace")
            self.tx_fd = os.open(identifier, guard.DIR_FLAGS, dir_fd=transactions)
        finally:
            os.close(transactions)
        found = guard.names(self.tx_fd, 8)
        if found - {"plan.json", "head.json", "records", "terminal.json", ".next-head.json"} or not {"plan.json", "records"}.issubset(found):
            raise RecoveryError("unknown or incomplete transaction metadata")
        data = guard.read_bytes(self.tx_fd, "plan.json", self.limits.plan_bytes)
        plan = guard.strict_json(data, self.limits.plan_bytes)
        self.plan = self._validate_plan(plan, allow_mount_rebind=True)
        self.plan_hash = _digest(data)
        self.records_fd = os.open("records", guard.DIR_FLAGS, dir_fd=self.tx_fd)
        files = guard.names(self.records_fd, self.limits.records + 1)
        self.pending_record = ".next-record" in files
        files.discard(".next-record")
        if (not files and not self.pending_record) or files != {f"{i:08d}.json" for i in range(1, len(files) + 1)}:
            raise RecoveryError("torn, missing or unknown journal record")
        previous, total = "0" * 64, 0
        records: list[tuple[dict, str]] = []
        count = len(files) + int(self.pending_record)
        if count > self.limits.records:
            raise RecoveryError("journal record ceiling exceeded")
        for revision in range(1, count + 1):
            self.deadline.check()
            name = ".next-record" if self.pending_record and revision == count else f"{revision:08d}.json"
            data = guard.read_bytes(self.records_fd, name, self.limits.record_bytes)
            total += len(data)
            if total > self.limits.journal_bytes:
                raise RecoveryError("journal total byte ceiling exceeded")
            current = self._check_record(guard.strict_json(data, self.limits.record_bytes), revision, previous)
            if records and current["origin_boot"] != records[0][0]["origin_boot"]:
                raise RecoveryError("journal origin boot changed")
            previous = _digest(data)
            records.append((current, previous))
        try:
            head = guard.read_json(self.tx_fd, "head.json")
        except FileNotFoundError:
            head = None
        if head is None:
            if len(records) != 1:
                raise RecoveryError("missing journal head")
            headed = 0
        else:
            if (set(head) != {"version", "transaction", "revision", "sha256"} or type(head["version"]) is not int or
                    head["version"] != 1 or head["transaction"] != identifier or type(head["revision"]) is not int or
                    not 1 <= head["revision"] <= len(records) or head["sha256"] != records[head["revision"] - 1][1]):
                raise RecoveryError("corrupt journal head")
            headed = head["revision"]
        if len(records) - headed > 1:
            raise RecoveryError("multiple uncommitted journal tails")
        self.current, self.last_hash = records[-1]
        if interrupted_release and self.current["phase"] not in ("committed", "rolled_back"):
            raise RecoveryError("open gate does not describe a terminal data generation")
        self.used_records, self.used_bytes = len(records), total
        self.unheaded = headed != len(records) or self.pending_record
        if ".next-head.json" in found:
            pending = guard.read_json(self.tx_fd, ".next-head.json")
            if type(pending.get("version")) is not int or type(pending.get("revision")) is not int or pending != self._head(self.used_records, self.last_hash):
                raise RecoveryError("torn or unknown pending head")
            self.pending_head = True
            self.unheaded = True

    def recover(self, identifier: str) -> str:
        """Known pre-commit states roll back; committed states retain new data."""
        if self.identifier is not None or self.operation_lock is not None:
            raise RecoveryError("recovery requires a fresh coordinator")
        self.operation_lock = self.gate.operation()
        self.recovering = True
        self.deadline = guard.Deadline(self.gate.clock, self.limits.seconds)
        self._load(identifier)
        if self.current["origin_boot"] != self.deadline.boot:
            if self.backend.permit_boot_rebind(copy.deepcopy(self.plan["mapping"]),
                                             copy.deepcopy(self.mapping)) is not True:
                raise RecoveryError("new boot requires trusted filesystem rebind")
            self.deadline.check()
        elif self.plan["mapping"] != self.mapping:
            raise RecoveryError("same boot cannot rebind component mounts")
        self._acquire_quiescence()
        if self.pending_record:
            self.gate.io.no_replace(self.records_fd, ".next-record", self.records_fd,
                                    f"{self.used_records:08d}.json", "recover:record")
            self.gate.io.sync(self.records_fd, "recover:records-parent")
            self.pending_record = False
        if self.pending_head:
            self.gate.io.hook("recover:head:before-replace")
            os.replace(".next-head.json", "head.json", src_dir_fd=self.tx_fd, dst_dir_fd=self.tx_fd)
            self.gate.io.hook("recover:head:after-replace")
            self.gate.io.sync(self.tx_fd, "recover:head-parent")
            self.pending_head = False
            self.unheaded = False
        if self.unheaded:
            self.gate.io.replace_json(self.tx_fd, "head.json", self._head(self.used_records, self.last_hash), "recover:head")
            self.unheaded = False
        if self.current["phase"] == "committed":
            self._all_new()
            return "committed"
        if self.current["phase"] == "rolled_back":
            self._all_old(sync=True)
            return "rolled_back"
        self.rollback()
        return "rolled_back"

    def _all_old(self, *, sync: bool = False) -> None:
        self._check(quiescent=True)
        self._namespace()
        for identifier, directory in self.components.items():
            expected = self.plan["components"][identifier]
            if self._fingerprint(directory.fd, "active", sync=sync, label="rollback-verified:" + identifier) != expected["old"]:
                raise RecoveryError("rollback did not restore exact old generation")
            incoming = self._fingerprint(directory.fd, "incoming")
            try:
                workspace = self._workspace(identifier)
            except FileNotFoundError:
                if incoming != expected["new"]:
                    raise RecoveryError("rollback lost the retained new generation")
            else:
                try:
                    new = self._fingerprint(workspace, "new")
                    if (self._fingerprint(workspace, "old") is not None or
                            new not in (None, expected["new"]) or incoming not in (None, expected["new"]) or
                            sum(item == expected["new"] for item in (new, incoming)) != 1):
                        raise RecoveryError("rollback retained generations are inconsistent")
                finally:
                    os.close(workspace)

    def rollback(self) -> None:
        if self.current is None or self.current["phase"] == "committed":
            raise RecoveryError("cannot roll back absent or committed transaction")
        self._check(quiescent=True)
        self._append("rolling_back", safety=True)
        for identifier, directory in reversed(list(self.components.items())):
            expected = self.plan["components"][identifier]
            active = self._fingerprint(directory.fd, "active")
            incoming = self._fingerprint(directory.fd, "incoming")
            try:
                workspace = self._workspace(identifier)
            except FileNotFoundError:
                if active != expected["old"] or incoming != expected["new"]:
                    raise RecoveryError("unknown pre-prepare generation state")
                continue
            try:
                old, new = self._fingerprint(workspace, "old"), self._fingerprint(workspace, "new")
                if old not in (None, expected["old"]) or new not in (None, expected["new"]) or incoming not in (None, expected["new"]):
                    raise RecoveryError("unknown rollback generation identity")
                if sum(item == expected["new"] for item in (active, new, incoming)) != 1:
                    raise RecoveryError("new generation missing or duplicated")
                if expected["old"] is not None and sum(item == expected["old"] for item in (active, old)) != 1:
                    raise RecoveryError("old generation missing or duplicated")
                if active == expected["new"]:
                    self._append("rolling_back", action="new-to-stage", component=identifier, safety=True)
                    self._move(identifier, directory.fd, "active", workspace, "new", "rollback:new")
                    if self._fingerprint(workspace, "new") != expected["new"]:
                        raise RecoveryError("rollback new-generation move changed identity")
                    self._append("rolling_back", safety=True)
                    active = None
                if expected["old"] is not None and active is None:
                    self._append("rolling_back", action="old-to-active", component=identifier, safety=True)
                    self._move(identifier, workspace, "old", directory.fd, "active", "rollback:old")
                    self._append("rolling_back", safety=True)
                elif active != expected["old"]:
                    raise RecoveryError("unexpected rollback active generation")
            finally:
                os.close(workspace)
        self._all_old(sync=True)
        self._append("rolled_back", safety=True)

    def release(self) -> None:
        if self.current is None or self.current["phase"] not in ("committed", "rolled_back"):
            raise RecoveryError("only verified terminal data may release admission")
        if self.current["phase"] == "committed":
            self._all_new()
        else:
            self._all_old()
        terminal = {"version": 1, "transaction": self.identifier, "outcome": self.current["phase"], "head_sha256": self.last_hash}
        found = guard.names(self.tx_fd, 8)
        if "terminal.json" in found:
            saved_terminal = guard.read_json(self.tx_fd, "terminal.json")
            if type(saved_terminal.get("version")) is not int or saved_terminal != terminal:
                raise RecoveryError("terminal metadata differs from journal")
        else:
            self.gate.io.create(self.tx_fd, "terminal.json", guard.encode(terminal), "release:terminal")
            self.gate.io.sync(self.tx_fd, "release:terminal-parent")
        value = self.gate.state(recovery=self.recovering)
        pending_gate = ".next-gate.json" in guard.names(self.gate.root.fd, 16)
        if value["state"] == "closed" and value["transaction"] == self.identifier:
            opened = {"version": 1, "state": "open", "transaction": None,
                      "history": value["history"] + [self.identifier], "epoch": str(uuid.uuid4())}
            if pending_gate:
                candidate = self.gate.validate_state(guard.read_json(self.gate.root.fd, ".next-gate.json"))
                if candidate["state"] != "open" or candidate["history"] != opened["history"]:
                    raise RecoveryError("pending gate is not this verified release")
                opened = candidate
        elif self.recovering and value["state"] == "open" and value["history"][-1:] == [self.identifier]:
            opened = value
            if pending_gate:
                raise RecoveryError("unexpected pending gate after release")
        else:
            raise RecoveryError("gate no longer belongs to transaction")
        self._check(quiescent=True)
        if pending_gate:
            self.gate.io.promote_json(self.gate.root.fd, "gate.json", opened, "release:gate")
        elif value["state"] != "open":
            self.gate.io.replace_json(self.gate.root.fd, "gate.json", opened, "release:gate")
        ready = {"version": 1, "epoch": opened["epoch"], "boot": self.gate.clock.boot_id(), "domain": guard.DOMAIN}
        if ".next-ready.json" in guard.names(self.gate.runtime.fd, 4):
            candidate = guard.read_json(self.gate.runtime.fd, ".next-ready.json")
            if type(candidate.get("version")) is not int or candidate != ready:
                raise RecoveryError("pending ready proof is stale or corrupt")
            self.gate.io.promote_json(self.gate.runtime.fd, "ready.json", ready, "release:ready")
        else:
            self.gate.io.replace_json(self.gate.runtime.fd, "ready.json", ready, "release:ready")
        # No service starts or automatic generation cleanup belong to B1.
        self.admission_lock.close()
        self.admission_lock = None
        self.operation_lock.close()
        self.operation_lock = None
        self.recovering = False
        self.gate.require_open()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", nargs="?", choices=("status", "initialize", "begin", "publish", "recover", "release"), default="status")
    parser.parse_args()
    print('{"status":"unavailable","native_adapter":false,"active_restore":false,"reason":"installed B2 adapter and remaining recovery qualifications required"}', file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

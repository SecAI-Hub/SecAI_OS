"""Real descriptor/DAC journal fixtures; SELinux lookups/xattrs are simulated.

These are not installed writer, mount, SELinux or power-loss qualification.
The root-only cases change ownership only inside pytest's private temporary tree.
"""
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_backup_transaction import FixtureBackend, FixtureClock, g, tx

CLASSES = ("user-documents", "user-outputs")
CONTEXT = "system_u:object_r:var_lib_t:s0"
ROOT_ONLY = pytest.mark.skipif(os.geteuid() != 0, reason="isolated root DAC fixture required")


class NativeFixtureBackend(FixtureBackend):
    COMPONENTS = {key: key + "-parent" for key in CLASSES}


@pytest.fixture
def local_policy(monkeypatch):
    installed = json.loads((Path(__file__).parents[1] /
                           "files/system/etc/secure-ai/config/backup-inventory.json").read_text())
    labels = {}

    def label(fd, name, **_kwargs):
        assert name == "security.selinux"
        value = os.fstat(fd)
        return labels.get((value.st_dev, value.st_ino), CONTEXT.encode() + b"\0")

    monkeypatch.setattr(tx.native_metadata.inventory, "load_inventory", lambda *_args, **_kwargs: installed)
    monkeypatch.setattr(tx.native_metadata.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=42001))
    monkeypatch.setattr(tx.native_metadata, "_target_context", lambda *_args: CONTEXT)
    monkeypatch.setattr(tx.native_metadata.os, "getxattr", label)
    return installed, labels


@pytest.fixture
def native_backend(tmp_path, local_policy):
    root = tmp_path / "native-fixture"
    root.mkdir(mode=0o700)
    backend = NativeFixtureBackend(root)
    for name in ("recovery", "runtime"):
        (root / name).mkdir(mode=0o700)
    for key, parent in backend.components().items():
        parent.mkdir(mode=0o700)
        for generation in ("active", "incoming"):
            tree = parent / generation
            tree.mkdir(mode=0o700)
            (tree / "empty directory").mkdir(mode=0o700)
            payload = tree / "payload"
            payload.write_bytes((generation + key).encode())
            if os.geteuid() == 0:
                incoming = generation == "incoming"
                uid, gid = (0, 42001) if incoming else (42002, 42002)
                for node in (payload, tree / "empty directory", tree):
                    os.chown(node, uid, gid)
                    mode = (0o2750 if key == "user-documents" else 0o2770) if node.is_dir() else 0o640
                    node.chmod(mode if incoming else (0o2770 if node.is_dir() else 0o600))
            else:
                payload.chmod(0o600)
    g.Gate.initialize(root / "recovery", root / "runtime")
    return backend


def engine_for(backend, *, clock=None, limits=None):
    gate = tx.NativeDataGate(backend.root / "recovery", backend.root / "runtime", native_classes=CLASSES, clock=clock)
    try:
        engine = tx.Engine(gate, backend, limits, native_classes=CLASSES)
    except BaseException:
        gate.close()
        raise
    return gate, engine


@pytest.mark.parametrize("classes", [["user-documents"], ("user-documents",), ("user-documents", "user-documents"), (None,)])
def test_native_contracts_must_cover_exact_trusted_components(native_backend, classes):
    gate = native_backend.gate()
    try:
        with pytest.raises(g.RecoveryError, match="exactly cover"):
            tx.Engine(gate, native_backend, native_classes=classes)
    finally:
        gate.close()


def test_native_fields_cannot_enable_b1_engine(native_backend):
    gate = native_backend.gate()
    engine = tx.Engine(gate, native_backend)
    try:
        with pytest.raises(g.RecoveryError, match="extra fields"):
            engine._validate_plan({"native_metadata": {}})
    finally:
        engine.close()
        gate.close()


def test_native_engine_requires_explicit_gate(native_backend):
    gate = native_backend.gate()
    try:
        with pytest.raises(g.RecoveryError, match="explicit matching"):
            tx.Engine(gate, native_backend, native_classes=CLASSES)
    finally:
        gate.close()


def test_native_gate_requires_explicit_engine(native_backend):
    gate, engine = engine_for(native_backend)
    try:
        with pytest.raises(g.RecoveryError, match="explicit matching"):
            tx.Engine(gate, native_backend)
    finally:
        engine.close()
        gate.close()


@ROOT_ONLY
@pytest.mark.parametrize("outcome", ["commit", "rollback", "recover"])
def test_native_generation_metadata_survives_journal_and_rename(native_backend, outcome):
    backend = native_backend
    before = {key: (parent / "active").stat() for key, parent in backend.components().items()}
    gate, engine = engine_for(backend)
    try:
        plan = engine.make_plan()
        assert plan["version"] == 2 and plan["kind"] == "native-data-components"
        assert plan["native_metadata"]["user-documents"]["gid"] == 42001
        identifier = engine.begin(plan)
        engine.quiesce()
        engine.prepare()
        engine.publish()
        if outcome == "commit":
            engine.validate()
            engine.commit()
            engine.release()
        elif outcome == "rollback":
            engine.rollback()
            engine.release()
    finally:
        engine.close()
        gate.close()
    if outcome == "recover":
        gate, engine = engine_for(backend)
        try:
            assert engine.recover(identifier) == "rolled_back"
            engine.release()
        finally:
            engine.close()
            gate.close()
    for key, parent in backend.components().items():
        active = (parent / "active").stat()
        if outcome == "commit":
            assert active.st_uid == 0 and active.st_gid == 42001
            assert (parent / "active/payload").read_bytes() == ("incoming" + key).encode()
        else:
            assert (active.st_uid, active.st_gid, active.st_mode, active.st_ino) == (
                before[key].st_uid, before[key].st_gid, before[key].st_mode, before[key].st_ino)
            assert (parent / "active/payload").read_bytes() == ("active" + key).encode()
    # Retained native history is not authority to broaden an ordinary B1 gate.
    gate = backend.gate()
    try:
        with pytest.raises(g.RecoveryError, match="invalid retained plan"):
            gate.require_open()
    finally:
        gate.close()


@ROOT_ONLY
@pytest.mark.parametrize("change", ["uid", "gid", "mode", "label"])
def test_forged_plan_cannot_authorize_incoming_metadata(native_backend, local_policy, change):
    gate, engine = engine_for(native_backend)
    try:
        plan = engine.make_plan()
        payload = native_backend.components()[CLASSES[0]] / "incoming/payload"
        if change == "uid":
            os.chown(payload, 42002, 42001)
        elif change == "gid":
            os.chown(payload, 0, 42002)
        elif change == "mode":
            payload.chmod(0o666)
        else:
            value = payload.stat()
            local_policy[1][(value.st_dev, value.st_ino)] = b"system_u:object_r:wrong_t:s0\0"
        # Recompute a content fingerprint without an incoming classification:
        # even a matching attacker-supplied hash cannot waive the local policy.
        engine.deadline = g.Deadline(gate.clock, engine.limits.seconds)
        parent = engine.components[CLASSES[0]]
        plan["components"][CLASSES[0]]["new"] = engine._fingerprint(parent.fd, "incoming")
        with pytest.raises(g.RecoveryError, match="installed target metadata"):
            engine.begin(plan)
        assert gate.state()["transaction"] is None
    finally:
        engine.close()
        gate.close()


@ROOT_ONLY
@pytest.mark.parametrize("suffix,allowed", [(b"", True), (b"\0", True), (b"\0\0", False)])
def test_native_label_matches_whole_context_without_trimming(native_backend, local_policy, suffix, allowed):
    payload = native_backend.components()[CLASSES[0]] / "incoming/payload"
    value = payload.stat()
    local_policy[1][(value.st_dev, value.st_ino)] = CONTEXT.encode() + suffix
    gate, engine = engine_for(native_backend)
    try:
        if allowed:
            assert engine.make_plan()["version"] == 2
        else:
            with pytest.raises(g.RecoveryError, match="installed target metadata"):
                engine.make_plan()
    finally:
        engine.close()
        gate.close()


@ROOT_ONLY
def test_changed_old_metadata_prevents_publication(native_backend):
    gate, engine = engine_for(native_backend)
    try:
        plan = engine.make_plan()
        old = native_backend.components()[CLASSES[0]] / "active"
        old.chmod(0o2750)
        with pytest.raises(g.RecoveryError, match="changed since plan review"):
            engine.begin(plan)
        assert gate.state()["transaction"] is None
    finally:
        engine.close()
        gate.close()


@ROOT_ONLY
def test_empty_siblings_stop_metadata_lookups_after_deadline(native_backend, monkeypatch):
    parent = native_backend.components()[CLASSES[0]] / "incoming"
    for index in range(20):
        item = parent / f"zero-{index:02}"
        item.touch(mode=0o640)
        os.chown(item, 0, 42001)
    clock = FixtureClock()
    clock.boot = json.loads((native_backend.root / "runtime/ready.json").read_text())["boot"]
    seen = []

    def context(path, _directory, _check=None):
        if path.name.startswith("zero-"):
            seen.append(path.name)
            clock.now += 2_000_000_000
        return CONTEXT

    monkeypatch.setattr(tx.native_metadata, "_target_context", context)
    gate, engine = engine_for(native_backend, clock=clock, limits=tx.Limits(seconds=1))
    try:
        with pytest.raises(g.RecoveryError, match="deadline expired"):
            engine.make_plan()
        assert seen == ["zero-00"]
        assert gate.state()["transaction"] is None
    finally:
        engine.close()
        gate.close()


@ROOT_ONLY
@pytest.mark.parametrize("change", ["group", "inventory", "plan"])
def test_native_contract_is_bound_to_plan_and_rechecked(native_backend, local_policy, monkeypatch, change):
    gate, engine = engine_for(native_backend)
    try:
        plan = engine.make_plan()
        if change == "group":
            monkeypatch.setattr(tx.native_metadata.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=42003))
        elif change == "inventory":
            local_policy[0]["description"] = "different installed policy"
        else:
            plan = copy.deepcopy(plan)
            plan["native_metadata"][CLASSES[0]]["gid"] = 42003
        with pytest.raises((g.RecoveryError, tx.native_metadata.Error)):
            engine.begin(plan)
        assert gate.state()["transaction"] is None
    finally:
        engine.close()
        gate.close()

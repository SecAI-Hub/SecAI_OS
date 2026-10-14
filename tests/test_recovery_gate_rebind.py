"""Trusted gate rebind with simulated mount IDs; no native boot qualification."""

import copy
import os
from pathlib import Path

import pytest

from test_backup_boot_rebind import prepared
from test_backup_transaction import FixtureClock, g, make_fixture, tx


def remount_fixture(monkeypatch, backend):
    original = g.mount_id
    prefix = str(backend.root) + "/"
    change = {"offset": 10000}

    def changed(fd):
        path = os.readlink(f"/proc/self/fd/{fd}")
        return original(fd) + (change["offset"] if path.startswith(prefix) else 0)

    monkeypatch.setattr(g, "mount_id", changed)
    return change


def test_trusted_gate_and_component_rebind_recover_without_reinitializing(tmp_path, monkeypatch):
    clock, backend, identifier, plan = prepared(tmp_path)
    root = backend.root / "recovery"
    runtime = backend.root / "runtime"
    layout = (root / "layout.json").read_bytes()
    (runtime / "ready.json").unlink()
    clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_fixture(monkeypatch, backend)
    approvals = []

    with pytest.raises(g.RecoveryError, match="layout binding"):
        g.Gate(root, runtime, clock=clock)

    def approve_gate(old, current):
        approvals.append((copy.deepcopy(old), copy.deepcopy(current)))
        return True

    monkeypatch.setattr(backend, "permit_boot_rebind", lambda *_args: True)
    gate = g.Gate(root, runtime, clock=clock, trusted_root_rebind=approve_gate)
    engine = tx.Engine(gate, backend)
    try:
        assert len(approvals) == 1 and approvals[0][0]["mount"] != approvals[0][1]["mount"]
        assert approvals[0][0] == g.strict_json(layout, 4096)["root"]
        assert (root / "layout.json").read_bytes() == layout
        assert not list(runtime.iterdir())
        with pytest.raises((g.RecoveryError, OSError)):
            gate.lease()
        assert engine.recover(identifier) == "rolled_back"
        assert engine.plan["mapping"] == plan["mapping"]
        engine.release()
        gate.require_open()
        assert (root / "layout.json").read_bytes() == layout
    finally:
        engine.close()
        gate.close()
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}


def rebound_gate_case(tmp_path, monkeypatch):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    root, runtime = backend.root / "recovery", backend.root / "runtime"
    (runtime / "ready.json").unlink()
    clock.boot = "22222222-2222-4222-8222-222222222222"
    change = remount_fixture(monkeypatch, backend)
    return clock, root, runtime, change


def descriptor_count():
    return len(os.listdir("/proc/self/fd"))


@pytest.mark.parametrize("approval", [False, 1, {}, None])
def test_rebind_requires_literal_true_and_closes_descriptors(tmp_path, monkeypatch, approval):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    layout = (root / "layout.json").read_bytes()
    count = descriptor_count()
    with pytest.raises(g.RecoveryError, match="rebind denied"):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=lambda *_args: approval)
    assert descriptor_count() == count
    assert (root / "layout.json").read_bytes() == layout and not list(runtime.iterdir())


def test_missing_or_noncallable_capability_never_accepts_new_mount(tmp_path, monkeypatch):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    count = descriptor_count()
    with pytest.raises(g.RecoveryError, match="trusted root rebind required"):
        g.Gate(root, runtime, clock=clock)
    with pytest.raises(g.RecoveryError, match="capability"):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=True)
    assert descriptor_count() == count


@pytest.mark.parametrize("field", ["device", "inode", "mode", "uid", "gid"])
def test_persistent_root_identity_change_never_reaches_callback(tmp_path, monkeypatch, field):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    layout = g.strict_json((root / "layout.json").read_bytes(), 4096)
    layout["root"][field] += 1
    (root / "layout.json").write_bytes(g.encode(layout))
    calls = []
    count = descriptor_count()
    with pytest.raises(g.RecoveryError, match="layout binding"):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=lambda *_args: calls.append(True) or True)
    assert calls == [] and descriptor_count() == count


@pytest.mark.parametrize("section,field,value", [
    ("root", "mount", True), ("root", "uid", False), ("root", "device", "1"),
    ("root", "inode", -1), ("root", "mode", 2**64),
    ("admission", "uid", False), ("operation", "mode", "0600"),
    ("admission", "mount", 1), ("root", "unknown", 1),
])
def test_malformed_layout_identity_never_reaches_callback(tmp_path, monkeypatch, section, field, value):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    layout = g.strict_json((root / "layout.json").read_bytes(), 4096)
    layout[section][field] = value
    (root / "layout.json").write_bytes(g.encode(layout))
    calls = []
    count = descriptor_count()
    with pytest.raises(g.RecoveryError, match="layout identity"):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=lambda *_args: calls.append(True) or True)
    assert calls == [] and descriptor_count() == count


@pytest.mark.parametrize("damage", ["lock", "namespace"])
def test_complete_gate_preflight_precedes_rebind_approval(tmp_path, monkeypatch, damage):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    if damage == "lock":
        layout = g.strict_json((root / "layout.json").read_bytes(), 4096)
        layout["admission"]["inode"] += 1
        (root / "layout.json").write_bytes(g.encode(layout))
    else:
        (root / "unexpected").write_bytes(b"preserve")
    calls = []
    count = descriptor_count()
    with pytest.raises(g.RecoveryError):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=lambda *_args: calls.append(True) or True)
    assert calls == [] and descriptor_count() == count


def test_callback_cannot_mutate_historical_or_session_identity(tmp_path, monkeypatch):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    layout = (root / "layout.json").read_bytes()

    def approve(old, current):
        old.clear()
        current.clear()
        return True

    gate = g.Gate(root, runtime, clock=clock, trusted_root_rebind=approve)
    try:
        gate.check(allow_pending=True)
        assert gate.layout == g.strict_json(layout, 4096)
        assert gate.root.identity["inode"] == root.stat().st_ino
        assert (root / "layout.json").read_bytes() == layout
        with pytest.raises((g.RecoveryError, OSError)):
            gate.lease()
    finally:
        gate.close()


@pytest.mark.parametrize("change", ["root-path", "root-mode", "mount", "layout-bytes", "layout-semantic", "lock-replacement"])
def test_changes_during_callback_fail_closed_and_close_descriptors(tmp_path, monkeypatch, change):
    clock, root, runtime, mounts = rebound_gate_case(tmp_path, monkeypatch)
    count = descriptor_count()

    def approve(_old, _current):
        if change == "root-path":
            root.rename(root.with_name("original-recovery"))
            root.mkdir(mode=0o700)
        elif change == "root-mode":
            root.chmod(0o750)
        elif change == "mount":
            mounts["offset"] += 10000
        elif change == "layout-bytes":
            with (root / "layout.json").open("ab") as stream:
                stream.write(b" ")
        elif change == "lock-replacement":
            (root / "admission.lock").rename(root.parent / "retained-admission.lock")
            (root / "admission.lock").write_bytes(b"stable\n")
            (root / "admission.lock").chmod(0o600)
        else:
            layout = g.strict_json((root / "layout.json").read_bytes(), 4096)
            layout["root"]["mount"] += 1
            (root / "layout.json").write_bytes(g.encode(layout))
        return True

    with pytest.raises(g.RecoveryError):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=approve)
    assert descriptor_count() == count
    assert not list(runtime.iterdir())


@pytest.mark.parametrize("failure", ["expiry", "exception"])
def test_callback_failure_keeps_runtime_empty_and_closes_descriptors(tmp_path, monkeypatch, failure):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    count = descriptor_count()

    def approve(*_args):
        if failure == "exception":
            raise OSError("synthetic trusted backend failure")
        clock.now += 6 * 1_000_000_000
        return True

    with pytest.raises((g.RecoveryError, OSError)):
        g.Gate(root, runtime, clock=clock, trusted_root_rebind=approve)
    assert descriptor_count() == count and not list(runtime.iterdir())


@pytest.mark.parametrize("change", ["mount", "root-path", "layout-bytes"])
def test_session_checks_stay_strict_after_approval(tmp_path, monkeypatch, change):
    clock, root, runtime, mounts = rebound_gate_case(tmp_path, monkeypatch)
    gate = g.Gate(root, runtime, clock=clock, trusted_root_rebind=lambda *_args: True)
    try:
        if change == "mount":
            mounts["offset"] += 10000
        elif change == "root-path":
            root.rename(root.with_name("original-recovery"))
            root.mkdir(mode=0o700)
        else:
            with (root / "layout.json").open("ab") as stream:
                stream.write(b" ")
        with pytest.raises(g.RecoveryError):
            gate.check(allow_pending=True)
    finally:
        gate.close()


def test_unchanged_root_needs_no_callback_and_preserves_normal_b1_admission(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    calls = []
    gate = g.Gate(backend.root / "recovery", backend.root / "runtime", clock=clock,
                  trusted_root_rebind=lambda *_args: calls.append(True) or False)
    try:
        gate.require_open()
        lease = gate.lease()
        lease.close()
        assert calls == []
    finally:
        gate.close()


def test_native_data_gate_forwards_trusted_root_capability(tmp_path, monkeypatch):
    clock, root, runtime, _change = rebound_gate_case(tmp_path, monkeypatch)
    policy = tx.native_metadata.IncomingPolicy(
        "user-documents", Path("/var/lib/secure-ai/vault/user_docs"),
        "secure-ai-vault-read", 32001, 0o2750, "0" * 64)
    monkeypatch.setattr(tx.native_metadata, "installed_incoming_policy", lambda _key: policy)
    calls = []
    gate = tx.NativeDataGate(root, runtime, clock=clock, native_classes=("user-documents",),
                             trusted_root_rebind=lambda *_args: calls.append(True) or True)
    try:
        gate.check(allow_pending=True)
        assert calls == [True]
        assert gate.metadata_contract()["user-documents"]["gid"] == 32001
        assert not list(runtime.iterdir())
    finally:
        gate.close()

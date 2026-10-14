"""Journal recovery with simulated reboot mount IDs; no native boot claim."""

import copy
import os

import pytest

from test_backup_transaction import FixtureClock, g, make_fixture, tx


def prepared(tmp_path, *, committed=False):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        plan = engine.make_plan()
        identifier = engine.begin(plan)
        engine.quiesce()
        engine.prepare()
        engine.publish()
        if committed:
            engine.validate()
            engine.commit()
    finally:
        engine.close()
        gate.close()
    return clock, backend, identifier, plan


def remount_components(monkeypatch, backend):
    original = g.mount_id
    roots = tuple(str(path) + "/" for path in backend.components().values())

    def changed(fd):
        path = os.readlink(f"/proc/self/fd/{fd}")
        return original(fd) + (10000 if any(path + "/" == root or path.startswith(root)
                                          for root in roots) else 0)

    monkeypatch.setattr(g, "mount_id", changed)


@pytest.mark.parametrize("committed", [False, True])
def test_new_boot_mount_rebind_recovers_only_after_explicit_approval(tmp_path, monkeypatch, committed):
    clock, backend, identifier, plan = prepared(tmp_path, committed=committed)
    clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_components(monkeypatch, backend)
    approvals = []

    def approve(old, current):
        approvals.append((copy.deepcopy(old), copy.deepcopy(current)))
        return True

    monkeypatch.setattr(backend, "permit_boot_rebind", approve)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        expected = "committed" if committed else "rolled_back"
        assert engine.recover(identifier) == expected
        assert approvals == [(plan["mapping"], engine.mapping)]
        assert any(old["mount"] != engine.mapping[key]["mount"] for key, old in plan["mapping"].items())
        engine.release()
        gate.require_open()
    finally:
        engine.close()
        gate.close()
    prefix = b"new-" if committed else b"old-"
    assert backend.active() == {key: prefix + key.encode() for key in backend.COMPONENTS}


@pytest.mark.parametrize("new_boot,approval", [(False, True), (True, False), (True, 1)])
def test_remount_requires_new_boot_and_literal_backend_approval(tmp_path, monkeypatch, new_boot, approval):
    clock, backend, identifier, _plan = prepared(tmp_path)
    if new_boot:
        clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_components(monkeypatch, backend)
    calls = []
    monkeypatch.setattr(backend, "permit_boot_rebind", lambda *_args: calls.append(True) or approval)
    backend.stopped = False
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError):
            engine.recover(identifier)
        assert backend.stopped is False
        assert bool(calls) is new_boot
        assert gate.state(recovery=True)["state"] == "closed"
    finally:
        engine.close()
        gate.close()


def test_fresh_plan_cannot_request_mount_rebind(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        plan = engine.make_plan()
        plan["mapping"]["documents"]["mount"] += 10000
        with pytest.raises(g.RecoveryError, match="trusted code component mapping"):
            engine.begin(plan)
        assert gate.state()["state"] == "open"
    finally:
        engine.close()
        gate.close()


def test_rebind_callback_cannot_mutate_the_verified_plan_or_current_binding(tmp_path, monkeypatch):
    clock, backend, identifier, plan = prepared(tmp_path)
    clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_components(monkeypatch, backend)

    def approve(old, current):
        old.clear()
        current.clear()
        return True

    monkeypatch.setattr(backend, "permit_boot_rebind", approve)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        current = copy.deepcopy(engine.mapping)
        assert engine.recover(identifier) == "rolled_back"
        assert engine.mapping == current
        assert engine.plan["mapping"] == plan["mapping"]
        engine.release()
    finally:
        engine.close()
        gate.close()


def test_rebind_callback_deadline_expiry_keeps_admission_closed(tmp_path, monkeypatch):
    clock, backend, identifier, _plan = prepared(tmp_path)
    clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_components(monkeypatch, backend)

    def approve(*_args):
        clock.now += 3601 * 1_000_000_000
        return True

    monkeypatch.setattr(backend, "permit_boot_rebind", approve)
    backend.stopped = False
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError, match="deadline expired"):
            engine.recover(identifier)
        assert backend.stopped is False
        assert gate.state(recovery=True)["state"] == "closed"
    finally:
        engine.close()
        gate.close()


@pytest.mark.parametrize("field", ["device", "inode", "mode", "uid", "gid", "mount"])
def test_replay_validation_rejects_persistent_identity_changes_and_invalid_types(tmp_path, field):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        plan = engine.make_plan()
        plan["mapping"]["documents"][field] = (
            True if field == "mount" else plan["mapping"]["documents"][field] + 1)
        with pytest.raises(g.RecoveryError):
            engine._validate_plan(plan, allow_mount_rebind=True)
        assert gate.state()["state"] == "open"
    finally:
        engine.close()
        gate.close()


def test_corrupt_journal_is_rejected_before_trusted_rebind_callback(tmp_path, monkeypatch):
    clock, backend, identifier, _plan = prepared(tmp_path)
    clock.boot = "22222222-2222-4222-8222-222222222222"
    remount_components(monkeypatch, backend)
    head = backend.root / "recovery/transactions" / identifier / "head.json"
    value = g.strict_json(head.read_bytes(), 1024 * 1024)
    value["sha256"] = "0" * 64
    head.write_bytes(g.encode(value))
    calls = []
    monkeypatch.setattr(backend, "permit_boot_rebind", lambda *_args: calls.append(True) or True)
    backend.stopped = False
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError, match="corrupt journal head"):
            engine.recover(identifier)
        assert calls == [] and backend.stopped is False
        assert head.read_bytes() == g.encode(value)
        assert gate.state(recovery=True)["state"] == "closed"
    finally:
        engine.close()
        gate.close()

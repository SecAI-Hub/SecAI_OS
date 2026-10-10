"""Cross-process session authority and durable snapshot failure boundaries."""
import errno
import hashlib
import json
import multiprocessing
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))

from common import auth as auth_module
from common.auth import AuthManager
from common.bounded_state import BoundedState, StateCapacity, StateRejected, StateUnavailable
from common.session_store import token_digest


@pytest.fixture
def managers(tmp_path, monkeypatch):
    # KDF behavior has independent real scrypt tests; exercise concurrency cheaply.
    def hashed(value, salt=None):
        return {"salt": "a" * 64, "hash": hashlib.sha512(value.encode()).hexdigest(), "params": {"n": auth_module.SCRYPT_N}}
    monkeypatch.setattr(auth_module, "hash_passphrase", hashed)
    monkeypatch.setattr(auth_module, "verify_passphrase", lambda value, saved: hashed(value)["hash"] == saved["hash"])
    directory = tmp_path / "auth"
    runtime = tmp_path / "runtime"
    def create(**kwargs):
        return AuthManager(str(directory), runtime_dir=str(runtime), **kwargs)
    first = create()
    assert first.setup_passphrase("synthetic-passphrase-one")
    return first, create, directory, runtime


def test_recycling_sessions_private_and_revoked_across_instances(managers):
    first, create, directory, _ = managers
    token = first.login("synthetic-passphrase-one")["token"]
    second = create()
    assert second.validate_session(token, refresh=False)
    assert not second.validate_session(token_digest(token))  # stored hash is not a bearer.
    assert token.encode() not in (directory / "sessions.json").read_bytes()
    assert token_digest(token) in (directory / "sessions.json").read_text()
    second.logout(token)
    assert not first.validate_session(token)
    token = first.login("synthetic-passphrase-one")["token"]
    assert second.change_passphrase("synthetic-passphrase-one", "synthetic-passphrase-two")["success"]
    assert not first.validate_session(token)


def test_runtime_recreation_invalidates_restored_authority(managers):
    first, create, _, runtime = managers
    token = first.login("synthetic-passphrase-one")["token"]
    (runtime / "epoch.json").unlink()
    assert not create().validate_session(token)
    with pytest.raises(StateUnavailable):
        first.validate_session(token)


def test_passive_activity_and_absolute_expiry(managers, monkeypatch):
    _first, create, _, _ = managers
    now = [100.0]
    monkeypatch.setattr(auth_module.runtime_clock, "now", lambda: now[0])
    manager = create(session_timeout=30, absolute_timeout=60)
    token = manager.login("synthetic-passphrase-one")["token"]
    now[0] = 129
    assert manager.validate_session(token, refresh=False)
    now[0] = 131
    assert not manager.validate_session(token, refresh=False)
    now[0] = 200
    token = manager.login("synthetic-passphrase-one")["token"]
    for current in (220, 240, 259):
        now[0] = current
        assert manager.validate_session(token)
    now[0] = 261
    assert not manager.validate_session(token)


def test_suspend_clock_controls_session_and_lockout_despite_wall_reversal(managers, monkeypatch):
    _first, create, _, _ = managers
    clock = [100.0]
    monkeypatch.setattr(auth_module.runtime_clock, "now", lambda: clock[0])
    manager = create(session_timeout=86400, absolute_timeout=60, max_attempts=1, lockout_duration=60)
    token = manager.login("synthetic-passphrase-one")["token"]
    assert not manager.login("wrong-passphrase")["success"]
    assert not manager.login("synthetic-passphrase-one")["success"]
    monkeypatch.setattr(auth_module.time, "time", lambda: 1.0)
    clock[0] = 161.0  # Simulated suspend-inclusive advance, no host suspension.
    assert not manager.validate_session(token, refresh=False)
    assert manager.login("synthetic-passphrase-one")["success"]


def test_login_cannot_publish_old_credential_after_concurrent_change(managers, monkeypatch):
    first, create, _, _ = managers
    other = create()
    original = auth_module.verify_passphrase
    changed = []
    def verify(value, saved):
        result = original(value, saved)
        if not changed:
            changed.append(True)
            assert other.change_passphrase("synthetic-passphrase-one", "synthetic-passphrase-two")["success"]
        return result
    monkeypatch.setattr(auth_module, "verify_passphrase", verify)
    assert first.login("synthetic-passphrase-one")["success"] is False


def state_file(tmp_path):
    def validate(value):
        if not isinstance(value, dict) or set(value) != {"value"} or type(value["value"]) is not int:
            raise ValueError("invalid state")
    return BoundedState(tmp_path / "private" / "state.json", lambda: {"value": 0}, validate, max_bytes=128)


@pytest.mark.parametrize("fault", ["short", "space", "sync"])
def test_snapshot_failures_latch_without_republishing_old_state(tmp_path, monkeypatch, fault):
    store = state_file(tmp_path)
    with store.transaction(write=True) as value:
        value["value"] = 1
    original_write = os.write
    original_sync = os.fsync
    def write(fd, raw):
        if fault == "space":
            raise OSError(errno.ENOSPC, "synthetic disk full")
        return original_write(fd, raw[:1] if fault == "short" else raw)
    def sync(fd):
        if fault == "sync" and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "synthetic directory sync failure")
        return original_sync(fd)
    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(StateUnavailable):
        with store.transaction(write=True) as value:
            value["value"] = 2
    with pytest.raises(StateUnavailable):
        with store.transaction():
            pass
    monkeypatch.undo()
    # A different live/restarted process observes the same persistent fence.
    with pytest.raises(StateUnavailable):
        with state_file(tmp_path).transaction():
            pass
    assert store.path.with_name("state.json.pending").exists()


def test_capacity_does_not_destroy_existing_state(tmp_path):
    store = state_file(tmp_path)
    with store.transaction(write=True) as value:
        value["value"] = 1
    with pytest.raises(StateCapacity):
        with store.transaction(write=True) as value:
            value["value"] = 10 ** 150
    with store.transaction() as value:
        assert value["value"] == 1


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "malformed", "duplicate", "oversized"])
def test_unsafe_existing_state_is_not_adopted(tmp_path, kind):
    store = state_file(tmp_path)
    with store.transaction(write=True):
        pass
    path = store.path
    if kind == "symlink":
        old = path.with_name("old")
        path.rename(old)
        path.symlink_to(old)
    elif kind == "hardlink":
        os.link(path, path.with_name("extra"))
    else:
        path.write_text({"malformed": "broken", "duplicate": '{"value":1,"value":2}', "oversized": " " * 129}[kind])
    with pytest.raises(StateUnavailable):
        with store.transaction():
            pass


def test_lock_path_replacement_rejected_before_publish(tmp_path):
    store = state_file(tmp_path)
    with store.transaction(write=True):
        pass
    with pytest.raises(StateUnavailable):
        with store.transaction(write=True) as value:
            lock = store.path.with_name(store.path.name + ".lock")
            lock.rename(lock.with_suffix(".old"))
            lock.write_text("")
            lock.chmod(0o660)
            value["value"] = 9
    assert json.loads(store.path.read_text())["value"] == 0


def test_unexpected_error_after_external_publication_keeps_fence(tmp_path):
    store = state_file(tmp_path)
    with store.transaction(write=True):
        pass
    with pytest.raises(StateUnavailable):
        with store.transaction(write=True):
            (tmp_path / "synthetic-credential").write_text("published-generation-two")
            raise RuntimeError("unexpected post-publication error")
    with pytest.raises(StateUnavailable):
        with state_file(tmp_path).transaction():
            pass
    assert (tmp_path / "synthetic-credential").read_text() == "published-generation-two"


def test_explicit_prepublication_rejection_keeps_store_available(tmp_path):
    store = state_file(tmp_path)
    with store.transaction(write=True):
        pass
    with pytest.raises(StateRejected):
        with store.transaction(write=True):
            raise StateRejected("prepublication admission conflict")
    with state_file(tmp_path).transaction() as state:
        assert state["value"] == 0


def _crash_at_boundary(directory, boundary):
    store = state_file(Path(directory))
    original_open, original_sync = os.open, os.fsync
    original_replace, original_unlink = os.replace, os.unlink
    syncs = 0
    def opened(path, *args, **kwargs):
        pending = str(path).endswith("state.json.pending")
        if pending and boundary == "before_fence":
            os._exit(0)
        fd = original_open(path, *args, **kwargs)
        if pending and boundary == "fence_created":
            os._exit(0)
        return fd
    def synced(fd):
        nonlocal syncs
        original_sync(fd)
        syncs += 1
        stages = {1: "fence_file_synced", 2: "fence_directory_synced", 3: "target_file_synced",
                  4: "target_directory_synced", 5: "fence_removal_synced"}
        if boundary == stages[syncs]:
            os._exit(0)
    def replaced(*args, **kwargs):
        original_replace(*args, **kwargs)
        if boundary == "target_replaced":
            os._exit(0)
    def unlinked(path, *args, **kwargs):
        original_unlink(path, *args, **kwargs)
        if str(path).endswith("state.json.pending") and boundary == "fence_removed":
            os._exit(0)
    os.open, os.fsync, os.replace, os.unlink = opened, synced, replaced, unlinked
    with store.transaction(write=True) as state:
        state["value"] = 2
    os._exit(2)  # Requested boundary must actually have been reached.


@pytest.mark.parametrize("boundary", ["before_fence", "fence_created", "fence_file_synced", "fence_directory_synced",
                                      "target_file_synced", "target_replaced", "target_directory_synced",
                                      "fence_removed", "fence_removal_synced"])
def test_killed_writer_boundary_matrix_existing_peer_and_reopen(tmp_path, boundary):
    store = state_file(tmp_path)
    with store.transaction(write=True) as state:
        state["value"] = 1
    child = multiprocessing.get_context("spawn").Process(target=_crash_at_boundary, args=(str(tmp_path), boundary))
    child.start()
    try:
        child.join(5)
        assert child.exitcode == 0
    finally:
        if child.is_alive():
            child.kill()
        child.join(5)
        assert not child.is_alive()
    committed = boundary in {"target_replaced", "target_directory_synced", "fence_removed", "fence_removal_synced"}
    assert json.loads(store.path.read_text())["value"] == (2 if committed else 1)
    fenced = boundary not in {"before_fence", "fence_removed", "fence_removal_synced"}
    for peer in (store, state_file(tmp_path)):
        if fenced:
            with pytest.raises(StateUnavailable):
                with peer.transaction():
                    pass
        else:
            with peer.transaction() as state:
                assert state["value"] == (2 if committed else 1)


def test_crash_boundary_from_threaded_caller_without_fork(tmp_path, monkeypatch):
    release = threading.Event()
    thread = threading.Thread(target=release.wait, daemon=True)
    thread.start()
    try:
        def forbidden_fork():
            pytest.fail("session crash fixtures must not fork their threaded caller")
        monkeypatch.setattr(os, "fork", forbidden_fork)
        test_killed_writer_boundary_matrix_existing_peer_and_reopen(tmp_path, "target_replaced")
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(5)
        assert not thread.is_alive()

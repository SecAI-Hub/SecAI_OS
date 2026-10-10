"""B1's only concrete backend: two private inert fixture components."""

from __future__ import annotations

import importlib.util
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "files/system/usr/libexec/secure-ai/secure-recovery-transaction.py"
SPEC = importlib.util.spec_from_file_location("recovery_transaction_test", HELPER)
assert SPEC and SPEC.loader
tx = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tx)
g = tx.guard
_CHILDREN: dict[int, tuple[int, int]] = {}
_FIXTURE_CHILD = None
_PARENT_GROUP = None
_FORK_RUNNER_PID = None


def signal_evidence(event):
    destination = os.environ.get("SECAI_B1_SIGNAL_REPORT")
    if destination:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, (json.dumps(event, separators=(",", ":")) + "\n").encode())
        finally:
            os.close(descriptor)


def private_fork():
    """Every fault child gets a distinct session; parent owns a stable pidfd."""
    global _FIXTURE_CHILD, _PARENT_GROUP
    assert os.getpid() == _FORK_RUNNER_PID, "fork requires the clean B1 fixture interpreter"
    assert threading.active_count() == 1 and len(os.listdir("/proc/self/task")) == 1, "fork requires one thread"
    assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
    reader, writer = os.pipe()
    parent_group = os.getpgrp()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            for descriptor, _owner in _CHILDREN.values():
                os.close(descriptor)
            _CHILDREN.clear()
            os.setsid()
            _FIXTURE_CHILD, _PARENT_GROUP = os.getpid(), parent_group
            assert os.getpgrp() == _FIXTURE_CHILD and os.getpgrp() != parent_group
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(15)
            os.write(writer, b"private-session")
            os.close(writer)
            return 0
        except BaseException:
            os._exit(97)
    os.close(writer)
    descriptor = os.pidfd_open(pid)
    _CHILDREN[pid] = (descriptor, os.getpid())
    try:
        assert select.select([reader], [], [], 3)[0], "fixture session handshake timed out"
        assert os.read(reader, 32) == b"private-session"
        assert os.getpgid(pid) == pid and os.getpgid(pid) != parent_group
    except BaseException:
        try:
            signal_child(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            wait_child(pid, 3)
        raise
    finally:
        os.close(reader)
    return pid


def owns_child(pid):
    return pid in _CHILDREN and _CHILDREN[pid][1] == os.getpid()


def signal_child(pid, sig):
    assert type(pid) is int and pid > 0 and pid != os.getpid() and owns_child(pid)
    descriptor, _owner = _CHILDREN[pid]
    signal_evidence({"kind": "owned-pidfd", "sender_pid": os.getpid(), "sender_pgid": os.getpgrp(),
                     "target_pid": pid, "verified_child_pgid": pid, "signal": int(sig)})
    signal.pidfd_send_signal(descriptor, sig, None, 0)


def child_alive(pid):
    if not owns_child(pid):
        return False
    return not select.select([_CHILDREN[pid][0]], [], [], 0)[0]


def kill_fixture_self():
    assert os.getpid() == _FIXTURE_CHILD
    assert os.getpgrp() == os.getpid() and os.getpgrp() != _PARENT_GROUP
    signal_evidence({"kind": "private-child-self", "sender_pid": os.getpid(), "sender_pgid": os.getpgrp(),
                     "target_pid": os.getpid(), "parent_pgid": _PARENT_GROUP, "signal": int(signal.SIGKILL)})
    os.kill(os.getpid(), signal.SIGKILL)


class FixtureClock:
    domain = g.DOMAIN

    def __init__(self):
        self.boot = "11111111-1111-4111-8111-111111111111"
        self.now = 1_000_000_000

    def boot_id(self):
        return self.boot

    def now_ns(self):
        return self.now


class FixtureBackend:
    """Never installed: trusted test code binds names to its private roots."""

    COMPONENTS = {"documents": "documents-parent", "outputs": "outputs-parent"}

    def __init__(self, root: Path):
        self.root = root
        self.stopped = False
        self.allow_rebind = False

    def components(self):
        return {name: self.root / directory for name, directory in self.COMPONENTS.items()}

    def stop_writers(self, deadline):
        deadline.check()
        self.stopped = True

    def quiescent(self):
        return self.stopped

    def permit_boot_rebind(self, old_mapping, current_mapping):
        return self.allow_rebind and old_mapping == current_mapping

    def gate(self, clock=None, hook=None):
        return g.Gate(self.root / "recovery", self.root / "runtime", clock=clock, io=g.DurableIO(hook))

    def active(self):
        return {name: (directory / "active/payload").read_bytes() if (directory / "active/payload").exists() else None
                for name, directory in self.components().items()}


def make_fixture(root: Path, clock=None) -> FixtureBackend:
    root.mkdir(mode=0o700)
    for name in ("recovery", "runtime", *FixtureBackend.COMPONENTS.values()):
        (root / name).mkdir(mode=0o700)
    backend = FixtureBackend(root)
    for name, directory in backend.components().items():
        for generation in ("active", "incoming"):
            tree = directory / generation
            tree.mkdir(mode=0o700)
            (tree / "empty directory").mkdir(mode=0o700)
            payload = tree / "payload"
            payload.write_bytes(("old-" if generation == "active" else "new-").encode() + name.encode())
            payload.chmod(0o600)
    g.Gate.initialize(root / "recovery", root / "runtime", clock=clock)
    return backend


@pytest.fixture
def backend(tmp_path):
    return make_fixture(tmp_path / "fixture")


def run_transaction(backend, *, clock=None, hook=None, release=True):
    gate = backend.gate(clock, hook)
    engine = tx.Engine(gate, backend)
    try:
        plan = engine.make_plan()
        identifier = engine.begin(plan)
        engine.quiesce()
        engine.prepare()
        engine.publish()
        engine.validate()
        engine.commit()
        if release:
            engine.release()
        return identifier
    finally:
        engine.close()
        gate.close()


def wait_child(pid: int, timeout=10):
    assert owns_child(pid), "refuse waiting or signaling an unregistered PID"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed, status = os.waitpid(pid, os.WNOHANG)
        if completed:
            os.close(_CHILDREN.pop(pid)[0])
            return status
        time.sleep(.01)
    signal_child(pid, signal.SIGKILL)
    for _attempt in range(200):
        completed, _status = os.waitpid(pid, os.WNOHANG)
        if completed:
            os.close(_CHILDREN.pop(pid)[0])
            break
        time.sleep(.01)
    raise AssertionError("private fixture child exceeded lifetime")


def cannot_admit(backend, clock=None):
    try:
        gate = backend.gate(clock)
    except (g.RecoveryError, OSError):
        return True
    try:
        try:
            lease = gate.lease()
        except (g.RecoveryError, OSError):
            return True
        lease.close()
        return False
    finally:
        gate.close()


def assert_original_bytes_preserved(backend):
    for name, directory in backend.components().items():
        payloads = [p.read_bytes() for p in directory.rglob("payload")]
        assert b"old-" + name.encode() in payloads
        assert b"new-" + name.encode() in payloads


def test_complete_commit_retains_old_generations_and_releases(backend):
    identifier = run_transaction(backend)
    assert backend.active() == {name: b"new-" + name.encode() for name in backend.COMPONENTS}
    assert not cannot_admit(backend)
    for name, directory in backend.components().items():
        workspace = directory / (".secai-recovery-" + identifier)
        assert (workspace / "old/payload").read_bytes() == b"old-" + name.encode()
        assert (directory / "active/empty directory").is_dir()
    assert_original_bytes_preserved(backend)


def test_rollback_retains_new_generations_and_restores_exact_old(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        engine.publish()
        assert cannot_admit(backend)
        engine.rollback()
        engine.release()
    finally:
        engine.close()
        gate.close()
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
    assert_original_bytes_preserved(backend)
    assert not cannot_admit(backend)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(destination="/etc"),
    lambda p: p.update(command=["/bin/false"]),
    lambda p: p.update(version=True),
    lambda p: p.update(clock_domain="monotonic"),
    lambda p: p["components"].update(unknown=p["components"]["documents"]),
    lambda p: p["components"]["documents"]["new"].update(bytes=True),
    lambda p: p["mapping"]["documents"].update(inode=0),
])
def test_plan_cannot_choose_destinations_commands_or_authority(mutation, backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        plan = engine.make_plan()
        mutation(plan)
        with pytest.raises(g.RecoveryError):
            engine.begin(plan)
        assert not list((backend.root / "recovery/transactions").iterdir())
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend)


@pytest.mark.parametrize("operation", ["initialize", "begin", "publish", "recover", "release"])
def test_production_cli_has_no_native_or_fixture_mutation(operation, tmp_path):
    result = subprocess.run([sys.executable, str(HELPER), operation], capture_output=True, timeout=5)
    assert result.returncode == 1 and b'"native_adapter":false' in result.stderr
    result = subprocess.run([sys.executable, str(HELPER), operation, "--fixture-root", str(tmp_path)], capture_output=True, timeout=5)
    assert result.returncode == 2
    assert not list(tmp_path.iterdir())


def test_no_replace_destination_keeps_unexpected_bytes_and_gate_closed(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    original = gate.io.no_replace
    inserted = False

    def collide(source_fd, source, target_fd, target, event):
        nonlocal inserted
        if event == "publish:new:documents" and not inserted:
            inserted = True
            os.mkdir("active", 0o700, dir_fd=target_fd)
        original(source_fd, source, target_fd, target, event)

    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        gate.io.no_replace = collide
        with pytest.raises(FileExistsError):
            engine.publish()
        assert (backend.components()["documents"] / "active").is_dir()
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)


def test_source_and_lock_replacement_fail_before_publication(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        lock = backend.root / "recovery/operation.lock"
        lock.rename(lock.with_name("old-operation"))
        lock.write_bytes(b"different")
        lock.chmod(0o600)
        with pytest.raises(g.RecoveryError):
            engine.publish()
    finally:
        engine.close()
        gate.close()
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
    assert cannot_admit(backend)


def test_component_parent_replacement_is_not_followed(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        directory = backend.components()["documents"]
        directory.rename(directory.with_name("original"))
        directory.mkdir(mode=0o700)
        with pytest.raises(g.RecoveryError, match="binding changed"):
            engine.prepare()
        assert list(directory.iterdir()) == []
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend)


@pytest.mark.parametrize("fault", ["record-bytes", "record-count", "plan-extra", "unknown-transaction", "unknown-stage"])
def test_corruption_and_unknown_state_remain_closed(fault, backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    identifier = engine.begin(engine.make_plan())
    engine.quiesce()
    engine.prepare()
    engine.close()
    gate.close()
    directory = backend.root / "recovery/transactions" / identifier
    if fault == "record-bytes":
        (directory / "records/00000001.json").write_bytes(b'{"version":')
    elif fault == "record-count":
        (directory / "records/00000001.json").unlink()
    elif fault == "plan-extra":
        plan = json.loads((directory / "plan.json").read_text())
        plan["destination"] = "/etc"
        (directory / "plan.json").write_text(json.dumps(plan))
    elif fault == "unknown-transaction":
        (directory.parent / "not-a-transaction").mkdir()
    else:
        (backend.components()["documents"] / ".unmanaged").mkdir()
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises((g.RecoveryError, g._inventory.ArchiveError, OSError)):
            engine.recover(identifier)
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)


def test_count_ceiling_reserves_rollback_capacity(backend):
    limits = tx.Limits(records=22)
    gate = backend.gate()
    engine = tx.Engine(gate, backend, limits)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        with pytest.raises(g.RecoveryError, match="safety reservation preserved"):
            engine.publish()
        assert engine.used_records == 6
        engine.rollback()
        engine.release()
        assert engine.used_records <= limits.records
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend)
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}


def test_bad_reservation_rejected_before_closing_gate(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend, tx.Limits(records=10))
    try:
        with pytest.raises(g.RecoveryError, match="reserved safety"):
            engine.begin(engine.make_plan())
        assert not list((backend.root / "recovery/transactions").iterdir())
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend)


def test_byte_ceiling_keeps_reserved_recovery_writes_available(backend):
    limits = tx.Limits(journal_bytes=22 * 1024, record_bytes=1024)
    gate = backend.gate()
    engine = tx.Engine(gate, backend, limits)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        with pytest.raises(g.RecoveryError, match="safety reservation preserved"):
            engine.publish()
            engine.validate()
            engine.commit()
        engine.rollback()
        engine.release()
        assert engine.used_bytes <= limits.journal_bytes
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend)
    assert_original_bytes_preserved(backend)


def test_limit_profile_is_immutable_and_bound_to_plan(backend):
    limits = tx.Limits(records=40)
    with pytest.raises(AttributeError):
        limits.records = 400
    gate = backend.gate()
    engine = tx.Engine(gate, backend, limits)
    try:
        plan = engine.make_plan()
    finally:
        engine.close()
    other = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError, match="limit profile changed"):
            other.begin(plan)
    finally:
        other.close()
        gate.close()
    assert not cannot_admit(backend)


def test_rollback_rename_failure_can_resume_without_losing_generations(backend):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    original = gate.io.no_replace

    def fail_old(source_fd, source, target_fd, target, event):
        if event == "rollback:old:outputs":
            raise OSError("synthetic rollback rename failure")
        original(source_fd, source, target_fd, target, event)

    try:
        identifier = engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        engine.publish()
        gate.io.no_replace = fail_old
        with pytest.raises(OSError, match="rollback rename"):
            engine.rollback()
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)
    gate = backend.gate()
    recovered = tx.Engine(gate, backend)
    try:
        assert recovered.recover(identifier) == "rolled_back"
        recovered.release()
    finally:
        recovered.close()
        gate.close()
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}


def test_released_history_cannot_be_replayed(backend):
    identifier = run_transaction(backend)
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError, match="cannot be replayed"):
            engine.recover(identifier)
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend)


@pytest.mark.parametrize("damage", ["plan", "record", "extra-record", "extra-file", "head-link"])
def test_retained_history_bytes_and_namespace_must_verify_before_admission(damage, backend):
    identifier = run_transaction(backend)
    directory = backend.root / "recovery/transactions" / identifier
    if damage == "plan":
        plan = directory / "plan.json"
        plan.write_bytes(plan.read_bytes() + b" ")
    elif damage == "record":
        record = directory / "records/00000001.json"
        record.write_bytes(record.read_bytes() + b" ")
    elif damage == "extra-record":
        (directory / "records/ignored").write_bytes(b"unexpected")
    elif damage == "extra-file":
        (directory / "ignored").write_bytes(b"unexpected")
    else:
        head = json.loads((directory / "head.json").read_text())
        terminal = json.loads((directory / "terminal.json").read_text())
        head["sha256"] = terminal["head_sha256"] = "0" * 64
        (directory / "head.json").write_text(json.dumps(head))
        (directory / "terminal.json").write_text(json.dumps(terminal))
    assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)


def test_initialize_invalid_runtime_never_leaks_root_descriptors(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    runtime = tmp_path / "not-a-directory"
    runtime.write_bytes(b"fixture")
    before = len(list(Path("/proc/self/fd").iterdir()))
    for _attempt in range(30):
        with pytest.raises(OSError):
            g.Gate.initialize(root, runtime)
    after = len(list(Path("/proc/self/fd").iterdir()))
    assert after == before
    assert list(root.iterdir()) == []


def test_atomic_metadata_replacement_refreshes_directory_view(backend, monkeypatch):
    gate = backend.gate()
    original_scandir = os.scandir

    class StaleView:
        def __enter__(self):
            self.iterator = original_scandir(gate.root.fd)
            return (entry for entry in self.iterator if entry.name != "gate.json")

        def __exit__(self, *_args):
            self.iterator.close()

    try:
        gate.close_for("33333333-3333-4333-8333-333333333333")
        # Actual guest defect: the original description omitted replaced
        # gate.json, while an independent description saw the current entry.
        monkeypatch.setattr(os, "scandir", lambda fd: StaleView() if fd == gate.root.fd else original_scandir(fd))
        assert gate.state()["state"] == "closed"
        (backend.root / "recovery/unexpected").write_bytes(b"must not be ignored")
        with pytest.raises(g.RecoveryError, match="unknown or incomplete"):
            gate.check()
    finally:
        gate.close()


def test_names_preserves_all_entries_and_count_bound_without_fd_leaks(tmp_path):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    (directory / "known").write_bytes(b"old")
    fd = g.open_directory(directory)
    try:
        assert g.names(fd, 1) == {"known"}
        (directory / "replacement").write_bytes(b"new")
        os.replace(directory / "replacement", directory / "known")
        (directory / ".unknown").write_bytes(b"debris")
        assert g.names(fd, 2) == {"known", ".unknown"}
        before = len(os.listdir("/proc/self/fd"))
        for _attempt in range(10):
            with pytest.raises(g.RecoveryError, match="count exceeded"):
                g.names(fd, 1)
        assert len(os.listdir("/proc/self/fd")) == before
        assert os.fstat(fd).st_ino == directory.stat().st_ino
    finally:
        os.close(fd)


@pytest.mark.parametrize("boundary", ["before", "after"])
def test_names_rejects_changed_directory_identity(tmp_path, monkeypatch, boundary):
    fd = g.open_directory(tmp_path)
    original_id = g.directory_id
    original_scandir = os.scandir
    enumerated = False

    def identify(descriptor):
        value = original_id(descriptor)
        if descriptor != fd and (boundary == "before" or enumerated):
            value["inode"] += 1
        return value

    def enumerate_directory(descriptor):
        nonlocal enumerated
        enumerated = True
        return original_scandir(descriptor)

    try:
        monkeypatch.setattr(g, "directory_id", identify)
        monkeypatch.setattr(os, "scandir", enumerate_directory)
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(g.RecoveryError, match="control directory"):
            g.names(fd, 4)
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(fd)


def test_names_propagates_enumeration_errors_and_closes_fresh_descriptor(tmp_path, monkeypatch):
    fd = g.open_directory(tmp_path)
    def unavailable(_descriptor):
        raise OSError(5, "synthetic directory read failure")
    try:
        monkeypatch.setattr(os, "scandir", unavailable)
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(OSError, match="synthetic directory read failure"):
            g.names(fd, 4)
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(fd)


def test_components_on_distinct_filesystems_use_local_generation_renames(tmp_path):
    if not Path("/dev/shm").is_dir() or Path("/dev/shm").stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("independent volatile fixture filesystem unavailable")
    original = make_fixture(tmp_path / "fixture")
    with tempfile.TemporaryDirectory(prefix="secai-b1-", dir="/dev/shm") as other_root:
        other = Path(other_root)
        for generation in ("active", "incoming"):
            tree = other / generation
            tree.mkdir(mode=0o700)
            payload = tree / "payload"
            payload.write_bytes(b"old-outputs" if generation == "active" else b"new-outputs")
            payload.chmod(0o600)

        class SeparateFilesystemBackend(FixtureBackend):
            def components(self):
                return {"documents": self.root / "documents-parent", "outputs": other}

        backend = SeparateFilesystemBackend(original.root)
        run_transaction(backend)
        assert backend.active() == {"documents": b"new-documents", "outputs": b"new-outputs"}
        assert_original_bytes_preserved(backend)


def test_boot_change_requires_explicit_backend_rebind(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    identifier = engine.begin(engine.make_plan())
    engine.quiesce()
    engine.prepare()
    engine.close()
    gate.close()
    clock.boot = "22222222-2222-4222-8222-222222222222"
    assert cannot_admit(backend, clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        with pytest.raises(g.RecoveryError, match="trusted filesystem rebind"):
            engine.recover(identifier)
    finally:
        engine.close()
        gate.close()
    backend.allow_rebind = True
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        assert engine.recover(identifier) == "rolled_back"
        engine.release()
    finally:
        engine.close()
        gate.close()
    assert not cannot_admit(backend, clock)


def test_suspend_counted_expiry_cannot_publish_or_open_gate(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend, tx.Limits(seconds=1))
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        clock.now += 2_000_000_000
        with pytest.raises(g.RecoveryError, match="deadline expired"):
            engine.publish()
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend, clock)
    assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}


@pytest.mark.parametrize("stage", ["prepare", "publish", "rollback"])
def test_fsync_failure_preserves_generations_and_closes_gate(stage, backend, monkeypatch):
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    original = os.fsync
    fail = False

    def storage_failure(fd):
        if fail:
            raise OSError(28, "synthetic ENOSPC/fsync failure")
        return original(fd)

    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        if stage in {"publish", "rollback"}:
            engine.prepare()
        if stage == "rollback":
            engine.publish()
        monkeypatch.setattr(os, "fsync", storage_failure)
        fail = True
        with pytest.raises(OSError):
            getattr(engine, stage)()
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)

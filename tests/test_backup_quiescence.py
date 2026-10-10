"""Private process and crash tests; no native systemd/cgroup backend is shipped."""

from __future__ import annotations

import json
import os
import signal
import threading
from pathlib import Path

import pytest

from backup_process_fixture import isolated_case
from test_backup_transaction import (
    FixtureBackend, FixtureClock, assert_original_bytes_preserved, cannot_admit,
    child_alive, g, kill_fixture_self, make_fixture, owns_child, private_fork,
    run_transaction, signal_child, tx, wait_child,
)


class ProcessBackend(FixtureBackend):
    """Fixture liveness registry stands in for the future independent cgroup check."""

    def __init__(self, root):
        super().__init__(root)
        self.pid = None
        self.kill_on_stop = True

    def stop_writers(self, deadline):
        deadline.check()
        if self.pid and self.kill_on_stop:
            signal_child(self.pid, signal.SIGTERM)
            wait_child(self.pid, 3)
            self.pid = None
        self.stopped = True

    def quiescent(self):
        if self.pid and child_alive(self.pid):
            return False
        return self.stopped


def start_writer(backend, *, close_lease=False):
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = private_fork()
    if pid == 0:
        os.close(ready_read)
        os.close(release_write)
        signal.alarm(8)
        try:
            gate = backend.gate()
            lease = gate.lease()
            if close_lease:
                lease.close()
                gate.close()
            os.write(ready_write, b"R")
            if os.read(release_read, 1):
                (backend.root / "late-publication").write_bytes(b"writer remained alive")
            os._exit(0)
        except BaseException:
            try:
                os.write(ready_write, b"B")
            finally:
                os._exit(1)
    os.close(ready_write)
    os.close(release_read)
    assert os.read(ready_read, 1) == b"R"
    os.close(ready_read)
    backend.pid = pid
    return release_write


def stop_fixture_writer(backend, release_fd):
    os.close(release_fd)
    if backend.pid and owns_child(backend.pid):
        try:
            signal_child(backend.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        wait_child(backend.pid, 3)
    backend.pid = None


@isolated_case()
def test_concurrent_writer_reaped_before_publication(tmp_path):
    original = make_fixture(tmp_path / "fixture")
    backend = ProcessBackend(original.root)
    release = start_writer(backend)
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        assert backend.pid is None
        with pytest.raises(BrokenPipeError):
            os.write(release, b"P")
        engine.prepare()
        engine.publish()
        engine.validate()
        engine.commit()
        engine.release()
        assert not (backend.root / "late-publication").exists()
    finally:
        stop_fixture_writer(backend, release)
        engine.close()
        gate.close()


@isolated_case()
def test_surviving_child_that_closed_lease_blocks_quiescence(tmp_path):
    original = make_fixture(tmp_path / "fixture")
    backend = ProcessBackend(original.root)
    backend.kill_on_stop = False
    release = start_writer(backend, close_lease=True)
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        with pytest.raises(g.RecoveryError, match="surviving descendant"):
            engine.quiesce()
        # EX was obtainable: a lock-only implementation would falsely pass.
        assert engine.admission_lock is not None
        assert backend.pid is not None
        assert cannot_admit(backend)
        assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
    finally:
        stop_fixture_writer(backend, release)
        engine.close()
        gate.close()


@isolated_case()
def test_late_start_holding_old_lease_prevents_exclusive_publication(tmp_path):
    original = make_fixture(tmp_path / "fixture")
    backend = ProcessBackend(original.root)
    backend.kill_on_stop = False
    release = start_writer(backend)
    gate = backend.gate()
    engine = tx.Engine(gate, backend, tx.Limits(seconds=1))
    try:
        engine.begin(engine.make_plan())
        with pytest.raises(g.RecoveryError, match="deadline expired"):
            engine.quiesce()
        assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
    finally:
        stop_fixture_writer(backend, release)
        engine.close()
        gate.close()
    assert cannot_admit(backend)


@isolated_case()
def test_new_writer_refuses_closed_gate(tmp_path):
    backend = make_fixture(tmp_path / "fixture")
    gate = backend.gate()
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        pid = private_fork()
        if pid == 0:
            # Do not retain the parent's operation lock across the fixture fork.
            os.close(engine.operation_lock.fd)
            try:
                other = backend.gate()
                lease = other.lease()
                lease.close()
                os._exit(2)
            except g.RecoveryError:
                os._exit(0)
        assert os.waitstatus_to_exitcode(wait_child(pid)) == 0
        engine.quiesce()
        engine.rollback()
        engine.release()
    finally:
        engine.close()
        gate.close()


@pytest.mark.parametrize("field,value", [("domain", "monotonic"), ("now", True), ("now", -1), ("boot", "invalid")])
def test_bad_clock_never_admits(field, value, tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    setattr(clock, field, value)
    assert cannot_admit(backend, clock)


def test_clock_regression_is_not_a_new_deadline(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    gate = backend.gate(clock)
    engine = tx.Engine(gate, backend)
    try:
        engine.begin(engine.make_plan())
        engine.quiesce()
        clock.now -= 1
        with pytest.raises(g.RecoveryError, match="regressed"):
            engine.prepare()
    finally:
        engine.close()
        gate.close()
    assert cannot_admit(backend, clock)


def test_fresh_boot_cannot_reuse_open_ready_proof(tmp_path):
    clock = FixtureClock()
    backend = make_fixture(tmp_path / "fixture", clock)
    clock.boot = "22222222-2222-4222-8222-222222222222"
    assert cannot_admit(backend, clock)
    with pytest.raises(g.RecoveryError, match="never resets"):
        g.Gate.initialize(backend.root / "recovery", backend.root / "runtime", clock)


def test_fixture_signals_refuse_unregistered_zero_negative_or_self_targets():
    for pid in (0, -1, os.getpid(), 999999999):
        with pytest.raises(AssertionError):
            signal_child(pid, signal.SIGTERM)
    with pytest.raises(AssertionError):
        kill_fixture_self()


@isolated_case()
def test_timed_out_child_is_reaped_and_stale_cleanup_cannot_signal_again(tmp_path):
    backend = ProcessBackend(make_fixture(tmp_path / "fixture").root)
    pid = private_fork()
    if pid == 0:
        signal.pause()
        os._exit(2)
    backend.pid = pid
    with pytest.raises(AssertionError, match="exceeded lifetime"):
        wait_child(pid, .1)
    assert not owns_child(pid)
    with pytest.raises(AssertionError):
        signal_child(pid, signal.SIGTERM)
    # Cleanup sees no owned pidfd, so it cannot target a reused numeric PID.
    reader, writer = os.pipe()
    os.close(reader)
    stop_fixture_writer(backend, writer)
    assert backend.pid is None


def _recover_in_fresh_child(backend, result_path):
    pid = private_fork()
    if pid == 0:
        signal.alarm(10)
        try:
            gate = backend.gate()
            try:
                if not cannot_admit(backend):
                    result = "already-open"
                else:
                    state = gate.state(recovery=True)
                    engine = tx.Engine(gate, FixtureBackend(backend.root))
                    try:
                        identifier = state["transaction"] or (state["history"][-1] if state["history"] else None)
                        result = engine.recover(identifier)
                        engine.release()
                    finally:
                        engine.close()
            finally:
                gate.close()
        except BaseException as exc:
            result = "blocked:" + type(exc).__name__ + ":" + str(exc)[:120]
        result_path.write_text(json.dumps({"result": result}))
        os._exit(0)
    assert os.waitstatus_to_exitcode(wait_child(pid, 12)) == 0
    return json.loads(result_path.read_text())["result"]


@isolated_case(seconds=600)
def test_sigkill_around_every_durable_forward_boundary(tmp_path):
    baseline = make_fixture(tmp_path / "baseline")
    events = []
    endings = (":before-fsync", ":after-fsync", ":before-rename", ":after-rename", ":before-replace", ":after-replace")
    run_transaction(baseline, hook=lambda event: events.append(event) if event.endswith(endings) else None)
    outcomes = {"rolled_back": 0, "committed": 0, "already-open": 0, "blocked": 0}
    blocked = []
    for target, event in enumerate(events):
        backend = make_fixture(tmp_path / f"case-{target:04d}")
        pid = private_fork()
        if pid == 0:
            signal.alarm(15)
            count = 0

            def failpoint(name):
                nonlocal count
                if name.endswith(endings):
                    if count == target:
                        kill_fixture_self()
                    count += 1

            try:
                run_transaction(backend, hook=failpoint)
            except BaseException:
                os._exit(3)
            os._exit(2)
        assert os.waitstatus_to_exitcode(wait_child(pid, 17)) == -9, (target, event)
        result = _recover_in_fresh_child(backend, tmp_path / f"result-{target:04d}.json")
        assert_original_bytes_preserved(backend)
        if result.startswith("blocked:"):
            outcomes["blocked"] += 1
            blocked.append({"index": target, "event": event, "result": result})
            assert cannot_admit(backend), (target, event, result)
        else:
            outcomes[result] += 1
            expected = b"new-" if result == "committed" else None
            values = backend.active()
            all_old = values == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
            all_new = values == {name: b"new-" + name.encode() for name in backend.COMPONENTS}
            assert all_old or all_new, (target, event, result)
            if expected is not None:
                assert all_new
            if result == "rolled_back":
                assert all_old
            assert not cannot_admit(backend), (target, event, result)
    assert outcomes["rolled_back"] and outcomes["committed"]
    assert len(events) >= 100
    report = {"durable_fault_points": len(events), "outcomes": outcomes, "blocked": blocked,
              "qualification": "process SIGKILL only; no mount/device/service or power-loss test"}
    destination = os.environ.get("SECAI_B1_FAULT_REPORT")
    if destination:
        Path(destination).write_text(json.dumps(report, indent=2) + "\n")


@pytest.mark.parametrize("complete", [False, True])
@isolated_case()
def test_interrupted_journal_write_torn_blocks_complete_recovers(complete, tmp_path):
    backend = make_fixture(tmp_path / "fixture")
    pid = private_fork()
    if pid == 0:
        gate = backend.gate()
        original = gate.io.create

        def interrupted(parent, name, data, event):
            if event == "journal:publishing:old-to-rollback":
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
                os.write(fd, data if complete else data[:len(data) // 2])
                os.fsync(fd)
                kill_fixture_self()
            original(parent, name, data, event)

        gate.io.create = interrupted
        engine = tx.Engine(gate, backend)
        engine.begin(engine.make_plan())
        engine.quiesce()
        engine.prepare()
        engine.publish()
        os._exit(2)
    assert os.waitstatus_to_exitcode(wait_child(pid)) == -9
    result = _recover_in_fresh_child(backend, tmp_path / "result.json")
    if complete:
        assert result == "rolled_back"
        assert not cannot_admit(backend)
    else:
        assert result.startswith("blocked:")
        assert cannot_admit(backend)
    assert_original_bytes_preserved(backend)


@pytest.mark.parametrize("event", [
    "release:gate:temporary:before-fsync", "release:gate:temporary:after-fsync",
    "release:gate:before-replace", "release:gate:after-replace",
    "release:gate:directory:before-fsync", "release:gate:directory:after-fsync",
    "release:ready:temporary:before-fsync", "release:ready:temporary:after-fsync",
    "release:ready:before-replace",
])
@isolated_case()
def test_completed_data_release_recovers_known_control_transition(event, tmp_path):
    backend = make_fixture(tmp_path / "fixture")
    pid = private_fork()
    if pid == 0:
        def interrupt(name):
            if name == event:
                kill_fixture_self()
        run_transaction(backend, hook=interrupt)
        os._exit(2)
    assert os.waitstatus_to_exitcode(wait_child(pid)) == -9
    assert cannot_admit(backend)
    assert _recover_in_fresh_child(backend, tmp_path / "result.json") == "committed"
    assert not cannot_admit(backend)
    assert_original_bytes_preserved(backend)


@isolated_case(seconds=600)
def test_sigkill_around_every_durable_rollback_boundary(tmp_path):
    endings = (":before-fsync", ":after-fsync", ":before-rename", ":after-rename", ":before-replace", ":after-replace")

    def start_and_rollback(backend, hook):
        gate = backend.gate()
        engine = tx.Engine(gate, backend)
        try:
            engine.begin(engine.make_plan())
            engine.quiesce()
            engine.prepare()
            engine.publish()
            gate.io.hook = hook
            engine.rollback()
            engine.release()
        finally:
            engine.close()
            gate.close()

    baseline = make_fixture(tmp_path / "baseline")
    events = []
    start_and_rollback(baseline, lambda name: events.append(name) if name.endswith(endings) else None)
    outcomes = {"rolled_back": 0, "already-open": 0, "blocked": 0}
    blocked = []
    for target, event in enumerate(events):
        backend = make_fixture(tmp_path / f"case-{target:04d}")
        pid = private_fork()
        if pid == 0:
            count = 0

            def failpoint(name):
                nonlocal count
                if name.endswith(endings):
                    if count == target:
                        kill_fixture_self()
                    count += 1

            start_and_rollback(backend, failpoint)
            os._exit(2)
        assert os.waitstatus_to_exitcode(wait_child(pid, 17)) == -9, (target, event)
        result = _recover_in_fresh_child(backend, tmp_path / f"result-{target:04d}.json")
        assert_original_bytes_preserved(backend)
        if result.startswith("blocked:"):
            outcomes["blocked"] += 1
            blocked.append({"index": target, "event": event, "result": result})
            assert cannot_admit(backend)
        else:
            assert result in {"rolled_back", "already-open"}, (target, event, result)
            outcomes[result] += 1
            assert not cannot_admit(backend)
            assert backend.active() == {name: b"old-" + name.encode() for name in backend.COMPONENTS}
    assert len(events) >= 50 and outcomes["rolled_back"]
    destination = os.environ.get("SECAI_B1_ROLLBACK_REPORT")
    if destination:
        Path(destination).write_text(json.dumps({"durable_fault_points": len(events), "outcomes": outcomes,
                                                "blocked": blocked, "qualification": "private process SIGKILL only"}, indent=2) + "\n")


def test_process_cases_run_from_threaded_caller_without_forking_it(tmp_path, monkeypatch):
    ready = threading.Event()
    done = threading.Event()

    def ordinary_background_work():
        ready.set()
        done.wait(30)

    def refuse_caller_fork():
        raise AssertionError("the threaded caller must not fork")

    worker = threading.Thread(target=ordinary_background_work, daemon=True)
    worker.start()
    assert ready.wait(2)
    try:
        assert worker.is_alive() and threading.active_count() >= 2
        monkeypatch.setattr(os, "fork", refuse_caller_fork)
        with pytest.raises(AssertionError, match="clean B1 fixture interpreter"):
            private_fork()
        for name, scenario, arguments in [
            ("writer", test_concurrent_writer_reaped_before_publication, {}),
            ("survivor", test_surviving_child_that_closed_lease_blocks_quiescence, {}),
            ("recovery", test_interrupted_journal_write_torn_blocks_complete_recovers, {"complete": True}),
        ]:
            root = tmp_path / name
            root.mkdir(mode=0o700)
            scenario(tmp_path=root, **arguments)
        assert worker.is_alive()
    finally:
        done.set()
        worker.join(2)
    assert not worker.is_alive()

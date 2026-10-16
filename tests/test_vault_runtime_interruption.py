"""Causal same-boot interruption cases; all devices, jobs and locks are fake.

OwnerKilled models abrupt loss of the operation owner at a mutation boundary;
these tests do not execute a real kill, cryptsetup, mount or service operation.
"""
import importlib.util
import fcntl
import json
import select
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SCRIPTS = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai"
BOOT = "f3692c37-e937-41d9-9e88-e0db7e080d0c"
OTHER_BOOT = "7711e21f-9a28-442c-bd59-9370b227f446"


class OwnerKilled(BaseException):
    pass


class StopWatching(BaseException):
    pass


def test_real_owner_termination_retains_intent_for_observer(runtime, tmp_path, monkeypatch):
    module, _host = runtime
    lock = tmp_path / "operation.lock"
    lock.touch(mode=0o600)
    script = '''import importlib.util,os,pathlib,sys,time
scripts,state,lock,boot=sys.argv[1:]
sys.path.insert(0,scripts)
spec=importlib.util.spec_from_file_location('owned_vault',pathlib.Path(scripts)/'vault-watchdog.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.STATE_FILE=state
module._boot_id=lambda: boot
module.vault_operation._LOCK_PATH=pathlib.Path(lock)
module.vault_operation._OWNER_UID=os.getuid()
module.vault_operation._OWNER_GID=os.getgid()
module.audit_event=lambda *a,**kw: None
module.vault_mount_state=lambda: ('expected','fixture-mapper')
def mutation_boundary():
    print('intent-committed-before-mutation',flush=True)
    while True: time.sleep(60)
module.stop_services=mutation_boundary
module.lock_vault('owned-process-fixture')
'''
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", script, str(SCRIPTS), module.STATE_FILE, str(lock), BOOT],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert select.select([child.stdout], [], [], 5)[0], "owned child readiness deadline"
        assert child.stdout.readline().strip() == "intent-committed-before-mutation"
        child.kill()
        assert child.wait(timeout=5) != 0
        pending = module.read_state()[module._PENDING]
        assert pending["boot_id"] == BOOT and pending["action"] == "lock"
        with lock.open("r") as descriptor:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cleanup = Mock(return_value=False)
        monkeypatch.setattr(module, "_lock_vault_held", cleanup)
        assert module._reconcile_operation(operation_fd=99) is False
        assert module.read_state()[module._PENDING] == pending
        assert module.read_state()["state"] == "error"
        cleanup.assert_called_once_with("interrupted_runtime_operation", operation_fd=99)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("interrupted_vault", SCRIPTS / "vault-watchdog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    host = {"mount": "expected", "mapper": True, "pending_consumer_job": None, "mutations": []}

    @contextmanager
    def operation():
        yield SimpleNamespace(fd=99)

    monkeypatch.setattr(module.vault_operation, "operation", operation)
    monkeypatch.setattr(module, "STATE_FILE", str(tmp_path / "vault-state"))
    monkeypatch.setattr(module, "_boot_id", lambda: BOOT)
    monkeypatch.setattr(module, "audit_event", Mock())
    monkeypatch.setattr(module, "vault_mount_state", lambda: (host["mount"], "fixture-mapper"))
    monkeypatch.setattr(module, "is_mapper_open", lambda: host["mapper"])
    monkeypatch.setattr(module, "vault_has_configuration", lambda: True)
    monkeypatch.setattr(module, "exact_vault_mount_verified", lambda: True)
    monkeypatch.setattr(module, "touch_activity", Mock(return_value=True))
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected external command"))

    def mount():
        host["mutations"].append("host-mounted")
        host["mount"] = "expected"

    monkeypatch.setattr(module.vault_mount, "start", mount)
    return module, host


def restart(module, monkeypatch, *, iterations=0):
    attempts = Mock(return_value=False)  # Interrupted-operation cleanup cannot be confirmed.
    monkeypatch.setattr(module, "_lock_vault_held", attempts)
    sleeps = 0

    def sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > iterations:
            raise StopWatching

    monkeypatch.setattr(module, "time", SimpleNamespace(time=time.time, monotonic=time.monotonic, sleep=sleep))
    with pytest.raises(StopWatching):
        module.watchdog_loop(30, 10)
    return attempts


@pytest.mark.parametrize("action", ["lock", "unlock"])
def test_interrupted_operation_is_not_adopted_as_unlocked_on_restart(runtime, monkeypatch, action):
    module, host = runtime
    assert module.write_state("unlocked" if action == "lock" else "locked", "previous complete status")

    def lost_owner():
        host["mutations"].append("consumers-stopping" if action == "lock" else "consumers-starting")
        raise OwnerKilled

    if action == "lock":
        monkeypatch.setattr(module, "stop_services", lost_owner)
        with pytest.raises(OwnerKilled):
            module.lock_vault("fixture interruption")
    else:
        host["mount"] = "absent"
        # A TPM-opened mapper is legitimate; no passphrase/device operation is needed.
        monkeypatch.setattr(module, "start_services", lost_owner)
        with pytest.raises(OwnerKilled):
            module.unlock_vault("fixture-passphrase")
        assert host["mutations"][0] == "host-mounted"

    assert host["mount"] == "expected" and host["mutations"]
    marker = module.read_state()[module._PENDING]
    assert marker["boot_id"] == BOOT and marker["action"] == action
    attempts = restart(module, monkeypatch)
    assert module.read_state()["state"] != "unlocked", "restart erased interrupted intent with verified-mount status"
    assert attempts.called, "same-boot interrupted work must be reconciled, not silently adopted"


def test_iteration_does_not_commit_locked_after_interrupted_cleanup_failed(runtime, monkeypatch):
    module, host = runtime
    host.update(mount="absent", mapper=False, pending_consumer_job="consumer-stop-91")
    assert module.write_state("unlocked", "previous complete status")

    def lost_owner():
        host["mutations"].append("consumer-stop-requested")
        raise OwnerKilled

    monkeypatch.setattr(module, "stop_services", lost_owner)
    with pytest.raises(OwnerKilled):
        module.lock_vault("fixture interruption")
    attempts = restart(module, monkeypatch, iterations=1)
    assert host["pending_consumer_job"] == "consumer-stop-91"
    assert attempts.called  # Startup could not finish the pending closure.
    assert module.read_state()["state"] not in {"locked", "unlocked"}, "iteration cleared unconfirmed operation"


def marker(*, boot=BOOT):
    return {"version": 1, "boot_id": boot,
            "operation_id": "2741d4cc-7250-4fc4-bfc8-3b0227ee3b22", "action": "unlock"}


def put_marker(module, value):
    Path(module.STATE_FILE).write_text(json.dumps({"state": "unlocked", module._PENDING: value}))


@pytest.mark.parametrize("value", [
    None, [], {}, marker() | {"version": True}, marker() | {"version": 1.0}, marker() | {"version": 2},
    marker() | {"action": "mount"}, marker() | {"action": []},
    marker() | {"boot_id": "not-a-uuid"}, marker() | {"operation_id": 4},
    marker() | {"extra": "future-contract"},
])
def test_malformed_or_future_intent_blocks_adoption_and_manual_unlock(runtime, monkeypatch, value):
    module, host = runtime
    put_marker(module, value)
    attempts = restart(module, monkeypatch, iterations=1)
    assert not attempts.called  # Invalid data cannot authorize even fixed recovery.
    assert not module.unlock_vault("fixture-passphrase")["success"]
    assert module.read_state()[module._PENDING] == value
    assert module.read_state()["state"] == "error"
    assert host["mutations"] == []


def test_other_boot_intent_is_not_boot_authorization(runtime, monkeypatch):
    module, host = runtime
    value = marker(boot=OTHER_BOOT)
    put_marker(module, value)
    attempts = restart(module, monkeypatch, iterations=1)
    assert not attempts.called
    assert not module.unlock_vault("fixture-passphrase")["success"]
    assert not module.lock_vault("operator-request")
    assert module.read_state()[module._PENDING] == value
    assert module.read_state()["state"] == "error"
    assert host["mutations"] == []


@pytest.mark.parametrize("state", ["error", "unlocked", "locked", "locking_soon", "setup_required"])
def test_status_and_error_writes_preserve_pending_intent(runtime, state):
    module, _host = runtime
    value = marker()
    put_marker(module, value)
    assert module.write_state(state, "fixture observation")
    assert module.read_state()[module._PENDING] == value
    assert module.read_state()["state"] == "error"


@pytest.mark.parametrize("action", ["lock", "unlock"])
def test_intent_persistence_failure_prevents_first_mutation(runtime, monkeypatch, action):
    module, host = runtime
    host["mount"] = "absent"
    stopped = Mock(side_effect=AssertionError("mutation before intent"))
    monkeypatch.setattr(module, "stop_services", stopped)
    monkeypatch.setattr(module.os, "fsync", Mock(side_effect=OSError("fixture fsync failure")))
    if action == "lock":
        assert module.lock_vault("fixture") is False
    else:
        assert module.unlock_vault("fixture-passphrase")["success"] is False
    assert host["mutations"] == []
    stopped.assert_not_called()


def test_successful_lock_clears_intent_only_after_independent_closure(runtime, monkeypatch):
    module, host = runtime
    host.update(mount="absent", mapper=False)
    value = marker()
    put_marker(module, value)

    def stopped():
        assert module.read_state()[module._PENDING] == value
        return True

    def idle():
        assert module.read_state()[module._PENDING] == value
        return True

    monkeypatch.setattr(module, "stop_services", stopped)
    monkeypatch.setattr(module.vault_mount, "consumers_idle", idle)
    assert module.lock_vault("fixture")
    assert module.read_state()["state"] == "locked"
    assert module._PENDING not in module.read_state()


def test_failed_closure_preserves_original_intent(runtime, monkeypatch):
    module, _host = runtime
    value = marker()
    put_marker(module, value)
    monkeypatch.setattr(module, "stop_services", lambda: False)
    assert not module.lock_vault("fixture")
    assert module.read_state()[module._PENDING] == value
    assert module.read_state()["state"] == "error"


def test_manual_unlock_settles_pending_then_performs_new_request(runtime, monkeypatch):
    module, host = runtime
    previous = marker()
    put_marker(module, previous)
    events = []

    def relock(reason, *, operation_fd):
        assert reason == "interrupted_runtime_operation" and operation_fd == 99
        assert module.read_state()[module._PENDING] == previous
        events.append("cleanup")
        host["mount"] = "absent"
        # A pre-opened TPM mapper remains in this synthetic path; no device command.
        return module.write_state("locked", _complete=True)

    def services():
        pending = module.read_state()[module._PENDING]
        assert pending["action"] == "unlock"
        assert pending["operation_id"] != previous["operation_id"]
        assert events == ["cleanup"] and host["mount"] == "expected"
        events.append("services")
        return True, []

    def activity():
        assert module._PENDING in module.read_state()
        events.append("activity")
        return True

    monkeypatch.setattr(module, "_lock_vault_held", relock)
    monkeypatch.setattr(module, "start_services", services)
    monkeypatch.setattr(module, "touch_activity", activity)
    assert module.unlock_vault("fixture-passphrase") == {"success": True}
    assert events == ["cleanup", "services", "activity"]
    assert module.read_state()["state"] == "unlocked"
    assert module._PENDING not in module.read_state()


def test_intent_created_after_startup_is_checked_each_iteration(runtime, monkeypatch):
    module, _host = runtime
    attempts = Mock(return_value=False)
    monkeypatch.setattr(module, "_lock_vault_held", attempts)
    sleeps = 0

    def sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            raise StopWatching
        assert module.read_state()["state"] == "unlocked"
        put_marker(module, marker())

    monkeypatch.setattr(module, "time", SimpleNamespace(time=time.time, monotonic=time.monotonic, sleep=sleep))
    with pytest.raises(StopWatching):
        module.watchdog_loop(30, 10)
    attempts.assert_called_once_with("interrupted_runtime_operation", operation_fd=99)
    assert module.read_state()["state"] == "error"
    assert module.read_state()[module._PENDING] == marker()


def test_unmarked_fresh_boot_tpm_mount_still_adopted(runtime, monkeypatch):
    module, _host = runtime
    # Fresh boot adoption does not use a runtime marker as boot authorization.
    monkeypatch.setattr(module, "_boot_id", Mock(side_effect=AssertionError("no pending operation")))
    attempts = restart(module, monkeypatch)
    attempts.assert_not_called()
    assert module.read_state()["state"] == "unlocked"
    assert module._PENDING not in module.read_state()


@pytest.mark.parametrize("raw", [
    b'{"pending_operation":{},"pending_operation":null}', b'[]', b'{', b'"value"', b'x' * 16385, b' ' * 16385,
])
def test_corrupt_record_cannot_be_replaced_with_status_or_trigger_mutation(runtime, monkeypatch, raw):
    module, host = runtime
    Path(module.STATE_FILE).write_bytes(raw)
    attempts = restart(module, monkeypatch, iterations=1)
    assert not attempts.called
    assert not module.unlock_vault("fixture-passphrase")["success"]
    assert not module.write_state("unlocked")
    assert Path(module.STATE_FILE).read_bytes() == raw
    assert host["mutations"] == []


def test_fixed_boot_id_reader_and_sandbox_bind(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("boot_reader_vault", SCRIPTS / "vault-watchdog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proc, bound = tmp_path / "proc-boot", tmp_path / "bound-boot"
    monkeypatch.setattr(module, "_BOOT_ID_PATHS", (proc, bound))
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()
    bound.write_text(BOOT + "\n")
    assert module._boot_id() == BOOT  # ProcSubset=pid: the fixed bind is available.
    proc.write_text(BOOT + "\n")
    assert module._boot_id() == BOOT
    bound.write_text("")  # Actual systemd bind-target placeholder seen by console.
    assert module._boot_id() == BOOT
    proc.unlink()
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()  # Empty fallback alone supplies no identity.
    proc.write_text("")
    bound.write_text(BOOT + "\n")
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()  # An empty original kernel source never gets waived.
    proc.write_text(BOOT + "\n")
    bound.write_text(" \n")
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()  # Only zero bytes, not malformed whitespace, is unavailable.
    bound.write_text(OTHER_BOOT + "\n")
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()
    bound.write_text("invalid")
    with pytest.raises(module.RuntimeIntentError):
        module._boot_id()
    unit = SCRIPTS.parents[1] / "lib/systemd/system/secure-ai-vault-watchdog.service"
    text = unit.read_text()
    assert "ProcSubset=pid" in text
    assert "BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/secure-ai-vault-boot-id" in text


def test_failed_unlock_rollback_retains_unlock_intent(runtime, monkeypatch):
    module, host = runtime
    host["mount"] = "absent"
    observed = []

    def services():
        observed.append(module.read_state()[module._PENDING])
        return False, ["fixture-consumer"]

    monkeypatch.setattr(module, "start_services", services)
    monkeypatch.setattr(module, "stop_services", lambda: False)
    assert not module.unlock_vault("fixture-passphrase")["success"]
    assert module.read_state()[module._PENDING] == observed[0]
    assert observed[0]["action"] == "unlock"
    assert module.read_state()["state"] == "error"
    assert "fixture-passphrase" not in Path(module.STATE_FILE).read_text()

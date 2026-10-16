"""Fixed vault-operation exclusion; devices and service actions are mocked."""
import fcntl
import importlib.util
import os
import select
import signal
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SCRIPTS = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def held_elsewhere(path):
    script = "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); sys.stdin.read(1)"
    child = subprocess.Popen([sys.executable, "-B", "-c", script, str(path)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "held"
        yield
    finally:
        child.communicate("x", timeout=5)
        assert child.returncode == 0


@pytest.fixture
def watchdog(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = load("serialized_vault_watchdog", "vault-watchdog.py")
    lock = tmp_path / "vault-operation.lock"
    lock.touch(mode=0o600)
    if hasattr(module, "vault_operation"):
        monkeypatch.setattr(module.vault_operation, "_LOCK_PATH", lock)
        monkeypatch.setattr(module.vault_operation, "_OWNER_UID", os.geteuid())
        monkeypatch.setattr(module.vault_operation, "_OWNER_GID", os.getegid())
        monkeypatch.setattr(module.vault_operation, "_ACQUIRE_SECONDS", 0.05)
    monkeypatch.setattr(module, "audit_event", Mock())
    monkeypatch.setattr(module, "write_state", Mock(return_value=True))
    monkeypatch.setattr(module, "stop_services", Mock(return_value=True))
    monkeypatch.setattr(module, "is_mapper_open", lambda: False)
    monkeypatch.setattr(module, "vault_has_configuration", lambda: True)
    monkeypatch.setattr(module.vault_mount, "start", Mock())
    monkeypatch.setattr(module.vault_mount, "stop", Mock())
    monkeypatch.setattr(module.vault_mount, "consumers_idle", Mock(return_value=True))
    return module, lock


@pytest.mark.parametrize("operation", ["lock", "unlock"])
def test_another_process_lock_blocks_vault_mutation(watchdog, monkeypatch, operation):
    module, lock = watchdog
    if operation == "lock":
        monkeypatch.setattr(module, "vault_mount_state", lambda: ("absent", ""))
    else:
        monkeypatch.setattr(module, "vault_mount_state", lambda: ("expected", "mapper"))
        monkeypatch.setattr(module, "exact_vault_mount_verified", lambda: True)
    with held_elsewhere(lock):
        if operation == "lock":
            assert module.lock_vault("fixture") is False
        else:
            assert module.unlock_vault("fixture-passphrase")["success"] is False
    module.stop_services.assert_not_called()
    module.write_state.assert_not_called()
    if operation == "lock":
        assert module.lock_vault("fixture") is True
    else:
        assert module.unlock_vault("fixture-passphrase")["success"] is True


@pytest.mark.parametrize("reason", ["preexisting", "services", "activity", "state"])
def test_unlock_failure_relocks_with_the_same_held_operation(watchdog, tmp_path, monkeypatch, reason):
    module, lock = watchdog
    monkeypatch.setattr(module, "is_mapper_open", lambda: True)
    states = iter([("expected", "mapper")] if reason == "preexisting" else
                  [("absent", ""), ("expected", "mapper")])
    monkeypatch.setattr(module, "vault_mount_state", lambda: next(states, ("expected", "mapper")))
    monkeypatch.setattr(module, "exact_vault_mount_verified", lambda: reason != "preexisting")
    monkeypatch.setattr(module, "MOUNT_POINT", str(tmp_path / "vault"))
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0))
    monkeypatch.setattr(module, "start_services", lambda: (reason != "services", ["fixture"]))
    monkeypatch.setattr(module, "touch_activity", lambda: reason != "activity")
    monkeypatch.setattr(module, "write_state", lambda state, *a: not (reason == "state" and state == "unlocked"))
    relocks = []

    def relock(why, *, operation_fd):
        assert os.fstat(operation_fd).st_ino == lock.stat().st_ino
        with lock.open("r+") as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        relocks.append(why)
        return True

    monkeypatch.setattr(module, "_lock_vault_held", relock)
    monkeypatch.setattr(module, "lock_vault", lambda *a: pytest.fail("rollback reacquired operation lock"))
    assert module.unlock_vault("fixture-passphrase")["success"] is False
    assert len(relocks) == 1
    with module.vault_operation.operation():
        pass  # Rollback released exclusion on return.


def test_watchdog_observation_busy_does_not_overwrite_state(watchdog, monkeypatch):
    module, lock = watchdog
    observed = Mock(return_value=("expected", "mapper"))
    monkeypatch.setattr(module, "vault_mount_state", observed)
    monkeypatch.setattr(module, "time", SimpleNamespace(
        sleep=lambda _: (_ for _ in ()).throw(KeyboardInterrupt())))
    with held_elsewhere(lock), pytest.raises(KeyboardInterrupt):
        module.watchdog_loop(30, 10)
    observed.assert_not_called()
    module.write_state.assert_not_called()


@pytest.mark.parametrize("mutation", ["missing", "mode", "symlink", "hardlink", "rebind"])
def test_operation_rejects_unprovisioned_or_changed_inode(watchdog, tmp_path, mutation):
    module, lock = watchdog
    if mutation == "missing":
        lock.unlink()
    elif mutation == "mode":
        lock.chmod(0o644)
    elif mutation == "symlink":
        lock.rename(tmp_path / "original")
        lock.symlink_to(tmp_path / "original")
    elif mutation == "hardlink":
        os.link(lock, tmp_path / "other-link")
    with pytest.raises(module.vault_operation.VaultOperationError), module.vault_operation.operation():
        assert mutation == "rebind"
        lock.rename(tmp_path / "retained-original")
        lock.touch(mode=0o600)
    assert not lock.exists() if mutation == "missing" else lock.exists()


@pytest.mark.parametrize("entry", ["unseal", "enroll", "wipe"])
def test_tpm_mutating_entrypoints_share_exclusion(watchdog, monkeypatch, entry):
    module, lock = watchdog
    tpm = load("serialized_tpm_vault", "secure-tpm-vault.py")
    for name in ("_LOCK_PATH", "_OWNER_UID", "_OWNER_GID", "_ACQUIRE_SECONDS"):
        monkeypatch.setattr(tpm.vault_operation, name, getattr(module.vault_operation, name))
    body = Mock(return_value=0)
    monkeypatch.setattr(tpm, "_" + entry + "_held", body)
    with held_elsewhere(lock), pytest.raises(tpm.vault_operation.VaultOperationError):
        if entry == "unseal":
            tpm.unseal()
        elif entry == "enroll":
            tpm.enroll(allow_vtpm=False, allow_insecure_boot=False)
        else:
            tpm.wipe("REMOVE-TPM2-UNLOCK")
    body.assert_not_called()


def test_setup_exec_keeps_lock_through_failure_cleanup(tmp_path):
    helper = tmp_path / "vault-operation-lock.py"
    lock = tmp_path / "vault-operation.lock"
    lock.touch(mode=0o600)
    source = (SCRIPTS / helper.name).read_text()
    source = source.replace('Path("/run/secure-ai/vault-operation.lock")', f'Path({str(lock)!r})')
    source = source.replace('_OWNER_UID = _OWNER_GID = 0',
                            f'_OWNER_UID = {os.geteuid()}\n_OWNER_GID = {os.getegid()}')
    # Only the fixture's installed fixed path/owner constants are substituted.
    helper.write_text(source)
    setup = tmp_path / "setup-vault.sh"
    setup.write_text('#!/bin/bash\nset -e\n'
                     + f'{sys.executable} -B {helper} validate-setup\n'
                     + 'trap \'echo cleanup; read -r done\' EXIT\nexit 1\n')
    setup.chmod(0o700)
    child = subprocess.Popen([sys.executable, "-B", str(helper), "setup", "/dev/fixture-only"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "cleanup"
        with lock.open("r+") as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        child.communicate("done\n", timeout=5)
    assert child.returncode == 1
    with lock.open("r+") as contender:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_installed_setup_handoff_precedes_vault_observation_and_is_fixed():
    source = (SCRIPTS / "setup-vault.sh").read_text()
    assert source.index('vault-operation-lock.py setup "$@"') < source.index('PARTITION="$1"')
    assert 'vault-operation-lock.py validate-setup || exit 1' in source
    assert 'trap cleanup EXIT INT TERM' in source
    unit = (SCRIPTS.parents[1] / "lib/systemd/system/secure-ai-vault-relock.service").read_text()
    assert 'ReadWritePaths=/run/secure-ai/vault-operation.lock' not in unit
    assert 'ProtectSystem=strict' in unit  # Read-only flock needs no sandbox widening.
    tmpfiles = (SCRIPTS.parents[1] / "lib/tmpfiles.d/secure-ai.conf").read_text()
    assert any(line.split() == ['f', '/run/secure-ai/vault-operation.lock', '0600', 'root', 'root', '-', '-']
               for line in tmpfiles.splitlines())


def test_operation_uses_readonly_fd_but_excludes_other_processes(watchdog):
    module, lock = watchdog
    with module.vault_operation.operation() as held:
        assert fcntl.fcntl(held.fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        with pytest.raises(OSError):
            os.write(held.fd, b"must not enter the lock file")
        with lock.open("r") as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert lock.read_bytes() == b""


def test_mutation_child_retains_exclusion_after_owner_is_killed(watchdog, tmp_path):
    _, lock = watchdog
    release = tmp_path / "release-child"
    child_code = (
        "import os,pathlib,sys,time; "
        "os.fstat(int(sys.argv[1])); print('child='+str(os.getpid()),flush=True); "
        "release=pathlib.Path(sys.argv[2]); "
        "exec('while not release.exists(): time.sleep(.01)')"
    )
    owner_code = f'''
import importlib.util,os,pathlib,subprocess,sys
sys.path.insert(0,{str(SCRIPTS)!r})
spec=importlib.util.spec_from_file_location('vault_owner',pathlib.Path({str(SCRIPTS)!r})/'vault-watchdog.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.vault_operation._LOCK_PATH=pathlib.Path({str(lock)!r})
module.vault_operation._OWNER_UID=os.geteuid()
module.vault_operation._OWNER_GID=os.getegid()
module.audit_event=lambda *a,**kw: None
module.write_state=lambda *a,**kw: True
module.vault_mount_state=lambda: ('expected','mapper')
module.stop_services=lambda: True
real_run=subprocess.run
def fake_mutation(argv,**kwargs):
    assert argv==['sync']
    fd=kwargs['pass_fds'][0]
    return real_run([sys.executable,'-B','-c',{child_code!r},str(fd),{str(release)!r}],**kwargs)
module.subprocess.run=fake_mutation
module.lock_vault('fixture-owner')
'''
    owner = subprocess.Popen([sys.executable, "-B", "-c", owner_code], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    child_fd = -1
    try:
        assert select.select([owner.stdout], [], [], 5)[0]
        line = owner.stdout.readline().strip()
        assert line.startswith("child=")
        child_fd = os.pidfd_open(int(line.removeprefix("child=")))
        owner.kill()
        owner.wait(timeout=5)
        with lock.open("r") as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        release.touch()
        if owner.poll() is None:
            owner.kill()
        if child_fd >= 0:
            for signum in (signal.SIGTERM, signal.SIGKILL):
                if select.select([child_fd], [], [], 2)[0]:
                    break
                signal.pidfd_send_signal(child_fd, signum)
            assert select.select([child_fd], [], [], 2)[0], "owned fixture child did not exit"
            os.close(child_fd)
        owner.communicate(timeout=5)
    with lock.open("r") as contender:
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

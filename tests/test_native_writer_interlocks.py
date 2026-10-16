"""Real private Linux flocks; manager/cgroup and expected root IDs are fixtures."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

from test_native_writer_scope import Deadline, installed_manager as installed_manager, scope

ROOT = Path(__file__).parents[1]
REAL_ROOT_ONLY = scope.native.root_only


def installer_attempt(path):
    source = (ROOT / "files/scripts/secai-enable-diffusion.sh").read_text()
    block = source.split('mkdir -p "$(dirname "$LOCK_FILE")"', 1)[1].split(
        "# Rollback changes shared runtime state.", 1)[0]
    block = 'mkdir -p "$(dirname "$LOCK_FILE")"' + block
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + block + "\necho proceeded"],
                          env=os.environ | {"LOCK_FILE": str(path)}, capture_output=True,
                          text=True, timeout=5)


@contextmanager
def held_by_child(path):
    code = ("import fcntl,sys; f=open(sys.argv[1],'r'); "
            "fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); sys.stdin.read(1)")
    child = subprocess.Popen([sys.executable, "-B", "-c", code, str(path)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline().strip() == "held"
        yield
    finally:
        child.communicate("x", timeout=5)
        assert child.returncode == 0


def assert_busy(path):
    with path.open("rb") as handle, pytest.raises(BlockingIOError):
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


def assert_available(path):
    with path.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.fixture
def locks(tmp_path, monkeypatch):
    installer_parent = tmp_path / "secure-ai"
    installer_parent.mkdir(mode=0o711)
    installer = installer_parent / ".diffusion-install.lock"
    installer.touch(mode=0o600)
    vault_parent = tmp_path / "run"
    vault_parent.mkdir(mode=0o700)
    vault = vault_parent / "vault-operation.lock"
    vault.touch(mode=0o600)
    monkeypatch.setattr(scope, "_INSTALLER_PATH", installer)
    monkeypatch.setattr(scope, "_INSTALLER_OWNER_UID", os.geteuid())
    monkeypatch.setattr(scope, "_INSTALLER_OWNER_GID", os.getegid())
    monkeypatch.setattr(scope, "_INSTALLER_ACQUIRE_SECONDS", 0.05)
    monkeypatch.setattr(scope.vault_operation, "_LOCK_PATH", vault)
    monkeypatch.setattr(scope.vault_operation, "_OWNER_UID", os.geteuid())
    monkeypatch.setattr(scope.vault_operation, "_OWNER_GID", os.getegid())
    monkeypatch.setattr(scope.vault_operation, "_ACQUIRE_SECONDS", 0.05)
    monkeypatch.setattr(scope.native, "root_only", lambda: None)
    return installer, vault


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_direct_installer_contends_on_same_inode_and_timestamp_touch_is_compatible(locks, mode):
    installer, vault = locks
    installer.chmod(mode)
    os.utime(installer, ns=(1_000_000_000, 1_000_000_000))
    before = installer.stat()
    with scope.DocumentsOutputsInterlocks() as held:
        attempt = installer_attempt(installer)
        assert attempt.returncode != 0 and "proceeded" not in attempt.stdout
        assert "Another diffusion install" in attempt.stderr
        after = installer.stat()
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        assert after.st_mtime_ns != before.st_mtime_ns
        assert after.st_size == 0
        assert held.installer_held() is True and held.vault_mount_held() is True
        assert_busy(vault)
    assert installer_attempt(installer).returncode == 0
    assert_available(vault)
    with pytest.raises(scope.Error):
        held.check()
    with pytest.raises(scope.Error):
        held.scope(lambda: True)


def test_absent_installer_lock_created_private_and_never_unlinked(locks):
    installer, _vault = locks
    installer.unlink()
    with scope.DocumentsOutputsInterlocks() as held:
        identity = installer.stat()
        assert identity.st_mode & 0o7777 == 0o600 and identity.st_size == 0
        assert held.installer_held() is True
    assert installer.stat().st_ino == identity.st_ino
    assert installer_attempt(installer).returncode == 0


@pytest.mark.parametrize("busy", ["installer", "vault"])
def test_acquisition_failure_closes_all_fds_and_releases_first_lock(locks, busy):
    installer, vault = locks
    held = scope.DocumentsOutputsInterlocks()
    with held_by_child(installer if busy == "installer" else vault):
        with pytest.raises(scope.Error):
            held.__enter__()
        assert held._installer.fd == held._installer.parent == -1
        assert held._vault.fd == held._vault.parent == -1
        if busy == "vault":
            assert installer_attempt(installer).returncode == 0
        with pytest.raises(scope.Error):
            held.installer_held()
        with pytest.raises(scope.Error):
            held.vault_mount_held()
    assert_available(installer)
    assert_available(vault)
    with pytest.raises(scope.Error):
        held.__enter__()


@pytest.mark.parametrize("invalid", ["symlink", "hardlink", "directory", "fifo", "nonempty", "writable", "executable"])
def test_unsafe_installer_inode_is_not_modified_or_removed(locks, tmp_path, invalid):
    installer, vault = locks
    installer.unlink()
    target = tmp_path / "retained"
    target.write_bytes(b"retained")
    if invalid == "symlink":
        installer.symlink_to(target)
    elif invalid == "hardlink":
        os.link(target, installer)
    elif invalid == "directory":
        installer.mkdir()
    elif invalid == "fifo":
        os.mkfifo(installer, 0o600)
    elif invalid == "nonempty":
        installer.write_bytes(b"retained lock bytes")
    else:
        installer.touch(mode=0o666 if invalid == "writable" else 0o700)
        installer.chmod(0o666 if invalid == "writable" else 0o700)
    before = installer.lstat()
    held = scope.DocumentsOutputsInterlocks()
    with pytest.raises(scope.Error):
        held.__enter__()
    assert installer.lstat() == before
    assert target.read_bytes() == b"retained"
    assert held._installer.fd == held._installer.parent == -1
    assert_available(vault)


@pytest.mark.parametrize("invalid", ["writable", "symlink", "owner", "group"])
def test_unsafe_installer_parent_rejected_before_creation(locks, tmp_path, monkeypatch, invalid):
    installer, vault = locks
    installer.unlink()
    if invalid == "writable":
        installer.parent.chmod(0o777)
    elif invalid == "symlink":
        old = installer.parent.with_name("retained-parent")
        installer.parent.rename(old)
        installer.parent.symlink_to(old, target_is_directory=True)
    elif invalid == "owner":
        monkeypatch.setattr(scope, "_INSTALLER_OWNER_UID", os.geteuid() + 1)
    else:
        monkeypatch.setattr(scope, "_INSTALLER_OWNER_GID", os.getegid() + 1)
    with pytest.raises(scope.Error), scope.DocumentsOutputsInterlocks():
        pytest.fail("unsafe parent accepted")
    assert not installer.exists()
    assert_available(vault)


def test_root_authority_checked_before_creation(locks, monkeypatch):
    installer, _vault = locks
    installer.unlink()
    monkeypatch.setattr(scope.native, "root_only", REAL_ROOT_ONLY)
    monkeypatch.setattr(scope.os, "getuid", lambda: 12345)
    with pytest.raises(scope.Error), scope.DocumentsOutputsInterlocks():
        pytest.fail("nonroot accepted")
    assert not installer.exists()


@pytest.mark.parametrize("change", ["inode", "parent", "mode", "mount"])
def test_observed_installer_binding_changes_deny_and_cleanup_retains_entries(locks, monkeypatch, change):
    installer, vault = locks
    held = scope.DocumentsOutputsInterlocks().__enter__()
    try:
        if change == "inode":
            installer.rename(installer.with_name("old-lock"))
            installer.touch(mode=0o600)
        elif change == "parent":
            installer.parent.rename(installer.parent.with_name("old-parent"))
            installer.parent.mkdir(mode=0o711)
            installer.touch(mode=0o600)
        elif change == "mode":
            installer.chmod(0o644)  # Even another safe mode differs from the pinned one.
        else:
            original = scope.native.guard.mount_id
            monkeypatch.setattr(scope.native.guard, "mount_id", lambda fd: original(fd) + 1)
        identity = installer.lstat()
        with pytest.raises(scope.Error):
            held.installer_held()
    finally:
        held.close()
    assert installer.lstat() == identity
    assert_available(vault)


def test_vault_replacement_denies_future_scope_checks(locks):
    _installer, vault = locks
    held = scope.DocumentsOutputsInterlocks().__enter__()
    try:
        vault.rename(vault.with_name("old-vault-lock"))
        vault.touch(mode=0o600)
        before = vault.stat()
        with pytest.raises(scope.Error):
            held.vault_mount_held()
    finally:
        held.close()
    assert vault.stat() == before


def test_exceptional_context_exit_releases_both_without_deleting_locks(locks):
    installer, vault = locks
    with pytest.raises(ValueError), scope.DocumentsOutputsInterlocks():
        raise ValueError("fixture maintenance error")
    assert_available(installer)
    assert_available(vault)


def test_both_real_exclusions_retained_during_fixed_scope_closure(locks, installed_manager, monkeypatch):
    installer, vault = locks
    controller = None
    try:
        with scope.DocumentsOutputsInterlocks() as held:
            real_manager = scope.native.manager

            def checked(*args):
                assert_busy(installer)
                assert_busy(vault)
                return real_manager(*args)

            monkeypatch.setattr(scope.native, "manager", checked)
            controller = held.scope(lambda: installed_manager.closed)
            controller.stop_writers(Deadline(1000))
            assert controller.quiescent() is True
        assert_available(installer)
        assert_available(vault)
        with pytest.raises(scope.Error):
            controller.quiescent()
        with pytest.raises(scope.Error):
            controller.stop_writers(Deadline(1000))
    finally:
        if controller is not None:
            controller.close()


@pytest.mark.parametrize("which", ["installer", "vault"])
def test_observed_binding_failure_permanently_invalidates_capability(locks, which):
    installer, vault = locks
    held = scope.DocumentsOutputsInterlocks().__enter__()
    try:
        if which == "installer":
            installer.chmod(0o644)
            with pytest.raises(scope.Error):
                held.installer_held()
            installer.chmod(0o600)
        else:
            original = vault.parent
            moved = original.with_name("temporarily-moved-vault-parent")
            original.rename(moved)
            try:
                with pytest.raises(scope.Error):
                    held.vault_mount_held()
            finally:
                moved.rename(original)
        # A restored pathname/mode cannot prove exclusion during the observed gap.
        # The context retains both original OFDs until explicit cleanup.
        assert_busy(installer)
        assert_busy(vault)
        with pytest.raises(scope.Error):
            held.scope(lambda: True)
        with pytest.raises(scope.Error):
            held.check()
    finally:
        held.close()
    assert_available(installer)
    assert_available(vault)

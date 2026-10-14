"""Failure-safe output publication through the agent storage capability."""

import errno
import os
import stat

import pytest

from agent.agent import storage
from agent.agent.models import CapabilityToken


@pytest.fixture
def output(tmp_path):
    directory = tmp_path / "outputs"
    directory.mkdir()
    return (
        storage.StorageGateway(str(tmp_path)),
        CapabilityToken(writable_paths=[str(directory / "**")]),
        directory,
    )


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["partial-write", "fsync"])
def test_failed_write_preserves_old_or_absent_publication(output, monkeypatch, existing, failure):
    gateway, capability, directory = output
    target = directory / "report.txt"
    if existing:
        target.write_bytes(b"original bytes")
    before = target.stat() if existing else None
    write = os.write
    calls = 0

    def partial_write(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return write(fd, data[:2])
        raise OSError(errno.ENOSPC, "synthetic exhausted output storage")

    def failed_sync(_fd):
        raise OSError(errno.EIO, "synthetic output fsync failure")

    with monkeypatch.context() as faults:
        if failure == "partial-write":
            faults.setattr(storage.os, "write", partial_write)
        else:
            faults.setattr(storage.os, "fsync", failed_sync)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=existing)

    assert result["ok"] is False
    if existing:
        assert target.read_bytes() == b"original bytes"
        assert (target.stat().st_ino, target.stat().st_mode) == (before.st_ino, before.st_mode)
    else:
        assert not target.exists()
    assert sorted(path.name for path in directory.iterdir()) == (["report.txt"] if existing else [])


def test_successful_overwrite_preserves_existing_owner_group_and_mode(output):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    target.chmod(0o640)
    before = target.stat()

    result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is True
    assert target.read_bytes() == b"replacement bytes"
    after = target.stat()
    assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
        before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))


@pytest.mark.skipif(os.geteuid() == 0, reason="kernel DAC rejection requires an unprivileged caller")
def test_writable_parent_does_not_authorize_readonly_target(output):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    target.chmod(0o400)

    result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False
    assert target.read_bytes() == b"original bytes"
    assert stat.S_IMODE(target.stat().st_mode) == 0o400


def test_concurrent_target_replacement_during_preparation_is_not_overwritten(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    sync = os.fsync
    replaced = False

    def replace_before_publication(fd):
        nonlocal replaced
        sync(fd)
        if not replaced:
            replaced = True
            concurrent = directory / "concurrent.txt"
            concurrent.write_bytes(b"concurrent replacement")
            os.replace(concurrent, target)

    with monkeypatch.context() as race:
        race.setattr(storage.os, "fsync", replace_before_publication)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False
    assert target.read_bytes() == b"concurrent replacement"
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


@pytest.mark.parametrize("overwrite", [False, True])
def test_new_name_is_published_without_clobbering_a_concurrent_creator(output, monkeypatch, overwrite):
    gateway, capability, directory = output
    target = directory / "report.txt"
    sync = os.fsync
    concurrent = None

    def concurrent_create(fd):
        nonlocal concurrent
        sync(fd)
        if concurrent is None:
            target.write_bytes(b"concurrent creator")
            target.chmod(0o400)
            concurrent = target.stat()

    with monkeypatch.context() as race:
        race.setattr(storage.os, "fsync", concurrent_create)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=overwrite)

    assert result["ok"] is False
    assert target.read_bytes() == b"concurrent creator"
    assert target.stat().st_ino == concurrent.st_ino
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_inherited_setgid_staging_is_private_and_new_file_stays_private(output, monkeypatch):
    gateway, capability, directory = output
    directory.chmod(0o2770)
    target = directory / "report.txt"
    sync = os.fsync
    observed = []

    def inspect_staging(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            staged = type(target)(os.readlink(f"/proc/self/fd/{fd}"))
            observed.append(stat.S_IMODE(staged.parent.stat().st_mode))
            assert observed[-1] == 0o2700
            assert not target.exists()
        sync(fd)

    with monkeypatch.context() as inspect:
        inspect.setattr(storage.os, "fsync", inspect_staging)
        result = gateway.write_file(str(target), "new bytes", capability)

    assert result["ok"] is True and observed
    assert target.read_bytes() == b"new bytes"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.stat().st_gid == directory.stat().st_gid
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


@pytest.mark.parametrize("failure", [False, True])
def test_existing_xattrs_are_retained_or_fail_before_publication(output, monkeypatch, failure):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    try:
        os.setxattr(target, "user.agent-test", b"retained metadata")
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("fixture filesystem has no user xattrs")
        raise
    before = target.stat()

    def denied_metadata(*_args):
        raise PermissionError(errno.EPERM, "synthetic metadata retention denial")

    with monkeypatch.context() as fault:
        if failure:
            fault.setattr(storage.os, "setxattr", denied_metadata)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is not failure
    assert target.read_bytes() == (b"original bytes" if failure else b"replacement bytes")
    assert os.getxattr(target, "user.agent-test") == b"retained metadata"
    if failure:
        assert target.stat().st_ino == before.st_ino
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_directory_sync_failure_reports_publication_without_claiming_durability(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    sync = os.fsync

    def failed_directory_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "synthetic directory fsync failure")
        sync(fd)

    with monkeypatch.context() as fault:
        fault.setattr(storage.os, "fsync", failed_directory_sync)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and result["published"] is True
    assert result["durability_confirmed"] is False
    assert "published" in result["error"]
    assert target.read_bytes() == b"replacement bytes"
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_parent_replacement_does_not_redirect_publication(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    moved = directory.with_name("moved-outputs")
    sync = os.fsync

    def move_parent(fd):
        sync(fd)
        directory.rename(moved)
        directory.mkdir()

    with monkeypatch.context() as race:
        race.setattr(storage.os, "fsync", move_parent)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False
    assert not target.exists()
    assert (moved / "report.txt").read_bytes() == b"original bytes"
    assert sorted(path.name for path in moved.iterdir()) == ["report.txt"]


def test_target_symlink_inserted_during_preparation_is_not_followed(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    outside = directory.parent / "outside.txt"
    outside.write_bytes(b"outside bytes")
    sync = os.fsync

    def insert_symlink(fd):
        sync(fd)
        target.unlink()
        target.symlink_to(outside)

    with monkeypatch.context() as race:
        race.setattr(storage.os, "fsync", insert_symlink)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and target.is_symlink()
    assert outside.read_bytes() == b"outside bytes"
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_staging_collision_never_removes_an_existing_directory(output, monkeypatch):
    gateway, capability, directory = output
    existing = directory / ".agent-write-collision"
    existing.mkdir()
    monkeypatch.setattr(storage.secrets, "token_hex", lambda _size: "collision")

    result = gateway.write_file(str(directory / "report.txt"), "new bytes", capability)

    assert result["ok"] is False and existing.is_dir()
    assert sorted(path.name for path in directory.iterdir()) == [existing.name]


def test_cleanup_failure_is_reported_without_leaking_handles(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    descriptors = len(os.listdir("/proc/self/fd"))

    def fail(*_args, **_kwargs):
        raise OSError(errno.EIO, "synthetic cleanup failure")

    with monkeypatch.context() as fault:
        fault.setattr(storage.os, "fsync", fail)
        fault.setattr(storage.os, "rmdir", fail)
        result = gateway.write_file(str(target), "new bytes", capability)

    assert result["ok"] is False and "cleanup_error" in result
    assert not target.exists()
    assert len(os.listdir("/proc/self/fd")) == descriptors
    retained = type(target)(result["staging"])
    assert not list(retained.iterdir())
    retained.rmdir()


def test_rename_failure_leaves_the_existing_inode_unchanged(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    before = target.stat()

    def denied(*_args, **_kwargs):
        raise PermissionError(errno.EPERM, "synthetic publication denial")

    with monkeypatch.context() as fault:
        fault.setattr(storage.os, "replace", denied)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and not result.get("published", False)
    assert target.read_bytes() == b"original bytes" and target.stat().st_ino == before.st_ino
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_fifo_target_is_rejected_without_waiting_for_a_reader(output):
    gateway, capability, directory = output
    target = directory / "report.txt"
    os.mkfifo(target)

    result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and stat.S_ISFIFO(target.stat().st_mode)
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


def test_missing_atomic_no_clobber_support_has_no_unsafe_fallback(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"

    def unsupported(*_args):
        raise OSError(errno.ENOSYS, "synthetic missing renameat2")

    monkeypatch.setattr(gateway, "_rename_no_replace", unsupported)
    result = gateway.write_file(str(target), "new bytes", capability)

    assert result["ok"] is False and not target.exists()
    assert not list(directory.iterdir())


@pytest.mark.parametrize("phase", ["preparation", "after-publication"])
def test_staging_directory_replacement_is_never_removed(output, monkeypatch, phase):
    gateway, capability, directory = output
    directory.chmod(0o2770)
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    moved = directory / "moved-private-staging"
    sync = os.fsync
    replacement = None

    def replace_staging(fd):
        nonlocal replacement
        sync(fd)
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if replacement is None and is_directory == (phase == "after-publication"):
            pinned_path = type(target)(os.readlink(f"/proc/self/fd/{fd}"))
            stage = pinned_path if is_directory else pinned_path.parent
            stage.rename(moved)
            stage.mkdir(mode=0o700)
            replacement = stage, stage.stat().st_ino

    with monkeypatch.context() as race:
        race.setattr(storage.os, "fsync", replace_staging)
        result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and result["cleanup_ambiguous"] is True
    assert replacement is not None
    entry, inode = replacement
    assert entry.is_dir() and entry.stat().st_ino == inode and not list(entry.iterdir())
    assert moved.is_dir() and not list(moved.iterdir())
    if phase == "preparation":
        assert target.read_bytes() == b"original bytes" and not result.get("published", False)
    else:
        assert target.read_bytes() == b"replacement bytes" and result["published"] is True
        assert result["durability_confirmed"] is False


def test_unopened_staging_entry_is_left_for_explicit_cleanup(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    open_file = os.open

    def deny_stage(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith(".agent-write-"):
            raise PermissionError(errno.EACCES, "synthetic unverified staging open")
        return open_file(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(storage.os, "open", deny_stage)
        result = gateway.write_file(str(target), "new bytes", capability)

    assert result["ok"] is False and result["cleanup_ambiguous"] is True
    retained = type(target)(result["staging"])
    assert retained.is_dir() and not list(retained.iterdir()) and not target.exists()


def test_staging_requires_expected_effective_owner(output, monkeypatch):
    gateway, capability, directory = output
    target = directory / "report.txt"
    fstat = os.fstat

    def foreign_stage(fd):
        value = fstat(fd)
        if stat.S_ISDIR(value.st_mode) and ".agent-write-" in os.readlink(f"/proc/self/fd/{fd}"):
            fields = list(value)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)
        return value

    with monkeypatch.context() as fault:
        fault.setattr(storage.os, "fstat", foreign_stage)
        result = gateway.write_file(str(target), "new bytes", capability)

    assert result["ok"] is False and result["cleanup_ambiguous"] is True
    assert "caller-owned" in result["error"]
    retained = type(target)(result["staging"])
    assert retained.is_dir() and not list(retained.iterdir()) and not target.exists()


def test_non_utf8_linux_xattr_name_is_preserved(output):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    attribute = b"user.agent-nonutf8-\xff"
    try:
        os.setxattr(target, attribute, b"retained bytes")
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            pytest.skip("fixture filesystem does not support this byte xattr name")
        raise
    assert os.fsdecode(attribute) in os.listxattr(target)

    result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is True
    assert target.read_bytes() == b"replacement bytes"
    assert os.getxattr(target, attribute) == b"retained bytes"
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]


@pytest.mark.parametrize("attribute", ["security.capability", "security.ima", "security.evm"])
def test_content_bound_integrity_metadata_is_rejected_before_staging(output, monkeypatch, attribute):
    gateway, capability, directory = output
    target = directory / "report.txt"
    target.write_bytes(b"original bytes")
    before = target.stat()
    read_metadata = gateway._file_metadata

    def content_bound(fd):
        uid, gid, mode, attributes = read_metadata(fd)
        return uid, gid, mode, {**attributes, attribute: b"old-content-bound-metadata"}

    monkeypatch.setattr(gateway, "_file_metadata", content_bound)
    result = gateway.write_file(str(target), "replacement bytes", capability, overwrite=True)

    assert result["ok"] is False and "content-bound" in result["error"]
    assert target.read_bytes() == b"original bytes" and target.stat().st_ino == before.st_ino
    assert sorted(path.name for path in directory.iterdir()) == ["report.txt"]

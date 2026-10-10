import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tor_start_check", ROOT / "files/system/usr/libexec/secure-ai/tor-start-check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.mark.parametrize("value", [b"0", b"", b"2", b"1\n", b"Disabled"])
def test_only_enforcing_kernel_value_is_accepted(tmp_path, value):
    path = tmp_path / "enforce"
    path.write_bytes(value)
    with pytest.raises(check.TorStartupError, match="enforcing"):
        check.require_enforcing(path)


def test_enforcing_value_and_missing_interface(tmp_path):
    path = tmp_path / "enforce"
    path.write_bytes(b"1")
    check.require_enforcing(path)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        check.require_enforcing(path)


@pytest.fixture
def private_log(tmp_path, monkeypatch):
    path = tmp_path / "tor.log"
    path.write_bytes(b"synthetic log")
    path.chmod(0o600)
    monkeypatch.setattr(check.os, "getxattr", lambda *args, **kwargs: b"system_u:object_r:tor_var_log_t:s0\0")
    return path


def inspect(path, **kwargs):
    return check.check_path(path, os.getuid(), os.getgid(), 0o600, "tor_var_log_t", **kwargs)


def test_private_single_link_log_passes(private_log):
    assert inspect(private_log).st_size == len(b"synthetic log")


def test_wider_mode_is_rejected(private_log):
    private_log.chmod(0o640)
    with pytest.raises(check.TorStartupError, match="ownership or mode"):
        inspect(private_log)


def test_wrong_owner_is_rejected(private_log):
    with pytest.raises(check.TorStartupError, match="ownership or mode"):
        check.check_path(private_log, os.getuid() + 1, os.getgid(), 0o600, "tor_var_log_t")


def test_generic_label_is_rejected(private_log, monkeypatch):
    monkeypatch.setattr(check.os, "getxattr", lambda *args, **kwargs: b"system_u:object_r:var_lib_t:s0\0")
    with pytest.raises(check.TorStartupError, match="SELinux label"):
        inspect(private_log)


def test_hardlink_and_symlink_are_rejected(private_log):
    link = private_log.with_name("hardlink")
    os.link(private_log, link)
    with pytest.raises(check.TorStartupError, match="link count"):
        inspect(private_log)
    link.unlink()
    link.symlink_to(private_log)
    with pytest.raises(check.TorStartupError, match="file type"):
        inspect(link)


def test_symlinked_parent_is_rejected(private_log):
    alias = private_log.parent / "alias"
    alias.symlink_to(private_log.parent, target_is_directory=True)
    with pytest.raises(check.TorStartupError, match="symlinked parent"):
        inspect(alias / private_log.name)

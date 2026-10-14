"""Local native metadata planning; no native activation/labeling qualification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "files/system/usr/libexec/secure-ai/secure-native-generation-metadata.py"
SPEC = importlib.util.spec_from_file_location("generation_metadata", SOURCE)
assert SPEC and SPEC.loader
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)
INSTALLED = json.loads((ROOT / "files/system/etc/secure-ai/config/backup-inventory.json").read_text())


@pytest.fixture
def installed(monkeypatch):
    selected = copy.deepcopy(INSTALLED)

    def load(path, *, trusted):
        assert path == metadata.INVENTORY and trusted is True
        return selected

    monkeypatch.setattr(metadata.inventory, "load_inventory", load)
    monkeypatch.setattr(metadata.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=32001))
    return selected


@pytest.mark.parametrize("class_id,target,mode", [
    ("user-documents", "user_docs", 0o2750), ("user-outputs", "outputs", 0o2770),
])
def test_incoming_metadata_is_local_and_distinct_from_old_snapshot(
    tmp_path, installed, monkeypatch, class_id, target, mode
):
    observed = []
    monkeypatch.setattr(metadata, "_target_context", lambda path, directory:
                        observed.append((path, directory)) or "system_u:object_r:var_lib_t:s0")
    policy = metadata.installed_incoming_policy(class_id)
    source = tmp_path / "old"
    source.write_bytes(b"unchanged")
    source.chmod(0o600)
    before = source.stat()
    with source.open("rb") as stream:
        old = metadata.snapshot_existing(stream.fileno())
    incoming = policy.target_metadata("report x.pdf", directory=False)
    root = policy.target_metadata("", directory=True)
    assert old["uid"] == before.st_uid and old["gid"] == before.st_gid
    assert old["mode"] == 0o600
    assert incoming["uid"] == 0 and incoming["gid"] == 32001 and incoming["mode"] == 0o640
    assert root["mode"] == mode
    assert observed == [
        (Path("/var/lib/secure-ai/vault") / target / "report x.pdf", False),
        (Path("/var/lib/secure-ai/vault") / target, True),
    ]
    after = source.stat()
    assert (before.st_uid, before.st_gid, before.st_mode, before.st_ctime_ns) == (
        after.st_uid, after.st_gid, after.st_mode, after.st_ctime_ns)
    assert source.read_bytes() == b"unchanged"


@pytest.mark.parametrize("field,value", [
    ("target", "vault/models"), ("owner", "nobody"), ("group", "root"),
    ("file_mode", "0777"), ("directory_mode", "0777"),
    ("source", "etc/shadow"), ("shape", "file"), ("required", False),
])
def test_changed_installed_contract_requires_review(installed, field, value):
    item = next(item for item in installed["classes"] if item["id"] == "user-documents")
    item[field] = value
    with pytest.raises(metadata.Error):
        metadata.installed_incoming_policy("user-documents")


@pytest.mark.parametrize("class_id", ["unknown", "approved-models", {}, None])
def test_unsupported_or_malformed_class_has_no_target_authority(class_id):
    with pytest.raises(metadata.Error):
        metadata.installed_incoming_policy(class_id)


@pytest.mark.parametrize("gid", [0, -1, True, 2**32, "32001"])
def test_numeric_group_is_locally_resolved_and_validated(installed, monkeypatch, gid):
    monkeypatch.setattr(metadata.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=gid))
    with pytest.raises(metadata.Error):
        metadata.installed_incoming_policy("user-documents")


@pytest.mark.parametrize("relative", ["../x", "/tmp/x", "a/../b", "a\\b", "", "bad\0name"])
def test_archive_names_cannot_escape_or_select_native_metadata(installed, relative):
    policy = metadata.installed_incoming_policy("user-documents")
    with pytest.raises(metadata.Error):
        policy.target_metadata(relative, directory=False)


@pytest.mark.parametrize("directory,kind", [(False, "file"), (True, "dir")])
def test_context_lookup_uses_installed_raw_policy_and_typed_literal_path(monkeypatch, directory, kind):
    calls = []

    def state():
        calls.append("kernel-enforcement")
        return b"1"

    def run(command, **kwargs):
        calls.append(command)
        assert "shell" not in kwargs and kwargs["timeout"] == 5
        return SimpleNamespace(returncode=0, stdout=b"system_u:object_r:var_lib_t:s0\n", stderr=b"")

    monkeypatch.setattr(metadata.subprocess, "run", run)
    monkeypatch.setattr(metadata, "_enforcement_state", state)
    path = Path("/var/lib/secure-ai/vault/user_docs/report x;$(id).pdf")
    assert metadata._target_context(path, directory) == "system_u:object_r:var_lib_t:s0"
    assert calls == [
        "kernel-enforcement",
        ["/usr/sbin/matchpathcon", "-N", "-n", "-m", kind, str(path)],
        "kernel-enforcement",
    ]


@pytest.mark.parametrize("state", [b"0", b"", b"11", b"1\n", b"enabled"])
def test_missing_enforcement_never_yields_target_context(monkeypatch, state):
    monkeypatch.setattr(metadata, "_enforcement_state", lambda: state)
    monkeypatch.setattr(metadata.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("lookup after missing enforcement"))
    with pytest.raises(metadata.Error):
        metadata._target_context(Path("/var/lib/secure-ai/vault/user_docs"), True)


@pytest.mark.parametrize("context", [b"", b"<<none>>", b"system_u:object_r:t:s0\nextra", b"x" * 4097])
def test_incomplete_or_unbounded_context_is_not_a_target_policy(monkeypatch, context):
    monkeypatch.setattr(metadata, "_enforcement_state", lambda: b"1")
    def run(command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=context, stderr=b"")

    monkeypatch.setattr(metadata.subprocess, "run", run)
    with pytest.raises(metadata.Error):
        metadata._target_context(Path("/var/lib/secure-ai/vault/user_docs"), True)


def test_enforcement_change_during_lookup_refuses_policy(monkeypatch):
    states = iter((b"1", b"0"))
    monkeypatch.setattr(metadata, "_enforcement_state", lambda: next(states))
    monkeypatch.setattr(metadata.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=b"system_u:object_r:var_lib_t:s0", stderr=b""))
    with pytest.raises(metadata.Error):
        metadata._target_context(Path("/var/lib/secure-ai/vault/user_docs"), True)


def test_missing_local_group_has_no_root_fallback(installed, monkeypatch):
    def missing(_name):
        raise KeyError("unavailable")

    monkeypatch.setattr(metadata.grp, "getgrnam", missing)
    with pytest.raises(metadata.Error, match="group unavailable"):
        metadata.installed_incoming_policy("user-documents")


def test_expired_policy_probe_does_not_issue_another_command(monkeypatch):
    expired = False
    calls = []

    def check():
        if expired:
            raise metadata.Error("deadline expired")

    def probe(command, _maximum):
        nonlocal expired
        calls.append(command)
        expired = True
        return b"system_u:object_r:var_lib_t:s0"

    monkeypatch.setattr(metadata, "_enforcement_state", lambda: b"1")
    monkeypatch.setattr(metadata, "_probe", probe)
    with pytest.raises(metadata.Error, match="deadline expired"):
        metadata._target_context(Path("/var/lib/secure-ai/vault/user_docs"), True, check)
    assert calls == [["/usr/sbin/matchpathcon", "-N", "-n", "-m", "dir", "/var/lib/secure-ai/vault/user_docs"]]


@pytest.mark.parametrize("value", [b"1", b"0", b"", b"11"])
def test_kernel_state_reader_is_bounded(tmp_path, monkeypatch, value):
    source = tmp_path / "enforce"
    source.write_bytes(value)
    monkeypatch.setattr(metadata, "ENFORCEMENT", source)
    assert metadata._enforcement_state() == value[:2]


@pytest.mark.parametrize("kind", ["missing", "symlink", "fifo", "directory"])
def test_kernel_state_reader_rejects_unavailable_or_unsafe_object(tmp_path, monkeypatch, kind):
    source = tmp_path / "enforce"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"1")
        source.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(source, 0o600)
    elif kind == "directory":
        source.mkdir()
    monkeypatch.setattr(metadata, "ENFORCEMENT", source)
    with pytest.raises(metadata.Error):
        metadata._enforcement_state()


def test_snapshot_rejects_executable_or_hardlinked_sources(tmp_path):
    source = tmp_path / "file"
    source.write_bytes(b"data")
    source.chmod(0o700)
    with source.open("rb") as stream, pytest.raises(metadata.Error):
        metadata.snapshot_existing(stream.fileno())
    source.chmod(0o600)
    os.link(source, tmp_path / "linked")
    with source.open("rb") as stream, pytest.raises(metadata.Error):
        metadata.snapshot_existing(stream.fileno())


def test_directory_snapshot_keeps_existing_setgid_metadata(tmp_path):
    directory = tmp_path / "old"
    directory.mkdir(mode=0o700)
    directory.chmod(0o2770)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        value = metadata.snapshot_existing(fd)
    finally:
        os.close(fd)
    assert value["kind"] == "directory" and value["mode"] == 0o2770
    assert stat.S_IMODE(directory.stat().st_mode) == 0o2770

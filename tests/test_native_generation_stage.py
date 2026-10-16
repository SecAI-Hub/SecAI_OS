"""Private materializer fixtures; ordinary cases mock root ownership and SELinux.

Two Linux-root cases use real DAC with fixture policy/group lookup and mocked
SELinux. No case qualifies installed native writes, MAC policy, mounts or restore.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).parents[1] / "files/system/usr/libexec/secure-ai/secure-native-generation-stage.py"
SPEC = importlib.util.spec_from_file_location("native_generation_stage", SOURCE)
assert SPEC and SPEC.loader
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)
CONTEXT = "system_u:object_r:var_lib_t:s0"
NATIVE_ROOT_CHECK = stage._require_root
NATIVE_FCHOWN = os.fchown
NATIVE_SNAPSHOT = stage.metadata.snapshot_existing


@pytest.fixture
def tree(tmp_path, monkeypatch):
    source, parent = tmp_path / "verified-source", tmp_path / "component"
    source.mkdir(mode=0o700)
    parent.mkdir(mode=0o700)
    (source / "empty directory").mkdir(mode=0o700)
    (source / "nested").mkdir(mode=0o700)
    (source / "nested/report ü.txt").write_bytes(b"verified bytes")
    (source / "nested/report ü.txt").chmod(0o600)
    (parent / "active").mkdir(mode=0o700)
    (parent / "active/original").write_bytes(b"active bytes")
    installed = json.loads((SOURCE.parents[3] / "etc/secure-ai/config/backup-inventory.json").read_text())
    owners, labels, lookups = {}, {}, []
    original_snapshot = stage.metadata.snapshot_existing
    getxattr = os.getxattr

    def key(fd):
        info = os.fstat(fd)
        return info.st_dev, info.st_ino

    def label(fd, name, *args, **kwargs):
        if name == "security.selinux" and key(fd) in labels:
            return labels[key(fd)]
        return getxattr(fd, name, *args, **kwargs)

    def set_label(fd, name, value):
        assert name == "security.selinux"
        labels[key(fd)] = value

    def snapshot(fd):
        value = original_snapshot(fd)
        if key(fd) in owners:
            value["uid"], value["gid"] = owners[key(fd)]
        return value

    def target_context(path, directory, check=None):
        if check:
            check()
        lookups.append((path, directory))
        if check:
            check()
        return CONTEXT

    monkeypatch.setattr(stage, "_require_root", lambda: None)
    monkeypatch.setattr(stage.metadata.inventory, "load_inventory", lambda *_args, **_kwargs: installed)
    monkeypatch.setattr(stage.metadata.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=42001))
    monkeypatch.setattr(stage.metadata, "_target_context", target_context)
    monkeypatch.setattr(stage.metadata, "snapshot_existing", snapshot)
    monkeypatch.setattr(stage.os, "getxattr", label)
    monkeypatch.setattr(stage.os, "setxattr", set_label)
    monkeypatch.setattr(stage.os, "fchown", lambda fd, uid, gid: owners.__setitem__(key(fd), (uid, gid)))
    origin = stage.guard.BoundDirectory(source)
    destination = stage.guard.BoundDirectory(parent)
    try:
        yield SimpleNamespace(source=source, parent=parent, origin=origin, destination=destination,
                              owners=owners, labels=labels, lookups=lookups)
    finally:
        origin.close()
        destination.close()


def unchanged(tree):
    assert (tree.source / "nested/report ü.txt").read_bytes() == b"verified bytes"
    assert stat.S_IMODE(tree.source.stat().st_mode) == 0o700
    assert stat.S_IMODE((tree.source / "nested/report ü.txt").stat().st_mode) == 0o600
    assert (tree.parent / "active/original").read_bytes() == b"active bytes"


@pytest.mark.parametrize("prefix", [".agent-write-", ".diffusion-write-"])
def test_unfinished_output_workspace_cannot_be_published(tree, prefix):
    pending = tree.source / "nested" / (prefix + "a" * 32)
    pending.mkdir(mode=0o700)
    (pending / "payload").write_bytes(b"unfinished bytes")
    (pending / "payload").chmod(0o600)
    with pytest.raises(stage.StageError, match="unfinished output") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-outputs")
    assert error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    assert (pending / "payload").read_bytes() == b"unfinished bytes"
    unchanged(tree)


@pytest.fixture
def archive_tree(tree, tmp_path):
    spec = importlib.util.spec_from_file_location("stage_test_v3", SOURCE.with_name("secure-backup-v3.py"))
    assert spec and spec.loader
    v3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v3)
    installation = tmp_path / "archive-installation"
    for name, filename, data in (("user_docs", "nested/report ü.txt", b"document bytes\x00\xff"),
                                 ("outputs", "answer.txt", b"output bytes")):
        root = installation / "var/lib/secure-ai/vault" / name
        root.mkdir(parents=True)
        (root / "empty folder").mkdir()
        target = root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        (root / "zero bytes").touch()
    installed = stage.inventory.load_inventory(stage.metadata.INVENTORY, trusted=True)
    archive = tmp_path / "archive.tar.gz"
    manifest = v3.create_archive(installation, archive, installed,
                                 ["user-documents", "user-outputs"], "1" * 64)
    envelope = tmp_path / "verified-envelope"
    envelope.mkdir(mode=0o700)
    assert v3.read_archive(archive, installed, destination=envelope) == manifest
    origin = stage.guard.BoundDirectory(envelope)
    try:
        yield SimpleNamespace(tree=tree, source=envelope, origin=origin, manifest=manifest,
                              sha256=hashlib.sha256(v3.inventory.encode(manifest)).hexdigest(),
                              installation=installation, v3=v3, installed=installed)
    finally:
        origin.close()


@pytest.mark.parametrize("class_id,filename,data,entries", [
    ("user-documents", "nested/report ü.txt", b"document bytes\x00\xff", 5),
    ("user-outputs", "answer.txt", b"output bytes", 4),
])
def test_archive_maps_only_selected_class_using_real_v3_envelope(archive_tree, class_id, filename, data, entries):
    fixture = archive_tree
    result = stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, class_id,
                                               verified_manifest_sha256=fixture.sha256)
    incoming = fixture.tree.parent / "incoming"
    assert result["published"] is True and result["durability_confirmed"] is True
    assert result["entries"] == entries and result["bytes"] == len(data)
    assert (incoming / filename).read_bytes() == data
    assert (incoming / "zero bytes").read_bytes() == b""
    assert (incoming / "empty folder").is_dir()
    assert not (incoming / "manifest.json").exists() and not (incoming / "objects").exists()
    assert not (incoming / ("answer.txt" if class_id == "user-documents" else "nested")).exists()
    assert (fixture.source / "manifest.json").is_file()
    unchanged(fixture.tree)


@pytest.mark.parametrize("mutation", ["selected", "unselected", "manifest", "unknown-file", "unknown-directory",
                                     "symlink", "hardlink", "unsafe-mode", "unsafe-owner"])
def test_archive_mutations_do_not_publish(archive_tree, monkeypatch, mutation):
    fixture = archive_tree
    selected = next(r for r in fixture.manifest["objects"] if r["class"] == "user-documents")
    unselected = next(r for r in fixture.manifest["objects"] if r["class"] == "user-outputs")
    path = fixture.source / selected["id"]
    if mutation in {"selected", "unselected"}:
        path = fixture.source / (selected if mutation == "selected" else unselected)["id"]
        path.write_bytes(b"x" * path.stat().st_size)
    elif mutation == "manifest":
        value = json.loads((fixture.source / "manifest.json").read_text())
        value["source"]["release_sha256"] = "2" * 64
        (fixture.source / "manifest.json").write_bytes(fixture.v3.inventory.encode(value))
    elif mutation == "unknown-file":
        path = fixture.source / "surprise"
        path.write_bytes(b"unknown")
        path.chmod(0o600)
    elif mutation == "unknown-directory":
        (fixture.source / "extra").mkdir(mode=0o700)
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to(fixture.tree.source / "nested/report ü.txt")
    elif mutation == "hardlink":
        os.link(path, fixture.source / "second-link")
    elif mutation == "unsafe-mode":
        path.chmod(0o644)
    else:
        uid = os.geteuid()
        monkeypatch.setattr(stage.os, "geteuid", lambda: uid + 1)
    with pytest.raises(stage.StageError) as error:
        stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, "user-documents",
                                          verified_manifest_sha256=fixture.sha256)
    assert error.value.published is False
    assert sorted(p.name for p in fixture.tree.parent.iterdir()) == ["active"]
    assert path.exists()  # Failed verification does not remove caller-owned source data.
    unchanged(fixture.tree)


@pytest.mark.parametrize("digest", [None, "", "0" * 64, "A" * 64, True, {"sha256": "1" * 64}])
def test_archive_requires_verified_canonical_manifest_digest(archive_tree, digest):
    fixture = archive_tree
    with pytest.raises(stage.StageError):
        stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, "user-documents",
                                          verified_manifest_sha256=digest)
    assert sorted(p.name for p in fixture.tree.parent.iterdir()) == ["active"]


def test_archive_change_after_initial_verification_is_detected(archive_tree, monkeypatch):
    fixture = archive_tree
    original = os.write
    changed = False
    selected = next(r for r in fixture.manifest["objects"]
                    if r["class"] == "user-documents" and r["size"])

    def change_object(fd, data):
        nonlocal changed
        if not changed:
            changed = True
            (fixture.source / selected["id"]).write_bytes(b"x" * selected["size"])
        return original(fd, data)

    monkeypatch.setattr(stage.os, "write", change_object)
    with pytest.raises(stage.StageError):
        stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, "user-documents",
                                          verified_manifest_sha256=fixture.sha256)
    assert changed and sorted(p.name for p in fixture.tree.parent.iterdir()) == ["active"]


def test_archive_framing_does_not_consume_logical_payload_limits(archive_tree):
    fixture = archive_tree
    limits = stage.inventory.Limits(total=fixture.manifest["totals"]["bytes"],
                                    file=max(r["size"] for r in fixture.manifest["objects"]))
    assert (fixture.source / "manifest.json").stat().st_size > limits.total
    result = stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, "user-documents",
                                               verified_manifest_sha256=fixture.sha256, limits=limits)
    assert result["published"] is True and result["entries"] == 5


@pytest.mark.parametrize("limit", ["file", "total", "entries", "manifest"])
def test_archive_logical_limits_still_apply(archive_tree, limit):
    fixture = archive_tree
    with pytest.raises(stage.StageError):
        stage.materialize_archive_incoming(fixture.tree.destination, fixture.origin, "user-documents",
                                          verified_manifest_sha256=fixture.sha256,
                                          limits=stage.inventory.Limits(**{limit: 1}))
    assert sorted(p.name for p in fixture.tree.parent.iterdir()) == ["active"]


def test_archive_empty_selected_root_and_unselected_class(archive_tree, tmp_path):
    fixture = archive_tree
    root = tmp_path / "empty-installation"
    (root / "var/lib/secure-ai/vault/user_docs").mkdir(parents=True)
    archive = tmp_path / "empty.tar.gz"
    manifest = fixture.v3.create_archive(root, archive, fixture.installed, ["user-documents"], "1" * 64)
    envelope = tmp_path / "empty-envelope"
    envelope.mkdir(mode=0o700)
    fixture.v3.read_archive(archive, fixture.installed, destination=envelope)
    origin = stage.guard.BoundDirectory(envelope)
    try:
        digest = hashlib.sha256(fixture.v3.inventory.encode(manifest)).hexdigest()
        with pytest.raises(stage.StageError):
            stage.materialize_archive_incoming(fixture.tree.destination, origin, "user-outputs",
                                              verified_manifest_sha256=digest)
        result = stage.materialize_archive_incoming(fixture.tree.destination, origin, "user-documents",
                                                   verified_manifest_sha256=digest)
        assert result["entries"] == 1 and result["bytes"] == 0
        assert list((fixture.tree.parent / "incoming").iterdir()) == []
    finally:
        origin.close()


@pytest.mark.parametrize("class_id,mode,canonical", [
    ("user-documents", 0o2750, "user_docs"), ("user-outputs", 0o2770, "outputs"),
])
def test_materializes_only_local_policy_and_keeps_source_and_active(tree, class_id, mode, canonical):
    result = stage.materialize_incoming(tree.destination, tree.origin, class_id)
    incoming = tree.parent / "incoming"
    assert result["published"] is True and result["durability_confirmed"] is True
    assert result["entries"] == 4 and result["bytes"] == len(b"verified bytes")
    assert (incoming / "nested/report ü.txt").read_bytes() == b"verified bytes"
    assert (incoming / "empty directory").is_dir()
    for path in (incoming, incoming / "nested", incoming / "empty directory", incoming / "nested/report ü.txt"):
        info = path.stat()
        key = info.st_dev, info.st_ino
        assert tree.owners[key] == (0, 42001)
        assert tree.labels[key] == CONTEXT.encode() + b"\0"
        assert stat.S_IMODE(info.st_mode) == (mode if path.is_dir() else 0o640)
    assert all(str(path).startswith("/var/lib/secure-ai/vault/" + canonical) for path, _ in tree.lookups)
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active", "incoming"]
    unchanged(tree)


@pytest.mark.parametrize("class_id", ["models", "unknown", None, {"destination": "/etc"}])
def test_unsupported_classes_have_no_destination_authority(tree, class_id):
    with pytest.raises(stage.StageError) as error:
        stage.materialize_incoming(tree.destination, tree.origin, class_id)
    assert error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "executable", "public-directory"])
def test_unsafe_or_nonprivate_source_is_rejected_before_output(tree, kind):
    if kind == "symlink":
        (tree.source / "link").symlink_to(tree.source / "nested/report ü.txt")
    elif kind == "hardlink":
        os.link(tree.source / "nested/report ü.txt", tree.source / "linked")
    elif kind == "fifo":
        os.mkfifo(tree.source / "pipe")
    elif kind == "executable":
        (tree.source / "nested/report ü.txt").chmod(0o700)
    else:
        (tree.source / "nested").chmod(0o750)
    with pytest.raises(stage.StageError) as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False and error.value.cleanup_error is None
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]


@pytest.mark.parametrize("limits", [{"file": 2}, {"total": 2}, {"entries": 2}, {"depth": 1}])
def test_bounds_reject_without_publishing(tree, limits):
    with pytest.raises(stage.StageError):
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents",
                                   limits=stage.inventory.Limits(**limits))
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


@pytest.mark.parametrize("failure", ["write", "ownership", "label", "file-sync"])
def test_prepublication_failure_removes_only_owned_work(tree, monkeypatch, failure):
    descriptors = len(os.listdir("/proc/self/fd"))
    def denied(*_args, **_kwargs):
        raise OSError("synthetic staging failure")

    attribute = {"write": "write", "ownership": "fchown", "label": "setxattr", "file-sync": "fsync"}[failure]
    with monkeypatch.context() as fault:
        fault.setattr(stage.os, attribute, denied)
        with pytest.raises(stage.StageError) as error:
            stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False
    assert len(os.listdir("/proc/self/fd")) == descriptors
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


def test_source_change_during_copy_is_rejected(tree, monkeypatch):
    write = os.write
    changed = False

    def change_origin(fd, data):
        nonlocal changed
        result = write(fd, data)
        if not changed:
            changed = True
            (tree.source / "nested/report ü.txt").write_bytes(b"changed bytes")
        return result

    monkeypatch.setattr(stage.os, "write", change_origin)
    with pytest.raises(stage.StageError, match="source changed") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]


@pytest.mark.parametrize("race", [False, True])
def test_existing_or_concurrent_incoming_is_never_replaced(tree, race):
    incoming = tree.parent / "incoming"

    def create_incoming(_event):
        if _event.endswith(":before-rename"):
            incoming.mkdir(mode=0o700)
            (incoming / "preserve").write_bytes(b"original incoming")

    if not race:
        create_incoming("native-stage:publish:before-rename")
    with pytest.raises(stage.StageError) as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents",
                                   io=stage.guard.DurableIO(create_incoming if race else None))
    assert error.value.published is False
    assert (incoming / "preserve").read_bytes() == b"original incoming"
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active", "incoming"]
    unchanged(tree)


def test_parent_sync_failure_retains_complete_published_incoming(tree, monkeypatch):
    sync = os.fsync

    def failed_parent_sync(fd):
        if os.readlink(f"/proc/self/fd/{fd}") == str(tree.parent):
            raise OSError("synthetic parent fsync failure")
        sync(fd)

    monkeypatch.setattr(stage.os, "fsync", failed_parent_sync)
    with pytest.raises(stage.StageError) as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is True and error.value.durability_confirmed is False
    assert (tree.parent / "incoming/nested/report ü.txt").read_bytes() == b"verified bytes"
    unchanged(tree)


def test_workspace_substitution_is_not_followed_or_recursively_cleaned(tree, monkeypatch):
    write = os.write
    replaced = None

    def replace_workspace(fd, data):
        nonlocal replaced
        result = write(fd, data)
        if replaced is None:
            work = next(path for path in tree.parent.iterdir() if path.name.startswith(".secai-native-stage-"))
            retained = tree.parent / "retained-private-work"
            work.rename(retained)
            work.mkdir(mode=0o700)
            replaced = work, work.stat().st_ino, retained
        return result

    monkeypatch.setattr(stage.os, "write", replace_workspace)
    with pytest.raises(stage.StageError) as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False and error.value.cleanup_error
    replacement, inode, retained = replaced
    assert replacement.is_dir() and replacement.stat().st_ino == inode and not list(replacement.iterdir())
    assert (retained / "tree/nested/report ü.txt").read_bytes() == b"verified bytes"
    assert not (tree.parent / "incoming").exists()
    unchanged(tree)


def test_corrupted_staged_bytes_are_rejected_by_final_readback(tree, monkeypatch):
    sync = os.fsync
    corrupted = False

    def corrupt_file(fd):
        nonlocal corrupted
        sync(fd)
        if not corrupted and stat.S_ISREG(os.fstat(fd).st_mode):
            corrupted = True
            os.pwrite(fd, b"CORRUPT", 0)

    monkeypatch.setattr(stage.os, "fsync", corrupt_file)
    with pytest.raises(stage.StageError, match="bytes changed before publication") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


@pytest.mark.parametrize("operation", ["fchown", "setxattr"])
def test_ignored_native_metadata_application_does_not_publish(tree, monkeypatch, operation):
    monkeypatch.setattr(stage.os, operation, lambda *_args: None)
    with pytest.raises(stage.StageError, match="metadata differs") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


def test_expiry_during_policy_lookup_prevents_further_lookup_or_publication(tree, monkeypatch):
    class Deadline:
        expired = False

        def check(self):
            if self.expired:
                raise stage.Error("synthetic operation deadline expired")

    deadline = Deadline()
    context = stage.metadata._target_context
    calls = []

    def expiring(*args, **kwargs):
        value = context(*args, **kwargs)
        calls.append(True)
        deadline.expired = True
        return value

    monkeypatch.setattr(stage.metadata, "_target_context", expiring)
    with pytest.raises(stage.StageError, match="deadline expired") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents", deadline=deadline)
    assert calls == [True] and error.value.published is False
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


def test_unknown_work_entries_block_publication_and_recursive_cleanup(tree, monkeypatch):
    sync = os.fsync
    injected = None

    def insert_unknown(fd):
        nonlocal injected
        sync(fd)
        if injected is None and stat.S_ISREG(os.fstat(fd).st_mode):
            work = next(path for path in tree.parent.iterdir() if path.name.startswith(".secai-native-stage-"))
            injected = work / "unknown-entry"
            injected.write_bytes(b"preserve unknown data")

    monkeypatch.setattr(stage.os, "fsync", insert_unknown)
    with pytest.raises(stage.StageError, match="unknown staging entries") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert error.value.published is False and error.value.cleanup_error
    assert injected.read_bytes() == b"preserve unknown data"
    assert not (tree.parent / "incoming").exists()
    unchanged(tree)


@pytest.mark.parametrize("unknown", [False, True])
def test_post_rename_hook_failure_reports_publication_or_unknown_state(tree, unknown):
    retained = tree.parent / "retained-published"

    def after_rename(event):
        if event.endswith(":after-rename"):
            if unknown:
                (tree.parent / "incoming").rename(retained)
            raise OSError("synthetic failure after kernel rename")

    with pytest.raises(stage.StageError, match="after kernel rename") as error:
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents",
                                   io=stage.guard.DurableIO(after_rename))
    assert error.value.published is (None if unknown else True)
    assert error.value.durability_confirmed is False
    incoming = retained if unknown else tree.parent / "incoming"
    assert (incoming / "nested/report ü.txt").read_bytes() == b"verified bytes"
    if unknown:
        assert error.value.cleanup_error and Path(error.value.workspace).is_dir()
    unchanged(tree)


@pytest.mark.skipif(os.getuid() == 0 and os.geteuid() == 0, reason="ordinary-UID root-authority rejection")
def test_real_root_guard_rejects_unprivileged_materialization(tree, monkeypatch):
    monkeypatch.setattr(stage, "_require_root", NATIVE_ROOT_CHECK)
    with pytest.raises(stage.Error, match="root authority"):
        stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


@pytest.mark.parametrize("suffix,allowed", [
    (b"", True), (b"\0", True), (b"\0\0", False), (b" ", False), (b"\0extra", False),
])
def test_kernel_label_getter_requires_the_exact_whole_context(tree, monkeypatch, suffix, allowed):
    getter = os.getxattr

    def kernel_label(fd, name, *args, **kwargs):
        info = os.fstat(fd)
        key = info.st_dev, info.st_ino
        if name == "security.selinux" and key in tree.labels:
            value = tree.labels[key]
            assert value.endswith(b"\0")
            return value[:-1] + suffix
        return getter(fd, name, *args, **kwargs)

    monkeypatch.setattr(stage.os, "getxattr", kernel_label)
    if allowed:
        assert stage.materialize_incoming(tree.destination, tree.origin, "user-documents")["published"] is True
        assert (tree.parent / "incoming/nested/report ü.txt").read_bytes() == b"verified bytes"
    else:
        with pytest.raises(stage.StageError, match="metadata differs") as error:
            stage.materialize_incoming(tree.destination, tree.origin, "user-documents")
        assert error.value.published is False
        assert sorted(path.name for path in tree.parent.iterdir()) == ["active"]
    unchanged(tree)


@pytest.mark.skipif(sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0,
                    reason="isolated Linux root DAC fixture required")
@pytest.mark.parametrize("class_id,mode", [("user-documents", 0o2750), ("user-outputs", 0o2770)],
                         ids=["documents", "outputs"])
def test_root_materialization_uses_real_dac(tree, monkeypatch, class_id, mode):
    monkeypatch.setattr(stage, "_require_root", NATIVE_ROOT_CHECK)
    monkeypatch.setattr(stage.os, "fchown", NATIVE_FCHOWN)
    monkeypatch.setattr(stage.metadata, "snapshot_existing", NATIVE_SNAPSHOT)
    before = {path.relative_to(tree.source): stage.inventory.identity(path.stat())
              for path in (tree.source, *tree.source.rglob("*"))}
    active = stage.inventory.identity((tree.parent / "active/original").stat())

    result = stage.materialize_incoming(tree.destination, tree.origin, class_id)

    assert result["published"] is True and result["durability_confirmed"] is True
    assert tree.owners == {}, "the ownership mock must not have been used"
    incoming = tree.parent / "incoming"
    for path in (incoming, *incoming.rglob("*")):
        info = path.stat()
        assert info.st_uid == 0 and info.st_gid == 42001
        assert stat.S_IMODE(info.st_mode) == (mode if path.is_dir() else 0o640)
        assert tree.labels[(info.st_dev, info.st_ino)] == CONTEXT.encode() + b"\0"
    assert (incoming / "nested/report ü.txt").read_bytes() == b"verified bytes"
    after = {path.relative_to(tree.source): stage.inventory.identity(path.stat())
             for path in (tree.source, *tree.source.rglob("*"))}
    assert after == before
    assert stage.inventory.identity((tree.parent / "active/original").stat()) == active
    assert sorted(path.name for path in tree.parent.iterdir()) == ["active", "incoming"]
    unchanged(tree)

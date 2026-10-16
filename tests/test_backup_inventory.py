"""Synthetic adversarial qualification of v3 inert archive boundaries."""

from __future__ import annotations

import copy
import gzip
import importlib.util
import io
import os
import stat
import subprocess
import sys
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO = Path(__file__).resolve().parents[1]
HELPERS = REPO / "files/system/usr/libexec/secure-ai"
SPEC = importlib.util.spec_from_file_location("backup_v3_test", HELPERS / "secure-backup-v3.py")
assert SPEC and SPEC.loader
v3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v3)
inv = v3.inventory
CONFIG = REPO / "files/system/etc/secure-ai/config/backup-inventory.json"


@pytest.fixture
def policy():
    return inv.load_inventory(CONFIG)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "installation"
    docs = root / "var/lib/secure-ai/vault/user_docs"
    docs.mkdir(parents=True)
    (docs / "日本語 notes").mkdir()
    (docs / "日本語 notes/cafe\u0301 résumé.txt").write_bytes(b"synthetic document\x00\xff")
    (docs / "empty folder").mkdir()
    (docs / "zero bytes").touch()
    return root


@pytest.fixture
def artifact(tmp_path, source, policy):
    path = tmp_path / "v3.tar.gz"
    manifest = v3.create_archive(source, path, policy, ["user-documents"], "1" * 64)
    return path, manifest


def repack(path, source, manifest=None, raw_manifest=None, extra=None):
    with tarfile.open(source, "r:gz") as archive:
        content = [(m.name, archive.extractfile(m).read()) for m in archive]
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in content:
            if name == "manifest.json":
                data = raw_manifest if raw_manifest is not None else inv.encode(manifest)
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o600, len(data)
            archive.addfile(item, io.BytesIO(data))
        if extra:
            member, data = extra
            archive.addfile(member, io.BytesIO(data))


def assert_rejected(path, policy, tmp_path, match=None, limits=None):
    destination = tmp_path / "inert-stage"
    destination.mkdir(mode=0o700)
    with pytest.raises(v3.ArchiveError, match=match):
        v3.read_archive(path, policy, destination=destination, limits=limits)
    assert list(destination.iterdir()) == []


def test_exact_unicode_spaces_binary_and_empty_directories(artifact, source, policy, tmp_path):
    path, manifest = artifact
    assert v3.read_archive(path, policy) == manifest
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    assert v3.read_archive(path, policy, destination=stage) == manifest
    records = {r["path"]: r for r in manifest["objects"]}
    original = source / "var/lib/secure-ai/vault/user_docs"
    for name, record in records.items():
        assert (stage / record["id"]).read_bytes() == (original / name).read_bytes()
        assert stat.S_IMODE((stage / record["id"]).stat().st_mode) == 0o600
    assert "日本語 notes/cafe\u0301 résumé.txt" in records
    assert {r["path"] for r in manifest["directories"]} == {"", "日本語 notes", "empty folder"}
    assert manifest["consistency"]["status"] == "partial_unquiesced"
    assert manifest["consistency"]["active_restore"] is False
    assert set(manifest["classes"]) == {c["id"] for c in policy["classes"]}
    assert manifest["classes"]["sessions"]["disposition"] == "excluded_authority"
    assert manifest["classes"]["catalog-history"]["reason"] == "unsupported_adapter_partial_export"


def test_exact_local_dac_and_destination_mapping(policy):
    docs = inv.local_policy(policy, "user-documents")
    output = inv.local_policy(policy, "user-outputs")
    assert docs["target"] == "vault/user_docs" and docs["group"] == "secure-ai-vault-read"
    assert docs["directory_mode"] == "2750" and docs["file_mode"] == "0640"
    assert output["group"] == "secure-ai-vault-write" and output["directory_mode"] == "2770"
    logs = next(c for c in policy["classes"] if c["id"] == "audit-evidence")
    assert logs["directory_mode"] == "3770"  # Source planning metadata only.
    with pytest.raises(v3.ArchiveError, match="DAC adapter"):
        inv.local_policy(policy, "audit-evidence")
    with pytest.raises(v3.ArchiveError):
        inv.local_policy(policy, "../../credentials")


def test_empty_is_existing_root_not_missing(tmp_path, policy):
    root = tmp_path / "source"
    docs = root / "var/lib/secure-ai/vault/user_docs"
    docs.mkdir(parents=True)
    value = v3.create_archive(root, tmp_path / "empty.gz", policy, ["user-documents"], "1" * 64)
    assert value["classes"]["user-documents"]["disposition"] == "empty"
    docs.rmdir()
    with pytest.raises(FileNotFoundError):
        v3.create_archive(root, tmp_path / "missing.gz", policy, ["user-documents"], "1" * 64)
    assert not (tmp_path / "missing.gz").exists()


@pytest.mark.parametrize("selection", [["sessions"], ["catalog-history"], ["audit-evidence"], ["login-credential"], ["invented"]])
def test_unimplemented_or_authority_classes_cannot_export(selection, tmp_path, policy, source):
    with pytest.raises(v3.ArchiveError):
        v3.create_archive(source, tmp_path / "absent.gz", policy, selection, "1" * 64)
    assert not (tmp_path / "absent.gz").exists()


def test_full_is_disabled_before_source_access(tmp_path, policy):
    with pytest.raises(v3.ArchiveError, match="requires maintenance"):
        v3.create_archive(tmp_path / "missing", tmp_path / "absent", policy,
                          ["user-documents"], "1" * 64, kind="full")
    assert list(tmp_path.iterdir()) == []


def test_unknown_root_requires_classification(source, policy, tmp_path):
    (source / "var/lib/secure-ai/unknown-producer").mkdir()
    with pytest.raises(v3.ArchiveError, match="unknown managed"):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64)
    assert not (tmp_path / "bad.gz").exists()


@pytest.mark.parametrize("kind", ["symlink", "parent-symlink", "hardlink", "fifo", "executable", "xattr", "nested-mount"])
def test_source_escape_and_metadata_rejected(kind, source, policy, tmp_path, monkeypatch):
    docs = source / "var/lib/secure-ai/vault/user_docs"
    if kind == "symlink":
        (docs / "escape").symlink_to(tmp_path)
    elif kind == "parent-symlink":
        saved = docs.with_name("moved")
        docs.rename(saved)
        docs.symlink_to(saved)
    elif kind == "hardlink":
        outside = tmp_path / "outside"
        outside.write_bytes(b"private")
        os.link(outside, docs / "link")
    elif kind == "fifo":
        os.mkfifo(docs / "pipe")
    elif kind == "executable":
        (docs / "zero bytes").chmod(0o700)
    elif kind == "xattr":
        os.setxattr(docs / "zero bytes", "user.unsupported", b"x")
    else:
        original = inv.mount_id

        def changed(fd):
            return original(fd) + (1 if os.readlink(f"/proc/self/fd/{fd}").endswith("empty folder") else 0)

        monkeypatch.setattr(inv, "mount_id", changed)
    with pytest.raises((v3.ArchiveError, OSError)):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64)
    assert not (tmp_path / "bad.gz").exists()


@pytest.mark.parametrize("names", [("File", "file"), ("café", "cafe\u0301")])
def test_ambiguous_filename_sets_rejected(names, source, policy, tmp_path):
    docs = source / "var/lib/secure-ai/vault/user_docs"
    for name in names:
        (docs / name).touch()
    with pytest.raises(v3.ArchiveError, match="collision"):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64)


@pytest.mark.parametrize("name", ["/absolute", "../escape", "a//b", "a/./b", "a/../b", "a\\b", "a\x00b", "\ud800", "x" * 241, "/".join(["d"] * 33), "/".join(["x" * 100] * 21)])
def test_fixed_component_path_depth_and_encoding_bounds(name):
    with pytest.raises(v3.ArchiveError):
        inv.relative_name(name, inv.Limits())


@pytest.mark.parametrize("limits", [dict(file=1), dict(total=1), dict(entries=2), dict(manifest=128), dict(archive=32)])
def test_export_bounds_prevent_completed_artifact(limits, source, policy, tmp_path):
    with pytest.raises(v3.ArchiveError):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64, inv.Limits(**limits))
    assert not (tmp_path / "bad.gz").exists()


def test_space_preflight_before_copy(source, policy, tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fstatvfs", lambda fd: SimpleNamespace(f_bavail=0, f_frsize=4096, f_favail=10))
    monkeypatch.setattr(v3, "_member", lambda *args: pytest.fail("source bytes copied before space preflight"))
    with pytest.raises(v3.ArchiveError, match="insufficient staging"):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64)
    assert not (tmp_path / "bad.gz").exists()


def test_same_size_source_change_detected(source, policy, tmp_path, monkeypatch):
    original = inv.SourceTree.file

    @contextmanager
    def mutate(self, record):
        with original(self, record) as fd:
            yield fd
            if record["size"]:
                (self.root / record["path"]).write_bytes(b"x" * record["size"])

    monkeypatch.setattr(inv.SourceTree, "file", mutate)
    with pytest.raises(v3.ArchiveError, match="source changed"):
        v3.create_archive(source, tmp_path / "bad.gz", policy, ["user-documents"], "1" * 64)
    assert not (tmp_path / "bad.gz").exists()


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(format_version=True),
    lambda m: m.update(inventory_version=True),
    lambda m: m.update(kind="full"),
    lambda m: m.update(created_at="yesterday"),
    lambda m: m.update(snapshot_started_at="9999-01-01T00:00:00+00:00"),
    lambda m: m.update(inventory_sha256="0" * 64),
    lambda m: m["source"].update(adapter="sandbox-v1"),
    lambda m: m["source"].update(schemas={"bytes": True}),
    lambda m: m["classes"].pop("sessions"),
    lambda m: m["classes"].update(unknown={}),
    lambda m: m["classes"]["user-documents"].update(files=True),
    lambda m: m["classes"]["sessions"].update(disposition="included"),
    lambda m: m["classes"]["user-documents"].update(disposition="reacquire"),
    lambda m: m["totals"].update(bytes=True),
    lambda m: m["objects"][0].update(size=True),
    lambda m: m["objects"][0].update(uid=0),
    lambda m: m["objects"][0].update(mode=0o777),
    lambda m: m["objects"][0].update(path="../escape"),
    lambda m: m["objects"][0].update(id="../../file"),
    lambda m: m["objects"][0].update(**{"class": "sessions"}),
    lambda m: m["objects"][0].update(sha256="0" * 64),
    lambda m: m["directories"].clear(),
    lambda m: m["objects"].append(copy.deepcopy(m["objects"][0])),
    lambda m: m["consistency"].update(active_restore=True),
    lambda m: m["consistency"].update(active_restore=0),
    lambda m: m.update(luks_header={"uuid": "fake"}),
    lambda m: m["historical_evidence"].update(status="verified"),
])
def test_manifest_contract_rejections(mutation, artifact, policy, tmp_path):
    original, manifest = artifact
    manifest = copy.deepcopy(manifest)
    mutation(manifest)
    path = tmp_path / "bad.gz"
    repack(path, original, manifest)
    assert_rejected(path, policy, tmp_path)


@pytest.mark.parametrize("bad", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}', b'{"x":-1e999}', b"[" * 2000 + b"]" * 2000])
def test_strict_json_rejects_duplicate_nonfinite_and_depth(bad):
    with pytest.raises(v3.ArchiveError):
        inv.strict_json(bad, 8192)


@pytest.mark.parametrize("kind", ["gzip-junk", "gzip-concatenated", "gzip-truncated", "tar-junk", "late-header", "one-zero", "nonzero-padding"])
def test_closed_stream_and_late_header_rejections(kind, artifact, policy, tmp_path):
    original, _manifest = artifact
    compressed = original.read_bytes()
    raw = gzip.decompress(compressed)
    with tarfile.open(original, "r:gz") as a:
        last = a.getmembers()[-1]
        end = last.offset_data + ((last.size + 511) // 512) * 512
    if kind == "gzip-junk":
        data = compressed + b"junk"
    elif kind == "gzip-concatenated":
        data = compressed + gzip.compress(b"hidden")
    elif kind == "gzip-truncated":
        data = compressed[:-1]
    elif kind == "tar-junk":
        data = gzip.compress(raw + b"hidden")
    elif kind == "late-header":
        data = gzip.compress(raw[:end] + b"invalid header" + raw[end + 14:])
    elif kind == "one-zero":
        data = gzip.compress(raw[:end + 512])
    else:
        with tarfile.open(original, "r:gz") as a:
            first = next(m for m in a if m.size % 512)
        offset = first.offset_data + first.size
        data = gzip.compress(raw[:offset] + b"X" + raw[offset + 1:])
    bad = tmp_path / "bad.gz"
    bad.write_bytes(data)
    assert_rejected(bad, policy, tmp_path)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE, tarfile.GNUTYPE_SPARSE, tarfile.GNUTYPE_LONGNAME, tarfile.XHDTYPE, tarfile.XGLTYPE])
def test_tar_extensions_and_link_types_rejected(member_type, artifact, policy, tmp_path):
    original, manifest = artifact
    member = tarfile.TarInfo("objects/99999999")
    member.type, member.mode = member_type, 0o600
    bad = tmp_path / "bad.gz"
    repack(bad, original, manifest, extra=(member, b""))
    assert_rejected(bad, policy, tmp_path, "non-regular")


def test_duplicate_payload_rejected(artifact, policy, tmp_path):
    original, manifest = artifact
    member = tarfile.TarInfo(manifest["objects"][0]["id"])
    member.mode = 0o600
    bad = tmp_path / "bad.gz"
    repack(bad, original, manifest, extra=(member, b""))
    assert_rejected(bad, policy, tmp_path, "duplicate")


@pytest.mark.parametrize("limits", [dict(file=1), dict(total=1), dict(entries=1), dict(manifest=1024), dict(archive=32)])
def test_read_bounds_cleanup_partial_stage(limits, artifact, policy, tmp_path):
    assert_rejected(artifact[0], policy, tmp_path, limits=inv.Limits(**limits))


def test_input_mutation_rejected_after_parse(artifact, policy, tmp_path, monkeypatch):
    path, _manifest = artifact
    original = v3.parse_tar

    def mutate(*args):
        result = original(*args)
        with path.open("ab") as handle:
            handle.write(b"change")
        return result

    monkeypatch.setattr(v3, "parse_tar", mutate)
    assert_rejected(path, policy, tmp_path, "changed")


@pytest.mark.parametrize("command", ["full", "config", "logs", "keys"])
def test_active_restore_gates_before_any_external_action(command, tmp_path):
    marker = tmp_path / "command-ran"
    fake = tmp_path / "bin"
    fake.mkdir()
    for name in ["cryptsetup", "systemctl", "id", "python3", "age"]:
        executable = fake / name
        executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
        executable.chmod(0o755)
    result = subprocess.run(["/bin/bash", str(HELPERS / "secai-restore.sh"), command, str(tmp_path / "missing.age"),
                             "--restore-luks-header", "--vault-device", "/dev/synthetic", "--confirm-luks-uuid", "fake"],
                            env={"PATH": str(fake)}, capture_output=True, timeout=5)
    assert result.returncode == 1 and b"Active restore unavailable" in result.stderr
    assert not marker.exists()


def test_helper_apply_gates_before_staging_or_target_access(tmp_path):
    result = subprocess.run([sys.executable, str(HELPERS / "secure-backup-archive.py"), "apply",
                             "--staging", str(tmp_path / "missing"), "--category", "full",
                             "--etc-root", str(tmp_path / "target")], capture_output=True, timeout=5)
    assert result.returncode == 1 and b"active restore unavailable" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_compressed_expansion_is_bounded_before_tar_completion(policy, tmp_path):
    bad = tmp_path / "bomb.gz"
    bad.write_bytes(gzip.compress(bytes(4 * 1024**2)))
    assert_rejected(bad, policy, tmp_path, "expanded tar", inv.Limits(total=1024, manifest=1024, entries=1))


def test_parser_deadline_removes_stage(artifact, policy, tmp_path, monkeypatch):
    original = inv.Budget.check

    def expired(self):
        self.deadline = 0
        original(self)

    monkeypatch.setattr(inv.Budget, "check", expired)
    assert_rejected(artifact[0], policy, tmp_path, "deadline")


def test_output_cannot_be_inside_selected_source(source, policy):
    output = source / "var/lib/secure-ai/vault/user_docs/recursive.gz"
    with pytest.raises(v3.ArchiveError, match="outside included"):
        v3.create_archive(source, output, policy, ["user-documents"], "1" * 64)
    assert not output.exists()


def test_v3_stage_changed_after_stream_is_rejected(artifact, policy, tmp_path, monkeypatch):
    original = v3.Stage.verify
    record = artifact[1]["objects"][0]

    def corrupt(self, expected, budget):
        (self.path / record["id"]).write_bytes(b"corrupt")
        original(self, expected, budget)

    monkeypatch.setattr(v3.Stage, "verify", corrupt)
    assert_rejected(artifact[0], policy, tmp_path, "staged object")


def test_source_parent_replacement_after_capture_removes_output(source, policy, tmp_path, monkeypatch):
    original = inv.SourceTree.verify

    def replace_root(self):
        self.root.rename(self.root.with_name("replaced"))
        self.root.mkdir()
        original(self)

    monkeypatch.setattr(inv.SourceTree, "verify", replace_root)
    output = tmp_path / "changed.gz"
    with pytest.raises(v3.ArchiveError, match="source root changed"):
        v3.create_archive(source, output, policy, ["user-documents"], "1" * 64)
    assert not output.exists()


def test_legacy_source_copy_has_limits_before_payload_copy(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_bytes(b"x" * 1000)
    destination = tmp_path / "destination"
    destination.mkdir(mode=0o700)
    with pytest.raises(v3.ArchiveError, match="per-file"):
        v3.copy_legacy_source(source, destination, inv.Limits(file=10))
    assert list(destination.iterdir()) == []
    v3.copy_legacy_source(source, destination)
    copied = destination / source.absolute().relative_to("/") / "file"
    assert copied.read_bytes() == b"x" * 1000
    assert stat.S_IMODE(copied.stat().st_mode) == 0o600


@pytest.mark.parametrize("prefix", [".agent-write-", ".diffusion-write-"])
@pytest.mark.parametrize("nested", [False, True])
def test_unfinished_output_workspaces_block_export(source, policy, tmp_path, prefix, nested):
    root = source / "var/lib/secure-ai/vault/outputs"
    root.mkdir()
    workspace = root / ("nested" if nested else "") / (prefix + "a" * 32)
    workspace.mkdir(parents=True, mode=0o700)
    payload = workspace / "payload.mp4"
    payload.write_bytes(b"unfinished private encoder bytes")
    output = tmp_path / "unfinished.gz"
    with pytest.raises(v3.ArchiveError, match="unfinished output"):
        v3.create_archive(source, output, policy, ["user-outputs"], "1" * 64)
    assert not output.exists()
    assert payload.read_bytes() == b"unfinished private encoder bytes"


@pytest.mark.parametrize("prefix", [".agent-write-", ".diffusion-write-"])
@pytest.mark.parametrize("directory", [False, True])
def test_unfinished_output_names_rejected_in_archive(source, policy, tmp_path, prefix, directory):
    root = source / "var/lib/secure-ai/vault/outputs"
    root.mkdir()
    if directory:
        (root / "ordinary").mkdir()
        (root / "ordinary/result.png").write_bytes(b"retained output")
    else:
        (root / "ordinary").write_bytes(b"retained output")
    original = tmp_path / "ordinary.gz"
    manifest = v3.create_archive(source, original, policy, ["user-outputs"], "1" * 64)
    reserved = prefix + "b" * 32
    for record in manifest["directories"] + manifest["objects"]:
        if record["class"] == "user-outputs" and record["path"].startswith("ordinary"):
            record["path"] = reserved + record["path"][len("ordinary"):]
    changed = tmp_path / "unfinished.gz"
    repack(changed, original, manifest)
    assert_rejected(changed, policy, tmp_path, match="unfinished output")


def test_workspace_spelling_is_preserved_in_documents_and_ordinary_outputs(source, policy, tmp_path):
    docs = source / "var/lib/secure-ai/vault/user_docs"
    (docs / ".diffusion-write-not-an-output").write_bytes(b"ordinary document")
    outputs = source / "var/lib/secure-ai/vault/outputs"
    outputs.mkdir()
    (outputs / "result.png").write_bytes(b"complete output")
    (outputs / ".ordinary-hidden-output").write_bytes(b"hidden user output")
    archive = tmp_path / "ordinary.gz"
    manifest = v3.create_archive(source, archive, policy,
                                 ["user-documents", "user-outputs"], "1" * 64)
    assert v3.read_archive(archive, policy) == manifest
    assert any(record["path"] == ".diffusion-write-not-an-output"
               and record["class"] == "user-documents" for record in manifest["objects"])

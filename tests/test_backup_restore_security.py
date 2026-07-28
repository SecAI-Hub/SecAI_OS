"""Adversarial tests for the encrypted backup archive boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/secure-backup-archive.py"
)
SPEC = importlib.util.spec_from_file_location("secure_backup_archive", HELPER_PATH)
assert SPEC and SPEC.loader
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)


def _tar_with_members(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as output:
        for member, data in members:
            output.addfile(member, io.BytesIO(data))


def _regular_member(name: str, data: bytes) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o600
    return member


def test_round_trip_uses_exact_manifest_and_safe_modes(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    source = staging / "etc/secure-ai/policy/policy.yaml"
    source.parent.mkdir(parents=True)
    source.write_text("version: 1\n", encoding="utf-8")
    source.chmod(0o777)
    output = tmp_path / "backup.tar.gz"

    created = archive.create_archive(staging, output, "config", None)
    verified = archive.verify_archive(output)
    assert verified == created
    assert verified["files"]["etc/secure-ai/policy/policy.yaml"]["size"] == 11

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    archive.extract_archive(output, extracted)
    restored = extracted / "etc/secure-ai/policy/policy.yaml"
    assert restored.read_text(encoding="utf-8") == "version: 1\n"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600


def test_create_rejects_symlink_source(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (staging / "link").symlink_to(outside)

    with pytest.raises(archive.ArchiveError, match="symbolic links"):
        archive.create_archive(staging, tmp_path / "backup.tar.gz", "config", None)


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../../etc/shadow",
        "/etc/shadow",
        "etc/secure-ai/../shadow",
        r"etc\secure-ai\policy",
    ],
)
def test_verify_rejects_path_traversal(tmp_path: Path, unsafe_name: str) -> None:
    payload = b"owned"
    bad = tmp_path / "bad.tar.gz"
    _tar_with_members(bad, [(_regular_member(unsafe_name, payload), payload)])

    with pytest.raises(archive.ArchiveError, match="archive member|path"):
        archive.verify_archive(bad)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_verify_rejects_non_regular_members(
    tmp_path: Path, member_type: bytes
) -> None:
    member = tarfile.TarInfo("etc/secure-ai/policy/bad")
    member.type = member_type
    if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
        member.linkname = "/etc/shadow"
    bad = tmp_path / "bad.tar.gz"
    _tar_with_members(bad, [(member, b"")])

    with pytest.raises(archive.ArchiveError, match="non-regular"):
        archive.verify_archive(bad)


def test_verify_rejects_duplicate_members(tmp_path: Path) -> None:
    name = "etc/secure-ai/policy/policy.yaml"
    bad = tmp_path / "duplicate.tar.gz"
    _tar_with_members(
        bad,
        [
            (_regular_member(name, b"first"), b"first"),
            (_regular_member(name, b"second"), b"second"),
        ],
    )
    with pytest.raises(archive.ArchiveError, match="duplicate"):
        archive.verify_archive(bad)


def test_verify_rejects_payload_not_authenticated_by_manifest(tmp_path: Path) -> None:
    name = "etc/secure-ai/policy/policy.yaml"
    payload = b"tampered"
    manifest = {
        "format": "secai-backup",
        "format_version": archive.FORMAT_VERSION,
        "category": "config",
        "created_at": "2026-07-27T00:00:00+00:00",
        "source_host": "test",
        "file_count": 1,
        "total_size": len(payload),
        "luks_header": {"included": False, "uuid": ""},
        "files": {
            name: {
                "sha256": "0" * 64,
                "size": len(payload),
            }
        },
    }
    manifest_data = json.dumps(manifest).encode()
    bad = tmp_path / "tampered.tar.gz"
    _tar_with_members(
        bad,
        [
            (_regular_member(name, payload), payload),
            (_regular_member("manifest.json", manifest_data), manifest_data),
        ],
    )
    with pytest.raises(archive.ArchiveError, match="does not match manifest"):
        archive.verify_archive(bad)


def test_extract_requires_empty_real_destination(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "file").write_text("data", encoding="utf-8")
    backup = tmp_path / "backup.tar.gz"
    archive.create_archive(staging, backup, "logs", None)

    destination = tmp_path / "destination"
    destination.mkdir()
    (destination / "existing").write_text("keep", encoding="utf-8")
    with pytest.raises(archive.ArchiveError, match="empty"):
        archive.extract_archive(backup, destination)


def test_apply_rejects_symlink_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging = tmp_path / "staging"
    policy = staging / "etc/secure-ai/policy/policy.yaml"
    policy.parent.mkdir(parents=True)
    policy.write_text("version: 1\n", encoding="utf-8")
    manifest = {
        "files": {
            "etc/secure-ai/policy/policy.yaml": {
                "sha256": "0" * 64,
                "size": policy.stat().st_size,
            }
        }
    }
    (staging / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    etc_root = tmp_path / "etc"
    outside = tmp_path / "outside"
    outside.write_text("do not overwrite", encoding="utf-8")
    target = etc_root / "secure-ai/policy/policy.yaml"
    target.parent.mkdir(parents=True)
    target.symlink_to(outside)
    secure_root = tmp_path / "secure-ai"
    monkeypatch.setattr(archive, "_fixed_owner", lambda _relative: (os.geteuid(), os.getegid()))

    with pytest.raises(archive.ArchiveError, match="non-regular target"):
        archive.apply_restore(staging, "config", etc_root, secure_root)
    assert outside.read_text(encoding="utf-8") == "do not overwrite"


def test_apply_rolls_back_all_prior_files_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    appliance = staging / "etc/secure-ai/config/appliance.yaml"
    policy = staging / "etc/secure-ai/policy/policy.yaml"
    appliance.parent.mkdir(parents=True)
    policy.parent.mkdir(parents=True)
    appliance.write_text("new: appliance\n", encoding="utf-8")
    policy.write_text("new: policy\n", encoding="utf-8")
    files = {
        "etc/secure-ai/config/appliance.yaml": {
            "sha256": "0" * 64,
            "size": appliance.stat().st_size,
        },
        "etc/secure-ai/policy/policy.yaml": {
            "sha256": "0" * 64,
            "size": policy.stat().st_size,
        },
    }
    (staging / "manifest.json").write_text(json.dumps({"files": files}), encoding="utf-8")

    etc_root = tmp_path / "etc"
    existing = etc_root / "secure-ai/config/appliance.yaml"
    existing.parent.mkdir(parents=True)
    existing.write_text("old: appliance\n", encoding="utf-8")
    secure_root = tmp_path / "secure-ai"
    monkeypatch.setattr(archive, "_fixed_owner", lambda _relative: (os.geteuid(), os.getegid()))
    original_copy = archive._copy_atomic
    failed = False

    def fail_on_policy(source: Path, target: Path, mode: int, uid: int, gid: int) -> None:
        nonlocal failed
        if target.name == "policy.yaml" and not failed:
            failed = True
            raise OSError("simulated media failure")
        original_copy(source, target, mode, uid, gid)

    monkeypatch.setattr(archive, "_copy_atomic", fail_on_policy)
    with pytest.raises(archive.ArchiveError, match="rolled back"):
        archive.apply_restore(staging, "config", etc_root, secure_root)
    assert existing.read_text(encoding="utf-8") == "old: appliance\n"
    assert not (etc_root / "secure-ai/policy/policy.yaml").exists()

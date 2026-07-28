"""Focused tests for the exact encrypted-vault mount gate."""

from __future__ import annotations

import importlib.util
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER_PATH = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
    / "verify-vault-mount.py"
)
SPEC = importlib.util.spec_from_file_location("vault_mount_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def test_crypttab_requires_one_canonical_uuid_entry(monkeypatch):
    content = (
        b"# appliance vault\n"
        b"secure-ai-vault UUID=01234567-89ab-cdef-0123-456789abcdef "
        b"none luks,tpm2-device=auto,tpm2-pcrs=0+2+4+7\n"
    )
    monkeypatch.setattr(verifier, "read_bounded_regular", lambda *_args: content)

    assert verifier.crypttab_uuid() == "01234567-89ab-cdef-0123-456789abcdef"


@pytest.mark.parametrize(
    "content",
    [
        (
            b"secure-ai-vault UUID=01234567-89ab-cdef-0123-456789abcdef "
            b"none luks,discard\n"
        ),
        (
            b"secure-ai-vault UUID=01234567-89ab-cdef-0123-456789abcdef none luks\n"
            b"secure-ai-vault UUID=11234567-89ab-cdef-0123-456789abcdef none luks\n"
        ),
        b"secure-ai-vault /dev/sda3 none luks\n",
        b"secure-ai-vault UUID=not-a-uuid none luks\n",
    ],
)
def test_crypttab_rejects_ambiguous_or_weakened_entries(monkeypatch, content):
    monkeypatch.setattr(verifier, "read_bounded_regular", lambda *_args: content)

    with pytest.raises(verifier.VaultVerificationError):
        verifier.crypttab_uuid()


def test_findmnt_must_report_expected_mapper_and_hardened_options(monkeypatch):
    output = json.dumps(
        {
            "filesystems": [
                {
                    "source": "/dev/mapper/secure-ai-vault",
                    "fstype": "ext4",
                    "options": "rw,nosuid,nodev,noexec,relatime",
                }
            ]
        }
    ).encode()
    completed = SimpleNamespace(returncode=0, stdout=output, stderr=b"")
    monkeypatch.setattr(verifier.subprocess, "run", lambda *_args, **_kwargs: completed)

    mount = verifier.mounted_filesystem()

    assert mount["source"] == "/dev/mapper/secure-ai-vault"
    assert mount["fstype"] == "ext4"


@pytest.mark.parametrize(
    ("source", "fstype", "options"),
    [
        ("/dev/mapper/lookalike", "ext4", "rw,nosuid,nodev,noexec"),
        ("/dev/mapper/secure-ai-vault", "xfs", "rw,nosuid,nodev,noexec"),
        ("/dev/mapper/secure-ai-vault", "ext4", "rw,nosuid,nodev"),
        ("/dev/mapper/secure-ai-vault", "ext4", "ro,nosuid,nodev,noexec"),
    ],
)
def test_findmnt_rejects_wrong_identity_filesystem_or_options(
    monkeypatch, source, fstype, options
):
    output = json.dumps(
        {
            "filesystems": [
                {"source": source, "fstype": fstype, "options": options}
            ]
        }
    ).encode()
    completed = SimpleNamespace(returncode=0, stdout=output, stderr=b"")
    monkeypatch.setattr(verifier.subprocess, "run", lambda *_args, **_kwargs: completed)

    with pytest.raises(verifier.VaultVerificationError):
        verifier.mounted_filesystem()


def test_marker_is_uuid_mapper_and_schema_bound(monkeypatch):
    initialized = datetime.now(UTC).isoformat()
    marker = json.dumps(
        {
            "initialized_at": initialized,
            "luks_uuid": "01234567-89ab-cdef-0123-456789abcdef",
            "mapper": "secure-ai-vault",
            "mount_point": "/var/lib/secure-ai/vault",
            "schema_version": 1,
        }
    ).encode()
    monkeypatch.setattr(verifier, "read_bounded_regular", lambda *_args: marker)

    verifier.verify_marker("01234567-89ab-cdef-0123-456789abcdef")


@pytest.mark.parametrize(
    "mutation",
    [
        {"luks_uuid": "11234567-89ab-cdef-0123-456789abcdef"},
        {"mapper": "lookalike"},
        {"mount_point": "/tmp/vault"},
        {"schema_version": 2},
        {"initialized_at": "not-a-time"},
    ],
)
def test_marker_rejects_invalid_binding_or_schema(monkeypatch, mutation):
    payload = {
        "initialized_at": datetime.now(UTC).isoformat(),
        "luks_uuid": "01234567-89ab-cdef-0123-456789abcdef",
        "mapper": "secure-ai-vault",
        "mount_point": "/var/lib/secure-ai/vault",
        "schema_version": 1,
    }
    payload.update(mutation)
    marker = json.dumps(payload).encode()
    monkeypatch.setattr(verifier, "read_bounded_regular", lambda *_args: marker)

    with pytest.raises(verifier.VaultVerificationError):
        verifier.verify_marker("01234567-89ab-cdef-0123-456789abcdef")


class _FakeVaultPath:
    def __init__(self, name: str, entries: dict[str, tuple[int, int]]) -> None:
        self.name = name
        self.entries = entries

    def lstat(self):
        if self.name == "":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o711,
                st_uid=0,
                st_gid=0,
            )
        mode, group_id = self.entries[self.name]
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | mode,
            st_uid=0,
            st_gid=group_id,
        )

    def __truediv__(self, name: str):
        return _FakeVaultPath(name, self.entries)


def test_directory_contract_is_exact(monkeypatch):
    group_ids = {
        "secure-ai-registry": 1001,
        "secure-ai-registry-containment": 1002,
        "secure-ai-vault-read": 1003,
        "secure-ai-vault-write": 1004,
    }
    entries = {
        name: (mode, group_ids[group_name])
        for name, (mode, group_name) in verifier.REQUIRED_DIRECTORIES.items()
    }
    monkeypatch.setattr(verifier, "MOUNT_POINT", _FakeVaultPath("", entries))
    monkeypatch.setattr(
        verifier.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=group_ids[name]),
    )

    verifier.verify_directories()


def test_directory_contract_rejects_mode_drift(monkeypatch):
    group_ids = {
        "secure-ai-registry": 1001,
        "secure-ai-registry-containment": 1002,
        "secure-ai-vault-read": 1003,
        "secure-ai-vault-write": 1004,
    }
    entries = {
        name: (mode, group_ids[group_name])
        for name, (mode, group_name) in verifier.REQUIRED_DIRECTORIES.items()
    }
    entries["models"] = (0o777, group_ids["secure-ai-registry"])
    monkeypatch.setattr(verifier, "MOUNT_POINT", _FakeVaultPath("", entries))
    monkeypatch.setattr(
        verifier.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=group_ids[name]),
    )

    with pytest.raises(verifier.VaultVerificationError):
        verifier.verify_directories()

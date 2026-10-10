"""Focused tests for the exact encrypted-vault mount gate."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import struct
import subprocess
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


def model_reader_acl(gid=1234, permission=5):
    entries = [(1,7,0xffffffff), (4,7,0xffffffff), (8,permission,gid),
               (16,7,0xffffffff), (32,0,0xffffffff)]
    return struct.pack('<I', 2)+b''.join(struct.pack('<HHI', *entry) for entry in entries)


def test_model_reader_acl_is_an_exact_read_only_role():
    verifier.validate_model_reader_acl(model_reader_acl(), 1234)
    for raw in [b'', model_reader_acl(permission=7), model_reader_acl(gid=5678),
                model_reader_acl()+struct.pack('<HHI',2,7,1234),
                struct.pack('<I',1)+model_reader_acl()[4:]]:
        with pytest.raises(verifier.VaultVerificationError):
            verifier.validate_model_reader_acl(raw, 1234)


def test_fresh_vault_acl_survives_private_promotion_and_rename(tmp_path):
    """Real Linux inheritance, including private transaction directories and mode0640."""
    if not shutil.which('setfacl'):
        pytest.skip('native ACL tool unavailable')
    reader = 2**31-17
    models = tmp_path/'models'
    models.mkdir(mode=0o2770)
    models.chmod(0o2770)
    grants = f'g:{reader}:r-x,m::rwx,d:u::rwx,d:g::rwx,d:g:{reader}:r-x,d:m::rwx,d:o::---'
    subprocess.run(['setfacl','-m',grants,str(models)], check=True, capture_output=True, timeout=3)
    for attribute in ['system.posix_acl_access','system.posix_acl_default']:
        verifier.validate_model_reader_acl(os.getxattr(models, attribute), reader)
    transaction = models/'.promotion-test'
    transaction.mkdir(mode=0o700)
    temporary = transaction/'artifact'
    descriptor = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o640)
    os.write(descriptor, b'private model fixture')
    os.close(descriptor)
    final = models/'approved.gguf'
    temporary.rename(final)
    raw = os.getxattr(final,'system.posix_acl_access')
    grants = [struct.unpack_from('<HHI',raw,offset) for offset in range(4,len(raw),8)]
    named = next(permission for tag,permission,gid in grants if tag == 8 and gid == reader)
    mask = next(permission for tag,permission,_gid in grants if tag == 16)
    assert named & mask == 4  # readable, never writable/executable
    assert final.stat().st_mode & 0o777 == 0o640

"""Tests for the persistent credential-storage encryption gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "libexec"
    / "secure-ai"
    / "verify-host-state-encryption.py"
)
SPEC = importlib.util.spec_from_file_location("host_state_encryption", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def _findmnt_result(device_id: str = "253:0"):
    output = json.dumps(
        {
            "filesystems": [
                {
                    "maj:min": device_id,
                    "source": "/dev/mapper/host-state",
                    "fstype": "ext4",
                }
            ]
        }
    ).encode()
    return SimpleNamespace(returncode=0, stdout=output, stderr=b"")


def test_direct_luks_mapping_is_accepted(tmp_path, monkeypatch):
    device = tmp_path / "253:0"
    (device / "dm").mkdir(parents=True)
    (device / "slaves").mkdir()
    (device / "dm" / "uuid").write_text(
        "CRYPT-LUKS2-0123456789abcdef-secai-host-state",
        encoding="ascii",
    )
    monkeypatch.setattr(verifier, "SYS_DEV_BLOCK", tmp_path)
    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *_args, **_kwargs: _findmnt_result(),
    )

    assert verifier.verify() == "253:0"


def test_lvm_above_luks_is_accepted(tmp_path, monkeypatch):
    logical = tmp_path / "253:1"
    encrypted = tmp_path / "253:0"
    (logical / "slaves").mkdir(parents=True)
    (encrypted / "slaves").mkdir(parents=True)
    (encrypted / "dm").mkdir()
    (encrypted / "dm" / "uuid").write_text(
        "CRYPT-LUKS2-0123456789abcdef-secai-host-state",
        encoding="ascii",
    )
    (logical / "slaves" / "encrypted").symlink_to(encrypted)
    monkeypatch.setattr(verifier, "SYS_DEV_BLOCK", tmp_path)
    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *_args, **_kwargs: _findmnt_result("253:1"),
    )

    assert verifier.verify() == "253:1"


def test_plain_block_storage_is_rejected(tmp_path, monkeypatch):
    device = tmp_path / "8:1"
    (device / "slaves").mkdir(parents=True)
    monkeypatch.setattr(verifier, "SYS_DEV_BLOCK", tmp_path)
    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *_args, **_kwargs: _findmnt_result("8:1"),
    )

    with pytest.raises(
        verifier.HostStateEncryptionError,
        match="not demonstrably LUKS-backed",
    ):
        verifier.verify()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{}",
        b'{"filesystems":[]}',
        b'{"filesystems":[{"maj:min":"not-a-device"}]}',
        b'{"filesystems":[{"maj:min":"253:0"},{"maj:min":"253:1"}]}',
    ],
)
def test_malformed_or_ambiguous_findmnt_is_rejected(monkeypatch, payload):
    result = SimpleNamespace(returncode=0, stdout=payload, stderr=b"")
    monkeypatch.setattr(
        verifier.subprocess,
        "run",
        lambda *_args, **_kwargs: result,
    )

    with pytest.raises(verifier.HostStateEncryptionError):
        verifier.backing_device_id()

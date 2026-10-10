"""Real age protocol with ephemeral fixture keys and private process failures."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import time
import json
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("backup_age_test", REPO / "files/system/usr/libexec/secure-ai/secure-backup-v3.py")
assert SPEC and SPEC.loader
v3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v3)


@pytest.fixture
def age():
    configured = os.environ.get("SECAI_AGE_TEST_BINARY")
    path = configured or shutil.which("age")
    if configured:
        assert Path(configured).is_file(), "configured age qualification binary is missing"
    if not path:
        pytest.skip("real age unavailable; set SECAI_AGE_TEST_BINARY for protocol qualification")
    return str(Path(path).resolve())


def keypair(age, root, name):
    keygen = str(Path(age).with_name("age-keygen"))
    identity = root / name
    result = subprocess.run([keygen, "-o", str(identity)], capture_output=True, timeout=10)
    assert result.returncode == 0
    result = subprocess.run([keygen, "-y", str(identity)], capture_output=True, timeout=10)
    assert result.returncode == 0
    return identity, result.stdout.decode("ascii").strip()


@pytest.fixture
def encrypted(age, tmp_path):
    tmp_path.chmod(0o700)
    identity, recipient = keypair(age, tmp_path, "identity")
    source = tmp_path / "synthetic"
    source.write_bytes(bytes(range(256)) * 1000)
    source.chmod(0o600)
    output = tmp_path / "synthetic.age"
    receipt = v3.age_transform(source, output, decrypt=False, recipient=recipient, age_binary=age)
    assert receipt["integrity"] == "created_not_restore_verified"
    return identity, recipient, source, output, receipt


def no_partial(root):
    assert not list(root.glob(".age-partial-*"))


def test_real_age_roundtrip_exact_receipt_and_no_implicit_origin(age, encrypted, tmp_path):
    identity, _recipient, source, ciphertext, receipt = encrypted
    output = tmp_path / "plaintext"
    result = v3.age_transform(ciphertext, output, decrypt=True, identity=identity, age_binary=age)
    assert output.read_bytes() == source.read_bytes()
    assert result["origin"] == "origin_unverified" and result["integrity"] == "age_verified"
    assert result["active_restore"] is False and result["freshness"] == "not_established"
    trusted = tmp_path / "trusted-plaintext"
    result = v3.age_transform(ciphertext, trusted, decrypt=True, identity=identity,
                              expected_sha256=receipt["sha256"], age_binary=age)
    assert result["origin"] == "trusted_receipt_match"
    assert trusted.read_bytes() == source.read_bytes()
    no_partial(tmp_path)


@pytest.mark.parametrize("damage", ["wrong-key", "truncated-final-tag", "header-bitflip", "middle-bitflip", "final-bitflip"])
def test_actual_age_failures_publish_nothing(damage, age, encrypted, tmp_path):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    data = bytearray(ciphertext.read_bytes())
    if damage == "wrong-key":
        identity, _other = keypair(age, tmp_path, "wrong-identity")
    elif damage == "truncated-final-tag":
        data = data[:-1]
    else:
        index = {"header-bitflip": 12, "middle-bitflip": len(data) // 2, "final-bitflip": len(data) - 1}[damage]
        data[index] ^= 1
    damaged = tmp_path / "damaged.age"
    damaged.write_bytes(data)
    output = tmp_path / "must-not-publish"
    with pytest.raises(v3.ArchiveError, match="age integrity"):
        v3.age_transform(damaged, output, decrypt=True, identity=identity, age_binary=age)
    assert not output.exists()
    no_partial(tmp_path)


def test_public_recipient_attacker_archive_does_not_match_independent_receipt(age, encrypted, tmp_path):
    identity, recipient, _source, _ciphertext, trusted_receipt = encrypted
    attacker = tmp_path / "attacker-content"
    attacker.write_bytes(b"new archive created using only the public recipient")
    substituted = tmp_path / "substitute.age"
    v3.age_transform(attacker, substituted, decrypt=False, recipient=recipient, age_binary=age)
    digest = hashlib.sha256(substituted.read_bytes()).hexdigest()
    untrusted = tmp_path / "inert"
    result = v3.age_transform(substituted, untrusted, decrypt=True, identity=identity,
                              transport_sha256=digest, age_binary=age)
    assert result["origin"] == "origin_unverified"
    with pytest.raises(v3.ArchiveError, match="trusted recovery receipt digest mismatch"):
        v3.age_transform(substituted, tmp_path / "rejected", decrypt=True, identity=identity,
                          expected_sha256=trusted_receipt["sha256"], age_binary=age)
    assert not (tmp_path / "rejected").exists()


@pytest.mark.parametrize("limits", [dict(ciphertext=100), dict(archive=100)])
def test_ciphertext_and_plaintext_limits_bound_real_age(limits, age, encrypted, tmp_path):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    with pytest.raises(v3.ArchiveError, match="size limit"):
        v3.age_transform(ciphertext, tmp_path / "limited", decrypt=True, identity=identity,
                          age_binary=age, limits=v3.Limits(**limits))
    assert not (tmp_path / "limited").exists()
    no_partial(tmp_path)


def test_decryption_child_deadline_kills_and_reaps(age, encrypted, tmp_path, monkeypatch):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    fake = tmp_path / "sleeping-age"
    fake.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(60)\n")
    fake.chmod(0o700)
    launched = []
    original = subprocess.Popen

    def record(*args, **kwargs):
        proc = original(*args, **kwargs)
        launched.append(proc)
        # No private identity path or key bytes enter the child arguments.
        assert str(identity) not in repr(args)
        assert identity.read_text().splitlines()[-1] not in repr(args)
        return proc

    monkeypatch.setattr(subprocess, "Popen", record)
    started = time.monotonic()
    with pytest.raises(v3.ArchiveError, match="deadline"):
        v3.age_transform(ciphertext, tmp_path / "timeout", decrypt=True, identity=identity,
                          age_binary=str(fake), limits=v3.Limits(seconds=1))
    assert time.monotonic() - started < 5
    assert len(launched) == 1 and launched[0].returncode == -9
    with pytest.raises(ChildProcessError):
        os.waitpid(launched[0].pid, os.WNOHANG)
    assert not (tmp_path / "timeout").exists()
    no_partial(tmp_path)


def test_child_exit_failure_never_publishes(age, encrypted, tmp_path):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    fake = tmp_path / "failing-age"
    fake.write_text("#!/usr/bin/python3\nimport os\nos.write(1,b'partial plaintext')\nraise SystemExit(7)\n")
    fake.chmod(0o700)
    with pytest.raises(v3.ArchiveError, match="age integrity"):
        v3.age_transform(ciphertext, tmp_path / "failed", decrypt=True, identity=identity, age_binary=str(fake))
    assert not (tmp_path / "failed").exists()
    no_partial(tmp_path)


def test_input_mutation_between_hash_and_child_is_detected(age, encrypted, tmp_path, monkeypatch):
    _identity, recipient, source, _ciphertext, _receipt = encrypted
    original = subprocess.Popen

    def mutate(*args, **kwargs):
        source.write_bytes(b"changed" + source.read_bytes()[7:])
        return original(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", mutate)
    with pytest.raises(v3.ArchiveError, match="input changed"):
        v3.age_transform(source, tmp_path / "mutated.age", decrypt=False, recipient=recipient, age_binary=age)
    assert not (tmp_path / "mutated.age").exists()
    no_partial(tmp_path)


def test_private_staging_and_identity_required(age, encrypted, tmp_path):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(v3.ArchiveError, match="private"):
        v3.age_transform(ciphertext, public / "output", decrypt=True, identity=identity, age_binary=age)
    identity.chmod(0o644)
    with pytest.raises(v3.ArchiveError, match="private"):
        v3.age_transform(ciphertext, tmp_path / "output", decrypt=True, identity=identity, age_binary=age)
    assert not (tmp_path / "output").exists()


def test_fsync_failure_reaps_child_and_removes_plaintext(age, encrypted, tmp_path, monkeypatch):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    original = os.fsync

    def fail(fd):
        if ".age-partial-" in os.readlink(f"/proc/self/fd/{fd}"):
            raise OSError("synthetic storage failure")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="synthetic storage"):
        v3.age_transform(ciphertext, tmp_path / "failed-fsync", decrypt=True, identity=identity, age_binary=age)
    assert not (tmp_path / "failed-fsync").exists()
    no_partial(tmp_path)


def test_real_cli_partial_export_decrypt_and_inert_extract(age, encrypted, tmp_path):
    identity, recipient, _source, _ciphertext, _receipt = encrypted
    installation = tmp_path / "installation"
    docs = installation / "var/lib/secure-ai/vault/user_docs"
    docs.mkdir(parents=True)
    (docs / "saved notes.txt").write_bytes(b"synthetic data")
    (docs / "empty").mkdir()
    working = tmp_path / "working"
    working.mkdir(mode=0o700)
    output = tmp_path / "export.age"
    helper = REPO / "files/system/usr/libexec/secure-ai/secure-backup-archive.py"
    config = REPO / "files/system/etc/secure-ai/config/backup-inventory.json"
    env = {**os.environ, "PATH": str(Path(age).parent) + ":/usr/bin:/bin"}

    def invoke(*args):
        result = subprocess.run([sys.executable, str(helper), *map(str, args)], env=env, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr.decode()
        return json.loads(result.stdout)

    created = invoke("export-inert", "--root", installation, "--classes", "user-documents",
                     "--release-sha256", "1" * 64, "--inventory", config,
                     "--staging-root", working, "--recipient", recipient, "--output", output)
    assert created["coverage"] == "partial_unquiesced" and created["active_restore"] is False
    assert list(working.iterdir()) == []
    plaintext = working / "validated.tar.gz"
    checked = invoke("decrypt", "--archive", output, "--identity", identity,
                     "--trusted-sha256", created["sha256"], "--output", plaintext)
    assert checked["origin"] == "trusted_receipt_match"
    stage = working / "objects"
    stage.mkdir(mode=0o700)
    extracted = invoke("extract-v3", "--archive", plaintext, "--inventory", config, "--destination", stage)
    manifest = extracted["manifest"]
    record = manifest["objects"][0]
    assert record["path"] == "saved notes.txt"
    assert (stage / record["id"]).read_bytes() == b"synthetic data"
    assert {r["path"] for r in manifest["directories"]} == {"", "empty"}


@pytest.mark.parametrize("sidecar", [None, b"invalid\n", b"0" * 64 + b"  synthetic.age\n"])
def test_cli_transport_sidecar_missing_malformed_or_mismatched(age, encrypted, tmp_path, sidecar):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    checksum = tmp_path / "checksum"
    if sidecar is not None:
        checksum.write_bytes(sidecar)
    output = tmp_path / "rejected"
    result = subprocess.run([sys.executable, str(REPO / "files/system/usr/libexec/secure-ai/secure-backup-archive.py"),
                             "decrypt", "--archive", str(ciphertext), "--identity", str(identity),
                             "--transport-sidecar", str(checksum), "--output", str(output)],
                            env={**os.environ, "PATH": str(Path(age).parent) + ":/usr/bin:/bin"},
                            capture_output=True, timeout=10)
    assert result.returncode == 1
    assert not output.exists()
    no_partial(tmp_path)


def test_output_parent_replacement_does_not_publish(age, encrypted, tmp_path, monkeypatch):
    identity, _recipient, _source, ciphertext, _receipt = encrypted
    parent = tmp_path / "output-parent"
    parent.mkdir(mode=0o700)
    original = v3.inventory.check_directory_binding

    def replace(path, fd):
        if path == parent:
            parent.rename(tmp_path / "old-parent")
            parent.mkdir(mode=0o700)
        original(path, fd)

    monkeypatch.setattr(v3.inventory, "check_directory_binding", replace)
    with pytest.raises(v3.ArchiveError, match="binding changed"):
        v3.age_transform(ciphertext, parent / "plaintext", decrypt=True, identity=identity, age_binary=age)
    assert not list(parent.iterdir())
    assert not list((tmp_path / "old-parent").iterdir())

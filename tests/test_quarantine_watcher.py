"""Tests for quarantine watcher promotion helpers."""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import watcher


def _policy_bundle() -> dict:
    components = {
        "policy.yaml": "1" * 64,
        "models.lock.yaml": "2" * 64,
        "diffusion-models.lock.yaml": "3" * 64,
        "sources.allowlist.yaml": "4" * 64,
        "yara/default.yar": "5" * 64,
    }
    digest = hashlib.sha256()
    digest.update(b"SecAI-Policy-Bundle-v1\0")
    for name, component_digest in components.items():
        name_bytes = name.encode()
        digest.update(len(name_bytes).to_bytes(8, "big"))
        digest.update(name_bytes)
        digest.update(bytes.fromhex(component_digest))
    return {
        "version": 1,
        "sha256": digest.hexdigest(),
        "components": components,
    }


def _directory_hash_pin() -> dict:
    manifest = {
        "passed": True,
        "available": True,
        "trust": "image-owned-manifest-pin",
        "manifest_sha256": "a" * 64,
        "revision": "b" * 40,
        "repo_id": "owner/model",
        "variant": "fp16",
        "files_checked": 3,
        "total_size_bytes": 123,
        "sha256_files_checked": 2,
        "git_blob_files_checked": 1,
    }
    return {
        "passed": True,
        "pinned": True,
        "match": True,
        "mechanism": "image-owned-huggingface-manifest",
        "manifest_sha256": manifest["manifest_sha256"],
        "revision": manifest["revision"],
        "directory_hash_pin": {
            "passed": False,
            "reason": "remote artifact has no pinned hash",
        },
        "huggingface_manifest": manifest,
    }


def test_policy_version_id_returns_scanner_attested_bundle_hash():
    evidence = _policy_bundle()

    assert watcher._policy_version_id(
        {"policy_bundle": evidence}
    ) == evidence["sha256"]
    assert watcher._policy_version_id(
        {"policy_bundle": {"sha256": "not-a-digest"}}
    ) == ""


def test_boundary_json_rejects_duplicate_keys_and_nonfinite_numbers():
    with pytest.raises(ValueError, match="malformed JSON"):
        watcher._decode_strict_json_object(b'{"passed":true,"passed":false}')
    with pytest.raises(ValueError, match="malformed JSON"):
        watcher._decode_strict_json_object(b'{"score":NaN}')


def test_promote_to_registry_sends_string_policy_version(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 201

        def read(self, _size=-1):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=30):
        captured["payload"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(watcher, "urlopen", fake_urlopen)
    monkeypatch.setattr(watcher, "_service_headers", lambda: {})
    monkeypatch.setattr(watcher, "_extract_scanner_versions", lambda details: {})
    policy_evidence = _policy_bundle()

    ok = watcher.promote_to_registry(
        filename="example-model.gguf",
        file_hash="deadbeef",
        size_bytes=123,
        scan_results={"smoke_test": "0.0"},
        staged_filename="opaque-stage.gguf",
        pipeline_details={
            "policy_bundle": policy_evidence,
        },
    )

    assert ok is True
    assert captured["payload"]["policy_version"] == policy_evidence["sha256"]
    assert captured["payload"]["policy_bundle"] == policy_evidence
    assert captured["payload"]["staged_filename"] == "opaque-stage.gguf"


def test_process_directory_writes_status_marker_when_cleanup_fails(monkeypatch, tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    promotion_dir = tmp_path / "promotion-staging"
    artifact_dir = quarantine_dir / "tiny-diffusion"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "model_index.json").write_text('{"_class_name":"StableDiffusionXLPipeline"}')
    (artifact_dir / "unet").mkdir()
    (artifact_dir / "unet" / "diffusion_pytorch_model.safetensors").write_bytes(b"\x00" * 16)

    monkeypatch.setattr(watcher, "QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(watcher, "PROMOTION_STAGING_DIR", promotion_dir)
    monkeypatch.setattr(watcher, "sha256_of_directory", lambda path: "abc123")
    monkeypatch.setattr(
        watcher,
        "_run_scanner_worker",
        lambda *args, **kwargs: {"passed": True, "details": {}},
    )
    monkeypatch.setattr(watcher, "_build_scan_summary", lambda details: {})
    monkeypatch.setattr(watcher, "promote_to_registry", lambda *args, **kwargs: True)
    monkeypatch.setattr(watcher, "audit_log", lambda *args, **kwargs: None)

    real_rmtree = watcher.shutil.rmtree

    def fake_rmtree(path, *args, **kwargs):
        if Path(path) == artifact_dir:
            raise PermissionError("cleanup denied")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(watcher.shutil, "rmtree", fake_rmtree)

    assert watcher.process_directory(artifact_dir) is True
    assert any(p.is_dir() for p in promotion_dir.iterdir())
    marker = quarantine_dir / ".tiny-diffusion.status.json"
    assert marker.exists()
    data = json.loads(marker.read_text())
    assert data["state"] == "promoted"
    assert data["sha256"] == "abc123"


def test_source_metadata_rejects_links_and_control_characters(tmp_path):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    source = tmp_path / ".model.gguf.source"
    target = tmp_path / "target"
    target.write_text("https://huggingface.co/example/model")
    source.symlink_to(target)

    try:
        watcher._read_source_metadata(artifact)
    except ValueError as exc:
        assert "regular file" in str(exc)
    else:
        raise AssertionError("symlink source metadata was accepted")

    source.unlink()
    source.write_text("https://huggingface.co/example/model\nsecond-line")
    try:
        watcher._read_source_metadata(artifact)
    except ValueError as exc:
        assert "control characters" in str(exc)
    else:
        raise AssertionError("multi-line source metadata was accepted")


def test_scanner_worker_environment_excludes_credentials(monkeypatch):
    monkeypatch.setenv("REGISTRY_TOKEN_PATH", "/run/credentials/token")
    monkeypatch.setenv("SERVICE_TOKEN_PATH", "/run/credentials/token")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/unit")
    monkeypatch.setenv("PATH", "/usr/bin")

    environment = watcher._scanner_worker_environment()

    assert environment["PATH"] == "/usr/bin"
    assert "REGISTRY_TOKEN_PATH" not in environment
    assert "SERVICE_TOKEN_PATH" not in environment
    assert "CREDENTIALS_DIRECTORY" not in environment


def test_scan_summary_never_copies_raw_scanner_content():
    summary = watcher._build_scan_summary(
        {
            "smoke_test": {
                "passed": False,
                "score": 0.5,
                "flags": [
                    {
                        "response_snippet": "sensitive model output",
                        "prompt": "fixed adversarial prompt",
                    }
                ],
                "startup_log": "untrusted process output",
            }
        }
    )

    assert summary == {"smoke_test": "0.5"}
    assert "sensitive" not in json.dumps(summary)
    assert "untrusted" not in json.dumps(summary)


def test_abnormal_scanner_exit_forces_service_boundary_restart(
    monkeypatch,
    tmp_path,
):
    class FailedProcess:
        pid = 123

        def wait(self, timeout=None):
            return 9

    def failed_popen(*args, **kwargs):
        kwargs["stdout"].write(b'{"passed":false,"details":{}}')
        kwargs["stdout"].flush()
        return FailedProcess()

    monkeypatch.setattr(watcher.subprocess, "Popen", failed_popen)

    with (
        pytest.raises(
            watcher.ScannerBoundaryError,
            match="scanner worker failed",
        ),
    ):
        watcher._run_scanner_worker(
            tmp_path / "model.gguf",
            "a" * 64,
            source_url="",
            directory=False,
        )


def test_importer_controlled_status_marker_cannot_suppress_scan(monkeypatch, tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    processing_dir = tmp_path / "processing"
    artifact_dir = quarantine_dir / "tiny-diffusion"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "model_index.json").write_text("{}")
    (quarantine_dir / ".tiny-diffusion.status.json").write_text("{}")

    monkeypatch.setattr(watcher, "QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(watcher, "PROCESSING_DIR", processing_dir)

    called = {"count": 0}

    def fake_process_directory(path):
        called["count"] += 1
        return True

    monkeypatch.setattr(watcher, "process_directory", fake_process_directory)

    watcher.scan_directory()

    assert called["count"] == 1


def test_claim_snapshot_survives_inbox_replacement_and_open_fd_write(
    monkeypatch,
    tmp_path,
):
    incoming = tmp_path / "incoming"
    processing = tmp_path / "processing"
    incoming.mkdir()
    artifact = incoming / "model.gguf"
    artifact.write_bytes(b"claimed bytes")
    open_descriptor = os.open(artifact, os.O_RDWR)

    monkeypatch.setattr(watcher, "QUARANTINE_DIR", incoming)
    monkeypatch.setattr(watcher, "PROCESSING_DIR", processing)

    real_move_sidecars = watcher._move_claim_sidecars

    def replace_inbox_path(logical_name, source_root):
        (incoming / logical_name).write_bytes(b"replacement poison")
        real_move_sidecars(logical_name, source_root)

    monkeypatch.setattr(watcher, "_move_claim_sidecars", replace_inbox_path)
    try:
        claim = watcher._claim_incoming_artifact(artifact)
        assert claim is not None
        os.lseek(open_descriptor, 0, os.SEEK_SET)
        os.write(open_descriptor, b"mutated later")
        os.fsync(open_descriptor)
    finally:
        os.close(open_descriptor)

    assert claim.artifact_path.read_bytes() == b"claimed bytes"
    assert (incoming / "model.gguf").read_bytes() == b"replacement poison"
    assert claim.artifact_path.parent.name == "snapshot"
    assert claim.root.parent == processing
    assert stat.S_IMODE(claim.root.stat().st_mode) == 0o2770
    assert stat.S_IMODE(claim.artifact_path.parent.stat().st_mode) == 0o2770
    assert stat.S_IMODE(claim.artifact_path.stat().st_mode) == 0o440
    assert stat.S_IMODE((claim.root / ".claim.json").stat().st_mode) == 0o640


def test_claim_snapshot_rejects_excessive_depth_before_scanning(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    current = source
    for index in range(watcher.DIFFUSION_MAX_DEPTH + 1):
        current = current / f"d{index}"
        current.mkdir()
    (current / "weight.safetensors").write_bytes(b"safe")

    with pytest.raises(ValueError, match="maximum depth"):
        watcher._copy_directory_snapshot(source, tmp_path / "snapshot")


def test_claim_snapshot_preserves_free_space_reserve(monkeypatch, tmp_path):
    source = tmp_path / "model.gguf"
    source.write_bytes(b"GGUF")
    destination_dir = tmp_path / "snapshot"
    destination_dir.mkdir()

    class FullFilesystem:
        f_bavail = 0
        f_frsize = 4096

    monkeypatch.setattr(watcher.os, "statvfs", lambda _path: FullFilesystem())

    with pytest.raises(ValueError, match="reserved disk capacity"):
        watcher._copy_regular_file_snapshot(
            source,
            destination_dir / source.name,
        )


def test_interrupted_claim_resumes_from_private_source(monkeypatch, tmp_path):
    incoming = tmp_path / "incoming"
    processing = tmp_path / "processing"
    incoming.mkdir()
    artifact = incoming / "model.gguf"
    artifact.write_bytes(b"stable")
    monkeypatch.setattr(watcher, "QUARANTINE_DIR", incoming)
    monkeypatch.setattr(watcher, "PROCESSING_DIR", processing)

    real_snapshot = watcher._snapshot_claim
    calls = {"count": 0}

    def fail_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("simulated interruption")
        return real_snapshot(*args, **kwargs)

    monkeypatch.setattr(watcher, "_snapshot_claim", fail_once)
    with pytest.raises(OSError, match="interruption"):
        watcher._claim_incoming_artifact(artifact)

    assert not artifact.exists()
    claims = watcher._ready_claims()
    assert len(claims) == 1
    assert claims[0].artifact_path.read_bytes() == b"stable"


def test_scanner_private_namespace_and_normal_exit_descendant_cleanup(
    monkeypatch,
    tmp_path,
):
    captured = {}

    class PassedProcess:
        pid = 456

        def wait(self, timeout=None):
            return 0

    def passed_popen(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        kwargs["stdout"].write(b'{"passed":false,"reason":"poison","details":{}}')
        kwargs["stdout"].flush()
        return PassedProcess()

    killed = []
    monkeypatch.setattr(watcher.subprocess, "Popen", passed_popen)
    monkeypatch.setattr(watcher.os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    snapshot = tmp_path / "processing" / ("a" * 32) / "snapshot"
    snapshot.mkdir(parents=True)
    artifact = snapshot / "model.gguf"
    artifact.write_bytes(b"GGUF")
    result = watcher._run_scanner_worker(
        artifact,
        "a" * 64,
        source_url="--directory",
        directory=False,
    )

    command = captured["command"]
    assert command[0] == watcher.BWRAP_BIN
    assert "--unshare-net" in command
    assert "--unshare-pid" in command
    run_tmpfs_index = command.index("/run") - 1
    assert command[run_tmpfs_index : run_tmpfs_index + 2] == ["--tmpfs", "/run"]
    assert "--source-url=--directory" in command
    assert captured["environment"]["QUARANTINE_DIR"] == str(snapshot)
    assert killed == [(456, watcher.signal.SIGKILL)]
    assert result["passed"] is False


def test_source_metadata_limit_is_exactly_4096_bytes(tmp_path):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF")
    source = tmp_path / ".model.gguf.source"
    source.write_bytes(b"a" * 4096)
    assert len(watcher._read_source_metadata(artifact)) == 4096

    source.write_bytes(b"a" * 4097)
    with pytest.raises(ValueError, match="exceeds safety limit"):
        watcher._read_source_metadata(artifact)


def test_watcher_requires_independently_assembled_complete_stage_schema():
    stage_names = {
        "source_policy",
        "format_gate",
        "hash_pin",
        "provenance",
        "static_scan",
        "smoke_test",
    }
    details = {name: {"passed": True} for name in stage_names}
    details["hash_pin"] = {
        "passed": True,
        "pinned": False,
        "note": (
            "first-install trust: hash recorded, must be pinned "
            "before next promotion"
        ),
    }
    details.update(
        {
            "hash": {"sha256": "a" * 64},
            "policy_bundle": _policy_bundle(),
        }
    )
    valid = {
        "passed": True,
        "reason": "all_checks_passed",
        "details": details,
    }

    assert watcher._validate_required_stage_result(
        valid,
        artifact_hash="a" * 64,
        directory=False,
        suffix=".gguf",
        source_url="",
    ) is valid

    incomplete = json.loads(json.dumps(valid))
    del incomplete["details"]["static_scan"]
    with pytest.raises(
        watcher.ScannerBoundaryError,
        match="omits a required stage",
    ):
        watcher._validate_required_stage_result(
            incomplete,
            artifact_hash="a" * 64,
            directory=False,
            suffix=".gguf",
            source_url="",
        )

    with pytest.raises(
        watcher.ScannerBoundaryError,
        match="remote file is not bound",
    ):
        watcher._validate_required_stage_result(
            valid,
            artifact_hash="a" * 64,
            directory=False,
            suffix=".gguf",
            source_url=(
                "https://huggingface.co/owner/model/resolve/"
                + "b" * 40
                + "/model.gguf"
            ),
        )


def test_directory_result_requires_typed_image_owned_manifest_evidence():
    stage_names = {
        "source_policy",
        "format_gate",
        "provenance",
        "static_scan",
        "smoke_test",
        "diffusion_deep_scan",
    }
    details = {name: {"passed": True} for name in stage_names}
    details.update({
        "hash_pin": _directory_hash_pin(),
        "hash": {"sha256": "c" * 64},
        "policy_bundle": _policy_bundle(),
    })
    valid = {
        "passed": True,
        "reason": "all_checks_passed",
        "details": details,
    }

    assert watcher._validate_required_stage_result(
        valid,
        artifact_hash="c" * 64,
        directory=True,
        suffix="",
        source_url="https://huggingface.co/owner/model",
    ) is valid

    forged = json.loads(json.dumps(valid))
    forged["details"]["hash_pin"]["huggingface_manifest"]["files_checked"] = 4
    with pytest.raises(
        watcher.ScannerBoundaryError,
        match="manifest evidence is inconsistent",
    ):
        watcher._validate_required_stage_result(
            forged,
            artifact_hash="c" * 64,
            directory=True,
            suffix="",
            source_url="https://huggingface.co/owner/model",
        )


def test_directory_promotion_carries_typed_provenance(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 201

        def read(self, _size=-1):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=30):
        captured["payload"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(watcher, "urlopen", fake_urlopen)
    monkeypatch.setattr(watcher, "_service_headers", lambda: {})
    details = {
        "hash_pin": _directory_hash_pin(),
        "policy_bundle": _policy_bundle(),
    }

    assert watcher.promote_to_registry(
        filename="model",
        file_hash="c" * 64,
        size_bytes=123,
        scan_results={"model_type": "diffusion"},
        model_type="diffusion",
        source_url="https://huggingface.co/owner/model",
        pipeline_details=details,
        staged_filename="opaque-stage",
    )
    assert captured["payload"]["directory_provenance"] == {
        "trust": "image-owned-manifest-pin",
        "manifest_sha256": "a" * 64,
        "revision": "b" * 40,
        "repo_id": "owner/model",
        "variant": "fp16",
        "files_checked": 3,
        "total_size_bytes": 123,
        "sha256_files_checked": 2,
        "git_blob_files_checked": 1,
    }
    assert captured["payload"]["source_revision"] == "b" * 40

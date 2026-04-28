"""Tests for quarantine watcher promotion helpers."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "quarantine"))

from quarantine import watcher


def test_policy_version_id_returns_hash_value(monkeypatch):
    monkeypatch.setattr(watcher, "_compute_policy_version", lambda: {"hash": "abc123", "note": "ignored"})

    assert watcher._policy_version_id() == "abc123"


def test_promote_to_registry_sends_string_policy_version(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 201

        def read(self):
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
    monkeypatch.setattr(watcher, "_policy_version_id", lambda: "policy-hash-1")

    ok = watcher.promote_to_registry(
        filename="example-model.gguf",
        file_hash="deadbeef",
        size_bytes=123,
        scan_results={"smoke_test": "0.0"},
    )

    assert ok is True
    assert captured["payload"]["policy_version"] == "policy-hash-1"


def test_stage_gguf_guard_manifest_moves_to_registry(monkeypatch, tmp_path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    manifest_path = tmp_path / "model.gguf.gguf-guard.json"
    manifest_path.write_text("{}")
    details = {
        "gguf_guard_manifest": {
            "generated": True,
            "manifest_path": str(manifest_path),
        }
    }

    monkeypatch.setattr(watcher, "REGISTRY_DIR", registry_dir)

    watcher._stage_gguf_guard_manifest(details)

    assert (registry_dir / manifest_path.name).exists()
    assert details["gguf_guard_manifest"]["manifest_path"] == manifest_path.name


def test_process_directory_writes_status_marker_when_cleanup_fails(monkeypatch, tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    registry_dir = tmp_path / "registry"
    artifact_dir = quarantine_dir / "tiny-diffusion"
    artifact_dir.mkdir(parents=True)
    registry_dir.mkdir()
    (artifact_dir / "model_index.json").write_text('{"_class_name":"StableDiffusionXLPipeline"}')
    (artifact_dir / "unet").mkdir()
    (artifact_dir / "unet" / "diffusion_pytorch_model.safetensors").write_bytes(b"\x00" * 16)

    monkeypatch.setattr(watcher, "QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(watcher, "REGISTRY_DIR", registry_dir)
    monkeypatch.setattr(watcher, "sha256_of_directory", lambda path: "abc123")
    monkeypatch.setattr(watcher, "load_policy", lambda: {})
    monkeypatch.setattr(
        watcher,
        "run_pipeline_directory",
        lambda *args, **kwargs: {"passed": True, "details": {}},
    )
    monkeypatch.setattr(watcher, "_enable_fsverity", lambda path: True)
    monkeypatch.setattr(watcher, "_build_scan_summary", lambda details: {})
    monkeypatch.setattr(watcher, "promote_to_registry", lambda *args, **kwargs: True)
    monkeypatch.setattr(watcher, "_write_provenance_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr(watcher, "audit_log", lambda *args, **kwargs: None)

    real_rmtree = watcher.shutil.rmtree

    def fake_rmtree(path, *args, **kwargs):
        if Path(path) == artifact_dir:
            raise PermissionError("cleanup denied")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(watcher.shutil, "rmtree", fake_rmtree)

    assert watcher.process_directory(artifact_dir) is True
    assert (registry_dir / "tiny-diffusion" / "model_index.json").exists()
    marker = quarantine_dir / ".tiny-diffusion.status.json"
    assert marker.exists()
    data = json.loads(marker.read_text())
    assert data["state"] == "promoted"
    assert data["sha256"] == "abc123"


def test_scan_directory_skips_marked_directory(monkeypatch, tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    artifact_dir = quarantine_dir / "tiny-diffusion"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "model_index.json").write_text("{}")
    (quarantine_dir / ".tiny-diffusion.status.json").write_text("{}")

    monkeypatch.setattr(watcher, "QUARANTINE_DIR", quarantine_dir)

    called = {"count": 0}

    def fake_process_directory(path):
        called["count"] += 1
        return True

    monkeypatch.setattr(watcher, "process_directory", fake_process_directory)

    watcher.scan_directory()

    assert called["count"] == 0

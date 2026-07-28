"""Typed hardware-state and fail-safe GPU policy tests."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
HELPER = SCRIPTS / "secure-hardware-detect.py"
INFERENCE_UNIT = (
    REPO_ROOT
    / "files"
    / "system"
    / "usr"
    / "lib"
    / "systemd"
    / "system"
    / "secure-ai-inference.service"
)
FIRSTBOOT = SCRIPTS / "firstboot.sh"
UI_APP = REPO_ROOT / "services" / "ui" / "ui" / "app.py"
MODEL_SELECTOR = SCRIPTS / "select-model.sh"


def load_helper():
    spec = importlib.util.spec_from_file_location("secure_hardware_detect", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hardware():
    return load_helper()


def test_detector_and_compatibility_wrappers_are_executable():
    for path in (
        HELPER,
        SCRIPTS / "detect-vm.sh",
        SCRIPTS / "detect-gpu.sh",
        SCRIPTS / "detect-tee.sh",
    ):
        assert path.exists()
        assert os.access(path, os.X_OK)


def test_state_is_typed_atomic_and_root_authored():
    content = HELPER.read_text()
    assert "object_pairs_hook=reject_duplicates" in content
    assert "info.st_uid != 0" in content
    assert "info.st_mode & 0o022" in content
    assert 'getattr(os, "O_NOFOLLOW", 0)' in content
    assert "os.fsync" in content
    assert "os.replace" in content
    assert "vm.env" not in content
    assert "tee.env" not in content


def test_inference_environment_contains_only_bounded_execution_values(
    hardware, tmp_path: Path, monkeypatch
):
    state_path = tmp_path / "gpu.json"
    env_path = tmp_path / "inference.env"
    monkeypatch.setattr(hardware, "GPU_STATE", state_path)
    monkeypatch.setattr(hardware, "INFERENCE_ENV", env_path)
    monkeypatch.setattr(hardware.os, "fchown", lambda *_args: None)
    real_stat = hardware.Path.stat

    def root_owned_stat(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        values = list(info)
        values[4] = 0
        return os.stat_result(values)

    monkeypatch.setattr(hardware.Path, "stat", root_owned_stat)
    hardware.write_gpu_state({
        "backend": "cpu",
        "gpu_layers": 0,
        "name": "host-controlled\nINJECTED=value",
    })
    assert env_path.read_text() == "GPU_BACKEND=cpu\nGPU_LAYERS=0\n"


def test_invalid_gpu_execution_policy_is_refused(hardware):
    with pytest.raises(hardware.DetectionError):
        hardware.write_gpu_state({
            "backend": "shell",
            "gpu_layers": 99,
        })


def test_vm_gpu_is_disabled_by_default(hardware, monkeypatch):
    monkeypatch.setattr(
        hardware,
        "_gpu_hardware",
        lambda: ("cuda", "GPU", -1),
    )
    monkeypatch.setattr(
        hardware,
        "read_state",
        lambda _path: {
            "is_vm": True,
            "gpu_enabled": False,
        },
    )
    state = hardware.detect_gpu()
    assert state["backend"] == "cpu"
    assert state["gpu_layers"] == 0
    assert state["forced_reason"] == "vm_gpu_disabled"


def test_cpu_capability_hint_does_not_claim_active_tee(
    hardware, monkeypatch
):
    monkeypatch.setattr(hardware, "_dmesg", lambda: "")
    monkeypatch.setattr(
        hardware,
        "_read_text",
        lambda path, limit=65536: (
            " flags : sev sme tdx tme " if str(path) == "/proc/cpuinfo" else ""
        ),
    )
    monkeypatch.setattr(hardware.Path, "exists", lambda _path: False)
    state = hardware.detect_tee()
    assert state["capability_hint"] is True
    assert state["active"] is False
    assert state["memory_encryption"] is False
    assert state["verified"] is False


def test_firstboot_never_sources_hardware_state():
    content = FIRSTBOOT.read_text()
    assert "source \"${SECURE_AI_ROOT}/vm.env\"" not in content
    assert "source \"${SECURE_AI_ROOT}/tee.env\"" not in content
    assert "secure-hardware-detect.py show vm" in content
    assert "secure-hardware-detect.py show tee" in content
    assert "jq -er" in content


def test_inference_defaults_cpu_and_uses_typed_environment():
    content = INFERENCE_UNIT.read_text()
    assert "Environment=GPU_LAYERS=0" in content
    assert "EnvironmentFile=-/var/lib/secure-ai/inference.env" in content
    assert "SupplementaryGroups=video render" in content


def test_model_selector_preserves_typed_cpu_policy(tmp_path: Path):
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    model = model_dir / "verified.gguf"
    model.write_bytes(b"manifest-bound-model")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({
            "models": [{
                "format": "gguf",
                "filename": model.name,
                "sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
            }],
        }),
        encoding="utf-8",
    )
    output = tmp_path / "model.env"
    env = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}",
        "GPU_LAYERS": "0",
        "CTX_SIZE": "4096",
        "THREADS": "2",
        "REGISTRY_DIR": str(model_dir),
        "REGISTRY_MANIFEST_PATH": str(manifest),
    }

    completed = subprocess.run(
        ["bash", str(MODEL_SELECTOR), str(output)],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    selected = output.read_text(encoding="utf-8")
    assert "GPU_LAYERS=0\n" in selected
    assert "CTX_SIZE=4096\n" in selected
    assert "THREADS=2\n" in selected


def test_model_selector_rejects_untyped_gpu_override(tmp_path: Path):
    env = {
        **os.environ,
        "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}",
        "GPU_LAYERS": "$(id)",
    }
    completed = subprocess.run(
        ["bash", str(MODEL_SELECTOR), str(tmp_path / "model.env")],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode != 0
    assert not (tmp_path / "model.env").exists()


def test_ui_cannot_rewrite_root_hardware_policy():
    content = UI_APP.read_text()
    route = content[content.index('("/api/vm/gpu"') :]
    route = route[: route.index("# ---------------------------------------------------------------------------", 1)]
    assert "subprocess.run" not in route
    assert "local root console" in route
    assert "secure-hardware-detect.py" in route

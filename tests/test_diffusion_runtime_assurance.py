"""Generation admission without model downloads or compute activation."""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from common import diffusion_registry
from common import runtime_assurance as gate

APP_PATH = Path(__file__).resolve().parents[1] / "services/diffusion-worker/app.py"
SERVICE_TOKEN = "b" * 64
ATTESTOR_TOKEN = "a" * 64


@pytest.fixture
def worker(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURE_AI_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DIFFUSION_DEVICE_PREFERENCE", "auto")
    service_path = tmp_path / "service-token"
    service_path.write_text(SERVICE_TOKEN)
    attestor_path = tmp_path / "attestor-token"
    attestor_path.write_text(ATTESTOR_TOKEN)
    monkeypatch.setenv("SERVICE_TOKEN_PATH", str(service_path))
    monkeypatch.setenv("REGISTRY_DIR", str(tmp_path))
    monkeypatch.setenv("ATTESTOR_TOKEN_PATH", str(attestor_path))
    spec = importlib.util.spec_from_file_location("diffusion_admission_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def verified(filename):
        matches = [m for m in module._find_diffusion_models() if m["name"] == filename]
        path = matches[0]["path"] if matches else str(module.REGISTRY_DIR / filename)
        return diffusion_registry.VerifiedModel(filename, filename, "c" * 64, path)
    monkeypatch.setattr(module, "_verified_diffusion_model", verified)
    monkeypatch.setattr(gate, "require_runtime", Mock(return_value="no_gpu"))
    client = module.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + SERVICE_TOKEN
    return module, client


def assert_slot_free(module):
    assert module._generation_slots.acquire(blocking=False)
    module._generation_slots.release()


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_native_denial_precedes_model_loader_and_releases_capacity(worker, monkeypatch, kind):
    module, client = worker
    check = Mock(side_effect=gate.RuntimeAssuranceUnavailable())
    monkeypatch.setattr(gate, "require_runtime", check)
    loader = Mock()
    monkeypatch.setattr(module, "_load_pipeline", loader)
    discovery = Mock()
    monkeypatch.setattr(module, "_find_diffusion_models", discovery)
    response = client.post(f"/v1/generate/{kind}", json={"prompt": "private"})
    assert response.status_code == 503
    assert response.json == {"error": gate.UNAVAILABLE, "code": "runtime_assurance_unavailable"}
    check.assert_called_once_with(module.ATTESTOR_URL, ATTESTOR_TOKEN)
    loader.assert_not_called()
    discovery.assert_not_called()
    assert_slot_free(module)


def test_caller_authentication_precedes_runtime_decision(worker, monkeypatch):
    module, client = worker
    check = Mock()
    monkeypatch.setattr(gate, "require_runtime", check)
    response = client.post("/v1/generate/image", json={}, headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 403
    check.assert_not_called()
    assert_slot_free(module)


@pytest.mark.parametrize("token", [None, "", "not-a-valid-token", SERVICE_TOKEN])
def test_missing_invalid_or_wrong_attestor_credential_fails_closed(worker, monkeypatch, token):
    module, client = worker
    if token is None:
        module.ATTESTOR_TOKEN_PATH.unlink()
    else:
        module.ATTESTOR_TOKEN_PATH.write_text(token)
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    # Restore the real transport; invalid credentials cannot be tested by a stub.
    real_gate = importlib.reload(gate)
    monkeypatch.setattr(real_gate.requests, "Session", lambda: session)
    session.get.side_effect = real_gate.requests.ConnectionError()
    response = client.post("/v1/generate/image", json={"prompt": "private"})
    assert response.status_code == 503
    if token != SERVICE_TOKEN:
        session.get.assert_not_called()
    else:
        assert session.get.call_args.kwargs["headers"]["Authorization"] == "Bearer " + SERVICE_TOKEN
    assert_slot_free(module)


@pytest.mark.parametrize("kind,image_conditioned", [("image", False), ("img2img", False),
                                                    ("video", False), ("video", True)])
@pytest.mark.parametrize("later", ["expired", "optional", "no_gpu"])
def test_current_decision_rechecked_after_loading_for_every_pipeline_call(
        worker, monkeypatch, kind, image_conditioned, later):
    module, client = worker
    # Initial optional permits CPU, then expiry or any mode change denies execution.
    last = gate.RuntimeAssuranceUnavailable() if later == "expired" else later
    initial = "no_gpu" if later == "optional" else "optional"
    check = Mock(side_effect=[initial, initial, last])
    monkeypatch.setattr(gate, "require_runtime", check)
    fake_torch = types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: False))
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    fake_utils = types.ModuleType("diffusers.utils")
    fake_utils.export_to_video = Mock()
    monkeypatch.setitem(sys.modules, "diffusers", types.ModuleType("diffusers"))
    monkeypatch.setitem(sys.modules, "diffusers.utils", fake_utils)
    capability = "img2vid" if image_conditioned else {"image": "txt2img", "img2img": "img2img", "video": "txt2vid"}[kind]
    monkeypatch.setattr(module, "_find_diffusion_models", lambda: [
        {"name": "local", "path": "/local", "type": "video" if kind == "video" else "image",
         "capabilities": [capability]}])
    pipe = Mock()
    loader = Mock(return_value=pipe)
    monkeypatch.setattr(module, "_load_pipeline", loader)
    image = types.SimpleNamespace(size=(512, 512))
    monkeypatch.setattr(module, "_decode_input_image", lambda _: image)
    monkeypatch.setattr(module, "_prepare_video_conditioning_input", lambda *args: image)
    body = {"prompt": "private", "model": "local"}
    if image_conditioned or kind == "img2img":
        body["image"] = "synthetic"
    response = client.post(f"/v1/generate/{kind}", json=body)
    assert response.status_code == 503 and response.json["error"] == gate.UNAVAILABLE
    assert check.call_count == 3
    loader.assert_called_once()
    pipe.assert_not_called()
    fake_utils.export_to_video.assert_not_called()
    assert_slot_free(module)


def test_explicit_no_gpu_ignores_cuda_override_offload_and_cached_gpu_pipeline(worker, monkeypatch, tmp_path):
    module, _ = worker
    monkeypatch.setenv("DIFFUSION_DEVICE_PREFERENCE", "cuda")
    monkeypatch.setenv("DIFFUSION_CPU_OFFLOAD", "1")
    fake_torch = types.SimpleNamespace(float16="fp16", float32="fp32",
                                      cuda=types.SimpleNamespace(is_available=lambda: True))
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    model = tmp_path / "model"
    model.mkdir()
    pipes = []
    class Pipeline:
        def __init__(self):
            self.to = Mock(return_value=self)
            self.enable_model_cpu_offload = Mock()
        @classmethod
        def from_pretrained(cls, *args, **kwargs):
            pipe = cls()
            pipe.dtype = kwargs["torch_dtype"]
            pipes.append(pipe)
            return pipe
    diffusers = types.ModuleType("diffusers")
    diffusers.AutoPipelineForText2Image = Pipeline
    diffusers.AutoPipelineForImage2Image = Pipeline
    diffusers.DiffusionPipeline = Pipeline
    monkeypatch.setitem(sys.modules, "diffusers", diffusers)
    check = Mock(side_effect=["optional", "no_gpu", "no_gpu"])
    monkeypatch.setattr(gate, "require_runtime", check)
    gpu_pipe = module._load_pipeline(str(model))
    # Also retain a legacy unbound cache entry: it cannot be reused.
    module._pipelines[f"{model}:image"] = gpu_pipe
    cpu_pipe = module._load_pipeline(str(model))
    assert cpu_pipe is not gpu_pipe
    assert module._load_pipeline(str(model)) is cpu_pipe
    assert check.call_count == 3  # no cached positive admission
    cpu_pipe.to.assert_called_once_with("cpu")
    assert cpu_pipe.dtype == "fp32"
    cpu_pipe.enable_model_cpu_offload.assert_not_called()
    assert module._get_device("no_gpu") == "cpu"


def test_explicit_sandbox_is_unsupported_host_assurance(worker, monkeypatch):
    module, client = worker
    check = Mock(side_effect=gate.RuntimeAssuranceUnavailable())
    monkeypatch.setattr(gate, "require_runtime", check)
    assert client.post("/v1/generate/image", json={}).status_code == 503
    monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")
    assert client.post("/v1/generate/image", json={}).status_code == 400
    assert module._require_generation_runtime() is None
    monkeypatch.setattr(module, "_get_device", lambda *args: "cpu")
    monkeypatch.setattr(module, "_get_gpu_info", lambda: {})
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json["host_assurance"] == "unsupported"
    assert health.json["deployment_mode"] == "sandbox"
    assert check.call_count == 1


def test_denied_runtime_keeps_management_and_recovery_available(worker, monkeypatch, tmp_path):
    module, client = worker
    check = Mock(side_effect=gate.RuntimeAssuranceUnavailable())
    monkeypatch.setattr(gate, "require_runtime", check)
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)
    (tmp_path / "saved.png").write_bytes(b"png")
    monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: False)))
    assert client.get("/health").status_code == 200
    assert client.get("/v1/models").status_code == 200
    assert client.get("/v1/outputs").status_code == 200
    assert client.get("/v1/outputs/saved.png").status_code == 200
    assert client.post("/v1/unload").status_code == 200
    check.assert_not_called()


def test_container_sources_include_common_without_implicit_sandbox():
    root = APP_PATH.parents[2]
    for filename in ("Dockerfile", "Dockerfile.sandbox"):
        source = (APP_PATH.parent / filename).read_text()
        assert "COPY services/common/ /app/common/" in source
        assert "SECURE_AI_DEPLOYMENT_MODE" not in source
    # Compose is the operator's explicit sandbox evaluation opt-in.
    import yaml
    compose = yaml.safe_load((root / "deploy/sandbox/compose.yaml").read_text())
    assert compose["services"]["diffusion"]["environment"]["SECURE_AI_DEPLOYMENT_MODE"] == "sandbox"


@pytest.mark.parametrize("setting,value", [("DIFFUSION_DEVICE_PREFERENCE", "cpu"),
                                           ("DIFFUSION_CPU_OFFLOAD", "1")])
def test_changed_device_or_offload_after_load_denies_execution(worker, monkeypatch, setting, value):
    module, client = worker
    monkeypatch.setattr(gate, "require_runtime", Mock(return_value="optional"))
    monkeypatch.setenv("DIFFUSION_CPU_OFFLOAD", "0")
    monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: True)))
    monkeypatch.setattr(module, "_find_diffusion_models", lambda: [
        {"name": "local", "path": "/local", "capabilities": ["txt2img"]}])
    pipe = Mock()
    def load(*args, **kwargs):
        monkeypatch.setenv(setting, value)
        return pipe
    monkeypatch.setattr(module, "_load_pipeline", load)
    response = client.post("/v1/generate/image", json={"prompt": "private", "model": "local"})
    assert response.status_code == 503 and response.json["error"] == gate.UNAVAILABLE
    pipe.assert_not_called()
    assert_slot_free(module)


@pytest.mark.parametrize("gpu_mode", ["required", "optional", "no_gpu"])
def test_native_cpu_binding_and_recheck_on_next_request(worker, monkeypatch, tmp_path, gpu_mode):
    module, client = worker
    check = Mock(return_value=gpu_mode)
    monkeypatch.setattr(gate, "require_runtime", check)
    generator = Mock()
    fake_torch = types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: True), Generator=generator)
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    monkeypatch.setenv("DIFFUSION_DEVICE_PREFERENCE", "cuda" if gpu_mode == "no_gpu" else "cpu")
    monkeypatch.setattr(module, "_find_diffusion_models", lambda: [
        {"name": "local", "path": "/local", "capabilities": ["txt2img"]}])
    monkeypatch.setattr(module, "OUTPUTS_DIR", tmp_path)
    class Image:
        def save(self, output, **kwargs):
            if isinstance(output, str):
                Path(output).write_bytes(b"png")
            else:
                output.write(b"png")
    pipe = Mock(return_value=types.SimpleNamespace(images=[Image()]))
    loader = Mock(return_value=pipe)
    monkeypatch.setattr(module, "_load_pipeline", loader)
    response = client.post("/v1/generate/image", json={"prompt": "private", "seed": 1, "model": "local"})
    assert response.status_code == 200
    assert check.call_count == 3
    generator.assert_called_once_with(device="cpu")
    assert loader.call_args.kwargs["binding"] == (gpu_mode, "cpu", False)
    pipe.assert_called_once()
    check.side_effect = gate.RuntimeAssuranceUnavailable()
    assert client.post("/v1/generate/image", json={"prompt": "private"}).status_code == 503
    pipe.assert_called_once()
    assert_slot_free(module)

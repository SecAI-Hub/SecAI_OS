"""Registry transport and generation integrity tests with inert local files."""
import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from common import diffusion_registry as registry
from common import runtime_assurance

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "d" * 64


@pytest.fixture
def transport(tmp_path, monkeypatch):
    root = tmp_path / "registry"
    model = root / "local"
    model.mkdir(parents=True)
    data = {"schema_version": 1, "status": "verified", "safe_to_use": "true",
            "name": "Reviewed Diffusion Model", "filename": "local", "format": "diffusion-directory",
            "path": str(model), "sha256": "a" * 64}
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json"}
    response.iter_content.return_value = [json.dumps(data).encode()]
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(registry.requests, "Session", lambda: session)
    return root, data, session, response


def verify(transport, **kwargs):
    root, _, _, _ = transport
    return registry.verify_model(kwargs.pop("origin", "http://127.0.0.1:8470"),
                                 kwargs.pop("token", TOKEN), kwargs.pop("filename", "local"), root, **kwargs)


def test_current_full_metadata_and_scoped_transport(transport, monkeypatch):
    root, data, session, response = transport
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    verified = verify(transport)
    assert verified == registry.VerifiedModel(data["name"], "local", "a" * 64, str(root / "local"))
    assert session.trust_env is False
    args, kwargs = session.get.call_args
    assert args == ("http://127.0.0.1:8470/v1/model/path",)
    assert kwargs["params"] == {"filename": "local"}
    assert kwargs["headers"]["Authorization"] == "Bearer " + TOKEN
    assert kwargs["headers"]["Accept-Encoding"] == "identity"
    assert kwargs["timeout"] == (1, 12) and kwargs["allow_redirects"] is False
    response.status_code = 409
    with pytest.raises(registry.ModelIntegrityUnavailable, match="^model integrity verification unavailable$"):
        verify(transport)
    assert session.get.call_count == 2


@pytest.mark.parametrize("changes", [{"schema_version": 0}, {"schema_version": True}, {"status": "ok"},
                                     {"safe_to_use": True}, {"safe_to_use": "false"}, {"filename": "other"},
                                     {"name": ""}, {"format": "gguf"}, {"path": "/outside/local"},
                                     {"sha256": "b"}, {"sha256": "A" * 64}])
def test_invalid_contract_denies(transport, changes):
    data = dict(transport[1], **changes)
    transport[3].iter_content.return_value = [json.dumps(data).encode()]
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport)


@pytest.mark.parametrize("raw", [b'{"path":"/legacy/local"}', b'null', b'{} {}', b'{"schema_version":1,"schema_version":1}',
                                 b'{"sha256":NaN}', b'\xff', b'x' * (registry.MAX_BYTES + 1)])
def test_legacy_malformed_duplicate_nonfinite_or_oversize_reply_denies(transport, raw):
    transport[3].iter_content.return_value = [raw]
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport)


@pytest.mark.parametrize("status", [301, 403, 404, 409, 429, 503, 504])
def test_registry_auth_missing_blocked_or_tamper_response_denies(transport, status):
    transport[3].status_code = status
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport)


@pytest.mark.parametrize("headers", [{"Content-Type": "text/html"}, {"Content-Type": "application/json", "Content-Encoding": "gzip"},
                                     {"Content-Type": "application/json", "Content-Length": "999999"},
                                     {"Content-Type": "application/json", "Content-Length": "bad"}])
def test_response_headers_are_bounded(transport, headers):
    transport[3].headers = headers
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport)


@pytest.mark.parametrize("origin,sandbox", [("http://registry:8470", False), ("http://public.example:8470", True),
                                           ("http://registry:80", True), ("http://localhost:8470", False),
                                           ("http://127.0.0.1:8471", False), ("https://127.0.0.1:8470", False),
                                           ("http://user@127.0.0.1:8470", False), ("http://127.0.0.1:8470/", False)])
def test_only_fixed_native_or_explicit_sandbox_service_origin(transport, origin, sandbox):
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport, origin=origin, sandbox=sandbox)
    transport[2].get.assert_not_called()


def test_explicit_sandbox_still_requires_full_verification(transport):
    assert verify(transport, origin="http://registry:8470", sandbox=True).filename == "local"
    transport[3].status_code = 403
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport, origin="http://registry:8470", sandbox=True)


@pytest.mark.parametrize("filename", ["", "../local", "/local", "nested/local", "local\\other", "local\x00", "local\n", ".."])
def test_exact_basename_required_before_transport(transport, filename):
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport, filename=filename)
    transport[2].get.assert_not_called()


@pytest.mark.parametrize("token", ["", "invalid", "A" * 64, None])
def test_invalid_registry_credential_never_dispatches(transport, token):
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport, token=token)
    transport[2].get.assert_not_called()


@pytest.mark.parametrize("kind", ["root", "model"])
def test_symlink_registry_root_or_model_rejected(transport, tmp_path, kind):
    root = transport[0]
    if kind == "root":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        with pytest.raises(registry.ModelIntegrityUnavailable):
            registry.verify_model("http://127.0.0.1:8470", TOKEN, "local", alias)
    else:
        (root / "local").rename(root / "moved")
        (root / "local").symlink_to(root / "moved", target_is_directory=True)
        with pytest.raises(registry.ModelIntegrityUnavailable):
            verify(transport)
    transport[2].get.assert_not_called()


def test_slow_body_total_deadline_denies(transport, monkeypatch):
    times = iter([0, 16])
    monkeypatch.setattr(registry.time, "monotonic", lambda: next(times))
    with pytest.raises(registry.ModelIntegrityUnavailable):
        verify(transport)


@pytest.fixture
def worker(tmp_path, monkeypatch):
    root = tmp_path / "registry"
    model = root / "local"
    model.mkdir(parents=True)
    (model / "model_index.json").write_text('{"_class_name":"StableDiffusionPipeline"}')
    (model / "weights.safetensors").write_bytes(b"inert")
    service = tmp_path / "service.token"
    service.write_text("e" * 64)
    attestor = tmp_path / "attestor.token"
    attestor.write_text("f" * 64)
    credential = tmp_path / "registry.token"
    credential.write_text(TOKEN)
    monkeypatch.setenv("REGISTRY_DIR", str(root))
    monkeypatch.setenv("SERVICE_TOKEN_PATH", str(service))
    monkeypatch.setenv("ATTESTOR_TOKEN_PATH", str(attestor))
    monkeypatch.setenv("REGISTRY_VERIFY_TOKEN_PATH", str(credential))
    # Vault setup provisions this directory before native writers start.
    # Generation must not recreate a missing or unmounted vault path.
    (tmp_path / "outputs").mkdir()
    monkeypatch.setenv("OUTPUTS_DIR", str(tmp_path / "outputs"))
    monkeypatch.delenv("SECURE_AI_DEPLOYMENT_MODE", raising=False)
    spec = importlib.util.spec_from_file_location("diffusion_integrity_worker", ROOT / "services/diffusion-worker/app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(runtime_assurance, "require_runtime", Mock(return_value="no_gpu"))
    identity = registry.VerifiedModel("Reviewed Diffusion Model", "local", "a" * 64, str(model))
    check = Mock(return_value=identity)
    monkeypatch.setattr(registry, "verify_model", check)
    pipes, loads = [], []
    class OutputImage:
        def save(self, output, **kwargs):
            if isinstance(output, str):
                Path(output).write_bytes(b"png")
            else:
                output.write(b"png")
    class Pipeline:
        def __init__(self):
            self.calls = 0
        def to(self, device):
            self.device = device
            return self
        def __call__(self, **kwargs):
            self.calls += 1
            return types.SimpleNamespace(images=[OutputImage()], frames=[[OutputImage()]])
    class Factory:
        @staticmethod
        def from_pretrained(path, **kwargs):
            loads.append((path, kwargs))
            pipe = Pipeline()
            pipes.append(pipe)
            return pipe
    diffusers = types.ModuleType("diffusers")
    diffusers.AutoPipelineForText2Image = Factory
    diffusers.AutoPipelineForImage2Image = Factory
    diffusers.DiffusionPipeline = Factory
    utils = types.ModuleType("diffusers.utils")
    utils.export_to_video = lambda frames, path, **kwargs: Path(path).write_bytes(b"mp4")
    monkeypatch.setitem(sys.modules, "diffusers", diffusers)
    monkeypatch.setitem(sys.modules, "diffusers.utils", utils)
    monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(float16="fp16", float32="fp32"))
    client = module.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + "e" * 64
    return module, client, check, identity, pipes, loads


def slot_free(module):
    assert module._generation_slots.acquire(blocking=False)
    module._generation_slots.release()


def test_generation_positive_contract_and_digest_cache_binding(worker):
    module, client, check, identity, pipes, loads = worker
    assert client.post("/v1/generate/image", json={"model": "local", "prompt": "private"}).status_code == 200
    assert check.call_count == 4  # selection, pre-load, post-load, pre-execution
    assert pipes[0].calls == 1
    assert loads[0][1]["local_files_only"] is True
    assert loads[0][1]["use_safetensors"] is True
    assert loads[0][1]["trust_remote_code"] is False
    check.assert_called_with(module.REGISTRY_URL, TOKEN, "local", module.REGISTRY_DIR, sandbox=False)
    assert any(identity.sha256 in key for key in module._pipelines)
    assert client.post("/v1/generate/image", json={"model": "local", "prompt": "private"}).status_code == 200
    assert check.call_count == 7 and len(pipes) == 1 and pipes[0].calls == 2
    slot_free(module)


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_direct_worker_requires_exact_selected_model(worker, kind):
    module, client, check, _, _, loads = worker
    response = client.post(f"/v1/generate/{kind}", json={"prompt": "private", "image": "synthetic"})
    assert response.status_code == 400
    check.assert_not_called()
    assert not loads
    slot_free(module)


@pytest.mark.parametrize("sandbox", [False, True])
def test_registry_denial_prevents_loading_in_native_and_explicit_sandbox(worker, monkeypatch, sandbox):
    module, client, check, _, _, loads = worker
    if sandbox:
        monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")
    check.side_effect = registry.ModelIntegrityUnavailable()
    response = client.post("/v1/generate/image", json={"model": "local", "prompt": "private"})
    assert response.status_code == 503
    assert response.json == {"error": registry.UNAVAILABLE, "code": "model_integrity_unavailable"}
    assert not loads
    slot_free(module)


@pytest.mark.parametrize("change", ["digest", "identity", "blocked"])
def test_uncached_load_change_denies_and_never_caches_pipeline(worker, change):
    module, client, check, identity, pipes, _ = worker
    replacement = (registry.ModelIntegrityUnavailable() if change == "blocked" else
                   identity._replace(sha256="b" * 64) if change == "digest" else identity._replace(name="new identity"))
    check.side_effect = [identity, identity, replacement]
    response = client.post("/v1/generate/image", json={"model": "local", "prompt": "private"})
    assert response.status_code == 503 and response.json["error"] == registry.UNAVAILABLE
    assert pipes[0].calls == 0 and not module._pipelines
    slot_free(module)


@pytest.mark.parametrize("kind,image_conditioned", [("image", False), ("img2img", False), ("video", False), ("video", True)])
def test_reverification_before_every_pipeline_call(worker, monkeypatch, kind, image_conditioned):
    module, client, check, identity, pipes, _ = worker
    if kind == "video":
        cls = "StableVideoDiffusionPipeline" if image_conditioned else "LTXPipeline"
        (Path(identity.path) / "model_index.json").write_text(json.dumps({"_class_name": cls}))
    if image_conditioned or kind == "img2img":
        image = types.SimpleNamespace(size=(512, 512))
        monkeypatch.setattr(module, "_decode_input_image", lambda _: image)
    check.side_effect = [identity, identity, identity, identity._replace(sha256="b" * 64)]
    response = client.post(f"/v1/generate/{kind}", json={"model": "local", "prompt": "private", "image": "synthetic"}
                           if image_conditioned or kind == "img2img" else {"model": "local", "prompt": "private"})
    assert response.status_code == 503 and response.json["error"] == registry.UNAVAILABLE
    assert pipes[0].calls == 0
    slot_free(module)


def test_cached_pipeline_change_before_execution_is_denied(worker):
    module, client, check, identity, pipes, _ = worker
    body = {"model": "local", "prompt": "private"}
    assert client.post("/v1/generate/image", json=body).status_code == 200
    check.side_effect = [identity, identity, identity._replace(sha256="b" * 64)]
    assert client.post("/v1/generate/image", json=body).status_code == 503
    assert len(pipes) == 1 and pipes[0].calls == 1
    slot_free(module)


def test_approved_replacement_digest_gets_a_new_pipeline(worker):
    module, client, check, identity, pipes, _ = worker
    body = {"model": "local", "prompt": "private"}
    assert client.post("/v1/generate/image", json=body).status_code == 200
    check.return_value = identity._replace(sha256="b" * 64)
    assert client.post("/v1/generate/image", json=body).status_code == 200
    assert len(pipes) == 2 and [p.calls for p in pipes] == [1, 1]
    slot_free(module)


def test_missing_registry_token_does_not_use_worker_or_attestor_credential(worker):
    module, client, check, _, _, loads = worker
    module.REGISTRY_VERIFY_TOKEN_PATH.unlink()
    assert client.post("/v1/generate/image", json={"model": "local", "prompt": "private"}).status_code == 503
    check.assert_not_called()
    assert not loads
    slot_free(module)


def test_distinct_native_and_sandbox_registry_scope_wiring(tmp_path):
    compose = yaml.safe_load((ROOT / "deploy/sandbox/compose.yaml").read_text())["services"]
    for role in ("read", "verify", "promote", "admin"):
        assert compose["registry"]["environment"][f"REGISTRY_{role.upper()}_TOKEN_PATH"] == f"/run/secrets/registry-{role}.token"
    assert "SERVICE_TOKEN_PATH" not in compose["registry"]["environment"]
    for service, role in (("ui", "admin"), ("quarantine", "promote"), ("diffusion", "verify")):
        key = "REGISTRY_VERIFY_TOKEN_PATH" if service == "diffusion" else "REGISTRY_TOKEN_PATH"
        assert compose[service]["environment"][key] == f"/run/secrets/registry-{role}.token"
        assert f"./runtime/credentials/registry-{role}.token:/run/secrets/registry-{role}.token:ro,z" in compose[service]["volumes"]
    unit = (ROOT / "files/system/usr/lib/systemd/system/secure-ai-diffusion.service").read_text()
    assert "Environment=REGISTRY_URL=http://127.0.0.1:8470" in unit
    assert "LoadCredential=registry-verify-token:/var/lib/secure-ai/credentials/registry-verify.token" in unit
    spec = importlib.util.spec_from_file_location("private_registry_credentials", ROOT / "scripts/sandbox/render_runtime.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    runtime = tmp_path / "private-runtime"
    runtime.mkdir()
    renderer._provision_target_credentials(runtime)
    tokens = [(runtime / "credentials" / f"registry-{role}.token").read_text() for role in ("read", "verify", "promote", "admin")]
    assert len(set(tokens)) == 4
    powershell = (ROOT / "scripts/sandbox/start.ps1").read_text()
    for role in ("read", "verify", "promote", "admin"):
        assert f'"registry-{role}"' in powershell


@pytest.mark.parametrize("stall", [False, True])
def test_real_http_stream_uses_remaining_deadline(tmp_path, monkeypatch, stall):
    # Use an owned ephemeral loopback server and route the already-validated
    # fixed origin there inside this test's session, avoiding any live registry.
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    import time
    import requests
    root = tmp_path / "registry"
    (root / "local").mkdir(parents=True)
    data = json.dumps({"schema_version": 1, "status": "verified", "safe_to_use": "true",
                       "name": "Reviewed", "filename": "local", "format": "diffusion-directory",
                       "path": str(root / "local"), "sha256": "a" * 64}).encode()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if stall:
                time.sleep(0.2)
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.handle_request)
    thread.start()
    session = requests.Session()
    get = session.get
    def routed_get(url, **kwargs):
        assert url == "http://127.0.0.1:8470/v1/model/path"
        return get(f"http://127.0.0.1:{server.server_port}/v1/model/path", **kwargs)
    monkeypatch.setattr(session, "get", routed_get)
    monkeypatch.setattr(registry.requests, "Session", lambda: session)
    if stall:
        monkeypatch.setattr(registry, "TOTAL_SECONDS", 0.08)
    started = time.monotonic()
    try:
        if stall:
            with pytest.raises(registry.ModelIntegrityUnavailable):
                registry.verify_model("http://127.0.0.1:8470", TOKEN, "local", root)
            assert time.monotonic() - started < 0.18
        else:
            assert registry.verify_model("http://127.0.0.1:8470", TOKEN, "local", root).filename == "local"
    finally:
        thread.join(timeout=2)
        server.server_close()
        assert not thread.is_alive()

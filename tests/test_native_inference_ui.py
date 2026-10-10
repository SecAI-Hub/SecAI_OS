"""Native model activation crosses the UI's session, audit and request boundaries."""
import json
from pathlib import Path
import sys

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))
import ui.app as ui


MODELS = [
    {"name": "Alpha", "filename": "alpha.gguf", "format": "gguf"},
    {"name": "Beta", "filename": "beta.gguf", "format": "gguf"},
]


def response(payload, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()
    return result


@pytest.fixture
def native(tmp_path, monkeypatch):
    monkeypatch.setattr(ui._auth, "is_configured", lambda: True)
    monkeypatch.setattr(ui._auth, "validate_session", lambda token, **kw: token == "native-test-session")
    monkeypatch.setattr(ui, "_native_inference_control_available", lambda: True)
    monkeypatch.setattr(ui, "_deployment_mode", lambda: "appliance")
    monkeypatch.setattr(ui, "_is_sandbox_deployment", lambda: False)
    monkeypatch.setattr(ui.runtime_assurance, "require_runtime", lambda *a, **kw: "no_gpu")
    monkeypatch.setattr(ui, "_service_headers", lambda **kw: {"Authorization": "Bearer test-registry"})
    monkeypatch.setattr(ui, "_ui_audit", ui.AuditChain(tmp_path / "audit.jsonl"))
    target = tmp_path / "inference-model-request"
    monkeypatch.setattr(ui, "_NATIVE_INFERENCE_REQUEST", target)

    def registry_get(url, **kwargs):
        assert url == ui.REGISTRY_URL + "/v1/models"
        assert kwargs["headers"] == {"Authorization": "Bearer test-registry"}
        return response(MODELS)

    monkeypatch.setattr(ui.requests, "get", registry_get)
    client = ui.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer native-test-session"
    return client, target


def test_queue_exact_second_model_and_do_not_overwrite_pending(native):
    client, target = native
    result = client.post("/api/inference/select", json={"model_filename": "beta.gguf"})
    assert result.status_code == 202
    request = json.loads(target.read_bytes())
    assert request == {"version": 1, "request_id": result.json["request_id"], "model_filename": "beta.gguf"}
    assert len(request["request_id"]) == 32
    assert target.stat().st_mode & 0o777 == 0o640
    assert target.stat().st_nlink == 1
    assert client.post("/api/inference/select", json={"model_filename": "alpha.gguf"}).status_code == 409
    assert json.loads(target.read_bytes()) == request


@pytest.mark.parametrize("body", [
    [], {}, {"model_filename": 42}, {"model_filename": "../beta.gguf"},
    {"model_filename": " beta.gguf"}, {"model_filename": "alpha.gguf,beta.gguf"},
    {"model_filename": "beta.gguf", "service": "sshd.service"},
    {"model_filename": "x" * 256 + ".gguf"}, {"model_filename": "beta.gguf\ud800"},
])
def test_invalid_selection_never_publishes(native, body):
    client, target = native
    assert client.post("/api/inference/select", json=body).status_code == 400
    assert not target.exists()


@pytest.mark.parametrize("models", [[], MODELS + [MODELS[1]], [{"filename": "other.gguf", "format": "gguf"}]])
def test_unknown_or_ambiguous_registry_selection_never_publishes(native, monkeypatch, models):
    client, target = native
    monkeypatch.setattr(ui.requests, "get", lambda *a, **kw: response(models))
    assert client.post("/api/inference/select", json={"model_filename": "beta.gguf"}).status_code == 404
    assert not target.exists()


@pytest.mark.parametrize("failure", ["registry_status", "registry_shape", "registry_timeout", "audit"])
def test_unavailable_dependencies_fail_before_action(native, monkeypatch, failure):
    client, target = native

    def unavailable(*a, **kw):
        raise OSError("sensitive internal details")

    if failure == "audit":
        monkeypatch.setattr(ui._ui_audit, "append", unavailable)
    elif failure == "registry_timeout":
        def timeout(*a, **kw):
            raise requests.Timeout("sensitive internal details")
        monkeypatch.setattr(ui.requests, "get", timeout)
    else:
        monkeypatch.setattr(ui.requests, "get", lambda *a, **kw: response(
            {} if failure == "registry_shape" else MODELS,
            503 if failure == "registry_status" else 200,
        ))
    result = client.post("/api/inference/select", json={"model_filename": "beta.gguf"})
    assert result.status_code == 503
    assert "sensitive" not in result.text
    assert not target.exists()


def test_native_selection_requires_session_and_csrf(native):
    client, target = native
    client.environ_base.pop("HTTP_AUTHORIZATION")
    assert client.post("/api/inference/select", json={"model_filename": "beta.gguf"}).status_code == 401
    client.set_cookie("session_token", "native-test-session")
    assert client.post("/api/inference/select", json={"model_filename": "beta.gguf"}).status_code == 403
    assert not target.exists()


def test_unavailable_native_control_does_not_publish(native, monkeypatch):
    client, target = native
    monkeypatch.setattr(ui, "_native_inference_control_available", lambda: False)
    assert client.post("/api/inference/select", json={"model_filename": "beta.gguf"}).status_code == 501
    assert not target.exists()


def test_restart_success_does_not_mark_the_wrong_loaded_model_usable(native, monkeypatch):
    client, _ = native
    monkeypatch.setattr(ui, "_loaded_inference_model_filenames", lambda **kw: ["alpha.gguf"])
    monkeypatch.setattr(ui.assurance, "read_root_json", lambda path: {
        "version": 1, "request_id": "a" * 32, "model_filename": "beta.gguf",
        "status": "succeeded", "detail": "Restart completed.", "ignored": "not exposed",
    })
    result = client.get("/api/inference/status")
    assert result.status_code == 200 and result.json["automation_available"] is True
    assert result.json["model_selection"]["status"] == "succeeded"
    assert "ignored" not in result.json["model_selection"]
    assert [model["usable"] for model in result.json["chat_models"]] == [True, False]


def test_untrusted_broker_feedback_is_ignored(native, monkeypatch):
    client, _ = native
    monkeypatch.setattr(ui, "_loaded_inference_model_filenames", lambda **kw: [])

    def untrusted(path):
        raise ui.assurance.EvidenceUnavailable("unsafe result")

    monkeypatch.setattr(ui.assurance, "read_root_json", untrusted)
    result = client.get("/api/inference/status")
    assert result.status_code == 200
    assert result.json["model_selection"] == {}
    assert result.json["available"] is False


@pytest.mark.parametrize("failure", ["http", "shape", "items", "json", "timeout"])
def test_registry_failure_never_exposes_usable_chat_models(native, monkeypatch, failure):
    client, _ = native
    monkeypatch.setattr(ui, "_loaded_inference_model_filenames", lambda **kw: ["alpha.gguf"])

    def broken(*args, **kwargs):
        if failure == "timeout":
            raise requests.Timeout("private backend details")
        if failure == "json":
            value = response([])
            value._content = b"not JSON: private details"
            return value
        return response({} if failure == "shape" else [None] if failure == "items" else MODELS,
                        503 if failure == "http" else 200)

    monkeypatch.setattr(ui.requests, "get", broken)
    result = client.get("/api/inference/status")
    assert result.status_code == 200
    assert result.json["registry_available"] is False
    assert result.json["available"] is False
    assert result.json["chat_models"] == []
    assert result.json["error"] == "Model registry is unavailable. Retry shortly."
    assert result.json["guidance"] == result.json["error"]
    assert "private" not in result.text


def test_native_status_does_not_offer_chat_before_runtime_admission(native, monkeypatch):
    client, _ = native
    monkeypatch.setattr(ui, "_loaded_inference_model_filenames", lambda **kw: ["alpha.gguf"])

    def denied(*args, **kwargs):
        raise ui.runtime_assurance.RuntimeAssuranceUnavailable()

    monkeypatch.setattr(ui.runtime_assurance, "require_runtime", denied)
    result = client.get("/api/inference/status")
    assert result.status_code == 200
    assert result.json["registry_available"] is True
    assert result.json["runtime_ready"] is False
    assert result.json["available"] is False
    assert result.json["loaded_models"] == ["alpha.gguf"]
    assert not any(model["usable"] for model in result.json["chat_models"])
    assert result.json["status_url"] == "/security"
    assert result.json["error"] == "Safety checks are not ready. Open Security Status for details."
    monkeypatch.setattr(ui.runtime_assurance, "require_runtime", lambda *a, **kw: "no_gpu")
    recovered = client.get("/api/inference/status")
    assert recovered.json["runtime_ready"] is True
    assert recovered.json["chat_models"][0]["usable"] is True
    assert recovered.json["status_url"] == ""


def test_sandbox_status_does_not_claim_native_admission(native, monkeypatch):
    client, _ = native
    monkeypatch.setattr(ui, "_is_sandbox_deployment", lambda: True)
    monkeypatch.setattr(ui, "_sandbox_control_configured", lambda: False)
    monkeypatch.setattr(ui, "_loaded_inference_model_filenames", lambda **kw: ["alpha.gguf"])

    def unexpected(*args, **kwargs):
        pytest.fail("sandbox must not borrow native attestor authority")

    monkeypatch.setattr(ui.runtime_assurance, "require_runtime", unexpected)
    result = client.get("/api/inference/status")
    assert result.status_code == 200 and result.json["runtime_ready"] is True
    assert result.json["chat_models"][0]["usable"] is True

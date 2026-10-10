"""Exercise every caller through the real credential/session boundary."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest
import requests
from urllib3.exceptions import ReadTimeoutError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))
import ui.app as ui
from agent.agent.executor import Executor
from agent.agent.models import Budgets, CapabilityToken
from agent.agent.planner import Planner
from agent.agent.policy import PolicyEngine
from common import inference_client


CHAT = {"choices": [{"message": {"content": "answer"}}]}
CHUNK = {"choices": [{"delta": {"content": "answer"}}]}
PLAN = {"content": '[{"action":"summarize","description":"Summarize","params":{}}]'}
MESSAGES = {"messages": [{"role": "user", "content": "Hello"}]}
ROUTES = ["/api/chat", "/api/chat/search", "/api/chat/stream"]


class Response(requests.Response):
    def __init__(self, data=None, *, status=200, raw=None, stream=False):
        super().__init__()
        self.status_code = status
        self._content = json.dumps(data).encode() if raw is None else raw
        self._content_consumed = True
        self.headers["Content-Type"] = "text/event-stream" if stream else "application/json"
        self.closed = False

    def close(self):
        self.closed = True
        super().close()


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "_runtime_chat_guard", lambda: None)
    # Caller/session compatibility only: execute the production worker exchange
    # with the existing Session mocks. Real process/socket/deadline isolation is
    # independently exercised in test_inference_transport.py and native probes.
    class InlineOperation:
        def __init__(self, raw, deadline):
            self.deadline = deadline
            self.events = inference_client.transport.exchange(json.loads(raw))

        def receive(self):
            return next(self.events)

        def close(self):
            self.events.close()

    monkeypatch.setattr(inference_client.transport, "Operation", InlineOperation)
    ui_key = tmp_path / "ui-key"
    agent_key = tmp_path / "agent-key"
    generic_key = tmp_path / "generic-key"
    for path, value in ((ui_key, "7"), (agent_key, "8"), (generic_key, "9")):
        path.write_text(value * 64)
        path.chmod(0o600)
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(ui_key))
    monkeypatch.setenv("SERVICE_TOKEN_PATH", str(generic_key))
    monkeypatch.setattr(ui, "load_appliance_config", lambda: {})
    monkeypatch.setattr(ui._auth, "is_configured", lambda: True)
    monkeypatch.setattr(ui._auth, "validate_session", lambda *args, **kwargs: True)
    monkeypatch.setattr(ui, "_ui_audit", ui.AuditChain(tmp_path / "audit.jsonl"))
    # These are separate registry RPCs, not the inference transport under test.
    monkeypatch.setattr(ui.requests, "get", lambda *a, **kw: Response([
        {"name": "Friendly name", "filename": "selected.gguf", "format": "gguf"},
    ]))
    monkeypatch.setattr(ui.requests, "post", lambda *a, **kw: Response({"safe_to_use": "true"}))
    client = ui.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-session"
    return client, ui_key, agent_key


@pytest.mark.parametrize("route", ROUTES + ["/api/inference/status", "planner", "executor"])
def test_every_caller_uses_its_credential_and_isolated_transport(boundary, monkeypatch, tmp_path, route):
    client, ui_key, agent_key = boundary
    expected = "8" if route in ("planner", "executor") else "7"
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(agent_key if expected == "8" else ui_key))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://must-not-contact.invalid:8123")
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login ambient password must-not-use\n")
    monkeypatch.setenv("NETRC", str(netrc))
    seen = []

    def send(session, request, **kwargs):
        assert session.trust_env is False
        assert request.headers["Authorization"] == "Bearer " + expected * 64
        assert kwargs["proxies"] == {}
        assert kwargs["allow_redirects"] is False
        seen.append(request)
        if request.url.endswith("/v1/models"):
            return Response({"data": [{"id": "selected.gguf"}]})
        if request.url.endswith("/completion"):
            return Response(PLAN if route == "planner" else {"content": "answer", "tokens_predicted": 2})
        body = json.loads(request.body)
        assert body["model"] == "selected.gguf"  # Never forward the display name.
        if body["stream"]:
            return Response(raw=("data: " + json.dumps(CHUNK) + "\n\ndata: [DONE]\n\n").encode(), stream=True)
        return Response(CHAT)

    monkeypatch.setattr(requests.Session, "send", send)
    if route == "planner":
        assert Planner(PolicyEngine())._plan_via_llm("Summarize", CapabilityToken(), 3)
    elif route == "executor":
        result = Executor(None)._inference_completion("Hello", Budgets())
        assert result["ok"] is True and result["tokens"] == 2
    elif route == "/api/inference/status":
        result = client.get(route).get_json()
        assert result["available"] is True and result["chat_models"][0]["usable"] is True
    else:
        result = client.post(route, json=dict(MESSAGES, model="Friendly name"))
        assert result.status_code == 200
        assert "[DONE]" in result.text if route.endswith("/stream") else "choices" in result.json
        result.close()
    assert len(seen) == (2 if route in ROUTES else 1)


@pytest.mark.parametrize("route", ROUTES + ["/api/inference/status", "planner", "executor"])
@pytest.mark.parametrize("credential", ["missing", "malformed", "unsafe"])
def test_unavailable_credential_never_reaches_inference(boundary, monkeypatch, route, credential):
    client, path, _ = boundary
    if credential == "missing":
        monkeypatch.delenv("INFERENCE_TOKEN_PATH")
    elif credential == "malformed":
        path.write_text("bad")
    else:
        path.chmod(0o660)
    with patch.object(requests.Session, "send", side_effect=AssertionError("inference RPC forbidden")) as send:
        if route == "planner":
            assert Planner(PolicyEngine())._plan_via_llm("Summarize", CapabilityToken(), 3) == []
        elif route == "executor":
            assert Executor(None)._inference_completion("Hello", Budgets())["ok"] is False
        elif route.endswith("/status"):
            assert client.get(route).json["available"] is False
        else:
            response = client.post(route, json=MESSAGES)
            assert response.status_code == 503
            assert response.json["integrity_failed"] is False
        send.assert_not_called()


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("phase", ["inventory", "generation"])
@pytest.mark.parametrize("upstream,expected", [(401, 503), (403, 503), (307, 502), (500, 502), ("timeout", 504), ("json", 502)])
def test_upstream_failures_are_not_success_or_integrity_failure(boundary, monkeypatch, route, phase, upstream, expected):
    client, _, _ = boundary
    responses = []

    def send(session, request, **kwargs):
        if phase == "generation" and request.url.endswith("/models"):
            response = Response({"data": [{"id": "selected.gguf"}]})
        elif upstream == "timeout":
            raise requests.Timeout("private request and credential details")
        elif upstream == "json":
            response = Response(raw=b"private non-json error")
        else:
            response = Response({"error": "private backend failure"}, status=upstream)
        responses.append(response)
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    result = client.post(route, json=MESSAGES)
    assert result.status_code == expected
    assert result.json["integrity_failed"] is False
    assert "private" not in result.text
    assert all(response.closed for response in responses)


@pytest.mark.parametrize("identity", ["/models/selected.gguf", "../selected.gguf", "unpromoted.gguf"])
def test_server_identity_is_never_reduced_to_registry_basename(boundary, monkeypatch, identity):
    client, _, _ = boundary
    monkeypatch.setattr(requests.Session, "send", lambda *a, **kw: Response({"data": [{"id": identity}]}))
    result = client.post("/api/chat", json=MESSAGES)
    assert result.status_code == 403 and result.json["integrity_failed"] is True


@pytest.mark.parametrize("route", ROUTES)
def test_registry_integrity_conflict_blocks_generation_as_integrity_failure(boundary, monkeypatch, route):
    client, _, _ = boundary
    seen = []

    def send(session, request, **kwargs):
        assert request.url.endswith("/v1/models"), "Rejected model must not reach generation"
        seen.append(request)
        return Response({"data": [{"id": "selected.gguf"}]})

    monkeypatch.setattr(requests.Session, "send", send)
    monkeypatch.setattr(ui.requests, "post", lambda *a, **kw: Response({
        "status": "unavailable", "safe_to_use": "false", "error": "private model path/hash details",
    }, status=409))
    result = client.post(route, json=MESSAGES)
    assert result.status_code == 403 and result.json["integrity_failed"] is True
    assert "private" not in result.text
    assert len(seen) == 1


@pytest.mark.parametrize("payload", [[], {}, {"data": {}}, {"data": [None]}, {"data": [{"id": None}]}])
def test_invalid_inventory_is_a_protocol_failure(boundary, monkeypatch, payload):
    client, _, _ = boundary
    monkeypatch.setattr(requests.Session, "send", lambda *a, **kw: Response(payload))
    result = client.post("/api/chat", json=MESSAGES)
    assert result.status_code == 502 and result.json["integrity_failed"] is False


@pytest.mark.parametrize("fault", ["timeout", "disconnect", "invalid-json", "invalid-shape", "truncated", "oversized", "invalid-utf8"])
def test_stream_errors_are_framed_and_close_upstream(boundary, monkeypatch, fault):
    client, _, _ = boundary
    response = Response(stream=True)

    def content(chunk_size):
        yield ("data: " + json.dumps(CHUNK) + "\n\n").encode()
        if fault == "timeout":
            raise requests.Timeout("sensitive upstream request")
        if fault == "disconnect":
            raise requests.ConnectionError("sensitive upstream request")
        yield {
            "invalid-json": b"data: private\n\n",
            "invalid-shape": b"data: []\n\n",
            "truncated": b"data: {",
            "oversized": b"x" * 65537,
            "invalid-utf8": b"data: \xff\n\n",
        }.get(fault, b"")

    response.iter_content = content
    monkeypatch.setattr(requests.Session, "send", lambda session, request, **kw: (
        Response({"data": [{"id": "selected.gguf"}]}) if request.url.endswith("/models") else response
    ))
    result = client.post("/api/chat/stream", json=MESSAGES)
    assert result.status_code == 200  # The first valid event has already been sent.
    frames = result.text.strip().split("\n\n")
    assert frames[-1] == "data: [DONE]"
    failure = json.loads(frames[-2].removeprefix("data: "))
    assert "error" in failure and failure["integrity_failed"] is False
    assert "private" not in result.text and "sensitive" not in result.text
    assert response.closed is True


def test_downstream_disconnect_closes_upstream(boundary, monkeypatch):
    client, _, _ = boundary
    response = Response(stream=True)
    response.iter_content = lambda chunk_size: iter([
        ("data: " + json.dumps(CHUNK) + "\n\n").encode(),
        b"data: [DONE]\n\n",
    ])
    monkeypatch.setattr(requests.Session, "send", lambda session, request, **kw: (
        Response({"data": [{"id": "selected.gguf"}]}) if request.url.endswith("/models") else response
    ))
    result = client.post("/api/chat/stream", json=MESSAGES, buffered=False)
    assert next(iter(result.response)).startswith(b"data: ")
    result.close()
    assert response.closed is True


@pytest.mark.parametrize("fault,expected", [("timeout", 504), ("body-timeout", 504), ("invalid", 502), ("empty", 502)])
def test_stream_failure_before_first_event_returns_http_error(boundary, monkeypatch, fault, expected):
    client, _, _ = boundary
    response = Response(stream=True)

    def content(chunk_size):
        if fault == "timeout":
            raise requests.Timeout("sensitive data")
        if fault == "body-timeout":
            raise requests.ConnectionError(ReadTimeoutError(None, "/private", "sensitive data"))
        if fault == "invalid":
            yield b"data: invalid\n\n"

    response.iter_content = content
    monkeypatch.setattr(requests.Session, "send", lambda session, request, **kw: (
        Response({"data": [{"id": "selected.gguf"}]}) if request.url.endswith("/models") else response
    ))
    result = client.post("/api/chat/stream", json=MESSAGES)
    assert result.status_code == expected
    assert result.json["integrity_failed"] is False
    assert response.closed is True


@pytest.mark.parametrize("route", ROUTES)
def test_credential_loss_after_inventory_prevents_generation(boundary, monkeypatch, route):
    client, path, _ = boundary
    calls = []

    def send(session, request, **kwargs):
        calls.append(request.url)
        assert request.url.endswith("/models")
        path.unlink()
        return Response({"data": [{"id": "selected.gguf"}]})

    monkeypatch.setattr(requests.Session, "send", send)
    result = client.post(route, json=MESSAGES)
    assert result.status_code == 503 and result.json["integrity_failed"] is False
    assert len(calls) == 1


@pytest.mark.parametrize("payload", [[], {}, {"content": None}, {"content": "answer", "tokens_predicted": True}])
def test_agent_rejects_invalid_completion_without_budget_changes(boundary, monkeypatch, payload):
    monkeypatch.setattr(requests.Session, "send", lambda *a, **kw: Response(payload))
    budgets = Budgets()
    result = Executor(None)._inference_completion("Hello", budgets)
    assert result["ok"] is False
    assert budgets.tokens_used == 0 and budgets.output_bytes_used == 0
    assert Planner(PolicyEngine())._plan_via_llm("Summarize", CapabilityToken(), 3) == []


def test_multiline_sse_data_is_one_valid_event():
    response = Response(raw=b':keepalive\r\ndata: {"choices":\r\ndata: [{"delta":{"content":"x"}}]}\r\n\r\ndata: [DONE]\r\n\r\n', stream=True)
    events = list(inference_client.chat_events(response))
    assert len(events) == 2
    assert json.loads(events[0][6:])["choices"][0]["delta"]["content"] == "x"


def test_native_llama_role_only_and_final_delta_shapes():
    chunks = [
        {"choices": [{"delta": {"role": "assistant", "content": None}, "finish_reason": None}]},
        CHUNK,
        {"choices": [{"delta": {}, "finish_reason": "length"}]},
        {"choices": [], "usage": {"completion_tokens": 2}},
    ]
    wire = "".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
    assert len(list(inference_client.chat_events(Response(raw=wire.encode(), stream=True)))) == 5
    with pytest.raises(inference_client.InferenceBackendError):
        inference_client.validate_chat({"choices": [{"message": {"content": None}}]})


@pytest.mark.parametrize("route", ["/api/chat", "/api/chat/search"])
@pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": [None]}, {"choices": [{"message": {"content": []}}]}, {"error": "private"}])
def test_invalid_chat_body_never_returns_success(boundary, monkeypatch, route, payload):
    client, _, _ = boundary
    monkeypatch.setattr(requests.Session, "send", lambda session, request, **kw: (
        Response({"data": [{"id": "selected.gguf"}]}) if request.url.endswith("/models") else Response(payload)
    ))
    result = client.post(route, json=MESSAGES)
    assert result.status_code == 502 and result.json["integrity_failed"] is False
    assert "private" not in result.text

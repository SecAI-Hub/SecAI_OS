"""Full-runtime admission stays separate from startup, status and sandbox mode."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))
os.environ.setdefault("AGENT_TASK_STATE_PATH", "")
from agent.agent import app as agent
from agent.agent.capabilities import clear_nonce_cache, create_token
from agent.agent.models import (
    SessionMode,
    Step,
    StepAction,
    StepStatus,
    Task,
    TaskStatus,
)
from common import runtime_assurance as gate
from ui import app as ui


def decision(**changes):
    return {"schema_version": 2, "verification_scope": "runtime", "policy_satisfied": True,
            "gpu_policy_satisfied": True, "gpu_mode": "required", "state": "attested",
            "assurance_mode": "hardware", "verified": True, "evidence_verified": True, **changes}


@pytest.mark.parametrize("changes", [
    {"schema_version": 1}, {"schema_version": True}, {"verification_scope": "bootstrap"},
    {"policy_satisfied": 1}, {"gpu_policy_satisfied": False}, {"gpu_mode": "absent"},
    {"state": "degraded"}, {"verified": False}, {"evidence_verified": False},
    {"assurance_mode": "software"}, {"assurance_mode": "evaluation"},
])
def test_bootstrap_old_or_partial_decisions_cannot_admit(changes):
    assert not gate.runtime_allowed(decision(**changes))


def test_evaluation_requires_explicit_nonhardware_runtime_pass():
    assert gate.runtime_allowed(decision(assurance_mode="evaluation", verified=False, evidence_verified=False))
    assert gate.runtime_allowed(decision(gpu_mode="no_gpu"))
    for field in decision():
        payload = decision()
        del payload[field]
        assert not gate.runtime_allowed(payload)


@pytest.fixture
def transport(monkeypatch):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json"}
    response.iter_content.return_value = [json.dumps(decision()).encode()]
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.return_value = response
    monkeypatch.setattr(gate.requests, "Session", lambda: session)
    return session, response


def test_native_transport_uses_only_explicit_auth_and_current_decision(transport, monkeypatch):
    session, response = transport
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    assert gate.require_runtime("http://127.0.0.1:8505", "a" * 64) == "required"
    assert session.trust_env is False
    args, kwargs = session.get.call_args
    assert args == ("http://127.0.0.1:8505/api/v1/verify",)
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["Authorization"] == "Bearer " + "a" * 64
    response.iter_content.return_value = [json.dumps(decision(gpu_policy_satisfied=False)).encode()]
    with pytest.raises(gate.RuntimeAssuranceUnavailable, match="^runtime assurance unavailable$"):
        gate.require_runtime("http://127.0.0.1:8505", "a" * 64)


@pytest.mark.parametrize("raw", [b'{"schema_version":2,"schema_version":2}', b'null',
                                 b'{"state":NaN}', b'{} {}', b'x' * (gate.MAX_BYTES + 1),
                                 json.dumps(decision(verification_scope="bootstrap")).encode()])
def test_malformed_or_oversize_native_reply_fails_closed(transport, raw):
    transport[1].iter_content.return_value = [raw]
    with pytest.raises(gate.RuntimeAssuranceUnavailable):
        gate.require_runtime("http://127.0.0.1:8505", "a" * 64)


@pytest.mark.parametrize("origin", ["http://localhost:8505", "http://127.0.0.1:8505/", "http://127.0.0.1:8505?x=1",
                                    "http://user@127.0.0.1:8505", "http://10.0.0.1:8505", "https://127.0.0.1:8505"])
def test_bad_origin_rejected_before_network(transport, origin):
    with pytest.raises(gate.RuntimeAssuranceUnavailable):
        gate.require_runtime(origin, "a" * 64)
    transport[0].get.assert_not_called()


@pytest.mark.parametrize("status", [301, 401, 500, 503])
def test_nonpassing_http_never_admits(transport, status):
    transport[1].status_code = status
    with pytest.raises(gate.RuntimeAssuranceUnavailable):
        gate.require_runtime("http://127.0.0.1:8505", "a" * 64)


@pytest.fixture
def ui_client(tmp_path, monkeypatch):
    monkeypatch.setattr(ui._auth, "is_configured", lambda: True)
    monkeypatch.setattr(ui._auth, "validate_session", lambda *args, **kwargs: True)
    monkeypatch.setattr(ui, "_is_sandbox_deployment", lambda: False)
    monkeypatch.setattr(ui, "_ui_audit", Mock())
    monkeypatch.setattr(ui, "_read_service_token", lambda target: "a" * 64)
    client = ui.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer synthetic-session"
    return client


@pytest.mark.parametrize("route", ["/api/chat", "/api/chat/stream", "/api/chat/search"])
def test_ui_denial_prevents_model_search_and_inference(ui_client, monkeypatch, route):
    denied = Mock(side_effect=gate.RuntimeAssuranceUnavailable())
    monkeypatch.setattr(gate, "require_runtime", denied)
    model, inference, search = Mock(), Mock(), Mock()
    monkeypatch.setattr(ui, "_verify_active_model", model)
    monkeypatch.setattr(ui.inference_http, "post", inference)
    monkeypatch.setattr(ui.requests, "post", search)
    response = ui_client.post(route, json={"messages": [{"role": "user", "content": "private"}], "search": True})
    assert response.status_code == 503
    assert response.json == {
        "error": "Safety checks are not ready. Open Security Status for details.",
        "code": "runtime_assurance_unavailable", "status_url": "/security",
    }
    model.assert_not_called()
    inference.assert_not_called()
    search.assert_not_called()
    ui._ui_audit.append.assert_called_once_with("inference_blocked", {"reason": gate.UNAVAILABLE})


def test_ui_native_allow_and_explicit_sandbox_skip(ui_client, monkeypatch):
    check = Mock()
    monkeypatch.setattr(gate, "require_runtime", check)
    with ui.app.test_request_context():
        assert ui._runtime_chat_guard() is None
    check.assert_called_once_with(ui.ATTESTOR_URL, "a" * 64)
    check.reset_mock()
    monkeypatch.setattr(ui, "_is_sandbox_deployment", lambda: True)
    with ui.app.test_request_context():
        assert ui._runtime_chat_guard() is None
    check.assert_not_called()


@pytest.mark.parametrize("route", ["/api/chat", "/api/chat/stream", "/api/chat/search"])
def test_ui_rechecks_after_model_or_search_delay(ui_client, monkeypatch, route):
    check = Mock(side_effect=[None, gate.RuntimeAssuranceUnavailable()])
    monkeypatch.setattr(gate, "require_runtime", check)
    monkeypatch.setattr(ui, "_verify_active_model", lambda body: {"safe": True})
    inference = Mock()
    monkeypatch.setattr(ui.inference_http, "post", inference)
    response = ui_client.post(route, json={"messages": [{"role": "user", "content": "private"}]})
    assert response.status_code == 503
    assert response.json["code"] == "runtime_assurance_unavailable"
    assert response.json["status_url"] == "/security"
    assert check.call_count == 2
    inference.assert_not_called()


@pytest.fixture
def agent_client(tmp_path, monkeypatch):
    clear_nonce_cache()
    monkeypatch.delenv("SECURE_AI_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(agent, "_tasks", {})
    monkeypatch.setattr(agent, "_audit", Mock())
    monkeypatch.setattr(agent, "_persist_tasks", lambda: True)
    agent._containment_frozen.clear()
    token = tmp_path / "token"
    token.write_text("a" * 64)
    monkeypatch.setenv("AGENT_UI_TOKEN_PATH", str(token))
    monkeypatch.setenv("RUNTIME_ATTESTOR_TOKEN_PATH", str(token))
    client = agent.app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + "a" * 64
    return client


def test_agent_denial_blocks_planner_including_heuristic_fallback(agent_client, monkeypatch):
    monkeypatch.setattr(gate, "require_runtime", Mock(side_effect=gate.RuntimeAssuranceUnavailable()))
    planner = Mock()
    monkeypatch.setattr(agent._planner, "plan", planner)
    response = agent_client.post("/v1/task", json={"intent": "read a document", "workspace": ["user_docs"]})
    assert response.status_code == 503 and response.json == {"error": gate.UNAVAILABLE}
    planner.assert_not_called()
    assert any(call.args[0] == "runtime_assurance_blocked" for call in agent._audit.append.call_args_list)
    assert agent_client.get("/v1/tasks").status_code == 200


def test_agent_rechecks_before_each_step_after_startup_pass(agent_client, monkeypatch):
    sequence = Mock(side_effect=[None, gate.RuntimeAssuranceUnavailable()])
    monkeypatch.setattr(gate, "require_runtime", sequence)
    monkeypatch.setattr(agent, "_verify_task_capability", lambda task: (True, ""))
    monkeypatch.setattr(agent, "verify_step_signature", lambda *args: (True, ""))
    monkeypatch.setattr(agent, "revalidate_step_capability", lambda *args: (True, ""))
    task = Task(intent="synthetic", status=TaskStatus.RUNNING, capability=create_token(SessionMode.STANDARD),
                steps=[Step(action=StepAction.READ_FILE, status=StepStatus.APPROVED) for _ in range(2)])
    executed = []
    def execute(step, *args):
        executed.append(step.step_id)
        step.status = StepStatus.COMPLETED
    monkeypatch.setattr(agent._executor, "execute", execute)
    agent._execute_task(task)
    assert executed == [task.steps[0].step_id]
    assert task.steps[1].status == StepStatus.FAILED
    assert task.steps[1].error == gate.UNAVAILABLE
    assert task.status == TaskStatus.FAILED and sequence.call_count == 2


def test_agent_only_explicit_sandbox_skips_native_check(agent_client, monkeypatch):
    check = Mock(side_effect=gate.RuntimeAssuranceUnavailable())
    monkeypatch.setattr(gate, "require_runtime", check)
    with pytest.raises(gate.RuntimeAssuranceUnavailable):
        agent._require_runtime_assurance()
    monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")
    agent._require_runtime_assurance()
    assert check.call_count == 1


@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_ui_generation_denial_prevents_backend_dispatch(ui_client, monkeypatch, kind):
    monkeypatch.setattr(gate, "require_runtime", Mock(side_effect=gate.RuntimeAssuranceUnavailable()))
    backend = Mock()
    monkeypatch.setattr(ui.requests, "post", backend)
    response = ui_client.post(f"/api/generate/{kind}", json={"model": "local", "prompt": "private"})
    assert response.status_code == 503
    assert response.json == {"error": "Safety checks are not ready. Open Security Status for details.",
                             "code": "runtime_assurance_unavailable", "status_url": "/security"}
    backend.assert_not_called()


@pytest.mark.parametrize("sandbox", [False, True])
@pytest.mark.parametrize("kind", ["image", "video", "img2img"])
def test_ui_generation_native_admission_and_explicit_sandbox_dispatch(ui_client, monkeypatch, kind, sandbox):
    check = Mock(return_value="no_gpu")
    monkeypatch.setattr(gate, "require_runtime", check)
    monkeypatch.setattr(ui, "_is_sandbox_deployment", lambda: sandbox)
    backend = Mock(return_value=Mock(status_code=200, json=lambda: {"generated": True}))
    monkeypatch.setattr(ui.requests, "post", backend)
    response = ui_client.post(f"/api/generate/{kind}", json={"model": "local", "prompt": "private"})
    assert response.status_code == 200 and response.json == {"generated": True}
    assert check.call_count == (0 if sandbox else 1)
    backend.assert_called_once()


@pytest.mark.parametrize("mode", ["required", "optional", "no_gpu"])
def test_native_transport_returns_validated_gpu_mode(transport, mode):
    transport[1].iter_content.return_value = [json.dumps(decision(gpu_mode=mode)).encode()]
    assert gate.require_runtime("http://127.0.0.1:8505", "a" * 64) == mode

"""Approval/history JSON boundary; rendered interaction is qualified separately."""
from pathlib import Path
import sys
from unittest.mock import patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))
import ui.app as ui


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(ui._auth, "is_configured", lambda: True)
    monkeypatch.setattr(ui._auth, "validate_session", lambda *args, **kwargs: True)
    monkeypatch.setattr(ui, "_ui_audit", ui.AuditChain(tmp_path / "ui-audit.jsonl"))
    with ui.app.test_client() as client:
        client.environ_base["HTTP_AUTHORIZATION"] = "Bearer synthetic-session"
        yield client


@pytest.mark.parametrize("route", ["/api/agent/tasks", "/api/agent/task/test-task"])
def test_json_review_content_is_exact_and_not_html_encoded(client, route):
    payload = {"params": {"path": '/outputs/a&b.txt', "content": '<script>alert("fixture")</script>&\n\u202e'},
               "result": {"url": "javascript:alert(1)"}}
    with patch.object(ui, "_agent_request", return_value=(payload, 200)):
        response = client.get(route)
    assert response.json == payload
    assert response.mimetype == "application/json"
    assert "no-store" in response.headers["Cache-Control"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_review_identifiers_are_forwarded_without_generic_approval(client, action):
    body = {"step_ids": ["111111111111"], "expected_plan_revision": "a" * 64, "step_hashes": {"111111111111": "b" * 64}}
    with patch.object(ui, "_agent_request", return_value=({"status": "pending_approval"}, 200)) as request:
        response = client.post("/api/agent/task/task/" + action, json=body)
    assert response.status_code == 200
    assert request.call_args.args == ("POST", "/v1/task/task/" + action)
    assert request.call_args.kwargs["json_body"] == body


@pytest.mark.parametrize("body", [
    {"approve_all": True}, {"deny_all": True}, {"step_ids": ["111111111111", "111111111111"]},
    {"expected_plan_revision": "A" * 64}, {"step_hashes": {"111111111111": 123}},
    {"step_ids": "111111111111"}, {"step_ids": ["../step"]}, {"step_hashes": []},
])
def test_malformed_review_never_reaches_agent(client, body):
    with patch.object(ui, "_agent_request", side_effect=AssertionError("must not proxy")) as request:
        assert client.post("/api/agent/task/task/approve", json=body).status_code == 400
    request.assert_not_called()


@pytest.mark.parametrize("path,upstream", [("/api/agent/history", "/v1/history"), ("/api/agent/history/task", "/v1/history/task")])
def test_history_removal_uses_delete_and_sanitized_audit(client, path, upstream):
    with patch.object(ui, "_agent_request", return_value=({"deleted": 1, "active_remaining": 2}, 200)) as request, \
         patch.object(ui._ui_audit, "append") as audit:
        response = client.delete(path)
    assert response.status_code == 200
    assert request.call_args.args == ("DELETE", upstream)
    assert request.call_args.kwargs.get("json_body") is None
    assert set(audit.call_args.args[1]) == {"scope", "status_code"}


def test_tcp_history_delete_cannot_fall_back_to_post(monkeypatch):
    monkeypatch.setattr(ui, "AGENT_SOCKET", "")
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"deleted":1}'
    response._content_consumed = True
    with patch.object(ui.requests, "delete", return_value=response) as delete, \
         patch.object(ui.requests, "post", side_effect=AssertionError("wrong HTTP method")):
        assert ui._agent_request("DELETE", "/v1/history")[0] == {"deleted": 1}
    assert delete.call_args.kwargs["allow_redirects"] is False
    assert "json" not in delete.call_args.kwargs


def test_history_policy_readiness_is_forwarded(client):
    policy = {"storage_policy": "metadata_only", "history_ready": False, "legacy_state_blocked": True}
    with patch.object(ui, "_agent_request", return_value=(policy, 200)) as request:
        response = client.get("/api/agent/history/policy")
    assert response.json == policy
    assert request.call_args.args == ("GET", "/v1/history/policy")


def test_invalid_upstream_review_numbers_fail_closed(client):
    with patch.object(ui, "_agent_request", return_value=({"approval_budgets": {"max_steps": float("nan")}}, 200)):
        response = client.get("/api/agent/task/task")
    assert response.status_code == 502

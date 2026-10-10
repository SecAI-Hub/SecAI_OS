import io
import json
import sys
import threading
from pathlib import Path

import pytest
import requests
from werkzeug.test import EnvironBuilder

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/search-mediator"))
import app as sm


@pytest.fixture
def gateway(monkeypatch):
    events, calls = [], []
    policy = {"version": 1, "search": {"enabled": True, "allowed_categories": ["general"],
              "allowed_engines": ["wikipedia"], "differential_privacy": {
                  "enabled": False, "decoy_count": 0, "uniqueness_mode": "allow", "batch_window": 0}}}
    monkeypatch.setattr(sm, "load_policy", lambda: policy)
    monkeypatch.setattr(sm, "_require_service_token", lambda: (True, None))
    if hasattr(sm, "_get_session_mode"):
        monkeypatch.setattr(sm, "_get_session_mode", lambda: "normal")
    monkeypatch.setattr(sm, "_random_delay", lambda: 0)
    monkeypatch.setattr(sm._egress, "sleep", lambda _seconds: None)

    class Audit:
        fail_event = None
        def append(self, event, payload):
            if event == self.fail_event:
                raise OSError("synthetic unavailable audit")
            events.append((event, payload))
    audit = Audit()
    monkeypatch.setattr(sm, "_audit_chain", audit)

    def transport(origin, endpoint, **kwargs):
        assert events[-1][0] == "search_egress_intent"
        calls.append((endpoint, kwargs))
        return {"results": []} if kwargs["expect_json"] else 200
    monkeypatch.setattr(sm, "_transport_get", transport)
    return policy, audit, events, calls


@pytest.mark.parametrize("route", ["/v1/search", "/v1/search/test", "/health"])
def test_intent_failure_prevents_every_network_path(gateway, route):
    policy, audit, events, calls = gateway
    policy["search"]["differential_privacy"].update(enabled=True, decoy_count=2)
    audit.fail_event = "search_egress_intent"
    client = sm.app.test_client()
    response = client.post(route, json={"query": "treatment research"}) if route == "/v1/search" else client.get(route)
    assert response.status_code == 503
    assert response.get_json()["egress"] == "not_sent"
    assert not calls


@pytest.mark.parametrize("event", ["search_egress_outcome", "web_search"])
def test_post_egress_audit_failure_is_explicitly_not_safe_to_retry(gateway, event):
    _, audit, _, calls = gateway
    audit.fail_event = event
    response = sm.app.test_client().post("/v1/search", json={"query": "public facts"})
    assert response.status_code == 503
    result = response.get_json()
    assert result["egress"] == "may_have_been_sent"
    assert result["retry_safe"] is False
    assert result["egress_attempts"] == len(calls) == 1
    assert len(result["request_id"]) == 32


def test_cover_decoys_and_search_have_ordered_minimized_audit(gateway):
    policy, _, events, calls = gateway
    policy["search"]["differential_privacy"].update(enabled=True, decoy_count=2)
    response = sm.app.test_client().post("/v1/search", json={"query": "treatment research"})
    assert response.status_code == 200
    assert len(calls) == 4
    names = [event for event, _ in events]
    assert names == ["search_egress_intent", "search_egress_outcome"] * 4 + ["web_search"]
    assert len({payload["request_id"] for _, payload in events}) == 1
    assert "treatment" not in json.dumps(events)
    assert response.get_json()["decoys_sent"] == 2
    assert response.get_json()["decoys_attempted"] == 2


@pytest.mark.parametrize("body", [[], True, 10, {"query": []}, {"query": {}}, {"query": "hello", "categories": []}, {"query": "hello", "categories": "../../admin"}])
def test_invalid_request_types_never_reach_transport(gateway, body):
    response = sm.app.test_client().post("/v1/search", json=body)
    assert response.status_code == 400
    assert not gateway[-1]


def test_streamed_body_limit_does_not_trust_content_length(gateway):
    body = json.dumps({"query": "x" * (sm.MAX_SEARCH_BODY_BYTES + 1)}).encode()
    environment = EnvironBuilder(path="/v1/search", method="POST", input_stream=io.BytesIO(body), content_type="application/json").get_environ()
    environment.pop("CONTENT_LENGTH", None)
    environment["wsgi.input_terminated"] = True
    response = sm.app.test_client().open(environment)
    assert response.status_code == 413
    assert not gateway[-1]


def test_admission_is_bounded_and_liveness_remains_responsive(gateway, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    responses = []
    def slow_transport(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return {"results": []}
    monkeypatch.setattr(sm, "_transport_get", slow_transport)
    worker = threading.Thread(target=lambda: responses.append(sm.app.test_client().post("/v1/search", json={"query":"public facts"}).status_code))
    worker.start()
    try:
        assert entered.wait(1)
        response = sm.app.test_client().post("/v1/search", json={"query":"public facts"})
        assert response.status_code == 429
        assert sm.app.test_client().get("/live").status_code == 200
    finally:
        release.set()
        worker.join(timeout=2)
    assert responses == [200]


def test_query_bearing_http_errors_never_enter_logs(gateway, monkeypatch, caplog):
    secret = "opaqueSyntheticPrivateQuery"
    def failing_transport(*args, **kwargs):
        raise requests.HTTPError("failure for http://localhost/search?q=" + secret)
    monkeypatch.setattr(sm, "_transport_get", failing_transport)
    with caplog.at_level("WARNING"):
        response = sm.app.test_client().post("/v1/search", json={"query": secret})
    assert response.status_code == 502
    assert secret not in caplog.text
    assert secret not in json.dumps(gateway[2])


@pytest.mark.parametrize("route", ["/v1/search", "/v1/search/test", "/health"])
def test_offline_mode_blocks_all_network_routes(gateway, monkeypatch, route):
    monkeypatch.setattr(sm, "_get_session_mode", lambda: "offline-only")
    client = sm.app.test_client()
    response = client.post(route, json={"query":"public facts"}) if route == "/v1/search" else client.get(route)
    assert response.status_code == (200 if route == "/health" else 403)
    assert not gateway[-1]

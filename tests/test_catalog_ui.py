"""Durable action routes retain authentication, profile, JSON and cookie gates."""
from unittest.mock import patch
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/ui"))
import ui.app as ui_app
from common.bounded_state import StateUnavailable

@pytest.fixture
def client(tmp_path):
    # Other UI tests intentionally reload the module. Bind its current Flask
    # instance instead of retaining an app object imported before that reload.
    ui_app.app.config["TESTING"] = True
    with patch.object(ui_app, "_ui_audit", ui_app.AuditChain(tmp_path / "ui-audit.jsonl")), \
            patch.object(ui_app._auth, "is_configured", return_value=True), \
            patch.object(ui_app._auth, "validate_session", return_value=True):
        with ui_app.app.test_client() as client:
            client.environ_base["HTTP_AUTHORIZATION"] = "Bearer synthetic-test-session"
            yield client


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    jobs = ui_app.CatalogJobs(tmp_path / "jobs")
    monkeypatch.setattr(ui_app, "_catalog_jobs", jobs)
    monkeypatch.setattr(ui_app, "QUARANTINE_DIR", tmp_path)
    monkeypatch.setattr(ui_app, "_airlock_check_egress", lambda *a, **k: (True, 200, ""))
    return jobs


def test_profile_gate_precedes_admission(client, jobs):
    entry = ui_app.MODEL_CATALOG[0]
    with patch.object(ui_app, "_read_active_profile", return_value=("offline_private", False)):
        result = client.post("/api/catalog/download", json={"url": entry["url"], "filename": entry["filename"]})
    assert result.status_code == 409
    assert jobs.snapshot() == {}


def test_expired_grant_race_is_401_without_admission(client, jobs):
    entry = ui_app.MODEL_CATALOG[0]
    profile = {"profile": "research", "mode": "appliance", "generation": "", "session": ""}
    with patch.object(ui_app, "_catalog_profile_binding", return_value=profile), \
            patch.object(ui_app._auth, "grant", side_effect=PermissionError("expired")):
        result = client.post("/api/catalog/download", json={"url": entry["url"], "filename": entry["filename"]})
    assert result.status_code == 401
    assert jobs.snapshot() == {}


@pytest.mark.parametrize("action", ["retry", "cancel"])
@pytest.mark.parametrize("payload", [None, [], {"grant": "untrusted"}, {"force": True}])
def test_job_actions_require_empty_json_object(client, jobs, action, payload):
    result = client.post("/api/catalog/jobs/" + "a" * 32 + "/" + action,
                         data="null" if payload is None else __import__("json").dumps(payload),
                         content_type="application/json")
    assert result.status_code == 400
    assert jobs.snapshot() == {}


def test_cookie_refresh_failure_is_controlled_and_retains_security_headers(client, jobs):
    client.set_cookie("session_token", "a" * 64)
    with patch.object(ui_app._auth, "get_session_info", side_effect=StateUnavailable("synthetic failure")):
        response = client.post("/api/catalog/jobs/" + "a" * 32 + "/cancel", json={})
    assert response.status_code == 503
    assert response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert any("session_token=;" in value for value in response.headers.getlist("Set-Cookie"))


def test_runtime_readiness_is_503_when_store_unavailable(client, jobs, monkeypatch):
    monkeypatch.setenv("CATALOG_WORKER_ENABLED", "1")
    with patch.object(ui_app._auth._store, "require_current_epoch", side_effect=StateUnavailable("synthetic")):
        response = client.get("/health")
    assert response.status_code == 503
    assert response.json["status"] == "unavailable"

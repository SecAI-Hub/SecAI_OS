"""Tests for the Secure AI web UI Flask app."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "ui"))

from ui.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealthAndStatus:
    def test_status_endpoint_returns_json(self, client):
        with patch("ui.app.requests") as mock_req:
            mock_req.get.side_effect = Exception("not running")
            resp = client.get("/api/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "services" in data

    def test_models_endpoint_empty_when_registry_down(self, client):
        import requests as req_lib
        with patch("ui.app.requests.get", side_effect=req_lib.ConnectionError("not running")):
            resp = client.get("/api/models")
            assert resp.status_code == 200
            assert resp.get_json() == []


class TestModelImport:
    def test_import_rejects_bad_extension(self, client):
        from io import BytesIO
        data = {"file": (BytesIO(b"fake"), "model.pkl")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "not allowed" in resp.get_json()["error"]

    def test_import_requires_file_or_path(self, client):
        resp = client.post("/api/models/import", json={})
        assert resp.status_code == 400


class TestPages:
    def test_chat_page_returns_html(self, client):
        with patch("ui.app.load_appliance_config", return_value={}):
            resp = client.get("/chat")
            assert resp.status_code == 200

    def test_models_page_returns_html(self, client):
        resp = client.get("/models")
        assert resp.status_code == 200


class TestSecurityStats:
    def test_security_stats_handles_unreachable(self, client):
        with patch("ui.app.requests") as mock_req:
            mock_req.get.side_effect = Exception("down")
            resp = client.get("/api/security/stats")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "tool_firewall" in data
            assert "airlock" in data

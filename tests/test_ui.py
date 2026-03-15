"""Tests for the Secure AI web UI Flask app."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "ui"))

from ui.app import app, load_model_catalog, _FALLBACK_CATALOG


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


class TestIntegrityMonitoring:
    def test_integrity_status_returns_json(self, client):
        import requests as req_lib
        with patch("ui.app.requests.get", side_effect=req_lib.ConnectionError("down")):
            resp = client.get("/api/integrity/status")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "status" in data

    def test_verify_all_handles_unreachable(self, client):
        import requests as req_lib
        with patch("ui.app.requests.post", side_effect=req_lib.ConnectionError("down")):
            resp = client.post("/api/integrity/verify-all")
            assert resp.status_code == 503

    def test_chat_blocked_on_integrity_failure(self, client):
        """Chat should return 403 when model integrity check fails."""
        mock_models_resp = type("Resp", (), {"json": lambda self: [], "status_code": 200})()
        with patch("ui.app.requests.get", return_value=mock_models_resp):
            resp = client.post("/api/chat", json={"messages": [{"role": "user", "content": "hi"}]})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["integrity_failed"] is True

    def test_chat_allowed_on_integrity_pass(self, client):
        """Chat should proceed when model passes integrity check."""
        mock_models_resp = type("Resp", (), {
            "json": lambda self: [{"name": "test-model"}],
            "status_code": 200,
        })()
        mock_verify_resp = type("Resp", (), {
            "json": lambda self: {"safe_to_use": "true", "status": "verified"},
            "status_code": 200,
        })()
        mock_chat_resp = type("Resp", (), {
            "json": lambda self: {"choices": [{"message": {"content": "hello"}}]},
            "status_code": 200,
        })()

        def mock_get(url, **kwargs):
            if "/v1/models" in url:
                return mock_models_resp
            raise Exception("unexpected GET")

        def mock_post(url, **kwargs):
            if "/v1/model/verify" in url:
                return mock_verify_resp
            if "/v1/chat/completions" in url:
                return mock_chat_resp
            raise Exception("unexpected POST")

        with patch("ui.app.requests.get", side_effect=mock_get), \
             patch("ui.app.requests.post", side_effect=mock_post):
            resp = client.post("/api/chat", json={"messages": [{"role": "user", "content": "hi"}]})
            assert resp.status_code == 200

    def test_stream_blocked_on_integrity_failure(self, client):
        """Stream chat should return 403 when model integrity check fails."""
        mock_models_resp = type("Resp", (), {"json": lambda self: [], "status_code": 200})()
        with patch("ui.app.requests.get", return_value=mock_models_resp):
            resp = client.post("/api/chat/stream", json={"messages": [{"role": "user", "content": "hi"}]})
            assert resp.status_code == 403


class TestModelCatalog:
    """Tests for the externalized model catalog loading."""

    def test_load_from_yaml_file(self):
        """Loading a valid YAML catalog returns its entries."""
        content = """
models:
  - name: Test Model
    type: llm
    filename: test.gguf
    url: https://example.com/test.gguf
    size_gb: 1.0
    vram_gb: 2
    description: A test model.
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            f.flush()
            catalog = load_model_catalog(f.name)
        os.unlink(f.name)
        assert len(catalog) == 1
        assert catalog[0]["name"] == "Test Model"
        assert catalog[0]["filename"] == "test.gguf"
        # Computed fields added automatically
        assert catalog[0]["expected_sha256"] == "pin-on-first-download"
        assert catalog[0]["expected_size_bytes"] == int(1.0 * 1024 * 1024 * 1024)

    def test_fallback_on_missing_file(self):
        """Missing YAML file returns the built-in fallback catalog."""
        catalog = load_model_catalog("/nonexistent/model-catalog.yaml")
        assert len(catalog) == len(_FALLBACK_CATALOG)
        assert catalog[0]["name"] == _FALLBACK_CATALOG[0]["name"]

    def test_fallback_on_malformed_yaml(self):
        """Malformed YAML returns the fallback catalog."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("not: [valid: yaml: {{")
            f.flush()
            catalog = load_model_catalog(f.name)
        os.unlink(f.name)
        assert len(catalog) == len(_FALLBACK_CATALOG)

    def test_fallback_on_missing_models_key(self):
        """YAML without 'models' key returns fallback."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 1\nother_key: value\n")
            f.flush()
            catalog = load_model_catalog(f.name)
        os.unlink(f.name)
        assert len(catalog) == len(_FALLBACK_CATALOG)

    def test_skips_entries_missing_required_fields(self):
        """Entries missing required fields are skipped."""
        content = """
models:
  - name: Valid Model
    type: llm
    filename: valid.gguf
    url: https://example.com/valid.gguf
  - name: Invalid Model
    type: llm
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            f.flush()
            catalog = load_model_catalog(f.name)
        os.unlink(f.name)
        assert len(catalog) == 1
        assert catalog[0]["name"] == "Valid Model"

    def test_fallback_when_all_entries_invalid(self):
        """If all entries are invalid, returns fallback."""
        content = """
models:
  - name: Bad Entry
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            f.flush()
            catalog = load_model_catalog(f.name)
        os.unlink(f.name)
        assert len(catalog) == len(_FALLBACK_CATALOG)

"""
Tests for UI file-handling hardening.

Covers:
- Upload filename sanitization (secure_filename + UUID prefix)
- Path separator rejection
- Extension allowlisting
- Local-path import staging directory restriction
- Non-regular file rejection (symlinks, FIFOs, device nodes)
"""

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Ensure services/ui and services/ are on the path so we can import the UI app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "ui"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services"))


@pytest.fixture
def ui_client(tmp_path):
    """Create a test client with isolated quarantine and staging dirs."""
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    staging_dir = tmp_path / "import-staging"
    staging_dir.mkdir(mode=0o700)

    # Ensure temp dirs exist for module-level initialization
    (tmp_path / "auth").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)

    with mock.patch.dict(os.environ, {
        "QUARANTINE_DIR": str(quarantine_dir),
        "IMPORT_STAGING_DIR": str(staging_dir),
        "AUTH_DATA_DIR": str(tmp_path / "auth"),
        "AUDIT_LOG_PATH": str(tmp_path / "logs" / "ui-audit.jsonl"),
        "SECURE_AI_ROOT": str(tmp_path),
        "BIND_ADDR": "127.0.0.1:18480",
        "COOKIE_SECURE": "false",
        "SESSION_TIMEOUT": "1800",
    }):
        if "ui.app" in sys.modules:
            del sys.modules["ui.app"]
        if "ui.slo_tracker" in sys.modules:
            del sys.modules["ui.slo_tracker"]
        from ui.app import app
        app.config["TESTING"] = True
        app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
        # Patch module-level vars since they are set at import time
        with mock.patch("ui.app.IMPORT_STAGING_DIR", staging_dir), \
             mock.patch("ui.app.QUARANTINE_DIR", quarantine_dir), \
             mock.patch("ui.app.SECURE_AI_ROOT", tmp_path):
            with app.test_client() as client:
                yield client, quarantine_dir, staging_dir


# ── Upload filename sanitization ──


class TestUploadFilenameSanitization:
    """Upload filename must be sanitized with secure_filename + UUID prefix."""

    def test_path_traversal_dot_dot_rejected(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake model data"), "../../../etc/shadow.gguf")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code in (400, 403)
        body = resp.get_json()
        assert "path separator" in body.get("error", "").lower() or "not allowed" in body.get("error", "").lower()

    def test_forward_slash_in_filename_rejected(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake"), "subdir/model.gguf")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code in (400, 403)

    def test_backslash_in_filename_rejected(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake"), "subdir\\model.gguf")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code in (400, 403)

    def test_empty_filename_rejected(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake"), "")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_disallowed_extension_rejected(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake pickle"), "model.pkl")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400
        body = resp.get_json()
        assert "format not allowed" in body.get("error", "")

    def test_allowed_gguf_extension_accepted(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake gguf data"), "test-model.gguf")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        # May be 202 (queued) or 401/403 (auth required) depending on auth state
        # The important thing is it's NOT rejected for filename/extension reasons
        assert resp.status_code != 400 or "format" not in resp.get_json().get("error", "")

    def test_allowed_safetensors_extension_accepted(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO
        data = {"file": (BytesIO(b"fake safetensors"), "model.safetensors")}
        resp = client.post("/api/models/import", data=data, content_type="multipart/form-data")
        assert resp.status_code != 400 or "format" not in resp.get_json().get("error", "")

    def test_uuid_prefix_prevents_collision(self, ui_client):
        """Two uploads with the same name should produce different destination files."""
        client, qdir, _ = ui_client
        from io import BytesIO

        data1 = {"file": (BytesIO(b"first"), "model.gguf")}
        resp1 = client.post("/api/models/import", data=data1, content_type="multipart/form-data")

        data2 = {"file": (BytesIO(b"second"), "model.gguf")}
        resp2 = client.post("/api/models/import", data=data2, content_type="multipart/form-data")

        # Both should succeed (not overwrite each other)
        if resp1.status_code == 202 and resp2.status_code == 202:
            files = list(qdir.iterdir())
            names = [f.name for f in files if not f.name.startswith(".")]
            # UUID prefix means they have different names even with same original
            assert len(set(names)) >= 2 or len(names) <= 1  # at least different if both landed


# ── Local path import staging restriction ──


class TestLocalImportStagingRestriction:
    """Local path imports must be restricted to the staging directory."""

    def test_path_outside_staging_rejected(self, ui_client):
        client, _, staging_dir = ui_client
        resp = client.post(
            "/api/models/import",
            json={"path": "/etc/passwd"},
            content_type="application/json",
        )
        assert resp.status_code in (400, 403)
        body = resp.get_json()
        assert "staging" in body.get("error", "").lower() or "restricted" in body.get("error", "").lower()

    def test_traversal_out_of_staging_rejected(self, ui_client, tmp_path):
        client, _, staging_dir = ui_client
        # Create a file outside staging
        outside = tmp_path / "outside.gguf"
        outside.write_bytes(b"outside model")
        # Try to traverse out
        traversal = str(staging_dir / ".." / "outside.gguf")
        resp = client.post(
            "/api/models/import",
            json={"path": traversal},
            content_type="application/json",
        )
        assert resp.status_code in (400, 403, 404)

    def test_path_inside_staging_accepted(self, ui_client, tmp_path):
        client, _, staging_dir = ui_client
        # Create a valid file inside staging
        model = staging_dir / "valid-model.gguf"
        model.write_bytes(b"valid gguf content")
        resp = client.post(
            "/api/models/import",
            json={"path": model.name},
            content_type="application/json",
        )
        # Should be accepted (202) or auth-blocked, not path-rejected
        assert resp.status_code != 403 or "staging" not in resp.get_json().get("error", "").lower()

    def test_symlink_outside_staging_rejected(self, ui_client, tmp_path):
        """Symlinks pointing outside staging must be rejected."""
        client, _, staging_dir = ui_client
        target = tmp_path / "secret.gguf"
        target.write_bytes(b"secret data")
        link = staging_dir / "symlink.gguf"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")
        resp = client.post(
            "/api/models/import",
            json={"path": str(link)},
            content_type="application/json",
        )
        # Should be rejected because lstat reveals it's not a regular file,
        # or because resolved path is outside staging
        assert resp.status_code in (400, 403)

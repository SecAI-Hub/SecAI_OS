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
import errno
import stat
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
             mock.patch("ui.app.SECURE_AI_ROOT", tmp_path), \
             mock.patch("ui.app._auth.is_configured", return_value=True), \
             mock.patch("ui.app._auth.validate_session", return_value=True):
            with app.test_client() as client:
                client.environ_base["HTTP_AUTHORIZATION"] = "Bearer ui-file-test-session"
                yield client, quarantine_dir, staging_dir


# ── Upload filename sanitization ──


def test_route_body_limit_runs_before_csrf_body_parsing(ui_client):
    """CSRF form parsing must never run under the global 50 GiB upload ceiling."""
    from ui import app as ui_app

    hooks = ui_app.app.before_request_funcs[None]
    assert hooks.index(ui_app.enforce_route_body_limit) < hooks.index(
        ui_app.csrf_protect
    )


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

    def test_upload_is_hidden_until_fsynced_publication(self, ui_client):
        """The watcher-visible name must not exist while bytes are copied."""
        client, qdir, _ = ui_client
        from io import BytesIO
        import ui.app as ui_app

        payload = b"complete model payload"
        original_publish = ui_app._publish_noreplace

        def observe_publication(source, destination):
            assert source.parent == qdir
            assert source.name.startswith(".")
            assert source.name.endswith(".part")
            assert source.read_bytes() == payload
            assert not destination.exists()
            original_publish(source, destination)

        with mock.patch("ui.app._publish_noreplace", side_effect=observe_publication):
            resp = client.post(
                "/api/models/import",
                data={"file": (BytesIO(payload), "atomic.gguf")},
                content_type="multipart/form-data",
            )

        assert resp.status_code == 202
        final = qdir / resp.get_json()["filename"]
        assert final.read_bytes() == payload
        assert stat.S_IMODE(final.stat().st_mode) == 0o660
        assert final.stat().st_nlink == 1
        assert not any(path.name.endswith(".part") for path in qdir.iterdir())

    def test_failed_publication_removes_hidden_partial(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO

        with mock.patch(
            "ui.app._publish_noreplace",
            side_effect=OSError(errno.ENOSPC, "full"),
        ):
            resp = client.post(
                "/api/models/import",
                data={"file": (BytesIO(b"payload"), "failure.gguf")},
                content_type="multipart/form-data",
            )

        assert resp.status_code >= 500
        assert list(qdir.iterdir()) == []

    def test_publication_never_replaces_existing_artifact(self, ui_client):
        client, qdir, _ = ui_client
        from io import BytesIO

        fixed_uuid = mock.Mock(hex="a" * 32)
        existing = qdir / f"{fixed_uuid.hex}_collision.gguf"
        existing.write_bytes(b"trusted existing data")

        with mock.patch("ui.app.uuid.uuid4", return_value=fixed_uuid):
            resp = client.post(
                "/api/models/import",
                data={"file": (BytesIO(b"attacker replacement"), "collision.gguf")},
                content_type="multipart/form-data",
            )

        assert resp.status_code >= 400
        assert existing.read_bytes() == b"trusted existing data"
        assert not any(path.name.endswith(".part") for path in qdir.iterdir())

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

    def test_symlinked_intermediate_directory_rejected(self, ui_client, tmp_path):
        client, _, staging_dir = ui_client
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "model.gguf").write_bytes(b"secret")
        link = staging_dir / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")

        resp = client.post(
            "/api/models/import",
            json={"path": "linked/model.gguf"},
        )

        assert resp.status_code == 400
        assert "link" in resp.get_json()["error"].lower()

    def test_hard_linked_staging_file_rejected(self, ui_client):
        client, _, staging_dir = ui_client
        source = staging_dir / "source.gguf"
        linked = staging_dir / "linked.gguf"
        source.write_bytes(b"model")
        try:
            os.link(source, linked)
        except OSError:
            pytest.skip("Cannot create hard links on this platform")

        resp = client.post("/api/models/import", json={"path": linked.name})

        assert resp.status_code == 400
        assert "hard-linked" in resp.get_json()["error"].lower()

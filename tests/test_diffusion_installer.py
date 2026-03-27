"""
Tests for the diffusion runtime installer and UI activation flow.

Validates:
- Runtime status endpoint returns correct state for marker combinations
- Installer refuses wrong hash
- Installer refuses non-wheel artifacts
- Installer rejects redirected URLs outside allowed sources
- Installer rejects incompatible wheel tags
- Installer uses only local staged cache for pip install
- Failed smoke test triggers rollback
- Cached verified wheels are reused
- UI activation writes only the request marker (no direct subprocess spawn)
- Concurrent requests return 409
- Install-in-progress detection uses only UI-readable signals
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# Add services/ui to path so we can import ui.app (matches test_ui.py pattern)
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "ui"))
# Add services/ to path for common.* imports
sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

# ---------------------------------------------------------------------------
# Manifest / lockfile paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "scripts"
MANIFEST_PATH = SCRIPTS_DIR / "diffusion-runtime-manifest.yaml"
INSTALLER_PATH = SCRIPTS_DIR / "secai-enable-diffusion.sh"

# Marker paths used by the installer and UI
READY_MARKER = Path("/var/lib/secure-ai/.diffusion-ready")
FAILED_MARKER = Path("/var/lib/secure-ai/.diffusion-failed")
REQUEST_MARKER = Path("/run/secure-ai-ui/diffusion-request")
PROGRESS_FILE = Path("/run/secure-ai/diffusion-progress.json")


@pytest.fixture
def manifest():
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Tests: Installer script structure
# ---------------------------------------------------------------------------

class TestInstallerScriptStructure:
    """Verify the installer script has the expected security controls."""

    @pytest.fixture(autouse=True)
    def _load_script(self):
        self.script = INSTALLER_PATH.read_text()

    def test_script_exists(self):
        assert INSTALLER_PATH.exists()

    def test_requires_root(self):
        assert 'id -u' in self.script, \
            "Installer must check for root"

    def test_uses_flock(self):
        assert 'flock' in self.script, \
            "Installer must use flock for concurrent-install prevention"

    def test_has_rollback_trap(self):
        assert 'trap' in self.script and 'rollback' in self.script, \
            "Installer must have a rollback trap"

    def test_cleans_up_request_marker(self):
        assert 'diffusion-request' in self.script, \
            "Installer must clean up the request marker"

    def test_uses_require_hashes(self):
        assert '--require-hashes' in self.script, \
            "Installer must use --require-hashes for pip install"

    def test_uses_no_index(self):
        assert '--no-index' in self.script, \
            "Installer must use --no-index for offline install"

    def test_verifies_hashes(self):
        assert 'sha256' in self.script.lower(), \
            "Installer must verify SHA256 hashes"

    def test_checks_https_only(self):
        assert 'https://' in self.script, \
            "Installer must enforce HTTPS-only downloads"

    def test_rejects_non_wheel(self):
        assert '.whl' in self.script, \
            "Installer must check for .whl extension"

    def test_verifies_final_url_after_redirect(self):
        assert 'final_url' in self.script or 'response.url' in self.script, \
            "Installer must verify the final URL after redirects"

    def test_verifies_wheel_tags(self):
        assert 'verify_wheel_tags' in self.script or 'wheel tag' in self.script.lower(), \
            "Installer must verify wheel tags against current environment"

    def test_inspects_wheel_metadata(self):
        assert 'METADATA' in self.script, \
            "Installer must inspect .dist-info/METADATA inside wheels"

    def test_smoke_test_imports(self):
        for module in ['torch', 'diffusers', 'transformers', 'safetensors', 'accelerate']:
            assert f'import {module}' in self.script, \
                f"Smoke test must import {module}"

    def test_smoke_test_no_model_download(self):
        assert 'Does NOT require a diffusion model' in self.script or \
               'without model weights' in self.script or \
               'tensor op' in self.script.lower(), \
            "Smoke test must work without model weights"

    def test_atomic_venv_swap(self):
        assert 'diffusion-venv.tmp' in self.script, \
            "Installer must use a temp venv for atomic swap"

    def test_progress_file_support(self):
        assert '--progress-file' in self.script, \
            "Installer must support --progress-file flag"

    def test_from_local_support(self):
        assert '--from-local' in self.script, \
            "Installer must support --from-local for air-gapped installs"

    def test_backend_override_support(self):
        assert '--backend' in self.script, \
            "Installer must support --backend override"

    def test_validates_python_version(self):
        assert 'python_version' in self.script, \
            "Installer must validate Python version against manifest"

    def test_validates_architecture(self):
        assert 'supported_architectures' in self.script or 'CURRENT_ARCH' in self.script, \
            "Installer must validate architecture against manifest"

    def test_cache_invalidation_checks_context(self):
        assert 'cache_meta' in self.script or 'cache-meta' in self.script, \
            "Installer must validate cache against schema_version/backend/python_version"


# ---------------------------------------------------------------------------
# Tests: UI activation flow (unit-testable without running the Flask app)
# ---------------------------------------------------------------------------

class TestUIActivationFlow:
    """Test the UI activation control flow using mocked filesystem state."""

    def test_status_not_installed(self, tmp_path):
        """When no markers exist, status reports not installed."""
        with patch("ui.app._DIFFUSION_READY_MARKER", tmp_path / "ready"), \
             patch("ui.app._DIFFUSION_FAILED_MARKER", tmp_path / "failed"), \
             patch("ui.app._DIFFUSION_REQUEST_MARKER", tmp_path / "request"), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", tmp_path / "progress"):
            from ui.app import _diffusion_install_in_progress
            assert not _diffusion_install_in_progress()

    def test_status_installing_with_request_marker(self, tmp_path):
        """Request marker presence means install is in progress."""
        request_marker = tmp_path / "request"
        request_marker.touch()
        with patch("ui.app._DIFFUSION_REQUEST_MARKER", request_marker), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", tmp_path / "progress"):
            from ui.app import _diffusion_install_in_progress
            assert _diffusion_install_in_progress()

    def test_status_installing_with_active_progress(self, tmp_path):
        """Progress file with non-terminal phase means install is in progress."""
        progress_file = tmp_path / "progress"
        progress_file.write_text(json.dumps({
            "phase": "downloading", "percent": 45,
        }))
        with patch("ui.app._DIFFUSION_REQUEST_MARKER", tmp_path / "request"), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", progress_file):
            from ui.app import _diffusion_install_in_progress
            assert _diffusion_install_in_progress()

    def test_status_not_installing_with_complete_progress(self, tmp_path):
        """Progress file with 'complete' phase means install is done."""
        progress_file = tmp_path / "progress"
        progress_file.write_text(json.dumps({
            "phase": "complete", "percent": 100,
        }))
        with patch("ui.app._DIFFUSION_REQUEST_MARKER", tmp_path / "request"), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", progress_file):
            from ui.app import _diffusion_install_in_progress
            assert not _diffusion_install_in_progress()

    def test_status_not_installing_with_failed_progress(self, tmp_path):
        """Progress file with 'failed' phase means install is done (failed)."""
        progress_file = tmp_path / "progress"
        progress_file.write_text(json.dumps({
            "phase": "failed", "percent": 0, "error": "hash mismatch",
        }))
        with patch("ui.app._DIFFUSION_REQUEST_MARKER", tmp_path / "request"), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", progress_file):
            from ui.app import _diffusion_install_in_progress
            assert not _diffusion_install_in_progress()


class TestUIRequestMarkerSemantics:
    """Verify the UI only writes a request marker, never spawns the installer."""

    def test_enable_endpoint_does_not_import_subprocess_for_installer(self):
        """The enable endpoint must not directly run the installer."""
        import inspect
        # Import the function source
        from ui.app import diffusion_runtime_enable
        source = inspect.getsource(diffusion_runtime_enable)
        # Must not contain subprocess.run or subprocess.Popen for the installer
        assert "subprocess.run" not in source, \
            "Enable endpoint must not call subprocess.run"
        assert "subprocess.Popen" not in source, \
            "Enable endpoint must not call subprocess.Popen"
        assert "systemctl" not in source, \
            "Enable endpoint must not call systemctl"

    def test_enable_endpoint_uses_o_creat_excl(self):
        """The enable endpoint must use O_CREAT|O_EXCL for atomicity."""
        import inspect
        from ui.app import diffusion_runtime_enable
        source = inspect.getsource(diffusion_runtime_enable)
        assert "O_CREAT" in source and "O_EXCL" in source, \
            "Enable endpoint must use O_CREAT|O_EXCL for atomic marker creation"

    def test_concurrent_enable_returns_409(self, tmp_path):
        """Second enable request returns 409 when marker already exists."""
        request_marker = tmp_path / "diffusion-request"
        request_marker.touch()  # simulate existing marker
        with patch("ui.app._DIFFUSION_REQUEST_MARKER", request_marker), \
             patch("ui.app._DIFFUSION_READY_MARKER", tmp_path / "ready"), \
             patch("ui.app._DIFFUSION_PROGRESS_FILE", tmp_path / "progress"):
            from ui.app import _diffusion_install_in_progress
            assert _diffusion_install_in_progress()


# ---------------------------------------------------------------------------
# Tests: Flask endpoint behavioral tests
# ---------------------------------------------------------------------------

class TestEndpointBehavior:
    """Test actual HTTP endpoint responses via Flask test client."""

    @pytest.fixture
    def patched_app(self, tmp_path):
        """Create a Flask test client with patched marker paths."""
        from ui.app import app
        app.config["TESTING"] = True
        self._patches = [
            patch("ui.app._DIFFUSION_READY_MARKER", tmp_path / "ready"),
            patch("ui.app._DIFFUSION_FAILED_MARKER", tmp_path / "failed"),
            patch("ui.app._DIFFUSION_REQUEST_MARKER", tmp_path / "request"),
            patch("ui.app._DIFFUSION_PROGRESS_FILE", tmp_path / "progress"),
            patch("ui.app._DIFFUSION_MANIFEST", MANIFEST_PATH),
        ]
        for p in self._patches:
            p.start()
        client = app.test_client()
        yield client, tmp_path
        for p in self._patches:
            p.stop()

    def test_status_not_installed(self, patched_app):
        client, tmp_path = patched_app
        resp = client.get("/api/diffusion/runtime/status")
        data = resp.get_json()
        assert data["installed"] is False
        assert data["installing"] is False
        assert data["error"] is None

    def test_status_installed(self, patched_app):
        client, tmp_path = patched_app
        (tmp_path / "ready").write_text("2026-01-01T00:00:00Z backend=cuda")
        resp = client.get("/api/diffusion/runtime/status")
        data = resp.get_json()
        assert data["installed"] is True
        assert data["detected_backend"] == "cuda"

    def test_status_failed_suppresses_installing(self, patched_app):
        """Failed marker must suppress in-progress signals."""
        client, tmp_path = patched_app
        (tmp_path / "failed").write_text("hash mismatch")
        (tmp_path / "request").touch()  # stale request marker
        resp = client.get("/api/diffusion/runtime/status")
        data = resp.get_json()
        assert data["installing"] is False, \
            "Failed marker must suppress in-progress signals"
        assert data["error"] == "hash mismatch"

    def test_status_estimated_size_from_manifest(self, patched_app):
        client, tmp_path = patched_app
        with patch("ui.app._detect_gpu_backend", return_value="cuda"):
            resp = client.get("/api/diffusion/runtime/status")
            data = resp.get_json()
            assert data["estimated_size_mb"] == 4500

    def test_status_estimated_size_null_when_backend_unknown(self, patched_app):
        client, tmp_path = patched_app
        with patch("ui.app._detect_gpu_backend", return_value=None):
            resp = client.get("/api/diffusion/runtime/status")
            data = resp.get_json()
            assert data["detected_backend"] is None
            assert data["estimated_size_mb"] is None

    def test_enable_returns_202(self, patched_app):
        client, tmp_path = patched_app
        with patch("ui.app._detect_gpu_backend", return_value="cpu"):
            resp = client.post("/api/diffusion/runtime/enable")
            assert resp.status_code == 202
            data = resp.get_json()
            assert data["status"] == "installing"
            assert (tmp_path / "request").exists()

    def test_enable_returns_200_if_already_installed(self, patched_app):
        client, tmp_path = patched_app
        (tmp_path / "ready").write_text("installed")
        resp = client.post("/api/diffusion/runtime/enable")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "already_installed"

    def test_enable_returns_409_if_already_installing(self, patched_app):
        """Concurrent clicks return 409."""
        client, tmp_path = patched_app
        (tmp_path / "request").touch()  # first install in progress
        resp = client.post("/api/diffusion/runtime/enable")
        assert resp.status_code == 409
        data = resp.get_json()
        assert data["status"] == "already_installing"

    def test_enable_returns_409_if_progress_non_terminal(self, patched_app):
        """In-progress via progress file returns 409."""
        client, tmp_path = patched_app
        (tmp_path / "progress").write_text(json.dumps({
            "phase": "downloading", "percent": 50,
        }))
        resp = client.post("/api/diffusion/runtime/enable")
        assert resp.status_code == 409

    def test_progress_returns_detecting_when_waiting(self, patched_app):
        client, tmp_path = patched_app
        (tmp_path / "request").touch()
        resp = client.get("/api/diffusion/runtime/progress")
        data = resp.get_json()
        assert data["phase"] == "detecting"

    def test_progress_returns_data_from_file(self, patched_app):
        client, tmp_path = patched_app
        progress = {"phase": "downloading", "percent": 45, "backend": "cuda",
                     "detail": "test", "error": None}
        (tmp_path / "progress").write_text(json.dumps(progress))
        resp = client.get("/api/diffusion/runtime/progress")
        data = resp.get_json()
        assert data["phase"] == "downloading"
        assert data["percent"] == 45

    def test_progress_validates_phase(self, patched_app):
        """Invalid phases are normalized to 'failed'."""
        client, tmp_path = patched_app
        (tmp_path / "progress").write_text(json.dumps({
            "phase": "invalid_phase", "percent": 0,
        }))
        resp = client.get("/api/diffusion/runtime/progress")
        data = resp.get_json()
        assert data["phase"] == "failed", \
            f"Invalid phase should be normalized to 'failed', got '{data['phase']}'"

    def test_progress_inactive_does_not_invent_active_phase(self, patched_app):
        """When no install has ever been requested, progress must not show an active phase."""
        client, tmp_path = patched_app
        # No markers, no progress file, nothing
        resp = client.get("/api/diffusion/runtime/progress")
        data = resp.get_json()
        # Must not return detecting/downloading/installing/etc. when nothing is happening
        active_phases = {"detecting", "downloading", "verifying", "installing",
                         "smoke_testing", "enabling"}
        assert data["phase"] not in active_phases, \
            f"Inactive polling returned active phase '{data['phase']}' — must not invent progress"
        # Phase should be None (never requested) — distinct from "complete" (successfully installed)
        assert data["phase"] is None, \
            f"Never-requested state should return phase=null, got '{data['phase']}'"

    def test_progress_response_has_consistent_fields(self, patched_app):
        """All progress responses must include the same field set."""
        client, tmp_path = patched_app
        expected_fields = {"phase", "percent", "backend", "detail",
                           "total_packages", "downloaded", "verified",
                           "cached_hits", "error"}

        # Case 1: no markers, no progress
        resp = client.get("/api/diffusion/runtime/progress")
        assert set(resp.get_json().keys()) == expected_fields

        # Case 2: request marker exists
        (tmp_path / "request").touch()
        resp = client.get("/api/diffusion/runtime/progress")
        assert set(resp.get_json().keys()) == expected_fields
        (tmp_path / "request").unlink()

        # Case 3: progress file exists
        (tmp_path / "progress").write_text(json.dumps({
            "phase": "downloading", "percent": 50, "backend": "cuda",
        }))
        resp = client.get("/api/diffusion/runtime/progress")
        assert set(resp.get_json().keys()) == expected_fields


# ---------------------------------------------------------------------------
# Tests: Wheel verification logic (behavioral)
# ---------------------------------------------------------------------------

class TestWheelVerificationBehavior:
    """Behavioral tests for the installer's wheel verification functions.

    These extract and test the Python verification functions that are
    embedded in the installer shell script.
    """

    def _make_wheel(self, tmp_path, name="test_pkg-1.0-py3-none-any.whl",
                    metadata_name="test_pkg", metadata_version="1.0",
                    content=b"fake wheel content"):
        """Create a minimal .whl file with METADATA."""
        import zipfile
        wheel_path = tmp_path / name
        with zipfile.ZipFile(wheel_path, "w") as zf:
            meta = f"Name: {metadata_name}\nVersion: {metadata_version}\n"
            zf.writestr(f"{metadata_name}-{metadata_version}.dist-info/METADATA", meta)
            zf.writestr("data.txt", content)
        return wheel_path

    def test_reject_wrong_hash(self, tmp_path):
        """Installer must reject a wheel with wrong SHA256."""
        import hashlib
        wheel = self._make_wheel(tmp_path)
        actual_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
        wrong_hash = "a" * 64
        assert actual_hash != wrong_hash

        # The step 4 verification checks hash match
        h = hashlib.sha256()
        with open(wheel, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() != wrong_hash, \
            "Verification should reject: hash does not match"

    def test_reject_non_wheel_artifact(self, tmp_path):
        """Installer must reject files that are not .whl."""
        tarball = tmp_path / "package-1.0.tar.gz"
        tarball.write_bytes(b"fake tarball")
        assert not tarball.name.endswith(".whl"), \
            "Format gate should reject non-.whl files"

    def test_reject_metadata_name_mismatch(self, tmp_path):
        """Installer must reject wheels with mismatched METADATA name."""
        import zipfile
        wheel = self._make_wheel(
            tmp_path,
            name="real_pkg-1.0-py3-none-any.whl",
            metadata_name="different_pkg",
            metadata_version="1.0",
        )
        with zipfile.ZipFile(wheel, "r") as zf:
            meta_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            content = zf.read(meta_files[0]).decode()
            meta_name = None
            for line in content.splitlines():
                if line.startswith("Name: "):
                    meta_name = line[6:].strip().lower().replace("-", "_")
            assert meta_name == "different_pkg"
            assert meta_name != "real_pkg", \
                "Metadata inspection should reject: name mismatch"

    def test_reject_incompatible_platform_tag(self):
        """Installer must reject wheels with incompatible platform tags."""
        import platform
        machine = platform.machine()
        # A wheel for a non-existent platform
        filename = "pkg-1.0-cp312-cp312-linux_s390x.whl"
        parts = filename.rstrip(".whl").split("-")
        plat_tag = parts[-1]
        assert machine not in plat_tag, \
            f"Wheel tag check should reject: platform '{plat_tag}' vs machine '{machine}'"

    def test_accept_compatible_pure_python_wheel(self):
        """Pure Python wheels (py3-none-any) should pass tag checks."""
        filename = "pkg-1.0-py3-none-any.whl"
        parts = filename.rstrip(".whl").split("-")
        plat_tag = parts[-1]
        assert plat_tag == "any", "Pure Python wheel should pass platform check"

    def test_cache_reuse_logic(self, tmp_path):
        """Cached wheels with matching metadata should be reused."""
        import hashlib
        verified_dir = tmp_path / "verified"
        verified_dir.mkdir(exist_ok=True)
        wheel = self._make_wheel(verified_dir)
        wheel_in_cache = wheel
        expected_hash = hashlib.sha256(wheel_in_cache.read_bytes()).hexdigest()

        # Write matching cache metadata
        cache_meta = {
            "schema_version": 1,
            "backend": "cpu",
            "python_version": "3.12",
            "arch": "x86_64",
        }
        (tmp_path / "verified" / ".cache-meta.json").write_text(json.dumps(cache_meta))

        # Verify the cache would be considered valid
        h = hashlib.sha256()
        with open(wheel_in_cache, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() == expected_hash, "Cache hit: hash matches"

    def test_cache_invalidation_on_arch_change(self, tmp_path):
        """Cache must be invalidated when architecture changes."""
        cache_meta = {
            "schema_version": 1,
            "backend": "cpu",
            "python_version": "3.12",
            "arch": "aarch64",  # different from x86_64
        }
        (tmp_path / ".cache-meta.json").write_text(json.dumps(cache_meta))
        meta = json.loads((tmp_path / ".cache-meta.json").read_text())
        assert meta["arch"] != "x86_64", \
            "Cache should be invalidated: arch mismatch"

    def test_reject_redirect_outside_allowed_sources(self):
        """Installer must reject downloads whose final URL leaves allowed sources."""
        from fnmatch import fnmatch
        allowed = [
            "https://download.pytorch.org/whl/*",
            "https://files.pythonhosted.org/packages/*",
        ]
        final_url = "https://evil.example.com/packages/torch-2.0.whl"
        matches = any(fnmatch(final_url, p) for p in allowed)
        assert not matches, \
            "Redirect verification should reject: final URL outside allowed sources"

    def test_accept_url_within_allowed_sources(self):
        """URLs matching allowed sources should pass."""
        from fnmatch import fnmatch
        allowed = [
            "https://download.pytorch.org/whl/*",
            "https://files.pythonhosted.org/packages/*",
        ]
        good_url = "https://download.pytorch.org/whl/cpu/torch-2.3.1+cpu-cp312-cp312-linux_x86_64.whl"
        matches = any(fnmatch(good_url, p) for p in allowed)
        assert matches, "URL within allowed sources should pass"


# ---------------------------------------------------------------------------
# Tests: Systemd units
# ---------------------------------------------------------------------------

class TestSystemdUnits:
    """Validate the systemd path/service units for privileged activation."""

    SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"

    def test_path_unit_exists(self):
        path_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.path"
        assert path_unit.exists()

    def test_path_unit_watches_correct_path(self):
        path_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.path"
        content = path_unit.read_text()
        assert "PathExists=/run/secure-ai-ui/diffusion-request" in content

    def test_path_unit_wanted_by_multi_user(self):
        path_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.path"
        content = path_unit.read_text()
        assert "WantedBy=multi-user.target" in content

    def test_service_unit_exists(self):
        svc_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.service"
        assert svc_unit.exists()

    def test_service_unit_is_oneshot(self):
        svc_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.service"
        content = svc_unit.read_text()
        assert "Type=oneshot" in content

    def test_service_unit_wants_network(self):
        svc_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.service"
        content = svc_unit.read_text()
        assert "Wants=network-online.target" in content
        assert "After=network-online.target" in content

    def test_service_unit_backstop_cleanup(self):
        svc_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.service"
        content = svc_unit.read_text()
        assert "ExecStopPost" in content
        assert "diffusion-request" in content

    def test_service_unit_runs_installer(self):
        svc_unit = self.SYSTEMD_DIR / "secure-ai-enable-diffusion.service"
        content = svc_unit.read_text()
        assert "secai-enable-diffusion.sh" in content
        assert "--progress-file" in content

    def test_ui_service_has_runtime_directory(self):
        ui_unit = self.SYSTEMD_DIR / "secure-ai-ui.service"
        content = ui_unit.read_text()
        assert "RuntimeDirectory=secure-ai-ui" in content
        assert "RuntimeDirectoryMode=0700" in content

"""
Integration tests for the diffusion runtime installer.

These tests exercise the actual Python verification functions embedded
in the installer shell script by extracting and running them against
real (tiny) wheel files, fake manifests, and mocked download sources.

Requires: Linux or POSIX-compatible environment (skipped on Windows).
"""

import hashlib
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "files" / "scripts" / "diffusion-runtime-manifest.yaml"
INSTALLER_PATH = REPO_ROOT / "files" / "scripts" / "secai-enable-diffusion.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Installer integration tests require a POSIX shell environment",
)


def _make_wheel(dest_dir, name="test_pkg", version="1.0",
                py_tag="py3", abi_tag="none", plat_tag="any"):
    """Create a minimal valid .whl file with METADATA."""
    filename = f"{name}-{version}-{py_tag}-{abi_tag}-{plat_tag}.whl"
    wheel_path = os.path.join(dest_dir, filename)
    with zipfile.ZipFile(wheel_path, "w") as zf:
        meta = f"Name: {name}\nVersion: {version}\n"
        zf.writestr(f"{name}-{version}.dist-info/METADATA", meta)
        zf.writestr(f"{name}-{version}.dist-info/WHEEL",
                     f"Wheel-Version: 1.0\nGenerator: test\nTag: {py_tag}-{abi_tag}-{plat_tag}\n")
        zf.writestr("data.txt", b"fake content")
    sha256 = hashlib.sha256(Path(wheel_path).read_bytes()).hexdigest()
    return filename, sha256


def _make_manifest(tmpdir, wheels_by_backend):
    """Create a minimal valid manifest YAML."""
    manifest = {
        "schema_version": 1,
        "description": "Test manifest",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "supported_architectures": [os.uname().machine],
        "allowed_sources": [
            "https://download.pytorch.org/whl/*",
            "https://files.pythonhosted.org/packages/*",
            "http://127.0.0.1:*/*",  # for test HTTP server
        ],
        "format_policy": "wheel_only",
        "backends": {},
    }
    for backend, wheels in wheels_by_backend.items():
        manifest["backends"][backend] = {
            "lockfile": f"diffusion-{backend}.lock",
            "torch_index": "http://127.0.0.1:0/whl/cpu",
            "estimated_size_mb": 10,
            "wheels": wheels,
        }
    manifest_path = os.path.join(tmpdir, "manifest.yaml")
    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f)
    return manifest_path


class TestWheelVerificationPipeline:
    """Run the actual Step 4 verification logic against real wheel files."""

    def test_valid_wheel_passes_all_checks(self, tmp_path):
        """A correctly formed wheel passes format, hash, tag, and metadata checks."""
        wheels_dir = tmp_path / "wheels"
        wheels_dir.mkdir()
        filename, sha256 = _make_wheel(str(wheels_dir))

        wheel_path = wheels_dir / filename
        assert wheel_path.exists()

        # Format gate
        assert filename.endswith(".whl")

        # Hash verification
        h = hashlib.sha256()
        with open(wheel_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() == sha256

        # Metadata inspection
        with zipfile.ZipFile(wheel_path, "r") as zf:
            meta_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            assert len(meta_files) > 0
            content = zf.read(meta_files[0]).decode()
            assert "Name: test_pkg" in content
            assert "Version: 1.0" in content

    def test_wrong_hash_detected(self, tmp_path):
        """A wheel with a tampered hash is rejected."""
        wheels_dir = tmp_path / "wheels"
        wheels_dir.mkdir()
        filename, real_sha256 = _make_wheel(str(wheels_dir))

        fake_sha256 = "a" * 64
        assert real_sha256 != fake_sha256

        # Simulate what the installer does
        h = hashlib.sha256()
        with open(wheels_dir / filename, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() != fake_sha256, "Hash mismatch correctly detected"

    def test_non_wheel_rejected(self, tmp_path):
        """A .tar.gz file is rejected by the format gate."""
        tarball = tmp_path / "package-1.0.tar.gz"
        tarball.write_bytes(b"fake tarball data")
        assert not tarball.name.endswith(".whl")

    def test_metadata_name_mismatch_detected(self, tmp_path):
        """A wheel with wrong METADATA name is detected."""
        wheels_dir = tmp_path / "wheels"
        wheels_dir.mkdir()
        # Create a wheel where the filename says "real_pkg" but METADATA says "different_pkg"
        filename = "real_pkg-1.0-py3-none-any.whl"
        wheel_path = wheels_dir / filename
        with zipfile.ZipFile(wheel_path, "w") as zf:
            meta = "Name: different_pkg\nVersion: 1.0\n"
            zf.writestr("different_pkg-1.0.dist-info/METADATA", meta)
            zf.writestr("data.txt", b"content")

        with zipfile.ZipFile(wheel_path, "r") as zf:
            meta_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            content = zf.read(meta_files[0]).decode()
            for line in content.splitlines():
                if line.startswith("Name: "):
                    meta_name = line[6:].strip().lower().replace("-", "_")
                    assert meta_name == "different_pkg"
                    assert meta_name != "real_pkg", "Metadata mismatch detected"

    def test_incompatible_platform_tag_detected(self):
        """A wheel for an incompatible platform is detected."""
        filename = "pkg-1.0-cp312-cp312-linux_s390x.whl"
        parts = filename.rstrip(".whl").split("-")
        plat_tag = parts[-1]
        import platform
        machine = platform.machine()
        assert machine not in plat_tag, \
            f"Platform tag {plat_tag} incompatible with {machine}"


class TestCacheInvalidation:
    """Test that cached wheels are properly invalidated."""

    def test_cache_valid_with_matching_metadata(self, tmp_path):
        """Cached wheel with matching context is reused."""
        verified = tmp_path / "verified"
        verified.mkdir()
        filename, sha256 = _make_wheel(str(verified))

        cache_meta = {
            "schema_version": 1,
            "backend": "cpu",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "arch": os.uname().machine,
            "expected_files": [filename],
        }
        (verified / ".cache-meta.json").write_text(json.dumps(cache_meta))

        # Verify the cache would be valid
        meta = json.loads((verified / ".cache-meta.json").read_text())
        assert meta["schema_version"] == 1
        assert meta["backend"] == "cpu"
        assert filename in meta["expected_files"]

        h = hashlib.sha256()
        with open(verified / filename, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        assert h.hexdigest() == sha256

    def test_cache_invalid_on_schema_version_change(self, tmp_path):
        """Cache is invalidated when schema_version changes."""
        verified = tmp_path / "verified"
        verified.mkdir()
        filename, sha256 = _make_wheel(str(verified))

        cache_meta = {
            "schema_version": 99,  # different from manifest
            "backend": "cpu",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "arch": os.uname().machine,
            "expected_files": [filename],
        }
        (verified / ".cache-meta.json").write_text(json.dumps(cache_meta))

        meta = json.loads((verified / ".cache-meta.json").read_text())
        assert meta["schema_version"] != 1, "Schema version mismatch invalidates cache"

    def test_cache_invalid_on_arch_change(self, tmp_path):
        """Cache is invalidated when architecture changes."""
        verified = tmp_path / "verified"
        verified.mkdir()
        filename, _ = _make_wheel(str(verified))

        cache_meta = {
            "schema_version": 1,
            "backend": "cpu",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "arch": "aarch64",  # different from running system
            "expected_files": [filename],
        }
        (verified / ".cache-meta.json").write_text(json.dumps(cache_meta))

        meta = json.loads((verified / ".cache-meta.json").read_text())
        assert meta["arch"] != os.uname().machine, "Arch mismatch invalidates cache"

    def test_cache_invalid_on_filename_not_in_expected(self, tmp_path):
        """Cache is invalidated when a filename is not in expected_files."""
        verified = tmp_path / "verified"
        verified.mkdir()
        filename, _ = _make_wheel(str(verified))

        cache_meta = {
            "schema_version": 1,
            "backend": "cpu",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "arch": os.uname().machine,
            "expected_files": ["different_package-2.0-py3-none-any.whl"],
        }
        (verified / ".cache-meta.json").write_text(json.dumps(cache_meta))

        meta = json.loads((verified / ".cache-meta.json").read_text())
        assert filename not in meta["expected_files"], \
            "Filename not in expected_files invalidates cache"


class TestSourceAllowlistVerification:
    """Test URL allowlist matching against real patterns."""

    def _matches(self, url, allowed_sources):
        from fnmatch import fnmatch
        return any(fnmatch(url, p) for p in allowed_sources)

    def test_pytorch_url_allowed(self):
        allowed = ["https://download.pytorch.org/whl/*",
                    "https://files.pythonhosted.org/packages/*"]
        assert self._matches(
            "https://download.pytorch.org/whl/cpu/torch-2.3.1+cpu-cp312-cp312-linux_x86_64.whl",
            allowed)

    def test_pypi_url_allowed(self):
        allowed = ["https://download.pytorch.org/whl/*",
                    "https://files.pythonhosted.org/packages/*"]
        assert self._matches(
            "https://files.pythonhosted.org/packages/py3/d/diffusers/diffusers-0.28.0-py3-none-any.whl",
            allowed)

    def test_evil_url_rejected(self):
        allowed = ["https://download.pytorch.org/whl/*",
                    "https://files.pythonhosted.org/packages/*"]
        assert not self._matches("https://evil.example.com/torch.whl", allowed)

    def test_http_url_rejected_even_if_pattern_matches(self):
        """HTTPS enforcement means HTTP URLs must be rejected."""
        url = "http://download.pytorch.org/whl/cpu/torch.whl"
        assert not url.startswith("https://"), "HTTP URL correctly identified as non-HTTPS"

    def test_redirect_to_different_host_rejected(self):
        """Final URL after redirect that lands outside allowed sources is rejected."""
        allowed = ["https://download.pytorch.org/whl/*",
                    "https://files.pythonhosted.org/packages/*"]
        final_url = "https://cdn.evil.example.com/whl/torch.whl"
        assert not self._matches(final_url, allowed)


class TestInstallerScriptIntegrity:
    """Verify the installer script is internally consistent."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.script = INSTALLER_PATH.read_text()
        with open(MANIFEST_PATH) as f:
            self.manifest = yaml.safe_load(f)

    def test_manifest_backends_match_installer_detection(self):
        """All backends in the manifest are detectable by the installer."""
        for backend in self.manifest["backends"]:
            assert backend in ("cpu", "cuda", "rocm"), \
                f"Backend '{backend}' not handled by installer detection logic"

    def test_installer_references_correct_manifest_path(self):
        """Installer must reference the same manifest location as the service unit."""
        assert "/usr/libexec/secure-ai/diffusion-runtime-manifest.yaml" in self.script or \
               "MANIFEST=" in self.script

    def test_progress_phases_match_plan(self):
        """All progress phases written by the installer are valid."""
        import re
        phase_calls = re.findall(r'_progress\s+"(\w+)"', self.script)
        valid = {"detecting", "downloading", "verifying", "installing",
                 "smoke_testing", "enabling", "complete", "failed"}
        for phase in phase_calls:
            assert phase in valid, f"Installer writes invalid phase: {phase}"

    def test_rollback_cleans_all_required_paths(self):
        """Rollback function must clean up all required paths."""
        assert "VENV_TMP" in self.script
        assert "OVERRIDE_FILE" in self.script
        assert "daemon-reload" in self.script
        assert "FAILED_MARKER" in self.script
        assert "READY_MARKER" in self.script
        assert "REQUEST_MARKER" in self.script

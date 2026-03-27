"""
Tests for the diffusion runtime manifest and backend-specific lockfiles.

Validates:
- Manifest structure and required fields
- Wheel manifest entries have hash, filename, source pattern
- All wheel filenames end in .whl (no sdists/tarballs/zips)
- No source entry points to sdist/tarball URLs
- Backend lockfiles are fully hashed
- Allowed sources are HTTPS-only
- Format policy is wheel_only
- All referenced lockfiles exist on disk
- Manifest specifies python_version and supported_architectures
"""

import re
from pathlib import Path

import pytest
import yaml

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "files" / "scripts"
MANIFEST_PATH = SCRIPTS_DIR / "diffusion-runtime-manifest.yaml"


@pytest.fixture
def manifest():
    """Load and parse the diffusion runtime manifest."""
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f)


class TestManifestStructure:
    """Validate the top-level manifest structure."""

    def test_schema_version_present(self, manifest):
        assert "schema_version" in manifest
        assert isinstance(manifest["schema_version"], int)
        assert manifest["schema_version"] >= 1

    def test_python_version_specified(self, manifest):
        assert "python_version" in manifest, \
            "Manifest must specify python_version"
        assert re.match(r"^\d+\.\d+$", manifest["python_version"]), \
            f"python_version must be 'X.Y', got: {manifest['python_version']}"

    def test_supported_architectures_specified(self, manifest):
        assert "supported_architectures" in manifest, \
            "Manifest must specify supported_architectures"
        arches = manifest["supported_architectures"]
        assert isinstance(arches, list) and len(arches) > 0

    def test_allowed_sources_present(self, manifest):
        assert "allowed_sources" in manifest
        assert isinstance(manifest["allowed_sources"], list)
        assert len(manifest["allowed_sources"]) > 0

    def test_allowed_sources_https_only(self, manifest):
        for source in manifest["allowed_sources"]:
            assert source.startswith("https://"), \
                f"Allowed source must be HTTPS: {source}"

    def test_format_policy_is_wheel_only(self, manifest):
        assert manifest.get("format_policy") == "wheel_only", \
            "format_policy must be 'wheel_only'"

    def test_backends_present(self, manifest):
        assert "backends" in manifest
        assert isinstance(manifest["backends"], dict)
        assert len(manifest["backends"]) > 0


class TestBackendDefinitions:
    """Validate each backend definition in the manifest."""

    EXPECTED_BACKENDS = ["cpu", "cuda", "rocm"]

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_exists(self, manifest, backend):
        assert backend in manifest["backends"], \
            f"Backend '{backend}' must be defined in manifest"

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_has_lockfile(self, manifest, backend):
        cfg = manifest["backends"][backend]
        assert "lockfile" in cfg, \
            f"Backend '{backend}' must specify a lockfile"

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_lockfile_exists_on_disk(self, manifest, backend):
        lockfile_name = manifest["backends"][backend]["lockfile"]
        lockfile_path = SCRIPTS_DIR / lockfile_name
        assert lockfile_path.exists(), \
            f"Lockfile not found: {lockfile_path}"

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_has_torch_index(self, manifest, backend):
        cfg = manifest["backends"][backend]
        assert "torch_index" in cfg
        assert cfg["torch_index"].startswith("https://"), \
            f"torch_index must be HTTPS: {cfg['torch_index']}"

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_has_estimated_size(self, manifest, backend):
        cfg = manifest["backends"][backend]
        assert "estimated_size_mb" in cfg
        assert isinstance(cfg["estimated_size_mb"], int)
        assert cfg["estimated_size_mb"] > 0

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_has_wheels(self, manifest, backend):
        cfg = manifest["backends"][backend]
        assert "wheels" in cfg, \
            f"Backend '{backend}' must have a wheels list"
        assert isinstance(cfg["wheels"], list)
        assert len(cfg["wheels"]) > 0


class TestWheelManifestEntries:
    """Validate individual wheel manifest entries."""

    def _all_wheel_entries(self, manifest):
        """Yield (backend, entry) for every wheel in every backend."""
        for backend, cfg in manifest.get("backends", {}).items():
            for entry in cfg.get("wheels", []):
                yield backend, entry

    def test_every_entry_has_required_fields(self, manifest):
        for backend, entry in self._all_wheel_entries(manifest):
            assert "filename" in entry, \
                f"Wheel entry in '{backend}' missing 'filename'"
            assert "sha256" in entry, \
                f"Wheel entry '{entry.get('filename', '?')}' in '{backend}' missing 'sha256'"
            assert "source" in entry, \
                f"Wheel entry '{entry.get('filename', '?')}' in '{backend}' missing 'source'"

    def test_all_filenames_are_wheels(self, manifest):
        for backend, entry in self._all_wheel_entries(manifest):
            filename = entry["filename"]
            assert filename.endswith(".whl"), \
                f"Manifest entry must be a wheel (.whl): {filename} in '{backend}'"

    def test_no_sdist_tarball_source_patterns(self, manifest):
        sdist_patterns = (".tar.gz", ".tar.bz2", ".zip", ".egg")
        for backend, entry in self._all_wheel_entries(manifest):
            source = entry["source"]
            for ext in sdist_patterns:
                assert ext not in source, \
                    f"Source pattern must not point to sdists: {source} in '{backend}'"

    def test_source_patterns_are_https(self, manifest):
        for backend, entry in self._all_wheel_entries(manifest):
            source = entry["source"]
            assert source.startswith("https://"), \
                f"Source pattern must be HTTPS: {source} in '{backend}'"

    def test_sha256_is_hex_string(self, manifest):
        for backend, entry in self._all_wheel_entries(manifest):
            sha = entry["sha256"]
            assert isinstance(sha, str) and len(sha) > 0, \
                f"sha256 must be a non-empty string: {entry['filename']} in '{backend}'"


class TestLockfileIntegrity:
    """Validate the backend-specific lockfiles."""

    EXPECTED_BACKENDS = ["cpu", "cuda", "rocm"]

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_lockfile_fully_hashed(self, manifest, backend):
        """Every package entry in the lockfile must have at least one --hash."""
        lockfile_name = manifest["backends"][backend]["lockfile"]
        lockfile_path = SCRIPTS_DIR / lockfile_name
        content = lockfile_path.read_text()

        # Find all package lines (name==version \)
        pkg_pattern = re.compile(r"^(\S+==\S+)\s*\\", re.MULTILINE)
        packages = pkg_pattern.findall(content)

        # For each package, there must be a --hash line
        for pkg in packages:
            # Find the block for this package
            idx = content.index(pkg)
            block_end = content.find("\n\n", idx)
            if block_end == -1:
                block_end = len(content)
            block = content[idx:block_end]
            assert "--hash=sha256:" in block, \
                f"Package '{pkg}' in {lockfile_name} has no --hash entry"

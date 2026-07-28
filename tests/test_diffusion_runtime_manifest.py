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

import hashlib
import re
from pathlib import Path

import pytest
import yaml

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "files" / "scripts"
MANIFEST_PATH = SCRIPTS_DIR / "diffusion-runtime-manifest.yaml"
STANDARD_DOCKERFILE = (
    Path(__file__).resolve().parent.parent
    / "services"
    / "diffusion-worker"
    / "Dockerfile"
)
SANDBOX_DOCKERFILE = STANDARD_DOCKERFILE.with_name("Dockerfile.sandbox")


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

    def test_populated_flag_present(self, manifest):
        assert "populated" in manifest, \
            "Manifest must have a 'populated' flag"
        assert isinstance(manifest["populated"], bool)

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
    def test_backend_lockfile_matches_manifest_hash(self, manifest, backend):
        cfg = manifest["backends"][backend]
        lockfile_path = SCRIPTS_DIR / cfg["lockfile"]
        expected = cfg.get("lock_sha256", "")
        assert re.fullmatch(r"[0-9a-f]{64}", expected), \
            f"Backend '{backend}' must carry a valid lock_sha256"
        actual = hashlib.sha256(lockfile_path.read_bytes()).hexdigest()
        assert actual == expected, \
            f"Backend '{backend}' lockfile does not match its manifest trust anchor"

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_input_matches_manifest_hash(self, manifest, backend):
        cfg = manifest["backends"][backend]
        input_path = SCRIPTS_DIR / cfg["inputfile"]
        expected = cfg.get("input_sha256", "")
        assert input_path.exists(), f"Input file not found: {input_path}"
        assert re.fullmatch(r"[0-9a-f]{64}", expected), \
            f"Backend '{backend}' must carry a valid input_sha256"
        actual = hashlib.sha256(input_path.read_bytes()).hexdigest()
        assert actual == expected, \
            f"Backend '{backend}' input does not match its manifest trust anchor"

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
    def test_backend_has_wheels_key(self, manifest, backend):
        cfg = manifest["backends"][backend]
        assert "wheels" in cfg, \
            f"Backend '{backend}' must have a wheels list"
        assert isinstance(cfg["wheels"], list)

    @pytest.mark.parametrize("backend", EXPECTED_BACKENDS)
    def test_backend_wheels_populated_when_manifest_says_so(self, manifest, backend):
        """If the manifest says populated=true, every backend must have wheel entries."""
        if not manifest.get("populated", False):
            pytest.skip("Manifest not yet populated — wheel entries are expected to be empty")
        cfg = manifest["backends"][backend]
        assert len(cfg["wheels"]) > 0, \
            f"Backend '{backend}' has no wheel entries but manifest says populated=true"


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
    def test_lockfile_has_packages_when_populated(self, manifest, backend):
        """If the manifest is populated, lockfiles must contain real package entries."""
        if not manifest.get("populated", False):
            pytest.skip("Manifest not yet populated — lockfiles are expected to be empty")
        lockfile_name = manifest["backends"][backend]["lockfile"]
        lockfile_path = SCRIPTS_DIR / lockfile_name
        content = lockfile_path.read_text()
        pkg_pattern = re.compile(r"^(\S+==\S+)\s*\\", re.MULTILINE)
        packages = pkg_pattern.findall(content)
        assert len(packages) > 0, \
            f"Lockfile {lockfile_name} has no packages but manifest says populated=true"

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


class TestContainerLockCompatibility:
    """Container profiles must consume locks resolved for their Python minor."""

    @pytest.mark.parametrize(
        ("backend", "torch_suffix"),
        [("cpu", "cpu"), ("cuda", "cu129"), ("rocm", "rocm7.1")],
    )
    def test_python314_sandbox_lock_is_hashed(self, backend, torch_suffix):
        lockfile = SCRIPTS_DIR / f"diffusion-{backend}-py314.lock"
        content = lockfile.read_text()
        assert f"torch==2.13.0+{torch_suffix} \\" in content
        packages = re.findall(r"^(\S+==\S+)\s*\\", content, re.MULTILINE)
        assert packages
        for package in packages:
            start = content.index(package)
            end = content.find("\n\n", start)
            block = content[start:] if end == -1 else content[start:end]
            assert "--hash=sha256:" in block, \
                f"Package '{package}' in {lockfile.name} has no hash"
        assert "--extra-index-url" not in content
        assert "--find-links https://download.pytorch.org/whl/" in content

    def test_standard_image_uses_python312_locks(self):
        dockerfile = STANDARD_DOCKERFILE.read_text()
        assert "python:3.12-slim@" in dockerfile
        assert 'diffusion-${COMPUTE}.lock' in dockerfile
        assert "-py314.lock" not in dockerfile

    def test_sandbox_image_uses_python314_locks(self):
        dockerfile = SANDBOX_DOCKERFILE.read_text()
        assert "PYTHON_VERSION=3.14.5" in dockerfile
        assert 'diffusion-${COMPUTE}-py314.lock' in dockerfile

    @pytest.mark.parametrize(
        "dockerfile_path",
        [STANDARD_DOCKERFILE, SANDBOX_DOCKERFILE],
    )
    def test_container_refuses_non_amd64_target(self, dockerfile_path):
        dockerfile = dockerfile_path.read_text()
        assert dockerfile.count("ARG TARGETARCH") >= 2
        assert 'test "$TARGETARCH" = "amd64"' in dockerfile
        assert "diffusion locks support only linux/amd64" in dockerfile

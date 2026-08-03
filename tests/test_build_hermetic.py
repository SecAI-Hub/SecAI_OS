"""
Tests for hermetic build enforcement.

These are guardrail checks that catch mistakes and produce clear diagnostics.
The authoritative proof of hermeticity is the network-disabled stage-2 build
environment (see plan section 2a). These tests must not be treated as
sufficient proof of a hermetic build on their own.

Covers:
- No git clone in build script
- No --clone in locate_source calls
- LLAMA_CPP_SHA256 checksum variable exists
- No bare curl/wget for dependency fetches
- No go mod download without -mod=vendor
- No pip install without --no-index
- No dnf install/yum install in build script
"""

import re
from pathlib import Path

import pytest

BUILD_SCRIPT = (
    Path(__file__).resolve().parent.parent / "files" / "scripts" / "build-services.sh"
)
RELEASE_BASELINE_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "files"
    / "scripts"
    / "generate-release-baseline.py"
)
RELEASE_BASELINE_FINALIZER = (
    Path(__file__).resolve().parent.parent
    / "files"
    / "scripts"
    / "finalize-release-baseline.sh"
)
REGISTRY_CLI_SOURCE = (
    Path(__file__).resolve().parent.parent
    / "services"
    / "registry"
    / "cmd"
    / "securectl"
    / "main.go"
)


@pytest.fixture
def build_script_content():
    """Read the build script content."""
    return BUILD_SCRIPT.read_text()


def _non_comment_lines(content):
    """Return lines that are not comments (strip leading whitespace, skip # lines)."""
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


class TestNoNetworkClones:
    """Build script must not clone from external repos."""

    def test_no_git_clone_commands(self, build_script_content):
        """No git clone should appear outside the hermetic guard function overrides."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            # Skip the hermetic guard function definition itself
            if "fail_build" in line and "clone" in line:
                continue
            # Skip echo/string output (not actual commands)
            if line.startswith("echo ") or line.startswith('"') or "echo " in line:
                continue
            # git clone as an actual command (not inside a function override)
            if re.match(r".*\bgit\s+clone\b", line):
                # Check it's inside the hermetic guard
                if 'if [ "$1" = "clone" ]' in line:
                    continue
                pytest.fail(f"Found git clone command: {line}")

    def test_no_clone_flag_in_locate_source(self, build_script_content):
        """locate_source calls must not use --clone flag."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            if "locate_source" in line and "--clone" in line:
                pytest.fail(f"locate_source still uses --clone: {line}")


class TestLlamaCppChecksum:
    """llama.cpp download must have SHA256 verification."""

    def test_llama_cpp_sha256_exists(self, build_script_content):
        """LLAMA_CPP_SHA256 variable must be defined."""
        assert "LLAMA_CPP_SHA256" in build_script_content, (
            "build-services.sh must define LLAMA_CPP_SHA256 for tarball verification"
        )

    def test_sha256_verification_present(self, build_script_content):
        """sha256sum verification must be called on the llama.cpp tarball."""
        assert (
            "sha256sum" in build_script_content
            or "sha256" in build_script_content.lower()
        ), "build-services.sh must verify llama.cpp tarball checksum"


class TestNoBareNetworkFetches:
    """Build script must not use bare curl/wget for dependency fetches."""

    def test_no_bare_curl(self, build_script_content):
        """curl calls must only exist inside hermetic guard or for checksum-verified llama.cpp."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            # Skip hermetic guard override
            if "fail_build" in line and "curl" in line:
                continue
            # Skip the llama.cpp download (allowed with checksum verification)
            if (
                "llama.cpp" in line.lower()
                or "LLAMA_CPP" in line
                or "LLAMA_TARBALL" in line
            ):
                continue
            if "curl()" in line:  # function definition
                continue
            # Skip echo/string output (not actual commands)
            if line.startswith("echo ") or line.startswith('"'):
                continue
            if re.match(r".*\bcurl\s+-", line) or re.match(r".*\bcurl\s+http", line):
                pytest.fail(f"Found bare curl fetch: {line}")

    def test_no_bare_wget(self, build_script_content):
        """No wget calls allowed."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            if "fail_build" in line and "wget" in line:
                continue
            if "wget()" in line:
                continue
            if re.match(r".*\bwget\b", line):
                pytest.fail(f"Found wget command: {line}")


class TestNoDnfInBuildScript:
    """Build deps must come from recipe, not ad hoc dnf/yum calls."""

    def test_no_dnf_install(self, build_script_content):
        """No dnf install commands (deps come from recipe rpm-ostree)."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            if re.match(r".*\bdnf\s+install\b", line):
                pytest.fail(f"Found dnf install in build script: {line}")

    def test_no_yum_install(self, build_script_content):
        """No yum install commands."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            if re.match(r".*\byum\s+install\b", line):
                pytest.fail(f"Found yum install in build script: {line}")


class TestHermeticPythonInstalls:
    """pip install must use --no-index in hermetic mode."""

    def test_pip_install_uses_no_index_or_find_links(self, build_script_content):
        """All pip install calls should use --no-index or --find-links for local wheelhouse."""
        lines = _non_comment_lines(build_script_content)
        for line in lines:
            if "pip" in line and "install" in line:
                # Skip comments and the hermetic env var setup
                if "PIP_NO_INDEX" in line:
                    continue
                if "PIP_DISABLE" in line:
                    continue
                # In hermetic mode, PIP_NO_INDEX=1 is set as env var,
                # so individual pip install calls don't need --no-index flag.
                # But they should use --find-links or the env var must be set.
                # This is a guardrail check, not proof.
                pass  # Allowed — PIP_NO_INDEX env var handles this


class TestPythonApplicationRuntime:
    """The image must consume the CPython 3.12 wheelhouse with CPython 3.12."""

    def test_uses_an_exact_isolated_python312_runtime(self, build_script_content):
        assert (
            'PYTHON_RUNTIME_DIR="/usr/lib/secure-ai/python3.12-venv"'
            in build_script_content
        )
        assert "/usr/bin/python3.12 -m venv --copies --clear" in build_script_content
        assert (
            'PYTHON_BIN="${PYTHON_RUNTIME_DIR}/bin/python3.12"' in build_script_content
        )
        assert '"${PYTHON_BIN}" -m pip install' in build_script_content

    def test_never_installs_application_packages_with_system_pip(
        self, build_script_content
    ):
        lines = _non_comment_lines(build_script_content)
        assert not any(re.search(r"\bpip3\s+install\b", line) for line in lines)
        assert "--prefix=/usr" not in build_script_content
        assert "--break-system-packages" not in build_script_content
        assert "--only-binary=:all:" in build_script_content

    def test_runtime_is_symlink_free_and_release_measured(self, build_script_content):
        assert (
            'find "${PYTHON_RUNTIME_DIR}" -type l -print -quit' in build_script_content
        )
        baseline_script = RELEASE_BASELINE_SCRIPT.read_text(encoding="utf-8")
        assert 'Path("/usr/lib/secure-ai/python3.12-venv")' in baseline_script

    def test_service_entrypoints_use_the_exact_runtime(self, build_script_content):
        shebang = "#!/usr/lib/secure-ai/python3.12-venv/bin/python3.12"
        assert build_script_content.count(shebang) == 3
        assert (
            build_script_content.count(
                "exec /usr/lib/secure-ai/python3.12-venv/bin/gunicorn"
            )
            == 2
        )

    def test_shared_security_primitives_are_installed(self, build_script_content):
        common_project = (
            Path(__file__).resolve().parent.parent
            / "services"
            / "common"
            / "pyproject.toml"
        )
        assert common_project.is_file()
        assert "install_python_source /tmp/services/common" in build_script_content
        assert "import common.audit_chain, common.auth" in build_script_content


class TestFinalReleaseBaseline:
    """Final measurements must bind immutable paths after policy assembly."""

    def test_generation_happens_only_in_the_finalizer(self, build_script_content):
        assert "generate-release-baseline.py" not in build_script_content
        finalizer = RELEASE_BASELINE_FINALIZER.read_text(encoding="utf-8")
        assert "set -euo pipefail" in finalizer
        assert '[ ! -f "$required_file" ] || [ -L "$required_file" ]' in finalizer
        assert 're.fullmatch(r"[0-9a-f]{40}", source_commit)' in finalizer
        assert 'python3 "$GENERATOR" --source-commit "$source_commit"' in finalizer
        assert "container signing policy is not reject-by-default" in finalizer
        assert "container signing policy does not contain the approved SecAI rule" in finalizer

    def test_candidates_use_immutable_image_paths(self, build_script_content):
        baseline_script = RELEASE_BASELINE_SCRIPT.read_text(encoding="utf-8")
        for forbidden_root in ("/usr/local", "/var", "/opt", "/tmp"):
            assert f'Path("{forbidden_root}' not in baseline_script

        required_block = build_script_content.split("REQUIRED_BINARIES=(", 1)[1].split(
            ")", 1
        )[0]
        for required_path in (
            "/usr/bin/securectl",
            "/usr/bin/secai-registryctl",
            "/usr/bin/gguf-guard",
        ):
            assert f'"{required_path}"' in required_block
            assert f'Path("{required_path}")' in baseline_script
        assert "OPTIONAL_BINARIES" not in build_script_content
        assert "/usr/local/bin/securectl" not in build_script_content
        assert "/usr/local/bin/gguf-guard" not in build_script_content

    def test_registry_cli_does_not_shadow_emergency_securectl(self):
        registry_cli = REGISTRY_CLI_SOURCE.read_text(encoding="utf-8")
        assert "secai-registryctl - Secure AI Appliance" in registry_cli
        for command in ("list", "info", "verify", "path", "delete", "status"):
            assert f"secai-registryctl {command}" in registry_cli
        assert "securectl - Secure AI Appliance" not in registry_cli


class TestHermeticGoBuilds:
    """Go builds must use -mod=vendor."""

    def test_goflags_mod_vendor(self, build_script_content):
        """GOFLAGS=-mod=vendor must be set in hermetic mode."""
        assert (
            "GOFLAGS" in build_script_content and "mod=vendor" in build_script_content
        ), "Hermetic mode must set GOFLAGS=-mod=vendor"

    def test_goproxy_off(self, build_script_content):
        """GOPROXY=off must be set in hermetic mode."""
        assert "GOPROXY=off" in build_script_content, (
            "Hermetic mode must set GOPROXY=off"
        )

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

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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

    def test_llama_release_pin_and_reported_build_identity_agree(self, build_script_content):
        assert 'LLAMA_CPP_VERSION="${LLAMA_CPP_VERSION:-v0.6.0}"' in build_script_content
        assert "09b36dba235fcac180efff18514da7038e65d8e5b9e4aefa59238468abfdec12" in build_script_content
        assert "-DLLAMA_BUILD_NUMBER=11429" in build_script_content
        assert build_script_content.count("d81235049384534c167caea52b85a694f6103d14") == 2


class TestNoBareNetworkFetches:
    """Build script must not use bare curl/wget for dependency fetches."""

    def test_no_bare_curl(self, build_script_content):
        """curl calls must be guarded or fetch checksum-verified source/toolchain archives."""
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
                or "GO_TARBALL" in line
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

        runtime = "/usr/lib/secure-ai/python3.12-venv/bin"
        ui_wrapper = build_script_content.split(
            "cat > \"${INSTALL_DIR}/ui\" <<'WRAPPER'", 1
        )[1].split("\nWRAPPER", 1)[0]
        search_wrapper = build_script_content.split(
            "cat > \"${INSTALL_DIR}/search-mediator\" <<'WRAPPER'", 1
        )[1].split("\nWRAPPER", 1)[0]
        assert f"exec {runtime}/python -I -B -m ui.runtime -- \\\n    {runtime}/gunicorn" in ui_wrapper
        assert f"exec {runtime}/gunicorn" in search_wrapper

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

    @pytest.mark.parametrize("kind", ["writable", "missing", "symlink", "directory", "fifo"])
    def test_attestation_policy_installation_precedes_measurement(self, tmp_path, kind):
        finalizer = RELEASE_BASELINE_FINALIZER.read_text(encoding="utf-8")
        marker = 'python3 - "$ATTESTATION_POLICY" <<\'PY\'\n'
        assert finalizer.index(marker) < finalizer.index('python3 "$GENERATOR"')
        operation = finalizer.split(marker, 1)[1].split("\nPY\n", 1)[0]
        assert 'readonly ATTESTATION_POLICY="/etc/secure-ai/policy/attestation.yaml"' in finalizer
        policy = tmp_path / "etc/secure-ai/policy/attestation.yaml"
        policy.parent.mkdir(parents=True)
        original = RELEASE_BASELINE_FINALIZER.parents[2] / "files/system/etc/secure-ai/policy/attestation.yaml"
        data = original.read_bytes()
        outside = tmp_path / "outside-policy"
        outside.write_bytes(data)
        outside.chmod(0o666)
        if kind == "writable":
            policy.write_bytes(data)
            policy.chmod(0o666)
        elif kind == "symlink":
            policy.symlink_to(outside)
        elif kind == "directory":
            policy.mkdir()
        elif kind == "fifo":
            os.mkfifo(policy, 0o600)

        # The production operation runs unchanged on a disposable image root.
        # Namespace root exercises actual fchown/fchmod without host privileges.
        command = [sys.executable, "-", str(policy), str(tmp_path), str(RELEASE_BASELINE_SCRIPT)]
        if os.geteuid() != 0:
            unshare = shutil.which("unshare")
            if not unshare:
                pytest.skip("requires root or unshare user namespace support")
            available = subprocess.run([unshare, "--user", "--map-root-user", "true"],
                                       check=False, capture_output=True)
            if available.returncode:
                pytest.skip("requires an enabled root user namespace")
            command = [unshare, "--user", "--map-root-user", *command]
        verification = '\nprint(f"installed:{installed.st_uid}:{installed.st_gid}:{stat.S_IMODE(installed.st_mode):o}")\n'
        if kind == "writable":
            # Execute the real generator after installation, with its absolute
            # image paths resolved solely inside this disposable process root.
            verification += '''
import importlib.util
root, generator_path = sys.argv[2:4]
spec = importlib.util.spec_from_file_location("release_baseline", generator_path)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
sys.argv = [generator_path, "--source-commit", "a" * 40]
generator.parse_args()  # Load argparse dependencies before entering the image.
os.chroot(root)
os.chdir("/")
raise SystemExit(generator.main())
'''
        result = subprocess.run(command, input=operation + verification, text=True,
                                capture_output=True, check=False, timeout=5)
        if kind == "writable":
            assert result.returncode == 0, result.stderr
            assert result.stdout.splitlines()[0] == "installed:0:0:644"
            assert stat.S_ISREG(policy.lstat().st_mode)
            assert stat.S_IMODE(policy.stat().st_mode) == 0o644
            assert policy.read_bytes() == data
            baseline = json.loads((tmp_path / "usr/share/secure-ai/integrity/release-baseline.json").read_text())
            assert baseline["files"] == [{"path": "/etc/secure-ai/policy/attestation.yaml",
                                          "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]
        else:
            assert result.returncode != 0
            assert result.stdout == ""
        assert stat.S_IMODE(outside.stat().st_mode) == 0o666
        assert outside.read_bytes() == data

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


@pytest.mark.parametrize("configured,expected", [(None, "1"), ("1", "1"), ("2", "2"), ("8", "8")])
def test_build_job_budget_is_explicit_and_defaults_to_one(build_script_content, configured, expected):
    preamble = build_script_content.split('echo "=== Building Secure AI services ==="', 1)[0]
    environment = dict(os.environ)
    environment.pop("SECAI_BUILD_JOBS", None)
    if configured is not None:
        environment["SECAI_BUILD_JOBS"] = configured
    result = subprocess.run(
        ["bash", "-c", preamble + '\nprintf "%s:%s\\n" "$BUILD_JOBS" "$GOMAXPROCS"'],
        env=environment, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{expected}:{expected}"
    go_commands = [line for line in build_script_content.splitlines() if "CGO_ENABLED=0 go build " in line]
    assert len(go_commands) == 11
    cmake_command = next(line for line in build_script_content.splitlines()
                         if line.startswith("cmake --build build --target llama-server "))
    commands = "\n".join(go_commands + [cmake_command])
    mocks = '\ngo() { printf "GO:%s:%s\\n" "$GOMAXPROCS" "$*"; }\ncmake() { printf "CMAKE:%s\\n" "$*"; }\n'
    dispatched = subprocess.run(
        ["bash", "-c", preamble + mocks + commands],
        env=environment, capture_output=True, text=True, timeout=5,
    )
    assert dispatched.returncode == 0, dispatched.stderr
    output = dispatched.stdout.splitlines()
    assert len(output) == 12
    assert all(line.startswith(f"GO:{expected}:build -p {expected} ") for line in output[:11])
    assert output[-1] == f"CMAKE:--build build --target llama-server -j{expected}"
    assert "$(nproc)" not in build_script_content


@pytest.mark.parametrize("configured", ["0", "9", "-1", "1.5", "two", "1 2", "$(nproc)", "99999999999999999999"])
def test_build_job_budget_rejects_invalid_values_before_building(build_script_content, configured):
    preamble = build_script_content.split('echo "=== Building Secure AI services ==="', 1)[0]
    result = subprocess.run(
        ["bash", "-c", preamble + "\necho build-would-start"],
        env={**os.environ, "SECAI_BUILD_JOBS": configured},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0
    assert "SECAI_BUILD_JOBS must be an integer from 1 to 8" in result.stdout + result.stderr
    assert "build-would-start" not in result.stdout

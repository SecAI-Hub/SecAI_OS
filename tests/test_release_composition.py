"""Execute source selection and payload checks without running an OS build."""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import tomllib
import yaml

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "files/scripts/build-services.sh"
VERIFY = ROOT / "files/scripts/verify-source-snapshot.py"
EMBEDDED = {
    "airlock": "airlock", "ai-model-registry": "registry",
    "agent-tool-firewall": "tool-firewall", "gpu-integrity-watch": "gpu-integrity-watch",
    "mcp-firewall": "mcp-firewall", "policy-engine": "policy-engine",
    "runtime-attestor": "runtime-attestor", "integrity-monitor": "integrity-monitor",
    "incident-recorder": "incident-recorder", "ai-quarantine": "quarantine",
}


@pytest.mark.parametrize("name,embedded", EMBEDDED.items())
def test_native_source_selection_cannot_choose_shadow(tmp_path, name, embedded):
    script = BUILDER.read_text()
    function = script.split("locate_source() {", 1)[1].split("\n}\n", 1)[0]
    selection = re.search(rf"if locate_source {name}\s+(.+?); then", script, re.DOTALL)[1]
    selection = selection.replace("\\\n", " ").strip()
    assert selection == f"/tmp/services/{embedded}"
    for relative, marker in [(f"services/{embedded}", "embedded"),
                             (f"upstreams/{name}", "shadow"), (name, "shadow")]:
        directory = tmp_path / relative
        directory.mkdir(parents=True)
        (directory / "marker").write_text(marker)
    build = tmp_path / "build"
    build.mkdir()
    shell = ('set -eu\nfail_build() { exit 42; }\n'
             'SRC_DIR="$1"\nlocate_source() {' + function + '\n}\n'
             'locate_source "$2" "$3"\ncat "$SOURCE_DIR/marker"\n')
    args = ["bash", "-c", shell, "selection", str(build), name, str(tmp_path / "services" / embedded)]
    result = subprocess.run(args, text=True, check=False, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "embedded"
    # An existing destination must never silently nest or retain old source.
    assert subprocess.run(args, check=False, capture_output=True).returncode == 42
    shutil.rmtree(build / name)
    shutil.rmtree(tmp_path / "services" / embedded)
    assert subprocess.run(args, check=False, capture_output=True).returncode != 0
    (tmp_path / "services" / embedded).symlink_to(tmp_path / "upstreams" / name)
    assert subprocess.run(args, check=False, capture_output=True).returncode == 42


@pytest.mark.parametrize("mutation", ["none", "edited", "added", "symlink", "traversal"])
def test_snapshot_is_checked_at_build_time(tmp_path, mutation):
    source = tmp_path / "snapshot"
    shutil.copytree(ROOT / "services/mcp-firewall", source, ignore=shutil.ignore_patterns("vendor"))
    if mutation == "edited":
        (source / "main.go").write_text("package main\n")
    elif mutation == "added":
        (source / "unreviewed.go").write_text("package main\n")
    elif mutation == "symlink":
        (source / "main.go").unlink()
        (source / "main.go").symlink_to(ROOT / "services/mcp-firewall/main.go")
    elif mutation == "traversal":
        manifest = json.loads((source / "UPSTREAM_SYNC.json").read_text())
        manifest["files"]["../outside"] = "0" * 64
        (source / "UPSTREAM_SYNC.json").write_text(json.dumps(manifest))
    result = subprocess.run([sys.executable, str(VERIFY), str(source)], check=False, capture_output=True)
    assert (result.returncode == 0) == (mutation == "none"), result.stderr
    build = BUILDER.read_text().split("if locate_source mcp-firewall", 1)[1].split("else GO_SKIPPED", 1)[0]
    assert build.index("verify-source-snapshot.py") < build.index("go build")


def test_native_scanner_version_assertion_matches_locked_packages():
    script = BUILDER.read_text()
    block = re.search(r'expected = (\{[^}]+"modelaudit"[^}]+\})', script)[1]
    expected = ast.literal_eval(block)
    lock = (ROOT / "vendor/application-requirements.lock").read_text()
    for name, version in expected.items():
        assert re.search(rf"^{name}=={re.escape(version)}(?:\s|$)", lock, re.MULTILINE)
    quarantine = tomllib.loads((ROOT / "services/quarantine/pyproject.toml").read_text())
    for name, version in expected.items():
        assert f"{name}=={version}" in quarantine["project"]["optional-dependencies"]["scan"]


def test_ui_wheel_package_data_is_explicit_and_scoped():
    config = tomllib.loads((ROOT / "services/ui/pyproject.toml").read_text())
    setuptools = config["tool"]["setuptools"]
    assert setuptools["packages"] == ["ui"]
    assert setuptools["include-package-data"] is False
    assert "templates/*.html" in setuptools["package-data"]["ui"]


def test_ci_requires_its_hash_locked_packaging_runtime():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["python-test"]
    assert job["env"]["SECAI_PACKAGING_PYTHON"] == "python"
    assert any("--require-hashes -r requirements-ci.lock" in step.get("run", "")
               for step in job["steps"])
    assert any("python -m pytest tests/" in step.get("run", "") for step in job["steps"])
    source = (ROOT / "requirements-ci.txt").read_text()
    lock = (ROOT / "requirements-ci.lock").read_text()
    application = (ROOT / "vendor/application-requirements.lock").read_text()
    for name, version in (("setuptools", "84.0.0"), ("wheel", "0.48.0")):
        assert f"{name}=={version}" in source
        pattern = rf"^{name}=={re.escape(version)}[^\n]*\n(?:    --hash=[^\n]+\n)+"
        assert re.search(pattern, lock, re.MULTILINE)[0] == re.search(pattern, application, re.MULTILINE)[0]


def test_native_ui_wheel_contains_exact_templates_and_renders_outside_checkout(tmp_path):
    runtime = os.getenv("SECAI_PACKAGING_PYTHON", sys.executable)
    available = subprocess.run([runtime, "-c", "import setuptools.build_meta"], check=False, capture_output=True)
    if available.returncode and "SECAI_PACKAGING_PYTHON" not in os.environ:
        pytest.skip("set SECAI_PACKAGING_PYTHON to the locked application runtime for wheel qualification")
    assert available.returncode == 0, available.stderr
    wheels = tmp_path / "wheels"
    target = tmp_path / "installed"
    env = {**os.environ, "PIP_NO_INDEX": "1", "PYTHONNOUSERSITE": "1"}
    for name in ("common", "ui", "agent"):
        source = tmp_path / "source" / name
        shutil.copytree(ROOT / "services" / name, source,
                        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build", ".pytest_cache"))
        result = subprocess.run([
            runtime, "-m", "pip", "wheel", "--no-index", "--no-deps",
            "--no-build-isolation", "--wheel-dir", str(wheels), str(source),
        ], cwd=tmp_path, env=env, check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
    with zipfile.ZipFile(next(wheels.glob("secai_agent-*.whl"))) as package:
        metadata = package.read("secai_agent-0.1.0.dist-info/METADATA").decode()
    required = re.findall(r"^Requires-Dist: (.+)$", metadata, re.MULTILINE)
    assert "requests==2.34.2" in required
    for lock_path in ("services/agent/requirements.txt", "services/agent/requirements.lock",
                      "vendor/application-requirements.lock"):
        assert re.search(r"^requests==2\.34\.2(?:\s|$)", (ROOT / lock_path).read_text(), re.MULTILINE)
    wheel = next(wheels.glob("secure_ai_ui-*.whl"))
    with zipfile.ZipFile(wheel) as package:
        payload = {name: package.read(name) for name in package.namelist()}
    expected = {path.relative_to(ROOT / "services/ui").as_posix(): path.read_bytes()
                for path in (ROOT / "services/ui/ui").rglob("*")
                if path.is_file() and "__pycache__" not in path.parts
                and (path.suffix == ".py" or "templates" in path.parts or "static" in path.parts)}
    assert {name: data for name, data in payload.items() if name.startswith("ui/")} == expected
    assert all(name.startswith(("ui/", "secure_ai_ui-0.1.0.dist-info/")) for name in payload)
    result = subprocess.run([
        runtime, "-m", "pip", "install", "--no-index", "--no-deps",
        "--target", str(target), *map(str, wheels.glob("*.whl")),
    ], cwd=tmp_path, env=env, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    # Import only installed wheels, use private synthetic state, and prohibit
    # connections even if a future template/context processor attempts one.
    child = r'''
import os, pathlib, socket, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root / "installed"))
def no_network(*args, **kwargs):
    raise AssertionError("packaging render must not connect to a service")
socket.socket.connect = no_network
socket.create_connection = no_network
os.environ.update({
    "SECAI_ALLOW_EPHEMERAL_FLASK_SECRET": "true", "BIND_ADDR": "127.0.0.1:8480",
    "AUDIT_LOG_PATH": str(root / "state/ui-audit.jsonl"),
    "AUTH_DATA_DIR": str(root / "state/auth"),
    "SECURE_AI_ROOT": str(root / "state"),
    "SETUP_TOKEN_PATH": str(root / "state/setup.token"),
    "SETUP_STATE_PATH": str(root / "state/setup.json"),
})
from ui import app as module
from flask import render_template
assert pathlib.Path(module.__file__).is_relative_to(root / "installed")
for name in module.app.jinja_env.list_templates():
    module.app.jinja_env.get_template(name)
with module.app.test_request_context("/login"):
    for name in ("login.html", "models.html", "security.html"):
        rendered = render_template(name, active_page=name.split(".")[0])
        assert "<!doctype html>" in rendered.lower()
response = module.app.test_client().get("/login")
assert response.status_code == 200, response.status_code
print("installed UI: 11 exact templates; login/models/security render; /login 200; no network")
'''
    result = subprocess.run([runtime, "-I", "-c", child, str(tmp_path)],
                            cwd=tmp_path, env=env, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

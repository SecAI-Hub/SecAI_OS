"""Installer rollback must have exclusive ownership before changing shared state."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "files/scripts/secai-enable-diffusion.sh"


@pytest.fixture
def installer(tmp_path):
    # Execute the actual rollback, traps and lock acquisition. Platform/runtime
    # installation is deliberately outside this private, no-device fixture.
    source = INSTALLER.read_text()
    code = source.split("# Fail-closed rollback\n", 1)[1].split(
        "# Step 1: Validate platform", 1)[0]
    venv = tmp_path / "venv.tmp"
    venv.mkdir()
    payload = venv / "retained"
    payload.write_bytes(b"another operation's staging")
    override = tmp_path / "override"
    override.mkdir()
    ready = tmp_path / "ready"
    ready.write_bytes(b"ready")
    override_file = override / "venv.conf"
    override_file.write_bytes(b"active override")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(f"#!{sys.executable}\n" + '''import fcntl, json, os, sys
held = False
with open(os.environ['LOCK_FILE'], 'a') as lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        held = True
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps({'args': sys.argv[1:], 'lock_held': held}) + '\\n')
''')
    systemctl.chmod(0o700)
    env = os.environ | {
        "VENV_TMP": str(venv), "OVERRIDE_DIR": str(override),
        "OVERRIDE_FILE": str(override_file), "READY_MARKER": str(ready),
        "FAILED_MARKER": str(tmp_path / "failed"),
        "REQUEST_MARKER": str(tmp_path / "request"),
        "AUDIT_LOG": str(tmp_path / "audit"), "PYTHON_BIN": sys.executable,
        "LOCK_FILE": str(tmp_path / "installer.lock"),
        "CALLS": str(tmp_path / "calls"),
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
    }

    def run(after=""):
        return subprocess.run(["bash", "-c", "set -euo pipefail\n"
                               "_progress_error() { :; }\n" + code + after],
                              env=env, capture_output=True, text=True, timeout=10)

    return tmp_path, env, run, (payload, override_file, ready)


@pytest.mark.parametrize("failure", ["lock_is_directory", "parent_is_file", "busy"])
def test_no_rollback_before_installer_exclusion(installer, failure):
    tmp_path, env, run, retained = installer
    lock = Path(env["LOCK_FILE"])
    held = None
    if failure == "lock_is_directory":
        lock.mkdir()
    elif failure == "parent_is_file":
        parent = tmp_path / "not-a-directory"
        parent.write_bytes(b"retained parent")
        env["LOCK_FILE"] = str(parent / "lock")
    else:
        held = lock.open("w")
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    before = [path.read_bytes() for path in retained]
    try:
        result = run()
    finally:
        if held is not None:
            held.close()
    assert result.returncode != 0
    assert "ROLLBACK:" not in result.stderr
    assert [path.read_bytes() for path in retained] == before
    assert not Path(env["FAILED_MARKER"]).exists()
    assert not Path(env["CALLS"]).exists()


def test_failure_after_exclusion_rolls_back_while_lock_is_held(installer):
    _, env, run, retained = installer
    result = run("\nfalse\n")
    assert result.returncode != 0
    assert "ROLLBACK:" in result.stderr
    assert all(not path.exists() for path in retained)
    assert Path(env["FAILED_MARKER"]).is_file()
    calls = [json.loads(line) for line in Path(env["CALLS"]).read_text().splitlines()]
    assert [call["args"] for call in calls] == [
        ["daemon-reload"], ["disable", "secure-ai-diffusion.service"]]
    assert all(call["lock_held"] for call in calls)
    with open(env["LOCK_FILE"], "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

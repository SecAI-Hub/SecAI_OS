"""Exercise the upstream maintenance command without network or Git mutations."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/update-upstream.sh"
COMMIT = "b" * 40
ARCHIVE = b"fixture source archive\n"


@pytest.fixture
def checkout(tmp_path):
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    private_tmp = tmp_path / "downloads"
    private_tmp.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python3"
    python.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n')
    python.chmod(0o755)
    fake_tool = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'curl':
    target = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
    if not target.is_relative_to(os.environ['TMPDIR']):
        sys.exit(23)
    target.write_bytes(b'fixture source archive\\n')
    if os.environ.get('CURL_FAIL'):
        sys.exit(22)
elif os.environ.get('GIT_FAIL'):
    sys.exit(1)
'''
    for name in ("curl", "git"):
        path = bin_dir / name
        path.write_text(fake_tool)
        path.chmod(0o755)
    lock = workspace / ".upstreams.lock.yaml"
    lock.write_text(yaml.safe_dump({"schema_version": 1, "upstreams": {
        "helper": {"upstream_url": "https://github.com/example/helper.git",
                   "pinned_commit": "a" * 40, "archive_sha256": "c" * 64,
                   "reviewer": "fixture-reviewer", "license": "Apache-2.0"},
        "other": {"pinned_commit": "d" * 40},
    }}))
    lock.chmod(0o640)
    env = os.environ | {"PATH": f"{bin_dir}:/usr/bin:/bin", "TMPDIR": str(private_tmp),
                        "CALLS": str(tmp_path / "calls")}
    return workspace, lock, private_tmp, env


def run_update(checkout, *args, extra_env=None):
    workspace, _, _, env = checkout
    return subprocess.run(["bash", str(SCRIPT), *args], cwd=workspace,
                          env=env | (extra_env or {}), capture_output=True,
                          text=True, timeout=10)


def calls(checkout):
    path = Path(checkout[3]["CALLS"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.parametrize("name,commit", [
    ("helper", "main"), ("helper", "-" + "a" * 39),
    ("helper", "a" * 39), ("helper", "A" * 40),
    ("../helper", COMMIT), ("helper/child", COMMIT),
    ("helper", "'; __import__('pathlib').Path('INJECTED').write_text('yes'); #"),
    ("'); __import__('pathlib').Path('INJECTED').write_text('yes'); #", COMMIT),
])
def test_rejects_untrusted_arguments_before_download_or_git(checkout, name, commit):
    before = checkout[1].read_bytes()
    result = run_update(checkout, name, commit)
    assert result.returncode != 0
    assert not (checkout[0] / "INJECTED").exists()
    assert calls(checkout) == []
    assert checkout[1].read_bytes() == before
    assert list(checkout[2].iterdir()) == []


@pytest.mark.parametrize("existing", [False, True])
def test_updates_selected_entry_and_cleans_private_download(checkout, existing):
    if existing:
        (checkout[0] / "upstreams/helper").mkdir(parents=True)
    before_other = yaml.safe_load(checkout[1].read_text())["upstreams"]["other"]
    result = run_update(checkout, "helper", COMMIT)
    assert result.returncode == 0, result.stderr
    tool_calls = calls(checkout)
    curl = next(call for call in tool_calls if call[0] == "curl")
    archive_path = Path(curl[curl.index("-o") + 1])
    assert archive_path.parent.parent == checkout[2]
    assert not archive_path.parent.exists()
    git = next(call for call in tool_calls if call[0] == "git")
    assert git[1:3] == ["subtree", "pull" if existing else "add"]
    assert COMMIT in git
    lock = yaml.safe_load(checkout[1].read_text())
    entry = lock["upstreams"]["helper"]
    assert entry["pinned_commit"] == COMMIT
    assert entry["archive_sha256"] == hashlib.sha256(ARCHIVE).hexdigest()
    assert entry["local_path"] == "upstreams/helper"
    assert entry["reviewer"] == "fixture-reviewer"
    assert lock["upstreams"]["other"] == before_other
    assert checkout[1].stat().st_mode & 0o777 == 0o640
    assert list(checkout[2].iterdir()) == []


@pytest.mark.parametrize("failure", ["CURL_FAIL", "GIT_FAIL"])
def test_failure_cleans_partial_download_without_updating_lock(checkout, failure):
    before = checkout[1].read_bytes()
    result = run_update(checkout, "helper", COMMIT, extra_env={failure: "1"})
    assert result.returncode != 0
    assert checkout[1].read_bytes() == before
    assert list(checkout[2].iterdir()) == []
    if failure == "CURL_FAIL":
        assert not any(call[0] == "git" for call in calls(checkout))


def test_rejects_unknown_upstream_and_extra_arguments(checkout):
    for args in [("missing", COMMIT), ("helper", COMMIT, "extra")]:
        assert run_update(checkout, *args).returncode != 0
    assert calls(checkout) == []

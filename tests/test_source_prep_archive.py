"""Tests for the verified source-prep handoff used by the image build."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
RESTORE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "restore-source-prep.py"
COMMIT_SHA = "a" * 40


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _bundle_members(application_lock: bytes) -> dict[str, bytes | None]:
    upstream_lock = b"upstreams: {}\n"
    llama_tarball = b"verified llama.cpp source"
    wheel = b"verified wheel"
    wheel_sums = f"{_sha256(wheel)}  verified.whl\n".encode()
    manifest = {
        "schema_version": 1,
        "commit_sha": COMMIT_SHA,
        "llama_cpp_version": "b5200",
        "llama_cpp_tarball_sha256": _sha256(llama_tarball),
        "wheelhouse_sha256sums_digest": _sha256(wheel_sums),
        "application_requirements_lock_digest": _sha256(application_lock),
        "upstreams_lock_digest": _sha256(upstream_lock),
        "wheel_count": 1,
        "application_dependency_mode": "staged-offline",
        "upstream_paths": ["upstreams/searxng"],
        "go_vendor_paths": ["services/demo/vendor"],
    }
    return {
        ".source-prep": None,
        ".source-prep/SOURCE_PREP_MANIFEST.json": json.dumps(manifest).encode(),
        ".source-prep/llama-cpp-staged.tar.gz": llama_tarball,
        ".upstreams.lock.yaml": upstream_lock,
        "upstreams": None,
        "upstreams/searxng": None,
        "upstreams/searxng/searxng.conf:socket": b"verified source\n",
        "vendor/wheels": None,
        "vendor/wheels/SHA256SUMS": wheel_sums,
        "vendor/wheels/verified.whl": wheel,
        "services/demo/vendor": None,
        "services/demo/vendor/example.com": None,
        "services/demo/vendor/example.com/dependency.go": b"package dependency\n",
    }


def _write_bundle(
    workspace: Path, extra_members: dict[str, bytes | None] | None = None
) -> tuple[Path, Path, str]:
    application_lock = b"verified application lock\n"
    application_lock_path = workspace / "vendor/application-requirements.lock"
    application_lock_path.parent.mkdir(parents=True)
    application_lock_path.write_bytes(application_lock)
    (workspace / ".upstreams.lock.yaml").write_text(
        "upstreams: {}\n", encoding="utf-8"
    )
    (workspace / "services/demo").mkdir(parents=True)

    members = _bundle_members(application_lock)
    if extra_members:
        members.update(extra_members)
    archive_path = workspace / "source-prep.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(content))

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = workspace / "source-prep.tar.gz.sha256"
    checksum_path.write_text(f"{digest}  source-prep.tar.gz\n", encoding="ascii")
    return archive_path, checksum_path, digest


def _run_restore(
    workspace: Path,
    archive_path: Path,
    checksum_path: Path,
    expected_digest: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["EXPECTED_SOURCE_PREP_SHA256"] = expected_digest
    env["GITHUB_SHA"] = COMMIT_SHA
    env["RUNNER_TEMP"] = str(workspace)
    return subprocess.run(
        [
            sys.executable,
            str(RESTORE_SCRIPT),
            "--archive",
            str(archive_path),
            "--checksum",
            str(checksum_path),
        ],
        cwd=workspace,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def test_restore_preserves_colon_filename_and_replaces_stale_tree(tmp_path: Path) -> None:
    archive_path, checksum_path, digest = _write_bundle(tmp_path)
    stale_tree = tmp_path / "upstreams"
    stale_tree.mkdir()
    (stale_tree / "stale").write_text("remove me", encoding="utf-8")

    result = _run_restore(tmp_path, archive_path, checksum_path, digest)

    assert result.returncode == 0, result.stderr
    assert (
        tmp_path / "upstreams" / "searxng" / "searxng.conf:socket"
    ).read_bytes() == b"verified source\n"
    assert not (tmp_path / "upstreams" / "stale").exists()
    assert (tmp_path / "services/demo/vendor/example.com/dependency.go").is_file()
    workflow = (REPO_ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    assert "find vendor/wheels -mindepth 1 -maxdepth 1 -type f -delete" in workflow
    assert "source-prep-bundle/source-prep.tar.gz" in workflow
    assert "            upstreams/\n" not in workflow


def test_restore_rejects_archive_checksum_mismatch(tmp_path: Path) -> None:
    archive_path, checksum_path, _ = _write_bundle(tmp_path)
    incorrect_digest = "0" * 64
    checksum_path.write_text(
        f"{incorrect_digest}  source-prep.tar.gz\n", encoding="ascii"
    )

    result = _run_restore(
        tmp_path, archive_path, checksum_path, incorrect_digest
    )

    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr
    assert not (tmp_path / "upstreams").exists()


def test_restore_rejects_member_outside_allowlist(tmp_path: Path) -> None:
    archive_path, checksum_path, digest = _write_bundle(
        tmp_path, {"../escape": b"must not extract\n"}
    )

    result = _run_restore(tmp_path, archive_path, checksum_path, digest)

    assert result.returncode != 0
    assert "non-canonical path" in result.stderr
    assert not (tmp_path.parent / "escape").exists()

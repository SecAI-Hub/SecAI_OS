"""Tests for the verified source-prep handoff used by the image build."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
RESTORE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "restore-source-prep.py"
SEARXNG_PREP_SCRIPT = REPO_ROOT / "files" / "scripts" / "prepare-searxng-source.py"
COMMIT_SHA = "a" * 40
SEARXNG_COMMIT = "b060c780d0751a55e75ad22f0d930c8965789db8"


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
    (workspace / ".upstreams.lock.yaml").write_text("upstreams: {}\n", encoding="utf-8")
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


def _searxng_fixture(workspace: Path) -> tuple[Path, Path]:
    source = workspace / "upstreams" / "searxng"
    package = source / "searx"
    package.mkdir(parents=True)
    (package / "version.py").write_text("# pinned source\n", encoding="utf-8")
    lock = workspace / ".upstreams.lock.yaml"
    lock.write_text(
        "\n".join(
            (
                "schema_version: 1",
                "upstreams:",
                "  searxng:",
                "    upstream_url: https://github.com/searxng/searxng.git",
                f"    pinned_commit: {SEARXNG_COMMIT}",
                '    commit_timestamp: "2026-07-26T16:53:10Z"',
                "    local_path: upstreams/searxng",
                "",
            )
        ),
        encoding="utf-8",
    )
    return lock, source


def _run_searxng_prep(
    lock: Path, source: Path, *extra: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SEARXNG_PREP_SCRIPT),
            "--lock",
            str(lock),
            "--source",
            str(source),
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_searxng_source_prep_creates_and_verifies_locked_version(tmp_path: Path):
    lock, source = _searxng_fixture(tmp_path)

    created = _run_searxng_prep(lock, source)
    verified = _run_searxng_prep(lock, source, "--verify-only")

    assert created.returncode == 0, created.stderr
    assert verified.returncode == 0, verified.stderr
    frozen = source / "searx" / "version_frozen.py"
    content = frozen.read_text(encoding="utf-8")
    assert 'VERSION_TAG = "2026.7.26+b060c78"' in content
    assert f'PINNED_COMMIT = "{SEARXNG_COMMIT}"' in content
    assert stat.S_IMODE(frozen.stat().st_mode) == 0o644
    assert int(frozen.stat().st_mtime) == 1785084790

    # The checksum-bound source-prep bundle uses GNU tar --mtime=epoch for a
    # reproducible cross-job artifact. Stage 2 must still authenticate the
    # generated content after that intentional transport normalization.
    archive_path = tmp_path / "searxng-source-prep.tar.gz"

    def normalize_mtime(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mtime = 0
        return info

    with tarfile.open(archive_path, mode="w:gz") as archive:
        archive.add(lock, arcname=".upstreams.lock.yaml", filter=normalize_mtime)
        archive.add(source.parent, arcname="upstreams", filter=normalize_mtime)

    restored = tmp_path / "restored"
    restored.mkdir()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        archive.extractall(restored, filter="data")
    restored_lock = restored / ".upstreams.lock.yaml"
    restored_source = restored / "upstreams" / "searxng"
    restored_verify = _run_searxng_prep(
        restored_lock, restored_source, "--verify-only"
    )

    assert int((restored_source / "searx/version_frozen.py").stat().st_mtime) == 0
    assert restored_verify.returncode == 0, restored_verify.stderr


def test_searxng_source_prep_refuses_existing_or_tampered_metadata(tmp_path: Path):
    lock, source = _searxng_fixture(tmp_path)
    frozen = source / "searx" / "version_frozen.py"
    frozen.write_text("unreviewed\n", encoding="utf-8")

    create_result = _run_searxng_prep(lock, source)
    verify_result = _run_searxng_prep(lock, source, "--verify-only")

    assert create_result.returncode != 0
    assert "pre-existing" in create_result.stderr
    assert verify_result.returncode != 0
    assert "does not match the lock" in verify_result.stderr


def test_searxng_source_prep_rejects_a_linked_package_directory(tmp_path: Path):
    lock, source = _searxng_fixture(tmp_path)
    package = source / "searx"
    real_package = source / "real-searx"
    package.rename(real_package)
    package.symlink_to(real_package, target_is_directory=True)

    result = _run_searxng_prep(lock, source)

    assert result.returncode != 0
    assert "package directory is unsafe" in result.stderr


def test_searxng_source_prep_is_required_by_both_build_stages():
    workflow = (REPO_ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    build_script = (REPO_ROOT / "files/scripts/build-services.sh").read_text(
        encoding="utf-8"
    )

    assert "python3 files/scripts/prepare-searxng-source.py" in workflow
    assert "python3 /tmp/files/scripts/prepare-searxng-source.py" in build_script
    assert "--verify-only" in build_script


def test_restore_preserves_colon_filename_and_replaces_stale_tree(
    tmp_path: Path,
) -> None:
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
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert ".bluebuild-scripts_*" not in dockerignore.splitlines()
    assert os.access(REPO_ROOT / "files/scripts/build-services.sh", os.X_OK)


def test_restore_rejects_archive_checksum_mismatch(tmp_path: Path) -> None:
    archive_path, checksum_path, _ = _write_bundle(tmp_path)
    incorrect_digest = "0" * 64
    checksum_path.write_text(
        f"{incorrect_digest}  source-prep.tar.gz\n", encoding="ascii"
    )

    result = _run_restore(tmp_path, archive_path, checksum_path, incorrect_digest)

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

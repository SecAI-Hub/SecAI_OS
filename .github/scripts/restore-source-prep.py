#!/usr/bin/env python3
"""Verify and atomically restore source-prep inputs between build jobs."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


BUNDLE_NAME = "source-prep.tar.gz"
CHECKSUM_NAME = f"{BUNDLE_NAME}.sha256"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MAX_ARCHIVE_MEMBERS = 250_000
MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
SOURCE_PREP_FILES = {
    PurePosixPath(".source-prep"),
    PurePosixPath(".source-prep/SOURCE_PREP_MANIFEST.json"),
    PurePosixPath(".source-prep/llama-cpp-staged.tar.gz"),
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--checksum", required=True, type=Path)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_digest() -> str:
    digest = os.environ.get("EXPECTED_SOURCE_PREP_SHA256", "")
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("source-prep job output is not a canonical SHA-256 digest")
    return digest


def _verify_bundle_digest(archive: Path, checksum: Path) -> str:
    if archive.name != BUNDLE_NAME or not archive.is_file() or archive.is_symlink():
        raise ValueError("source-prep archive is missing or has an unexpected name")
    if (
        checksum.name != CHECKSUM_NAME
        or not checksum.is_file()
        or checksum.is_symlink()
    ):
        raise ValueError("source-prep checksum is missing or has an unexpected name")

    expected = _expected_digest()
    expected_sidecar = f"{expected}  {BUNDLE_NAME}\n"
    sidecar = checksum.read_text(encoding="ascii")
    if not hmac.compare_digest(sidecar, expected_sidecar):
        raise ValueError("source-prep checksum sidecar does not match the job output")
    actual = _sha256(archive)
    if not hmac.compare_digest(actual, expected):
        raise ValueError(
            f"source-prep archive checksum mismatch: expected {expected}, got {actual}"
        )
    return actual


def _member_root(path: PurePosixPath) -> PurePosixPath:
    parts = path.parts
    if path in SOURCE_PREP_FILES:
        return PurePosixPath(".source-prep")
    if path == PurePosixPath(".upstreams.lock.yaml"):
        return path
    if parts and parts[0] == "upstreams":
        return PurePosixPath("upstreams")
    if parts[:2] == ("vendor", "wheels"):
        if len(parts) == 2:
            return PurePosixPath("vendor/wheels")
        if len(parts) == 3 and (
            parts[2] == "SHA256SUMS" or parts[2].endswith(".whl")
        ):
            return PurePosixPath("vendor/wheels")
    if len(parts) >= 3 and parts[0] == "services" and parts[2] == "vendor":
        return PurePosixPath(*parts[:3])
    raise ValueError(f"archive member is outside the source-prep allowlist: {path}")


def _validated_member(member: tarfile.TarInfo) -> tuple[PurePosixPath, PurePosixPath]:
    path = PurePosixPath(member.name)
    raw_name = member.name.rstrip("/")
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or raw_name != path.as_posix()
    ):
        raise ValueError(f"archive contains a non-canonical path: {member.name!r}")
    root = _member_root(path)
    if member.islnk():
        raise ValueError(f"archive contains a hard link: {member.name!r}")
    if member.sparse:
        raise ValueError(f"archive contains a sparse file: {member.name!r}")
    if not (member.isfile() or member.isdir() or member.issym()):
        raise ValueError(f"archive contains a special file: {member.name!r}")
    if member.issym():
        target = PurePosixPath(member.linkname)
        resolved = PurePosixPath(
            posixpath.normpath((path.parent / target).as_posix())
        )
        if (
            not member.linkname
            or target.is_absolute()
            or resolved.is_absolute()
            or not resolved.parts
            or ".." in resolved.parts
            or _member_root(resolved) != root
        ):
            raise ValueError(f"archive contains an unsafe symlink: {member.name!r}")
    return path, root


def _preflight_archive(archive: tarfile.TarFile) -> set[PurePosixPath]:
    members = archive.getmembers()
    if not members:
        raise ValueError("source-prep archive is empty")
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("source-prep archive exceeds the member-count limit")

    seen: set[PurePosixPath] = set()
    directory_roots: set[PurePosixPath] = set()
    total_size = 0
    for member in members:
        path, root = _validated_member(member)
        if path in seen:
            raise ValueError(f"archive contains a duplicate path: {member.name!r}")
        seen.add(path)
        if member.isfile():
            total_size += member.size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("source-prep archive exceeds the extracted-size limit")
        if path == root and member.isdir():
            directory_roots.add(root)

    required_roots = {
        PurePosixPath(".source-prep"),
        PurePosixPath("upstreams"),
        PurePosixPath("vendor/wheels"),
    }
    missing_roots = required_roots - directory_roots
    if missing_roots:
        missing = ", ".join(sorted(path.as_posix() for path in missing_roots))
        raise ValueError(f"source-prep archive is missing directory roots: {missing}")
    if PurePosixPath(".upstreams.lock.yaml") not in seen:
        raise ValueError("source-prep archive is missing the upstream lock")
    return directory_roots


def _manifest_digest(manifest: dict[str, object], field: str) -> str:
    value = manifest.get(field)
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"manifest field {field!r} is not a canonical SHA-256 digest")
    return value


def _manifest_paths(
    manifest: dict[str, object], field: str, prefix: tuple[str, ...]
) -> list[PurePosixPath]:
    raw_paths = manifest.get(field)
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ValueError(f"manifest field {field!r} contains no paths")
    paths: list[PurePosixPath] = []
    for raw_path in raw_paths:
        if not isinstance(raw_path, str):
            raise ValueError(f"manifest field {field!r} contains a non-string path")
        path = PurePosixPath(raw_path)
        if (
            path.is_absolute()
            or len(path.parts) <= len(prefix)
            or path.parts[: len(prefix)] != prefix
            or ".." in path.parts
            or path.as_posix() != raw_path
        ):
            raise ValueError(f"manifest field {field!r} contains an unsafe path")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise ValueError(f"manifest field {field!r} contains duplicate paths")
    return paths


def _regular_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required source-prep file is missing: {relative}")
    return path


def _verify_wheelhouse(staging_root: Path, manifest: dict[str, object]) -> None:
    checksum_path = _regular_file(staging_root, "vendor/wheels/SHA256SUMS")
    expected_digest = _manifest_digest(manifest, "wheelhouse_sha256sums_digest")
    if not hmac.compare_digest(_sha256(checksum_path), expected_digest):
        raise ValueError("wheelhouse SHA256SUMS digest does not match the manifest")

    lines = [line for line in checksum_path.read_text(encoding="utf-8").splitlines() if line]
    wheel_count = manifest.get("wheel_count")
    if not isinstance(wheel_count, int) or wheel_count < 1 or len(lines) != wheel_count:
        raise ValueError("wheelhouse count does not match the manifest")

    seen_names: set[str] = set()
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([^/]+\.whl)", line)
        if not match:
            raise ValueError("wheelhouse checksum manifest contains an unsafe entry")
        expected, filename = match.groups()
        if filename in seen_names:
            raise ValueError("wheelhouse checksum manifest contains a duplicate entry")
        seen_names.add(filename)
        wheel_path = _regular_file(staging_root, f"vendor/wheels/{filename}")
        if not hmac.compare_digest(_sha256(wheel_path), expected):
            raise ValueError(f"wheelhouse checksum mismatch for {filename}")

    wheel_dir = staging_root / "vendor/wheels"
    actual_names = {
        path.name
        for path in wheel_dir.iterdir()
        if path.is_file() and not path.is_symlink() and path.suffix == ".whl"
    }
    if actual_names != seen_names:
        raise ValueError("wheelhouse contents do not exactly match SHA256SUMS")


def _verify_manifest(staging_root: Path, workspace: Path) -> list[PurePosixPath]:
    manifest_path = _regular_file(
        staging_root, ".source-prep/SOURCE_PREP_MANIFEST.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("source-prep manifest has an unsupported schema")

    workflow_sha = os.environ.get("GITHUB_SHA", "")
    manifest_sha = manifest.get("commit_sha")
    if not COMMIT_RE.fullmatch(workflow_sha) or manifest_sha != workflow_sha:
        raise ValueError("source-prep manifest does not belong to this workflow commit")
    if manifest.get("application_dependency_mode") != "staged-offline":
        raise ValueError("source-prep manifest is not in staged-offline mode")

    staged_lock = _regular_file(staging_root, ".upstreams.lock.yaml")
    checkout_lock = _regular_file(workspace, ".upstreams.lock.yaml")
    expected_lock = _manifest_digest(manifest, "upstreams_lock_digest")
    for lock_path in (staged_lock, checkout_lock):
        if not hmac.compare_digest(_sha256(lock_path), expected_lock):
            raise ValueError("upstream lock digest does not match the manifest")

    application_lock = _regular_file(
        workspace, "vendor/application-requirements.lock"
    )
    expected_application_lock = _manifest_digest(
        manifest, "application_requirements_lock_digest"
    )
    if not hmac.compare_digest(
        _sha256(application_lock), expected_application_lock
    ):
        raise ValueError("application dependency lock does not match the manifest")

    llama_tarball = _regular_file(
        staging_root, ".source-prep/llama-cpp-staged.tar.gz"
    )
    expected_llama = _manifest_digest(manifest, "llama_cpp_tarball_sha256")
    if not hmac.compare_digest(_sha256(llama_tarball), expected_llama):
        raise ValueError("llama.cpp source digest does not match the manifest")

    upstream_paths = _manifest_paths(manifest, "upstream_paths", ("upstreams",))
    go_vendor_paths = _manifest_paths(manifest, "go_vendor_paths", ("services",))
    for path in upstream_paths + go_vendor_paths:
        staged_path = staging_root.joinpath(*path.parts)
        if staged_path.is_symlink() or not staged_path.is_dir():
            raise ValueError(f"required source-prep directory is missing: {path}")
    for path in go_vendor_paths:
        if len(path.parts) != 3 or path.parts[2] != "vendor":
            raise ValueError("manifest contains an invalid Go vendor path")

    _verify_wheelhouse(staging_root, manifest)
    return go_vendor_paths


def _remove_existing_destination(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"source-prep destination is a symlink: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _overlay_staged_inputs(
    staging_root: Path, workspace: Path, go_vendor_paths: list[PurePosixPath]
) -> None:
    roots = [
        PurePosixPath(".source-prep"),
        PurePosixPath(".upstreams.lock.yaml"),
        PurePosixPath("upstreams"),
        PurePosixPath("vendor/wheels"),
        *go_vendor_paths,
    ]
    workspace_resolved = workspace.resolve(strict=True)
    transfers: list[tuple[Path, Path]] = []
    for root in roots:
        source = staging_root.joinpath(*root.parts)
        destination = workspace.joinpath(*root.parts)
        if not source.exists() or source.is_symlink():
            raise ValueError(f"source-prep root is missing or unsafe: {root}")
        parent = destination.parent.resolve(strict=True)
        if parent != workspace_resolved and workspace_resolved not in parent.parents:
            raise ValueError(f"source-prep destination escapes the workspace: {root}")
        transfers.append((source, destination))

    for source, destination in transfers:
        _remove_existing_destination(destination)
        os.replace(source, destination)


def main() -> None:
    args = _arguments()
    workspace = Path.cwd()
    runner_temp = Path(os.environ.get("RUNNER_TEMP", args.archive.parent))
    try:
        actual_digest = _verify_bundle_digest(args.archive, args.checksum)
        with tarfile.open(args.archive, mode="r:gz") as archive:
            directory_roots = _preflight_archive(archive)
            with tempfile.TemporaryDirectory(
                prefix="source-prep-", dir=runner_temp
            ) as temp_dir:
                staging_root = Path(temp_dir)
                archive.extractall(staging_root, filter="data")
                go_vendor_paths = _verify_manifest(staging_root, workspace)
                archived_vendor_roots = {
                    root
                    for root in directory_roots
                    if len(root.parts) == 3
                    and root.parts[0] == "services"
                    and root.parts[2] == "vendor"
                }
                if archived_vendor_roots != set(go_vendor_paths):
                    raise ValueError(
                        "archive Go vendor roots do not match the source-prep manifest"
                    )
                _overlay_staged_inputs(staging_root, workspace, go_vendor_paths)
    except (OSError, UnicodeError, json.JSONDecodeError, tarfile.TarError, ValueError) as exc:
        raise SystemExit(f"source-prep restoration failed: {exc}") from exc

    print(
        f"Restored a verified source-prep bundle for {len(go_vendor_paths)} Go services "
        f"from {actual_digest}"
    )


if __name__ == "__main__":
    main()

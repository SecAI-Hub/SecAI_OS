#!/usr/bin/env python3
"""Create or verify deterministic SearXNG version metadata for an archive build."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

import yaml


COMMIT_RE = re.compile(r"[0-9a-f]{40}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
MAX_LOCK_BYTES = 1024 * 1024


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def _regular_file(path: Path, *, maximum: int | None = None) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"refusing non-regular file: {path}")
    if maximum is not None and metadata.st_size > maximum:
        raise ValueError(f"file exceeds safety limit: {path}")
    return path.read_bytes()


def _metadata(lock_path: Path, source_path: Path) -> tuple[bytes, int]:
    lock = yaml.safe_load(_regular_file(lock_path, maximum=MAX_LOCK_BYTES))
    if not isinstance(lock, dict):
        raise ValueError("upstream lock must be a mapping")
    upstreams = lock.get("upstreams")
    if not isinstance(upstreams, dict) or not isinstance(
        upstreams.get("searxng"), dict
    ):
        raise ValueError("upstream lock has no SearXNG entry")
    entry = upstreams["searxng"]

    commit = str(entry.get("pinned_commit", ""))
    timestamp = str(entry.get("commit_timestamp", ""))
    local_path = entry.get("local_path")
    upstream_url = str(entry.get("upstream_url", ""))
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("SearXNG commit pin is not canonical")
    if not TIMESTAMP_RE.fullmatch(timestamp):
        raise ValueError("SearXNG commit timestamp is not canonical UTC")
    if local_path != "upstreams/searxng":
        raise ValueError("SearXNG local path is not canonical")
    if upstream_url != "https://github.com/searxng/searxng.git":
        raise ValueError("SearXNG upstream URL is not canonical")

    expected_source = (lock_path.parent / local_path).resolve(strict=True)
    actual_source = source_path.resolve(strict=True)
    if actual_source != expected_source:
        raise ValueError("SearXNG source does not match its locked local path")
    source_metadata = source_path.lstat()
    if not stat.S_ISDIR(source_metadata.st_mode) or source_path.is_symlink():
        raise ValueError("SearXNG source root is not a safe directory")

    commit_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    version = f"{commit_time.year}.{commit_time.month}.{commit_time.day}+{commit[:7]}"
    values = {
        "VERSION_STRING": version,
        "VERSION_TAG": version,
        "DOCKER_TAG": version.replace("+", "-"),
        "GIT_URL": upstream_url.removesuffix(".git"),
        "GIT_BRANCH": f"pinned/{commit}",
        "PINNED_COMMIT": commit,
    }
    lines = [
        "# SPDX-License-Identifier: AGPL-3.0-or-later",
        "# Generated from the checksum-bound SecAI OS upstream lock.",
        "",
    ]
    lines.extend(f"{name} = {json.dumps(value)}" for name, value in values.items())
    return ("\n".join(lines) + "\n").encode("utf-8"), int(commit_time.timestamp())


def _output_path(source_path: Path) -> Path:
    package_dir = source_path / "searx"
    metadata = package_dir.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or package_dir.is_symlink():
        raise ValueError("SearXNG package directory is unsafe")
    version_module = package_dir / "version.py"
    _regular_file(version_module, maximum=1024 * 1024)
    return package_dir / "version_frozen.py"


def _verify(
    output: Path,
    expected: bytes,
    expected_timestamp: int,
    *,
    require_timestamp: bool,
) -> None:
    actual = _regular_file(output, maximum=64 * 1024)
    metadata = output.lstat()
    if actual != expected:
        raise ValueError("frozen SearXNG version metadata does not match the lock")
    if stat.S_IMODE(metadata.st_mode) != 0o644:
        raise ValueError("frozen SearXNG version metadata has an unsafe mode")
    # Source-prep creation uses the upstream commit time for deterministic
    # metadata. The checksum-bound cross-job tar transport deliberately
    # normalizes every member mtime to the Unix epoch, so Stage 2 authenticates
    # the generated content and safe mode without treating transport metadata
    # as trust material.
    if require_timestamp and int(metadata.st_mtime) != expected_timestamp:
        raise ValueError("frozen SearXNG version metadata has an unexpected timestamp")


def _create(output: Path, content: bytes, timestamp: int) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to replace pre-existing frozen version metadata")
    temporary = output.with_name(f".{output.name}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.utime(temporary, (timestamp, timestamp), follow_symlinks=False)
        os.replace(temporary, output)
        directory_fd = os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    args = _arguments()
    expected, timestamp = _metadata(args.lock, args.source)
    output = _output_path(args.source)
    if args.verify_only:
        _verify(output, expected, timestamp, require_timestamp=False)
        print(f"Verified deterministic SearXNG version metadata: {output}")
    else:
        _create(output, expected, timestamp)
        _verify(output, expected, timestamp, require_timestamp=True)
        print(f"Created deterministic SearXNG version metadata: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

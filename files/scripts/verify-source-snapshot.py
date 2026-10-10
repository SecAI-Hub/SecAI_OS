#!/usr/bin/env python3
"""Check the reviewed embedded snapshot before compiling its payload.

The checkout and CI artifact provenance authenticate this manifest; these hashes
detect drift and do not provide a separate signature or attest a dirty checkout.
Go vendor dependencies are verified by the source-preparation workflow.
"""

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath


def verify(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("snapshot root must be a real directory")
    manifest_path = root / "UPSTREAM_SYNC.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("snapshot manifest missing or unsafe")
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema_version") != 1
            or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("base_commit", ""))
            or not isinstance(manifest.get("files"), dict) or not manifest["files"]):
        raise ValueError("invalid source snapshot manifest")
    declared = manifest["files"]
    for relative, digest in declared.items():
        path = PurePosixPath(relative)
        if (path.is_absolute() or ".." in path.parts or str(path) != relative
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("unsafe snapshot entry")
        source = root
        for part in path.parts:
            source /= part
            if source.is_symlink():
                raise ValueError(f"symlink in snapshot: {relative}")
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError(f"snapshot mismatch: {relative}")
    # The existing sample is not consumed by Go or installed. Any new build
    # input, policy or other file requires explicit review in the manifest.
    excluded = {"UPSTREAM_SYNC.json", "examples/sample-requests.json"}
    for source in root.rglob("*"):
        relative = source.relative_to(root).as_posix()
        if relative == "vendor" or relative.startswith("vendor/"):
            continue
        if source.is_symlink():
            raise ValueError(f"symlink in snapshot: {relative}")
        if not source.is_dir() and relative not in declared and relative not in excluded:
            raise ValueError(f"unreviewed snapshot file: {relative}")


if __name__ == "__main__":
    try:
        verify(Path(sys.argv[1]))
    except (ValueError, OSError, KeyError, TypeError, IndexError) as exc:
        sys.exit(f"source snapshot verification failed: {exc}")
    print("reviewed source snapshot verified")

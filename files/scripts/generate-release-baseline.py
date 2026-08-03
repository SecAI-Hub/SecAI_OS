#!/usr/bin/env python3
"""Generate release-bound expected measurements for immutable appliance files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_OUTPUT = Path("/usr/share/secure-ai/integrity/release-baseline.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def candidate_paths() -> list[Path]:
    paths: set[Path] = set()
    recursive_roots = (
        Path("/usr/libexec/secure-ai"),
        Path("/usr/lib/secure-ai/python3.12-venv"),
        Path("/etc/secure-ai"),
    )
    for root in recursive_roots:
        if root.is_dir():
            paths.update(path for path in root.rglob("*"))

    unit_root = Path("/usr/lib/systemd/system")
    if unit_root.is_dir():
        paths.update(unit_root.glob("secure-ai-*"))
        paths.update(unit_root.glob("greenboot-*"))
    user_unit_root = Path("/usr/lib/systemd/user")
    if user_unit_root.is_dir():
        paths.update(user_unit_root.glob("secure-ai-*"))

    paths.update(
        {
            Path("/etc/containers/policy.json"),
            Path("/etc/containers/registries.d/secai-os.yaml"),
            Path("/etc/pki/containers/secai-cosign.pub"),
            Path("/usr/bin/llama-server"),
            Path("/usr/local/bin/gguf-guard"),
            Path("/usr/local/bin/securectl"),
        }
    )
    return sorted(paths, key=lambda path: path.as_posix())


def main() -> int:
    args = parse_args()
    if not SOURCE_COMMIT.fullmatch(args.source_commit):
        raise SystemExit("--source-commit must be an immutable 40-character SHA")

    measurements: list[dict[str, object]] = []
    for path in candidate_paths():
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(path_stat.st_mode):
            raise SystemExit(f"refusing symlink in release baseline scope: {path}")
        if not stat.S_ISREG(path_stat.st_mode):
            continue
        content = path.read_bytes()
        measurements.append(
            {
                "path": path.as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )

    if not measurements:
        raise SystemExit("release baseline scope did not contain any files")

    document = {
        "version": 1,
        "source_commit": args.source_commit,
        "files": measurements,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o644)
    os.replace(temporary, args.output)
    print(f"Wrote {args.output} with {len(measurements)} expected measurements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

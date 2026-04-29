#!/usr/bin/env bash
# Verify Containerfile/Dockerfile FROM refs and sandbox compose image refs are
# digest-pinned, including sandbox-only build files.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WAIVERS_FILE="${REPO_ROOT}/.github/container-pin-waivers.json"

python3 - "$REPO_ROOT" "$WAIVERS_FILE" <<'PY'
import datetime as dt
import json
import pathlib
import re
import sys

repo = pathlib.Path(sys.argv[1])
waivers_path = pathlib.Path(sys.argv[2])
today = dt.date.today().isoformat()

waivers: list[dict[str, str]] = []
if waivers_path.exists():
    data = json.loads(waivers_path.read_text(encoding="utf-8"))
    waivers = data.get("dynamic_from", [])


def rel(path: pathlib.Path) -> str:
    return path.relative_to(repo).as_posix()


def has_active_waiver(path: pathlib.Path, image_ref: str) -> bool:
    relative = rel(path)
    for waiver in waivers:
        if waiver.get("path") != relative:
            continue
        if waiver.get("image_ref") != image_ref:
            continue
        expires = waiver.get("expires", "")
        if expires < today:
            print(
                f"ERROR: expired dynamic image waiver for {relative}: {image_ref} "
                f"(expired {expires})"
            )
            return False
        print(
            f"WAIVED: {relative}: dynamic image {image_ref} "
            f"(expires {expires})"
        )
        return True
    return False


def from_files() -> list[pathlib.Path]:
    roots = [repo / "services", repo / "deploy"]
    files: list[pathlib.Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name
            if (
                name == "Containerfile"
                or name.startswith("Containerfile.")
                or name == "Dockerfile"
                or name.startswith("Dockerfile.")
            ):
                files.append(path)
    return sorted(files)


def compose_files() -> list[pathlib.Path]:
    roots = [repo / "deploy"]
    files: list[pathlib.Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(root.rglob("*.yaml"))
        files.extend(root.rglob("*.yml"))
    return sorted(set(files))


def helper_script_files() -> list[pathlib.Path]:
    roots = [repo / "scripts", repo / ".github" / "scripts", repo / "files" / "scripts"]
    files: list[pathlib.Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".sh", ".bash", ".ps1"}:
                files.append(path)
    return sorted(files)


errors = 0
checked = 0

from_re = re.compile(r"^\s*FROM\s+([^\s]+)")
for path in from_files():
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = from_re.match(line)
        if not match:
            continue
        image_ref = match.group(1)
        if image_ref == "scratch":
            continue
        checked += 1
        if "$" in image_ref:
            if not has_active_waiver(path, image_ref):
                print(f"ERROR: {rel(path)}:{line_no}: dynamic unpinned FROM {image_ref}")
                errors += 1
            continue
        if "@sha256:" not in image_ref:
            print(f"ERROR: {rel(path)}:{line_no}: unpinned FROM {image_ref}")
            errors += 1

image_re = re.compile(r"^\s*image:\s+([^\s#]+)")
for path in compose_files():
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = image_re.match(line)
        if not match:
            continue
        image_ref = match.group(1).strip('"\'')
        checked += 1
        if image_ref.startswith(("secai-", "${")):
            continue
        if "$" in image_ref:
            print(f"ERROR: {rel(path)}:{line_no}: dynamic unpinned compose image {image_ref}")
            errors += 1
            continue
        if "@sha256:" not in image_ref:
            print(f"ERROR: {rel(path)}:{line_no}: unpinned compose image {image_ref}")
            errors += 1

script_image_re = re.compile(
    r"(?P<ref>(?:docker\.io|quay\.io|ghcr\.io)/(?!secai-hub/secai_os\b)"
    r"[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+(?:@[A-Za-z0-9:]+)?)"
)
for path in helper_script_files():
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in script_image_re.finditer(line):
            image_ref = match.group("ref").strip('"\'')
            checked += 1
            if "@sha256:" not in image_ref:
                print(f"ERROR: {rel(path)}:{line_no}: unpinned helper image {image_ref}")
                errors += 1

if errors:
    print(f"FAIL: {errors} unpinned container image reference(s) found")
    sys.exit(1)

print(f"OK: {checked} container image reference(s) are digest-pinned or explicitly waived")
PY

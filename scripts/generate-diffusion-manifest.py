#!/usr/bin/env python3
"""Build the diffusion wheel manifest from uv's platform-specific pylocks."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

BACKENDS = ("cpu", "cuda", "rocm")
PYTORCH_INDEXES = {
    "cpu": "https://download.pytorch.org/whl/cpu",
    "cuda": "https://download.pytorch.org/whl/cu129",
    "rocm": "https://download.pytorch.org/whl/rocm7.1",
}
ALLOWED_WHEEL_HOSTS = {
    "files.pythonhosted.org",
    "download.pytorch.org",
    "download-r2.pytorch.org",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LOCK_PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.-]+)==\S+\s*\\$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock_hashes(path: Path) -> dict[str, set[str]]:
    hashes: dict[str, set[str]] = {}
    current = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        package_match = LOCK_PACKAGE_RE.match(line)
        if package_match:
            current = canonical_name(package_match.group(1))
            hashes.setdefault(current, set())
            continue
        if not current:
            continue
        for digest in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
            hashes[current].add(digest)
    return hashes


def wheel_hash(wheel: dict[str, Any], lock_hashes: set[str]) -> str:
    recorded = wheel.get("hashes", {}).get("sha256", "")
    if recorded:
        if not SHA256_RE.fullmatch(recorded):
            raise ValueError(f"invalid wheel SHA256: {recorded!r}")
        if recorded not in lock_hashes:
            raise ValueError(f"selected wheel hash is absent from requirements lock: {recorded}")
        return recorded

    # PyTorch's index occasionally publishes a single platform wheel without
    # exposing its hash in PEP 751 metadata. uv still calculates and records
    # that artifact hash in the requirements lock; use it when unambiguous.
    if len(lock_hashes) == 1:
        return next(iter(lock_hashes))

    # A small number of PyTorch index entries omit the artifact hash. Fetch
    # only those selected wheels and calculate the trust anchor ourselves.
    url = wheel["url"]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_WHEEL_HOSTS:
        raise ValueError(f"refusing untrusted wheel URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "SecAI-OS-lock-generator/1"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=900) as response:
        final = urllib.parse.urlparse(response.url)
        if final.scheme != "https" or final.hostname not in ALLOWED_WHEEL_HOSTS:
            raise ValueError(f"refusing untrusted wheel redirect: {response.url}")
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_wheel(package: dict[str, Any]) -> dict[str, Any]:
    wheels = package.get("wheels", [])
    if not wheels:
        raise ValueError(
            f"{package.get('name', '<unknown>')}=={package.get('version', '<unknown>')} "
            "has no compatible wheel"
        )
    # uv's platform-specific pylock lists the preferred CPython/platform wheel
    # first and a pure-Python fallback second when both are compatible.
    wheel = wheels[0]
    filename = Path(urllib.parse.unquote(urllib.parse.urlparse(wheel["url"]).path)).name
    if not filename.endswith(".whl"):
        raise ValueError(f"non-wheel artifact selected: {filename}")
    return wheel


def manifest_entry(
    backend: str,
    package: dict[str, Any],
    hashes_by_package: dict[str, set[str]],
) -> dict[str, str]:
    wheel = select_wheel(package)
    parsed = urllib.parse.urlparse(wheel["url"])
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_WHEEL_HOSTS:
        raise ValueError(f"refusing untrusted wheel URL: {wheel['url']}")
    filename = Path(urllib.parse.unquote(parsed.path)).name
    source = (
        f"{PYTORCH_INDEXES[backend]}/*"
        if parsed.hostname in {"download.pytorch.org", "download-r2.pytorch.org"}
        else "https://files.pythonhosted.org/packages/*"
    )
    package_name = canonical_name(str(package.get("name", "")))
    package_hashes = hashes_by_package.get(package_name, set())
    if not package_hashes:
        raise ValueError(f"{package_name} has no hashes in the requirements lock")
    return {
        "filename": filename,
        "sha256": wheel_hash(wheel, package_hashes),
        "source": source,
    }


def build_manifest(
    template_path: Path,
    lock_dir: Path,
    pylock_dir: Path,
) -> dict[str, Any]:
    manifest = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = max(int(manifest.get("schema_version", 1)) + 1, 2)
    manifest["description"] = (
        "Diffusion runtime trust anchor — CPython 3.12 Linux/x86_64 "
        "backend locks and exact wheel hashes"
    )
    manifest["populated"] = True
    manifest["python_version"] = "3.12"
    manifest["supported_architectures"] = ["x86_64"]
    manifest["allowed_sources"] = [
        "https://download.pytorch.org/whl/*",
        "https://files.pythonhosted.org/packages/*",
    ]
    manifest["format_policy"] = "wheel_only"

    backend_cfg = manifest.setdefault("backends", {})
    for backend in BACKENDS:
        lock_path = lock_dir / f"diffusion-{backend}.lock"
        input_path = template_path.parent / f"diffusion-{backend}.in"
        pylock_path = pylock_dir / f"pylock.{backend}.toml"
        pylock = tomllib.loads(pylock_path.read_text(encoding="utf-8"))
        packages = pylock.get("packages", [])
        if not packages:
            raise ValueError(f"{backend} pylock has no packages")

        hashes_by_package = parse_lock_hashes(lock_path)
        entries = [
            manifest_entry(backend, package, hashes_by_package)
            for package in packages
        ]
        filenames = [entry["filename"] for entry in entries]
        if len(filenames) != len(set(filenames)):
            raise ValueError(f"{backend} manifest contains duplicate wheel filenames")

        cfg = backend_cfg.setdefault(backend, {})
        cfg["lockfile"] = lock_path.name
        cfg["lock_sha256"] = sha256_file(lock_path)
        cfg["inputfile"] = input_path.name
        cfg["input_sha256"] = sha256_file(input_path)
        cfg["torch_index"] = PYTORCH_INDEXES[backend]
        cfg["estimated_size_mb"] = max(int(cfg.get("estimated_size_mb", 1)), 1)
        cfg["wheels"] = entries

    manifest["backends"] = {backend: backend_cfg[backend] for backend in BACKENDS}
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--lock-dir", required=True, type=Path)
    parser.add_argument("--pylock-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    manifest = build_manifest(args.template, args.lock_dir, args.pylock_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{args.output.name}.",
        dir=args.output.parent,
        text=True,
    )
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(manifest, stream, sort_keys=False, width=120)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())

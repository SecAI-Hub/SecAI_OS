#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from Python manifests and source.

Syft does not currently identify dependencies in several SecAI Python source
directories, which previously produced release SBOMs with zero components.
This helper records exact requirements plus hashed source files without
installing or importing the service under inspection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
import uuid
from pathlib import Path
from urllib.parse import quote

REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?==([^;\s\\]+)"
)
SOURCE_SUFFIXES = {
    ".json",
    ".lock",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
    ".yar",
}


def canonical_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_components(paths: list[Path]) -> list[dict[str, object]]:
    versions: dict[str, str] = {}
    display_names: dict[str, str] = {}

    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = REQUIREMENT.match(line)
            if not match:
                continue
            display_name, version = match.groups()
            canonical = canonical_package_name(display_name)
            previous = versions.get(canonical)
            if previous is not None and previous != version:
                raise ValueError(
                    f"conflicting versions for {canonical}: {previous} and {version}"
                )
            versions[canonical] = version
            display_names[canonical] = display_name

    components: list[dict[str, object]] = []
    for canonical in sorted(versions):
        version = versions[canonical]
        purl = f"pkg:pypi/{quote(canonical)}@{quote(version)}"
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": display_names[canonical],
                "version": version,
                "purl": purl,
                "properties": [
                    {"name": "secai:dependencySource", "value": "requirements"}
                ],
            }
        )
    return components


def source_components(service_dir: Path, repo_root: Path) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    for path in sorted(service_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name.startswith("Dockerfile"):
            pass
        elif path.suffix.lower() not in SOURCE_SUFFIXES:
            continue

        relative = path.relative_to(repo_root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        components.append(
            {
                "type": "file",
                "bom-ref": f"urn:secai:file:sha256:{digest}",
                "name": relative,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [{"name": "secai:sourcePath", "value": relative}],
            }
        )
    return components


def project_metadata(
    service_dir: Path, explicit_name: str | None, explicit_version: str | None
) -> tuple[str, str]:
    name = explicit_name
    version = explicit_version
    pyproject = service_dir / "pyproject.toml"
    if pyproject.is_file():
        project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
        name = name or project.get("name")
        version = version or project.get("version")
    return name or service_dir.name, version or "0.0.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-dir", required=True, type=Path)
    parser.add_argument("--requirements", action="append", default=[], type=Path)
    parser.add_argument("--name")
    parser.add_argument("--version")
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument(
        "--dependency-completeness",
        choices=("locked", "direct-locked", "none-required"),
        default="locked",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    service_dir = args.service_dir.resolve()
    if not service_dir.is_dir():
        raise SystemExit(f"service directory not found: {args.service_dir}")

    requirement_paths = [path.resolve() for path in args.requirements]
    missing = [str(path) for path in requirement_paths if not path.is_file()]
    if missing:
        raise SystemExit(f"requirements file not found: {', '.join(missing)}")

    name, version = project_metadata(service_dir, args.name, args.version)
    application_ref = f"pkg:generic/{quote(name)}@{quote(version)}"
    dependencies = requirement_components(requirement_paths)
    sources = source_components(service_dir, repo_root)
    if args.dependency_completeness != "none-required" and not dependencies:
        raise SystemExit(
            f"refusing to emit a dependency SBOM with zero dependencies for {name}"
        )
    if args.dependency_completeness == "none-required" and dependencies:
        raise SystemExit(
            f"{name} declares dependencies but was marked as having none required"
        )
    components = dependencies + sources
    if not components:
        raise SystemExit(f"refusing to emit an empty SBOM for {name}")

    serial_seed = f"{name}\0{version}\0{args.source_commit}"
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": application_ref,
                "name": name,
                "version": version,
                "properties": [
                    {"name": "secai:sourceCommit", "value": args.source_commit},
                    {
                        "name": "secai:sourcePath",
                        "value": service_dir.relative_to(repo_root).as_posix(),
                    },
                    {
                        "name": "secai:dependencyComponentCount",
                        "value": str(len(dependencies)),
                    },
                    {
                        "name": "secai:sourceFileComponentCount",
                        "value": str(len(sources)),
                    },
                    {
                        "name": "secai:dependencyCompleteness",
                        "value": args.dependency_completeness,
                    },
                    *[
                        {
                            "name": "secai:requirementsManifest",
                            "value": json.dumps(
                                {
                                    "path": path.relative_to(repo_root).as_posix(),
                                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        }
                        for path in requirement_paths
                    ],
                ],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "secai-python-sbom-generator",
                        "version": "1",
                    }
                ]
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": application_ref,
                "dependsOn": [
                    component["bom-ref"]
                    for component in dependencies
                    if "bom-ref" in component
                ],
            }
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"Wrote {args.output}: {len(dependencies)} dependencies, "
        f"{len(sources)} source files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

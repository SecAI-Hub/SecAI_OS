#!/usr/bin/env python3
"""Audit every committed Python dependency set with pip-audit.

This is intentionally stricter than the old CI snippet: an audit command
failure without parseable vulnerability output is a CI failure, not a quiet
"no findings" result.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

REQUIREMENT_FILES = [
    Path("requirements-ci.lock"),
    Path(".github/requirements-windows-sandbox.lock"),
    Path("services/agent/requirements.lock"),
    Path("services/search-mediator/requirements.lock"),
    Path("services/ui/requirements.lock"),
    Path("services/quarantine/requirements.lock"),
    Path("vendor/application-requirements.lock"),
]

NO_DEPS_REQUIREMENT_FILES = [
    # Backend-local PyTorch/torchvision artifacts use PEP 440 local versions.
    # The temporary audit copy canonicalizes those versions to their PyPI base
    # releases so advisory findings remain visible. Real artifact locks and
    # their hashes are never changed.
    (
        Path("files/scripts/diffusion-cuda.lock"),
        frozenset({"torch", "torchvision"}),
    ),
    (
        Path("files/scripts/diffusion-rocm.lock"),
        frozenset({"torch", "torchvision", "triton-rocm"}),
    ),
    (
        Path("files/scripts/diffusion-cpu.lock"),
        frozenset({"torch", "torchvision"}),
    ),
    (
        Path("files/scripts/diffusion-cuda-py314.lock"),
        frozenset({"torch", "torchvision"}),
    ),
    (
        Path("files/scripts/diffusion-rocm-py314.lock"),
        frozenset({"torch", "torchvision", "triton-rocm"}),
    ),
    (
        Path("files/scripts/diffusion-cpu-py314.lock"),
        frozenset({"torch", "torchvision"}),
    ),
]

# ROCm publishes its backend-specific Triton build as ``triton-rocm`` outside
# PyPI. Audit the corresponding upstream ``triton`` release as a conservative
# advisory proxy while retaining the exact backend artifact and hash in the
# committed lock.
CANONICAL_ADVISORY_NAMES = {
    "triton-rocm": "triton",
}

WAIVERS_FILE = Path(".github/vuln-waivers.json")


def pip_audit_cmd() -> list[str]:
    exe = shutil.which("pip-audit")
    if exe:
        return [exe]
    return [sys.executable, "-m", "pip_audit"]


def load_waivers() -> set[str]:
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    data = json.loads(WAIVERS_FILE.read_text(encoding="utf-8"))
    return {
        item["id"]
        for item in data.get("python", [])
        if item.get("expires", "") >= today
    }


def target_environment(req: Path) -> dict[str, str]:
    """Select the lock generator's target, never the auditor host's markers."""
    python = "3.14.8" if req.name.endswith("-py314.lock") else "3.12.15"
    windows = req.name == "requirements-windows-sandbox.lock"
    return {
        "implementation_name": "cpython", "implementation_version": python,
        "os_name": "nt" if windows else "posix",
        "platform_machine": "AMD64" if windows else "x86_64",
        "platform_python_implementation": "CPython",
        "platform_system": "Windows" if windows else "Linux",
        "python_full_version": python, "python_version": python.rsplit(".", 1)[0],
        "sys_platform": "win32" if windows else "linux",
    }


def expected_requirements(
    req: Path, local_packages: frozenset[str] = frozenset(),
    *, environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Validate pinned artifact entries and select their exact advisory pairs.

    Artifact hashes remain in the real lock. The temporary advisory input has
    no resolver options, hashes, markers, URLs or dependency installation.
    """
    environment = target_environment(req) if environment is None else environment
    text = req.read_text(encoding="utf-8")
    text = re.sub(r"\\\r?\n", " ", text)
    selected: dict[str, str] = {}
    seen_local: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # These artifact retrieval options are never forwarded to pip-audit.
        if re.fullmatch(r"--(?:index-url|find-links) https://[^\s]+", line):
            continue
        hashes = re.findall(r"\s+--hash=sha256:([0-9a-f]{64})(?=\s|$)", line)
        if not hashes:
            raise ValueError(f"{req}: requirement has no valid SHA256 artifact hash")
        requirement_text = re.sub(r"\s+--hash=sha256:[0-9a-f]{64}(?=\s|$)", "", line).strip()
        requirement = Requirement(requirement_text)
        specifiers = list(requirement.specifier)
        if (requirement.url or requirement.extras or len(specifiers) != 1
                or specifiers[0].operator != "==" or "*" in specifiers[0].version):
            raise ValueError(f"{req}: dependency must be one exact version without extras or URL")
        name = str(canonicalize_name(requirement.name))
        version = Version(specifiers[0].version)
        if name in local_packages:
            seen_local.add(name)
        elif version.local is not None:
            raise ValueError(f"{req}: local version has no reviewed advisory mapping: {name}")
        if requirement.marker:
            # Release/kernel and optional-extra markers lack a fixed target in
            # this gate. Refuse to borrow a value from the auditing machine.
            expression = re.sub(r'"[^"\n]*"', '', str(requirement.marker))
            if re.search(r"\b(platform_release|platform_version|extra|extras|dependency_groups)\b", expression):
                raise ValueError(f"{req}: marker needs an explicit unsupported target value")
            if not requirement.marker.evaluate(environment=environment):
                continue
        if name in local_packages:
            name = CANONICAL_ADVISORY_NAMES.get(name, name)
            version = Version(version.public)
        if name in selected:
            raise ValueError(f"{req}: duplicate selected advisory package: {name}")
        selected[name] = str(version)
    if local_packages - seen_local:
        raise ValueError(f"{req}: expected local package blocks missing: {sorted(local_packages - seen_local)}")
    if not selected:
        raise ValueError(f"{req}: no dependencies selected for target environment")
    return selected


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant: {value}")


def run_audit(expected: dict[str, str]) -> tuple[int, Any | None, str]:
    # A new private input prevents pip/requirements evaluation from omitting
    # already installed build tools, resolving new dependencies or fetching URLs.
    with tempfile.TemporaryDirectory(prefix="secai-advisories-") as directory:
        req = Path(directory) / "selected.txt"
        req.write_text("".join(f"{name}=={version}\n" for name, version in sorted(expected.items())))
        try:
            proc = subprocess.run(
                [*pip_audit_cmd(), "--strict", "--desc", "--no-deps", "--disable-pip",
                 "--progress-spinner", "off", "-r", str(req), "-f", "json"],
                check=False, capture_output=True, text=True, timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 2, None, f"audit tool failed: {exc}"
    try:
        data = json.loads(proc.stdout, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, TypeError):
        data = None
    return proc.returncode, data, proc.stderr.strip()


def validate_coverage(data: Any, expected: dict[str, str], code: int) -> list[tuple[str, str, str]]:
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise ValueError("audit JSON must contain a dependencies array")  # noqa: TRY004
    seen: dict[str, str] = {}
    findings: list[tuple[str, str, str]] = []
    for dep in data["dependencies"]:
        if (not isinstance(dep, dict) or not isinstance(dep.get("name"), str)
                or not dep["name"] or not isinstance(dep.get("version"), str)
                or not dep["version"] or "skip_reason" in dep
                or not isinstance(dep.get("vulns"), list)):
            raise ValueError("malformed or skipped audit dependency")
        name = str(canonicalize_name(dep["name"], validate=True))
        version = str(Version(dep["version"]))
        if name in seen:
            raise ValueError(f"duplicate audit dependency: {name}")
        seen[name] = version
        ids: set[str] = set()
        for vuln in dep["vulns"]:
            if (not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str)
                    or not vuln["id"].strip() or not isinstance(vuln.get("description", ""), str)
                    or vuln["id"] in ids):
                raise ValueError("malformed or duplicate vulnerability record")
            ids.add(vuln["id"])
            findings.append((name, vuln["id"], vuln.get("description", "")))
    if seen != expected:
        missing = sorted(set(expected) - set(seen))
        unexpected = sorted(set(seen) - set(expected))
        wrong = sorted(name for name in seen.keys() & expected.keys() if seen[name] != expected[name])
        raise ValueError(f"audit coverage mismatch: missing={missing}, unexpected={unexpected}, wrong_version={wrong}")
    if code != (1 if findings else 0):
        raise ValueError(f"audit exit code {code} is inconsistent with {len(findings)} finding(s)")
    return findings


def audit_one(req: Path, waivers: set[str], *, local_packages: frozenset[str] = frozenset()) -> int:
    stderr = ""
    try:
        expected = expected_requirements(req, local_packages)
        code, data, stderr = run_audit(expected)
        findings = validate_coverage(data, expected, code)
    except (ValueError, OSError) as exc:
        print(f"::error::{req}: {exc}")
        if stderr:
            print(stderr)
        return 1
    errors = 0
    for package, vuln_id, description in findings:
        if vuln_id in waivers:
            print(f"WAIVED: {req}: {package} {vuln_id}")
        else:
            print(f"::error::{req}: {package}: {vuln_id} - {description}")
            errors += 1
    if not errors:
        print(f"OK: {req}: coverage {len(expected)}/{len(expected)}, "
              f"{len(findings)} finding(s), all waived" if findings else
              f"OK: {req}: coverage {len(expected)}/{len(expected)}, no vulnerabilities")
    return errors


def main() -> int:
    waivers = load_waivers()
    errors = 0

    for req in REQUIREMENT_FILES:
        print(f"=== pip-audit {req} ===")
        if not req.exists():
            print(f"::error::{req} is missing")
            errors += 1
            continue

        errors += audit_one(req, waivers)

    for req, local_packages in NO_DEPS_REQUIREMENT_FILES:
        print(f"=== pip-audit {req} (no-deps) ===")
        if not req.exists():
            print(f"::error::{req} is missing")
            errors += 1
            continue
        errors += audit_one(req, waivers, local_packages=local_packages)

    if errors:
        print(f"FAIL: {errors} Python dependency audit error(s)")
        return 1
    print("PASS: all Python dependency audits passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

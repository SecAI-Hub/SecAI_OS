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


REQUIREMENT_FILES = [
    Path("requirements-ci.lock"),
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
    today = dt.date.today().isoformat()
    data = json.loads(WAIVERS_FILE.read_text(encoding="utf-8"))
    return {
        item["id"]
        for item in data.get("python", [])
        if item.get("expires", "") >= today
    }


def extract_findings(data: Any) -> list[tuple[str, str, str]]:
    deps = data if isinstance(data, list) else data.get("dependencies", [])
    findings: list[tuple[str, str, str]] = []
    for dep in deps:
        for vuln in dep.get("vulns", []):
            findings.append(
                (
                    dep.get("name", "unknown"),
                    vuln.get("id", "unknown"),
                    vuln.get("description", ""),
                )
            )
    return findings


def split_local_advisory_requirements(
    req: Path,
    package_names: frozenset[str],
) -> tuple[Path, Path]:
    """Build hash-complete and canonical-advisory temporary inputs.

    ``pip-audit`` cannot query advisories for versions such as
    ``2.13.0+cu129`` because those artifacts are not published on PyPI. It also
    enables hash mode for the whole file when any requirement has a hash, so a
    canonical unhashed line cannot coexist with the remaining hashed lock.

    Return one hash-complete copy for all ordinary packages and one small,
    unhashed advisory-only copy containing canonical base releases. Both are
    audited, so backend-local packages cannot silently disappear from coverage.
    """
    if not package_names:
        return req, req

    package_re = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")
    remaining = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        prefix=f"{req.stem}-audit-",
        suffix=".txt",
    )
    advisory = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        prefix=f"{req.stem}-local-advisory-",
        suffix=".txt",
    )
    canonicalized: set[str] = set()
    selected = False
    with remaining, advisory:
        advisory.write("--index-url https://pypi.org/simple\n")
        for line in req.read_text(encoding="utf-8").splitlines():
            if line.startswith("--find-links https://download.pytorch.org/"):
                continue
            match = package_re.match(line)
            if match:
                name = match.group(1).lower().replace("_", "-")
                selected = name in package_names
                if selected:
                    version = match.group(2).split("+", 1)[0]
                    advisory_name = CANONICAL_ADVISORY_NAMES.get(name, name)
                    advisory.write(f"{advisory_name}=={version}\n")
                    canonicalized.add(name)
                    continue
            if selected:
                continue
            remaining.write(line + "\n")
    missing = package_names - canonicalized
    if missing:
        Path(remaining.name).unlink(missing_ok=True)
        Path(advisory.name).unlink(missing_ok=True)
        raise ValueError(
            f"{req}: expected local package block(s) missing: "
            + ", ".join(sorted(missing))
        )
    return Path(remaining.name), Path(advisory.name)


def run_audit(req: Path, *, no_deps: bool = False) -> tuple[int, Any | None, str]:
    extra_args = ["--no-deps", "--disable-pip"] if no_deps else []
    proc = subprocess.run(
        [
            *pip_audit_cmd(),
            "--strict",
            "--desc",
            *extra_args,
            "-r",
            str(req),
            "-f",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        data = None
    stderr = proc.stderr.strip()
    return proc.returncode, data, stderr


def audit_one(
    req: Path,
    waivers: set[str],
    *,
    no_deps: bool = False,
    label: str | Path | None = None,
) -> int:
    display = label or req
    code, data, stderr = run_audit(req, no_deps=no_deps)
    if data is None:
        print(f"::error::{display}: pip-audit produced no parseable JSON")
        if stderr:
            print(stderr)
        return 1

    errors = 0
    findings = extract_findings(data)
    for package, vuln_id, description in findings:
        if vuln_id in waivers:
            print(f"WAIVED: {display}: {package} {vuln_id}")
        else:
            print(f"::error::{display}: {package}: {vuln_id} - {description}")
            errors += 1

    if errors:
        return errors
    if findings:
        print(f"OK: all findings waived for {display}")
    else:
        print(f"OK: no vulnerabilities in {display}")

    if code not in (0, 1):
        print(f"::error::{display}: pip-audit failed with exit code {code}")
        if stderr:
            print(stderr)
        return 1
    return 0


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
        audit_path, advisory_path = split_local_advisory_requirements(
            req,
            local_packages,
        )
        if local_packages:
            canonicalized = ", ".join(sorted(local_packages))
            print(
                f"NOTE: {req}: separately auditing canonical local "
                f"version(s): {canonicalized}"
            )
        try:
            errors += audit_one(audit_path, waivers, no_deps=True, label=req)
            if advisory_path != req:
                errors += audit_one(
                    advisory_path,
                    waivers,
                    no_deps=True,
                    label=f"{req} (canonical local-version advisories)",
                )
        finally:
            if audit_path != req:
                audit_path.unlink(missing_ok=True)
            if advisory_path != req:
                advisory_path.unlink(missing_ok=True)

    if errors:
        print(f"FAIL: {errors} Python dependency audit error(s)")
        return 1
    print("PASS: all Python dependency audits passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

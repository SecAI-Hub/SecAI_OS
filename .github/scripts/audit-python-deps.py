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
    Path("requirements-ci.txt"),
    Path("services/agent/requirements.txt"),
    Path("services/search-mediator/requirements.txt"),
    Path("services/ui/requirements.lock"),
    Path("services/quarantine/requirements.lock"),
]

NO_DEPS_REQUIREMENT_FILES = [
    (Path("files/scripts/diffusion-cuda.lock"), frozenset()),
    (Path("files/scripts/diffusion-rocm.lock"), frozenset()),
    (Path("files/scripts/diffusion-cpu.lock"), frozenset({"torch"})),
]

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


def strip_requirement_blocks(req: Path, package_names: frozenset[str]) -> Path:
    """Return an auditable copy with selected pip-compile package blocks removed."""
    if not package_names:
        return req

    package_re = re.compile(r"^([A-Za-z0-9_.-]+)==")
    output = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        prefix=f"{req.stem}-audit-",
        suffix=".txt",
    )
    skip = False
    with output:
        for line in req.read_text(encoding="utf-8").splitlines():
            match = package_re.match(line)
            if match:
                name = match.group(1).lower().replace("_", "-")
                skip = name in package_names
            if not skip:
                output.write(line + "\n")
    return Path(output.name)


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
    label: Path | None = None,
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

    for req, skipped_packages in NO_DEPS_REQUIREMENT_FILES:
        print(f"=== pip-audit {req} (no-deps) ===")
        if not req.exists():
            print(f"::error::{req} is missing")
            errors += 1
            continue
        audit_path = strip_requirement_blocks(req, skipped_packages)
        if skipped_packages:
            skipped = ", ".join(sorted(skipped_packages))
            print(f"NOTE: {req}: skipped non-PyPI local-version package(s): {skipped}")
        try:
            errors += audit_one(audit_path, waivers, no_deps=True, label=req)
        finally:
            if audit_path != req:
                audit_path.unlink(missing_ok=True)

    if errors:
        print(f"FAIL: {errors} Python dependency audit error(s)")
        return 1
    print("PASS: all Python dependency audits passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Audit every committed Python dependency set with pip-audit.

This is intentionally stricter than the old CI snippet: an audit command
failure without parseable vulnerability output is a CI failure, not a quiet
"no findings" result.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REQUIREMENT_FILES = [
    Path("requirements-ci.txt"),
    Path("services/agent/requirements.txt"),
    Path("services/search-mediator/requirements.txt"),
    Path("services/ui/requirements.lock"),
    Path("services/quarantine/requirements.lock"),
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


def run_audit(req: Path) -> tuple[int, Any | None, str]:
    proc = subprocess.run(
        [
            *pip_audit_cmd(),
            "--strict",
            "--desc",
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


def main() -> int:
    waivers = load_waivers()
    errors = 0

    for req in REQUIREMENT_FILES:
        print(f"=== pip-audit {req} ===")
        if not req.exists():
            print(f"::error::{req} is missing")
            errors += 1
            continue

        code, data, stderr = run_audit(req)
        if data is None:
            print(f"::error::{req}: pip-audit produced no parseable JSON")
            if stderr:
                print(stderr)
            errors += 1
            continue

        findings = extract_findings(data)
        unwaived = 0
        for package, vuln_id, description in findings:
            if vuln_id in waivers:
                print(f"WAIVED: {req}: {package} {vuln_id}")
            else:
                print(f"::error::{req}: {package}: {vuln_id} - {description}")
                unwaived += 1

        if unwaived:
            errors += unwaived
        elif findings:
            print(f"OK: all findings waived for {req}")
        else:
            print(f"OK: no vulnerabilities in {req}")

        if code not in (0, 1):
            print(f"::error::{req}: pip-audit failed with exit code {code}")
            if stderr:
                print(stderr)
            errors += 1

    if errors:
        print(f"FAIL: {errors} Python dependency audit error(s)")
        return 1
    print("PASS: all Python dependency audits passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

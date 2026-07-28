#!/usr/bin/env python3
"""Collect a redacted, machine-readable SecAI OS qualification report.

The report is evidence input, not an automatic certification.  It deliberately
omits hostnames, usernames, network addresses, disk serials, TPM unique values,
and device UUIDs.  Run it on the Fedora appliance under test and attach the
result to the release-specific readiness evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = "1.0"
ALLOWED_OS_RELEASE_KEYS = {
    "ID",
    "VERSION_ID",
    "VARIANT_ID",
    "IMAGE_ID",
    "IMAGE_VERSION",
}
SENSITIVE_FIELD = re.compile(
    r"(hostname|username|serial|uuid|machine.?id|mac address|ip address)",
    re.IGNORECASE,
)


def run_command(argv: Sequence[str], timeout: int = 15) -> dict[str, Any]:
    """Run a read-only probe and return bounded output without raising."""
    executable = shutil.which(argv[0])
    if executable is None:
        return {"available": False}
    try:
        result = subprocess.run(
            [executable, *argv[1:]],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "error": type(exc).__name__}

    output = result.stdout.strip()
    if len(output) > 256 * 1024:
        output = output[: 256 * 1024]
    return {
        "available": True,
        "exit_code": result.returncode,
        "stdout": output,
    }


def parse_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        if key in ALLOWED_OS_RELEASE_KEYS:
            result[key] = value.strip().strip('"')
    return result


def redact_mapping(value: Any) -> Any:
    """Recursively remove keys that can identify a specific machine or user."""
    if isinstance(value, dict):
        return {
            key: redact_mapping(item)
            for key, item in value.items()
            if not SENSITIVE_FIELD.search(str(key))
        }
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    return value


def parse_json_probe(probe: dict[str, Any]) -> Any:
    if probe.get("exit_code") != 0 or not probe.get("stdout"):
        return probe
    try:
        return redact_mapping(json.loads(probe["stdout"]))
    except json.JSONDecodeError:
        return probe


def rpm_ostree_evidence() -> dict[str, Any]:
    probe = run_command(("rpm-ostree", "status", "--json"), timeout=30)
    if probe.get("exit_code") != 0 or not probe.get("stdout"):
        return probe
    try:
        raw = json.loads(probe["stdout"])
    except json.JSONDecodeError:
        return {"available": True, "error": "invalid_json"}

    deployments = []
    for deployment in raw.get("deployments", []):
        if not deployment.get("booted"):
            continue
        deployments.append(
            {
                "booted": True,
                "checksum": deployment.get("checksum"),
                "version": deployment.get("version"),
                "origin": deployment.get("origin"),
                "container_image_reference": deployment.get(
                    "container-image-reference"
                ),
            }
        )
    return {"available": True, "booted_deployments": deployments}


def tpm_evidence() -> dict[str, Any]:
    device_present = Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists()
    probe = run_command(("tpm2_getcap", "properties-fixed"))
    allowed_lines = []
    for line in str(probe.get("stdout", "")).splitlines():
        if any(
            name in line
            for name in (
                "TPM2_PT_MANUFACTURER",
                "TPM2_PT_VENDOR_STRING",
                "TPM2_PT_FIRMWARE_VERSION",
            )
        ):
            allowed_lines.append(line.strip())
    return {
        "device_present": device_present,
        "tool_available": probe.get("available", False),
        "probe_exit_code": probe.get("exit_code"),
        "properties": allowed_lines,
    }


def gpu_evidence() -> dict[str, Any]:
    return {
        "pci": run_command(("lspci", "-nnk")),
        "nvidia": run_command(
            (
                "nvidia-smi",
                "--query-gpu=name,driver_version,vbios_version,memory.total",
                "--format=csv,noheader",
            )
        ),
        "rocm": run_command(("rocminfo",)),
        "vulkan": run_command(("vulkaninfo", "--summary")),
    }


def collect() -> dict[str, Any]:
    disk = shutil.disk_usage("/")
    report = {
        "schema_version": SCHEMA_VERSION,
        "collected_at": datetime.now(UTC).isoformat(),
        "assurance": {
            "certified": False,
            "classification": "evidence-only",
            "notice": (
                "Presence checks do not prove Secure Boot, TPM quote validity, "
                "driver integrity, workload stability, or production support."
            ),
        },
        "platform": {
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
            "os_release": parse_os_release(),
        },
        "resources": {
            "disk_root_bytes_total": disk.total,
            "disk_root_bytes_free": disk.free,
            "memory": run_command(("free", "--bytes")),
            "cpu": parse_json_probe(run_command(("lscpu", "--json"))),
        },
        "boot_security": {
            "secure_boot": run_command(("mokutil", "--sb-state")),
            "tpm2": tpm_evidence(),
        },
        "gpu": gpu_evidence(),
        "deployment": rpm_ostree_evidence(),
        "services": run_command(
            (
                "systemctl",
                "--no-pager",
                "--plain",
                "--failed",
                "--output=json",
            )
        ),
    }
    return redact_mapping(report)


def write_atomic(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect redacted SecAI OS hardware qualification evidence"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination JSON file (created mode 0600)",
    )
    args = parser.parse_args()
    write_atomic(args.output, collect())
    print(f"Wrote evidence-only report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

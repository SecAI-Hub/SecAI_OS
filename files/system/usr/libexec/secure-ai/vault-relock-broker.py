#!/usr/bin/env python3
"""Fixed-function root broker for incident-triggered vault relock.

Unprivileged incident-recorder processes can only submit a small JSON request
to a dedicated setgid inbox. The broker accepts no command, device, mountpoint,
or service names from that request; it invokes exactly one audited operation
and writes a root-owned result into a non-writable result directory.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REQUEST_DIR = Path(
    os.getenv("VAULT_RELOCK_REQUEST_DIR", "/run/secure-ai/vault-control/requests")
)
PROCESSING_DIR = Path(
    os.getenv("VAULT_RELOCK_PROCESSING_DIR", "/run/secure-ai/vault-control/processing")
)
RESULT_DIR = Path(
    os.getenv("VAULT_RELOCK_RESULT_DIR", "/run/secure-ai/vault-control/results")
)
WATCHDOG = "/usr/libexec/secure-ai/vault-watchdog.py"
INCIDENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MAX_REQUEST_BYTES = 4096


def _atomic_result(incident_id: str, *, success: bool, error: str = "") -> None:
    payload = {
        "success": success,
        "incident_id": incident_id,
    }
    if error:
        payload["error"] = error[:512]
    data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".result-", dir=RESULT_DIR)
    try:
        os.fchmod(fd, 0o640)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp_name, RESULT_DIR / f"{incident_id}.json")
        dir_fd = os.open(RESULT_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _read_claimed_request(path: Path) -> tuple[str, dict[str, str]]:
    filename_id = path.name.removesuffix(".json")
    if not INCIDENT_RE.fullmatch(filename_id):
        raise ValueError("invalid request filename")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REQUEST_BYTES:
            raise ValueError("request must be a bounded regular file")
        data = os.read(fd, MAX_REQUEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("request must be an object")
    allowed = {"action", "incident_id", "reason"}
    if set(payload) - allowed:
        raise ValueError("request contains unsupported fields")
    incident_id = payload.get("incident_id")
    if (
        payload.get("action") != "relock"
        or not isinstance(incident_id, str)
        or incident_id != filename_id
    ):
        raise ValueError("request action or incident id mismatch")
    return incident_id, payload


def process_request(inbox_path: Path) -> None:
    claimed = PROCESSING_DIR / inbox_path.name
    try:
        os.replace(inbox_path, claimed)
    except FileNotFoundError:
        return

    incident_id = claimed.name.removesuffix(".json")
    try:
        incident_id, _payload = _read_claimed_request(claimed)
        result = subprocess.run(
            [
                sys.executable,
                WATCHDOG,
                "--lock-once",
                "--reason",
                f"incident_containment:{incident_id}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stdout.strip().splitlines()
            error = detail[-1] if detail else "vault watchdog returned failure"
            _atomic_result(incident_id, success=False, error=error)
            return
        _atomic_result(incident_id, success=True)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        if INCIDENT_RE.fullmatch(incident_id):
            _atomic_result(incident_id, success=False, error=str(exc))
    finally:
        try:
            claimed.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    if os.geteuid() != 0:
        print("vault relock broker must run as root", file=sys.stderr)
        return 1
    for directory in (REQUEST_DIR, PROCESSING_DIR, RESULT_DIR):
        if not directory.is_dir():
            print(f"required broker directory is missing: {directory}", file=sys.stderr)
            return 1
    for request in sorted(REQUEST_DIR.glob("*.json")):
        process_request(request)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

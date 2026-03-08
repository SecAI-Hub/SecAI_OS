#!/usr/bin/env python3
"""
Secure AI Appliance - Audit Chain Verification

Verifies the integrity of all hash-chained audit logs.
Run via secure-ai-audit-verify.timer (default: every 30 minutes).

On chain break: logs CRITICAL alert, snapshots the broken log,
starts a new chain.
"""

import glob
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add services/ to path for audit_chain import
SERVICES_DIR = os.getenv("SERVICES_DIR", "/usr/libexec/secure-ai/services")
sys.path.insert(0, SERVICES_DIR)

# Also try the development path
_dev_path = str(Path(__file__).resolve().parent.parent.parent.parent / "services")
if os.path.isdir(_dev_path):
    sys.path.insert(0, _dev_path)

from common.audit_chain import AuditChain

logging.basicConfig(level=logging.INFO, format="[audit-verify] %(message)s")
log = logging.getLogger("audit-verify")

LOGS_DIR = os.getenv("AUDIT_LOGS_DIR", "/var/lib/secure-ai/logs")
RESULT_FILE = os.path.join(LOGS_DIR, "audit-verify-last.json")
BROKEN_DIR = os.path.join(LOGS_DIR, "broken")


def main():
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(BROKEN_DIR, exist_ok=True)

    # Find all JSONL audit logs
    log_files = glob.glob(os.path.join(LOGS_DIR, "*-audit.jsonl"))

    if not log_files:
        log.info("No audit logs found in %s", LOGS_DIR)
        _write_result("ok", 0, 0, [])
        return

    total_checked = 0
    total_failures = 0
    details = []

    for log_path in sorted(log_files):
        name = os.path.basename(log_path)
        result = AuditChain.verify(log_path)
        total_checked += 1

        if result["valid"]:
            log.info("OK: %s (%d entries)", name, result["entries"])
            details.append({
                "file": name,
                "status": "ok",
                "entries": result["entries"],
            })
        else:
            total_failures += 1
            log.critical(
                "CHAIN BREAK in %s at line %s: %s",
                name, result.get("broken_at"), result.get("detail"),
            )
            details.append({
                "file": name,
                "status": "broken",
                "broken_at": result.get("broken_at"),
                "detail": result.get("detail"),
                "entries_before_break": result.get("entries"),
            })

            # Snapshot the broken log
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            snapshot = os.path.join(BROKEN_DIR, f"{name}.broken.{ts}")
            try:
                shutil.copy2(log_path, snapshot)
                os.chmod(snapshot, 0o444)
                log.info("Snapshotted broken log: %s", snapshot)
            except OSError as e:
                log.error("Failed to snapshot: %s", e)

    status = "ok" if total_failures == 0 else "failed"
    if total_failures > 0:
        log.critical(
            "AUDIT VERIFICATION FAILED: %d/%d log(s) have broken chains",
            total_failures, total_checked,
        )
    else:
        log.info(
            "Audit verification passed: %d log(s) verified OK",
            total_checked,
        )

    _write_result(status, total_checked, total_failures, details)


def _write_result(status, checked, failures, details):
    result = {
        "status": status,
        "logs_checked": checked,
        "failures": failures,
        "details": details,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(RESULT_FILE, "w") as f:
            json.dump(result, f, indent=2)
    except OSError as e:
        log.error("Failed to write result file: %s", e)


if __name__ == "__main__":
    main()

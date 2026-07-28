#!/usr/bin/env python3
"""Verify explicitly enrolled Secure AI audit-log formats.

Not every service historically emitted the same format. This verifier never
pretends a plain JSONL stream is hash-chained: the root-owned manifest assigns
each filename a verifier and a truthful security class.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SERVICES_DIR = os.getenv("SERVICES_DIR", "/usr/libexec/secure-ai/services")
sys.path.insert(0, SERVICES_DIR)
for _parent in Path(__file__).resolve().parents:
    _candidate = _parent / "services" / "common" / "audit_chain.py"
    if _candidate.is_file():
        sys.path.insert(0, str(_parent / "services"))
        break

from common.audit_chain import AuditChain  # noqa: E402

logging.basicConfig(level=logging.INFO, format="[audit-verify] %(message)s")
log = logging.getLogger("audit-verify")

LOGS_DIR = Path(os.getenv("AUDIT_LOGS_DIR", "/var/lib/secure-ai/logs"))
RESULT_FILE = LOGS_DIR / "audit-verify-last.json"
BROKEN_DIR = LOGS_DIR / "broken"
MANIFEST_PATH = Path(os.getenv(
    "AUDIT_FORMAT_MANIFEST",
    "/etc/secure-ai/config/audit-log-formats.json",
))
KEY_DIR = Path(os.getenv("AUDIT_HMAC_KEY_DIR", "/run/credentials"))
MAX_LINE_BYTES = 1024 * 1024
MCP_VERIFY_BIN = os.getenv(
    "MCP_AUDIT_VERIFY_BIN",
    "/usr/libexec/secure-ai/mcp-firewall",
)
SUPPORTED_FORMATS = {
    "python-hmac-chain",
    "mcp-sha256-chain",
    "structured-jsonl",
}


def _safe_basename(value: object, field: str) -> str:
    name = str(value or "")
    if (
        not name
        or name != os.path.basename(name)
        or name in {".", ".."}
        or "\x00" in name
    ):
        raise ValueError(f"{field} must be a basename")
    return name


def load_manifest() -> list[dict[str, object]]:
    data = MANIFEST_PATH.read_bytes()
    if len(data) > 1024 * 1024:
        raise ValueError("audit format manifest exceeds size limit")
    payload = json.loads(data)
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("audit format manifest must have version 1")
    entries = payload.get("logs")
    if not isinstance(entries, list) or not entries:
        raise ValueError("audit format manifest has no log entries")
    enrolled: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError("audit manifest entry must be an object")
        filename = _safe_basename(raw.get("file"), "file")
        if filename in seen:
            raise ValueError(f"duplicate audit manifest entry: {filename}")
        seen.add(filename)
        log_format = str(raw.get("format", ""))
        if log_format not in SUPPORTED_FORMATS:
            raise ValueError(f"unsupported audit format for {filename}: {log_format}")
        key_file = raw.get("key_file")
        if log_format == "python-hmac-chain":
            _safe_basename(key_file, "key_file")
        elif key_file:
            raise ValueError(f"{filename} specifies an unused key")
        enrolled.append({
            "file": filename,
            "format": log_format,
            "key_file": key_file,
            "required": raw.get("required") is True,
            "security_class": str(raw.get("security_class", "")),
        })
    return enrolled


def _structured_jsonl(path: Path) -> dict[str, object]:
    count = 0
    try:
        with path.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if len(raw) > MAX_LINE_BYTES:
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "JSONL line exceeds size limit",
                    }
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError:
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "invalid JSON",
                    }
                if not isinstance(value, dict):
                    return {
                        "valid": False,
                        "entries": count,
                        "broken_at": line_number,
                        "detail": "JSONL entry is not an object",
                    }
                count += 1
    except OSError as exc:
        return {
            "valid": False,
            "entries": count,
            "broken_at": None,
            "detail": f"read error: {exc}",
        }
    return {
        "valid": True,
        "entries": count,
        "broken_at": None,
        "detail": "structured JSONL syntax valid; no tamper-evidence claim",
    }


def _mcp_hash(entry: dict[str, object]) -> str:
    canonical = {
        "sequence": entry.get("sequence"),
        "timestamp": entry.get("timestamp"),
        "prev_hash": entry.get("prev_hash"),
        "event": entry.get("event"),
        "decision": entry.get("decision"),
        "request": entry.get("request"),
        "detail": entry.get("detail"),
    }
    # Go encoding/json sorts string map keys and emits compact JSON.
    data = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _mcp_sha256_chain(path: Path) -> dict[str, object]:
    count = 0
    previous = "genesis"
    try:
        with path.open("rb") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if len(raw) > MAX_LINE_BYTES:
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "line exceeds size limit",
                    }
                if not raw.strip():
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "invalid JSON",
                    }
                if (
                    not isinstance(entry, dict)
                    or entry.get("sequence") != count + 1
                    or entry.get("prev_hash") != previous
                ):
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number,
                        "detail": "sequence or chain linkage mismatch",
                    }
                expected = _mcp_hash(entry)
                stored = str(entry.get("hash", ""))
                if not hmac.compare_digest(stored, expected):
                    return {
                        "valid": False, "entries": count,
                        "broken_at": line_number, "detail": "entry hash mismatch",
                    }
                previous = stored
                count += 1
    except OSError as exc:
        return {
            "valid": False, "entries": count,
            "broken_at": None, "detail": f"read error: {exc}",
        }
    return {
        "valid": True, "entries": count, "broken_at": None,
        "detail": "unkeyed SHA-256 linkage valid; privileged writers can forge entries",
    }


def verify_entry(entry: dict[str, object]) -> dict[str, object]:
    path = LOGS_DIR / str(entry["file"])
    if not path.exists():
        required = bool(entry["required"])
        return {
            "valid": not required,
            "entries": 0,
            "broken_at": None,
            "detail": "required log is missing" if required else "optional log not present",
            "status": "missing",
        }
    if path.is_symlink() or not path.is_file():
        return {
            "valid": False, "entries": 0, "broken_at": None,
            "detail": "audit path is not a regular file",
        }
    log_format = str(entry["format"])
    if log_format == "python-hmac-chain":
        key_path = KEY_DIR / str(entry["key_file"])
        result = AuditChain.verify(str(path), key_path=str(key_path))
    elif log_format == "mcp-sha256-chain":
        try:
            completed = subprocess.run(
                [MCP_VERIFY_BIN, "audit", "-log", str(path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
            )
            result = {
                "valid": completed.returncode == 0,
                "entries": 0,
                "broken_at": None,
                "detail": completed.stdout.strip()[:1024],
            }
        except (OSError, subprocess.SubprocessError) as exc:
            result = {
                "valid": False,
                "entries": 0,
                "broken_at": None,
                "detail": f"MCP audit verifier unavailable: {exc}",
            }
    else:
        result = _structured_jsonl(path)
    return result


def _snapshot_broken(path: Path) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    destination = BROKEN_DIR / f"{path.name}.broken.{timestamp}"
    try:
        shutil.copy2(path, destination, follow_symlinks=False)
        destination.chmod(0o440)
    except OSError as exc:
        log.error("failed to snapshot %s: %s", path.name, exc)


def _write_result(status: str, details: list[dict[str, object]]) -> None:
    result = {
        "status": status,
        "logs_checked": len(details),
        "failures": sum(item.get("status") in {"broken", "unmanaged"} for item in details),
        "details": details,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    fd, temp_name = tempfile.mkstemp(prefix=".audit-verify-", dir=LOGS_DIR)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, RESULT_FILE)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    BROKEN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        manifest = load_manifest()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        log.critical("audit format manifest invalid: %s", exc)
        _write_result("failed", [{
            "file": MANIFEST_PATH.name,
            "status": "broken",
            "detail": str(exc),
        }])
        return 1

    details: list[dict[str, object]] = []
    enrolled = {str(entry["file"]) for entry in manifest}
    for entry in manifest:
        result = verify_entry(entry)
        valid = bool(result.get("valid"))
        status = str(result.pop("status", "ok" if valid else "broken"))
        detail = {
            "file": entry["file"],
            "format": entry["format"],
            "security_class": entry["security_class"],
            "status": status,
            **result,
        }
        details.append(detail)
        if valid:
            log.info("%s: %s (%s)", status.upper(), entry["file"], entry["format"])
        else:
            log.critical("VERIFY FAILED: %s: %s", entry["file"], result.get("detail"))
            _snapshot_broken(LOGS_DIR / str(entry["file"]))

    candidates = {
        path.name
        for pattern in ("*-audit.jsonl", "audit.jsonl")
        for path in LOGS_DIR.glob(pattern)
        if path.is_file()
    }
    for filename in sorted(candidates - enrolled):
        details.append({
            "file": filename,
            "format": "unknown",
            "security_class": "unverified",
            "status": "unmanaged",
            "valid": False,
            "detail": "audit log exists but is not enrolled in the format manifest",
        })
        log.critical("UNMANAGED AUDIT LOG: %s", filename)

    failed = any(item["status"] in {"broken", "unmanaged"} for item in details)
    _write_result("failed" if failed else "ok", details)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

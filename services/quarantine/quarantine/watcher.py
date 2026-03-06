"""
Quarantine watcher: monitors the quarantine drop directory for new artifacts,
runs the verification/scanning pipeline, and promotes passing artifacts to
the trusted registry via its HTTP API.
"""

import hashlib
import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

from quarantine.pipeline import run_pipeline

log = logging.getLogger("quarantine")

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/quarantine"))
REGISTRY_DIR = Path(os.getenv("REGISTRY_DIR", "/registry"))
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
POLICY_PATH = Path(os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml"))
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/quarantine-audit.jsonl"))

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
DENIED_EXTENSIONS = {".pkl", ".pickle", ".pt", ".bin"}


def audit_log(event: str, filename: str, **kwargs):
    """Append a structured audit entry to the quarantine audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "filename": filename,
        **kwargs,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log.warning("failed to write audit log: %s", e)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_policy() -> dict:
    if POLICY_PATH.exists():
        return yaml.safe_load(POLICY_PATH.read_text()) or {}
    return {}


def model_name_from_filename(filename: str) -> str:
    """Derive a human-readable model name from filename."""
    stem = Path(filename).stem
    # Remove common quantization suffixes for a cleaner name
    for suffix in [".Q4_K_M", ".Q5_K_M", ".Q8_0", ".Q4_0", ".Q6_K", ".f16", ".f32"]:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def promote_to_registry(filename: str, file_hash: str, size_bytes: int, scan_results: dict) -> bool:
    """Call the registry's promote endpoint to register the artifact."""
    name = model_name_from_filename(filename)
    payload = {
        "name": name,
        "filename": filename,
        "sha256": file_hash,
        "size_bytes": size_bytes,
        "scan_results": {k: str(v) for k, v in scan_results.items()},
    }

    try:
        req = Request(
            f"{REGISTRY_URL}/v1/model/promote",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            log.info("registry promotion response: %s", result)
            return resp.status == 201
    except URLError as e:
        log.error("failed to contact registry for promotion: %s", e)
        return False
    except Exception as e:
        log.error("unexpected error during promotion: %s", e)
        return False


def process_artifact(artifact_path: Path) -> bool:
    """Run the full pipeline on a single artifact. Returns True if promoted."""
    log.info("processing: %s", artifact_path.name)

    ext = artifact_path.suffix.lower()
    if ext in DENIED_EXTENSIONS:
        log.warning("REJECTED (denied format): %s", artifact_path.name)
        audit_log("rejected", artifact_path.name, reason="denied_format", extension=ext)
        artifact_path.unlink()
        return False

    if ext not in ALLOWED_EXTENSIONS:
        log.warning("REJECTED (unknown format): %s", artifact_path.name)
        audit_log("rejected", artifact_path.name, reason="unknown_format", extension=ext)
        artifact_path.unlink()
        return False

    file_hash = sha256_file(artifact_path)
    file_size = artifact_path.stat().st_size
    log.info("sha256: %s  size: %d bytes", file_hash, file_size)

    result = run_pipeline(artifact_path, file_hash, load_policy())

    if not result["passed"]:
        log.warning("REJECTED (%s): %s", result["reason"], artifact_path.name)
        audit_log(
            "rejected", artifact_path.name,
            reason=result["reason"],
            sha256=file_hash,
            size_bytes=file_size,
            details={k: str(v) for k, v in result.get("details", {}).items()},
        )
        artifact_path.unlink()
        return False

    # Move file to registry directory
    dest = REGISTRY_DIR / artifact_path.name
    shutil.move(str(artifact_path), str(dest))
    log.info("moved to registry dir: %s", dest)

    # Collect scan result summary for the manifest
    details = result.get("details", {})
    scan_summary = {}
    if "format_gate" in details:
        scan_summary["format_gate"] = "pass" if details["format_gate"].get("passed") else "fail"
    if "static_scan" in details:
        scan_summary["static_scan"] = details["static_scan"].get("scanner", "unknown")
    if "smoke_test" in details:
        scan_summary["smoke_test"] = str(details["smoke_test"].get("score", "n/a"))

    # Register with the registry service
    if promote_to_registry(artifact_path.name, file_hash, file_size, scan_summary):
        log.info("PROMOTED: %s (registered in manifest)", artifact_path.name)
        audit_log(
            "promoted", artifact_path.name,
            sha256=file_hash,
            size_bytes=file_size,
            scan_summary=scan_summary,
        )
        return True
    else:
        log.error("PROMOTED to disk but registry update failed: %s", artifact_path.name)
        log.error("The file is in %s but not in the manifest. Manual intervention needed.", dest)
        audit_log(
            "promotion_partial", artifact_path.name,
            sha256=file_hash,
            size_bytes=file_size,
            note="file moved to registry dir but manifest update failed",
        )
        return False


def scan_directory():
    """One-shot scan of the quarantine directory."""
    if not QUARANTINE_DIR.exists():
        return
    for entry in sorted(QUARANTINE_DIR.iterdir()):
        if entry.is_file() and not entry.name.startswith("."):
            try:
                process_artifact(entry)
            except Exception:
                log.exception("error processing %s", entry.name)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log.info("quarantine watcher starting")
    log.info("watching: %s", QUARANTINE_DIR)
    log.info("registry dir: %s", REGISTRY_DIR)
    log.info("registry API: %s", REGISTRY_URL)

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        scan_directory()
        time.sleep(5)


if __name__ == "__main__":
    main()

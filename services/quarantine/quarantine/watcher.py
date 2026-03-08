"""
Quarantine watcher: monitors the quarantine drop directory for new artifacts,
runs the verification/scanning pipeline, and promotes passing artifacts to
the trusted registry via its HTTP API.

Supports:
- Single-file LLM models (.gguf, .safetensors)
- Multi-file diffusion model directories (containing model_index.json)

Everything is fully automatic. Users drop files into quarantine (via UI or CLI)
and the watcher handles scanning, verification, and promotion with zero
manual intervention.
"""

import hashlib
import json
import logging
import os
import shutil
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import sys
import yaml

from quarantine.pipeline import (
    run_pipeline,
    run_pipeline_directory,
    sha256_of_directory,
)

# Add services/ to path so we can import common.audit_chain
_services_root = str(Path(__file__).resolve().parent.parent.parent)
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)

from common.audit_chain import AuditChain

log = logging.getLogger("quarantine")

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/quarantine"))
REGISTRY_DIR = Path(os.getenv("REGISTRY_DIR", "/registry"))
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://127.0.0.1:8470")
POLICY_PATH = Path(os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml"))
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/quarantine-audit.jsonl"))

ALLOWED_EXTENSIONS = {".gguf", ".safetensors"}
DENIED_EXTENSIONS = {".pkl", ".pickle", ".pt", ".bin"}

# Hash-chained audit log instance
_audit_chain = AuditChain(str(AUDIT_LOG_PATH))


def audit_log(event: str, filename: str, **kwargs):
    """Append a hash-chained audit entry to the quarantine audit log."""
    _audit_chain.append(event, {"filename": filename, **kwargs})


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
    for suffix in [".Q4_K_M", ".Q5_K_M", ".Q8_0", ".Q4_0", ".Q6_K", ".f16", ".f32"]:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def _read_source_metadata(artifact_path: Path) -> str:
    """Read source URL from .source metadata file if present.

    When a model is downloaded via the UI's one-click download, a companion
    .source file is written alongside containing the origin URL. This lets
    the pipeline verify the source against the allowlist.
    """
    source_file = artifact_path.parent / f".{artifact_path.name}.source"
    if source_file.exists():
        try:
            return source_file.read_text().strip()
        except OSError:
            pass
    return ""


def promote_to_registry(filename: str, file_hash: str, size_bytes: int,
                        scan_results: dict, model_type: str = "llm") -> bool:
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
    """Run the full pipeline on a single-file artifact. Returns True if promoted."""
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
    source_url = _read_source_metadata(artifact_path)
    log.info("sha256: %s  size: %d bytes  source: %s", file_hash, file_size, source_url or "local")

    result = run_pipeline(artifact_path, file_hash, load_policy(), source_url=source_url)

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
        # Clean up source metadata file
        source_meta = artifact_path.parent / f".{artifact_path.name}.source"
        if source_meta.exists():
            source_meta.unlink()
        return False

    # Move file to registry directory
    dest = REGISTRY_DIR / artifact_path.name
    shutil.move(str(artifact_path), str(dest))
    log.info("moved to registry dir: %s", dest)

    # Clean up source metadata
    source_meta = artifact_path.parent / f".{artifact_path.name}.source"
    if source_meta.exists():
        source_meta.unlink()

    # Collect scan result summary
    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)

    if promote_to_registry(artifact_path.name, file_hash, file_size, scan_summary):
        log.info("PROMOTED: %s (registered in manifest)", artifact_path.name)
        audit_log("promoted", artifact_path.name, sha256=file_hash,
                  size_bytes=file_size, scan_summary=scan_summary)
        return True
    else:
        log.error("PROMOTED to disk but registry update failed: %s", artifact_path.name)
        audit_log("promotion_partial", artifact_path.name, sha256=file_hash,
                  size_bytes=file_size, note="file moved but manifest update failed")
        return False


def process_directory(artifact_dir: Path) -> bool:
    """Run the full pipeline on a multi-file diffusion model directory.
    Returns True if promoted.
    """
    log.info("processing directory: %s", artifact_dir.name)

    # Compute deterministic hash of the entire directory
    dir_hash = sha256_of_directory(artifact_dir)
    source_url = _read_source_metadata(artifact_dir)
    log.info("directory hash: %s  source: %s", dir_hash, source_url or "local")

    # Calculate total size
    total_size = sum(f.stat().st_size for f in artifact_dir.rglob("*") if f.is_file())

    result = run_pipeline_directory(artifact_dir, dir_hash, load_policy(), source_url=source_url)

    if not result["passed"]:
        log.warning("REJECTED (%s): %s", result["reason"], artifact_dir.name)
        audit_log(
            "rejected", artifact_dir.name,
            reason=result["reason"],
            sha256=dir_hash,
            size_bytes=total_size,
            model_type="diffusion",
            details={k: str(v) for k, v in result.get("details", {}).items()},
        )
        shutil.rmtree(artifact_dir)
        source_meta = artifact_dir.parent / f".{artifact_dir.name}.source"
        if source_meta.exists():
            source_meta.unlink()
        return False

    # Move directory to registry
    dest = REGISTRY_DIR / artifact_dir.name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(artifact_dir), str(dest))
    log.info("moved to registry dir: %s", dest)

    source_meta = artifact_dir.parent / f".{artifact_dir.name}.source"
    if source_meta.exists():
        source_meta.unlink()

    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)
    scan_summary["model_type"] = "diffusion"

    if promote_to_registry(artifact_dir.name, dir_hash, total_size, scan_summary, model_type="diffusion"):
        log.info("PROMOTED: %s (diffusion model registered)", artifact_dir.name)
        audit_log("promoted", artifact_dir.name, sha256=dir_hash,
                  size_bytes=total_size, model_type="diffusion", scan_summary=scan_summary)
        return True
    else:
        log.error("PROMOTED to disk but registry update failed: %s", artifact_dir.name)
        audit_log("promotion_partial", artifact_dir.name, sha256=dir_hash,
                  size_bytes=total_size, note="directory moved but manifest update failed")
        return False


def _build_scan_summary(details: dict) -> dict:
    """Build a summary dict from pipeline details for the registry manifest."""
    summary = {}
    if "source_policy" in details:
        summary["source_policy"] = "pass" if details["source_policy"].get("passed") else "fail"
    if "format_gate" in details:
        summary["format_gate"] = "pass" if details["format_gate"].get("passed") else "fail"
    if "provenance" in details:
        summary["provenance"] = details["provenance"].get("provenance", "unknown")
    if "static_scan" in details:
        scan = details["static_scan"]
        summary["static_scan"] = scan.get("scanner", "unknown")
    if "smoke_test" in details:
        summary["smoke_test"] = str(details["smoke_test"].get("score", "n/a"))
    if "diffusion_deep_scan" in details:
        summary["diffusion_deep_scan"] = "pass" if details["diffusion_deep_scan"].get("passed") else "fail"
    return summary


def scan_directory():
    """One-shot scan of the quarantine directory."""
    if not QUARANTINE_DIR.exists():
        return

    for entry in sorted(QUARANTINE_DIR.iterdir()):
        if entry.name.startswith("."):
            continue

        try:
            if entry.is_dir():
                # Check if it's a diffusion model directory (has model_index.json)
                if (entry / "model_index.json").exists():
                    process_directory(entry)
                else:
                    log.warning("skipping directory without model_index.json: %s", entry.name)
            elif entry.is_file():
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

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
import socket
import subprocess
import time
from datetime import datetime, timezone
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


def _extract_scanner_versions(scan_results: dict) -> dict:
    """Extract scanner version info from pipeline scan result details."""
    versions = {}
    for key, value in scan_results.items():
        if isinstance(value, dict):
            ver = value.get("scanner_version")
            if ver:
                versions[key] = ver
        elif isinstance(value, str):
            # Try to parse stringified dicts (from {k: str(v)} conversions)
            pass
    return versions


def _compute_policy_version() -> dict:
    """Read the policy file and return its hash as a version identifier."""
    if not POLICY_PATH.exists():
        return {"hash": "none", "note": "no policy file"}
    try:
        content = POLICY_PATH.read_bytes()
        return {"hash": hashlib.sha256(content).hexdigest()}
    except OSError:
        return {"hash": "unreadable"}


def promote_to_registry(filename: str, file_hash: str, size_bytes: int,
                        scan_results: dict, model_type: str = "llm",
                        source_url: str = "",
                        pipeline_details: dict | None = None) -> bool:
    """Call the registry's promote endpoint to register the artifact."""
    name = model_name_from_filename(filename)

    # Extract scanner versions from full pipeline details if available
    scanner_versions = {}
    if pipeline_details:
        scanner_versions = _extract_scanner_versions(pipeline_details)

    # Extract source revision for HuggingFace URLs
    source_revision = ""
    if source_url and "huggingface.co" in source_url:
        # Try to extract revision/commit from URL (e.g. /resolve/main/ or /commit/abc123)
        import re
        rev_match = re.search(r"/resolve/([^/]+)/", source_url)
        if rev_match:
            source_revision = rev_match.group(1)

    payload = {
        "name": name,
        "filename": filename,
        "sha256": file_hash,
        "size_bytes": size_bytes,
        "scan_results": {k: str(v) for k, v in scan_results.items()},
        "source": source_url,
        "source_revision": source_revision,
        "scanner_versions": scanner_versions,
        "policy_version": _compute_policy_version(),
    }

    # Include gguf-guard data if available from pipeline
    if pipeline_details:
        fp = pipeline_details.get("gguf_guard_fingerprint")
        if fp:
            payload["gguf_guard_fingerprint"] = fp
        manifest_info = pipeline_details.get("gguf_guard_manifest", {})
        if manifest_info.get("generated"):
            payload["gguf_guard_manifest"] = manifest_info.get("manifest_path", "")

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

    # Enable fs-verity on the promoted file (before provenance manifest)
    fsverity_ok = _enable_fsverity(dest)

    # Clean up source metadata
    source_meta = artifact_path.parent / f".{artifact_path.name}.source"
    if source_meta.exists():
        source_meta.unlink()

    # Collect scan result summary
    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)

    # Extract source revision
    source_revision = ""
    if source_url and "huggingface.co" in source_url:
        import re
        rev_match = re.search(r"/resolve/([^/]+)/", source_url)
        if rev_match:
            source_revision = rev_match.group(1)

    if promote_to_registry(artifact_path.name, file_hash, file_size, scan_summary,
                           source_url=source_url, pipeline_details=details):
        log.info("PROMOTED: %s (registered in manifest)", artifact_path.name)
        audit_log("promoted", artifact_path.name, sha256=file_hash,
                  size_bytes=file_size, scan_summary=scan_summary)
        # Write provenance manifest after successful promotion
        _write_provenance_manifest(
            dest, artifact_path.name, file_hash, file_size,
            source_url, source_revision, scan_summary, details,
            fsverity_success=fsverity_ok,
        )
        return True
    else:
        log.error("PROMOTED to disk but registry update failed: %s", artifact_path.name)
        audit_log("promotion_partial", artifact_path.name, sha256=file_hash,
                  size_bytes=file_size, note="file moved but manifest update failed")
        # Still write provenance manifest even if registry update failed
        _write_provenance_manifest(
            dest, artifact_path.name, file_hash, file_size,
            source_url, source_revision, scan_summary, details,
            fsverity_success=fsverity_ok,
        )
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

    # Enable fs-verity on individual model files in the directory
    fsverity_ok = True
    verity_extensions = {".safetensors", ".json"}
    for f in dest.rglob("*"):
        if f.is_file() and f.suffix in verity_extensions:
            if not _enable_fsverity(f):
                fsverity_ok = False

    source_meta = artifact_dir.parent / f".{artifact_dir.name}.source"
    if source_meta.exists():
        source_meta.unlink()

    details = result.get("details", {})
    scan_summary = _build_scan_summary(details)
    scan_summary["model_type"] = "diffusion"

    # Extract source revision
    source_revision = ""
    if source_url and "huggingface.co" in source_url:
        import re
        rev_match = re.search(r"/resolve/([^/]+)/", source_url)
        if rev_match:
            source_revision = rev_match.group(1)

    if promote_to_registry(artifact_dir.name, dir_hash, total_size, scan_summary,
                           model_type="diffusion", source_url=source_url,
                           pipeline_details=details):
        log.info("PROMOTED: %s (diffusion model registered)", artifact_dir.name)
        audit_log("promoted", artifact_dir.name, sha256=dir_hash,
                  size_bytes=total_size, model_type="diffusion", scan_summary=scan_summary)
        # Write provenance manifest after successful promotion
        _write_provenance_manifest(
            dest, artifact_dir.name, dir_hash, total_size,
            source_url, source_revision, scan_summary, details,
            fsverity_success=fsverity_ok,
        )
        return True
    else:
        log.error("PROMOTED to disk but registry update failed: %s", artifact_dir.name)
        audit_log("promotion_partial", artifact_dir.name, sha256=dir_hash,
                  size_bytes=total_size, note="directory moved but manifest update failed")
        # Still write provenance manifest even if registry update failed
        _write_provenance_manifest(
            dest, artifact_dir.name, dir_hash, total_size,
            source_url, source_revision, scan_summary, details,
            fsverity_success=fsverity_ok,
        )
        return False


def _enable_fsverity(filepath: Path) -> bool:
    """Enable fs-verity on a promoted model file for kernel-level integrity."""
    try:
        subprocess.run(
            ["fsverity", "enable", str(filepath)],
            check=True, capture_output=True, timeout=30,
        )
        log.info("fs-verity enabled on %s", filepath.name)
        return True
    except FileNotFoundError:
        log.warning("fsverity tool not installed, skipping runtime integrity protection")
        return False
    except subprocess.CalledProcessError as e:
        # Common reasons: filesystem doesn't support verity, file is open, etc.
        log.warning(
            "fs-verity not supported for %s: %s",
            filepath.name,
            e.stderr.decode().strip() if e.stderr else str(e),
        )
        return False


def _get_fsverity_digest(filepath: Path) -> str | None:
    """Read the fs-verity digest of a file."""
    try:
        result = subprocess.run(
            ["fsverity", "digest", str(filepath)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip().split()[0]  # "sha256:abc123..."
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return None


def _write_provenance_manifest(
    artifact_path: Path,
    filename: str,
    file_hash: str,
    size_bytes: int,
    source_url: str,
    source_revision: str,
    scan_results: dict,
    pipeline_details: dict,
    fsverity_success: bool = False,
) -> None:
    """Generate and optionally sign a JSON provenance manifest for a promoted model."""
    manifest = {
        "schema_version": "1.0",
        "artifact": {
            "filename": filename,
            "sha256": file_hash,
            "size_bytes": size_bytes,
        },
        "source": {
            "url": source_url or "local-import",
            "revision": source_revision or "unknown",
        },
        "scanners": _extract_scanner_versions(pipeline_details),
        "policy": {
            "version": _compute_policy_version(),
        },
        "promotion": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "hostname": socket.gethostname(),
        },
        "scan_summary": _build_scan_summary(pipeline_details),
        "integrity": {
            "fsverity_enabled": fsverity_success,
            "fsverity_digest": _get_fsverity_digest(artifact_path) if fsverity_success else None,
        },
    }

    manifest_path = REGISTRY_DIR / f"{filename}.provenance.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info("provenance manifest written: %s", manifest_path.name)

    # Try to sign with local cosign key
    cosign_key = Path("/etc/secure-ai/keys/cosign.key")
    if cosign_key.exists():
        try:
            subprocess.run(
                [
                    "cosign", "sign-blob", "--key", str(cosign_key),
                    "--output-signature", str(manifest_path) + ".sig",
                    str(manifest_path),
                ],
                check=True, capture_output=True, timeout=30,
            )
            log.info("provenance manifest signed: %s", filename)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            log.warning("could not sign provenance manifest: %s", e)
    else:
        log.info("no cosign key found, provenance manifest unsigned")


def _build_scan_summary(details: dict) -> dict:
    """Build a summary dict from pipeline details for the registry manifest."""
    summary = {}
    scanner_versions = {}
    if "source_policy" in details:
        summary["source_policy"] = "pass" if details["source_policy"].get("passed") else "fail"
    if "format_gate" in details:
        summary["format_gate"] = "pass" if details["format_gate"].get("passed") else "fail"
    if "provenance" in details:
        summary["provenance"] = details["provenance"].get("provenance", "unknown")
        ver = details["provenance"].get("scanner_version")
        if ver:
            scanner_versions["cosign"] = ver
    if "static_scan" in details:
        scan = details["static_scan"]
        summary["static_scan"] = scan.get("scanner", "unknown")
        # Extract modelscan version from nested details
        ms_details = scan.get("details", {})
        ms_info = ms_details.get("modelscan", {}) if isinstance(ms_details, dict) else {}
        ver = ms_info.get("scanner_version") if isinstance(ms_info, dict) else None
        if ver:
            scanner_versions["modelscan"] = ver
    if "smoke_test" in details:
        summary["smoke_test"] = str(details["smoke_test"].get("score", "n/a"))
        ver = details["smoke_test"].get("scanner_version")
        if ver:
            scanner_versions["llama-server"] = ver
    if "diffusion_deep_scan" in details:
        summary["diffusion_deep_scan"] = "pass" if details["diffusion_deep_scan"].get("passed") else "fail"
    if scanner_versions:
        summary["scanner_versions"] = scanner_versions
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

"""Credentialless scan broker for the Docker Compose evaluation deployment.

The broker runs in a container with ``network_mode: none`` and no registry
credential mounts. The credentialed watcher exchanges bounded request/result
files over a private volume. Every request is executed in a fresh process
group; the scanner worker and its local llama-server share the container's
isolated loopback, while no host or Compose service network is reachable.
"""

import json
import logging
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

log = logging.getLogger("quarantine.scanner-broker")

JOB_DIR = Path(
    os.getenv("SCANNER_JOB_DIR", "/var/lib/secure-ai/quarantine-scanner-jobs")
)
PROCESSING_DIR = Path(
    os.getenv("PROCESSING_DIR", "/var/lib/secure-ai/quarantine/processing")
)
POLICY_PATH = Path(os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml"))
WORKER_TIMEOUT = int(os.getenv("SCANNER_BROKER_WORKER_TIMEOUT", "1740"))
MAX_OUTPUT_BYTES = int(os.getenv("SCANNER_WORKER_MAX_OUTPUT", str(8 * 1024 * 1024)))
MAX_REQUEST_BYTES = 16 * 1024
MAX_SOURCE_URL_BYTES = 4096
POLL_INTERVAL = 0.25
SCANNER_UID = int(os.getenv("SCANNER_UID", "65534"))
SCANNER_GID = int(os.getenv("SCANNER_GID", "65534"))


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKey(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _decode_strict_json_object(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {constant}")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise ValueError("broker message is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError("broker message root must be an object")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bounded_json(path: Path, maximum: int) -> dict:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise ValueError("broker message is not a bounded regular file")
        raw = handle.read(maximum + 1)
    return _decode_strict_json_object(raw)


def _atomic_write_json(path: Path, payload: dict) -> None:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("broker result exceeds safety limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        # The setgid job directory assigns the dedicated IPC group. The
        # watcher can read the result but cannot modify its contents.
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _validate_request(job_id: str, request: dict) -> tuple[Path, str, str, bool]:
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("job identifier is malformed")
    if set(request) != {
        "version",
        "artifact",
        "sha256",
        "source_url",
        "directory",
    }:
        raise ValueError("scan request has unexpected fields")
    if request["version"] != 1 or type(request["directory"]) is not bool:
        raise ValueError("scan request version/type is invalid")

    expected_hash = request["sha256"]
    source_url = request["source_url"]
    raw_artifact = request["artifact"]
    if (
        not isinstance(expected_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        or not isinstance(source_url, str)
        or len(source_url.encode("utf-8")) > MAX_SOURCE_URL_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in source_url)
        or not isinstance(raw_artifact, str)
    ):
        raise ValueError("scan request values are invalid")

    artifact = Path(raw_artifact)
    processing_root = PROCESSING_DIR.resolve(strict=True)
    claim_root = artifact.parent.parent
    if (
        not artifact.is_absolute()
        or artifact.name in {"", ".", ".."}
        or artifact.parent.name != "snapshot"
        or claim_root.parent.resolve(strict=True) != processing_root
        or not re.fullmatch(r"[0-9a-f]{32}", claim_root.name)
        or claim_root.name != job_id
    ):
        raise ValueError("scan artifact is outside the processing claim layout")
    for directory in (claim_root, artifact.parent):
        metadata = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("scan claim path contains a link")
    artifact_metadata = artifact.lstat()
    is_directory = stat.S_ISDIR(artifact_metadata.st_mode)
    if artifact.is_symlink() or is_directory != request["directory"]:
        raise ValueError("scan artifact type does not match request")
    if not is_directory and (
        not stat.S_ISREG(artifact_metadata.st_mode)
        or artifact_metadata.st_nlink != 1
    ):
        raise ValueError("scan artifact is not a single-link regular file")
    return artifact, expected_hash, source_url, is_directory


def _worker_environment(scanner_root: Path) -> dict[str, str]:
    allowed = {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PYTHONPATH",
        "MODELS_LOCK_PATH",
        "DIFFUSION_MODELS_LOCK_PATH",
        "SOURCES_ALLOWLIST_PATH",
        "LLAMA_SERVER_BIN",
        "GGUF_GUARD_BIN",
        "COSIGN_BIN",
        "FICKLING_BIN",
        "MODELAUDIT_BIN",
        "MODELSCAN_BIN",
        "GARAK_BIN",
        "SMOKE_TEST_TIMEOUT",
        "YARA_RULES_DIR",
        "YARA_SCAN_TIMEOUT",
    }
    environment = {
        name: value for name, value in os.environ.items() if name in allowed
    }
    package_root = str(Path(__file__).resolve().parent.parent)
    inherited_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = (
        f"{package_root}{os.pathsep}{inherited_pythonpath}"
        if inherited_pythonpath
        else package_root
    )
    environment["QUARANTINE_DIR"] = str(scanner_root)
    return environment


def _limit_worker_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES),
    )


def _prepare_worker_process() -> None:
    """Drop the broker's job-volume DAC identity before parser code executes."""
    _limit_worker_output()
    if not sys.platform.startswith("linux"):
        return
    if os.geteuid() != 0:
        raise PermissionError("scanner broker must start as root to drop worker DAC")
    os.setgroups([])
    os.setgid(SCANNER_GID)
    os.setuid(SCANNER_UID)


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _run_worker(
    job_id: str,
    artifact: Path,
    expected_hash: str,
    source_url: str,
    directory: bool,
) -> dict:
    command = [
        sys.executable,
        "-m",
        "quarantine.scanner_worker",
        "--artifact",
        str(artifact),
        "--sha256",
        expected_hash,
        "--policy",
        str(POLICY_PATH),
    ]
    if source_url:
        # Preserve attacker-controlled source text as one argparse value even
        # when it begins with an option-like hyphen.
        command.append(f"--source-url={source_url}")
    if directory:
        command.append("--directory")

    cancel_path = JOB_DIR / f"{job_id}.cancel"
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=_worker_environment(artifact.parent),
            close_fds=True,
            start_new_session=True,
            preexec_fn=_prepare_worker_process,
        )
        deadline = time.monotonic() + WORKER_TIMEOUT
        while process.poll() is None:
            if cancel_path.exists() or time.monotonic() >= deadline:
                _kill_process_group(process)
                raise TimeoutError("credentialless scanner job timed out or was cancelled")
            time.sleep(POLL_INTERVAL)
        return_code = process.wait()
        _kill_process_group(process)

        stdout_file.seek(0)
        raw = stdout_file.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise ValueError("credentialless scanner output exceeds limit")
        try:
            result = _decode_strict_json_object(raw)
        except ValueError as exc:
            raise ValueError("credentialless scanner output is malformed") from exc
        if (
            return_code != 0
            or not isinstance(result, dict)
            or not isinstance(result.get("passed"), bool)
        ):
            raise ValueError("credentialless scanner exited abnormally")
        return result


def _process_request(request_path: Path) -> None:
    if request_path.name.endswith(".request.json"):
        job_id = request_path.name.removesuffix(".request.json")
    elif request_path.name.endswith(".active.json"):
        job_id = request_path.name.removesuffix(".active.json")
    else:
        raise ValueError("unexpected broker request filename")
    active_path = JOB_DIR / f"{job_id}.active.json"
    result_path = JOB_DIR / f"{job_id}.result.json"
    cancel_path = JOB_DIR / f"{job_id}.cancel"
    try:
        if request_path != active_path:
            os.rename(request_path, active_path)
            _fsync_directory(JOB_DIR)
        request = _read_bounded_json(active_path, MAX_REQUEST_BYTES)
        artifact, expected_hash, source_url, directory = _validate_request(
            job_id,
            request,
        )
        result = _run_worker(
            job_id,
            artifact,
            expected_hash,
            source_url,
            directory,
        )
        envelope = {"version": 1, "status": "ok", "result": result}
    except Exception as exc:
        log.error("scanner broker job %s failed (%s)", job_id, type(exc).__name__)
        envelope = {
            "version": 1,
            "status": "boundary_error",
            "reason": "credentialless_scanner_boundary_failed",
        }
    _atomic_write_json(result_path, envelope)
    active_path.unlink(missing_ok=True)
    cancel_path.unlink(missing_ok=True)
    _fsync_directory(JOB_DIR)


def scan_jobs_once() -> None:
    JOB_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    requests = sorted(JOB_DIR.glob("*.active.json"))
    requests.extend(sorted(JOB_DIR.glob("*.request.json")))
    for request_path in requests:
        job_id = request_path.name.split(".", 1)[0]
        if (JOB_DIR / f"{job_id}.result.json").exists():
            request_path.unlink(missing_ok=True)
            continue
        _process_request(request_path)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    JOB_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    log.info(
        "credentialless scanner broker started (network namespace supplied by runtime)"
    )
    while True:
        scan_jobs_once()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()

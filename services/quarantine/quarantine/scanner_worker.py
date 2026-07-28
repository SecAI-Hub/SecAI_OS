"""Credentialless quarantine scanner subprocess.

The long-lived watcher owns the registry promotion credential but never imports
or invokes the artifact parsers directly.  It launches this worker beneath a
second, narrower Landlock ruleset that permits read-only access to quarantine
inputs and no access to credentials, promotion staging, or audit logs.
"""

import argparse
import ctypes
import hashlib
import json
import logging
import os
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

log = logging.getLogger("quarantine.scanner-worker")

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_SOURCE_URL_BYTES = 4096
MAX_STAGE_OUTPUT_BYTES = 8 * 1024 * 1024
STAGE_TIMEOUT = int(os.getenv("SCANNER_STAGE_TIMEOUT", "1200"))
MODELS_LOCK_PATH = Path(
    os.getenv("MODELS_LOCK_PATH", "/etc/secure-ai/policy/models.lock.yaml")
)
DIFFUSION_MODELS_LOCK_PATH = Path(
    os.getenv(
        "DIFFUSION_MODELS_LOCK_PATH",
        "/etc/secure-ai/policy/diffusion-models.lock.yaml",
    )
)
SOURCES_ALLOWLIST_PATH = Path(
    os.getenv(
        "SOURCES_ALLOWLIST_PATH",
        "/etc/secure-ai/policy/sources.allowlist.yaml",
    )
)
YARA_RULES_DIR = Path(
    os.getenv(
        "YARA_RULES_DIR",
        Path(__file__).resolve().parent / "yara_rules",
    )
)
DIFFUSION_MAX_FILES = 20_000
DIFFUSION_MAX_ENTRIES = 25_000
DIFFUSION_MAX_DEPTH = 32
DIFFUSION_MAX_PATH_BYTES = 4096
DIFFUSION_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
DIFFUSION_MAX_FILE_BYTES = 50 * 1024 * 1024 * 1024
PR_SET_CHILD_SUBREAPER = 36
PR_SET_DUMPABLE = 4


def _sha256_regular_file(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("artifact must be a regular file")
    if metadata.st_nlink != 1:
        raise ValueError("hard-linked artifacts are not accepted")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise ValueError("artifact changed while it was being opened")
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inspect_directory_files(artifact_dir: Path) -> list[Path]:
    root_metadata = artifact_dir.lstat()
    if artifact_dir.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("artifact directory must be a real directory")

    files: list[Path] = []
    pending: list[tuple[Path, int]] = [(artifact_dir, 0)]
    entries_seen = 0
    total_bytes = 0
    while pending:
        directory, parent_depth = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > DIFFUSION_MAX_ENTRIES:
                    raise ValueError("artifact directory contains too many entries")
                path = Path(entry.path)
                relative = path.relative_to(artifact_dir)
                if any(part.startswith(".") for part in relative.parts):
                    raise ValueError("hidden artifact paths are not allowed")
                relative_bytes = relative.as_posix().encode("utf-8")
                if len(relative_bytes) > DIFFUSION_MAX_PATH_BYTES:
                    raise ValueError("artifact path exceeds safety limit")
                depth = parent_depth + 1
                if depth > DIFFUSION_MAX_DEPTH:
                    raise ValueError("artifact directory exceeds maximum depth")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("artifact directory contains a symbolic link")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((path, depth))
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("artifact directory contains an unsafe file")
                if metadata.st_size > DIFFUSION_MAX_FILE_BYTES:
                    raise ValueError("artifact file exceeds safety limit")
                total_bytes += metadata.st_size
                if total_bytes > DIFFUSION_MAX_TOTAL_BYTES:
                    raise ValueError("artifact directory exceeds safety limit")
                files.append(path)
                if len(files) > DIFFUSION_MAX_FILES:
                    raise ValueError("artifact directory contains too many files")
    return sorted(
        files,
        key=lambda path: path.relative_to(artifact_dir).as_posix().encode("utf-8"),
    )


def _sha256_directory(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b"SecAI-Directory-Hash-v1\0")
    for file_path in _inspect_directory_files(path):
        relative = file_path.relative_to(path).as_posix().encode("utf-8")
        metadata = file_path.lstat()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(file_path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
            ):
                raise ValueError("directory artifact changed while it was opened")
            digest.update(struct.pack(">Q", len(relative)))
            digest.update(relative)
            digest.update(struct.pack(">Q", opened.st_size))
            bytes_read = 0
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                bytes_read += len(chunk)
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            if (
                bytes_read != opened.st_size
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                raise ValueError("directory artifact changed while it was hashed")
    return digest.hexdigest()


def _sha256_control_file(path: Path) -> str:
    """Hash an immutable-image control file without following symlinks.

    OSTree deployments may legitimately hard-link image-owned files, so the
    single-link artifact rule is intentionally not applied to policy inputs.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"control input is not a regular file: {path.name}")
        bytes_read = 0
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            bytes_read += len(chunk)
            digest.update(chunk)
        if bytes_read != metadata.st_size:
            raise ValueError(f"control input changed while hashing: {path.name}")
    return digest.hexdigest()


def _load_policy(path: Path) -> dict:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_POLICY_BYTES:
        raise ValueError("scanner policy file is invalid or too large")
    with path.open("rb") as handle:
        raw = handle.read(MAX_POLICY_BYTES + 1)
    policy = yaml.safe_load(raw) or {}
    if not isinstance(policy, dict):
        raise ValueError("scanner policy root must be a mapping")
    return policy


def _policy_bundle_evidence(policy_path: Path) -> dict[str, object]:
    """Hash every input that can change an admission decision."""
    component_paths = [
        ("policy.yaml", policy_path),
        ("models.lock.yaml", MODELS_LOCK_PATH),
        ("diffusion-models.lock.yaml", DIFFUSION_MODELS_LOCK_PATH),
        ("sources.allowlist.yaml", SOURCES_ALLOWLIST_PATH),
    ]
    yara_rules = sorted(YARA_RULES_DIR.glob("*.yar"), key=lambda item: item.name)
    if not yara_rules:
        raise ValueError("policy bundle contains no YARA rules")
    component_paths.extend(
        (f"yara/{rule.name}", rule)
        for rule in yara_rules
    )

    bundle = hashlib.sha256()
    bundle.update(b"SecAI-Policy-Bundle-v1\0")
    components: dict[str, str] = {}
    for logical_name, path in component_paths:
        digest = _sha256_control_file(path)
        components[logical_name] = digest
        name_bytes = logical_name.encode("utf-8")
        bundle.update(len(name_bytes).to_bytes(8, "big"))
        bundle.update(name_bytes)
        bundle.update(bytes.fromhex(digest))
    return {
        "version": 1,
        "sha256": bundle.hexdigest(),
        "components": components,
    }


def _validate_source_url(source_url: str) -> None:
    if len(source_url.encode("utf-8")) > MAX_SOURCE_URL_BYTES:
        raise ValueError("source URL exceeds safety limit")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in source_url):
        raise ValueError("source URL contains control characters")


def _validated_artifact_path(raw_path: str) -> Path:
    quarantine_root = Path(
        os.getenv("QUARANTINE_DIR", "/var/lib/secure-ai/quarantine/incoming")
    ).resolve(strict=True)
    artifact = Path(raw_path)
    if artifact.parent.resolve(strict=True) != quarantine_root:
        raise ValueError("artifact must be a direct child of the quarantine directory")
    return artifact


class _DuplicateStageKey(ValueError):
    pass


def _reject_duplicate_stage_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateStageKey(f"duplicate stage result key: {key}")
        result[key] = value
    return result


def _stage_environment(scanner_root: Path) -> dict[str, str]:
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


def _limit_stage_output() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_STAGE_OUTPUT_BYTES, MAX_STAGE_OUTPUT_BYTES),
    )


def _enable_child_subreaper() -> bool:
    """Make escaped/double-forked stage descendants reparent to coordinator."""
    if not sys.platform.startswith("linux"):
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0


def _protect_coordinator_from_stage_processes() -> bool:
    """Prevent a compromised child stage from ptracing its coordinator."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if not sys.platform.startswith("linux"):
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0


def _reap_reparented_stage_descendants() -> None:
    if not sys.platform.startswith("linux"):
        return
    children_path = Path(f"/proc/self/task/{os.getpid()}/children")
    for _ in range(64):
        try:
            child_ids = [
                int(value)
                for value in children_path.read_text(encoding="ascii").split()
            ]
        except (OSError, ValueError):
            child_ids = []
        if not child_ids:
            break
        for child_id in child_ids:
            try:
                os.kill(child_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                waited, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if waited == 0:
                break
        time.sleep(0.01)


def _kill_stage_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
    _reap_reparented_stage_descendants()


def _run_stage(
    stage: str,
    artifact: Path,
    expected_sha256: str,
    policy_path: Path,
    *,
    source_url: str,
    directory: bool,
) -> dict:
    """Run exactly one admission stage in a separately reaped subprocess."""
    command = [
        sys.executable,
        "-m",
        "quarantine.scanner_stage",
        "--stage",
        stage,
        "--artifact",
        str(artifact),
        "--sha256",
        expected_sha256,
        "--policy",
        str(policy_path),
    ]
    if source_url:
        # The source sidecar is untrusted.  Joined option syntax prevents a
        # leading "-" from becoming a scanner-stage argument.
        command.append(f"--source-url={source_url}")
    if directory:
        command.append("--directory")

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=_stage_environment(artifact.parent),
            close_fds=True,
            start_new_session=True,
            preexec_fn=_limit_stage_output,
        )
        try:
            return_code = process.wait(timeout=STAGE_TIMEOUT)
        except subprocess.TimeoutExpired:
            _kill_stage_process_group(process)
            return {
                "passed": False,
                "reason": "stage_timeout",
                "failure_class": "TimeoutExpired",
            }
        else:
            _kill_stage_process_group(process)

        stdout_file.seek(0)
        raw = stdout_file.read(MAX_STAGE_OUTPUT_BYTES + 1)
        if len(raw) > MAX_STAGE_OUTPUT_BYTES:
            return {
                "passed": False,
                "reason": "stage_output_limit",
                "failure_class": "OutputLimit",
            }
        try:
            envelope = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_stage_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"invalid JSON constant: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return {
                "passed": False,
                "reason": "stage_output_invalid",
                "failure_class": "InvalidOutput",
            }
        if (
            return_code != 0
            or not isinstance(envelope, dict)
            or set(envelope) != {"version", "stage", "result"}
            or envelope.get("version") != 1
            or envelope.get("stage") != stage
            or not isinstance(envelope.get("result"), dict)
            or type(envelope["result"].get("passed")) is not bool
        ):
            return {
                "passed": False,
                "reason": "stage_boundary_failed",
                "failure_class": "BoundaryFailure",
            }
        return envelope["result"]


def scan(
    artifact: Path,
    expected_sha256: str,
    policy: dict,
    *,
    source_url: str,
    directory: bool,
    policy_path: Path | None = None,
) -> dict:
    """Coordinate separately reaped stages without parsing artifact content."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected SHA-256 is malformed")
    _validate_source_url(source_url)
    selected_policy_path = policy_path or Path(
        os.getenv("POLICY_PATH", "/etc/secure-ai/policy/policy.yaml")
    )

    stages: tuple[str, ...]
    if directory:
        before = _sha256_directory(artifact)
        if policy.get("models", {}).get("allow_diffusion_directories", True) is not True:
            return {
                "passed": False,
                "reason": "diffusion_directories_disabled",
                "details": {},
            }
        stages = (
            "source_policy",
            "format_gate",
            "hash_pin",
            "provenance",
            "static_scan",
            "diffusion_deep_scan",
        )
    else:
        before = _sha256_regular_file(artifact)
        stages = (
            "source_policy",
            "format_gate",
            "hash_pin",
            "provenance",
            "static_scan",
        )
        if artifact.suffix.lower() == ".gguf":
            if policy.get("models", {}).get("require_behavior_tests", True) is not True:
                return {
                    "passed": False,
                    "reason": "smoke_test",
                    "details": {
                        "smoke_test": {
                            "passed": False,
                            "reason": "production policy cannot disable behavioral testing",
                        }
                    },
                }
            stages += ("smoke_test",)

    if before != expected_sha256:
        raise ValueError("artifact changed before scanner execution")

    details: dict[str, object] = {}
    for stage in stages:
        stage_result = _run_stage(
            stage,
            artifact,
            expected_sha256,
            selected_policy_path,
            source_url=source_url,
            directory=directory,
        )
        details[stage] = stage_result
        if not stage_result["passed"]:
            return {
                "passed": False,
                "reason": stage,
                "details": details,
            }

    if directory:
        details["smoke_test"] = {
            "passed": True,
            "note": "not applicable for diffusion models",
        }
        after = _sha256_directory(artifact)
    else:
        if artifact.suffix.lower() != ".gguf":
            details["smoke_test"] = {
                "passed": True,
                "note": "not applicable for safetensors",
            }
        after = _sha256_regular_file(artifact)
    details["hash"] = {"sha256": expected_sha256}
    if after != expected_sha256:
        return {
            "passed": False,
            "reason": "artifact_changed_during_scan",
            "details": details,
        }
    return {
        "passed": True,
        "reason": "all_checks_passed",
        "details": details,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a quarantine scan without promotion credentials"
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--source-url", default="")
    parser.add_argument("--directory", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    if sys.platform.startswith("linux"):
        if not _enable_child_subreaper():
            log.error("credentialless scanner could not enable descendant reaping")
            raise SystemExit(2)
        if not _protect_coordinator_from_stage_processes():
            log.error("credentialless scanner could not disable ptrace/core dumps")
            raise SystemExit(2)

    try:
        artifact = _validated_artifact_path(args.artifact)
        policy_evidence = _policy_bundle_evidence(Path(args.policy))
        policy = _load_policy(Path(args.policy))
    except Exception as exc:
        # Invalid control-plane inputs are an operational boundary failure.
        # The watcher treats this non-zero exit as fail-closed and asks systemd
        # to recreate the service boundary.
        log.error(
            "credentialless scanner control-plane setup failed (%s)",
            type(exc).__name__,
        )
        raise SystemExit(2) from exc

    try:
        result = scan(
            artifact,
            args.sha256,
            policy,
            source_url=args.source_url,
            directory=args.directory,
            policy_path=Path(args.policy),
        )
    except Exception as exc:
        # Parser exceptions are deterministic properties of an untrusted
        # artifact until proven otherwise. Return a normal fail-closed scan
        # result so one poison file cannot consume systemd's restart budget.
        log.warning(
            "artifact rejected after scanner exception (%s)",
            type(exc).__name__,
        )
        result = {
            "passed": False,
            "reason": "artifact_parser_rejected",
            "details": {
                "failure_class": type(exc).__name__,
            },
        }

    try:
        if _policy_bundle_evidence(Path(args.policy)) != policy_evidence:
            raise ValueError("policy bundle changed during scanner execution")
        details = result.setdefault("details", {})
        if not isinstance(details, dict):
            raise ValueError("pipeline details are invalid")
        details["policy_bundle"] = policy_evidence
        encoded = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except Exception as exc:
        log.error(
            "credentialless scanner result/control validation failed (%s)",
            type(exc).__name__,
        )
        raise SystemExit(2) from exc

    print(encoded)


if __name__ == "__main__":
    main()

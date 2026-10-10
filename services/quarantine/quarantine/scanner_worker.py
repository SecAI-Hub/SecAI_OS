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
import math
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
from dataclasses import dataclass
from pathlib import Path

import yaml

log = logging.getLogger("quarantine.scanner-worker")

MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_SOURCE_URL_BYTES = 4096
MAX_STAGE_OUTPUT_BYTES = 8 * 1024 * 1024
STAGE_TIMEOUT = int(os.getenv("SCANNER_STAGE_TIMEOUT", "1200"))
STAGE_CLEANUP_TIMEOUT = 5.0
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


class CoordinatorIsolationError(RuntimeError):
    """The process domain cannot safely establish or finish stage ownership."""


@dataclass(eq=False)
class _CoordinatorDomain:
    owner_pid: int
    owner_starttime: int
    stage: subprocess.Popen | None = None
    stage_pid: int | None = None
    stage_starttime: int | None = None
    closed: bool = False


_coordinator_domain: _CoordinatorDomain | None = None


def _process_identity(pid: int) -> tuple[int, int, int]:
    """Return parent PID, process-group ID and kernel process birth identity."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()
        return int(fields[1]), int(fields[2]), int(fields[19])
    except (OSError, ValueError, IndexError) as exc:
        raise CoordinatorIsolationError("process identity is unavailable") from exc


def _single_coordinator_thread() -> None:
    try:
        threads = [entry.name for entry in Path("/proc/self/task").iterdir()]
    except OSError as exc:
        raise CoordinatorIsolationError("coordinator threads are unavailable") from exc
    if threads != [str(os.getpid())]:
        raise CoordinatorIsolationError("coordinator must have one OS thread")
    # With the default disposition, our unreaped children retain their PIDs.
    # A caller-installed auto-reaper is incompatible with exclusive ownership.
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise CoordinatorIsolationError("coordinator requires default child reaping")


def _coordinator_children() -> list[int]:
    try:
        raw = Path(f"/proc/self/task/{os.getpid()}/children").read_text(encoding="ascii")
        children = [int(value) for value in raw.split()]
    except (OSError, ValueError) as exc:
        raise CoordinatorIsolationError("coordinator child enumeration failed") from exc
    if any(pid <= 0 for pid in children) or len(set(children)) != len(children):
        raise CoordinatorIsolationError("coordinator child enumeration is invalid")
    return children


def _establish_coordinator_domain() -> _CoordinatorDomain:
    """Bootstrap only an exclusive executable process, never an ambient caller."""
    global _coordinator_domain
    if not sys.platform.startswith("linux") or _coordinator_domain is not None:
        raise CoordinatorIsolationError("fresh Linux coordinator process required")
    _single_coordinator_thread()
    if _coordinator_children():
        raise CoordinatorIsolationError("coordinator has preexisting children")
    owner = os.getpid()
    birth = _process_identity(owner)[2]
    try:
        protected = _enable_child_subreaper() and _protect_coordinator_from_stage_processes()
    except (OSError, ValueError) as exc:
        raise CoordinatorIsolationError("coordinator process controls unavailable") from exc
    if not protected:
        raise CoordinatorIsolationError("coordinator process controls unavailable")
    domain = _CoordinatorDomain(owner, birth)
    _coordinator_domain = domain
    return domain


def _require_domain(domain: _CoordinatorDomain | None = None) -> _CoordinatorDomain:
    current = _coordinator_domain
    if domain is None:
        domain = current
    if (not isinstance(domain, _CoordinatorDomain) or domain is not current
            or domain.closed or domain.owner_pid != os.getpid()):
        raise CoordinatorIsolationError("active same-process coordinator domain required")
    if _process_identity(os.getpid())[2] != domain.owner_starttime:
        raise CoordinatorIsolationError("coordinator process identity changed")
    _single_coordinator_thread()
    return domain


def _close_coordinator_domain(domain: _CoordinatorDomain) -> None:
    global _coordinator_domain
    domain.closed = True
    if _coordinator_domain is domain:
        _coordinator_domain = None


def _require_stage(process: subprocess.Popen | None = None,
                   domain: _CoordinatorDomain | None = None) -> _CoordinatorDomain:
    domain = _require_domain(domain)
    if (domain.stage is None or domain.stage_pid is None
            or domain.stage.pid != domain.stage_pid
            or (process is not None and process is not domain.stage)):
        raise CoordinatorIsolationError("exact registered stage process required")
    return domain


def _reap_reparented_stage_descendants(
    domain: _CoordinatorDomain | None = None, *, deadline: float | None = None,
) -> None:
    domain = _require_stage(domain=domain)
    if domain.stage is None or domain.stage.returncode is None:
        raise CoordinatorIsolationError("stage leader must be reaped through its owned handle")
    now = time.monotonic()
    if deadline is None:
        deadline = now + STAGE_CLEANUP_TIMEOUT
    elif not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline):
        raise CoordinatorIsolationError("invalid stage cleanup deadline")
    else:
        deadline = min(deadline, now + STAGE_CLEANUP_TIMEOUT)
    while True:
        _require_stage(domain=domain)
        children = _coordinator_children()
        if not children:
            if domain.stage is None or domain.stage.returncode is None:
                raise CoordinatorIsolationError("stage leader has not been reaped")
            domain.stage = None
            domain.stage_pid = None
            domain.stage_starttime = None
            return
        for child_id in children:
            if time.monotonic() >= deadline:
                raise CoordinatorIsolationError("stage descendants did not drain before deadline")
            parent, _group, birth = _process_identity(child_id)
            if parent != domain.owner_pid:
                raise CoordinatorIsolationError("descendant no longer belongs to coordinator")
            # No other thread/reaper is allowed in this domain. A child that
            # exits remains our zombie until this exact waitpid releases it.
            if _process_identity(child_id) != (parent, _group, birth):
                raise CoordinatorIsolationError("descendant identity changed")
            try:
                os.kill(child_id, signal.SIGKILL)
                os.waitpid(child_id, os.WNOHANG)
            except OSError as exc:
                raise CoordinatorIsolationError("owned descendant cleanup failed") from exc
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CoordinatorIsolationError("stage descendants did not drain before deadline")
        time.sleep(min(0.01, remaining))


def _kill_stage_process_group(process: subprocess.Popen,
                              domain: _CoordinatorDomain | None = None) -> None:
    domain = _require_stage(process, domain)
    deadline = time.monotonic() + STAGE_CLEANUP_TIMEOUT
    if process.returncode is None:
        try:
            if domain.stage_starttime is None:
                # Popen has returned and this exact handle/PID was registered,
                # but /proc identity acquisition failed. Terminate only that
                # unreaped child through Popen; never infer a process group.
                process.kill()
            else:
                parent, group, birth = _process_identity(process.pid)
                if (parent, group, birth) != (domain.owner_pid, process.pid, domain.stage_starttime):
                    raise CoordinatorIsolationError("stage process identity/group changed")
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise CoordinatorIsolationError("owned stage termination failed") from exc
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise CoordinatorIsolationError("stage leader did not drain before deadline") from exc
    # wait() has already reaped a successful leader; its numeric group ID is
    # no longer ours to signal. Drain only children in this exclusive domain.
    _reap_reparented_stage_descendants(domain, deadline=deadline)


def _run_stage(
    stage: str,
    artifact: Path,
    expected_sha256: str,
    policy_path: Path,
    *,
    source_url: str,
    directory: bool,
    domain: _CoordinatorDomain | None = None,
) -> dict:
    """Run one stage only inside the bootstrapped exclusive process domain."""
    domain = _require_domain(domain)
    if domain.stage is not None or _coordinator_children():
        raise CoordinatorIsolationError("previous children or stage ownership remain")
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
        try:
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
        except (OSError, subprocess.SubprocessError) as exc:
            raise CoordinatorIsolationError("stage process could not start") from exc
        domain.stage = process
        domain.stage_pid = process.pid
        timed_out = False
        try:
            parent, group, birth = _process_identity(process.pid)
            if parent != domain.owner_pid or group != process.pid:
                raise CoordinatorIsolationError("new stage was not created in its owned group")
            domain.stage_starttime = birth
            try:
                return_code = process.wait(timeout=STAGE_TIMEOUT)
            except subprocess.TimeoutExpired:
                timed_out = True
            except OSError as exc:
                raise CoordinatorIsolationError("stage wait failed") from exc
        finally:
            _kill_stage_process_group(process, domain)
        if timed_out:
            return {"passed": False, "reason": "stage_timeout", "failure_class": "TimeoutExpired"}

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
    try:
        domain = _establish_coordinator_domain()
    except CoordinatorIsolationError as exc:
        log.error("credentialless scanner ownership setup failed (%s)", type(exc).__name__)
        raise SystemExit(2) from exc
    try:
        _main_in_domain(args)
    finally:
        _close_coordinator_domain(domain)


def _main_in_domain(args) -> None:
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
    except CoordinatorIsolationError as exc:
        log.error("credentialless scanner isolation cleanup failed (%s)", type(exc).__name__)
        raise SystemExit(2) from exc
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

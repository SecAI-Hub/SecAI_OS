#!/usr/bin/env python3
"""Host-local control API for the Docker sandbox launcher.

The UI container intentionally does not get the Docker socket. This helper runs
on the host, listens on loopback or a verified private container bridge, and
only accepts token-authenticated requests for a small allowlist of sandbox
start profiles.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
import re
import secrets
import signal
import shutil
import socket
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit


VALID_PROFILES = {"offline_private", "research", "full_lab"}
UNKNOWN_PROFILE = "unknown"
PROFILE_ARGS = {
    "offline_private": (),
    "research": ("--with-search",),
    "full_lab": ("--with-search", "--with-diffusion"),
}
PS_SWITCHES = {
    "--with-search": "-WithSearch",
    "--with-airlock": "-WithAirlock",
    "--with-inference": "-WithInference",
    "--with-diffusion": "-WithDiffusion",
    "--with-gpu": "-WithGpu",
}
SAFE_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=:-]{0,254}\.gguf$", re.IGNORECASE)
MAX_BODY_BYTES = 8192
MAX_HEADER_BYTES = 16384
MAX_HEADER_COUNT = 32
BODY_READ_TIMEOUT_SECONDS = 5.0
APPLY_TIMEOUT_SECONDS = int(os.getenv("SECAI_CONTROL_APPLY_TIMEOUT", "1800"))
PROCESS_KILL_TIMEOUT_SECONDS = 30
PROCESS_TERM_GRACE_SECONDS = 10
CONTROL_PORT = 8498
CONTROL_PROTOCOL_VERSION = 3
CONTROL_STATE_PROTOCOL_VERSION = 1
CONTROL_STATE_PROOF_DOMAIN = "secai-sandbox-control-state:v1"
CONTROL_CONNECTION_LIMIT = 16
HEADER_READ_TIMEOUT_SECONDS = 5.0
CONTROL_STOP_TIMEOUT_SECONDS = PROCESS_KILL_TIMEOUT_SECONDS + 20
AUTH_CLOCK_SKEW_SECONDS = 30
AUTH_NONCE_LIMIT = 2048
AUTH_NONCE_TTL_SECONDS = (AUTH_CLOCK_SKEW_SECONDS * 2) + 1
AUTH_NONCE_STATE_MAX_BYTES = 262144
MAX_ENV_FILE_BYTES = 1048576
MAX_RECORDED_HOST_BYTES = 64
MAX_RECORDED_PID_BYTES = 32
MAX_GENERATION_MANIFEST_BYTES = 262144
MAX_GENERATION_MANIFEST_ENTRIES = 256
WINDOWS_REPARSE_POINT = 0x400
WINDOWS_CREATE_SUSPENDED = 0x00000004
WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
WINDOWS_PROCESS_TERMINATE = 0x00000001
WINDOWS_PROCESS_SET_QUOTA = 0x00000100
WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
WINDOWS_SYNCHRONIZE = 0x00100000
WINDOWS_THREAD_SUSPEND_RESUME = 0x00000002
WINDOWS_THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
WINDOWS_TOOLHELP_SNAPSHOT_THREADS = 0x00000004
WINDOWS_WAIT_OBJECT_0 = 0x00000000
WINDOWS_WAIT_TIMEOUT = 0x00000102
WINDOWS_ERROR_NO_MORE_FILES = 18
WINDOWS_ERROR_INVALID_PARAMETER = 87
WINDOWS_INVALID_SUSPEND_COUNT = 0xFFFFFFFF
ENDPOINT_PRESENT = "present"
ENDPOINT_ABSENT = "absent"
ENDPOINT_AMBIGUOUS = "ambiguous"
PRIVATE_BIND_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
PODMAN_CONTROL_NETWORK = "secai-sandbox_ingress"
CONTROL_TOKEN_BYTES = 64
CONTROL_TOKEN_POSIX_MODE = 0o604
RUNTIME_DIR_POSIX_MODE = 0o700
RUNTIME_GENERATION_FORMAT = 1

_state_lock = threading.Lock()
_termination_lock = threading.Lock()
_active_thread: threading.Thread | None = None
_active_process: subprocess.Popen[str] | None = None
_active_windows_job: _WindowsJob | None = None
_shutdown_requested = threading.Event()
_tree_containment_failed = threading.Event()
_tree_termination_confirmed = threading.Event()
_shutdown_worker_lock = threading.Lock()
_shutdown_worker: threading.Thread | None = None
_auth_nonce_lock = threading.Lock()
_auth_nonces: dict[str, float] = {}
_server: ThreadingHTTPServer | None = None
_server_token = ""
_server_session = ""


def _windows_last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        return 0
    return int(getter())


def _load_windows_dll(name: str) -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise RuntimeError("Windows DLL loading is unavailable on this host")
    return loader(name, use_last_error=True)


def _windows_powershell() -> str | None:
    """Prefer supported PowerShell 7 while retaining Windows PowerShell fallback."""
    return shutil.which("pwsh") or shutil.which("powershell")


class _WindowsJobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", ctypes.c_ulong),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", ctypes.c_ulong),
        ("affinity", ctypes.c_size_t),
        ("priority_class", ctypes.c_ulong),
        ("scheduling_class", ctypes.c_ulong),
    ]


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _WindowsJobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _WindowsJobBasicLimitInformation),
        ("io_info", _WindowsIoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class _WindowsJobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("total_user_time", ctypes.c_longlong),
        ("total_kernel_time", ctypes.c_longlong),
        ("this_period_total_user_time", ctypes.c_longlong),
        ("this_period_total_kernel_time", ctypes.c_longlong),
        ("total_page_fault_count", ctypes.c_ulong),
        ("total_processes", ctypes.c_ulong),
        ("active_processes", ctypes.c_ulong),
        ("total_terminated_processes", ctypes.c_ulong),
    ]


class _WindowsThreadEntry(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_ulong),
        ("usage_count", ctypes.c_ulong),
        ("thread_id", ctypes.c_ulong),
        ("owner_process_id", ctypes.c_ulong),
        ("base_priority", ctypes.c_long),
        ("priority_delta", ctypes.c_long),
        ("flags", ctypes.c_ulong),
    ]


class _WindowsJob:
    """A kill-on-close Windows Job Object assigned before child code runs."""

    def __init__(self, kernel32: Any, handle: int) -> None:
        self._kernel32 = kernel32
        self._handle = handle

    @staticmethod
    def _last_error(action: str) -> OSError:
        code = _windows_last_error()
        return OSError(code, f"{action} failed with Windows error {code}")

    @classmethod
    def create(cls) -> _WindowsJob:
        if not _running_on_windows():
            raise RuntimeError("Windows Job Objects are unavailable on this host")
        kernel32 = _load_windows_dll("kernel32")
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.OpenProcess.argtypes = [
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.CreateToolhelp32Snapshot.argtypes = [
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Thread32First.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WindowsThreadEntry),
        ]
        kernel32.Thread32First.restype = ctypes.c_int
        kernel32.Thread32Next.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WindowsThreadEntry),
        ]
        kernel32.Thread32Next.restype = ctypes.c_int
        kernel32.OpenThread.argtypes = [
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_ulong,
        ]
        kernel32.OpenThread.restype = ctypes.c_void_p
        kernel32.GetProcessIdOfThread.argtypes = [ctypes.c_void_p]
        kernel32.GetProcessIdOfThread.restype = ctypes.c_ulong
        kernel32.ResumeThread.argtypes = [ctypes.c_void_p]
        kernel32.ResumeThread.restype = ctypes.c_ulong

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise cls._last_error("CreateJobObjectW")
        job = cls(kernel32, int(handle))
        limits = _WindowsJobExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = (
            WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        configured = kernel32.SetInformationJobObject(
            ctypes.c_void_p(job._handle),
            9,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        )
        if not configured:
            error = cls._last_error("SetInformationJobObject")
            try:
                job.close()
            except OSError as close_error:
                error.add_note(f"secondary handle-close failure: {close_error}")
                raise error from close_error
            raise error
        return job

    def _close_native_handle(self, handle: Any) -> None:
        if not self._kernel32.CloseHandle(handle):
            raise self._last_error("CloseHandle")

    @contextlib.contextmanager
    def _checked_handle(self, handle: Any) -> Any:
        try:
            yield handle
        except BaseException as primary:
            try:
                self._close_native_handle(handle)
            except OSError as close_error:
                primary.add_note(f"secondary handle-close failure: {close_error}")
            raise
        else:
            self._close_native_handle(handle)

    def assign(self, proc: subprocess.Popen[str]) -> None:
        process_handle = self._kernel32.OpenProcess(
            WINDOWS_PROCESS_TERMINATE | WINDOWS_PROCESS_SET_QUOTA,
            False,
            proc.pid,
        )
        if not process_handle:
            raise self._last_error("OpenProcess")
        with self._checked_handle(process_handle):
            assigned = self._kernel32.AssignProcessToJobObject(
                ctypes.c_void_p(self._handle),
                process_handle,
            )
            if not assigned:
                raise self._last_error("AssignProcessToJobObject")

    def resume(self, proc: subprocess.Popen[str]) -> None:
        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            WINDOWS_TOOLHELP_SNAPSHOT_THREADS,
            0,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if not snapshot or int(snapshot) == invalid_handle:
            raise self._last_error("CreateToolhelp32Snapshot")
        thread_ids: list[int] = []
        minimum_entry_size = (
            _WindowsThreadEntry.owner_process_id.offset
            + ctypes.sizeof(ctypes.c_ulong)
        )
        with self._checked_handle(snapshot):
            entry = _WindowsThreadEntry()
            entry.size = ctypes.sizeof(entry)
            has_entry = self._kernel32.Thread32First(
                snapshot,
                ctypes.byref(entry),
            )
            if not has_entry:
                error = _windows_last_error()
                if error != WINDOWS_ERROR_NO_MORE_FILES:
                    raise self._last_error("Thread32First")
            while has_entry:
                if int(entry.size) < minimum_entry_size:
                    raise RuntimeError(
                        "Thread32First returned an incomplete thread entry"
                    )
                if int(entry.owner_process_id) == proc.pid:
                    thread_ids.append(int(entry.thread_id))
                entry.size = ctypes.sizeof(entry)
                has_entry = self._kernel32.Thread32Next(
                    snapshot,
                    ctypes.byref(entry),
                )
            error = _windows_last_error()
            if error not in {0, WINDOWS_ERROR_NO_MORE_FILES}:
                raise self._last_error("Thread32Next")

        if len(thread_ids) != 1:
            raise RuntimeError(
                "suspended child did not have exactly one initial thread"
            )
        thread_handle = self._kernel32.OpenThread(
            (
                WINDOWS_THREAD_SUSPEND_RESUME
                | WINDOWS_THREAD_QUERY_LIMITED_INFORMATION
            ),
            False,
            thread_ids[0],
        )
        if not thread_handle:
            raise self._last_error("OpenThread")
        with self._checked_handle(thread_handle):
            owner_pid = int(
                self._kernel32.GetProcessIdOfThread(thread_handle)
            )
            if owner_pid != proc.pid:
                if owner_pid == 0:
                    raise self._last_error("GetProcessIdOfThread")
                raise RuntimeError(
                    "suspended child thread identity changed before resume"
                )
            previous_count = int(self._kernel32.ResumeThread(thread_handle))
            if previous_count == WINDOWS_INVALID_SUSPEND_COUNT:
                raise self._last_error("ResumeThread")
            if previous_count != 1:
                raise RuntimeError(
                    "suspended child had an unexpected thread suspend count"
                )

    def active_processes(self) -> int:
        accounting = _WindowsJobBasicAccountingInformation()
        returned = ctypes.c_ulong()
        queried = self._kernel32.QueryInformationJobObject(
            ctypes.c_void_p(self._handle),
            1,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            ctypes.byref(returned),
        )
        if not queried:
            raise self._last_error("QueryInformationJobObject")
        return int(accounting.active_processes)

    def terminate_and_wait(self, timeout: float) -> bool:
        if self.active_processes() == 0:
            return True
        terminated = self._kernel32.TerminateJobObject(
            ctypes.c_void_p(self._handle),
            1,
        )
        if not terminated and self.active_processes() != 0:
            raise self._last_error("TerminateJobObject")
        deadline = time.monotonic() + timeout
        while self.active_processes() != 0:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def close(self) -> None:
        if not self._handle:
            return
        closed = self._kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        if not closed:
            raise self._last_error("CloseHandle")
        self._handle = 0


def _close_windows_job(job: _WindowsJob) -> bool:
    try:
        job.close()
    except OSError:
        _tree_containment_failed.set()
        return False
    return True


class ControlConfig:
    def __init__(
        self,
        repo_root: Path,
        runtime_dir: Path,
        token_path: Path,
        runtime: str = "auto",
        podman_network: str = PODMAN_CONTROL_NETWORK,
    ) -> None:
        self.repo_root = repo_root
        self.runtime_dir = runtime_dir
        self.token_path = token_path
        self.runtime = runtime
        self.podman_network = podman_network
        self.status_path = runtime_dir / "state" / "control-status.json"
        self.pid_path = runtime_dir / "control-server.pid"
        self.host_path = runtime_dir / "control-server-host"
        self.session_path = runtime_dir / "control-server-session"
        self.env_path = repo_root / "deploy" / "sandbox" / ".env"


CONFIG: ControlConfig | None = None


def _running_on_windows() -> bool:
    return os.name == "nt"


def _now() -> float:
    return round(time.time(), 3)


def _read_token() -> str:
    """Return the token captured before this server began accepting requests."""
    return _server_token


def _read_session() -> str:
    """Return the session captured before this server began accepting requests."""
    return _server_session


def _valid_control_token(token: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", token))


def _valid_session_id(session_id: object) -> bool:
    return isinstance(session_id, str) and bool(
        re.fullmatch(r"[0-9a-f]{64}", session_id)
    )


def _new_controller_session() -> str:
    session_id = secrets.token_hex(32)
    if not _valid_session_id(session_id):
        raise RuntimeError("failed to generate a valid controller session")
    return session_id


def _health_proof(
    token: str,
    challenge: str,
    protocol_version: int = CONTROL_PROTOCOL_VERSION,
) -> str:
    if (
        not _valid_control_token(token)
        or not re.fullmatch(r"[0-9a-f]{64}", challenge)
        or type(protocol_version) is not int
        or protocol_version < 1
    ):
        return ""
    message = (
        f"secai-sandbox-control-health:v{protocol_version}:{challenge}"
    ).encode("ascii")
    return hmac.new(token.encode("ascii"), message, "sha256").hexdigest()


def _state_proof(
    token: str,
    challenge: str,
    session_id: str,
    status: str,
    profile_state: str,
    profile: str,
) -> str:
    if (
        not _valid_control_token(token)
        or not re.fullmatch(r"[0-9a-f]{64}", challenge)
        or not _valid_session_id(session_id)
        or (
            profile_state == "active"
            and (status != "ok" or profile not in VALID_PROFILES)
        )
        or (
            profile_state == "degraded"
            and (status != "degraded" or profile != UNKNOWN_PROFILE)
        )
        or profile_state not in {"active", "degraded"}
    ):
        return ""
    message = "\n".join(
        (
            CONTROL_STATE_PROOF_DOMAIN,
            challenge,
            session_id,
            status,
            profile_state,
            profile,
        )
    ).encode("ascii")
    return hmac.new(token.encode("ascii"), message, "sha256").hexdigest()


def _verify_challenge_health_payload(
    *,
    token: str,
    challenge: str,
    payload: object,
) -> bool:
    if not isinstance(payload, dict):
        return False
    protocol_version = payload.get("protocol_version")
    state_protocol_version = payload.get("state_protocol_version")
    if (
        payload.get("controller") != "secai-sandbox-control"
        or type(protocol_version) is not int
        or protocol_version != CONTROL_PROTOCOL_VERSION
        or type(state_protocol_version) is not int
        or state_protocol_version != CONTROL_STATE_PROTOCOL_VERSION
    ):
        return False
    session_id = payload.get("session_id")
    status = payload.get("status")
    profile_state = payload.get("profile_state")
    profile = payload.get("profile")
    if not all(
        isinstance(value, str)
        for value in (session_id, status, profile_state, profile)
    ):
        return False
    expected_health_proof = _health_proof(
        token,
        challenge,
        CONTROL_PROTOCOL_VERSION,
    )
    expected_state_proof = _state_proof(
        token,
        challenge,
        session_id,
        status,
        profile_state,
        profile,
    )
    return bool(
        expected_health_proof
        and expected_state_proof
        and hmac.compare_digest(
            str(payload.get("proof", "")),
            expected_health_proof,
        )
        and hmac.compare_digest(
            str(payload.get("state_proof", "")),
            expected_state_proof,
        )
    )


def _request_signature(
    *,
    token: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    protocol_version: int = CONTROL_PROTOCOL_VERSION,
) -> tuple[str, str]:
    if (
        not _valid_control_token(token)
        or method not in {"GET", "POST"}
        or path not in {"/v1/status", "/v1/apply", "/v1/shutdown"}
        or not timestamp.isascii()
        or not timestamp.isdecimal()
        or not re.fullmatch(r"[0-9a-f]{64}", nonce)
        or protocol_version < 1
    ):
        return "", ""
    body_sha256 = hashlib.sha256(body).hexdigest()
    message = "\n".join(
        (
            f"secai-sandbox-control-request:v{protocol_version}",
            timestamp,
            nonce,
            method,
            path,
            body_sha256,
        )
    ).encode("ascii")
    signature = hmac.new(token.encode("ascii"), message, "sha256").hexdigest()
    return body_sha256, signature


def _consume_auth_nonce(nonce: str, now: float) -> bool:
    with _auth_nonce_lock:
        for candidate, expires_at in list(_auth_nonces.items()):
            if expires_at <= now:
                _auth_nonces.pop(candidate, None)
        if nonce in _auth_nonces:
            return False
        _auth_nonces[nonce] = now + AUTH_NONCE_TTL_SECONDS
        while len(_auth_nonces) > AUTH_NONCE_LIMIT:
            oldest = next(iter(_auth_nonces))
            _auth_nonces.pop(oldest, None)
        if not _persist_auth_nonce_state_locked():
            _auth_nonces.pop(nonce, None)
            return False
    return True


def _request_auth_headers(
    token: str,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(32)
    body_sha256, signature = _request_signature(
        token=token,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    if not signature:
        return {}
    return {
        "Content-Type": "application/json",
        "X-SecAI-Timestamp": timestamp,
        "X-SecAI-Nonce": nonce,
        "X-SecAI-Content-SHA256": body_sha256,
        "X-SecAI-Signature": signature,
    }


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    payload = (json.dumps(data, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > AUTH_NONCE_STATE_MAX_BYTES:
        raise OSError("sandbox controller JSON state exceeds the size limit")
    _write_private_file_atomic(path, payload)


def _open_private_directory(
    path: Path,
    *,
    normalize_mode: bool = False,
) -> int:
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError("sandbox controller state parent is not a real directory")
    if os.name == "nt":
        _verify_windows_owner_only_acl(path)
        final_path = os.lstat(path)
        if (
            not stat.S_ISDIR(final_path.st_mode)
            or _is_reparse_point(final_path)
            or (final_path.st_dev, final_path.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(
                "sandbox controller state parent changed during ACL validation"
            )
        # Windows os.open cannot portably acquire directory handles. Callers
        # use randomized, exclusive absolute-path operations after this
        # reparse-point and owner-only DACL validation.
        return -1
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _is_reparse_point(opened)
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(
                "sandbox controller state parent changed during validation"
            )
        if hasattr(os, "geteuid"):
            if opened.st_uid != os.geteuid():
                raise RuntimeError(
                    "sandbox controller state parent is not owned by "
                    "the controller user"
                )
            if normalize_mode:
                os.fchmod(descriptor, RUNTIME_DIR_POSIX_MODE)
                opened = os.fstat(descriptor)
            if stat.S_IMODE(opened.st_mode) != RUNTIME_DIR_POSIX_MODE:
                raise RuntimeError(
                    "sandbox controller state parent must have mode 0700"
                )
        _verify_windows_owner_only_acl(path)
        final_path = os.lstat(path)
        if (
            not stat.S_ISDIR(final_path.st_mode)
            or _is_reparse_point(final_path)
            or (final_path.st_dev, final_path.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(
                "sandbox controller state parent changed during ACL validation"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_private_directory(path: Path) -> None:
    parent_descriptor = _open_private_directory(path.parent)
    try:
        try:
            if os.name == "nt":
                os.mkdir(path, RUNTIME_DIR_POSIX_MODE)
            else:
                os.mkdir(
                    path.name,
                    RUNTIME_DIR_POSIX_MODE,
                    dir_fd=parent_descriptor,
                )
                os.fsync(parent_descriptor)
        except FileExistsError:
            pass
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
    if os.name == "nt":
        metadata = os.lstat(path)
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
            raise RuntimeError(
                "sandbox controller state path is not a real directory"
            )
        _set_windows_owner_only_acl(path, directory=True)
        secured = os.lstat(path)
        if (
            not stat.S_ISDIR(secured.st_mode)
            or _is_reparse_point(secured)
            or (secured.st_dev, secured.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(
                "sandbox controller state directory changed during ACL "
                "normalization"
            )
    descriptor = _open_private_directory(path, normalize_mode=True)
    if descriptor >= 0:
        os.close(descriptor)


def _private_file_metadata_is_safe(
    metadata: os.stat_result,
    expected_size: int,
) -> bool:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size != expected_size
        or metadata.st_nlink != 1
    ):
        return False
    if hasattr(os, "geteuid"):
        return (
            metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
        )
    return True


def _write_private_file_atomic(
    path: Path,
    payload: bytes,
) -> tuple[int, int]:
    """Atomically replace a small private runtime file without following links."""
    if not path.name or path.name in {".", ".."}:
        raise RuntimeError("sandbox controller state path is invalid")
    parent_descriptor = _open_private_directory(path.parent)
    temporary_name = (
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    temporary_path = path.parent / temporary_name
    descriptor = -1
    temporary_created = False
    installed = False
    try:
        open_target: str | Path
        open_options: dict[str, int]
        if os.name == "nt":
            open_target = temporary_path
            open_options = {}
        else:
            open_target = temporary_name
            open_options = {"dir_fd": parent_descriptor}
        descriptor = os.open(
            open_target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            **open_options,
        )
        temporary_created = True
        _write_all(descriptor, payload)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if not _private_file_metadata_is_safe(opened, len(payload)):
            raise RuntimeError(
                "sandbox controller temporary state file is unsafe"
            )
        if os.name == "nt":
            os.close(descriptor)
            descriptor = -1
            _set_windows_owner_only_acl(
                temporary_path,
                directory=False,
            )
            final_temporary = os.lstat(temporary_path)
            if (
                not _private_file_metadata_is_safe(
                    final_temporary,
                    len(payload),
                )
                or (final_temporary.st_dev, final_temporary.st_ino)
                != (opened.st_dev, opened.st_ino)
            ):
                raise RuntimeError(
                    "sandbox controller temporary state file changed "
                    "during ACL validation"
                )

        if os.name == "nt":
            os.replace(temporary_path, path)
        else:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        installed = True
        if parent_descriptor >= 0:
            os.fsync(parent_descriptor)

        if os.name == "nt":
            final_path = os.lstat(path)
        else:
            final_path = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        if not _private_file_metadata_is_safe(final_path, len(payload)):
            raise RuntimeError(
                "sandbox controller state file is unsafe after publication"
            )
        if (final_path.st_dev, final_path.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise RuntimeError(
                "sandbox controller state file changed during publication"
            )
        if descriptor >= 0:
            final_opened = os.fstat(descriptor)
            if (final_opened.st_dev, final_opened.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise RuntimeError(
                    "sandbox controller state descriptor changed "
                    "during publication"
                )
        _verify_windows_owner_only_acl(path)
        published_path = os.lstat(path)
        if (
            not _private_file_metadata_is_safe(
                published_path,
                len(payload),
            )
            or (published_path.st_dev, published_path.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(
                "sandbox controller state file changed during ACL validation"
            )
        return opened.st_dev, opened.st_ino
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not installed and temporary_created:
            try:
                if os.name == "nt":
                    temporary_path.unlink()
                else:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _unlink_private_file_if_payload(
    path: Path,
    expected: bytes,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> bool:
    """Unlink one private file only while it still contains expected bytes."""
    if (
        not path.name
        or path.name in {".", ".."}
        or not expected
    ):
        return False
    parent_descriptor = _open_private_directory(path.parent)
    descriptor = -1
    try:
        try:
            if os.name == "nt":
                metadata = os.lstat(path)
                open_target: str | Path = path
                open_options: dict[str, int] = {}
            else:
                metadata = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                open_target = path.name
                open_options = {"dir_fd": parent_descriptor}
        except FileNotFoundError:
            return False
        if (
            not _private_file_metadata_is_safe(metadata, len(expected))
            or (
                expected_identity is not None
                and (metadata.st_dev, metadata.st_ino)
                != expected_identity
            )
        ):
            return False
        _verify_windows_owner_only_acl(path)
        descriptor = os.open(
            open_target,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            **open_options,
        )
        opened = os.fstat(descriptor)
        if (
            not _private_file_metadata_is_safe(opened, len(expected))
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            return False
        chunks: list[bytes] = []
        total = 0
        while total <= len(expected):
            chunk = os.read(
                descriptor,
                min(65536, len(expected) + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        if not hmac.compare_digest(payload, expected):
            return False
        final_opened = os.fstat(descriptor)
        if os.name == "nt":
            final_path = os.lstat(path)
        else:
            final_path = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        if (
            not _private_file_metadata_is_safe(final_opened, len(expected))
            or not _private_file_metadata_is_safe(final_path, len(expected))
            or (final_opened.st_dev, final_opened.st_ino)
            != (opened.st_dev, opened.st_ino)
            or (final_path.st_dev, final_path.st_ino)
            != (opened.st_dev, opened.st_ino)
            or (
                expected_identity is not None
                and (final_path.st_dev, final_path.st_ino)
                != expected_identity
            )
        ):
            return False
        if os.name == "nt":
            # Windows does not allow this portable descriptor to be deleted
            # while open. The private, owner-only parent prevents replacement
            # by a less-privileged process during this close/unlink window.
            os.close(descriptor)
            descriptor = -1
            final_path = os.lstat(path)
            if (
                not _private_file_metadata_is_safe(
                    final_path,
                    len(expected),
                )
                or (final_path.st_dev, final_path.st_ino)
                != (opened.st_dev, opened.st_ino)
            ):
                return False
            path.unlink()
        else:
            os.unlink(path.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        return True
    except FileNotFoundError:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _auth_nonce_state_path() -> Path | None:
    if CONFIG is None:
        return None
    return CONFIG.runtime_dir / "control-auth-nonces.json"


def _persist_auth_nonce_state_locked() -> bool:
    path = _auth_nonce_state_path()
    if path is None:
        return True
    try:
        _write_json_atomic(
            path,
            {
                "version": 1,
                "nonces": [
                    {"nonce": nonce, "expires_at": expires_at}
                    for nonce, expires_at in _auth_nonces.items()
                ],
            },
        )
    except (OSError, RuntimeError):
        return False
    return True


def _load_auth_nonce_state(now: float | None = None) -> bool:
    path = _auth_nonce_state_path()
    current_time = time.time() if now is None else now
    with _auth_nonce_lock:
        _auth_nonces.clear()
        if path is None:
            return True
        try:
            payload = _read_runtime_file_no_follow(
                path,
                AUTH_NONCE_STATE_MAX_BYTES,
            )
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            data = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
            )
        except (UnicodeError, ValueError):
            return False
        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or not isinstance(data.get("nonces"), list)
            or len(data["nonces"]) > AUTH_NONCE_LIMIT
        ):
            return False
        for entry in data["nonces"]:
            if not isinstance(entry, dict):
                return False
            nonce = entry.get("nonce")
            expires_at = entry.get("expires_at")
            if (
                not isinstance(nonce, str)
                or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or not isinstance(expires_at, (int, float))
                or isinstance(expires_at, bool)
            ):
                return False
            if float(expires_at) > current_time:
                _auth_nonces[nonce] = float(expires_at)
        return _persist_auth_nonce_state_locked()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(
            _read_runtime_file_no_follow(
                path,
                AUTH_NONCE_STATE_MAX_BYTES,
            ).decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        return data if isinstance(data, dict) else {}
    except (OSError, UnicodeError, ValueError):
        return {}


def _lexical_absolute_path(value: str | os.PathLike[str]) -> Path:
    """Make a path absolute without resolving its final filesystem object."""
    return Path(os.path.abspath(os.fspath(value)))


def _validate_control_token_runtime(runtime_dir: Path, token_path: Path) -> None:
    if (
        not runtime_dir.is_absolute()
        or not token_path.is_absolute()
        or _lexical_absolute_path(runtime_dir) != runtime_dir
        or _lexical_absolute_path(token_path) != token_path
        or token_path != runtime_dir / "control-token"
    ):
        raise RuntimeError(
            "sandbox control token must be the lexical control-token child "
            "of the absolute runtime directory"
        )

    metadata = os.lstat(runtime_dir)
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise RuntimeError("sandbox runtime path must be a real directory")
    if hasattr(os, "geteuid"):
        if metadata.st_uid != os.geteuid():
            raise RuntimeError(
                "sandbox runtime directory must be owned by the controller user"
            )
        if stat.S_IMODE(metadata.st_mode) != RUNTIME_DIR_POSIX_MODE:
            raise RuntimeError("sandbox runtime directory must have mode 0700")
    _verify_windows_owner_only_acl(runtime_dir)


def _verify_windows_owner_only_acl(path: Path) -> None:
    """Recheck the launcher-enforced owner-only Windows DACL."""
    if os.name != "nt":
        return
    powershell = _windows_powershell()
    if not powershell:
        raise RuntimeError(
            "PowerShell is required to verify the sandbox control token ACL"
        )
    check_script = (
        "$ErrorActionPreference='Stop';"
        "$acl=Get-Acl -LiteralPath $env:SECAI_CONTROL_ACL_TARGET;"
        "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;"
        "$owner=$acl.GetOwner("
        "[System.Security.Principal.SecurityIdentifier]);"
        "$rules=@($acl.GetAccessRules("
        "$true,$true,[System.Security.Principal.SecurityIdentifier]));"
        "if(-not $acl.AreAccessRulesProtected"
        " -or $owner.Value -ne $sid.Value"
        " -or $rules.Count -ne 1"
        " -or $rules[0].IdentityReference.Value -ne $sid.Value"
        " -or $rules[0].AccessControlType -ne "
        "[System.Security.AccessControl.AccessControlType]::Allow"
        " -or (($rules[0].FileSystemRights -band "
        "[System.Security.AccessControl.FileSystemRights]::FullControl)"
        " -ne [System.Security.AccessControl.FileSystemRights]::FullControl)"
        "){exit 1};"
        "exit 0"
    )
    child_env = os.environ.copy()
    child_env["SECAI_CONTROL_ACL_TARGET"] = str(path)
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                check_script,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_env,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "failed to verify the sandbox control token ACL"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            "sandbox control token paths must have owner-only Windows ACLs"
        )


def _set_windows_owner_only_acl(path: Path, *, directory: bool) -> None:
    """Protect a Windows path with one current-owner FullControl ACE."""
    if os.name != "nt":
        return
    powershell = _windows_powershell()
    if not powershell:
        raise RuntimeError(
            "PowerShell is required to secure sandbox controller paths"
        )
    if directory:
        security_type = (
            "[System.Security.AccessControl.DirectorySecurity]::new()"
        )
        inheritance = (
            "[System.Security.AccessControl.InheritanceFlags]::"
            "ContainerInherit -bor "
            "[System.Security.AccessControl.InheritanceFlags]::"
            "ObjectInherit"
        )
        rule = (
            "[System.Security.AccessControl.FileSystemAccessRule]::new("
            "$sid,"
            "[System.Security.AccessControl.FileSystemRights]::FullControl,"
            f"({inheritance}),"
            "[System.Security.AccessControl.PropagationFlags]::None,"
            "[System.Security.AccessControl.AccessControlType]::Allow)"
        )
    else:
        security_type = (
            "[System.Security.AccessControl.FileSecurity]::new()"
        )
        rule = (
            "[System.Security.AccessControl.FileSystemAccessRule]::new("
            "$sid,"
            "[System.Security.AccessControl.FileSystemRights]::FullControl,"
            "[System.Security.AccessControl.AccessControlType]::Allow)"
        )
    script = (
        "$ErrorActionPreference='Stop';"
        "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;"
        f"$acl={security_type};"
        "$acl.SetOwner($sid);"
        "$acl.SetAccessRuleProtection($true,$false);"
        f"$rule={rule};"
        "[void]$acl.AddAccessRule($rule);"
        "Set-Acl -LiteralPath $env:SECAI_CONTROL_ACL_TARGET "
        "-AclObject $acl;"
    )
    child_env = os.environ.copy()
    child_env["SECAI_CONTROL_ACL_TARGET"] = str(path)
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_env,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(
            "failed to secure the sandbox controller Windows ACL"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            "failed to secure the sandbox controller Windows ACL"
        )
    _verify_windows_owner_only_acl(path)


def _control_token_metadata_is_safe(metadata: os.stat_result) -> bool:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size != CONTROL_TOKEN_BYTES
        or metadata.st_nlink != 1
    ):
        return False
    if hasattr(os, "geteuid"):
        return (
            metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == CONTROL_TOKEN_POSIX_MODE
        )
    return True


def _load_control_token(runtime_dir: Path, token_path: Path) -> str:
    """Securely load one exact control token without following links."""
    _validate_control_token_runtime(runtime_dir, token_path)
    _verify_windows_owner_only_acl(token_path)
    metadata = os.lstat(token_path)
    if not _control_token_metadata_is_safe(metadata):
        raise RuntimeError(
            "sandbox control token must be an owner-controlled, mode-0604, "
            "singly linked real 64-byte regular file"
        )

    descriptor = os.open(
        token_path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not _control_token_metadata_is_safe(opened)
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(
                "sandbox control token changed during validation"
            )
        chunks: list[bytes] = []
        total = 0
        while total <= CONTROL_TOKEN_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, CONTROL_TOKEN_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        if len(payload) != CONTROL_TOKEN_BYTES:
            raise RuntimeError(
                "sandbox control token must contain exactly 64 bytes"
            )
        final_opened = os.fstat(descriptor)
        final_path = os.lstat(token_path)
        if (
            not _control_token_metadata_is_safe(final_opened)
            or not _control_token_metadata_is_safe(final_path)
            or (final_opened.st_dev, final_opened.st_ino)
            != (opened.st_dev, opened.st_ino)
            or (final_path.st_dev, final_path.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(
                "sandbox control token changed while it was being read"
            )
    finally:
        os.close(descriptor)

    _verify_windows_owner_only_acl(token_path)
    final_path = os.lstat(token_path)
    if (
        not _control_token_metadata_is_safe(final_path)
        or (final_path.st_dev, final_path.st_ino)
        != (metadata.st_dev, metadata.st_ino)
    ):
        raise RuntimeError(
            "sandbox control token changed during ACL validation"
        )
    try:
        token = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "sandbox control token must contain lowercase hexadecimal"
        ) from exc
    if not _valid_control_token(token):
        raise RuntimeError(
            "sandbox control token must contain exactly 64 lowercase "
            "hexadecimal characters"
        )
    return token


def _read_runtime_file_no_follow(path: Path, maximum_size: int) -> bytes:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size > maximum_size
        or metadata.st_nlink != 1
    ):
        raise OSError("runtime file is not a safe regular file")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or opened.st_size > maximum_size
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise OSError("runtime file changed during validation")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_size:
            chunk = os.read(
                descriptor,
                min(65536, maximum_size + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_size:
            raise OSError("runtime file exceeds the size limit")
        payload = b"".join(chunks)
        final_opened = os.fstat(descriptor)
        final_path = os.lstat(path)
        if (
            not stat.S_ISREG(final_opened.st_mode)
            or _is_reparse_point(final_opened)
            or final_opened.st_size > maximum_size
            or final_opened.st_nlink != 1
            or not stat.S_ISREG(final_path.st_mode)
            or _is_reparse_point(final_path)
            or final_path.st_size > maximum_size
            or final_path.st_nlink != 1
            or (final_opened.st_dev, final_opened.st_ino)
            != (opened.st_dev, opened.st_ino)
            or (final_path.st_dev, final_path.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise OSError("runtime file changed while it was being read")
        return payload
    finally:
        os.close(descriptor)


def _active_generation(runtime_dir: Path) -> str:
    payload = _read_runtime_file_no_follow(
        runtime_dir / "active-generation",
        64,
    )
    generation = payload.decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}", generation):
        raise OSError("active generation is malformed")
    generations_dir = runtime_dir / "generations"
    parent_metadata = os.lstat(generations_dir)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or _is_reparse_point(parent_metadata)
    ):
        raise OSError("runtime generations directory is unsafe")
    generation_dir = generations_dir / generation
    metadata = os.lstat(generation_dir)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse_point(metadata)
        or (
            hasattr(os, "geteuid")
            and (
                metadata.st_uid != os.geteuid()
                or bool(metadata.st_mode & 0o222)
            )
        )
    ):
        raise OSError("active generation directory is unsafe")
    return generation


def _ready_marker(
    runtime_dir: Path,
    marker_name: str,
    description: str,
) -> str:
    if marker_name not in {"ready-generation", "ready-session"}:
        raise ValueError("unsupported runtime readiness marker")
    status_dir = runtime_dir / "generation-status"
    metadata = os.lstat(status_dir)
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise OSError("runtime generation status directory is unsafe")
    if hasattr(os, "geteuid") and (
        metadata.st_uid != os.geteuid()
        or bool(metadata.st_mode & 0o022)
    ):
        raise OSError("runtime generation status directory is unsafe")
    marker_path = status_dir / marker_name
    marker_metadata = os.lstat(marker_path)
    if hasattr(os, "geteuid") and (
        marker_metadata.st_uid != os.geteuid()
        or bool(marker_metadata.st_mode & 0o022)
    ):
        raise OSError(f"{description} marker is unsafe")
    payload = _read_runtime_file_no_follow(
        marker_path,
        64,
    )
    final_status = os.lstat(status_dir)
    final_marker = os.lstat(marker_path)
    if (
        (final_status.st_dev, final_status.st_ino)
        != (metadata.st_dev, metadata.st_ino)
        or (final_marker.st_dev, final_marker.st_ino)
        != (marker_metadata.st_dev, marker_metadata.st_ino)
        or (
            hasattr(os, "geteuid")
            and (
                final_status.st_uid != os.geteuid()
                or bool(final_status.st_mode & 0o022)
                or final_marker.st_uid != os.geteuid()
                or bool(final_marker.st_mode & 0o022)
            )
        )
    ):
        raise OSError(f"{description} state changed while being read")
    value = payload.decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise OSError(f"{description} is malformed")
    return value


def _ready_generation(runtime_dir: Path) -> str:
    return _ready_marker(
        runtime_dir,
        "ready-generation",
        "ready generation",
    )


def _ready_session(runtime_dir: Path) -> str:
    return _ready_marker(
        runtime_dir,
        "ready-session",
        "ready session",
    )


def _read_immutable_generation_file(path: Path, maximum_size: int) -> bytes:
    metadata = os.lstat(path)
    if hasattr(os, "geteuid") and (
        metadata.st_uid != os.geteuid()
        or bool(metadata.st_mode & 0o222)
    ):
        raise OSError("runtime generation file is not immutable")
    payload = _read_runtime_file_no_follow(path, maximum_size)
    final_metadata = os.lstat(path)
    if (
        (final_metadata.st_dev, final_metadata.st_ino)
        != (metadata.st_dev, metadata.st_ino)
        or (
            hasattr(os, "geteuid")
            and (
                final_metadata.st_uid != os.geteuid()
                or bool(final_metadata.st_mode & 0o222)
            )
        )
    ):
        raise OSError("runtime generation file changed while being read")
    return payload


def _profile_matches_generation_manifest(
    generation: str,
    profile_payload: bytes,
    manifest_payload: bytes,
) -> bool:
    try:
        manifest = json.loads(
            manifest_payload.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, ValueError):
        return False
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"files", "generation", "version"}
        or manifest.get("generation") != generation
        or manifest.get("version") != RUNTIME_GENERATION_FORMAT
        or isinstance(manifest.get("version"), bool)
        or not isinstance(manifest.get("files"), list)
        or not 1 <= len(manifest["files"]) <= MAX_GENERATION_MANIFEST_ENTRIES
    ):
        return False

    seen_paths: set[str] = set()
    profile_entry: dict[str, Any] | None = None
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size",
        }:
            return False
        relative_path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or relative_path in seen_paths
            or Path(relative_path).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(relative_path).parts)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            return False
        seen_paths.add(relative_path)
        if relative_path == "profile.json":
            profile_entry = entry

    return bool(
        profile_entry is not None
        and profile_entry["size"] == len(profile_payload)
        and hmac.compare_digest(
            profile_entry["sha256"],
            hashlib.sha256(profile_payload).hexdigest(),
        )
    )


def _current_profile() -> str:
    if CONFIG is None:
        return UNKNOWN_PROFILE
    try:
        server_session = _read_session()
        if not _valid_session_id(server_session):
            return UNKNOWN_PROFILE
        ready_session = _ready_session(CONFIG.runtime_dir)
        ready_generation = _ready_generation(CONFIG.runtime_dir)
        generation = _active_generation(CONFIG.runtime_dir)
        if (
            ready_session != server_session
            or ready_generation != generation
        ):
            return UNKNOWN_PROFILE
        generation_dir = (
            CONFIG.runtime_dir
            / "generations"
            / generation
        )
        profile_payload = _read_immutable_generation_file(
            generation_dir / "profile.json",
            4096,
        )
        manifest_payload = _read_immutable_generation_file(
            generation_dir / "generation.json",
            MAX_GENERATION_MANIFEST_BYTES,
        )
        if not _profile_matches_generation_manifest(
            generation,
            profile_payload,
            manifest_payload,
        ):
            return UNKNOWN_PROFILE
        # Re-read each atomic pointer in publication order after the immutable
        # generation files. A concurrent publication, controller restart, or
        # readiness transition is never reported as active.
        if (
            _active_generation(CONFIG.runtime_dir) != generation
            or _ready_generation(CONFIG.runtime_dir) != generation
            or _ready_session(CONFIG.runtime_dir) != server_session
            or _read_session() != server_session
        ):
            return UNKNOWN_PROFILE
        parsed = json.loads(
            profile_payload.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        if not isinstance(parsed, dict) or set(parsed) != {"active"}:
            return UNKNOWN_PROFILE
    except (OSError, UnicodeError, ValueError):
        return UNKNOWN_PROFILE
    profile = parsed.get("active")
    return (
        profile
        if isinstance(profile, str) and profile in VALID_PROFILES
        else UNKNOWN_PROFILE
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _host_gpu_backend() -> str:
    configured = os.getenv("SECAI_DIFFUSION_COMPUTE", "").strip().lower()
    if configured in {"cuda", "rocm"}:
        return configured
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            probe = subprocess.run(
                [nvidia_smi, "-L"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if probe.returncode == 0:
                return "cuda"
        except (OSError, subprocess.SubprocessError):
            pass
    if Path("/dev/kfd").exists():
        return "rocm"
    return ""


def _gpu_requested(payload: dict[str, Any], profile: str) -> tuple[bool, str]:
    if profile != "full_lab":
        return False, ""
    raw = payload.get("gpu", "auto")
    if isinstance(raw, bool):
        enabled = raw
    else:
        value = str(raw).strip().lower()
        if value in {"false", "0", "no", "off", "none"}:
            return False, ""
        enabled = value in {"true", "1", "yes", "on", "auto", "cuda", "rocm"}
        if value in {"cuda", "rocm"}:
            return enabled, value
    if not enabled:
        return False, ""
    backend = _host_gpu_backend()
    if backend:
        return True, backend
    return False, ""


def _status(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    if CONFIG is None:
        return {
            "status": "unconfigured",
            "profile": UNKNOWN_PROFILE,
            "profile_state": "degraded",
        }
    data = _read_json(CONFIG.status_path)
    # Older controller versions persisted launcher output. Never return it:
    # subprocess output can echo environment values or credential paths.
    data.pop("output_tail", None)
    if not data:
        data = {"status": "idle"}
    if data.get("status") == "running" and (
        _active_thread is None or not _active_thread.is_alive()
    ):
        data.update({
            "status": "failed",
            "error": "previous sandbox automation was interrupted",
            "detail": (
                "The controller restarted before the previous sandbox change "
                "reported completion. You can retry the request."
            ),
            "updated_at": _now(),
        })
        _write_json_atomic(CONFIG.status_path, data)
    current_profile = _current_profile()
    data.update({
        "profile": current_profile,
        "profile_state": (
            "active" if current_profile in VALID_PROFILES else "degraded"
        ),
        "valid_profiles": sorted(VALID_PROFILES),
        "controller": "secai-sandbox-control",
        "protocol_version": CONTROL_PROTOCOL_VERSION,
        "state_protocol_version": CONTROL_STATE_PROTOCOL_VERSION,
        "gpu_backend": _host_gpu_backend() or None,
    })
    if extra:
        data.update(extra)
    return data


def _display_command(profile: str, *, inference: bool, gpu: bool) -> str:
    args = list(PROFILE_ARGS[profile])
    if inference:
        args.append("--with-inference")
    if gpu and "--with-gpu" not in args:
        args.append("--with-gpu")
    return ".\\secai-sandbox.cmd start" + ((" " + " ".join(args)) if args else "")


def _command_args(profile: str, *, inference: bool, gpu: bool) -> list[str]:
    args = list(PROFILE_ARGS[profile])
    if inference and "--with-inference" not in args:
        args.append("--with-inference")
    if gpu and "--with-gpu" not in args:
        args.append("--with-gpu")
    if os.name == "nt":
        if CONFIG is None:
            raise RuntimeError("controller is not configured")
        powershell = _windows_powershell()
        if not powershell:
            raise RuntimeError("PowerShell is required by the sandbox controller")
        start_script = CONFIG.repo_root / "scripts" / "sandbox" / "start.ps1"
        return [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(start_script),
            *[PS_SWITCHES[arg] for arg in args],
        ]
    if CONFIG is None:
        raise RuntimeError("controller is not configured")
    start_script = CONFIG.repo_root / "scripts" / "sandbox" / "start.sh"
    return [str(start_script), *args]


def _validate_model_filename(value: object) -> str:
    if value in (None, ""):
        return ""
    filename = str(value)
    if "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise ValueError("invalid model filename")
    if not SAFE_MODEL_RE.match(filename):
        raise ValueError("model filename must be a single .gguf registry filename")
    return filename


def _is_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT
    )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("file write made no progress")
        view = view[written:]


def _restrict_windows_file_acl(path: Path) -> None:
    _set_windows_owner_only_acl(path, directory=False)


def _read_env_file_safely(
    path: Path,
) -> tuple[list[str], os.stat_result | None]:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return [], None
    except OSError as exc:
        raise RuntimeError("sandbox .env metadata could not be read") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse_point(metadata)
        or metadata.st_size > MAX_ENV_FILE_BYTES
    ):
        raise RuntimeError("sandbox .env must be a bounded real regular file")

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError("sandbox .env changed during validation")
        chunks: list[bytes] = []
        remaining = MAX_ENV_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_ENV_FILE_BYTES:
            raise RuntimeError("sandbox .env exceeds the maximum supported size")
        text = payload.decode("utf-8", errors="strict")
        if "\x00" in text:
            raise RuntimeError("sandbox .env contains a NUL byte")
    except UnicodeDecodeError as exc:
        raise RuntimeError("sandbox .env must be valid UTF-8") from exc
    except OSError as exc:
        raise RuntimeError("sandbox .env could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return text.splitlines(), metadata


def _set_env_value(path: Path, key: str, value: str) -> None:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
        raise ValueError("invalid sandbox environment key")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError("invalid sandbox environment value")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = os.lstat(path.parent)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or _is_reparse_point(parent_metadata)
    ):
        raise RuntimeError("sandbox .env parent must be a real directory")

    lines, original = _read_env_file_safely(path)
    replacement = f"{key}={value}"
    lines = [line for line in lines if not line.startswith(f"{key}=")]
    lines.append(replacement)
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        _write_all(descriptor, payload)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _restrict_windows_file_acl(temporary)

        if original is None:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise RuntimeError(
                    "sandbox .env appeared during atomic creation"
                ) from exc
            temporary.unlink()
        else:
            current = os.lstat(path)
            if (
                not stat.S_ISREG(current.st_mode)
                or _is_reparse_point(current)
                or (current.st_dev, current.st_ino)
                != (original.st_dev, original.st_ino)
            ):
                raise RuntimeError("sandbox .env changed before atomic replacement")
            os.replace(temporary, path)
        _fsync_directory(path.parent)
        _verify_windows_owner_only_acl(path)
    except OSError as exc:
        raise RuntimeError("sandbox .env could not be updated atomically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _popen_kwargs() -> dict[str, Any]:
    if _running_on_windows():
        return {
            "creationflags": (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | WINDOWS_CREATE_SUSPENDED
            ),
        }
    return {"start_new_session": True}


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(
    proc: subprocess.Popen[str],
    process_group_id: int,
    timeout: float,
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        proc.poll()
        if not _process_group_exists(process_group_id):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _terminate_suspended_windows_process(
    proc: subprocess.Popen[str],
) -> bool:
    """Terminate a never-resumed process that cannot have spawned children."""
    try:
        proc.kill()
        proc.wait(timeout=PROCESS_KILL_TIMEOUT_SECONDS)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _terminate_process_tree(
    proc: subprocess.Popen[str],
    windows_job: _WindowsJob | None = None,
) -> bool:
    with _termination_lock:
        if _tree_termination_confirmed.is_set():
            return True
        if _running_on_windows():
            if windows_job is None:
                with _state_lock:
                    if _active_process is proc:
                        windows_job = _active_windows_job
            if windows_job is None:
                _tree_containment_failed.set()
                return False
            try:
                confirmed = windows_job.terminate_and_wait(
                    PROCESS_KILL_TIMEOUT_SECONDS
                )
            except (OSError, RuntimeError):
                _tree_containment_failed.set()
                return False
            if confirmed:
                proc.poll()
                _tree_termination_confirmed.set()
            else:
                _tree_containment_failed.set()
            return confirmed

        process_group_id = proc.pid
        if not _process_group_exists(process_group_id):
            proc.poll()
            _tree_termination_confirmed.set()
            return True
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            _tree_termination_confirmed.set()
            return True
        except PermissionError:
            _tree_containment_failed.set()
            return False
        if _wait_for_process_group_exit(
            proc,
            process_group_id,
            PROCESS_TERM_GRACE_SECONDS,
        ):
            _tree_termination_confirmed.set()
            return True
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            _tree_termination_confirmed.set()
            return True
        except PermissionError:
            _tree_containment_failed.set()
            return False
        confirmed = _wait_for_process_group_exit(
            proc,
            process_group_id,
            PROCESS_KILL_TIMEOUT_SECONDS,
        )
        if confirmed:
            _tree_termination_confirmed.set()
        else:
            _tree_containment_failed.set()
        return confirmed


def _run_start_command(
    command: list[str],
    *,
    child_env_overrides: dict[str, str] | None = None,
) -> tuple[int, bool, bool, bool]:
    global _active_process, _active_windows_job
    _tree_containment_failed.clear()
    _tree_termination_confirmed.clear()
    child_env = os.environ.copy()
    if CONFIG is not None and CONFIG.runtime in {"docker", "podman"}:
        child_env["SECAI_CONTAINER_RUNTIME"] = CONFIG.runtime
    if child_env_overrides:
        child_env.update(child_env_overrides)

    windows_job = _WindowsJob.create() if _running_on_windows() else None
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(CONFIG.repo_root) if CONFIG is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            env=child_env,
            **_popen_kwargs(),
        )
    except Exception as exc:
        if windows_job is not None and not _close_windows_job(windows_job):
            raise RuntimeError(
                "failed to close the unused Windows containment job"
            ) from exc
        raise

    if windows_job is not None:
        assigned = False
        try:
            windows_job.assign(proc)
            assigned = True
            if _shutdown_requested.is_set():
                contained = windows_job.terminate_and_wait(
                    PROCESS_KILL_TIMEOUT_SECONDS
                )
                if not contained:
                    _tree_containment_failed.set()
                proc.poll()
                contained = _close_windows_job(windows_job) and contained
                return (
                    proc.returncode if proc.returncode is not None else -1,
                    False,
                    True,
                    contained,
                )
            windows_job.resume(proc)
        except Exception as exc:
            if assigned:
                try:
                    contained = windows_job.terminate_and_wait(
                        PROCESS_KILL_TIMEOUT_SECONDS
                    )
                except (OSError, RuntimeError):
                    contained = False
            else:
                contained = _terminate_suspended_windows_process(proc)
            closed = _close_windows_job(windows_job)
            if not contained or not closed:
                _tree_containment_failed.set()
            raise RuntimeError(
                "sandbox start process could not enter verified Windows containment"
            ) from exc

    with _state_lock:
        cancelled = _shutdown_requested.is_set()
        if not cancelled:
            _active_process = proc
            _active_windows_job = windows_job
    if cancelled:
        contained = _terminate_process_tree(proc, windows_job)
        if windows_job is not None:
            contained = _close_windows_job(windows_job) and contained
        return (
            proc.returncode if proc.returncode is not None else -1,
            False,
            True,
            contained,
        )

    deadline = time.monotonic() + APPLY_TIMEOUT_SECONDS
    timed_out = False
    cancelled = False
    contained = True
    try:
        while proc.poll() is None:
            if _shutdown_requested.is_set():
                cancelled = True
                contained = _terminate_process_tree(proc, windows_job)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                contained = _terminate_process_tree(proc, windows_job)
                break
            try:
                proc.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if windows_job is not None:
            with _termination_lock:
                if contained:
                    try:
                        contained = windows_job.terminate_and_wait(
                            PROCESS_KILL_TIMEOUT_SECONDS
                        )
                    except (OSError, RuntimeError):
                        contained = False
                if contained:
                    _tree_termination_confirmed.set()
                else:
                    _tree_containment_failed.set()
                with _state_lock:
                    if _active_process is proc:
                        _active_process = None
                    if _active_windows_job is windows_job:
                        _active_windows_job = None
                if not _close_windows_job(windows_job):
                    contained = False
        else:
            with _state_lock:
                if _active_process is proc:
                    _active_process = None
    return (
        proc.returncode if proc.returncode is not None else -1,
        timed_out,
        cancelled,
        contained,
    )


def _run_apply(
    *,
    profile: str,
    inference: bool,
    gpu: bool,
    gpu_backend: str,
    model_filename: str,
    requested_by: str,
) -> None:
    if CONFIG is None:
        return
    child_env_overrides = {
        "SECAI_DIFFUSION_COMPUTE": gpu_backend if gpu and gpu_backend else "cpu",
        "SECAI_DIFFUSION_DEVICE_PREFERENCE": (
            "auto" if gpu and gpu_backend else "cpu"
        ),
        "SECAI_DIFFUSION_CPU_OFFLOAD": "0",
    }
    command = _command_args(profile, inference=inference, gpu=gpu)
    display = _display_command(profile, inference=inference, gpu=gpu)
    started = _now()
    _write_json_atomic(CONFIG.status_path, {
        "status": "running",
        "profile": profile,
        "inference": inference,
        "gpu": gpu,
        "gpu_backend": gpu_backend,
        "model_filename": model_filename,
        "requested_by": requested_by,
        "command": display,
        "started_at": started,
        "updated_at": started,
    })
    if inference and model_filename:
        _set_env_value(
            CONFIG.env_path,
            "SECAI_INFERENCE_MODEL_PATH",
            f"/var/lib/secure-ai/registry/{model_filename}",
        )
    try:
        returncode, timed_out, cancelled, contained = _run_start_command(
            command,
            child_env_overrides=child_env_overrides,
        )
        finished = _now()
        _write_json_atomic(CONFIG.status_path, {
            "status": (
                "complete"
                if (
                    returncode == 0
                    and not timed_out
                    and not cancelled
                    and contained
                )
                else "failed"
            ),
            "profile": profile,
            "inference": inference,
            "gpu": gpu,
            "gpu_backend": gpu_backend,
            "model_filename": model_filename,
            "requested_by": requested_by,
            "command": display,
            "exit_code": returncode,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "process_tree_contained": contained,
            "error": (
                "sandbox start process tree could not be terminated safely"
                if not contained
                else (
                    "sandbox start command cancelled for controller shutdown"
                    if cancelled
                    else (
                        f"sandbox start command timed out after {APPLY_TIMEOUT_SECONDS}s"
                        if timed_out
                        else (
                            "sandbox start command failed; rerun the host launcher "
                            "directly for diagnostic output"
                            if returncode != 0
                            else ""
                        )
                    )
                )
            ),
            "started_at": started,
            "finished_at": finished,
            "updated_at": finished,
        })
    except Exception as exc:
        finished = _now()
        _write_json_atomic(CONFIG.status_path, {
            "status": "failed",
            "profile": profile,
            "inference": inference,
            "gpu": gpu,
            "gpu_backend": gpu_backend,
            "model_filename": model_filename,
            "requested_by": requested_by,
            "command": display,
            "error": str(exc),
            "started_at": started,
            "finished_at": finished,
            "updated_at": finished,
        })


def _start_apply(payload: dict[str, Any], requested_by: str) -> tuple[dict[str, Any], int]:
    global _active_thread
    profile = str(payload.get("profile") or _current_profile())
    if profile not in VALID_PROFILES:
        return {"error": f"invalid profile: {profile}"}, 400
    inference = bool(payload.get("inference", False))
    gpu, gpu_backend = _gpu_requested(payload, profile)
    try:
        model_filename = _validate_model_filename(payload.get("model_filename"))
    except ValueError as exc:
        return {"error": str(exc)}, 400

    with _state_lock:
        if _shutdown_requested.is_set():
            return {
                "status": "stopping",
                "detail": "The sandbox controller is shutting down.",
            }, 503
        if _tree_containment_failed.is_set():
            return {
                "status": "containment_failed",
                "detail": (
                    "A previous sandbox process tree could not be terminated "
                    "safely. Stop it from the host before retrying."
                ),
            }, 503
        if _active_thread is not None and _active_thread.is_alive():
            return {
                "status": "already_in_progress",
                "detail": (
                    "A sandbox profile change is already running. "
                    "Wait for it to finish, then retry if the UI does not reconnect."
                ),
                **_status(),
            }, 409
        _active_thread = threading.Thread(
            target=_run_apply,
            kwargs={
                "profile": profile,
                "inference": inference,
                "gpu": gpu,
                "gpu_backend": gpu_backend,
                "model_filename": model_filename,
                "requested_by": requested_by,
            },
            daemon=False,
        )
        _active_thread.start()

    return {
        "status": "accepted",
        "profile": profile,
        "inference": inference,
        "gpu": gpu,
        "gpu_backend": gpu_backend or None,
        "model_filename": model_filename,
        "command": _display_command(profile, inference=inference, gpu=gpu),
    }, 202


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = CONTROL_CONNECTION_LIMIT

    def __init__(self, server_address: tuple[str, int], handler_class: type) -> None:
        self._connection_slots = threading.BoundedSemaphore(
            CONTROL_CONNECTION_LIMIT
        )
        super().__init__(server_address, handler_class)

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        # A peer can disconnect at any response boundary. Avoid turning those
        # host-local disconnects into attacker-amplifiable traceback logs.
        return


class _BoundedHeaderReader:
    def __init__(self, stream: Any, byte_limit: int) -> None:
        self._stream = stream
        self._remaining = byte_limit

    def readline(self, size: int = -1) -> bytes:
        # Read at most one byte past the aggregate ceiling so parse_headers
        # cannot allocate its much larger standard-library maximum first.
        bounded_size = self._remaining + 1
        if size >= 0:
            bounded_size = min(size, bounded_size)
        line = self._stream.readline(bounded_size)
        self._remaining -= len(line)
        if self._remaining < 0:
            raise http.client.LineTooLong(
                f"aggregate request headers exceed {MAX_HEADER_BYTES} bytes"
            )
        return line


class Handler(BaseHTTPRequestHandler):
    server_version = "SecAISandboxControl/3.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(HEADER_READ_TIMEOUT_SECONDS)

    def parse_request(self) -> bool:
        raw_reader = self.rfile
        self.rfile = _BoundedHeaderReader(raw_reader, MAX_HEADER_BYTES)
        try:
            if not super().parse_request():
                return False
        finally:
            self.rfile = raw_reader
        header_bytes = sum(
            len(key.encode("utf-8")) + len(value.encode("utf-8")) + 4
            for key, value in self.headers.items()
        )
        if len(self.headers) > MAX_HEADER_COUNT or header_bytes > MAX_HEADER_BYTES:
            self.send_error(431, "request headers exceed the fixed limit")
            return False
        return True

    def log_message(self, fmt: str, *args: object) -> None:
        # The fixed health path is polled continuously, and unauthenticated
        # clients can reach this host-local listener. Do not create an
        # attacker-amplifiable, unbounded access log.
        return

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            socket.timeout,
        ):
            self.close_connection = True

    def _single_header(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        return values[0].strip() if len(values) == 1 else ""

    def _authorized(self, body: bytes) -> bool:
        token = _read_token()
        timestamp = self._single_header("X-SecAI-Timestamp")
        nonce = self._single_header("X-SecAI-Nonce")
        supplied_body_hash = self._single_header("X-SecAI-Content-SHA256")
        supplied_signature = self._single_header("X-SecAI-Signature")
        if (
            not token
            or not timestamp.isascii()
            or not timestamp.isdecimal()
            or len(timestamp) > 12
        ):
            return False
        request_time = int(timestamp, 10)
        now = time.time()
        if abs(now - request_time) > AUTH_CLOCK_SKEW_SECONDS:
            return False
        expected_body_hash, expected_signature = _request_signature(
            token=token,
            method=self.command,
            path=self.path,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        if (
            not expected_signature
            or not hmac.compare_digest(supplied_body_hash, expected_body_hash)
            or not hmac.compare_digest(supplied_signature, expected_signature)
        ):
            return False
        return _consume_auth_nonce(nonce, now)

    def _read_raw_body(self) -> tuple[bytes, str | None]:
        if self.headers.get("Transfer-Encoding") is not None:
            return b"", "transfer encoding is not supported"
        content_lengths = self.headers.get_all("Content-Length", [])
        if len(content_lengths) != 1:
            return b"", "exactly one content length is required"
        raw_len = content_lengths[0].strip()
        if not raw_len.isascii() or not raw_len.isdecimal():
            return b"", "invalid content length"
        try:
            length = int(raw_len, 10)
        except ValueError:
            return b"", "invalid content length"
        if length > MAX_BODY_BYTES:
            return b"", "request too large"
        try:
            self.connection.settimeout(BODY_READ_TIMEOUT_SECONDS)
            data = self.rfile.read(length) if length else b""
        except (TimeoutError, socket.timeout):
            return b"", "request body timeout"
        if length and len(data) != length:
            return b"", "incomplete request body"
        return data, None

    def _decode_json_body(
        self,
        data: bytes,
    ) -> tuple[dict[str, Any], str | None]:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            return {}, "invalid json"
        if not isinstance(payload, dict):
            return {}, "json body must be an object"
        return payload, None

    def _read_body(self) -> tuple[dict[str, Any], str | None]:
        data, error = self._read_raw_body()
        if error:
            return {}, error
        return self._decode_json_body(data)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            current_profile = _current_profile()
            payload = {
                "status": (
                    "ok" if current_profile in VALID_PROFILES else "degraded"
                ),
                "controller": "secai-sandbox-control",
                "protocol_version": CONTROL_PROTOCOL_VERSION,
                "state_protocol_version": CONTROL_STATE_PROTOCOL_VERSION,
                "profile": current_profile,
                "profile_state": (
                    "active"
                    if current_profile in VALID_PROFILES
                    else "degraded"
                ),
            }
            challenges = parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=False,
            ).get("challenge", [])
            if len(challenges) == 1:
                proof = _health_proof(_read_token(), challenges[0])
                session_id = _read_session()
                state_proof = _state_proof(
                    _read_token(),
                    challenges[0],
                    session_id,
                    payload["status"],
                    payload["profile_state"],
                    payload["profile"],
                )
                if proof and state_proof:
                    payload.update({
                        "proof": proof,
                        "session_id": session_id,
                        "state_proof": state_proof,
                    })
            self._send_json(payload)
            return
        if parsed.path == "/v1/status" and not parsed.query:
            if not self._authorized(b""):
                self._send_json({"error": "unauthorized"}, 401)
                return
            self._send_json(_status())
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path not in {"/v1/apply", "/v1/shutdown"}:
            self._send_json({"error": "not found"}, 404)
            return
        data, error = self._read_raw_body()
        if error:
            self._send_json({"error": error}, 400 if error != "request too large" else 413)
            return
        if not self._authorized(data):
            self._send_json({"error": "unauthorized"}, 401)
            return
        if self.path == "/v1/shutdown":
            if data:
                self._send_json({"error": "shutdown body must be empty"}, 400)
                return
            self._send_json({"status": "stopping"})
            _begin_shutdown()
            return
        payload, error = self._decode_json_body(data)
        if error:
            self._send_json({"error": error}, 400 if error != "request too large" else 413)
            return
        result, status = _start_apply(payload, requested_by=self.client_address[0])
        self._send_json(result, status)


def _cancel_active_apply() -> bool:
    _shutdown_requested.set()
    with _state_lock:
        process = _active_process
        windows_job = _active_windows_job
        thread = _active_thread
    if process is not None:
        _terminate_process_tree(process, windows_job)
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=CONTROL_STOP_TIMEOUT_SECONDS)
    return bool(
        (process is None or process.poll() is not None)
        and (thread is None or not thread.is_alive())
        and not _tree_containment_failed.is_set()
    )


def _shutdown_server() -> None:
    _shutdown_requested.set()
    while not _cancel_active_apply():
        time.sleep(0.1)
    time.sleep(0.1)
    if _server is not None:
        _server.shutdown()


def _begin_shutdown() -> None:
    global _shutdown_worker
    _shutdown_requested.set()
    with _shutdown_worker_lock:
        if _shutdown_worker is not None and _shutdown_worker.is_alive():
            return
        _shutdown_worker = threading.Thread(
            target=_shutdown_server,
            daemon=False,
            name="secai-sandbox-control-shutdown",
        )
        _shutdown_worker.start()


def _handle_shutdown_signal(_signum: int, _frame: object) -> None:
    _begin_shutdown()


def _safe_private_bind_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("sandbox control bind address is invalid") from exc
    if (
        address.version != 4
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or not (
            address.is_loopback
            or any(address in network for network in PRIVATE_BIND_NETWORKS)
        )
    ):
        raise ValueError(
            "sandbox control bind address must be loopback or a private IPv4 address"
        )
    return str(address)


def _safe_explicit_bind_address(value: str) -> str:
    safe = _safe_private_bind_address(value)
    if not ipaddress.ip_address(safe).is_loopback:
        raise ValueError(
            "explicit sandbox control bind addresses must be IPv4 loopback"
        )
    return safe


def _address_is_local(value: str) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((value, 0))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _docker_bridge_gateway() -> str:
    docker = shutil.which("docker")
    if not docker:
        return ""
    try:
        result = subprocess.run(
            [
                docker,
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _docker_is_rootless() -> bool | None:
    docker = shutil.which("docker")
    if not docker:
        return None
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{json .SecurityOptions}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        options = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if not isinstance(options, list):
        return None
    return any("rootless" in str(option).lower() for option in options)


def _docker_is_desktop() -> bool | None:
    docker = shutil.which("docker")
    if not docker:
        return None
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{json .OperatingSystem}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        operating_system = (
            json.loads(result.stdout) if result.returncode == 0 else None
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if not isinstance(operating_system, str):
        return None
    return "docker desktop" in operating_system.lower()


def _podman_bridge_gateway(network_name: str) -> str:
    if network_name != PODMAN_CONTROL_NETWORK:
        return ""
    podman = shutil.which("podman")
    if not podman:
        return ""
    try:
        result = subprocess.run(
            [podman, "network", "inspect", network_name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        payload = json.loads(result.stdout) if result.returncode == 0 else []
        network = payload[0] if len(payload) == 1 else {}
        labels = network.get("labels")
        subnets = network.get("subnets")
        if (
            network.get("name") != PODMAN_CONTROL_NETWORK
            or network.get("driver") != "bridge"
            or network.get("internal") is not False
            or not isinstance(labels, dict)
            or labels.get("io.podman.compose.project") != "secai-sandbox"
            or labels.get("com.docker.compose.project") != "secai-sandbox"
            or labels.get("com.docker.compose.network") != "ingress"
            or not isinstance(subnets, list)
            or len(subnets) != 1
            or not isinstance(subnets[0], dict)
        ):
            return ""
        return str(subnets[0]["gateway"])
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        return ""


def _podman_is_rootless() -> bool | None:
    podman = shutil.which("podman")
    if not podman:
        return None
    try:
        result = subprocess.run(
            [podman, "info", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        payload = json.loads(result.stdout) if result.returncode == 0 else {}
        rootless = payload["host"]["security"]["rootless"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None
    return rootless if isinstance(rootless, bool) else None


def _resolve_linux_runtime(requested: str) -> tuple[str, bool, bool]:
    if requested not in {"auto", "docker", "podman"}:
        raise RuntimeError("unsupported sandbox container runtime")

    candidates = (
        ("podman", "docker")
        if requested == "auto"
        else (requested,)
    )
    for candidate in candidates:
        if not shutil.which(candidate):
            continue
        if candidate == "podman":
            rootless = _podman_is_rootless()
            if rootless is not None:
                if rootless and requested == "auto":
                    continue
                return candidate, rootless, False
            continue
        desktop = _docker_is_desktop()
        if desktop:
            return candidate, False, True
        rootless = _docker_is_rootless()
        if rootless is not None:
            if rootless and requested == "auto":
                continue
            return candidate, rootless, False

    if requested == "auto":
        raise RuntimeError("no functional Docker or Podman runtime was detected")
    raise RuntimeError(f"{requested} is unavailable or did not answer its info probe")


def _resolve_bind_host(
    requested: str,
    runtime: str = "auto",
    podman_network: str = PODMAN_CONTROL_NETWORK,
) -> str:
    if requested != "auto":
        return _safe_explicit_bind_address(requested)
    if platform.system() != "Linux":
        if runtime == "podman":
            raise RuntimeError(
                "the sandbox controller supports Podman only on native Linux; "
                "use Docker Desktop on macOS or Windows"
            )
        return "127.0.0.1"

    selected_runtime, rootless, desktop = _resolve_linux_runtime(runtime)
    if selected_runtime == "docker":
        if desktop:
            return "127.0.0.1"
        if rootless:
            raise RuntimeError(
                "rootless Docker host-loopback routing is not supported by "
                "the sandbox controller; use rootful Podman on native Linux "
                "or Docker Desktop"
            )
        candidate = _docker_bridge_gateway()
    else:
        if rootless:
            raise RuntimeError(
                "rootless Podman does not route containers to host loopback "
                "by default; use rootful Podman or Docker Desktop"
            )
        candidate = _podman_bridge_gateway(podman_network)

    try:
        safe = _safe_private_bind_address(candidate)
    except ValueError as exc:
        raise RuntimeError("container engine returned an unsafe host gateway") from exc
    if _address_is_local(safe):
        return safe
    raise RuntimeError(
        "could not resolve a private, host-local container bridge gateway"
    )


def _read_recorded_host(
    runtime_dir: Path,
    requested: str,
    runtime: str = "auto",
    podman_network: str = PODMAN_CONTROL_NETWORK,
) -> str:
    host_path = runtime_dir / "control-server-host"
    try:
        recorded = _read_runtime_file_no_follow(
            host_path,
            MAX_RECORDED_HOST_BYTES,
        ).decode("ascii").strip()
    except (OSError, UnicodeError):
        recorded = ""
    if recorded:
        return _safe_private_bind_address(recorded)
    if requested == "auto":
        return _resolve_bind_host(requested, runtime, podman_network)
    return _safe_explicit_bind_address(requested)


def _read_recorded_pid(runtime_dir: Path) -> int:
    try:
        raw_pid = _read_runtime_file_no_follow(
            runtime_dir / "control-server.pid",
            MAX_RECORDED_PID_BYTES,
        ).decode("ascii").strip()
        pid = int(raw_pid, 10)
    except (OSError, UnicodeError, ValueError):
        return 0
    return pid if pid > 1 else 0


def _windows_process_exists(pid: int) -> bool:
    kernel32 = _load_windows_dll("kernel32")
    kernel32.OpenProcess.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.OpenProcess(
        WINDOWS_SYNCHRONIZE | WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not handle:
        # INVALID_PARAMETER is the documented response for a PID that does not
        # exist. Access denied and other failures are ambiguous, so retain the
        # recorded PID and fail closed rather than treating it as stale.
        return _windows_last_error() != WINDOWS_ERROR_INVALID_PARAMETER
    wait_result = kernel32.WaitForSingleObject(handle, 0)
    closed = kernel32.CloseHandle(handle)
    if not closed:
        return True
    if wait_result == WINDOWS_WAIT_OBJECT_0:
        return False
    if wait_result == WINDOWS_WAIT_TIMEOUT:
        return True
    return True


def _process_exists(pid: int) -> bool:
    if pid <= 1:
        return False
    if _running_on_windows():
        return _windows_process_exists(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _validated_probe_status(
    *,
    http_status: int,
    payload: object,
    token: str,
    challenge: str,
) -> int:
    if http_status != 200 or not isinstance(payload, dict):
        return 1
    protocol_version = payload.get("protocol_version")
    if (
        payload.get("controller") != "secai-sandbox-control"
        or type(protocol_version) is not int
    ):
        return 1
    expected_proof = _health_proof(token, challenge, protocol_version)
    if not expected_proof or not hmac.compare_digest(
        str(payload.get("proof", "")),
        expected_proof,
    ):
        return 1
    if protocol_version != CONTROL_PROTOCOL_VERSION:
        return 2
    state_protocol_version = payload.get("state_protocol_version")
    if (
        type(state_protocol_version) is not int
        or state_protocol_version != CONTROL_STATE_PROTOCOL_VERSION
    ):
        return 2
    return (
        0
        if _verify_challenge_health_payload(
            token=token,
            challenge=challenge,
            payload=payload,
        )
        else 1
    )


def _probe_endpoint(
    runtime_dir: Path,
    token_path: Path,
    host: str,
    port: int,
    runtime: str = "auto",
    podman_network: str = PODMAN_CONTROL_NETWORK,
    loaded_token: str | None = None,
) -> int:
    try:
        token = (
            loaded_token
            if loaded_token is not None
            else _load_control_token(runtime_dir, token_path)
        )
        endpoint = _read_recorded_host(
            runtime_dir,
            host,
            runtime,
            podman_network,
        )
    except (OSError, ValueError, RuntimeError):
        return 1
    if not _valid_control_token(token):
        return 1

    challenge = secrets.token_hex(32)
    conn = http.client.HTTPConnection(endpoint, port, timeout=2)
    response_status = 0
    payload: object = None
    try:
        conn.request(
            "GET",
            f"/health?challenge={challenge}",
        )
        response = conn.getresponse()
        response_body = response.read(MAX_BODY_BYTES + 1)
        if len(response_body) > MAX_BODY_BYTES:
            payload = None
        else:
            payload = json.loads(response_body.decode("utf-8"))
            response_status = response.status
    except (OSError, TimeoutError, ValueError, http.client.HTTPException):
        pass
    finally:
        conn.close()
    probe_status = _validated_probe_status(
        http_status=response_status,
        payload=payload,
        token=token,
        challenge=challenge,
    )
    return probe_status


def _probe_existing(
    runtime_dir: Path,
    token_path: Path,
    host: str,
    port: int,
    runtime: str = "auto",
    podman_network: str = PODMAN_CONTROL_NETWORK,
) -> int:
    return _probe_endpoint(
        runtime_dir,
        token_path,
        host,
        port,
        runtime,
        podman_network,
    )


def _endpoint_state(endpoint: str, port: int) -> str:
    try:
        connection = socket.create_connection((endpoint, port), timeout=2)
    except OSError as exc:
        if (
            isinstance(exc, ConnectionRefusedError)
            or exc.errno == errno.ECONNREFUSED
            or getattr(exc, "winerror", None) == 10061
        ):
            return ENDPOINT_ABSENT
        return ENDPOINT_AMBIGUOUS
    connection.close()
    return ENDPOINT_PRESENT


def _clear_controller_metadata(runtime_dir: Path) -> None:
    for path in (
        runtime_dir / "control-server.pid",
        runtime_dir / "control-server-host",
        runtime_dir / "control-server-session",
    ):
        with contextlib.suppress(OSError):
            path.unlink()


def _stop_existing(
    runtime_dir: Path,
    token_path: Path,
    host: str,
    port: int,
    runtime: str = "auto",
    podman_network: str = PODMAN_CONTROL_NETWORK,
) -> int:
    pid = _read_recorded_pid(runtime_dir)
    try:
        token = _load_control_token(runtime_dir, token_path)
        endpoint = _read_recorded_host(
            runtime_dir,
            host,
            runtime,
            podman_network,
        )
    except (OSError, ValueError, RuntimeError):
        token = ""
        try:
            endpoint = _read_recorded_host(
                runtime_dir,
                host,
                runtime,
                podman_network,
            )
        except (ValueError, RuntimeError):
            return int(_process_exists(pid))

    probe_status = (
        _probe_endpoint(
            runtime_dir,
            token_path,
            host,
            port,
            runtime,
            podman_network,
            token,
        )
        if _valid_control_token(token)
        else 1
    )
    if probe_status not in {0, 2}:
        endpoint_state = _endpoint_state(endpoint, port)
        if endpoint_state != ENDPOINT_ABSENT or _process_exists(pid):
            return 1
        _clear_controller_metadata(runtime_dir)
        return 0

    conn = http.client.HTTPConnection(endpoint, port, timeout=2)
    try:
        request_body = b""
        conn.request(
            "POST",
            "/v1/shutdown",
            body=request_body,
            headers=_request_auth_headers(
                token,
                "POST",
                "/v1/shutdown",
                request_body,
            ),
        )
        response = conn.getresponse()
        response_body = response.read(MAX_BODY_BYTES + 1)
        if (
            len(response_body) > MAX_BODY_BYTES
            or response.status != 200
        ):
            return 1
    except (OSError, TimeoutError, http.client.HTTPException):
        return 1
    finally:
        conn.close()

    deadline = time.monotonic() + CONTROL_STOP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        process_stopped = not _process_exists(pid)
        endpoint_stopped = _endpoint_state(endpoint, port) == ENDPOINT_ABSENT
        if process_stopped and endpoint_stopped:
            _clear_controller_metadata(runtime_dir)
            return 0
        time.sleep(0.05)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--token-path")
    parser.add_argument("--host", default="auto")
    parser.add_argument(
        "--runtime",
        choices=("auto", "docker", "podman"),
        default="auto",
    )
    parser.add_argument(
        "--podman-network",
        choices=(PODMAN_CONTROL_NETWORK,),
        default=PODMAN_CONTROL_NETWORK,
    )
    parser.add_argument("--port", type=int, default=CONTROL_PORT)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    # Do not resolve the runtime or token final components. Resolution would
    # follow an attacker-controlled link before the no-follow checks can reject
    # it. Lexical normalization also makes the exact parent relationship
    # unambiguous.
    runtime_dir = _lexical_absolute_path(args.runtime_dir)
    token_path = (
        _lexical_absolute_path(args.token_path)
        if args.token_path
        else runtime_dir / "control-token"
    )

    if args.port != CONTROL_PORT:
        parser.error(f"the sandbox control port is fixed at {CONTROL_PORT}")
    if args.probe and args.stop:
        parser.error("--probe and --stop are mutually exclusive")
    if args.probe:
        return _probe_existing(
            runtime_dir,
            token_path,
            args.host,
            args.port,
            args.runtime,
            args.podman_network,
        )
    if args.stop:
        return _stop_existing(
            runtime_dir,
            token_path,
            args.host,
            args.port,
            args.runtime,
            args.podman_network,
        )

    global CONFIG, _server, _server_session, _server_token
    CONFIG = ControlConfig(
        repo_root,
        runtime_dir,
        token_path,
        args.runtime,
        args.podman_network,
    )
    try:
        configured_token = _load_control_token(runtime_dir, token_path)
    except (OSError, RuntimeError):
        parser.error(
            "the sandbox control token failed its path, ownership, mode, "
            "link-count, or content validation"
        )
    try:
        _ensure_private_directory(CONFIG.status_path.parent)
    except (OSError, RuntimeError):
        parser.error(
            "the sandbox controller state directory could not be secured"
        )
    if not _load_auth_nonce_state():
        parser.error(
            "the persisted sandbox request replay state is malformed or "
            "could not be secured"
        )
    bind_host = _resolve_bind_host(
        args.host,
        args.runtime,
        args.podman_network,
    )
    configured_session = _new_controller_session()
    _shutdown_requested.clear()
    _server = BoundedThreadingHTTPServer((bind_host, args.port), Handler)
    # Requests and health proofs use this immutable process-lifetime value.
    # Re-reading a replaced path here would desynchronize the controller from
    # the token inode already mounted into the UI.
    _server_token = configured_token
    _server_session = configured_session
    previous_handlers: dict[int, Any] = {}
    session_identity: tuple[int, int] | None = None
    pid_identity: tuple[int, int] | None = None
    host_identity: tuple[int, int] | None = None
    pid_payload = str(os.getpid()).encode("ascii")
    host_payload = bind_host.encode("ascii")
    session_payload = configured_session.encode("ascii")
    try:
        session_identity = _write_private_file_atomic(
            CONFIG.session_path,
            session_payload,
        )
        pid_identity = _write_private_file_atomic(
            CONFIG.pid_path,
            pid_payload,
        )
        host_identity = _write_private_file_atomic(
            CONFIG.host_path,
            host_payload,
        )
        for signal_number in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signal_number] = signal.signal(
                signal_number,
                _handle_shutdown_signal,
            )
        _server.serve_forever()
    finally:
        _shutdown_requested.set()
        _cancel_active_apply()
        _server.server_close()
        for path, payload, identity in (
            (CONFIG.session_path, session_payload, session_identity),
            (CONFIG.pid_path, pid_payload, pid_identity),
            (CONFIG.host_path, host_payload, host_identity),
        ):
            if identity is None:
                continue
            with contextlib.suppress(OSError, RuntimeError):
                _unlink_private_file_if_payload(
                    path,
                    payload,
                    expected_identity=identity,
                )
        _server_session = ""
        _server_token = ""
        for signal_number, previous in previous_handlers.items():
            signal.signal(signal_number, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

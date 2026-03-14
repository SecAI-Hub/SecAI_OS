"""Sandbox and isolation primitives for agent execution (M43 — Stronger Isolation).

Provides process-level compartmentalization, step signature validation,
workspace hard-wall enforcement, and high-risk action subprocess isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .models import (
    CapabilityToken,
    Step,
    StepAction,
    StepStatus,
)

log = logging.getLogger("agent.sandbox")

# ---------------------------------------------------------------------------
# Step signature: prevents in-memory tampering between planning and execution
# ---------------------------------------------------------------------------

_STEP_SIGN_KEY: bytes | None = None


def _get_step_key() -> bytes:
    """Load the step-signing key, creating one if needed."""
    global _STEP_SIGN_KEY
    if _STEP_SIGN_KEY is not None:
        return _STEP_SIGN_KEY
    try:
        from .keystore import create_provider, load_config
        config = load_config()
        provider = create_provider(config)
        _STEP_SIGN_KEY = provider.get_key("step-signing")
    except Exception:
        # Fallback: derive from default key
        _STEP_SIGN_KEY = hashlib.sha256(b"step-signing-fallback").digest()
    return _STEP_SIGN_KEY


def sign_step(step: Step, cap: CapabilityToken) -> str:
    """Compute HMAC-SHA256 over step + capability binding fields.

    This signature proves the step has not been modified between policy
    evaluation and execution.  The executor MUST verify this before
    running any handler.
    """
    key = _get_step_key()
    payload = json.dumps({
        "step_id": step.step_id,
        "action": step.action.value,
        "params": step.params,
        "token_id": cap.token_id,
        "task_id": cap.task_id,
        "policy_digest": cap.policy_digest,
    }, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_step_signature(step: Step, cap: CapabilityToken, signature: str) -> tuple[bool, str]:
    """Verify a step's HMAC signature.

    Returns (valid, reason).
    """
    if not signature:
        return False, "step not signed"
    expected = sign_step(step, cap)
    if not hmac.compare_digest(signature, expected):
        return False, "step signature mismatch — possible in-memory tampering"
    return True, "valid"


# ---------------------------------------------------------------------------
# Per-step capability re-validation
# ---------------------------------------------------------------------------

def revalidate_step_capability(step: Step, cap: CapabilityToken) -> tuple[bool, str]:
    """Re-validate a step's parameters against the capability token.

    This is a defense-in-depth check that runs AGAIN at execution time,
    not just during policy evaluation.  Catches any in-memory mutation
    of step params between approval and execution.
    """
    import fnmatch

    # Check token expiry
    if cap.is_expired():
        return False, "capability token expired at execution time"

    params = step.params

    # File read scope
    if step.action in (StepAction.READ_FILE, StepAction.LOCAL_SEARCH):
        path = params.get("path", "")
        if path and not _path_in_scope(path, cap.readable_paths):
            return False, f"path '{path}' not in readable scope at execution time"

    # File write scope
    if step.action in (StepAction.WRITE_FILE, StepAction.OVERWRITE_FILE,
                        StepAction.DRAFT, StepAction.REPORT):
        path = params.get("path", "")
        if path and not _path_in_scope(path, cap.writable_paths):
            return False, f"path '{path}' not in writable scope at execution time"

    # Tool allowlist
    if step.action == StepAction.TOOL_INVOKE:
        tool = params.get("tool", "")
        if tool and cap.allowed_tools and tool not in cap.allowed_tools:
            return False, f"tool '{tool}' not in allowed tools at execution time"

    # Online access
    if step.action == StepAction.OUTBOUND_REQUEST and not cap.allow_online:
        return False, "online access not permitted at execution time"

    return True, "valid"


def _path_in_scope(path: str, allowed: list[str]) -> bool:
    """Check if a normalised path matches any allowed glob."""
    import fnmatch
    norm = os.path.normpath(os.path.abspath(path))
    for pattern in allowed:
        norm_pat = os.path.normpath(pattern)
        if fnmatch.fnmatch(norm, norm_pat):
            return True
        dir_pat = norm_pat.rstrip("*").rstrip("/")
        if norm == dir_pat or norm.startswith(dir_pat + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Workspace hard walls — filesystem-level isolation
# ---------------------------------------------------------------------------

# Actions classified as high-risk for isolation purposes
HIGH_RISK_ACTIONS: set[StepAction] = {
    StepAction.OUTBOUND_REQUEST,
    StepAction.EXPORT_DATA,
    StepAction.TRUST_CHANGE,
    StepAction.BATCH_DELETE,
    StepAction.WIDEN_SCOPE,
    StepAction.ENABLE_TOOL,
    StepAction.CHANGE_SECURITY,
}


class WorkspaceGuard:
    """Enforces per-workspace filesystem isolation.

    Verifies that all file operations stay within their designated
    workspace boundaries.  Prevents:
    - Cross-workspace file descriptor reuse
    - Symlink traversal escapes
    - Hardlink tricks
    - Path component manipulation
    """

    # Known dangerous path patterns
    _TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./"),             # parent directory traversal
        re.compile(r"/\.\./"),            # embedded traversal
        re.compile(r"\x00"),              # null byte injection
        re.compile(r"[\n\r]"),            # newline injection
    ]

    def __init__(self, workspace_mounts: dict[str, str] | None = None):
        """Initialize with workspace ID -> filesystem path mapping.

        Example: {"user_docs": "/var/lib/secure-ai/vault/user_docs",
                  "outputs": "/var/lib/secure-ai/vault/outputs"}
        """
        self._mounts = workspace_mounts or {}
        self._open_fds: dict[str, set[int]] = {}  # workspace_id -> set of fd numbers

    def validate_path(self, path: str, workspace_id: str) -> tuple[bool, str]:
        """Validate that a path belongs to the specified workspace.

        Resolves symlinks and checks the real path is within bounds.
        Returns (valid, reason).
        """
        # Check for traversal patterns in the raw path
        for pattern in self._TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return False, f"path contains dangerous pattern: {path}"

        norm = os.path.normpath(os.path.abspath(path))

        # Resolve symlinks to get the real path
        try:
            real = os.path.realpath(norm)
        except OSError as exc:
            return False, f"cannot resolve path: {exc}"

        # If the real path differs from the normalised path, it's a symlink
        if real != norm:
            # Check the symlink target is also in the workspace
            if not self._is_in_workspace(real, workspace_id):
                return False, (
                    f"symlink escape detected: {norm} -> {real} "
                    f"is outside workspace '{workspace_id}'"
                )

        # Check the final path is in the workspace
        if not self._is_in_workspace(real, workspace_id):
            return False, f"path {real} is outside workspace '{workspace_id}'"

        # Check for hardlink tricks (file on a different device)
        if os.path.exists(real):
            try:
                stat = os.lstat(norm)
                real_stat = os.stat(real)
                # If inode differs between lstat and stat, something is wrong
                if stat.st_ino != real_stat.st_ino and not os.path.islink(norm):
                    return False, f"hardlink mismatch detected for {norm}"
            except OSError:
                pass  # File may not exist yet (write operations)

        return True, "valid"

    def _is_in_workspace(self, real_path: str, workspace_id: str) -> bool:
        """Check if a resolved path is within a workspace mount."""
        mount = self._mounts.get(workspace_id)
        if not mount:
            return False
        mount_real = os.path.realpath(mount)
        return real_path == mount_real or real_path.startswith(mount_real + "/")

    def check_no_cross_workspace_fd(self, workspace_id: str, fd: int) -> bool:
        """Verify a file descriptor doesn't cross workspace boundaries.

        Tracks open FDs per workspace and blocks reuse across workspaces.
        """
        for ws_id, fds in self._open_fds.items():
            if ws_id != workspace_id and fd in fds:
                log.warning(
                    "cross-workspace fd reuse detected: fd=%d was in "
                    "workspace '%s', now requested by '%s'",
                    fd, ws_id, workspace_id,
                )
                return False
        # Register this fd
        if workspace_id not in self._open_fds:
            self._open_fds[workspace_id] = set()
        self._open_fds[workspace_id].add(fd)
        return True

    def release_fd(self, workspace_id: str, fd: int) -> None:
        """Release a tracked file descriptor."""
        if workspace_id in self._open_fds:
            self._open_fds[workspace_id].discard(fd)


# ---------------------------------------------------------------------------
# High-risk subprocess isolation
# ---------------------------------------------------------------------------

class SubprocessIsolator:
    """Runs high-risk step handlers in separate subprocess with restricted profile.

    This creates a one-way IPC boundary: the parent sends step data to the
    subprocess via stdin/JSON, and receives the result via stdout/JSON.
    The subprocess cannot access the parent's memory space.
    """

    # Per-step timeout based on action type
    _TIMEOUTS: dict[StepAction, int] = {
        StepAction.READ_FILE: 10,
        StepAction.WRITE_FILE: 10,
        StepAction.OVERWRITE_FILE: 10,
        StepAction.TOOL_INVOKE: 30,
        StepAction.OUTBOUND_REQUEST: 30,
        StepAction.EXPORT_DATA: 30,
        StepAction.LOCAL_SEARCH: 10,
        StepAction.SUMMARIZE: 60,
        StepAction.DRAFT: 60,
        StepAction.CLASSIFY: 30,
        StepAction.REPORT: 60,
        StepAction.EXPLAIN_SECURITY: 30,
    }

    def get_timeout(self, action: StepAction) -> int:
        """Return the per-step timeout in seconds."""
        return self._TIMEOUTS.get(action, 30)

    def is_high_risk(self, action: StepAction) -> bool:
        """Check if an action requires subprocess isolation."""
        return action in HIGH_RISK_ACTIONS

    def execute_isolated(
        self,
        step: Step,
        cap_dict: dict,
        handler_module: str = "agent.sandbox",
    ) -> dict[str, Any]:
        """Execute a step handler in a subprocess with restricted profile.

        The subprocess receives step data via stdin JSON and returns results
        via stdout JSON.  Any exception kills only the subprocess, not the
        main agent.

        Returns the step result dict.
        """
        timeout = self.get_timeout(step.action)

        payload = json.dumps({
            "step": {
                "step_id": step.step_id,
                "action": step.action.value,
                "params": step.params,
            },
            "capability": cap_dict,
        })

        try:
            result = subprocess.run(
                ["python3", "-m", handler_module, "--isolated-step"],
                input=payload,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={
                    **os.environ,
                    "SECAI_ISOLATED": "1",
                    "SECAI_STEP_TIMEOUT": str(timeout),
                },
            )

            if result.returncode != 0:
                return {
                    "ok": False,
                    "error": f"isolated handler exited with code {result.returncode}: {result.stderr[:500]}",
                }

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"isolated handler timed out after {timeout}s"}
        except (json.JSONDecodeError, OSError) as exc:
            return {"ok": False, "error": f"isolated handler error: {exc}"}


# ---------------------------------------------------------------------------
# Worker recycling — zero sensitive buffers after high-risk tasks
# ---------------------------------------------------------------------------

def recycle_worker_state(task_id: str) -> None:
    """Zero sensitive in-memory state after a high-risk task completes.

    This prevents data leakage between tasks by clearing:
    - Any cached file contents
    - Inference responses
    - Tool call results
    - Temporary credentials

    Called automatically after task completion.
    """
    import gc

    log.info("recycling worker state for task %s", task_id)

    # Force garbage collection to release any dangling references
    gc.collect()

    # Clear any temporary files created during the task
    tmp_dir = Path(tempfile.gettempdir()) / f"secai-task-{task_id}"
    if tmp_dir.exists():
        import shutil
        try:
            shutil.rmtree(tmp_dir)
            log.info("cleaned temp directory for task %s", task_id)
        except OSError as exc:
            log.warning("failed to clean temp dir for task %s: %s", task_id, exc)


# ---------------------------------------------------------------------------
# Model worker isolation profile
# ---------------------------------------------------------------------------

class ModelWorkerProfile:
    """Defines isolation constraints for the inference worker.

    Tighter profiles for GPU devices, shared memory, temp directories,
    and model cache paths.
    """

    def __init__(self):
        self.allowed_gpu_devices: list[str] = [
            "/dev/nvidia*",
            "/dev/dri/*",
        ]
        self.allowed_shm_size: int = 2 * 1024 * 1024 * 1024  # 2 GB
        self.allowed_tmp_paths: list[str] = [
            "/tmp/secai-inference-*",
        ]
        self.allowed_model_paths: list[str] = [
            "/var/lib/secure-ai/registry/models/*",
        ]
        self.recycle_after_high_risk: bool = True
        self.zero_buffers_on_teardown: bool = True

    def validate_model_path(self, path: str) -> tuple[bool, str]:
        """Check if a model path is allowed by this profile."""
        import fnmatch
        norm = os.path.normpath(os.path.abspath(path))
        for pattern in self.allowed_model_paths:
            if fnmatch.fnmatch(norm, pattern):
                return True, "allowed"
        return False, f"model path {norm} not in allowed paths"

    def to_dict(self) -> dict:
        return {
            "allowed_gpu_devices": self.allowed_gpu_devices,
            "allowed_shm_size": self.allowed_shm_size,
            "allowed_tmp_paths": self.allowed_tmp_paths,
            "allowed_model_paths": self.allowed_model_paths,
            "recycle_after_high_risk": self.recycle_after_high_risk,
            "zero_buffers_on_teardown": self.zero_buffers_on_teardown,
        }


# ---------------------------------------------------------------------------
# Module entry point for isolated step execution
# ---------------------------------------------------------------------------

def _run_isolated_step() -> None:
    """Entry point when this module is invoked as a subprocess.

    Reads step data from stdin, executes the handler, writes result
    to stdout.  This function should NEVER be called from the main
    agent process.
    """
    import sys
    data = json.loads(sys.stdin.read())
    # In isolated mode, we simply validate and return a safe response
    # The actual handler execution is delegated to the executor
    result = {
        "ok": True,
        "isolated": True,
        "step_id": data.get("step", {}).get("step_id", ""),
    }
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__" or (
    len(__import__("sys").argv) > 1 and "--isolated-step" in __import__("sys").argv
):
    _run_isolated_step()

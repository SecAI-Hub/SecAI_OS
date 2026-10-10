"""Agent service Flask API (spec §8, M40 — Verified Supervisor).

Endpoints for task submission, approval, and status.  The agent
orchestrates planner → policy engine → executor with HMAC-signed
capability tokens, two-phase approval for high-risk actions, and
per-step policy decision evidence in the audit trail.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, cast

from flask import Flask, jsonify, request
from common import runtime_assurance

from .action_catalog import UNAVAILABLE_ACTIONS, action_catalog
from .approval import approval_snapshot
from .capabilities import (
    create_budgets,
    create_token,
    hash_intent,
    hash_policy_file,
    verify_token,
)
from .executor import Executor
from .models import (
    SessionMode,
    StepAction,
    StepStatus,
    Task,
    TaskStatus,
)
from .planner import ActionUnavailable, Planner
from .policy import PolicyEngine
from .sandbox import (
    recycle_worker_state,
    revalidate_step_capability,
    sign_step,
    verify_step_signature,
)
from .storage import StorageGateway
from .task_store import (
    TERMINAL_STATUSES,
    HistoryPolicy,
    TaskStore,
    history_policy_from_config,
)

log = logging.getLogger("agent")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

# --- Configuration ---------------------------------------------------------

_POLICY_PATH = os.getenv("AGENT_POLICY_PATH", "/etc/secure-ai/policy/agent.yaml")
_AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/agent-audit.jsonl")
_VAULT_ROOT = os.getenv("VAULT_ROOT", "/var/lib/secure-ai/vault")
_BIND_ADDR = os.getenv("BIND_ADDR", "127.0.0.1:8476")
_TASK_STATE_PATH = os.getenv(
    "AGENT_TASK_STATE_PATH",
    "/var/lib/secure-ai/agent/tasks.json",
)
_CONTAINMENT_STATE_PATH = os.getenv(
    "AGENT_CONTAINMENT_STATE_PATH",
    "/var/lib/secure-ai/agent/containment.json",
)

# --- Workspace registry (resolve IDs to real paths server-side) ------------

_WORKSPACE_REGISTRY: dict[str, str] = {
    "user_docs": "/var/lib/secure-ai/vault/user_docs",
    "outputs": "/var/lib/secure-ai/vault/outputs",
}


def _resolve_workspaces(workspace_ids: list[str]) -> tuple[list[str], str | None]:
    """Resolve workspace IDs to filesystem paths.

    Returns (resolved_paths, error_message). If error_message is not None,
    at least one workspace ID was unrecognised.
    """
    resolved = []
    for ws_id in workspace_ids:
        ws_id = ws_id.strip()
        if ws_id in _WORKSPACE_REGISTRY:
            resolved.append(_WORKSPACE_REGISTRY[ws_id])
        else:
            return [], f"unknown workspace: {ws_id}"
    return resolved, None


# --- Service layer ---------------------------------------------------------

_policy = PolicyEngine(_POLICY_PATH)
_storage = StorageGateway(_VAULT_ROOT)
_planner = Planner(_policy)
_executor = Executor(_storage)

# Audit chain (imported lazily to avoid circular import if common not available)
_audit = None
try:
    import sys

    _services_root = str(Path(__file__).resolve().parent.parent.parent)
    if _services_root not in sys.path:
        sys.path.insert(0, _services_root)
    from common.audit_chain import AuditChain

    _audit = AuditChain(_AUDIT_LOG_PATH)
except ImportError:
    log.warning("audit_chain not available, audit logging disabled")

# Raw task content/authority lives only in this process. Legacy raw history is
# rejected before it can enter the live task map or be exposed through the API.
try:
    _history_policy = history_policy_from_config()
    _history_configuration_error = None
except ValueError:
    _history_policy = HistoryPolicy()
    _history_configuration_error = "invalid history privacy configuration; memory-only operation"
_task_store = TaskStore(_TASK_STATE_PATH, policy=_history_policy, configuration_error=_history_configuration_error)
_tasks: dict[str, Task] = _task_store.load()
_tasks_lock = threading.Lock()
_history_lock = threading.RLock()
_history_reaper_stop = threading.Event()
_containment_frozen = threading.Event()
_execution_condition = threading.Condition()
_active_executions = 0

# Background execution thread pool
_MAX_CONCURRENT_TASKS = 4
_execution_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_TASKS)
_VALID_PREFERENCES = {
    StepAction.READ_FILE.value,
    StepAction.WRITE_FILE.value,
    StepAction.OVERWRITE_FILE.value,
}


def _audit_log(event: str, data: dict | None = None):
    """Append an audit entry if the chain is available."""
    if _audit:
        _audit.append(event, data or {})


def _history_view(snapshot: list[Task]) -> list[Task]:
    try:
        return _task_store.retained_tasks(snapshot)
    except (ValueError, TypeError):
        _task_store.last_error = "history retention clock is unavailable"
        return [task for task in snapshot if not task.history_only and (task.status not in TERMINAL_STATUSES or any(step.status == StepStatus.RUNNING for step in task.steps))]


def _persist_tasks() -> bool:
    # Serialize snapshot acquisition with deletion, so an older pending save
    # cannot resurrect an explicitly deleted terminal record.
    with _history_lock:
        with _tasks_lock:
            snapshot = list(_tasks.values())
        retained = _history_view(snapshot)
        saved = _task_store.save(retained)
        kept = {task.task_id for task in retained}
        with _tasks_lock:
            for task in snapshot:
                if task.task_id not in kept and task.status in TERMINAL_STATUSES:
                    _tasks.pop(task.task_id, None)
        return saved


def _refresh_history() -> None:
    with _history_lock:
        with _tasks_lock:
            snapshot = list(_tasks.values())
        retained = _history_view(snapshot)
        if len(retained) != len(snapshot):
            _persist_tasks()


def _history_retention_worker() -> None:
    while not _history_reaper_stop.wait(60):
        _refresh_history()


def _json_object() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, (jsonify({"error": "JSON body must be an object"}), 400)
    return body, None


def _has_unknown_fields(body: dict[str, Any], allowed: set[str]) -> bool:
    return any(not isinstance(key, str) or key not in allowed for key in body)


def _policy_is_current() -> bool:
    digest = hash_policy_file(_POLICY_PATH)
    if digest and hmac.compare_digest(digest, _policy.policy_digest):
        return True
    return (
        not digest
        and not _policy.policy_digest
        and os.getenv("SECAI_ALLOW_MISSING_AGENT_POLICY", "") == "1"
    )


def _validate_preferences(value: object) -> tuple[dict[str, str], str | None]:
    if value is None:
        return {}, None
    if not isinstance(value, dict) or len(value) > len(_VALID_PREFERENCES):
        return {}, "preferences must be a bounded object"
    result: dict[str, str] = {}
    for raw_action, raw_preference in value.items():
        if raw_action not in _VALID_PREFERENCES:
            return {}, f"unsupported configurable preference: {raw_action}"
        if raw_preference not in {"always", "ask", "never"}:
            return {}, f"invalid preference for {raw_action}"
        result[raw_action] = raw_preference
    return result, None


def _verify_task_capability(task: Task) -> tuple[bool, str]:
    if task.history_only:
        return False, "historical metadata has no execution authority"
    cap = task.capability
    if cap is None:
        return False, "missing capability token"
    valid, reason = verify_token(cap, consume_nonce=False)
    if not valid:
        return False, reason
    if cap.task_id != task.task_id:
        return False, "capability task binding mismatch"
    if not hmac.compare_digest(cap.intent_hash, hash_intent(task.intent)):
        return False, "capability intent binding mismatch"
    if not _policy_is_current() or not hmac.compare_digest(
        cap.policy_digest,
        _policy.policy_digest,
    ):
        return False, "capability policy binding mismatch"
    if cap.budget_limits != task.budgets.limits_dict():
        return False, "capability budget binding mismatch"
    return True, "valid"


def _load_containment_state() -> None:
    """Restore the sticky freeze latch; malformed state fails closed."""
    try:
        descriptor = os.open(
            _CONTAINMENT_STATE_PATH,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > 16 * 1024
            ):
                raise ValueError("unsafe containment state file")
            raw = os.read(descriptor, 16 * 1024 + 1)
        finally:
            os.close(descriptor)
        payload = json.loads(raw)
    except FileNotFoundError:
        return
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        log.error("agent containment state is unreadable; freezing fail-closed")
        _containment_frozen.set()
        return
    if not isinstance(payload, dict):
        log.error("agent containment state has an invalid schema; freezing fail-closed")
        _containment_frozen.set()
    elif payload.get("frozen") is True:
        _containment_frozen.set()


def _persist_containment_state(*, incident_id: str, reason: str) -> None:
    state_path = Path(_CONTAINMENT_STATE_PATH)
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    payload = {
        "frozen": True,
        "incident_id": incident_id,
        "reason": reason,
        "frozen_at": time.time(),
    }
    fd, temp_name = tempfile.mkstemp(
        prefix=".containment-",
        suffix=".json",
        dir=state_path.parent,
    )
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, state_path)
        dir_fd = os.open(state_path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _cancel_task_for_containment(task: Task) -> None:
    with task.runtime_lock:
        if task.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        ):
            return
        task.status = TaskStatus.CANCELLED
        task.completed_at = time.time()
        for step in task.steps:
            if step.status in (StepStatus.PENDING, StepStatus.APPROVED):
                step.status = StepStatus.SKIPPED


def _bind_host() -> str:
    if _BIND_ADDR.startswith("unix:"):
        return ""
    try:
        host, _port = _BIND_ADDR.rsplit(":", 1)
    except ValueError:
        return ""
    return host.strip("[]")


def _loopback_tcp_bind() -> bool:
    host = _bind_host()
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _credential_token(path_env: str, *, allow_legacy_tcp: bool = False) -> str:
    """Read one inbound capability credential without following symlinks."""
    path = os.getenv(path_env, "").strip()
    sandbox_legacy = (
        _BIND_ADDR.startswith("unix:")
        and os.getenv("SECURE_AI_DEPLOYMENT_MODE", "").strip().lower()
        == "sandbox"
    )
    if not path and allow_legacy_tcp and (
        not _BIND_ADDR.startswith("unix:") or sandbox_legacy
    ):
        path = os.getenv(
            "SERVICE_TOKEN_PATH",
            "/run/secure-ai/credentials/agent.token",
        ).strip()
    if not path:
        return ""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not 16 <= info.st_size <= 4096
            ):
                return ""
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        token = raw.decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        return ""
    return token if 16 <= len(token) <= 4096 else ""


def _require_runtime_assurance() -> None:
    if os.getenv("SECURE_AI_DEPLOYMENT_MODE", "").strip().lower() == "sandbox":
        return
    runtime_assurance.require_runtime(
        os.getenv("RUNTIME_ATTESTOR_URL", "http://127.0.0.1:8505"),
        _credential_token("RUNTIME_ATTESTOR_TOKEN_PATH"),
    )


def _request_capability_token() -> str:
    """Select the only credential authorized for the requested route."""
    if request.path in {"/api/v1/freeze", "/v1/containment/freeze"}:
        return _credential_token(
            "AGENT_CONTAINMENT_TOKEN_PATH",
            allow_legacy_tcp=True,
        )
    return _credential_token("AGENT_UI_TOKEN_PATH", allow_legacy_tcp=True)


@app.before_request
def require_service_auth():
    """Require route-scoped bearer authentication on TCP and Unix sockets.

    Socket DAC controls who may connect, but it is not an authorization
    boundary: the UI task-control identity and incident-recorder containment
    identity are intentionally distinct.
    """
    protected = request.path.startswith("/v1/") or request.path.startswith("/api/v1/")
    if not protected:
        return None
    expected = _request_capability_token()
    if not expected:
        if (
            os.getenv("SECAI_ALLOW_INSECURE_NO_AUTH", "") == "1"
            and _loopback_tcp_bind()
        ):
            return None
        return jsonify({"error": "service authentication unavailable"}), 503
    supplied = request.headers.get("Authorization", "")
    if not supplied.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    candidate = supplied[7:].strip()
    if not candidate or not hmac.compare_digest(candidate, expected):
        return jsonify({"error": "unauthorized"}), 401
    return None


@app.before_request
def reject_task_mutation_while_frozen():
    """Reject new execution and approval work while containment is latched."""
    if not _containment_frozen.is_set() or request.method == "GET":
        return None
    if request.path.startswith("/v1/task"):
        return jsonify({"error": "agent frozen by incident containment"}), 423
    return None


# --- API Endpoints ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    _refresh_history()
    with _tasks_lock:
        active = sum(1 for t in _tasks.values() if t.status == TaskStatus.RUNNING)
        total = len(_tasks)
    persistence_healthy = _task_store.healthy
    policy_current = _policy_is_current()
    return jsonify({
        "status": "ok" if persistence_healthy and policy_current else "degraded",
        "service": "agent",
        "active_tasks": active,
        "total_tasks": total,
        "containment_frozen": _containment_frozen.is_set(),
        "persistence_healthy": persistence_healthy,
        "history_policy": _task_store.policy_status(),
        "policy_current": policy_current,
    })


@app.route("/api/v1/freeze", methods=["POST"])
@app.route("/v1/containment/freeze", methods=["POST"])
def freeze_for_containment():
    """Persist the freeze latch, cancel queued work, and wait for drain."""
    body, error_response = _json_object()
    if error_response:
        return error_response
    assert body is not None
    if _has_unknown_fields(body, {"action", "incident_id", "reason"}):
        return jsonify({"error": "unknown containment field"}), 400
    if (
        not isinstance(body.get("action"), str)
        or not isinstance(body.get("incident_id"), str)
        or not isinstance(body.get("reason", ""), str)
    ):
        return jsonify({"error": "containment fields must be strings"}), 400
    incident_id = str(body.get("incident_id", "")).strip()
    reason = str(body.get("reason", "")).strip()
    if body.get("action") != "freeze" or not incident_id:
        return jsonify({"error": "action=freeze and incident_id are required"}), 400
    if len(incident_id) > 128 or any(
        not (char.isalnum() or char in "._-") for char in incident_id
    ):
        return jsonify({"error": "invalid incident_id"}), 400
    if len(reason) > 1024:
        return jsonify({"error": "reason too long"}), 400
    try:
        _persist_containment_state(incident_id=incident_id, reason=reason)
    except OSError:
        log.exception("failed to persist agent containment latch")
        return jsonify({"error": "cannot persist containment latch"}), 500

    _containment_frozen.set()
    with _tasks_lock:
        for task in _tasks.values():
            _cancel_task_for_containment(task)
    _persist_tasks()
    _audit_log("agent_frozen", {
        "incident_id": incident_id,
        "reason": reason,
    })

    try:
        drain_timeout = min(
            max(float(os.getenv("AGENT_FREEZE_DRAIN_TIMEOUT", "35")), 1.0),
            60.0,
        )
    except ValueError:
        drain_timeout = 35.0
    deadline = time.monotonic() + drain_timeout
    with _execution_condition:
        while _active_executions > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return jsonify({
                    "status": "frozen",
                    "drained": False,
                    "active_executions": _active_executions,
                    "incident_id": incident_id,
                }), 503
            _execution_condition.wait(timeout=remaining)
    return jsonify({
        "status": "frozen",
        "drained": True,
        "active_executions": 0,
        "incident_id": incident_id,
        "persisted": True,
    })


@app.route("/v1/task", methods=["POST"])
def submit_task():
    """Submit a new task for the agent to plan and execute.

    Body: {
        "intent": "summarize the documents in my workspace",
        "mode": "standard",            // optional, default: standard
        "workspace": ["user_docs"],    // optional workspace IDs (resolved server-side)
        "preferences": {}               // optional configurable_prefs
    }
    """
    body, error_response = _json_object()
    if error_response:
        return error_response
    assert body is not None
    if _has_unknown_fields(body, {"intent", "mode", "workspace", "preferences"}):
        return jsonify({"error": "unknown task field"}), 400
    raw_intent = body.get("intent", "")
    if not isinstance(raw_intent, str):
        return jsonify({"error": "intent must be a string"}), 400
    intent = raw_intent.strip()
    if not intent:
        return jsonify({"error": "intent is required"}), 400

    if len(intent) > 2000:
        return jsonify({"error": "intent too long (max 2000 chars)"}), 400

    # Parse session mode
    mode_str = body.get("mode", "standard")
    if not isinstance(mode_str, str):
        return jsonify({"error": "mode must be a string"}), 400
    try:
        mode = SessionMode(mode_str)
    except ValueError:
        return jsonify({"error": f"invalid mode: {mode_str}"}), 400

    # Resolve workspace IDs to filesystem paths (no raw paths from clients)
    workspace_ids = body.get("workspace", [])
    if not isinstance(workspace_ids, list) or len(workspace_ids) > len(
        _WORKSPACE_REGISTRY
    ):
        return jsonify({"error": "workspace must be an array of workspace IDs"}), 400
    if any(
        not isinstance(workspace_id, str) or len(workspace_id) > 64
        for workspace_id in workspace_ids
    ):
        return jsonify({"error": "invalid workspace ID"}), 400
    extra_readable, ws_err = _resolve_workspaces(workspace_ids)
    if ws_err:
        return jsonify({"error": ws_err}), 400

    prefs, prefs_error = _validate_preferences(body.get("preferences", {}))
    if prefs_error:
        return jsonify({"error": prefs_error}), 400
    if not _policy_is_current():
        return jsonify({"error": "agent policy is unavailable or changed; restart required"}), 503

    # Create task first to get task_id
    task = Task(
        intent=intent,
        mode=mode,
    )

    budgets = create_budgets(mode)

    # Create HMAC-signed capability token bound to this task, its policy
    # version, configurable preferences, budget limits, and finite lifetime.
    cap = create_token(
        mode,
        task_id=task.task_id,
        intent=intent,
        policy_path=_POLICY_PATH,
        extra_readable=extra_readable,
        configurable_prefs=prefs,
        custom_budgets=budgets.limits_dict(),
        ttl_seconds=budgets.max_wall_clock_seconds,
    )

    task.capability = cap
    task.budgets = budgets

    # Verify token immediately (proves signing is consistent)
    token_valid, token_reason = verify_token(cap, consume_nonce=True)
    if not token_valid:
        log.error("new capability token failed verification: %s", token_reason)
        return jsonify({"error": "capability authority unavailable"}), 503

    _audit_log("task_submitted", {
        "task_id": task.task_id,
        "intent_hash": hash_intent(intent),
        "intent_length": len(intent),
        "mode": mode.value,
        "token_id": cap.token_id,
        "token_valid": token_valid,
    })

    # This guard is outside the planner's heuristic fallback exception path.
    try:
        _require_runtime_assurance()
    except runtime_assurance.RuntimeAssuranceUnavailable:
        try:
            _audit_log("runtime_assurance_blocked", {"task_id": task.task_id, "action": "plan"})
        except Exception:
            log.error("runtime assurance denial audit unavailable")
        return jsonify({"error": runtime_assurance.UNAVAILABLE}), 503

    # Plan the task
    try:
        steps = _planner.plan(intent, cap, max_steps=budgets.max_steps)
    except ActionUnavailable:
        return jsonify({"error": "requested action is unavailable; choose a supported workflow"}), 400
    except Exception:
        log.error("planning failed")
        task.status = TaskStatus.FAILED
        with _tasks_lock:
            _tasks[task.task_id] = task
        _persist_tasks()
        return jsonify({"error": "planning failed", "task_id": task.task_id}), 500

    task.steps = steps

    # Compute plan hash for audit trail
    plan_hash = hashlib.sha256(
        "|".join(f"{s.action.value}:{s.description}" for s in steps).encode()
    ).hexdigest()[:16]

    # Evaluate each step against policy with decision evidence
    needs_approval = False
    evidence_list: list[dict] = []
    for step in task.steps:
        decision, reason, evidence = _policy.evaluate_with_evidence(
            step, cap, token_valid=token_valid
        )
        step.params["_policy_reason"] = reason
        step.params["_policy_decision"] = decision
        evidence_list.append(evidence.to_dict())

        if decision == "allow":
            step.status = StepStatus.APPROVED
        elif decision == "ask":
            step.status = StepStatus.PENDING
            needs_approval = True
        else:  # deny
            step.status = StepStatus.DENIED
            step.error = reason

        # Bind the evaluated step to the capability and policy state so any
        # mutation between planning, approval, and execution is detected.
        step.signature = sign_step(step, cap)

    if needs_approval:
        task.status = TaskStatus.PENDING_APPROVAL
    elif any(step.status == StepStatus.APPROVED for step in task.steps):
        task.status = TaskStatus.RUNNING
    else:
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()

    with _tasks_lock:
        _tasks[task.task_id] = task
    _persist_tasks()

    if task.status == TaskStatus.RUNNING and not _schedule_execution(task):
        return jsonify({
            "error": "agent execution capacity reached; resubmit later",
            "task_id": task.task_id,
        }), 429

    _audit_log("task_planned", {
        "task_id": task.task_id,
        "plan_hash": plan_hash,
        "steps": len(steps),
        "needs_approval": needs_approval,
        "policy_decisions": evidence_list,
    })

    return jsonify(task.to_dict()), 201


@app.route("/v1/task/<task_id>", methods=["GET"])
def get_task(task_id: str):
    """Get current content or non-executable historical metadata."""
    _refresh_history()
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    return jsonify(task.to_dict())


def _approval_selection(body: dict[str, Any], task: Task):
    if _has_unknown_fields(body, {"step_ids", "expected_plan_revision", "step_hashes"}):
        return None, (jsonify({"error": "unknown approval or denial field"}), 400)
    step_ids = body.get("step_ids")
    if not isinstance(step_ids, list) or not 1 <= len(step_ids) <= 100 or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{12}", item) for item in step_ids) or len(set(step_ids)) != len(step_ids):
        return None, (jsonify({"error": "explicit unique step_ids are required"}), 400)
    revision, hashes = body.get("expected_plan_revision"), body.get("step_hashes")
    if revision is None or hashes is None:
        return None, (jsonify({"error": "refresh the task before deciding", "code": "review_required"}), 409)
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision) or not isinstance(hashes, dict) or set(hashes) != set(step_ids) or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in hashes.values()):
        return None, (jsonify({"error": "invalid reviewed plan snapshot"}), 400)
    try:
        current = approval_snapshot(task)
    except (ValueError, TypeError):
        return None, (jsonify({"error": "plan snapshot unavailable; resubmit with fresh authority"}), 409)
    if not hmac.compare_digest(revision, current["plan_revision"]) or any(identifier not in current["step_hashes"] or not hmac.compare_digest(hashes[identifier], current["step_hashes"][identifier]) for identifier in step_ids):
        return None, (jsonify({"error": "plan changed; review the current task", "code": "stale_review"}), 409)
    return step_ids, None


@app.route("/v1/task/<task_id>/approve", methods=["POST"])
def approve_steps(task_id: str):
    """Approve pending steps in a task (two-phase approval for high-risk).

    A decision requires explicit step IDs and the revision/hashes displayed
    to the user; legacy approve_all is not an authorization surface.
    """
    body, error_response = _json_object()
    if error_response:
        return error_response
    assert body is not None
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404

    with task.runtime_lock:
        if task.history_only:
            return jsonify({"error": "historical metadata cannot be approved"}), 409
        step_ids, error_response = _approval_selection(body, task)
        if error_response:
            return error_response
        if task.status != TaskStatus.PENDING_APPROVAL:
            return jsonify({
                "error": f"task is {task.status.value}, not pending_approval"
            }), 409

        # Verify capability token is still valid before approving.
        token_valid, token_reason = _verify_task_capability(task)
        if not token_valid:
            _audit_log("approval_rejected", {
                "task_id": task_id,
                "reason": f"token invalid: {token_reason}",
            })
            return jsonify({
                "error": f"capability token invalid: {token_reason}",
            }), 403

        pending_ids = {
            step.step_id for step in task.steps
            if step.status == StepStatus.PENDING
        }
        requested_ids = set(step_ids)
        if not requested_ids.issubset(pending_ids):
            return jsonify({"error": "approval contains an unknown or resolved step"}), 400

        approved_count = 0
        integrity_error: tuple[str, str] | None = None
        for step in task.steps:
            if step.status != StepStatus.PENDING:
                continue
            if step.step_id in requested_ids:
                if task.capability is None:
                    task.status = TaskStatus.FAILED
                    integrity_error = (step.step_id, "missing capability token")
                    break
                sig_valid, sig_reason = verify_step_signature(
                    step,
                    task.capability,
                    step.signature,
                )
                if not sig_valid:
                    step.status = StepStatus.FAILED
                    step.error = sig_reason
                    task.status = TaskStatus.FAILED
                    integrity_error = (step.step_id, sig_reason)
                    break
                step.status = StepStatus.APPROVED
                approved_count += 1

        still_pending = any(s.status == StepStatus.PENDING for s in task.steps)
        schedule_execution = integrity_error is None and not still_pending
        if schedule_execution:
            task.status = TaskStatus.RUNNING

    if integrity_error is not None:
        step_id, reason = integrity_error
        _audit_log("approval_rejected", {
            "task_id": task_id,
            "step_id": step_id,
            "reason": reason,
        })
        _persist_tasks()
        return jsonify({
            "error": f"step integrity check failed: {reason}",
            "step_id": step_id,
        }), 409

    _audit_log("steps_approved", {
        "task_id": task_id,
        "approved_count": approved_count,
        "token_id": task.capability.token_id if task.capability else "",
    })

    _persist_tasks()
    if schedule_execution:
        if not _schedule_execution(task):
            return jsonify({
                "error": "agent execution capacity reached; resubmit the task later"
            }), 429

    return jsonify(task.to_dict())


@app.route("/v1/task/<task_id>/deny", methods=["POST"])
def deny_steps(task_id: str):
    """Deny pending steps in a task.

    Denial is also bound to the exact displayed plan and selected steps.
    """
    body, error_response = _json_object()
    if error_response:
        return error_response
    assert body is not None
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    with task.runtime_lock:
        if task.history_only:
            return jsonify({"error": "historical metadata cannot be denied"}), 409
        step_ids, error_response = _approval_selection(body, task)
        if error_response:
            return error_response
        if task.status != TaskStatus.PENDING_APPROVAL:
            return jsonify({
                "error": f"task is {task.status.value}, not pending_approval"
            }), 409
        pending_ids = {
            step.step_id for step in task.steps
            if step.status == StepStatus.PENDING
        }
        requested_ids = set(step_ids)
        if not requested_ids.issubset(pending_ids):
            return jsonify({"error": "denial contains an unknown or resolved step"}), 400

        denied_count = 0
        for step in task.steps:
            if step.status != StepStatus.PENDING:
                continue
            if step.step_id in requested_ids:
                step.status = StepStatus.DENIED
                step.error = "denied by user"
                denied_count += 1

        # If no pending steps remain, proceed with approved ones.
        still_pending = any(s.status == StepStatus.PENDING for s in task.steps)
        schedule_execution = False
        if not still_pending:
            has_approved = any(s.status == StepStatus.APPROVED for s in task.steps)
            if has_approved:
                task.status = TaskStatus.RUNNING
                schedule_execution = True
            else:
                task.status = TaskStatus.CANCELLED
                task.completed_at = time.time()

    _audit_log("steps_denied", {
        "task_id": task_id,
        "denied_count": denied_count,
    })

    _persist_tasks()
    if schedule_execution and not _schedule_execution(task):
        return jsonify({
            "error": "agent execution capacity reached; resubmit the task later"
        }), 429
    return jsonify(task.to_dict())


@app.route("/v1/task/<task_id>/cancel", methods=["POST"])
def cancel_task(task_id: str):
    """Cancel a running or pending task."""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404

    with task.runtime_lock:
        if task.history_only:
            return jsonify({"error": "historical metadata cannot be cancelled"}), 409
        if task.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        ):
            return jsonify({"error": f"task already {task.status.value}"}), 409

        task.status = TaskStatus.CANCELLED
        task.completed_at = time.time()

        # Mark remaining pending/approved steps as skipped.
        for step in task.steps:
            if step.status in (StepStatus.PENDING, StepStatus.APPROVED):
                step.status = StepStatus.SKIPPED

    _audit_log("task_cancelled", {"task_id": task_id})

    _persist_tasks()
    return jsonify(task.to_dict())


@app.route("/v1/tasks", methods=["GET"])
def list_tasks():
    """List retained history and active tasks (most recent first)."""
    _refresh_history()
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid limit"}), 400
    if limit < 1:
        return jsonify({"error": "invalid limit"}), 400
    limit = min(limit, 200)
    with _tasks_lock:
        tasks = sorted(
            _tasks.values(),
            key=lambda t: t.created_at,
            reverse=True,
        )[:limit]
    return jsonify({"tasks": [t.to_dict() for t in tasks]})


@app.route("/v1/history/policy", methods=["GET"])
def history_policy():
    _refresh_history()
    return jsonify(_task_store.policy_status())


@app.route("/v1/history", methods=["DELETE"])
@app.route("/v1/history/<task_id>", methods=["DELETE"])
def delete_history(task_id: str | None = None):
    """Delete terminal history only; never cancel, delete or requeue active work."""
    if request.get_data(cache=True) or request.args:
        return jsonify({"error": "history deletion accepts no body or query parameters"}), 400
    with _history_lock:
        with _tasks_lock:
            snapshot = list(_tasks.values())
        targets = []
        found = task_id is None
        active = 0
        for task in snapshot:
            with task.runtime_lock:
                is_active = not task.history_only and (task.status not in TERMINAL_STATUSES or any(step.status == StepStatus.RUNNING for step in task.steps))
                if is_active:
                    active += 1
                if task_id is None or task.task_id == task_id:
                    found = True
                    if is_active:
                        if task_id is not None:
                            return jsonify({"error": "active work cannot be deleted; cancel it first"}), 409
                    else:
                        targets.append(task.task_id)
        if not found:
            return jsonify({"error": "history record not found"}), 404
        remaining = [task for task in snapshot if task.task_id not in targets]
        if not _task_store.save(remaining):
            return jsonify({"error": "history deletion could not be committed", "deleted": 0}), 503
        with _tasks_lock:
            for identifier in targets:
                _tasks.pop(identifier, None)
        return jsonify({"deleted": len(targets), "active_remaining": active,
                        "external_backups_deleted": False, "audit_evidence_deleted": False})


@app.route("/v1/modes", methods=["GET"])
def list_modes():
    """List available operating modes with descriptions."""
    return jsonify({
        "modes": [
            {
                "id": "offline_only",
                "actions": action_catalog("offline_only"),
                "name": "Offline Only",
                "description": "Strongest privacy. No online actions. Local files only.",
            },
            {
                "id": "standard",
                "actions": action_catalog("standard"),
                "name": "Standard / Autopilot",
                "description": "Default. Low-risk local actions are automatic. Online disabled unless explicitly enabled.",
            },
            {
                "id": "online_assisted",
                "actions": action_catalog("online_assisted"),
                "name": "Online Assisted",
                "description": "May request online augmentation via airlock. Every outbound action needs approval.",
            },
            {
                "id": "sensitive",
                "actions": action_catalog("sensitive"),
                "name": "Sensitive Session",
                "description": "Tighter scopes, aggressive recycling, stricter logging. For especially private tasks.",
            },
        ],
        "unavailable_actions": UNAVAILABLE_ACTIONS,
    })


# --- Background task execution --------------------------------------------

def _capacity_failure(task: Task) -> None:
    with task.runtime_lock:
        task.status = TaskStatus.FAILED
        task.completed_at = time.time()
        for step in task.steps:
            if step.status == StepStatus.APPROVED:
                step.status = StepStatus.FAILED
                step.error = "agent execution capacity reached"
                break
    _audit_log("execution_capacity_rejected", {"task_id": task.task_id})
    _persist_tasks()


def _schedule_execution(task: Task) -> bool:
    if task.history_only:
        return False
    if not _execution_slots.acquire(blocking=False):
        _capacity_failure(task)
        return False
    try:
        with task.runtime_lock:
            # A cancellation can race with slot acquisition. Treat an already
            # terminal task as successfully unscheduled, with no side effects.
            if task.status != TaskStatus.RUNNING:
                _execution_slots.release()
                return True
            threading.Thread(
                target=_execute_task,
                args=(task, True),
                daemon=True,
            ).start()
        return True
    except Exception:
        _execution_slots.release()
        _capacity_failure(task)
        return False


def _execute_task(task: Task, slot_acquired: bool = False):
    """Execute approved steps sequentially in a background thread."""
    global _active_executions
    if task.history_only:
        return
    if not slot_acquired:
        slot_acquired = _execution_slots.acquire(blocking=False)
        if not slot_acquired:
            _capacity_failure(task)
            return
    with _execution_condition:
        _active_executions += 1
    log.info("executing task %s (%d steps)", task.task_id, len(task.steps))

    try:
        with task.runtime_lock:
            if _containment_frozen.is_set():
                _cancel_task_for_containment(task)
                return
        for step in task.steps:
            should_stop = False
            should_persist = False
            with task.runtime_lock:
                # Only execute approved steps.
                if step.status != StepStatus.APPROVED:
                    continue

                # The lock stays held through the one bounded executor call.
                # Cancellation therefore cannot report success while that
                # step is still able to begin a side effect.
                if (
                    task.status == TaskStatus.CANCELLED
                    or _containment_frozen.is_set()
                ):
                    _cancel_task_for_containment(task)
                    step.status = StepStatus.SKIPPED
                    should_stop = True
                    should_persist = True
                elif task.capability and task.capability.is_expired():
                    step.status = StepStatus.FAILED
                    step.error = "capability token expired during execution"
                    task.status = TaskStatus.FAILED
                    _audit_log("token_expired_during_execution", {
                        "task_id": task.task_id,
                        "step_id": step.step_id,
                    })
                    should_stop = True
                    should_persist = True
                else:
                    budget_err = task.budgets.check()
                    if budget_err:
                        step.status = StepStatus.FAILED
                        step.error = budget_err
                        task.status = TaskStatus.FAILED
                        _audit_log("budget_exceeded", {
                            "task_id": task.task_id,
                            "error": budget_err,
                        })
                        should_stop = True
                        should_persist = True
                    elif task.capability is None:
                        step.status = StepStatus.FAILED
                        step.error = "missing capability token"
                        task.status = TaskStatus.FAILED
                        _audit_log("capability_missing", {
                            "task_id": task.task_id,
                        })
                        should_stop = True
                        should_persist = True
                    else:
                        token_valid, token_reason = _verify_task_capability(task)
                        if not token_valid:
                            step.status = StepStatus.FAILED
                            step.error = token_reason
                            task.status = TaskStatus.FAILED
                            _audit_log("token_integrity_violation", {
                                "task_id": task.task_id,
                                "step_id": step.step_id,
                                "reason": token_reason,
                            })
                            should_stop = True
                            should_persist = True
                        else:
                            sig_valid, sig_reason = verify_step_signature(
                                step,
                                task.capability,
                                step.signature,
                            )
                            if not sig_valid:
                                step.status = StepStatus.FAILED
                                step.error = sig_reason
                                task.status = TaskStatus.FAILED
                                _audit_log("step_integrity_violation", {
                                    "task_id": task.task_id,
                                    "step_id": step.step_id,
                                    "reason": sig_reason,
                                })
                                should_stop = True
                                should_persist = True
                            else:
                                cap_valid, cap_reason = revalidate_step_capability(
                                    step,
                                    task.capability,
                                )
                                if not cap_valid:
                                    step.status = StepStatus.FAILED
                                    step.error = cap_reason
                                    task.status = TaskStatus.FAILED
                                    _audit_log("step_capability_violation", {
                                        "task_id": task.task_id,
                                        "step_id": step.step_id,
                                        "reason": cap_reason,
                                    })
                                    should_stop = True
                                    should_persist = True
                                else:
                                    try:
                                        _require_runtime_assurance()
                                    except runtime_assurance.RuntimeAssuranceUnavailable:
                                        step.status = StepStatus.FAILED
                                        step.error = runtime_assurance.UNAVAILABLE
                                        task.status = TaskStatus.FAILED
                                        should_stop = True
                                        should_persist = True
                                        _audit_log("runtime_assurance_blocked", {
                                            "task_id": task.task_id,
                                            "step_id": step.step_id,
                                            "action": "execute",
                                        })
                                    else:
                                        _executor.execute(
                                            step,
                                            task.capability,
                                            task.budgets,
                                        )
                                        _audit_log("step_executed", {
                                            "task_id": task.task_id,
                                            "step_id": step.step_id,
                                            "action": step.action.value,
                                            "status": step.status.value,
                                            "token_id": task.capability.token_id,
                                        })
                                        should_persist = True
                                        if step.status == StepStatus.FAILED:
                                            task.status = TaskStatus.FAILED
                                            should_stop = True

            if should_persist:
                _persist_tasks()
            if should_stop:
                break

        with task.runtime_lock:
            # Finalise task status without overriding a concurrent cancellation.
            if task.status == TaskStatus.RUNNING:
                failed = any(s.status == StepStatus.FAILED for s in task.steps)
                task.status = (
                    TaskStatus.FAILED if failed else TaskStatus.COMPLETED
                )

            if task.completed_at is None:
                task.completed_at = time.time()

            completion_event = {
                "task_id": task.task_id,
                "status": task.status.value,
                "steps_completed": sum(
                    1 for s in task.steps if s.status == StepStatus.COMPLETED
                ),
                "steps_failed": sum(
                    1 for s in task.steps if s.status == StepStatus.FAILED
                ),
                "steps_denied": sum(
                    1 for s in task.steps if s.status == StepStatus.DENIED
                ),
            }
            final_status = task.status.value

        _audit_log("task_completed", completion_event)
        log.info("task %s finished: %s", task.task_id, final_status)
    finally:
        _persist_tasks()
        recycle_worker_state(task.task_id)
        with _execution_condition:
            _active_executions -= 1
            _execution_condition.notify_all()
        if slot_acquired:
            _execution_slots.release()


# --- Security headers ------------------------------------------------------

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# --- Entrypoint ------------------------------------------------------------

def _make_unix_server(sock_path: str):
    """Build a WSGI server bound directly to a Unix domain socket."""
    import socket as _socket
    from pathlib import Path
    from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

    af_unix_raw = getattr(_socket, "AF_UNIX", None)
    if af_unix_raw is None:
        raise RuntimeError("Unix domain sockets are not supported on this platform")
    af_unix = int(af_unix_raw)

    sock_file = Path(sock_path)
    sock_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        sock_file.unlink()
    except FileNotFoundError:
        pass

    class _UnixWSGIServer(WSGIServer):
        address_family = af_unix

        def __init__(self, socket_path: str, handler_cls: type[WSGIRequestHandler]) -> None:
            self._socket_path = socket_path
            super().__init__(("localhost", 0), handler_cls, bind_and_activate=False)
            self.server_address = cast(Any, socket_path)
            self.server_bind()
            self.server_activate()

        def server_bind(self):
            self.socket.bind(self._socket_path)
            self.server_name = "localhost"
            self.server_port = 0
            self.setup_environ()

        def get_request(self):
            request, _client_address = self.socket.accept()
            return request, ("local", 0)

    srv = _UnixWSGIServer(str(sock_file), WSGIRequestHandler)
    srv.set_app(app)
    # The systemd unit places the socket in a dedicated setgid IPC directory
    # shared only with the UI and incident recorder.
    os.chmod(sock_file, 0o660)
    return srv

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    log.info("policy: %s", _POLICY_PATH)
    log.info("vault: %s", _VAULT_ROOT)
    _load_containment_state()
    threading.Thread(target=_history_retention_worker, daemon=True, name="history-retention").start()

    if _BIND_ADDR.startswith("unix:"):
        # Production: listen on a Unix domain socket (no TCP attack surface).
        sock_path = _BIND_ADDR[len("unix:"):]
        srv = _make_unix_server(sock_path)

        log.info("agent service starting on unix:%s", sock_path)
        _audit_log("service_started", {"bind": _BIND_ADDR})
        srv.serve_forever()
    else:
        # Dev / fallback: plain TCP on loopback.
        host, port_str = _BIND_ADDR.rsplit(":", 1)
        port = int(port_str)
        log.info("agent service starting on %s:%d (TCP — dev mode)", host, port)
        _audit_log("service_started", {"bind": _BIND_ADDR})
        app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

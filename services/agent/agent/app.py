"""Agent service Flask API (spec §8, M40 — Verified Supervisor).

Endpoints for task submission, approval, and status.  The agent
orchestrates planner → policy engine → executor with HMAC-signed
capability tokens, two-phase approval for high-risk actions, and
per-step policy decision evidence in the audit trail.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time

from flask import Flask, jsonify, request

from .capabilities import (
    create_budgets,
    create_token,
    hash_intent,
    verify_token,
)
from .executor import Executor
from .models import (
    SessionMode,
    StepStatus,
    Task,
    TaskStatus,
)
from .planner import Planner
from .policy import PolicyEngine
from .storage import StorageGateway

log = logging.getLogger("agent")

app = Flask(__name__)

# --- Configuration ---------------------------------------------------------

_POLICY_PATH = os.getenv("AGENT_POLICY_PATH", "/etc/secure-ai/policy/agent.yaml")
_AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/lib/secure-ai/logs/agent-audit.jsonl")
_VAULT_ROOT = os.getenv("VAULT_ROOT", "/var/lib/secure-ai/vault")
_BIND_ADDR = os.getenv("BIND_ADDR", "127.0.0.1:8476")

# --- Workspace registry (resolve IDs to real paths server-side) ------------

_WORKSPACE_REGISTRY: dict[str, str] = {
    "user_docs": "/var/lib/secure-ai/vault/user_docs/**",
    "outputs": "/var/lib/secure-ai/vault/outputs/**",
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
    from pathlib import Path

    _services_root = str(Path(__file__).resolve().parent.parent.parent)
    if _services_root not in sys.path:
        sys.path.insert(0, _services_root)
    from common.audit_chain import AuditChain

    _audit = AuditChain(_AUDIT_LOG_PATH)
except ImportError:
    log.warning("audit_chain not available, audit logging disabled")

# In-memory task store (single-instance appliance, not shared)
_tasks: dict[str, Task] = {}
_tasks_lock = threading.Lock()

# Background execution thread pool
_MAX_CONCURRENT_TASKS = 4


def _audit_log(event: str, data: dict | None = None):
    """Append an audit entry if the chain is available."""
    if _audit:
        _audit.append(event, data or {})


# --- API Endpoints ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    with _tasks_lock:
        active = sum(1 for t in _tasks.values() if t.status == TaskStatus.RUNNING)
        total = len(_tasks)
    return jsonify({
        "status": "ok",
        "service": "agent",
        "active_tasks": active,
        "total_tasks": total,
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
    body = request.get_json(silent=True) or {}
    intent = body.get("intent", "").strip()
    if not intent:
        return jsonify({"error": "intent is required"}), 400

    if len(intent) > 2000:
        return jsonify({"error": "intent too long (max 2000 chars)"}), 400

    # Parse session mode
    mode_str = body.get("mode", "standard")
    try:
        mode = SessionMode(mode_str)
    except ValueError:
        return jsonify({"error": f"invalid mode: {mode_str}"}), 400

    # Resolve workspace IDs to filesystem paths (no raw paths from clients)
    workspace_ids = body.get("workspace", [])
    if not isinstance(workspace_ids, list):
        return jsonify({"error": "workspace must be an array of workspace IDs"}), 400
    extra_readable, ws_err = _resolve_workspaces(workspace_ids)
    if ws_err:
        return jsonify({"error": ws_err}), 400

    prefs = body.get("preferences", {})

    # Create task first to get task_id
    task = Task(
        intent=intent,
        mode=mode,
    )

    # Create HMAC-signed capability token bound to this task
    cap = create_token(
        mode,
        task_id=task.task_id,
        intent=intent,
        policy_path=_POLICY_PATH,
        extra_readable=extra_readable,
        configurable_prefs=prefs,
    )
    budgets = create_budgets(mode)

    task.capability = cap
    task.budgets = budgets

    # Verify token immediately (proves signing is consistent)
    token_valid, token_reason = verify_token(cap)

    _audit_log("task_submitted", {
        "task_id": task.task_id,
        "intent_hash": hash_intent(intent),
        "intent_length": len(intent),
        "mode": mode.value,
        "token_id": cap.token_id,
        "token_valid": token_valid,
    })

    # Plan the task
    try:
        steps = _planner.plan(intent, cap, max_steps=budgets.max_steps)
    except Exception as exc:
        log.error("planning failed: %s", exc)
        task.status = TaskStatus.FAILED
        with _tasks_lock:
            _tasks[task.task_id] = task
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

    if needs_approval:
        task.status = TaskStatus.PENDING_APPROVAL
    else:
        task.status = TaskStatus.RUNNING
        # Start execution in background
        threading.Thread(
            target=_execute_task,
            args=(task,),
            daemon=True,
        ).start()

    with _tasks_lock:
        _tasks[task.task_id] = task

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
    """Get task status and step details."""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    return jsonify(task.to_dict())


@app.route("/v1/task/<task_id>/approve", methods=["POST"])
def approve_steps(task_id: str):
    """Approve pending steps in a task (two-phase approval for high-risk).

    Body: {
        "step_ids": ["abc123", "def456"],  // specific steps, or omit for all
        "approve_all": false               // approve all pending steps
    }
    """
    body = request.get_json(silent=True) or {}
    step_ids = body.get("step_ids", [])
    approve_all = body.get("approve_all", False)

    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404

    if task.status != TaskStatus.PENDING_APPROVAL:
        return jsonify({"error": f"task is {task.status.value}, not pending_approval"}), 409

    # Verify capability token is still valid before approving
    if task.capability:
        token_valid, token_reason = verify_token(task.capability)
        if not token_valid:
            _audit_log("approval_rejected", {
                "task_id": task_id,
                "reason": f"token invalid: {token_reason}",
            })
            return jsonify({
                "error": f"capability token invalid: {token_reason}",
            }), 403

    approved_count = 0
    for step in task.steps:
        if step.status != StepStatus.PENDING:
            continue
        if approve_all or step.step_id in step_ids:
            step.status = StepStatus.APPROVED
            approved_count += 1

    _audit_log("steps_approved", {
        "task_id": task_id,
        "approved_count": approved_count,
        "token_id": task.capability.token_id if task.capability else "",
    })

    # Check if all pending steps are now resolved
    still_pending = any(s.status == StepStatus.PENDING for s in task.steps)
    if not still_pending:
        task.status = TaskStatus.RUNNING
        threading.Thread(
            target=_execute_task,
            args=(task,),
            daemon=True,
        ).start()

    return jsonify(task.to_dict())


@app.route("/v1/task/<task_id>/deny", methods=["POST"])
def deny_steps(task_id: str):
    """Deny pending steps in a task.

    Body: {
        "step_ids": ["abc123"],
        "deny_all": false
    }
    """
    body = request.get_json(silent=True) or {}
    step_ids = body.get("step_ids", [])
    deny_all = body.get("deny_all", False)

    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404

    denied_count = 0
    for step in task.steps:
        if step.status != StepStatus.PENDING:
            continue
        if deny_all or step.step_id in step_ids:
            step.status = StepStatus.DENIED
            step.error = "denied by user"
            denied_count += 1

    _audit_log("steps_denied", {
        "task_id": task_id,
        "denied_count": denied_count,
    })

    # If no pending steps remain, proceed with approved ones
    still_pending = any(s.status == StepStatus.PENDING for s in task.steps)
    if not still_pending:
        has_approved = any(s.status == StepStatus.APPROVED for s in task.steps)
        if has_approved:
            task.status = TaskStatus.RUNNING
            threading.Thread(
                target=_execute_task,
                args=(task,),
                daemon=True,
            ).start()
        else:
            task.status = TaskStatus.CANCELLED
            task.completed_at = time.time()

    return jsonify(task.to_dict())


@app.route("/v1/task/<task_id>/cancel", methods=["POST"])
def cancel_task(task_id: str):
    """Cancel a running or pending task."""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404

    if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
        return jsonify({"error": f"task already {task.status.value}"}), 409

    task.status = TaskStatus.CANCELLED
    task.completed_at = time.time()

    # Mark remaining pending/approved steps as skipped
    for step in task.steps:
        if step.status in (StepStatus.PENDING, StepStatus.APPROVED):
            step.status = StepStatus.SKIPPED

    _audit_log("task_cancelled", {"task_id": task_id})

    return jsonify(task.to_dict())


@app.route("/v1/tasks", methods=["GET"])
def list_tasks():
    """List all tasks (most recent first)."""
    limit = min(int(request.args.get("limit", 50)), 200)
    with _tasks_lock:
        tasks = sorted(
            _tasks.values(),
            key=lambda t: t.created_at,
            reverse=True,
        )[:limit]
    return jsonify({"tasks": [t.to_dict() for t in tasks]})


@app.route("/v1/modes", methods=["GET"])
def list_modes():
    """List available operating modes with descriptions."""
    return jsonify({
        "modes": [
            {
                "id": "offline_only",
                "name": "Offline Only",
                "description": "Strongest privacy. No online actions. Local files only.",
            },
            {
                "id": "standard",
                "name": "Standard / Autopilot",
                "description": "Default. Low-risk local actions are automatic. Online disabled unless explicitly enabled.",
            },
            {
                "id": "online_assisted",
                "name": "Online Assisted",
                "description": "May request online augmentation via airlock. Every outbound action needs approval.",
            },
            {
                "id": "sensitive",
                "name": "Sensitive Session",
                "description": "Tighter scopes, aggressive recycling, stricter logging. For especially private tasks.",
            },
        ]
    })


# --- Background task execution --------------------------------------------

def _execute_task(task: Task):
    """Execute approved steps sequentially in a background thread."""
    log.info("executing task %s (%d steps)", task.task_id, len(task.steps))

    for step in task.steps:
        # Only execute approved steps
        if step.status != StepStatus.APPROVED:
            continue

        # Check if task was cancelled
        if task.status == TaskStatus.CANCELLED:
            step.status = StepStatus.SKIPPED
            continue

        # Token expiry check before each step
        if task.capability and task.capability.is_expired():
            step.status = StepStatus.FAILED
            step.error = "capability token expired during execution"
            task.status = TaskStatus.FAILED
            _audit_log("token_expired_during_execution", {
                "task_id": task.task_id,
                "step_id": step.step_id,
            })
            break

        # Budget check
        budget_err = task.budgets.check()
        if budget_err:
            step.status = StepStatus.FAILED
            step.error = budget_err
            task.status = TaskStatus.FAILED
            _audit_log("budget_exceeded", {
                "task_id": task.task_id,
                "error": budget_err,
            })
            break

        # Execute step (capability guaranteed non-None by expiry check above)
        assert task.capability is not None
        _executor.execute(step, task.capability, task.budgets)

        _audit_log("step_executed", {
            "task_id": task.task_id,
            "step_id": step.step_id,
            "action": step.action.value,
            "status": step.status.value,
            "token_id": task.capability.token_id if task.capability else "",
        })

        # If step failed and it's critical, stop the task
        if step.status == StepStatus.FAILED:
            task.status = TaskStatus.FAILED
            break

    # Finalise task status
    if task.status == TaskStatus.RUNNING:
        failed = any(s.status == StepStatus.FAILED for s in task.steps)
        task.status = TaskStatus.FAILED if failed else TaskStatus.COMPLETED

    task.completed_at = time.time()

    _audit_log("task_completed", {
        "task_id": task.task_id,
        "status": task.status.value,
        "steps_completed": sum(1 for s in task.steps if s.status == StepStatus.COMPLETED),
        "steps_failed": sum(1 for s in task.steps if s.status == StepStatus.FAILED),
        "steps_denied": sum(1 for s in task.steps if s.status == StepStatus.DENIED),
    })

    log.info("task %s finished: %s", task.task_id, task.status.value)


# --- Security headers ------------------------------------------------------

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# --- Entrypoint ------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    log.info("policy: %s", _POLICY_PATH)
    log.info("vault: %s", _VAULT_ROOT)

    if _BIND_ADDR.startswith("unix:"):
        # Production: listen on a Unix domain socket (no TCP attack surface).
        import socket as _socket
        from wsgiref.simple_server import WSGIServer, make_server

        sock_path = _BIND_ADDR[len("unix:"):]

        # Remove stale socket file if present (e.g. after unclean shutdown).
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        class _UnixWSGIServer(WSGIServer):
            address_family = _socket.AF_UNIX

        srv = make_server("", 0, app, server_class=_UnixWSGIServer)
        # Replace the TCP socket with a Unix one bound to sock_path.
        srv.socket.close()
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.bind(sock_path)
        os.chmod(sock_path, 0o660)
        sock.listen(128)
        srv.socket = sock

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

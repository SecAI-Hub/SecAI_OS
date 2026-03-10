"""Agent service Flask API (spec §8).

Endpoints for task submission, approval, and status.  The agent
orchestrates planner → policy engine → executor with capability
tokens and budget enforcement.
"""

from __future__ import annotations

import logging
import os
import threading
import time

import yaml
from flask import Flask, jsonify, request

from .capabilities import create_budgets, create_token
from .executor import Executor
from .models import (
    CapabilityToken,
    RiskLevel,
    SessionMode,
    Step,
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
        "workspace": ["/vault/user_docs"],  // optional extra readable paths
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

    # Create capability token
    extra_readable = body.get("workspace", [])
    prefs = body.get("preferences", {})
    cap = create_token(mode, extra_readable=extra_readable, configurable_prefs=prefs)
    budgets = create_budgets(mode)

    # Create task
    task = Task(
        intent=intent,
        mode=mode,
        capability=cap,
        budgets=budgets,
    )

    _audit_log("task_submitted", {
        "task_id": task.task_id,
        "intent_length": len(intent),
        "mode": mode.value,
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

    # Evaluate each step against policy
    needs_approval = False
    for step in task.steps:
        decision, reason = _policy.evaluate(step, cap)
        step.params["_policy_reason"] = reason

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
        "steps": len(steps),
        "needs_approval": needs_approval,
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
    """Approve pending steps in a task.

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

        # Execute step
        _executor.execute(step, task.capability, task.budgets)

        _audit_log("step_executed", {
            "task_id": task.task_id,
            "step_id": step.step_id,
            "action": step.action.value,
            "status": step.status.value,
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

    host, port_str = _BIND_ADDR.rsplit(":", 1)
    port = int(port_str)

    log.info("agent service starting on %s:%d", host, port)
    log.info("policy: %s", _POLICY_PATH)
    log.info("vault: %s", _VAULT_ROOT)

    _audit_log("service_started", {"bind": _BIND_ADDR})

    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

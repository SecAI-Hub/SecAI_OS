"""Public review identities for signed operations; these hashes grant no authority."""
import hashlib
import json


def _canonical(value) -> bytes:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 20_000 or depth > 32:
            raise ValueError("approval snapshot exceeds structural limits")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("approval snapshot has an invalid key")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise ValueError("approval snapshot has an invalid value")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ValueError("approval snapshot is not canonical JSON") from error
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("approval snapshot exceeds review size limit")
    return encoded


def approval_snapshot(task) -> dict:
    """Snapshot immutable operation and authority fields under the caller's lock.

    Execution status/results and authenticators are deliberately excluded. Full
    material params, policy decision/reason, scopes and both budget limit sources
    are bound. Existing capability/step signatures must still be revalidated by
    the caller; a client-provided hash can never authorize a changed operation.
    """
    cap = task.capability
    if cap is None:
        raise ValueError("task has no live approval authority")
    scope = {
        "readable_paths": cap.readable_paths,
        "writable_paths": cap.writable_paths,
        "allowed_tools": cap.allowed_tools,
        "allow_online": cap.allow_online,
        "sensitivity_ceiling": cap.sensitivity_ceiling.value,
        "expires_at": cap.expires_at,
    }
    limits = task.budgets.limits_dict()
    authority = {
        "scope": scope, "budget_limits": limits, "capability_limits": cap.budget_limits,
        "preferences": cap.configurable_prefs, "policy_digest": cap.policy_digest,
        "capability_task_id": cap.task_id, "intent_hash": cap.intent_hash,
        "issued_at": cap.issued_at, "mode": task.mode.value, "capability_mode": cap.session_mode.value,
    }
    operations = []
    hashes = {}
    for step in task.steps:
        if step.step_id in hashes:
            raise ValueError("approval snapshot has duplicate step IDs")
        operation = {
            "step_id": step.step_id, "action": step.action.value,
            "description": step.description, "params": step.params,
            "risk_level": step.risk_level.value,
        }
        operations.append(operation)
        hashes[step.step_id] = hashlib.sha256(_canonical({"authority": authority, "operation": operation})).hexdigest()
    revision = hashlib.sha256(_canonical({
        "task_id": task.task_id, "intent": task.intent,
        "authority": authority, "operations": operations,
    })).hexdigest()
    # Copy the snapshot so later task mutation cannot change already-rendered
    # scope/limits while leaving their revision unchanged.
    return json.loads(_canonical({
        "plan_revision": revision, "step_hashes": hashes,
        "approval_scope": scope, "approval_budgets": limits,
    }))

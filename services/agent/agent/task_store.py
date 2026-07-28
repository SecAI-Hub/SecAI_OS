"""Bounded, atomic persistence for Agent task history.

Capability tokens and internal step signatures are deliberately never written
to disk. Tasks that were not terminal at shutdown are restored for visibility
as recovery-required records and must be resubmitted with a fresh capability.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any

from .models import (
    Budgets,
    RiskLevel,
    SessionMode,
    Step,
    StepAction,
    StepStatus,
    Task,
    TaskStatus,
)


_TERMINAL_STATUSES = {
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
    TaskStatus.RECOVERY_REQUIRED,
}
_SENSITIVE_KEY_MARKERS = (
    "authorization",
    "body",
    "capability",
    "content",
    "credential",
    "nonce",
    "password",
    "secret",
    "signature",
    "text",
    "token",
)


def _safe_text(value: object, limit: int) -> str:
    text = value if isinstance(value, str) else ""
    return text[:limit]


def _redact(value: object, *, depth: int = 0) -> Any:
    """Produce a bounded JSON-safe value while removing likely credentials."""
    if depth >= 8:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:16_384]
    if isinstance(value, list):
        return [_redact(item, depth=depth + 1) for item in value[:256]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:256]:
            key = str(raw_key)[:128]
            lowered = key.lower()
            if any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS):
                result[key] = "[redacted]"
            else:
                result[key] = _redact(item, depth=depth + 1)
        return result
    return str(value)[:1024]


def _task_snapshot(task: Task) -> dict[str, Any]:
    """Serialize task history without live authority or authenticators."""
    with task.runtime_lock:
        return {
            "task_id": task.task_id,
            "intent": task.intent[:2000],
            "status": task.status.value,
            "mode": task.mode.value,
            "steps": [
                {
                    "step_id": step.step_id,
                    "action": step.action.value,
                    "description": step.description[:4096],
                    "risk_level": step.risk_level.value,
                    "status": step.status.value,
                    "params": _redact(step.params),
                    "result": _redact(step.result),
                    "error": _safe_text(step.error, 4096) if step.error else None,
                }
                for step in task.steps[:100]
            ],
            # Persist only usage counters needed for historical diagnostics.
            # Budget authority is not restored after a restart.
            "budget_usage": {
                "steps_used": task.budgets.steps_used,
                "tool_calls_used": task.budgets.tool_calls_used,
                "tokens_used": task.budgets.tokens_used,
                "files_touched": task.budgets.files_touched,
                "output_bytes_used": task.budgets.output_bytes_used,
            },
            "created_at": task.created_at,
            "completed_at": task.completed_at,
        }


def _finite_time(value: object, default: float | None = None) -> float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 < value <= time.time() + 300
    ):
        return float(value)
    return default


def _restore_step(raw: object) -> Step | None:
    if not isinstance(raw, dict):
        return None
    try:
        step = Step(
            step_id=_safe_text(raw.get("step_id"), 64),
            action=StepAction(raw.get("action")),
            description=_safe_text(raw.get("description"), 4096),
            risk_level=RiskLevel(raw.get("risk_level")),
            status=StepStatus(raw.get("status")),
            params=_redact(raw.get("params", {})),
            result=_redact(raw.get("result")) if raw.get("result") is not None else None,
            error=_safe_text(raw.get("error"), 4096) if raw.get("error") else None,
            signature="",
        )
    except (TypeError, ValueError):
        return None
    if not step.step_id:
        return None
    return step


def _restore_task(raw: object) -> Task | None:
    if not isinstance(raw, dict):
        return None
    try:
        status = TaskStatus(raw.get("status"))
        task = Task(
            task_id=_safe_text(raw.get("task_id"), 64),
            intent=_safe_text(raw.get("intent"), 2000),
            status=status,
            mode=SessionMode(raw.get("mode")),
            steps=[
                step
                for item in list(raw.get("steps", []))[:100]
                if (step := _restore_step(item)) is not None
            ],
            capability=None,
            budgets=Budgets(),
            created_at=_finite_time(raw.get("created_at"), time.time()) or time.time(),
            completed_at=_finite_time(raw.get("completed_at")),
        )
    except (TypeError, ValueError):
        return None
    if not task.task_id or not task.intent:
        return None

    usage = raw.get("budget_usage")
    if isinstance(usage, dict):
        for name in (
            "steps_used",
            "tool_calls_used",
            "tokens_used",
            "files_touched",
            "output_bytes_used",
        ):
            value = usage.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                setattr(task.budgets, name, min(value, 2**31 - 1))

    if status not in _TERMINAL_STATUSES:
        task.status = TaskStatus.RECOVERY_REQUIRED
        task.completed_at = time.time()
        for step in task.steps:
            if step.status in {
                StepStatus.PENDING,
                StepStatus.APPROVED,
                StepStatus.RUNNING,
            }:
                step.status = StepStatus.FAILED
                step.error = "interrupted by service restart; resubmit the task"
    return task


class TaskStore:
    """Atomic JSON task history with strict size and count bounds."""

    VERSION = 1

    def __init__(self, path: str | Path | None, *, max_tasks: int = 500) -> None:
        self.path = Path(path) if path else None
        self.max_tasks = max(1, min(int(max_tasks), 5000))
        self._lock = threading.Lock()
        self.last_error: str | None = None

    @property
    def healthy(self) -> bool:
        return self.last_error is None

    def load(self) -> dict[str, Task]:
        if self.path is None:
            return {}
        try:
            if not self.path.exists():
                self.last_error = None
                return {}
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_size > 16 * 1024 * 1024
                ):
                    raise ValueError("unsafe task-state file")
                raw = os.read(descriptor, 16 * 1024 * 1024 + 1)
            finally:
                os.close(descriptor)
            payload = json.loads(raw)
            if not isinstance(payload, dict) or payload.get("version") != self.VERSION:
                self.last_error = "task-state schema is invalid"
                return {}
            restored: dict[str, Task] = {}
            for raw in list(payload.get("tasks", []))[-self.max_tasks :]:
                task = _restore_task(raw)
                if task is not None:
                    restored[task.task_id] = task
            try:
                self.path.chmod(0o660)
            except OSError:
                pass
            self.last_error = None
            return restored
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            self.last_error = "task-state could not be loaded safely"
            return {}

    def save(self, tasks: list[Task]) -> bool:
        if self.path is None:
            self.last_error = None
            return True
        with self._lock:
            ordered = sorted(tasks, key=lambda task: task.created_at)[-self.max_tasks :]
            payload = {
                "version": self.VERSION,
                "tasks": [_task_snapshot(task) for task in ordered],
            }
            parent = self.path.parent
            temporary: Path | None = None
            fd: int | None = None
            try:
                parent.mkdir(mode=0o2770, parents=True, exist_ok=True)
                try:
                    parent.chmod(0o2770)
                except OSError:
                    pass
                temporary = parent / (
                    f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
                )
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o660,
                )
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                    fd = None
                    json.dump(payload, handle, separators=(",", ":"), allow_nan=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                temporary = None
                self.path.chmod(0o660)
                try:
                    directory_fd = os.open(parent, os.O_RDONLY)
                except OSError:
                    directory_fd = None
                if directory_fd is not None:
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                self.last_error = None
                return True
            except (OSError, TypeError, ValueError):
                # Persistence must never cause the policy/execution API to fail.
                self.last_error = "task-state could not be persisted"
                return False
            finally:
                if fd is not None:
                    os.close(fd)
                if temporary is not None:
                    try:
                        temporary.unlink()
                    except OSError:
                        pass

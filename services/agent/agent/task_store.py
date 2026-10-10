"""Bounded metadata-only history, separate from live task authority and content.

Version 1 may contain user content. It is deliberately neither restored nor
silently overwritten; an administrator must review an offline upgrade first.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

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

TERMINAL_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.RECOVERY_REQUIRED})
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 5000
_CLOCK_SKEW = 300
_COUNTERS = ('steps_used', 'tool_calls_used', 'tokens_used', 'files_touched', 'output_bytes_used')
_TASK_FIELDS = {'task_id', 'status', 'mode', 'steps', 'budget_usage', 'created_at', 'completed_at', 'expires_at'}
_STEP_FIELDS = {'step_id', 'action', 'risk_level', 'status', 'decision'}


@dataclass(frozen=True)
class HistoryPolicy:
    max_tasks: int = 500
    ttl_seconds: int = 7 * 24 * 3600
    store_raw_prompts: bool = False
    store_raw_responses: bool = False

    def __post_init__(self):
        for name, minimum, maximum in [('max_tasks', 1, MAX_RECORDS), ('ttl_seconds', 60, 30 * 24 * 3600)]:
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f'invalid history {name}')
        if type(self.store_raw_prompts) is not bool or type(self.store_raw_responses) is not bool:
            raise ValueError('raw logging preferences must be booleans')


def _read_regular(path: Path, limit: int, *, configuration: bool = False) -> bytes:
    if any(parent.is_symlink() for parent in path.absolute().parents):
        raise ValueError('symlinked history/configuration directory')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('unsafe history/configuration file')
        if configuration and info.st_mode & 0o022:
            raise ValueError('configuration is writable by an untrusted group or user')
        if not configuration and info.st_mode & 0o007:
            raise ValueError('history must not be accessible to other users')
        raw = os.read(descriptor, limit + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        if len(raw) != info.st_size or len(raw) > limit or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('history/configuration changed during read')
        return raw
    finally:
        os.close(descriptor)


def history_policy_from_config(path: str | Path | None = None, *, environ=None) -> HistoryPolicy:
    """Validate logging preferences; they never authorize raw history storage."""
    env = os.environ if environ is None else environ
    configured = path or env.get('APPLIANCE_CONFIG')
    source = Path(configured or '/etc/secure-ai/config/appliance.yaml')
    try:
        data = yaml.safe_load(_read_regular(source, 1024 * 1024, configuration=True))
    except FileNotFoundError:
        if configured:
            raise ValueError('explicit appliance privacy configuration is unavailable') from None
        data = {}
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        raise ValueError('appliance privacy configuration is invalid') from None
    if not isinstance(data, dict):
        raise ValueError('appliance privacy configuration must be an object')
    logging_config = data.get('logging', {})
    if not isinstance(logging_config, dict):
        raise ValueError('logging configuration must be an object')
    values = {}
    for variable, field, default in [('AGENT_TASK_HISTORY_LIMIT', 'max_tasks', 500),
                                      ('AGENT_TASK_HISTORY_TTL_SECONDS', 'ttl_seconds', 604800)]:
        raw = env.get(variable)
        if raw is None:
            values[field] = default
        elif not isinstance(raw, str) or not re.fullmatch(r'[1-9][0-9]{0,7}', raw):
            raise ValueError(f'invalid {variable}')
        else:
            values[field] = int(raw)
    return HistoryPolicy(**values, store_raw_prompts=logging_config.get('store_raw_prompts', False),
                         store_raw_responses=logging_config.get('store_raw_responses', False))


def _timestamp(value: object) -> float:
    if type(value) not in (int, float):
        raise ValueError('invalid history timestamp')
    numeric = cast(int | float, value)
    if not 0 < numeric <= 32503680000 or not math.isfinite(numeric):
        raise ValueError('invalid history timestamp')
    return float(numeric)


def _identifier(value: object, length: int) -> str:
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError('invalid generated history identifier')
    return value


def _counter(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**31 - 1:
        raise ValueError('invalid history counter')
    return value


def _task_snapshot(task: Task, ttl_seconds: int) -> dict[str, Any]:
    """Whitelist machine metadata; never inspect arbitrary content or key names."""
    with task.runtime_lock:
        created = _timestamp(task.created_at)
        completed = _timestamp(task.completed_at) if task.completed_at is not None else None
        if completed is not None and (completed < created or task.status not in TERMINAL_STATUSES):
            raise ValueError('history completion is inconsistent')
        anchor = completed if task.status in TERMINAL_STATUSES and completed is not None else created
        expires = anchor + ttl_seconds
        if task.history_only and task.history_expires_at is not None:
            expires = min(expires, _timestamp(task.history_expires_at))
        if expires < created:
            raise ValueError("history expires before task creation")
        if len({step.step_id for step in task.steps[:100]}) != len(task.steps[:100]):
            raise ValueError("duplicate step identifier")
        task.history_expires_at = expires
        return {
            'task_id': _identifier(task.task_id, 16), 'status': TaskStatus(task.status).value,
            'mode': SessionMode(task.mode).value,
            'steps': [{'step_id': _identifier(step.step_id, 12), 'action': StepAction(step.action).value,
                       'risk_level': RiskLevel(step.risk_level).value, 'status': StepStatus(step.status).value,
                       'decision': step.params.get('_policy_decision') if isinstance(step.params.get('_policy_decision'), str) and step.params['_policy_decision'] in {'allow', 'ask', 'deny'} else 'unknown'}
                      for step in task.steps[:100]],
            'budget_usage': {name: _counter(getattr(task.budgets, name)) for name in _COUNTERS},
            'created_at': created,
            'completed_at': completed,
            'expires_at': expires,
        }


def _restore_task(raw: object, now: float, ttl_seconds: int, *, recorded_at: float | None = None) -> Task:
    if not isinstance(raw, dict) or set(raw) != _TASK_FIELDS:
        raise ValueError('history record is not metadata-only')
    created = _timestamp(raw['created_at'])
    completed = _timestamp(raw['completed_at']) if raw['completed_at'] is not None else None
    status = TaskStatus(raw['status'])
    if completed is not None and (completed < created or status not in TERMINAL_STATUSES):
        raise ValueError('history completion is inconsistent')
    expires = _timestamp(raw['expires_at'])
    ceiling = min(now, recorded_at if recorded_at is not None else now)
    if created > ceiling or (completed is not None and completed > ceiling) or expires < created or expires > max(created, completed or created) + 30 * 24 * 3600:
        raise ValueError('history timestamp is inconsistent')
    if not isinstance(raw['steps'], list) or len(raw['steps']) > 100:
        raise ValueError('invalid history steps')
    steps = []
    seen = set()
    for item in raw['steps']:
        if not isinstance(item, dict) or set(item) != _STEP_FIELDS or item['decision'] not in ('allow', 'ask', 'deny', 'unknown'):
            raise ValueError('invalid history step metadata')
        identifier = _identifier(item['step_id'], 12)
        if identifier in seen:
            raise ValueError('duplicate historical step identifier')
        seen.add(identifier)
        steps.append(Step(step_id=identifier, action=StepAction(item['action']), risk_level=RiskLevel(item['risk_level']),
                          status=StepStatus(item['status']), params={'_policy_decision': item['decision']}))
    if not isinstance(raw['budget_usage'], dict) or set(raw['budget_usage']) != set(_COUNTERS):
        raise ValueError('invalid history counters')
    budgets = Budgets()
    for name in _COUNTERS:
        setattr(budgets, name, _counter(raw['budget_usage'][name]))
    if status not in TERMINAL_STATUSES:
        status = TaskStatus.RECOVERY_REQUIRED
        for step in steps:
            if step.status in {StepStatus.PENDING, StepStatus.APPROVED, StepStatus.RUNNING}:
                step.status = StepStatus.FAILED
    return Task(task_id=_identifier(raw['task_id'], 16), status=status, mode=SessionMode(raw['mode']),
                intent='', steps=steps, capability=None, budgets=budgets, created_at=created, completed_at=completed,
                history_only=True, history_expires_at=min(expires, (completed or created) + ttl_seconds))


class TaskStore:
    """Atomic bounded metadata store; legacy/raw/corrupt state blocks replacement."""
    VERSION = 2

    def __init__(self, path: str | Path | None, *, max_tasks: int = 500, ttl_seconds: int = 604800,
                 policy: HistoryPolicy | None = None, configuration_error: str | None = None):
        self.path = Path(path) if path else None
        self.policy = policy or HistoryPolicy(max_tasks=max_tasks, ttl_seconds=ttl_seconds)
        self.max_tasks = self.policy.max_tasks
        self.ttl_seconds = self.policy.ttl_seconds
        self._lock = threading.RLock()
        self._loaded = False
        self._blocked = configuration_error is not None
        self._last_seen = 0.0
        self._expected_file = False
        self._expected_digest: str | None = None
        self.last_error = configuration_error

    @property
    def healthy(self) -> bool:
        return self.last_error is None

    @property
    def blocked(self) -> bool:
        return self._blocked

    def policy_status(self) -> dict:
        return {'schema_version': self.VERSION, 'storage_policy': 'metadata_only',
                'max_tasks': self.max_tasks, 'ttl_seconds': self.ttl_seconds,
                'history_ready': self.healthy, 'legacy_state_blocked': self._blocked,
                'persistent': self.path is not None, 'raw_content_persisted': False,
                'active_content': 'memory_only', 'restart_behavior': 'metadata_only_not_executable',
                'retention_basis': 'terminal_completion_or_task_creation', 'external_backups_deleted': False}

    def _now(self) -> float:
        now = _timestamp(time.time())
        if now + _CLOCK_SKEW < self._last_seen:
            raise ValueError('history clock moved backwards; restart with reviewed time required')
        self._last_seen = max(now, self._last_seen)
        return self._last_seen

    def retained_tasks(self, tasks: list[Task]) -> list[Task]:
        """Retention view; never discard active runtime work."""
        with self._lock:
            now = self._now()
            def anchor(task):
                return task.completed_at if task.status in TERMINAL_STATUSES and task.completed_at is not None else task.created_at
            def expiry(task):
                current = anchor(task) + self.ttl_seconds
                return min(current, task.history_expires_at) if task.history_only and task.history_expires_at is not None else current
            eligible = [task for task in tasks if expiry(task) > now]
            kept = {task.task_id for task in sorted(eligible, key=lambda item: (anchor(item), item.task_id))[-self.max_tasks:]}
            return [task for task in tasks if task.task_id in kept or (not task.history_only and (task.status not in TERMINAL_STATUSES or any(step.status == StepStatus.RUNNING for step in task.steps)))]

    def _read(self) -> dict[str, Task]:
        if self._blocked:
            return {}
        if self.path is None:
            self._loaded = True
            return {}
        try:
            raw = _read_regular(self.path, MAX_STATE_BYTES)
        except FileNotFoundError:
            if self._expected_file:
                raise ValueError('previous history file disappeared')
            self._loaded = True
            return {}
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {'version', 'updated_at', 'tasks'} or type(payload['version']) is not int or payload['version'] != self.VERSION:
            raise ValueError('legacy or invalid history schema; explicit offline upgrade required')
        if not isinstance(payload['tasks'], list) or len(payload['tasks']) > MAX_RECORDS:
            raise ValueError('invalid history record count')
        observed = _timestamp(payload['updated_at'])
        self._last_seen = max(self._last_seen, observed)
        now = self._now()
        restored = {}
        for record in payload['tasks']:
            task = _restore_task(record, now, self.ttl_seconds, recorded_at=observed)
            if task.task_id in restored:
                raise ValueError('duplicate historical task identifier')
            restored[task.task_id] = task
        self._loaded = True
        self._expected_file = True
        self._expected_digest = hashlib.sha256(raw).hexdigest()
        retained = self.retained_tasks(list(restored.values()))
        if len(retained) != len(restored):
            self._write(retained)
        return {task.task_id: task for task in retained}

    @contextmanager
    def _disk_guard(self):
        if self.path is None:
            yield
            return
        parent = self.path.parent
        if any(item.is_symlink() for item in [parent, *parent.absolute().parents]):
            raise ValueError("unsafe history directory")
        if not parent.exists():
            parent.mkdir(mode=0o2770, parents=True)
            parent.chmod(0o2770)
        if parent.stat().st_mode & 0o007:
            raise ValueError("history directory is accessible to other users")
        lock_path = parent / f".{self.path.name}.lock"
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
            try:
                os.fchmod(fd, 0o660)
            except BaseException:
                os.close(fd)
                raise
        except FileExistsError:
            fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o660:
                raise ValueError("unsafe history lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # A crash may leave an uncommitted v2 temporary file. Only metadata
            # written by this schema is removed; old/unknown data needs review.
            pattern = re.compile(re.escape(f".{self.path.name}.") + r"[0-9]+\.[a-f0-9]{16}\.tmp")
            removed = False
            for candidate in parent.iterdir():
                if pattern.fullmatch(candidate.name):
                    payload = json.loads(_read_regular(candidate, MAX_STATE_BYTES))
                    if not isinstance(payload, dict) or set(payload) != {"version", "updated_at", "tasks"} or payload["version"] != self.VERSION or not isinstance(payload["tasks"], list) or len(payload["tasks"]) > MAX_RECORDS:
                        raise ValueError("unreviewed historical temporary state")
                    for raw in payload["tasks"]:
                        _restore_task(raw, self._now(), self.ttl_seconds, recorded_at=_timestamp(payload["updated_at"]))
                    candidate.unlink()
                    removed = True
            if removed:
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            yield
        finally:
            os.close(fd)

    def load(self) -> dict[str, Task]:
        with self._lock:
            if self._blocked:
                return {}
            try:
                with self._disk_guard():
                    restored = self._read()
                self.last_error = None
                return restored
            except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
                self._blocked = True
                self.last_error = 'history unavailable; preserve state and perform a reviewed offline upgrade or recovery'
                return {}

    def _write(self, tasks: list[Task]) -> None:
        records = [_task_snapshot(task, self.ttl_seconds) for task in tasks]
        if len({record["task_id"] for record in records}) != len(records):
            raise ValueError("duplicate task identifier")
        now = self._now()
        if any(item['created_at'] > now or (item['completed_at'] is not None and item['completed_at'] > now) for item in records):
            raise ValueError('task history timestamp is in the future')
        records = sorted((item for item in records if item['expires_at'] > now), key=lambda item: (item['completed_at'] or item['created_at'], item['task_id']))[-self.max_tasks:]
        data = (json.dumps({'version': self.VERSION, 'updated_at': now, 'tasks': records}, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(data) > MAX_STATE_BYTES:
            raise ValueError('history exceeds byte limit')
        if self.path is None:
            return
        parent = self.path.parent
        if any(item.is_symlink() for item in [parent, *parent.absolute().parents]):
            raise ValueError('unsafe history directory')
        parent.mkdir(mode=0o2770, parents=True, exist_ok=True)
        metadata = parent.stat()
        if metadata.st_mode & 0o007:
            raise ValueError('history directory is accessible to other users')
        if not self._expected_file and os.path.lexists(self.path):
            raise ValueError('unreviewed history appeared before save')
        if self._expected_file:
            previous = _read_regular(self.path, MAX_STATE_BYTES)
            if hashlib.sha256(previous).hexdigest() != self._expected_digest:
                raise ValueError("history changed outside this process")
        temporary = parent / f'.{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp'
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o660)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            self._expected_file = True
            self._expected_digest = hashlib.sha256(data).hexdigest()
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()

    def save(self, tasks: list[Task]) -> bool:
        with self._lock:
            if self._blocked:
                return False
            try:
                with self._disk_guard():
                    if not self._loaded:
                        self._read()
                    self._write(tasks)
                self.last_error = None
                return True
            except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
                self.last_error = 'task history could not be persisted'
                if not self._loaded:
                    self._blocked = True
                return False

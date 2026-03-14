"""Data models for the agent service.

Defines tasks, steps, capability tokens, operating modes, sensitivity
labels, budgets, and the risk classification taxonomy used by the
policy engine.
"""

from __future__ import annotations

import enum
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SessionMode(str, enum.Enum):
    """Operating modes from spec §3."""
    OFFLINE_ONLY = "offline_only"
    STANDARD = "standard"           # default — assisted autopilot
    ONLINE_ASSISTED = "online_assisted"
    SENSITIVE = "sensitive"


class RiskLevel(str, enum.Enum):
    """Risk tiers from spec §7."""
    AUTO = "auto"                    # low-risk, execute immediately
    CONFIGURABLE = "configurable"    # medium-risk, user preference
    APPROVAL_REQUIRED = "approval_required"  # high-risk, always ask


class SensitivityLevel(str, enum.Enum):
    """Content sensitivity labels from spec §6."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StepAction(str, enum.Enum):
    """Recognised agent actions (spec §4, §5, §10)."""
    # --- allow by default (auto) ---
    LOCAL_SEARCH = "local_search"
    SUMMARIZE = "summarize"
    DRAFT = "draft"
    CLASSIFY = "classify"
    REPORT = "report"
    EXPLAIN_SECURITY = "explain_security"

    # --- configurable (medium-risk) ---
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    OVERWRITE_FILE = "overwrite_file"
    TOOL_INVOKE = "tool_invoke"

    # --- approval required (high-risk) ---
    OUTBOUND_REQUEST = "outbound_request"
    EXPORT_DATA = "export_data"
    TRUST_CHANGE = "trust_change"
    BATCH_DELETE = "batch_delete"
    WIDEN_SCOPE = "widen_scope"
    ENABLE_TOOL = "enable_tool"
    CHANGE_SECURITY = "change_security"


class StepStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskStatus(str, enum.Enum):
    PLANNING = "planning"
    PENDING_APPROVAL = "pending_approval"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Budget limits
# ---------------------------------------------------------------------------

@dataclass
class Budgets:
    """Hard budget caps from spec §6."""
    max_steps: int = 20
    max_tool_calls: int = 50
    max_tokens: int = 32_000
    max_wall_clock_seconds: float = 300.0   # 5 min
    max_files_touched: int = 20
    max_output_bytes: int = 1_048_576       # 1 MB

    # runtime counters
    steps_used: int = 0
    tool_calls_used: int = 0
    tokens_used: int = 0
    files_touched: int = 0
    output_bytes_used: int = 0
    start_time: float = field(default_factory=time.time)

    def check(self) -> str | None:
        """Return an error message if any budget is exceeded, else None."""
        if self.steps_used >= self.max_steps:
            return f"step budget exceeded ({self.steps_used}/{self.max_steps})"
        if self.tool_calls_used >= self.max_tool_calls:
            return f"tool-call budget exceeded ({self.tool_calls_used}/{self.max_tool_calls})"
        if self.tokens_used >= self.max_tokens:
            return f"token budget exceeded ({self.tokens_used}/{self.max_tokens})"
        elapsed = time.time() - self.start_time
        if elapsed >= self.max_wall_clock_seconds:
            return f"wall-clock budget exceeded ({elapsed:.0f}s/{self.max_wall_clock_seconds:.0f}s)"
        if self.files_touched >= self.max_files_touched:
            return f"files-touched budget exceeded ({self.files_touched}/{self.max_files_touched})"
        if self.output_bytes_used >= self.max_output_bytes:
            return f"output-size budget exceeded ({self.output_bytes_used}/{self.max_output_bytes})"
        return None


# ---------------------------------------------------------------------------
# Capability token
# ---------------------------------------------------------------------------

@dataclass
class CapabilityToken:
    """Per-run capability token from spec §6.

    Defines exactly what a task run is allowed to do: which paths it
    can read/write, which tools it may invoke, whether online access
    is possible, and the maximum sensitivity level it may handle.

    Tokens are cryptographically signed (HMAC-SHA256) and bound to
    a specific task context to prevent reuse, replay, and tampering.
    """
    token_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    readable_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    allow_online: bool = False
    sensitivity_ceiling: SensitivityLevel = SensitivityLevel.LOW
    session_mode: SessionMode = SessionMode.STANDARD

    # User preferences for medium-risk actions: action -> "always" | "ask" | "never"
    configurable_prefs: dict[str, str] = field(default_factory=dict)

    # --- Cryptographic binding (M40 — Verified Supervisor) ---
    task_id: str = ""              # bound task ID
    intent_hash: str = ""          # SHA-256 of the original intent string
    policy_digest: str = ""        # SHA-256 of the policy file at token creation
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0        # 0 = inherit from budget wall-clock
    signature: str = ""            # HMAC-SHA256 hex digest

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "readable_paths": self.readable_paths,
            "writable_paths": self.writable_paths,
            "allowed_tools": self.allowed_tools,
            "allow_online": self.allow_online,
            "sensitivity_ceiling": self.sensitivity_ceiling.value,
            "session_mode": self.session_mode.value,
            "task_id": self.task_id,
            "intent_hash": self.intent_hash,
            "policy_digest": self.policy_digest,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }

    def is_expired(self) -> bool:
        """Check whether this token has passed its expiry time."""
        if self.expires_at <= 0:
            return False
        return time.time() > self.expires_at


# ---------------------------------------------------------------------------
# Step & Task
# ---------------------------------------------------------------------------

@dataclass
class Step:
    """A single planned action within a task."""
    step_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    action: StepAction = StepAction.SUMMARIZE
    description: str = ""
    risk_level: RiskLevel = RiskLevel.AUTO
    status: StepStatus = StepStatus.PENDING
    params: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "action": self.action.value,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "status": self.status.value,
            "params": self.params,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class PolicyDecision:
    """Per-step policy decision evidence (M40 — Verified Supervisor).

    Records the full decision context for each step so the audit trail
    can prove exactly why an action was allowed, denied, or escalated.
    """
    step_id: str = ""
    action: str = ""
    decision: str = ""              # "allow" | "ask" | "deny"
    reason: str = ""
    risk_level: str = ""
    token_id: str = ""
    token_valid: bool = False
    policy_digest: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "token_id": self.token_id,
            "token_valid": self.token_valid,
            "policy_digest": self.policy_digest,
            "timestamp": self.timestamp,
        }


# High-risk actions that require two-phase approval (M40).
TWO_PHASE_ACTIONS: set[str] = {
    StepAction.TRUST_CHANGE.value,
    StepAction.EXPORT_DATA.value,
    StepAction.WIDEN_SCOPE.value,
    StepAction.ENABLE_TOOL.value,
    StepAction.CHANGE_SECURITY.value,
}


@dataclass
class Task:
    """A user-submitted task broken into policy-evaluated steps."""
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    intent: str = ""
    status: TaskStatus = TaskStatus.PLANNING
    mode: SessionMode = SessionMode.STANDARD
    steps: list[Step] = field(default_factory=list)
    capability: CapabilityToken | None = None
    budgets: Budgets = field(default_factory=Budgets)
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "intent": self.intent,
            "status": self.status.value,
            "mode": self.mode.value,
            "steps": [s.to_dict() for s in self.steps],
            "capability": self.capability.to_dict() if self.capability else None,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

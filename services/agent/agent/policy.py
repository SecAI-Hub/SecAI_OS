"""Deny-by-default policy engine (spec §8, §10).

Evaluates each proposed step against the capability token, workspace
scope, sensitivity labels, session mode, and the concrete allow/deny
matrix.  Small, auditable, and deny-by-default.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from typing import Any

import yaml

from .models import (
    CapabilityToken,
    PolicyDecision,
    RiskLevel,
    SensitivityLevel,
    SessionMode,
    Step,
    StepAction,
    TWO_PHASE_ACTIONS,
)

log = logging.getLogger("agent.policy")

# ---------------------------------------------------------------------------
# Allow / deny matrix (spec §10)
# ---------------------------------------------------------------------------

# Actions allowed by default (auto-approve, no user interaction)
_AUTO_ALLOW: set[StepAction] = {
    StepAction.LOCAL_SEARCH,
    StepAction.SUMMARIZE,
    StepAction.DRAFT,
    StepAction.CLASSIFY,
    StepAction.REPORT,
    StepAction.EXPLAIN_SECURITY,
}

# Actions denied by default (never allowed without explicit policy override)
_ALWAYS_DENY: set[StepAction] = {
    StepAction.CHANGE_SECURITY,
}

# Actions requiring hard approval (always ask the user)
_HARD_APPROVAL: set[StepAction] = {
    StepAction.OUTBOUND_REQUEST,
    StepAction.EXPORT_DATA,
    StepAction.TRUST_CHANGE,
    StepAction.BATCH_DELETE,
    StepAction.WIDEN_SCOPE,
    StepAction.ENABLE_TOOL,
}

# Actions that are configurable (medium-risk — user can set always/ask/never)
_CONFIGURABLE: set[StepAction] = {
    StepAction.READ_FILE,
    StepAction.WRITE_FILE,
    StepAction.OVERWRITE_FILE,
    StepAction.TOOL_INVOKE,
}


def classify_risk(action: StepAction) -> RiskLevel:
    """Classify the risk level of an action per the allow/deny matrix."""
    if action in _AUTO_ALLOW:
        return RiskLevel.AUTO
    if action in _HARD_APPROVAL or action in _ALWAYS_DENY:
        return RiskLevel.APPROVAL_REQUIRED
    if action in _CONFIGURABLE:
        return RiskLevel.CONFIGURABLE
    # Unknown action → deny
    return RiskLevel.APPROVAL_REQUIRED


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Deny-by-default step evaluator with token verification."""

    def __init__(self, policy_path: str | None = None):
        self._policy: dict[str, Any] = {}
        self._policy_path = policy_path or ""
        self._policy_digest = ""
        if policy_path and os.path.isfile(policy_path):
            try:
                with open(policy_path) as f:
                    raw = f.read()
                    self._policy = yaml.safe_load(raw) or {}
                import hashlib
                self._policy_digest = hashlib.sha256(raw.encode()).hexdigest()
                log.info("loaded agent policy from %s", policy_path)
            except (yaml.YAMLError, OSError) as exc:
                log.warning("failed to load agent policy: %s", exc)

    @property
    def policy_digest(self) -> str:
        """SHA-256 digest of the loaded policy file."""
        return self._policy_digest

    # --- public API --------------------------------------------------------

    def evaluate(
        self,
        step: Step,
        cap: CapabilityToken,
    ) -> tuple[str, str]:
        """Evaluate a step against policy.

        Returns:
            (decision, reason) where decision is one of:
            "allow"   — step may execute immediately
            "ask"     — step needs user approval before executing
            "deny"    — step is blocked by policy
        """
        # 0. Token expiry check
        if cap.is_expired():
            return "deny", "capability token expired"

        # 1. Hard deny for always-denied actions
        if step.action in _ALWAYS_DENY:
            return "deny", f"action '{step.action.value}' is always denied by policy"

        # 2. Session-mode restrictions
        decision, reason = self._check_session_mode(step, cap)
        if decision == "deny":
            return decision, reason

        # 3. Capability scope checks
        decision, reason = self._check_capability_scope(step, cap)
        if decision == "deny":
            return decision, reason

        # 4. Sensitivity ceiling
        decision, reason = self._check_sensitivity(step, cap)
        if decision == "deny":
            return decision, reason

        # 5. Risk-level classification
        risk = classify_risk(step.action)

        if risk == RiskLevel.AUTO:
            return "allow", "low-risk action, auto-approved"

        if risk == RiskLevel.APPROVAL_REQUIRED:
            return "ask", f"high-risk action '{step.action.value}' requires approval"

        # Configurable: check user preferences
        pref = cap.configurable_prefs.get(step.action.value, "ask")
        if pref == "always":
            return "allow", f"user preference: always allow '{step.action.value}'"
        if pref == "never":
            return "deny", f"user preference: never allow '{step.action.value}'"
        return "ask", f"configurable action '{step.action.value}' — awaiting approval"

    def evaluate_with_evidence(
        self,
        step: Step,
        cap: CapabilityToken,
        token_valid: bool = True,
    ) -> tuple[str, str, PolicyDecision]:
        """Evaluate a step and return a full PolicyDecision evidence record.

        This wraps evaluate() and captures the decision context for
        the audit trail.
        """
        decision, reason = self.evaluate(step, cap)

        # Two-phase actions: always escalate to "ask" even if policy
        # would auto-allow (extra safety layer for M40).
        if (step.action.value in TWO_PHASE_ACTIONS
                and decision == "allow"):
            decision = "ask"
            reason = (f"two-phase approval required for "
                      f"'{step.action.value}'")

        evidence = PolicyDecision(
            step_id=step.step_id,
            action=step.action.value,
            decision=decision,
            reason=reason,
            risk_level=classify_risk(step.action).value,
            token_id=cap.token_id,
            token_valid=token_valid,
            policy_digest=self._policy_digest,
        )
        return decision, reason, evidence

    # --- internal checks ---------------------------------------------------

    def _check_session_mode(
        self, step: Step, cap: CapabilityToken
    ) -> tuple[str, str]:
        """Enforce session-mode restrictions."""
        mode = cap.session_mode

        # Offline-only: block anything online
        if mode == SessionMode.OFFLINE_ONLY:
            if step.action in (StepAction.OUTBOUND_REQUEST, StepAction.EXPORT_DATA):
                return "deny", "offline-only mode blocks all online actions"

        # Standard: online disabled unless explicitly enabled
        if mode == SessionMode.STANDARD:
            if step.action == StepAction.OUTBOUND_REQUEST and not cap.allow_online:
                return "deny", "online augmentation not enabled for this session"

        # Sensitive: tighter file scopes enforced via capability token
        # (no additional restriction here beyond capability checks)

        return "allow", ""

    def _check_capability_scope(
        self, step: Step, cap: CapabilityToken
    ) -> tuple[str, str]:
        """Check that the step operates within the capability token scope."""
        params = step.params

        # File reads
        if step.action in (StepAction.READ_FILE, StepAction.LOCAL_SEARCH):
            path = params.get("path", "")
            if path and not self._path_allowed(path, cap.readable_paths):
                return "deny", f"path '{path}' not in readable scope"

        # File writes
        if step.action in (
            StepAction.WRITE_FILE,
            StepAction.OVERWRITE_FILE,
            StepAction.DRAFT,
            StepAction.REPORT,
        ):
            path = params.get("path", "")
            if path and not self._path_allowed(path, cap.writable_paths):
                return "deny", f"path '{path}' not in writable scope"

        # Tool invocations
        if step.action == StepAction.TOOL_INVOKE:
            tool = params.get("tool", "")
            if tool and cap.allowed_tools and tool not in cap.allowed_tools:
                return "deny", f"tool '{tool}' not in allowed tools"

        # Online actions
        if step.action == StepAction.OUTBOUND_REQUEST:
            if not cap.allow_online:
                return "deny", "capability token does not allow online access"

        return "allow", ""

    def _check_sensitivity(
        self, step: Step, cap: CapabilityToken
    ) -> tuple[str, str]:
        """Block actions that exceed the sensitivity ceiling."""
        label = step.params.get("sensitivity")
        if not label:
            return "allow", ""

        try:
            step_level = SensitivityLevel(label)
        except ValueError:
            return "allow", ""

        ceiling = cap.sensitivity_ceiling
        levels = [SensitivityLevel.LOW, SensitivityLevel.MEDIUM, SensitivityLevel.HIGH]
        if levels.index(step_level) > levels.index(ceiling):
            return "deny", (
                f"sensitivity '{step_level.value}' exceeds ceiling "
                f"'{ceiling.value}'"
            )

        return "allow", ""

    @staticmethod
    def _path_allowed(path: str, allowed: list[str]) -> bool:
        """Check if a path matches any allowed glob pattern."""
        if not allowed:
            return False
        # Normalise: resolve .. and strip trailing slashes
        norm = os.path.normpath(path)
        for pattern in allowed:
            if fnmatch.fnmatch(norm, os.path.normpath(pattern)):
                return True
        return False

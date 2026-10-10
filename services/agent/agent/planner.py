"""Task planner — decomposes user intent into policy-evaluated steps (spec §8).

The planner turns user intent into a proposed sequence of steps.  It
cannot call tools directly, cannot access raw files, and cannot emit
direct network actions.  It uses the local inference worker to
decompose tasks into structured step sequences.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import requests
from common import inference_client as inference_http

from .models import (
    CapabilityToken,
    Step,
    StepAction,
)
from .policy import PolicyEngine, classify_risk
from .action_catalog import action_catalog, implemented_actions

log = logging.getLogger("agent.planner")

_INFERENCE_URL = os.getenv("INFERENCE_URL", "http://127.0.0.1:8465")

# Map of action keywords to StepAction for LLM output parsing
_ACTION_KEYWORDS: dict[str, StepAction] = {
    "search": StepAction.LOCAL_SEARCH,
    "find": StepAction.LOCAL_SEARCH,
    "list": StepAction.LOCAL_SEARCH,
    "summarize": StepAction.SUMMARIZE,
    "summary": StepAction.SUMMARIZE,
    "draft": StepAction.DRAFT,
    "write": StepAction.DRAFT,
    "compose": StepAction.DRAFT,
    "classify": StepAction.CLASSIFY,
    "tag": StepAction.CLASSIFY,
    "categorize": StepAction.CLASSIFY,
    "report": StepAction.REPORT,
    "generate report": StepAction.REPORT,
    "explain": StepAction.EXPLAIN_SECURITY,
    "read": StepAction.READ_FILE,
    "open": StepAction.READ_FILE,
    "save": StepAction.WRITE_FILE,
    "create file": StepAction.WRITE_FILE,
    "overwrite": StepAction.OVERWRITE_FILE,
    "replace": StepAction.OVERWRITE_FILE,
    "fetch": StepAction.OUTBOUND_REQUEST,
    "download": StepAction.OUTBOUND_REQUEST,
}


class ActionUnavailable(ValueError):
    """The requested workflow has no executable action contract."""


_UNAVAILABLE_INTENT = re.compile(
    r"^\s*(?:please\s+)?(?:tool\b|mcp\b|invoke\b|export\b|share\b|promote\b|revoke\b|"
    r"(?:bulk delete|delete all)\b|(?:run|execute|call|use)\s+(?:a\s+|the\s+)?(?:tool|mcp|command|shell|script)\b)",
    re.IGNORECASE,
)

# System prompt instructs the LLM to output structured step plans
_SYSTEM_PROMPT = """\
You are a task planner for a secure local AI appliance.  Given a user
intent, decompose it into a sequence of concrete steps.

RULES:
- You may ONLY use these actions: {actions}
- Each step must specify: action, description, and params (as JSON).
- Output ONLY a JSON array of step objects. No explanation text.
- Keep plans minimal — use the fewest steps necessary.
- Never plan network actions unless the intent explicitly requests online help.
- Never plan security changes, policy edits, or tool installation.
- Prefer read-only operations. Only write when the intent requires output.

AVAILABLE ACTIONS:
{action_details}

OUTPUT FORMAT (JSON array only, no markdown):
[
  {{"action": "read_file", "description": "Read the document", "params": {{"path": "/vault/user_docs/report.txt"}}}},
  {{"action": "summarize", "description": "Summarize the document", "params": {{"path": "/vault/user_docs/report.txt"}}}}
]
"""


class Planner:
    """Decomposes user intent into a sequence of steps.

    Uses the local inference worker to generate structured plans,
    then validates and classifies each step's risk level.
    """

    def __init__(self, policy: PolicyEngine):
        self._policy = policy

    def plan(
        self,
        intent: str,
        cap: CapabilityToken,
        max_steps: int = 20,
    ) -> list[Step]:
        """Create a plan from user intent.

        Returns a list of Step objects with risk levels classified
        but not yet evaluated for approval.
        """
        if _UNAVAILABLE_INTENT.search(intent):
            raise ActionUnavailable("Tool execution, exports and control-plane changes are unavailable. Choose a supported local workflow.")

        # Try LLM-based planning first
        steps = self._plan_via_llm(intent, cap, max_steps)

        # Fall back to heuristic planning if LLM is unavailable
        if not steps:
            steps = self._plan_heuristic(intent, cap)

        # Classify risk level for each step
        for step in steps:
            if step.action not in implemented_actions():
                raise ActionUnavailable("The proposed plan contains an action without an executable handler.")
            if step.action == StepAction.OUTBOUND_REQUEST and not cap.allow_online:
                raise ActionUnavailable("Online requests are unavailable in this session mode.")
            step.risk_level = classify_risk(step.action)

        return steps[:max_steps]

    # --- LLM-based planning ------------------------------------------------

    def _plan_via_llm(
        self,
        intent: str,
        cap: CapabilityToken,
        max_steps: int,
    ) -> list[Step]:
        """Use the inference worker to decompose the intent."""
        actions = ", ".join(sorted(a.value for a in implemented_actions()
                                   if a != StepAction.OUTBOUND_REQUEST or cap.allow_online))
        details = "\n".join(f"  {entry['action']} — {entry['description']}" for entry in action_catalog(cap.session_mode.value)
                            if entry["action"] != "outbound_request" or cap.allow_online)
        system = _SYSTEM_PROMPT.format(actions=actions, action_details=details)
        readable_scopes = ", ".join(self._display_scope(path) for path in cap.readable_paths) or "none"
        writable_scopes = ", ".join(self._display_scope(path) for path in cap.writable_paths) or "none"

        prompt = (
            f"{system}\n\n"
            f"Session mode: {cap.session_mode.value}\n"
            f"Readable scopes: {readable_scopes}\n"
            f"Writable scopes: {writable_scopes}\n"
            f"Online access: {'yes' if cap.allow_online else 'no'}\n\n"
            f"USER INTENT: {intent}\n\n"
            f"PLAN (JSON array):"
        )

        try:
            resp = inference_http.post(
                f"{_INFERENCE_URL}/completion",
                json={
                    "prompt": prompt,
                    "n_predict": 2048,
                    "temperature": 0.1,
                    "stop": ["```", "\n\n\n"],
                },
                timeout=60,
            )

            data = inference_http.read_json(resp)
            text = data.get("content")
            if not isinstance(text, str):
                raise ValueError("invalid inference content")
            return self._parse_llm_plan(text)

        except (requests.RequestException, ValueError) as error:
            log.warning("%s; falling back to heuristic", inference_http.backend_error(error))
            return []

    def _parse_llm_plan(self, text: str) -> list[Step]:
        """Parse LLM output into Step objects."""
        # Try to extract JSON array from the response
        text = text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$", "", text)

        try:
            raw_steps = json.loads(text)
        except json.JSONDecodeError:
            # Try to find a JSON array in the text
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if not match:
                log.warning("could not parse LLM plan output")
                return []
            try:
                raw_steps = json.loads(match.group())
            except json.JSONDecodeError:
                log.warning("could not parse extracted JSON from LLM output")
                return []

        if not isinstance(raw_steps, list):
            return []

        steps = []
        for raw in raw_steps:
            if not isinstance(raw, dict):
                continue
            action_str = raw.get("action", "")
            try:
                action = StepAction(action_str)
            except ValueError:
                log.warning("unknown action '%s' in LLM plan, skipping", action_str)
                continue

            steps.append(Step(
                action=action,
                description=raw.get("description", ""),
                params=self._sanitize_params(raw.get("params", {})),
            ))

        self._normalize_step_context(steps)
        return steps

    @staticmethod
    def _sanitize_params(params: Any) -> dict[str, Any]:
        """Drop placeholder values copied from prompt examples."""
        if not isinstance(params, dict):
            return {}
        sanitized: dict[str, Any] = {}
        for key, value in params.items():
            if isinstance(value, str) and value.strip() in {"...", "…"}:
                continue
            if key in {"path", "scope"} and isinstance(value, str):
                value = Planner._strip_scope_glob(value)
            sanitized[key] = value
        return sanitized

    @staticmethod
    def _normalize_step_context(steps: list[Step]) -> None:
        """Propagate obvious file context between adjacent planning steps."""
        last_read_path = ""
        for step in steps:
            for key in ("path", "scope"):
                value = step.params.get(key)
                if isinstance(value, str):
                    step.params[key] = Planner._strip_scope_glob(value)
            if step.action == StepAction.READ_FILE:
                last_read_path = str(step.params.get("path", "")).strip()
                continue
            if step.action == StepAction.SUMMARIZE:
                content = str(step.params.get("content", "")).strip()
                path = str(step.params.get("path", "")).strip()
                if not content and not path and last_read_path:
                    step.params["path"] = last_read_path

    # --- heuristic fallback ------------------------------------------------

    def _plan_heuristic(
        self,
        intent: str,
        cap: CapabilityToken,
    ) -> list[Step]:
        """Simple keyword-based planning when inference is unavailable.

        Matches intent keywords to known actions.  This is intentionally
        conservative — it prefers simple single-step plans over complex
        multi-step ones.
        """
        intent_lower = intent.lower().strip()
        steps: list[Step] = []

        # Check for multi-word keywords first (longest match)
        matched = False
        for keyword in sorted(_ACTION_KEYWORDS.keys(), key=len, reverse=True):
            if keyword in intent_lower:
                action = _ACTION_KEYWORDS[keyword]
                steps.append(Step(
                    action=action,
                    description=intent,
                    params=self._extract_params(intent, action, cap),
                ))
                matched = True
                break

        if not matched:
            # Default to summarize for unrecognised intents
            steps.append(Step(
                action=StepAction.SUMMARIZE,
                description=intent,
                params={"content": intent},
            ))

        return steps

    @staticmethod
    def _extract_params(
        intent: str, action: StepAction, cap: CapabilityToken
    ) -> dict[str, Any]:
        """Extract basic parameters from intent text."""
        params: dict[str, Any] = {}

        # Try to find file paths in the intent
        path_match = re.search(r"['\"]?(/[\w/._-]+)['\"]?", intent)
        if path_match:
            path = path_match.group(1)
            if action in (StepAction.READ_FILE, StepAction.LOCAL_SEARCH, StepAction.SUMMARIZE):
                params["path"] = path
            elif action in (StepAction.WRITE_FILE, StepAction.OVERWRITE_FILE, StepAction.DRAFT, StepAction.REPORT):
                params["path"] = path
                params["instruction"] = intent

        if action == StepAction.DRAFT and "instruction" not in params:
            params["instruction"] = intent

        if action == StepAction.CLASSIFY:
            params["content"] = intent

        if action == StepAction.EXPLAIN_SECURITY:
            params["context"] = intent

        if action == StepAction.OUTBOUND_REQUEST:
            match = re.search(r"https?://[^\s<>\"']+", intent)
            if match:
                params["url"] = match.group(0)
            params["method"] = "GET"

        return params

    @staticmethod
    def _strip_scope_glob(path: str) -> str:
        """Normalize wildcard scope strings copied from capability prompts."""
        value = str(path).strip()
        while value.endswith("/**") or value.endswith("\\**"):
            value = value[:-3]
        while value.endswith("/*") or value.endswith("\\*"):
            value = value[:-2]
        return value.rstrip("/\\") or value

    @staticmethod
    def _display_scope(path: str) -> str:
        """Show directory scopes without glob suffixes in the planning prompt."""
        return Planner._strip_scope_glob(path)

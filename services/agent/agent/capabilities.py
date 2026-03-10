"""Capability token management (spec §6).

Creates scoped per-run tokens based on session mode and workspace
configuration.  Tokens are opaque to the agent planner — only the
policy engine and executor read them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path

from .models import (
    Budgets,
    CapabilityToken,
    SensitivityLevel,
    SessionMode,
)

log = logging.getLogger("agent.capabilities")

# ---------------------------------------------------------------------------
# Default scopes per session mode
# ---------------------------------------------------------------------------

_MODE_DEFAULTS: dict[SessionMode, dict] = {
    SessionMode.OFFLINE_ONLY: {
        "readable_paths": ["/var/lib/secure-ai/vault/user_docs/**"],
        "writable_paths": ["/var/lib/secure-ai/vault/outputs/**"],
        "allowed_tools": [
            "filesystem.read",
            "filesystem.list",
            "filesystem.write",
        ],
        "allow_online": False,
        "sensitivity_ceiling": SensitivityLevel.MEDIUM,
        "budgets": Budgets(
            max_steps=20,
            max_tool_calls=50,
            max_wall_clock_seconds=300,
        ),
    },
    SessionMode.STANDARD: {
        "readable_paths": ["/var/lib/secure-ai/vault/user_docs/**"],
        "writable_paths": ["/var/lib/secure-ai/vault/outputs/**"],
        "allowed_tools": [
            "filesystem.read",
            "filesystem.list",
            "filesystem.write",
        ],
        "allow_online": False,
        "sensitivity_ceiling": SensitivityLevel.MEDIUM,
        "budgets": Budgets(
            max_steps=30,
            max_tool_calls=80,
            max_wall_clock_seconds=600,
        ),
    },
    SessionMode.ONLINE_ASSISTED: {
        "readable_paths": ["/var/lib/secure-ai/vault/user_docs/**"],
        "writable_paths": ["/var/lib/secure-ai/vault/outputs/**"],
        "allowed_tools": [
            "filesystem.read",
            "filesystem.list",
            "filesystem.write",
        ],
        "allow_online": True,
        "sensitivity_ceiling": SensitivityLevel.MEDIUM,
        "budgets": Budgets(
            max_steps=30,
            max_tool_calls=80,
            max_wall_clock_seconds=600,
        ),
    },
    SessionMode.SENSITIVE: {
        "readable_paths": [],  # must be explicitly scoped
        "writable_paths": ["/var/lib/secure-ai/vault/outputs/**"],
        "allowed_tools": [
            "filesystem.read",
            "filesystem.list",
        ],
        "allow_online": False,
        "sensitivity_ceiling": SensitivityLevel.HIGH,
        "budgets": Budgets(
            max_steps=10,
            max_tool_calls=20,
            max_wall_clock_seconds=120,
            max_files_touched=5,
        ),
    },
}


def create_token(
    mode: SessionMode,
    *,
    extra_readable: list[str] | None = None,
    extra_writable: list[str] | None = None,
    extra_tools: list[str] | None = None,
    configurable_prefs: dict[str, str] | None = None,
    custom_budgets: dict[str, int | float] | None = None,
) -> CapabilityToken:
    """Create a scoped capability token for a task run.

    Uses mode defaults and optionally narrows/widens scope with extras.
    """
    defaults = _MODE_DEFAULTS.get(mode, _MODE_DEFAULTS[SessionMode.STANDARD])

    readable = list(defaults["readable_paths"])
    writable = list(defaults["writable_paths"])
    tools = list(defaults["allowed_tools"])

    if extra_readable:
        readable.extend(extra_readable)
    if extra_writable:
        writable.extend(extra_writable)
    if extra_tools:
        tools.extend(extra_tools)

    token = CapabilityToken(
        readable_paths=readable,
        writable_paths=writable,
        allowed_tools=tools,
        allow_online=defaults["allow_online"],
        sensitivity_ceiling=defaults["sensitivity_ceiling"],
        session_mode=mode,
        configurable_prefs=configurable_prefs or {},
    )

    log.info(
        "created capability token %s (mode=%s, readable=%d, writable=%d, tools=%d)",
        token.token_id,
        mode.value,
        len(readable),
        len(writable),
        len(tools),
    )
    return token


def create_budgets(
    mode: SessionMode,
    overrides: dict[str, int | float] | None = None,
) -> Budgets:
    """Create budget limits for a task based on session mode."""
    defaults = _MODE_DEFAULTS.get(mode, _MODE_DEFAULTS[SessionMode.STANDARD])
    base: Budgets = defaults["budgets"]

    budgets = Budgets(
        max_steps=base.max_steps,
        max_tool_calls=base.max_tool_calls,
        max_tokens=base.max_tokens,
        max_wall_clock_seconds=base.max_wall_clock_seconds,
        max_files_touched=base.max_files_touched,
        max_output_bytes=base.max_output_bytes,
    )

    if overrides:
        for k, v in overrides.items():
            if hasattr(budgets, k):
                setattr(budgets, k, v)

    return budgets

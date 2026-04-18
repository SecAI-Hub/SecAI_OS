"""Capability token management (spec §6, M40/M41 — Verified Supervisor + HSM Keys).

Creates scoped per-run tokens based on session mode and workspace
configuration.  Tokens are HMAC-SHA256 signed and bound to a specific
task context (intent hash, policy digest, nonce) to prevent reuse,
replay, and tampering.

Key management is delegated to the keystore abstraction layer (M41),
which supports software, TPM2, and PKCS#11 HSM backends.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path

from .models import (
    Budgets,
    CapabilityToken,
    SensitivityLevel,
    SessionMode,
)

log = logging.getLogger("agent.capabilities")

# ---------------------------------------------------------------------------
# Keystore-backed signing (M41 — HSM-Backed Key Handling)
# ---------------------------------------------------------------------------

# The active key provider, initialised lazily.
_key_provider = None

# Nonce replay cache: set of seen nonces (bounded by _MAX_NONCE_CACHE).
_seen_nonces: set[str] = set()
_MAX_NONCE_CACHE = 10_000


def _get_provider():
    """Return the active KeyProvider, creating it on first call."""
    global _key_provider
    if _key_provider is not None:
        return _key_provider

    try:
        from .keystore import create_provider, load_config
        config = load_config()
        _key_provider = create_provider(config)
        log.info("keystore provider: %s", _key_provider.provider_name())
    except Exception as exc:
        # Fallback to a minimal in-process provider
        log.warning("keystore init failed (%s), using ephemeral keys", exc)
        from .keystore import SoftwareKeyProvider
        _key_provider = SoftwareKeyProvider()

    return _key_provider


def _get_signing_key() -> bytes:
    """Load the HMAC signing key via the keystore provider.

    In production the key may come from TPM2, HSM, or filesystem
    depending on keystore.yaml configuration.
    """
    return _get_provider().get_key("default")


def _reset_signing_key() -> None:
    """Reset the key provider cache (for testing only)."""
    global _key_provider
    _key_provider = None


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def hash_intent(intent: str) -> str:
    """Return SHA-256 hex digest of a task intent string."""
    return hashlib.sha256(intent.encode("utf-8")).hexdigest()


def hash_policy_file(policy_path: str) -> str:
    """Return SHA-256 hex digest of a policy file, or empty string."""
    try:
        data = Path(policy_path).read_bytes()
        return hashlib.sha256(data).hexdigest()
    except (OSError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# HMAC-SHA256 token signing / verification
# ---------------------------------------------------------------------------

def _compute_signature(token: CapabilityToken) -> str:
    """Compute HMAC-SHA256 over the token's binding fields."""
    key = _get_signing_key()
    # Canonical payload: sorted JSON of the binding-critical fields
    payload = json.dumps({
        "token_id": token.token_id,
        "task_id": token.task_id,
        "intent_hash": token.intent_hash,
        "policy_digest": token.policy_digest,
        "nonce": token.nonce,
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        "session_mode": token.session_mode.value,
        "allow_online": token.allow_online,
        "sensitivity_ceiling": token.sensitivity_ceiling.value,
        "readable_paths": sorted(token.readable_paths),
        "writable_paths": sorted(token.writable_paths),
        "allowed_tools": sorted(token.allowed_tools),
    }, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_token(token: CapabilityToken) -> CapabilityToken:
    """Sign a capability token in-place and return it."""
    token.signature = _compute_signature(token)
    return token


def verify_token(
    token: CapabilityToken,
    *,
    consume_nonce: bool = True,
) -> tuple[bool, str]:
    """Verify a capability token's HMAC signature, nonce, and expiry.

    Returns (valid, reason).
    """
    # 1. Check expiry
    if token.is_expired():
        return False, "token expired"

    # 2. Replay protection — reject reused nonces
    if consume_nonce and token.nonce in _seen_nonces:
        return False, "nonce already seen (replay)"

    # 3. Verify HMAC signature
    if not token.signature:
        return False, "token not signed"

    expected = _compute_signature(token)
    if not hmac.compare_digest(token.signature, expected):
        return False, "signature mismatch"

    # 4. Record nonce (bounded cache)
    if consume_nonce:
        if len(_seen_nonces) >= _MAX_NONCE_CACHE:
            _seen_nonces.clear()
        _seen_nonces.add(token.nonce)

    return True, "valid"


def clear_nonce_cache() -> None:
    """Clear the nonce replay cache (for testing only)."""
    _seen_nonces.clear()


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
    task_id: str = "",
    intent: str = "",
    policy_path: str = "",
    extra_readable: list[str] | None = None,
    extra_writable: list[str] | None = None,
    extra_tools: list[str] | None = None,
    configurable_prefs: dict[str, str] | None = None,
    custom_budgets: dict[str, int | float] | None = None,
    ttl_seconds: float = 0,
) -> CapabilityToken:
    """Create a scoped, signed capability token for a task run.

    Uses mode defaults and optionally narrows/widens scope with extras.
    The token is HMAC-signed and bound to the task context.
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

    now = time.time()
    expires = now + ttl_seconds if ttl_seconds > 0 else 0.0

    token = CapabilityToken(
        readable_paths=readable,
        writable_paths=writable,
        allowed_tools=tools,
        allow_online=defaults["allow_online"],
        sensitivity_ceiling=defaults["sensitivity_ceiling"],
        session_mode=mode,
        configurable_prefs=configurable_prefs or {},
        task_id=task_id,
        intent_hash=hash_intent(intent) if intent else "",
        policy_digest=hash_policy_file(policy_path) if policy_path else "",
        issued_at=now,
        expires_at=expires,
    )

    # Sign the token
    sign_token(token)

    log.info(
        "created signed capability token %s (mode=%s, task=%s, "
        "readable=%d, writable=%d, tools=%d, ttl=%.0f)",
        token.token_id,
        mode.value,
        task_id or "(unbound)",
        len(readable),
        len(writable),
        len(tools),
        ttl_seconds,
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

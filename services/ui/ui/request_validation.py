"""Validate JSON structure before UI handlers access fields or call services."""
import math
import re

_STRING_FIELDS = {
    "auth_setup": ("passphrase", "setup_token"),
    "auth_login": ("passphrase",),
    "auth_change_passphrase": ("current", "new_passphrase"),
    "setup_complete": ("profile",),
    "catalog_download": ("url", "filename"),
    "verify_model": ("name",),
    "select_inference_model": ("model_filename",),
    "verify_model_manifest": ("name",),
    "delete_model": ("name",),
    "import_model": ("path",),
    "chat": ("model",),
    "chat_stream": ("model",),
    "chat_with_search": ("model",),
    "web_search": ("query", "category"),
    "generate_image": ("model", "prompt", "negative_prompt"),
    "generate_video": ("model", "prompt", "negative_prompt"),
    "preview_profile": ("profile",),
    "select_profile": ("profile",),
    "sandbox_control_apply": ("profile", "model_filename"),
    "agent_submit_task": ("intent", "mode"),
}
_CHAT_ENDPOINTS = {"chat", "chat_stream", "chat_with_search"}
JSON_ENDPOINTS = frozenset(_STRING_FIELDS) | {
    "toggle_vm_gpu", "emergency_panic", "agent_approve_steps", "agent_deny_steps",
}


def validate_json_body(body: object, endpoint: str | None) -> str | None:
    if not isinstance(body, dict):
        return "JSON body must be an object"

    # Bound structural work and reject values Python's permissive JSON decoder
    # accepts but UTF-8 encoders, strict downstream APIs, or logging reject.
    pending = [(body, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 16_384:
            return "JSON structure exceeds supported limits"
        if isinstance(value, dict):
            if nodes + len(pending) + 2 * len(value) > 16_384:
                return "JSON structure exceeds supported limits"
            pending.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            if nodes + len(pending) + len(value) > 16_384:
                return "JSON structure exceeds supported limits"
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                return "JSON strings must contain valid Unicode"
        elif isinstance(value, float) and not math.isfinite(value):
            return "JSON numbers must be finite"

    string_fields = _STRING_FIELDS.get(endpoint, ()) if endpoint is not None else ()
    for field in string_fields:
        if field in body and not isinstance(body[field], str):
            return f"{field} must be a string"

    if endpoint in {"agent_approve_steps", "agent_deny_steps"}:
        if set(body) - {"step_ids", "expected_plan_revision", "step_hashes"}:
            return "unknown approval field"
        # The backend rejects missing/stale review identities with 409. Reject
        # malformed supplied identities here, before any privileged proxy call.
        if "step_ids" in body:
            ids = body["step_ids"]
            if (not isinstance(ids, list) or not 1 <= len(ids) <= 100
                    or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{12}", item) for item in ids)
                    or len(set(ids)) != len(ids)):
                return "invalid approval selection"
        if "expected_plan_revision" in body and (
            not isinstance(body["expected_plan_revision"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", body["expected_plan_revision"])
        ):
            return "invalid plan revision"
        if "step_hashes" in body:
            hashes = body["step_hashes"]
            if (not isinstance(hashes, dict) or len(hashes) > 100
                    or any(not isinstance(key, str) or not isinstance(value, str)
                           or not re.fullmatch(r"[0-9a-f]{12}", key)
                           or not re.fullmatch(r"[0-9a-f]{64}", value) for key, value in hashes.items())):
                return "invalid step review hashes"

    for field in ("search",) if endpoint == "chat_with_search" else ():
        if field in body and type(body[field]) is not bool:
            return f"{field} must be a boolean"
    if endpoint == "sandbox_control_apply":
        if "inference" in body and type(body["inference"]) is not bool:
            return "inference must be a boolean"
        if "gpu" in body and type(body["gpu"]) not in (bool, str):
            return "gpu must be a boolean or a supported GPU mode"
    if endpoint == "toggle_vm_gpu" and "enabled" in body and type(body["enabled"]) is not bool:
        return "enabled must be a boolean"
    if endpoint == "emergency_panic" and "level" in body and type(body["level"]) is not int:
        return "level must be an integer"

    if endpoint in _CHAT_ENDPOINTS:
        messages = body.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 512:
            return "messages must contain between 1 and 512 messages"
        for message in messages:
            if not isinstance(message, dict):
                return "each message must be an object"
            role = message.get("role")
            if not isinstance(role, str) or role not in {"system", "developer", "user", "assistant", "tool"}:
                return "each message must have a supported role"
            if not isinstance(message.get("content"), str):
                return "message content must be a string"
    return None

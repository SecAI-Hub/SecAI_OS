"""Fail-closed admission using the native attestor's current runtime decision.

The consumer authenticates its read; only the attestor verifies signed GPU and
hardware evidence. No last-good decision is cached here.
"""
import json
import re
import time
from urllib.parse import urlsplit

import requests

UNAVAILABLE = "runtime assurance unavailable"
MAX_BYTES = 16_384


class RuntimeAssuranceUnavailable(ValueError):
    def __init__(self):
        super().__init__(UNAVAILABLE)


def runtime_allowed(data):
    if not isinstance(data, dict):
        return False
    if (type(data.get("schema_version")) is not int or data["schema_version"] != 2
            or data.get("verification_scope") != "runtime"
            or data.get("policy_satisfied") is not True
            or data.get("gpu_policy_satisfied") is not True
            or not isinstance(data.get("gpu_mode"), str)
            or data["gpu_mode"] not in {"required", "optional", "no_gpu"}
            or data.get("state") != "attested"):
        return False
    if data.get("assurance_mode") == "hardware":
        return data.get("verified") is True and data.get("evidence_verified") is True
    if data.get("assurance_mode") == "evaluation":
        return data.get("verified") is False and data.get("evidence_verified") is False
    return False


def _decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeAssuranceUnavailable()
            result[key] = value
        return result

    def invalid(_):
        raise RuntimeAssuranceUnavailable()

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def require_runtime(origin, token) -> str:
    """Require a current runtime pass and return its approved GPU mode.

    Consumers may use the returned mode to enforce CPU-only execution. The
    decision is validated anew for every call; a previous return is not an
    admission token for a later action.
    """
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or any(ord(char) <= 32 for char in origin)
                or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token)):
            raise RuntimeAssuranceUnavailable()
        started = time.monotonic()
        with requests.Session() as session:
            session.trust_env = False
            with session.get(origin + "/api/v1/verify",
                             headers={"Authorization": "Bearer " + token,
                                      "Accept": "application/json", "Accept-Encoding": "identity"},
                             timeout=(1, 2), stream=True, allow_redirects=False) as response:
                if (response.status_code != 200
                        or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.headers.get("Content-Encoding", "identity").strip().lower() != "identity"):
                    raise RuntimeAssuranceUnavailable()
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
                    raise RuntimeAssuranceUnavailable()
                raw = bytearray()
                for chunk in response.iter_content(chunk_size=1):
                    raw.extend(chunk)
                    if len(raw) > MAX_BYTES or time.monotonic() - started > 5:
                        raise RuntimeAssuranceUnavailable()
                decision = _decode(raw)
                if not runtime_allowed(decision):
                    raise RuntimeAssuranceUnavailable()
                return decision["gpu_mode"]
    except (requests.RequestException, ValueError, TypeError, UnicodeError, RecursionError, OSError) as error:
        raise RuntimeAssuranceUnavailable() from error

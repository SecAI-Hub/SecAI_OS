"""Fixed-origin HTTP with a killable wall-clock deadline and bounded output.

The small worker receives query data over stdin, never argv or environment. It
cannot follow redirects, use ambient proxies, retain cookies between requests,
or decompress responses. Killing it bounds DNS, connect, headers and body reads.
"""

import json
import logging
import math
import os
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import requests

MAX_BODY_BYTES = 2 * 1024 * 1024
HEADERS = {
    "Accept": "application/json",
    "Accept-Encoding": "identity",
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "SecAI-SearchMediator/1.0",
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
}


def validate_origin(raw: str) -> str:
    if not isinstance(raw, str) or raw != raw.strip() or len(raw) > 2048:
        raise ValueError("invalid upstream origin")
    if "\\" in raw or any(c.isspace() or unicodedata.category(c).startswith("C") for c in raw):
        raise ValueError("invalid upstream origin")
    parsed = urlparse(raw)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("upstream must be an HTTP(S) origin")
    _ = parsed.port
    return raw.rstrip("/")


def fetch(origin, endpoint, *, params=None, timeout, expect_json):
    """Worker-only transport; callers use request_bounded for a total deadline."""
    origin = validate_origin(origin)
    if endpoint not in {"/search", "/healthz"}:
        raise ValueError("upstream endpoint is not allowed")
    if not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("invalid upstream timeout")
    with requests.Session() as session:
        session.trust_env = False
        with session.get(origin + endpoint, params=params, headers=HEADERS,
                         timeout=timeout, allow_redirects=False, stream=True) as response:
            if 300 <= response.status_code < 400:
                raise requests.RequestException("upstream redirect refused")
            response.raise_for_status()
            if not expect_json:
                return response.status_code
            if response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
                raise ValueError("compressed upstream response refused")
            if response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError("upstream response is not JSON")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
                raise ValueError("upstream response exceeds size limit")
            raw = response.raw.read(MAX_BODY_BYTES + 1, decode_content=False)
            if len(raw) > MAX_BODY_BYTES:
                raise ValueError("upstream response exceeds size limit")
            decoded = json.loads(raw.decode("utf-8", errors="strict"))
            if not isinstance(decoded, dict):
                raise ValueError("upstream JSON root is not an object")
            return decoded


def request_bounded(origin, endpoint, *, params=None, timeout, expect_json):
    validate_origin(origin)
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise requests.Timeout("search deadline exceeded")
    payload = json.dumps({"origin": origin, "endpoint": endpoint, "params": params,
                          "timeout": timeout, "expect_json": expect_json}).encode("utf-8")
    if len(payload) > 64 * 1024:
        raise ValueError("upstream request exceeds size limit")
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(Path(__file__).resolve())], input=payload,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
            check=False, close_fds=True, shell=False,
            env={key: value for key, value in os.environ.items()
                 if key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR"}},
        )
    except subprocess.TimeoutExpired:
        raise requests.Timeout("search deadline exceeded") from None
    if completed.returncode != 0 or len(completed.stdout) > MAX_BODY_BYTES * 6 + 1024:
        raise requests.RequestException("upstream worker failed")
    envelope = json.loads(completed.stdout)
    if envelope.get("error") == "timeout":
        raise requests.Timeout("upstream timed out")
    if "error" in envelope:
        raise requests.RequestException("upstream response rejected")
    return envelope["data"]


def _worker():
    # HTTPError strings contain request URLs. No exception or library log is
    # serialized across this privacy boundary, including failure diagnostics.
    logging.disable(logging.CRITICAL)
    try:
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("request too large")
        payload = json.loads(raw)
        output = {"data": fetch(**payload)}
    except requests.Timeout:
        output = {"error": "timeout"}
    except Exception:
        output = {"error": "upstream"}
    sys.stdout.write(json.dumps(output, ensure_ascii=True))


if __name__ == "__main__":
    _worker()

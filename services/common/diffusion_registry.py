"""Bounded current registry verification for a local diffusion directory.

This is point-in-time disk verification, not proof of loaded memory or GPU VRAM.
No successful response is cached; the caller binds it to its loaded pipeline.
"""
import json
import re
import time
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

import requests

UNAVAILABLE = "model integrity verification unavailable"
MAX_BYTES = 16_384
TOTAL_SECONDS = 15


class ModelIntegrityUnavailable(ValueError):
    def __init__(self):
        super().__init__(UNAVAILABLE)


class VerifiedModel(NamedTuple):
    name: str
    filename: str
    sha256: str
    path: str


def valid_filename(filename):
    return (isinstance(filename, str) and 0 < len(filename) <= 512
            and filename not in {".", ".."}
            and not any(c in filename for c in "/\\\x00")
            and not any(ord(c) < 32 or ord(c) == 127 for c in filename))


def _decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ModelIntegrityUnavailable()
            result[key] = value
        return result
    def invalid(_):
        raise ModelIntegrityUnavailable()
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def _local_path(root, filename):
    root = Path(root)
    # All ancestors must resolve to the configured absolute root without aliases.
    if not root.is_absolute() or str(root.resolve(strict=True)) != str(root) or not root.is_dir():
        raise ModelIntegrityUnavailable()
    expected = root / filename
    if expected.is_symlink() or not expected.is_dir() or str(expected.resolve(strict=True)) != str(expected):
        raise ModelIntegrityUnavailable()
    return str(expected)


def _limit_body_read(response, stream_socket, started):
    remaining = TOTAL_SECONDS - (time.monotonic() - started)
    if remaining <= 0:
        raise ModelIntegrityUnavailable()
    # requests/urllib3 keep the original read timeout during streaming. Narrow
    # the underlying CPython socket timeout to the remaining total budget before
    # each read, including when the body stalls after the registry has hashed.
    # An unsupported transport layout fails closed instead of losing the bound.
    try:
        if response.raw.closed is not True:
            stream_socket.settimeout(min(12, remaining))
    except AttributeError:
        raise ModelIntegrityUnavailable() from None


def verify_model(origin, token, filename, registry_dir, *, sandbox=False):
    """Require exact filename/directory/digest metadata from a scoped peer."""
    try:
        parsed = urlsplit(origin)
        native = parsed.hostname in {"127.0.0.1", "::1"} and parsed.port == 8470
        evaluation = sandbox is True and parsed.hostname == "registry" and parsed.port == 8470
        if (parsed.scheme != "http" or not (native or evaluation)
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or any(ord(c) <= 32 for c in origin)
                or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token)
                or not valid_filename(filename)):
            raise ModelIntegrityUnavailable()
        path = _local_path(registry_dir, filename)
        started = time.monotonic()
        with requests.Session() as session:
            session.trust_env = False
            with session.get(origin + "/v1/model/path", params={"filename": filename},
                             headers={"Authorization": "Bearer " + token,
                                      "Accept": "application/json", "Accept-Encoding": "identity"},
                             timeout=(1, 12), stream=True, allow_redirects=False) as response:
                if (response.status_code != 200
                        or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.headers.get("Content-Encoding", "identity").strip().lower() != "identity"):
                    raise ModelIntegrityUnavailable()
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
                    raise ModelIntegrityUnavailable()
                raw = bytearray()
                try:
                    stream_socket = response.raw._fp.fp.raw._sock
                except AttributeError:
                    raise ModelIntegrityUnavailable() from None
                _limit_body_read(response, stream_socket, started)
                for chunk in response.iter_content(chunk_size=1):
                    raw.extend(chunk)
                    if len(raw) > MAX_BYTES or time.monotonic() - started > TOTAL_SECONDS:
                        raise ModelIntegrityUnavailable()
                    _limit_body_read(response, stream_socket, started)
                data = _decode(raw)
                if (time.monotonic() - started > TOTAL_SECONDS or not isinstance(data, dict)
                        or type(data.get("schema_version")) is not int or data["schema_version"] != 1
                        or data.get("status") != "verified" or data.get("safe_to_use") != "true"
                        or data.get("format") != "diffusion-directory" or data.get("filename") != filename
                        or data.get("path") != path or not isinstance(data.get("name"), str)
                        or not data["name"].strip() or len(data["name"]) > 512
                        or not isinstance(data.get("sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", data["sha256"])):
                    raise ModelIntegrityUnavailable()
                if _local_path(registry_dir, filename) != path:
                    raise ModelIntegrityUnavailable()
                return VerifiedModel(data["name"], filename, data["sha256"], path)
    except (requests.RequestException, ValueError, TypeError, UnicodeError, RecursionError, OSError):
        raise ModelIntegrityUnavailable() from None

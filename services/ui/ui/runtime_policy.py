"""Canonical current profile proof, shared without importing the Flask app."""
import hashlib
import hmac
import json
import logging
import os
import re
import stat
from pathlib import Path

import requests
import yaml

log = logging.getLogger("ui.runtime_policy")

PROFILE_STATE_PATH = "/var/lib/secure-ai/state/profile.json"
PROFILE_OVERRIDE_PATH = "/etc/secure-ai/local.d/profile.yaml"
PROFILE_REQUEST_PATH = "/run/secure-ai-ui/profile-request"
PROFILE_RESULT_PATH = "/run/secure-ai/profile-result.json"
APPLIANCE_CONFIG_PATH = "/etc/secure-ai/config/appliance.yaml"
VALID_PROFILES = {"offline_private", "research", "full_lab"}
INVALID_PROFILE_OVERRIDE = "invalid_override"
UNREADY_SANDBOX_PROFILE = "sandbox_generation_unready"
SANDBOX_READY_GENERATION_PATH = (
    "/run/secure-ai-generation-status/ready-generation"
)
SANDBOX_READY_SESSION_PATH = (
    "/run/secure-ai-generation-status/ready-session"
)
SANDBOX_GENERATION_MANIFEST_PATH = (
    "/var/lib/secure-ai/state/generation.json"
)
SANDBOX_GENERATION_PROFILE_PATH = (
    "/var/lib/secure-ai/state/profile.json"
)
_SANDBOX_GENERATION_RE = re.compile(r"[0-9a-f]{64}")
_WINDOWS_REPARSE_POINT = 0x400
_SANDBOX_GENERATION_FORMAT = 1
_MAX_SANDBOX_MANIFEST_BYTES = 262_144
_MAX_SANDBOX_MANIFEST_ENTRIES = 256
_MAX_SANDBOX_PROFILE_BYTES = 4096
_MAX_SANDBOX_CONTROL_HEALTH_BYTES = 4096
_SANDBOX_CONTROL_PROTOCOL_VERSION = 3


def _read_stable_sandbox_file(path: Path, maximum_size: int) -> bytes:
    """Read one bounded regular file without accepting a path race."""
    if not path.is_absolute() or maximum_size < 1:
        raise OSError("sandbox runtime file path is invalid")
    parent = path.parent
    descriptor = -1
    try:
        parent_before = os.lstat(parent)
        metadata = os.lstat(path)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or getattr(parent_before, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
            or parent_before.st_mode & 0o022
            or not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
            or metadata.st_size > maximum_size
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise OSError("sandbox runtime file is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
            or opened.st_size > maximum_size
            or opened.st_nlink != 1
            or opened.st_mode & 0o022
            or (opened.st_dev, opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise OSError("sandbox runtime file changed before reading")
        payload = bytearray()
        while len(payload) <= maximum_size:
            chunk = os.read(
                descriptor,
                min(65_536, maximum_size + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > maximum_size:
            raise OSError("sandbox runtime file exceeds its size limit")
        opened_after = os.fstat(descriptor)
        path_after = os.lstat(path)
        parent_after = os.lstat(parent)
        if (
            (opened_after.st_dev, opened_after.st_ino)
            != (opened.st_dev, opened.st_ino)
            or (path_after.st_dev, path_after.st_ino)
            != (opened.st_dev, opened.st_ino)
            or not stat.S_ISREG(path_after.st_mode)
            or getattr(path_after, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
            or path_after.st_size > maximum_size
            or path_after.st_nlink != 1
            or path_after.st_mode & 0o022
            or (parent_after.st_dev, parent_after.st_ino)
            != (parent_before.st_dev, parent_before.st_ino)
            or not stat.S_ISDIR(parent_after.st_mode)
            or getattr(parent_after, "st_file_attributes", 0)
            & _WINDOWS_REPARSE_POINT
            or parent_after.st_mode & 0o022
        ):
            raise OSError("sandbox runtime file changed while being read")
        return bytes(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_ready_state_value(
    environment_name: str,
    default_path: str,
) -> str | None:
    marker_value = os.getenv(environment_name, default_path)
    if not marker_value:
        return None
    try:
        payload = _read_stable_sandbox_file(Path(marker_value), 64)
        ready = payload.decode("ascii")
    except (OSError, UnicodeError):
        return None
    if not _SANDBOX_GENERATION_RE.fullmatch(ready):
        return None
    return ready


def _read_ready_state_markers() -> tuple[str, str] | None:
    generation = _read_ready_state_value(
        "SANDBOX_READY_GENERATION_PATH",
        SANDBOX_READY_GENERATION_PATH,
    )
    session_id = _read_ready_state_value(
        "SANDBOX_READY_SESSION_PATH",
        SANDBOX_READY_SESSION_PATH,
    )
    if generation is None or session_id is None:
        return None
    # Re-read both after the pair is assembled. An invalidation or publication
    # between reads never becomes an accepted mixed state.
    if (
        _read_ready_state_value(
            "SANDBOX_READY_GENERATION_PATH",
            SANDBOX_READY_GENERATION_PATH,
        )
        != generation
        or _read_ready_state_value(
            "SANDBOX_READY_SESSION_PATH",
            SANDBOX_READY_SESSION_PATH,
        )
        != session_id
    ):
        return None
    return generation, session_id


def _unique_sandbox_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _load_strict_sandbox_json(payload: bytes):
    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_unique_sandbox_json_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {value}")
        ),
    )


def _profile_from_generation_manifest(
    expected_generation: str,
    profile_payload: bytes,
    manifest_payload: bytes,
) -> str | None:
    try:
        manifest = _load_strict_sandbox_json(manifest_payload)
    except (UnicodeError, ValueError):
        return None
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"files", "generation", "version"}
        or manifest.get("generation") != expected_generation
        or manifest.get("version") != _SANDBOX_GENERATION_FORMAT
        or isinstance(manifest.get("version"), bool)
        or not isinstance(manifest.get("files"), list)
        or not 1 <= len(manifest["files"]) <= _MAX_SANDBOX_MANIFEST_ENTRIES
    ):
        return None

    seen_paths = set()
    profile_entry = None
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size",
        }:
            return None
        relative_path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or relative_path in seen_paths
            or "\\" in relative_path
            or Path(relative_path).is_absolute()
            or Path(relative_path).as_posix() != relative_path
            or any(
                part in {"", ".", ".."}
                for part in Path(relative_path).parts
            )
            or not isinstance(digest, str)
            or not _SANDBOX_GENERATION_RE.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            return None
        seen_paths.add(relative_path)
        if relative_path == "profile.json":
            profile_entry = entry
    if (
        profile_entry is None
        or profile_entry["size"] != len(profile_payload)
        or not hmac.compare_digest(
            profile_entry["sha256"],
            hashlib.sha256(profile_payload).hexdigest(),
        )
    ):
        return None
    try:
        profile_data = _load_strict_sandbox_json(profile_payload)
    except (UnicodeError, ValueError):
        return None
    if not isinstance(profile_data, dict) or set(profile_data) != {"active"}:
        return None
    profile = profile_data.get("active")
    return (
        profile
        if isinstance(profile, str) and profile in VALID_PROFILES
        else None
    )


def _sandbox_controller_proves_profile(
    profile: str,
    session_id: str,
    *, control_config=None,
) -> bool:
    url, token = (control_config or _sandbox_control_config)()
    if (
        not url
        or not token
        or not isinstance(profile, str)
        or profile not in VALID_PROFILES
        or not isinstance(session_id, str)
        or not _SANDBOX_GENERATION_RE.fullmatch(session_id)
    ):
        return False
    challenge = os.urandom(32).hex()
    try:
        response = requests.get(
            f"{url}/health?challenge={challenge}",
            headers={"Accept-Encoding": "identity"},
            stream=True,
            timeout=(1.0, 1.0),
        )
    except requests.RequestException:
        return False
    try:
        if response.status_code != 200:
            return False
        content_length = response.headers.get("Content-Length", "")
        if content_length:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError):
                return False
            if not 0 <= declared_length <= _MAX_SANDBOX_CONTROL_HEALTH_BYTES:
                return False
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=4096):
            if not isinstance(chunk, bytes):
                return False
            total += len(chunk)
            if total > _MAX_SANDBOX_CONTROL_HEALTH_BYTES:
                return False
            chunks.append(chunk)
        payload = _load_strict_sandbox_json(b"".join(chunks))
    except (
        AttributeError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        requests.RequestException,
    ):
        return False
    finally:
        try:
            response.close()
        except requests.RequestException:
            pass
    if not isinstance(payload, dict):
        return False
    protocol_version = payload.get("protocol_version")
    state_protocol_version = payload.get("state_protocol_version")
    proof = payload.get("proof")
    state_proof = payload.get("state_proof")
    if (
        set(payload) != {
            "controller",
            "profile",
            "profile_state",
            "proof",
            "protocol_version",
            "session_id",
            "state_proof",
            "state_protocol_version",
            "status",
        }
        or payload.get("status") != "ok"
        or payload.get("controller") != "secai-sandbox-control"
        or type(protocol_version) is not int
        or protocol_version != _SANDBOX_CONTROL_PROTOCOL_VERSION
        or type(state_protocol_version) is not int
        or state_protocol_version != 1
        or payload.get("profile_state") != "active"
        or payload.get("profile") != profile
        or not isinstance(payload.get("session_id"), str)
        or not hmac.compare_digest(
            payload["session_id"],
            session_id,
        )
        or not isinstance(proof, str)
        or not _SANDBOX_GENERATION_RE.fullmatch(proof)
        or not isinstance(state_proof, str)
        or not _SANDBOX_GENERATION_RE.fullmatch(state_proof)
    ):
        return False
    health_message = (
        "secai-sandbox-control-health:"
        f"v{_SANDBOX_CONTROL_PROTOCOL_VERSION}:{challenge}"
    ).encode("ascii")
    expected_health_proof = hmac.new(
        token.encode("ascii"),
        health_message,
        hashlib.sha256,
    ).hexdigest()
    state_message = "\n".join((
        "secai-sandbox-control-state:v1",
        challenge,
        session_id,
        "ok",
        "active",
        profile,
    )).encode("ascii")
    expected_state_proof = hmac.new(
        token.encode("ascii"),
        state_message,
        hashlib.sha256,
    ).hexdigest()
    return (
        hmac.compare_digest(proof, expected_health_proof)
        and hmac.compare_digest(state_proof, expected_state_proof)
    )


def _ready_sandbox_profile(*, read_markers=None, proves_profile=None) -> str | None:
    read_markers = read_markers or _read_ready_state_markers
    proves_profile = proves_profile or _sandbox_controller_proves_profile
    expected = os.getenv("SECAI_RUNTIME_GENERATION", "")
    if not _SANDBOX_GENERATION_RE.fullmatch(expected):
        return None
    ready_before = read_markers()
    if (
        ready_before is None
        or not hmac.compare_digest(ready_before[0], expected)
    ):
        return None
    profile_path = Path(os.getenv(
        "SANDBOX_GENERATION_PROFILE_PATH",
        SANDBOX_GENERATION_PROFILE_PATH,
    ))
    manifest_path = Path(os.getenv(
        "SANDBOX_GENERATION_MANIFEST_PATH",
        SANDBOX_GENERATION_MANIFEST_PATH,
    ))
    try:
        profile_payload = _read_stable_sandbox_file(
            profile_path,
            _MAX_SANDBOX_PROFILE_BYTES,
        )
        manifest_payload = _read_stable_sandbox_file(
            manifest_path,
            _MAX_SANDBOX_MANIFEST_BYTES,
        )
    except OSError:
        return None
    profile = _profile_from_generation_manifest(
        expected,
        profile_payload,
        manifest_payload,
    )
    ready_after = read_markers()
    if (
        profile is None
        or ready_after is None
        or ready_after != ready_before
        or not proves_profile(
            profile,
            ready_before[1],
        )
    ):
        return None
    # The launcher invalidates the generation marker before stopping or
    # replacing services. Re-check it after the network challenge so a stop
    # racing the proof cannot leave this request with a stale active profile.
    return (
        profile
        if read_markers() == ready_before
        else None
    )



def _sandbox_control_config() -> tuple[str, str]:
    """Return the host-side sandbox control URL and request-signing key."""
    url = os.getenv("SANDBOX_CONTROL_URL", "").strip().rstrip("/")
    token_path = os.getenv("SANDBOX_CONTROL_TOKEN_PATH", "").strip()
    if not url or not token_path:
        return "", ""
    try:
        token = _read_stable_sandbox_file(
            Path(token_path),
            64,
        ).decode("ascii")
    except (OSError, UnicodeError):
        token = ""
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        return "", ""
    return url, token



def read_native_profile(override_path=PROFILE_OVERRIDE_PATH, state_path=PROFILE_STATE_PATH):
    # Operator override (hard lock)
    if os.path.exists(override_path):
        try:
            with open(override_path) as f:
                data = yaml.safe_load(f)
            name = data.get("profile", "") if isinstance(data, dict) else ""
            if name in VALID_PROFILES:
                return name, True  # (profile_name, is_locked)
        except (OSError, UnicodeError, yaml.YAMLError):
            pass
        # An operator-created override is authoritative. If it is unreadable
        # or invalid, never silently fall through to mutable runtime state.
        log.error("profile override is present but invalid; profile changes are disabled")
        return INVALID_PROFILE_OVERRIDE, True

    # Runtime state
    if os.path.exists(state_path):
        try:
            with open(state_path) as f:
                data = json.load(f)
            name = data.get("active", "")
            if name in VALID_PROFILES:
                return name, False
        except Exception:
            pass

    # Native appliance fallback
    return "offline_private", False


def current_profile():
    if os.getenv("SECURE_AI_DEPLOYMENT_MODE", "").strip().lower() == "sandbox":
        return _ready_sandbox_profile() or UNREADY_SANDBOX_PROFILE, False
    return read_native_profile()

def binding():
    profile, _ = current_profile()
    if profile not in {"research", "full_lab"}:
        raise PermissionError("current profile does not permit catalog downloads")
    sandbox = os.getenv("SECURE_AI_DEPLOYMENT_MODE", "").strip().lower() == "sandbox"
    markers = _read_ready_state_markers() if sandbox else None
    if sandbox and markers is None:
        raise PermissionError("sandbox generation is unready")
    return {"profile": profile, "mode": "sandbox" if sandbox else "appliance",
            "generation": markers[0] if markers else "", "session": markers[1] if markers else ""}

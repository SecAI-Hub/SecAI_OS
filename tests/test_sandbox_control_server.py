import contextlib
import importlib.util
import io
import json
import os
import signal
import stat
import sys
import threading
import time
from email.message import Message
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "sandbox" / "control_server.py"
)
SPEC = importlib.util.spec_from_file_location("secai_sandbox_control", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)
TEST_SERVER_SESSION = "7" * 64


class _Connection:
    def __init__(self):
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value


def _handler(headers: list[tuple[str, str]], body: bytes = b""):
    handler = control.Handler.__new__(control.Handler)
    message = Message()
    for key, value in headers:
        message[key] = value
    handler.headers = message
    handler.rfile = io.BytesIO(body)
    handler.connection = _Connection()
    return handler


def _safe_control_token(runtime_dir: Path, token: str = "a" * 64) -> Path:
    runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        runtime_dir.chmod(0o700)
    token_path = runtime_dir / "control-token"
    token_path.write_text(token, encoding="ascii")
    if os.name != "nt":
        token_path.chmod(control.CONTROL_TOKEN_POSIX_MODE)
    return token_path


def _ignore_native_acl_in_fixture(monkeypatch):
    if os.name == "nt":
        monkeypatch.setattr(
            control,
            "_verify_windows_owner_only_acl",
            lambda _path, **_kwargs: None,
        )


def _write_generation_profile(
    runtime_dir: Path,
    generation: str,
    profile_payload: str,
) -> Path:
    generation_dir = runtime_dir / "generations" / generation
    generation_dir.mkdir(parents=True, exist_ok=True)
    payload = profile_payload.encode("utf-8")
    (generation_dir / "profile.json").write_bytes(payload)
    manifest = {
        "files": [
            {
                "path": "profile.json",
                "sha256": control.hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ],
        "generation": generation,
        "version": control.RUNTIME_GENERATION_FORMAT,
    }
    (generation_dir / "generation.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        (generation_dir / "profile.json").chmod(0o444)
        (generation_dir / "generation.json").chmod(0o444)
        generation_dir.chmod(0o555)
    return generation_dir


def _write_ready_generation(runtime_dir: Path, generation: str) -> Path:
    status_dir = runtime_dir / "generation-status"
    status_dir.mkdir(parents=True, exist_ok=True)
    (status_dir / "ready-session").write_text(
        TEST_SERVER_SESSION,
        encoding="ascii",
    )
    ready_path = status_dir / "ready-generation"
    ready_path.write_text(generation, encoding="ascii")
    return ready_path


def _signed_health_payload(
    token: str,
    challenge: str,
    *,
    session_id: str = TEST_SERVER_SESSION,
    status: str = "ok",
    profile_state: str = "active",
    profile: str = "research",
) -> dict[str, object]:
    return {
        "controller": "secai-sandbox-control",
        "protocol_version": control.CONTROL_PROTOCOL_VERSION,
        "state_protocol_version": control.CONTROL_STATE_PROTOCOL_VERSION,
        "status": status,
        "profile_state": profile_state,
        "profile": profile,
        "session_id": session_id,
        "proof": control._health_proof(token, challenge),
        "state_proof": control._state_proof(
            token,
            challenge,
            session_id,
            status,
            profile_state,
            profile,
        ),
    }


@pytest.fixture(autouse=True)
def _controller_session_for_profile_tests():
    previous = control._server_session
    control._server_session = TEST_SERVER_SESSION
    try:
        yield
    finally:
        control._server_session = previous


def test_control_body_requires_one_non_negative_content_length():
    assert _handler([])._read_body()[1] == "exactly one content length is required"
    assert _handler([("Content-Length", "-1")])._read_body()[1] == "invalid content length"
    assert _handler([
        ("Content-Length", "2"),
        ("Content-Length", "2"),
    ])._read_body()[1] == "exactly one content length is required"


def test_control_body_rejects_transfer_encoding_and_short_reads():
    assert _handler([
        ("Content-Length", "2"),
        ("Transfer-Encoding", "chunked"),
    ], b"{}")._read_body()[1] == "transfer encoding is not supported"
    assert _handler([("Content-Length", "4")], b"{}")._read_body()[1] == (
        "incomplete request body"
    )


def test_control_body_accepts_bounded_json_object_and_sets_timeout():
    handler = _handler([("Content-Length", "2")], b"{}")
    payload, error = handler._read_body()
    assert error is None
    assert payload == {}
    assert handler.connection.timeout == control.BODY_READ_TIMEOUT_SECONDS


def test_control_health_proof_is_challenge_bound(monkeypatch, tmp_path):
    token = "a" * 64
    first = control._health_proof(token, "b" * 64)
    second = control._health_proof(token, "c" * 64)
    assert len(first) == 64
    assert first != second
    assert first != control._health_proof(token, "b" * 64, 1)
    assert control._health_proof(token, "b" * 64, 3.0) == ""
    assert control._health_proof(token, "not-a-challenge") == ""
    assert control._health_proof("", "b" * 64) == ""

    timestamp = str(int(time.time()))
    nonce = "d" * 64
    body = b'{"profile":"research"}'
    body_hash, signature = control._request_signature(
        token=token,
        method="POST",
        path="/v1/apply",
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    assert body_hash == control.hashlib.sha256(body).hexdigest()
    assert len(signature) == 64
    assert signature != control._request_signature(
        token=token,
        method="POST",
        path="/v1/shutdown",
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )[1]

    old_config = control.CONFIG
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    _ignore_native_acl_in_fixture(monkeypatch)
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    control._auth_nonces.clear()
    try:
        assert control._consume_auth_nonce(nonce, time.time()) is True
        nonce_state = control.CONFIG.runtime_dir / "control-auth-nonces.json"
        assert nonce_state.exists()
        assert nonce_state.stat().st_mode & 0o777 == 0o600
        assert control._consume_auth_nonce(nonce, time.time()) is False
        control._auth_nonces.clear()
        assert control._load_auth_nonce_state() is True
        assert control._consume_auth_nonce(nonce, time.time()) is False
    finally:
        control._auth_nonces.clear()
        control.CONFIG = old_config

    request_headers = control._request_auth_headers(
        token,
        "POST",
        "/v1/apply",
        body,
    )
    handler = _handler(list(request_headers.items()), body)
    handler.command = "POST"
    handler.path = "/v1/apply"
    monkeypatch.setattr(control, "_read_token", lambda: token)
    assert handler._authorized(body) is True
    assert handler._authorized(body) is False
    control._auth_nonces.clear()


def test_control_state_proof_binds_every_health_field():
    token = "a" * 64
    challenge = "b" * 64
    payload = _signed_health_payload(token, challenge)
    canonical = "\n".join(
        (
            "secai-sandbox-control-state:v1",
            challenge,
            TEST_SERVER_SESSION,
            "ok",
            "active",
            "research",
        )
    ).encode("ascii")
    assert payload["state_proof"] == control.hmac.new(
        token.encode("ascii"),
        canonical,
        "sha256",
    ).hexdigest()
    assert control._verify_challenge_health_payload(
        token=token,
        challenge=challenge,
        payload=payload,
    )

    tampered_values = {
        "controller": "other-controller",
        "protocol_version": 2,
        "state_protocol_version": 2,
        "session_id": "8" * 64,
        "status": "degraded",
        "profile_state": "degraded",
        "profile": "full_lab",
        "proof": "0" * 64,
        "state_proof": "0" * 64,
    }
    for field, value in tampered_values.items():
        tampered = dict(payload)
        tampered[field] = value
        assert not control._verify_challenge_health_payload(
            token=token,
            challenge=challenge,
            payload=tampered,
        ), field
    for field, value in (
        ("protocol_version", 3.0),
        ("state_protocol_version", 1.0),
    ):
        tampered = dict(payload)
        tampered[field] = value
        assert not control._verify_challenge_health_payload(
            token=token,
            challenge=challenge,
            payload=tampered,
        ), field
    assert not control._verify_challenge_health_payload(
        token="c" * 64,
        challenge=challenge,
        payload=payload,
    )
    assert not control._verify_challenge_health_payload(
        token=token,
        challenge="c" * 64,
        payload=payload,
    )


def test_control_state_proof_accepts_only_defined_profile_states():
    token = "a" * 64
    challenge = "b" * 64
    degraded = _signed_health_payload(
        token,
        challenge,
        status="degraded",
        profile_state="degraded",
        profile=control.UNKNOWN_PROFILE,
    )
    assert control._verify_challenge_health_payload(
        token=token,
        challenge=challenge,
        payload=degraded,
    )
    assert control._state_proof(
        token,
        challenge,
        TEST_SERVER_SESSION,
        "ok",
        "degraded",
        control.UNKNOWN_PROFILE,
    ) == ""
    assert control._state_proof(
        token,
        challenge,
        TEST_SERVER_SESSION,
        "ok",
        "active",
        control.UNKNOWN_PROFILE,
    ) == ""


def test_control_private_metadata_write_replaces_link_without_following(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    outside = tmp_path / "outside"
    outside.write_bytes(b"must-not-change")
    target = runtime_dir / "control-server-host"
    try:
        target.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    control._write_private_file_atomic(target, b"127.0.0.1")

    assert not target.is_symlink()
    assert target.read_bytes() == b"127.0.0.1"
    assert outside.read_bytes() == b"must-not-change"
    assert os.lstat(target).st_nlink == 1
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert not list(runtime_dir.glob(".control-server-host.*.tmp"))


def test_control_private_metadata_write_does_not_follow_temp_collision(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    monkeypatch.setattr(control.secrets, "token_hex", lambda _size: "c" * 16)
    target = runtime_dir / "control-server-host"
    temporary = runtime_dir / (
        f".control-server-host.{os.getpid()}.{'c' * 16}.tmp"
    )
    outside = tmp_path / "outside-collision"
    outside.write_bytes(b"must-not-change")
    try:
        temporary.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(FileExistsError):
        control._write_private_file_atomic(target, b"127.0.0.1")

    assert temporary.is_symlink()
    assert outside.read_bytes() == b"must-not-change"
    assert not target.exists()


def test_control_session_metadata_rotates_and_unlinks_only_matching_value(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    first = "1" * 64
    second = "2" * 64
    target = runtime_dir / "control-server-session"

    first_identity = control._write_private_file_atomic(
        target,
        first.encode("ascii"),
    )
    assert target.read_text(encoding="ascii") == first
    assert os.lstat(target).st_nlink == 1
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert not control._unlink_private_file_if_payload(
        target,
        second.encode("ascii"),
    )
    assert target.exists()

    second_identity = control._write_private_file_atomic(
        target,
        second.encode("ascii"),
    )
    assert not control._unlink_private_file_if_payload(
        target,
        first.encode("ascii"),
    )
    assert target.read_text(encoding="ascii") == second
    replacement_identity = control._write_private_file_atomic(
        target,
        second.encode("ascii"),
    )
    assert first_identity != second_identity
    assert second_identity != replacement_identity
    assert not control._unlink_private_file_if_payload(
        target,
        second.encode("ascii"),
        expected_identity=second_identity,
    )
    assert control._unlink_private_file_if_payload(
        target,
        second.encode("ascii"),
        expected_identity=replacement_identity,
    )
    assert not target.exists()

    outside = tmp_path / "outside-session"
    outside.write_text(second, encoding="ascii")
    try:
        target.symlink_to(outside)
    except OSError:
        return
    assert not control._unlink_private_file_if_payload(
        target,
        second.encode("ascii"),
    )
    assert target.is_symlink()
    assert outside.read_text(encoding="ascii") == second


def test_control_session_ids_are_random_exact_lowercase_hex():
    first = control._new_controller_session()
    second = control._new_controller_session()
    assert first != second
    assert control._valid_session_id(first)
    assert control._valid_session_id(second)
    assert len(first) == len(second) == 64


def test_control_private_state_directory_is_real_and_private(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    state_dir = runtime_dir / "state"
    state_dir.mkdir(mode=0o755)

    control._ensure_private_directory(state_dir)

    assert state_dir.is_dir()
    assert not state_dir.is_symlink()
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(state_dir).st_mode) == 0o700


def test_windows_acl_commands_distinguish_protected_and_inherited(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "acl-target"
    target.mkdir()
    calls = []

    class Result:
        returncode = 0

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr(control.os, "name", "nt")
    monkeypatch.setattr(control.shutil, "which", lambda _name: "pwsh")
    monkeypatch.setattr(control.subprocess, "run", run)

    control._verify_windows_owner_only_acl(target)
    control._verify_windows_owner_only_acl(
        target,
        allow_inherited=True,
    )
    control._set_windows_owner_only_acl(target, directory=True)

    assert len(calls) == 4
    assert calls[0][1]["env"]["SECAI_CONTROL_ALLOW_INHERITED_ACL"] == "0"
    assert calls[1][1]["env"]["SECAI_CONTROL_ALLOW_INHERITED_ACL"] == "1"
    assert "DirectorySecurity" in calls[2][0][0][-1]
    assert "ContainerInherit" in calls[2][0][0][-1]
    assert calls[3][1]["env"]["SECAI_CONTROL_ALLOW_INHERITED_ACL"] == "0"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACLs")
def test_windows_native_controller_state_acl_inheritance(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    control._set_windows_owner_only_acl(state_dir, directory=True)
    control._verify_windows_owner_only_acl(state_dir)

    inherited_file = state_dir / "inherited"
    inherited_file.write_bytes(b"state")
    control._verify_windows_owner_only_acl(
        inherited_file,
        allow_inherited=True,
    )
    control._set_windows_owner_only_acl(inherited_file, directory=False)
    control._verify_windows_owner_only_acl(inherited_file)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversize"])
def test_control_nonce_state_rejects_unsafe_file(
    tmp_path,
    monkeypatch,
    unsafe_kind,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    _safe_control_token(runtime_dir)
    nonce_path = runtime_dir / "control-auth-nonces.json"
    if unsafe_kind == "symlink":
        outside = tmp_path / "outside-nonces"
        outside.write_text(
            '{"version":1,"nonces":[]}\n',
            encoding="utf-8",
        )
        try:
            nonce_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        nonce_path.write_bytes(
            b"x" * (control.AUTH_NONCE_STATE_MAX_BYTES + 1)
        )

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._load_auth_nonce_state() is False
    finally:
        control._auth_nonces.clear()
        control.CONFIG = old_config


def test_control_token_requires_exact_lowercase_hex():
    assert control._valid_control_token("a" * 64)
    for value in (
        "",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        ("a" * 63) + "g",
        ("a" * 64) + "\n",
    ):
        assert not control._valid_control_token(value)


def test_control_token_loader_requires_exact_private_runtime_and_mode(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    token_path = _safe_control_token(runtime_dir)

    assert control._load_control_token(runtime_dir, token_path) == "a" * 64

    wrong_path = runtime_dir / "alternate-token"
    wrong_path.write_text("b" * 64, encoding="ascii")
    if os.name != "nt":
        wrong_path.chmod(control.CONTROL_TOKEN_POSIX_MODE)
    with pytest.raises(RuntimeError, match="lexical control-token child"):
        control._load_control_token(runtime_dir, wrong_path)

    if os.name != "nt":
        token_path.chmod(0o600)
        with pytest.raises(RuntimeError, match="mode-0604"):
            control._load_control_token(runtime_dir, token_path)


def test_control_token_loader_rejects_token_symlink_and_hardlink(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    source = tmp_path / "source-token"
    source.write_text("a" * 64, encoding="ascii")
    if os.name != "nt":
        source.chmod(control.CONTROL_TOKEN_POSIX_MODE)
    token_path = runtime_dir / "control-token"

    try:
        token_path.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    with pytest.raises((OSError, RuntimeError)):
        control._load_control_token(runtime_dir, token_path)
    token_path.unlink()

    try:
        os.link(source, token_path)
    except OSError as exc:
        pytest.skip(f"hardlink creation is unavailable: {exc}")
    with pytest.raises(RuntimeError, match="singly linked"):
        control._load_control_token(runtime_dir, token_path)


def test_control_token_loader_rejects_runtime_directory_symlink(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    outside = tmp_path / "outside"
    _safe_control_token(outside)
    runtime_dir = tmp_path / "runtime"
    try:
        runtime_dir.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(RuntimeError, match="real directory"):
        control._load_control_token(
            runtime_dir,
            runtime_dir / "control-token",
        )


def test_control_token_loader_rejects_inode_swap(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    token_path = _safe_control_token(runtime_dir)
    replacement = runtime_dir / "replacement"
    replacement.write_text("b" * 64, encoding="ascii")
    if os.name != "nt":
        replacement.chmod(control.CONTROL_TOKEN_POSIX_MODE)
    original_open = control.os.open
    raced = False

    def replace_before_open(path, flags, *args):
        nonlocal raced
        if Path(path) == token_path and not raced:
            raced = True
            os.replace(replacement, token_path)
        return original_open(path, flags, *args)

    monkeypatch.setattr(control.os, "open", replace_before_open)
    with pytest.raises(RuntimeError, match="changed during validation"):
        control._load_control_token(runtime_dir, token_path)
    assert raced is True


def test_control_server_token_is_stable_after_path_replacement(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    runtime_dir = tmp_path / "runtime"
    token_path = _safe_control_token(runtime_dir, "a" * 64)
    replacement = runtime_dir / "replacement"
    replacement.write_text("b" * 64, encoding="ascii")
    if os.name != "nt":
        replacement.chmod(control.CONTROL_TOKEN_POSIX_MODE)

    previous = control._server_token
    try:
        control._server_token = control._load_control_token(
            runtime_dir,
            token_path,
        )
        os.replace(replacement, token_path)
        assert control._read_token() == "a" * 64
        assert control._read_token() != control._load_control_token(
            runtime_dir,
            token_path,
        )
    finally:
        control._server_token = previous


def test_control_profile_follows_atomic_active_generation_switch(tmp_path):
    runtime_dir = tmp_path / "runtime"
    generations_dir = runtime_dir / "generations"
    generations_dir.mkdir(parents=True)
    first = "a" * 64
    second = "b" * 64
    for generation, profile in (
        (first, "research"),
        (second, "full_lab"),
    ):
        _write_generation_profile(
            runtime_dir,
            generation,
            json.dumps({"active": profile}) + "\n",
        )
    active = runtime_dir / "active-generation"
    active.write_text(first, encoding="ascii")
    ready = _write_ready_generation(runtime_dir, first)

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == "research"
        temporary = runtime_dir / ".active-generation.test.tmp"
        temporary.write_text(second, encoding="ascii")
        os.replace(temporary, active)
        assert control._current_profile() == control.UNKNOWN_PROFILE
        ready_temporary = (
            runtime_dir / "generation-status" / ".ready.test.tmp"
        )
        ready_temporary.write_text(second, encoding="ascii")
        os.replace(ready_temporary, ready)
        assert control._current_profile() == "full_lab"
    finally:
        control.CONFIG = old_config


def test_control_profile_rejects_intermediate_generation_link(tmp_path):
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    outside_root = tmp_path / "outside-root"
    generation = "c" * 64
    _write_generation_profile(
        outside_root,
        generation,
        '{"active":"full_lab"}\n',
    )
    outside = outside_root / "generations"
    try:
        (runtime_dir / "generations").symlink_to(
            outside,
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    (runtime_dir / "active-generation").write_text(
        generation,
        encoding="ascii",
    )
    _write_ready_generation(runtime_dir, generation)

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == control.UNKNOWN_PROFILE
    finally:
        control.CONFIG = old_config


@pytest.mark.parametrize(
    ("pointer_payload", "profile_payload"),
    [
        ("", '{"active":"offline_private"}\n'),
        ("malformed", '{"active":"offline_private"}\n'),
        ("d" * 64, "{not-json"),
        ("d" * 64, '{"active":"invalid"}\n'),
        ("d" * 64, "[]\n"),
        (
            "d" * 64,
            '{"active":"research","active":"offline_private"}\n',
        ),
        ("d" * 64, '{"active":"offline_private","extra":true}\n'),
    ],
)
def test_control_profile_reports_corrupt_generation_state_as_unknown(
    tmp_path,
    pointer_payload,
    profile_payload,
):
    runtime_dir = tmp_path / "runtime"
    generation = "d" * 64
    _write_generation_profile(
        runtime_dir,
        generation,
        profile_payload,
    )
    _write_ready_generation(runtime_dir, generation)
    if pointer_payload:
        (runtime_dir / "active-generation").write_text(
            pointer_payload,
            encoding="ascii",
        )

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == control.UNKNOWN_PROFILE
        status = control._status()
        assert status["profile"] == control.UNKNOWN_PROFILE
        assert status["profile_state"] == "degraded"
    finally:
        control.CONFIG = old_config


def test_control_profile_reports_concurrent_pointer_switch_as_unknown(
    tmp_path,
    monkeypatch,
):
    runtime_dir = tmp_path / "runtime"
    generation = "e" * 64
    _write_generation_profile(
        runtime_dir,
        generation,
        '{"active":"offline_private"}\n',
    )
    observed = iter((generation, "f" * 64))
    monkeypatch.setattr(
        control,
        "_active_generation",
        lambda _runtime_dir: next(observed),
    )
    monkeypatch.setattr(
        control,
        "_ready_generation",
        lambda _runtime_dir: generation,
    )
    monkeypatch.setattr(
        control,
        "_ready_session",
        lambda _runtime_dir: TEST_SERVER_SESSION,
    )

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == control.UNKNOWN_PROFILE
        monkeypatch.setattr(
            control,
            "_active_generation",
            lambda _runtime_dir: generation,
        )
        ready_observed = iter((generation, "f" * 64))
        monkeypatch.setattr(
            control,
            "_ready_generation",
            lambda _runtime_dir: next(ready_observed),
        )
        assert control._current_profile() == control.UNKNOWN_PROFILE
        monkeypatch.setattr(
            control,
            "_ready_generation",
            lambda _runtime_dir: generation,
        )
        ready_session_observed = iter(
            (TEST_SERVER_SESSION, "8" * 64)
        )
        monkeypatch.setattr(
            control,
            "_ready_session",
            lambda _runtime_dir: next(ready_session_observed),
        )
        assert control._current_profile() == control.UNKNOWN_PROFILE
    finally:
        control.CONFIG = old_config


def test_control_profile_requires_valid_generation_manifest(tmp_path):
    runtime_dir = tmp_path / "runtime"
    generation = "9" * 64
    generation_dir = _write_generation_profile(
        runtime_dir,
        generation,
        '{"active":"offline_private"}\n',
    )
    (runtime_dir / "active-generation").write_text(
        generation,
        encoding="ascii",
    )
    ready_path = _write_ready_generation(runtime_dir, generation)
    manifest_path = generation_dir / "generation.json"
    valid_manifest = manifest_path.read_text(encoding="utf-8")

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == "offline_private"
        invalid_manifests = (
            '{"files":[],"generation":"'
            + generation
            + '","version":1}\n',
            valid_manifest.replace(
                '"version": 1',
                '"version": 2',
            ),
            valid_manifest.replace(
                generation,
                "8" * 64,
            ),
            valid_manifest.replace(
                control.hashlib.sha256(
                    b'{"active":"offline_private"}\n'
                ).hexdigest(),
                "0" * 64,
            ),
            '{"files":[],"generation":"'
            + generation
            + '","generation":"'
            + generation
            + '","version":1}\n',
            '{"files":['
            '{"path":"profile.json","sha256":"'
            + ("0" * 64)
            + '","size":29},'
            '{"path":"profile.json","sha256":"'
            + ("0" * 64)
            + '","size":29}],'
            '"generation":"'
            + generation
            + '","version":1}\n',
        )
        for invalid_manifest in invalid_manifests:
            if os.name != "nt":
                manifest_path.chmod(0o644)
            manifest_path.write_text(
                invalid_manifest,
                encoding="utf-8",
            )
            if os.name != "nt":
                manifest_path.chmod(0o444)
            assert control._current_profile() == control.UNKNOWN_PROFILE
        if os.name != "nt":
            manifest_path.chmod(0o644)
        manifest_path.write_text(valid_manifest, encoding="utf-8")
        if os.name != "nt":
            manifest_path.chmod(0o444)
        ready_session_path = (
            runtime_dir / "generation-status" / "ready-session"
        )
        ready_session_path.unlink()
        assert control._current_profile() == control.UNKNOWN_PROFILE
        ready_session_path.write_text("8" * 64, encoding="ascii")
        assert control._current_profile() == control.UNKNOWN_PROFILE
        ready_session_path.unlink()
        outside_session = tmp_path / "outside-ready-session"
        outside_session.write_text(TEST_SERVER_SESSION, encoding="ascii")
        try:
            ready_session_path.symlink_to(outside_session)
        except OSError:
            ready_session_path.write_text(
                TEST_SERVER_SESSION,
                encoding="ascii",
            )
        else:
            assert control._current_profile() == control.UNKNOWN_PROFILE
            ready_session_path.unlink()
            ready_session_path.write_text(
                TEST_SERVER_SESSION,
                encoding="ascii",
            )
        ready_path.unlink()
        assert control._current_profile() == control.UNKNOWN_PROFILE
        outside_marker = tmp_path / "outside-ready"
        outside_marker.write_text(generation, encoding="ascii")
        try:
            ready_path.symlink_to(outside_marker)
        except OSError:
            pass
        else:
            assert control._current_profile() == control.UNKNOWN_PROFILE
    finally:
        control.CONFIG = old_config


def test_control_profile_is_bound_to_current_controller_session(tmp_path):
    runtime_dir = tmp_path / "runtime"
    generation = "6" * 64
    _write_generation_profile(
        runtime_dir,
        generation,
        '{"active":"research"}\n',
    )
    (runtime_dir / "active-generation").write_text(
        generation,
        encoding="ascii",
    )
    _write_ready_generation(runtime_dir, generation)

    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    try:
        assert control._current_profile() == "research"
        restarted_session = "8" * 64
        control._server_session = restarted_session
        assert control._current_profile() == control.UNKNOWN_PROFILE
        (
            runtime_dir / "generation-status" / "ready-session"
        ).write_text(restarted_session, encoding="ascii")
        assert control._current_profile() == "research"
    finally:
        control.CONFIG = old_config


def test_control_health_reports_unknown_profile_as_degraded(
    tmp_path,
    monkeypatch,
):
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    monkeypatch.setattr(control, "_read_token", lambda: "a" * 64)
    handler = control.Handler.__new__(control.Handler)
    handler.path = f"/health?challenge={'b' * 64}"
    responses = []
    handler._send_json = (
        lambda payload, status=200: responses.append((payload, status))
    )
    try:
        handler.do_GET()
    finally:
        control.CONFIG = old_config

    assert responses[0][0]["status"] == "degraded"
    assert responses[0][0]["profile"] == control.UNKNOWN_PROFILE
    assert responses[0][0]["profile_state"] == "degraded"
    assert (
        responses[0][0]["state_protocol_version"]
        == control.CONTROL_STATE_PROTOCOL_VERSION
    )
    assert responses[0][0]["session_id"] == TEST_SERVER_SESSION
    assert len(responses[0][0]["proof"]) == 64
    assert len(responses[0][0]["state_proof"]) == 64
    assert control._verify_challenge_health_payload(
        token="a" * 64,
        challenge="b" * 64,
        payload=responses[0][0],
    )


def test_control_health_reports_session_bound_active_profile(
    tmp_path,
    monkeypatch,
):
    token = "a" * 64
    challenge = "b" * 64
    runtime_dir = tmp_path / "runtime"
    generation = "5" * 64
    _write_generation_profile(
        runtime_dir,
        generation,
        '{"active":"full_lab"}\n',
    )
    (runtime_dir / "active-generation").write_text(
        generation,
        encoding="ascii",
    )
    _write_ready_generation(runtime_dir, generation)
    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        runtime_dir,
        runtime_dir / "control-token",
    )
    monkeypatch.setattr(control, "_read_token", lambda: token)
    handler = control.Handler.__new__(control.Handler)
    handler.path = f"/health?challenge={challenge}"
    responses = []
    handler._send_json = (
        lambda payload, status=200: responses.append((payload, status))
    )
    try:
        handler.do_GET()
    finally:
        control.CONFIG = old_config

    payload = responses[0][0]
    assert payload["status"] == "ok"
    assert payload["profile"] == "full_lab"
    assert payload["profile_state"] == "active"
    assert payload["session_id"] == TEST_SERVER_SESSION
    assert control._verify_challenge_health_payload(
        token=token,
        challenge=challenge,
        payload=payload,
    )


def test_control_runtime_reader_completes_short_regular_file_reads(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "runtime-value"
    target.write_bytes(b"a" * 64)
    original_read = os.read
    calls = []

    def short_read(descriptor, size):
        payload = original_read(descriptor, min(size, 5))
        calls.append(len(payload))
        return payload

    monkeypatch.setattr(control.os, "read", short_read)
    assert control._read_runtime_file_no_follow(target, 64) == b"a" * 64
    assert len(calls) > 1


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversize"])
def test_control_recorded_host_ignores_unsafe_metadata(
    tmp_path,
    unsafe_kind,
):
    host_path = tmp_path / "control-server-host"
    if unsafe_kind == "symlink":
        outside = tmp_path / "outside-host"
        outside.write_text("8.8.8.8", encoding="ascii")
        try:
            host_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        host_path.write_bytes(b"8" * (control.MAX_RECORDED_HOST_BYTES + 1))

    assert control._read_recorded_host(
        tmp_path,
        "127.0.0.1",
    ) == "127.0.0.1"


@pytest.mark.parametrize("unsafe_kind", ["symlink", "oversize"])
def test_control_recorded_pid_ignores_unsafe_metadata(
    tmp_path,
    unsafe_kind,
):
    pid_path = tmp_path / "control-server.pid"
    if unsafe_kind == "symlink":
        outside = tmp_path / "outside-pid"
        outside.write_text("4242", encoding="ascii")
        try:
            pid_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        pid_path.write_bytes(b"4" * (control.MAX_RECORDED_PID_BYTES + 1))

    assert control._read_recorded_pid(tmp_path) == 0


def test_control_bind_address_accepts_only_loopback_or_private_ipv4():
    assert control._safe_private_bind_address("127.0.0.1") == "127.0.0.1"
    assert control._safe_private_bind_address("172.18.0.1") == "172.18.0.1"
    assert control._safe_explicit_bind_address("127.0.0.1") == "127.0.0.1"
    for value in (
        "0.0.0.0",
        "8.8.8.8",
        "169.254.1.1",
        "192.0.0.1",
        "::1",
        "invalid",
    ):
        with pytest.raises(ValueError):
            control._safe_private_bind_address(value)
    with pytest.raises(ValueError):
        control._safe_explicit_bind_address("172.18.0.1")


def test_control_auto_bind_uses_loopback_or_a_local_linux_bridge(monkeypatch):
    monkeypatch.setattr(control.platform, "system", lambda: "Darwin")
    assert control._resolve_bind_host("auto") == "127.0.0.1"

    monkeypatch.setattr(control.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "docker" else None,
    )
    monkeypatch.setattr(control, "_docker_is_rootless", lambda: False)
    monkeypatch.setattr(control, "_docker_bridge_gateway", lambda: "172.18.0.1")
    monkeypatch.setattr(control, "_address_is_local", lambda value: value == "172.18.0.1")
    assert control._resolve_bind_host("auto") == "172.18.0.1"

    requested_networks = []
    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "podman" else None,
    )
    monkeypatch.setattr(control, "_podman_is_rootless", lambda: False)
    monkeypatch.setattr(
        control,
        "_podman_bridge_gateway",
        lambda network: (
            requested_networks.append(network) or "10.89.0.1"
            if network == control.PODMAN_CONTROL_NETWORK
            else ""
        ),
    )
    monkeypatch.setattr(control, "_address_is_local", lambda value: value == "10.89.0.1")
    assert control._resolve_bind_host("auto", "podman") == "10.89.0.1"
    assert requested_networks == ["secai-sandbox_ingress"]
    with pytest.raises(RuntimeError):
        control._resolve_bind_host("auto", "podman", "podman")


def test_control_auto_bind_fails_closed_without_a_private_linux_bridge(monkeypatch):
    monkeypatch.setattr(control.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "docker" else None,
    )
    monkeypatch.setattr(control, "_docker_is_rootless", lambda: False)
    monkeypatch.setattr(control, "_docker_bridge_gateway", lambda: "8.8.8.8")
    with pytest.raises(RuntimeError):
        control._resolve_bind_host("auto")


def test_control_auto_bind_rejects_rootless_engines(
    monkeypatch,
):
    monkeypatch.setattr(control.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "docker" else None,
    )
    monkeypatch.setattr(control, "_docker_is_rootless", lambda: True)
    with pytest.raises(RuntimeError, match="rootless Docker"):
        control._resolve_bind_host("auto", "docker")

    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "podman" else None,
    )
    monkeypatch.setattr(control, "_podman_is_rootless", lambda: True)
    with pytest.raises(RuntimeError, match="rootless Podman"):
        control._resolve_bind_host("auto", "podman")

    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}"
        if name in {"podman", "docker"}
        else None,
    )
    monkeypatch.setattr(control, "_docker_is_rootless", lambda: False)
    assert control._resolve_linux_runtime("auto")[0] == "docker"

    monkeypatch.setattr(
        control.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == "docker" else None,
    )
    monkeypatch.setattr(control, "_docker_is_desktop", lambda: True)
    assert control._resolve_bind_host("auto", "docker") == "127.0.0.1"


def test_control_probe_never_transmits_bearer_token(monkeypatch, tmp_path):
    requests = []

    class _Response:
        status = 404

        def read(self, _limit):
            return b'{"error":"not found"}'

    class _HTTPConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, body=None, headers=None):
            requests.append((method, path, body, headers or {}))

        def getresponse(self):
            return _Response()

        def close(self):
            pass

    monkeypatch.setattr(
        control,
        "_read_recorded_host",
        lambda *_args: "127.0.0.1",
    )
    monkeypatch.setattr(control.http.client, "HTTPConnection", _HTTPConnection)

    assert control._probe_endpoint(
        tmp_path,
        tmp_path / "control-token",
        "auto",
        control.CONTROL_PORT,
        loaded_token="a" * 64,
    ) == 1
    assert len(requests) == 1
    assert requests[0][0] == "GET"
    assert requests[0][1].startswith("/health?challenge=")
    assert "Authorization" not in requests[0][3]
    assert all("a" * 64 not in str(part) for part in requests[0])


def test_control_probe_proof_authenticates_reported_protocol():
    token = "a" * 64
    challenge = "b" * 64
    current = _signed_health_payload(token, challenge)
    assert control._validated_probe_status(
        http_status=200,
        payload=current,
        token=token,
        challenge=challenge,
    ) == 0

    legacy_v3 = {
        "controller": "secai-sandbox-control",
        "protocol_version": control.CONTROL_PROTOCOL_VERSION,
        "proof": control._health_proof(token, challenge),
    }
    assert control._validated_probe_status(
        http_status=200,
        payload=legacy_v3,
        token=token,
        challenge=challenge,
    ) == 2
    incompatible_state_protocol = dict(current)
    incompatible_state_protocol["state_protocol_version"] = 2
    assert control._validated_probe_status(
        http_status=200,
        payload=incompatible_state_protocol,
        token=token,
        challenge=challenge,
    ) == 2
    float_state_protocol = dict(current)
    float_state_protocol["state_protocol_version"] = 1.0
    assert control._validated_probe_status(
        http_status=200,
        payload=float_state_protocol,
        token=token,
        challenge=challenge,
    ) == 2
    float_protocol = dict(current)
    float_protocol["protocol_version"] = 3.0
    assert control._validated_probe_status(
        http_status=200,
        payload=float_protocol,
        token=token,
        challenge=challenge,
    ) == 1

    stale = {
        "controller": "secai-sandbox-control",
        "protocol_version": 1,
        "proof": control._health_proof(token, challenge, 1),
    }
    assert control._validated_probe_status(
        http_status=200,
        payload=stale,
        token=token,
        challenge=challenge,
    ) == 2
    stale["protocol_version"] = control.CONTROL_PROTOCOL_VERSION
    assert control._validated_probe_status(
        http_status=200,
        payload=stale,
        token=token,
        challenge=challenge,
    ) == 1
    tampered = dict(current)
    tampered["profile"] = "full_lab"
    assert control._validated_probe_status(
        http_status=200,
        payload=tampered,
        token=token,
        challenge=challenge,
    ) == 1


def test_control_stop_refuses_unverified_and_stops_authenticated_old_protocol(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    if os.name != "nt":
        tmp_path.chmod(0o700)
    monkeypatch.setattr(control, "_read_recorded_pid", lambda _runtime: 123)
    monkeypatch.setattr(control, "_process_exists", lambda _pid: False)
    monkeypatch.setattr(control, "_probe_endpoint", lambda *_args: 1)
    monkeypatch.setattr(
        control,
        "_endpoint_state",
        lambda *_args: control.ENDPOINT_AMBIGUOUS,
    )
    token_path = _safe_control_token(tmp_path)
    (tmp_path / "control-server-host").write_text(
        "127.0.0.1",
        encoding="utf-8",
    )

    assert control._stop_existing(
        tmp_path,
        token_path,
        "auto",
        control.CONTROL_PORT,
    ) == 1

    requests: list[tuple[str, str, bytes, dict[str, str]]] = []

    class _Response:
        status = 200

        def read(self, _limit):
            return b'{"status":"stopping"}'

    class _HTTPConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, body=b"", headers=None):
            requests.append((method, path, body, headers or {}))

        def getresponse(self):
            return _Response()

        def close(self):
            pass

    monkeypatch.setattr(control, "_read_recorded_pid", lambda _runtime: 0)
    monkeypatch.setattr(control, "_process_exists", lambda _pid: False)
    probe_arguments = []
    monkeypatch.setattr(
        control,
        "_probe_endpoint",
        lambda *_args: (probe_arguments.append(_args) or 2),
    )
    monkeypatch.setattr(
        control,
        "_endpoint_state",
        lambda *_args: control.ENDPOINT_ABSENT,
    )
    monkeypatch.setattr(control.http.client, "HTTPConnection", _HTTPConnection)

    assert control._stop_existing(
        tmp_path,
        token_path,
        "auto",
        control.CONTROL_PORT,
    ) == 0
    assert requests and requests[0][0:3] == ("POST", "/v1/shutdown", b"")
    assert "Authorization" not in requests[0][3]
    assert len(requests[0][3]["X-SecAI-Signature"]) == 64
    assert probe_arguments[0][-1] == "a" * 64


def test_control_stop_does_not_send_token_to_unverified_endpoint(
    tmp_path,
    monkeypatch,
):
    _ignore_native_acl_in_fixture(monkeypatch)
    if os.name != "nt":
        tmp_path.chmod(0o700)
    token_path = _safe_control_token(tmp_path)
    (tmp_path / "control-server-host").write_text(
        "127.0.0.1",
        encoding="ascii",
    )
    monkeypatch.setattr(control, "_read_recorded_pid", lambda _runtime: 123)
    monkeypatch.setattr(control, "_process_exists", lambda _pid: True)
    monkeypatch.setattr(control, "_probe_endpoint", lambda *_args: 1)
    monkeypatch.setattr(
        control,
        "_endpoint_state",
        lambda *_args: control.ENDPOINT_PRESENT,
    )

    def unexpected_connection(*_args, **_kwargs):
        pytest.fail("unverified endpoints must not receive shutdown credentials")

    monkeypatch.setattr(
        control.http.client,
        "HTTPConnection",
        unexpected_connection,
    )
    assert control._stop_existing(
        tmp_path,
        token_path,
        "auto",
        control.CONTROL_PORT,
    ) == 1


def test_control_server_has_bounded_header_handling():
    assert control.BoundedThreadingHTTPServer.daemon_threads is True
    assert (
        control.BoundedThreadingHTTPServer.request_queue_size
        == control.CONTROL_CONNECTION_LIMIT
    )
    assert 0 < control.HEADER_READ_TIMEOUT_SECONDS <= 5
    assert control.Handler.server_version == "SecAISandboxControl/3.0"
    assert control.MAX_HEADER_BYTES == 16384
    assert control.MAX_HEADER_COUNT == 32
    assert "handle_error" in control.BoundedThreadingHTTPServer.__dict__
    bounded = control._BoundedHeaderReader(
        io.BytesIO(b"a" * (control.MAX_HEADER_BYTES + 1)),
        control.MAX_HEADER_BYTES,
    )
    with pytest.raises(control.http.client.LineTooLong):
        bounded.readline()


def test_control_shutdown_cancels_resistant_process_tree(tmp_path, monkeypatch):
    old_config = control.CONFIG
    old_active_process = control._active_process
    control.CONFIG = control.ControlConfig(
        tmp_path,
        tmp_path / "runtime",
        tmp_path / "runtime" / "control-token",
    )
    control._active_process = None
    control._shutdown_requested.clear()
    control._tree_containment_failed.clear()
    control._tree_termination_confirmed.clear()
    monkeypatch.setattr(control, "PROCESS_TERM_GRACE_SECONDS", 0.2)

    child_pid_path = tmp_path / "resistant-child.pid"
    child_code = (
        "import os, pathlib, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(os.getpid())); "
        "time.sleep(30)"
    )
    parent_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(30)"
    )
    result: list[tuple[int, bool, bool, bool]] = []
    worker = threading.Thread(
        target=lambda: result.append(
            control._run_start_command([sys.executable, "-c", parent_code])
        )
    )
    child_pid = 0
    try:
        worker.start()
        deadline = time.monotonic() + 5
        while (
            control._active_process is None or not child_pid_path.exists()
        ) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert control._active_process is not None
        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        assert control._process_exists(child_pid)

        control._shutdown_requested.set()
        worker.join(timeout=10)

        assert not worker.is_alive()
        assert result and result[0][2] is True
        assert result[0][3] is True
        assert control._active_process is None
        assert not control._process_exists(child_pid)
        assert not control._tree_containment_failed.is_set()
    finally:
        if child_pid and control._process_exists(child_pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(
                    child_pid,
                    getattr(signal, "SIGKILL", signal.SIGTERM),
                )
        control._shutdown_requested.clear()
        control._tree_containment_failed.clear()
        control._tree_termination_confirmed.clear()
        control._active_process = old_active_process
        control.CONFIG = old_config


def test_control_env_update_is_atomic_private_and_handles_partial_writes(
    tmp_path,
    monkeypatch,
):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "UNCHANGED=value\nTARGET=old\nTARGET=stale\n",
        encoding="utf-8",
    )
    env_path.chmod(0o644)
    original_write = control.os.write
    write_sizes = []

    def partial_write(descriptor, payload):
        chunk = payload[:5]
        written = original_write(descriptor, chunk)
        write_sizes.append(written)
        return written

    monkeypatch.setattr(control.os, "write", partial_write)

    control._set_env_value(env_path, "TARGET", "new")

    assert env_path.stat().st_mode & 0o777 == 0o600
    assert env_path.read_text(encoding="utf-8") == (
        "UNCHANGED=value\nTARGET=new\n"
    )
    assert len(write_sizes) > 1
    assert max(write_sizes) <= 5
    assert list(tmp_path.iterdir()) == [env_path]


@pytest.mark.parametrize("invalid_kind", ["symlink", "directory", "oversize"])
def test_control_env_update_rejects_nonregular_targets(
    tmp_path,
    invalid_kind,
):
    env_path = tmp_path / ".env"
    outside = tmp_path / "outside"
    if invalid_kind == "symlink":
        outside.write_text("must-not-change", encoding="utf-8")
        try:
            env_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    elif invalid_kind == "directory":
        env_path.mkdir()
    else:
        env_path.write_bytes(b"x" * (control.MAX_ENV_FILE_BYTES + 1))

    metadata = os.lstat(env_path)
    original_payload = (
        env_path.read_bytes() if invalid_kind == "oversize" else None
    )

    with pytest.raises(RuntimeError, match=r"\.env"):
        control._set_env_value(env_path, "TARGET", "new")

    assert os.lstat(env_path).st_ino == metadata.st_ino
    if invalid_kind == "symlink":
        assert env_path.is_symlink()
        assert outside.read_text(encoding="utf-8") == "must-not-change"
    elif invalid_kind == "directory":
        assert env_path.is_dir()
    else:
        assert env_path.read_bytes() == original_payload


def test_control_gpu_environment_is_request_scoped(tmp_path, monkeypatch):
    old_config = control.CONFIG
    control.CONFIG = control.ControlConfig(
        tmp_path,
        tmp_path / "runtime",
        tmp_path / "runtime" / "control-token",
    )
    captured = []
    monkeypatch.setenv("SECAI_DIFFUSION_COMPUTE", "host-default")
    monkeypatch.setenv("SECAI_DIFFUSION_DEVICE_PREFERENCE", "host-choice")
    monkeypatch.setenv("SECAI_DIFFUSION_CPU_OFFLOAD", "host-offload")
    monkeypatch.setattr(control, "_command_args", lambda *_args, **_kwargs: ["start"])
    monkeypatch.setattr(control, "_display_command", lambda *_args, **_kwargs: "start")
    monkeypatch.setattr(control, "_write_json_atomic", lambda *_args: None)

    def run_start(_command, *, child_env_overrides=None):
        captured.append(dict(child_env_overrides or {}))
        return 0, False, False, True

    monkeypatch.setattr(control, "_run_start_command", run_start)
    try:
        control._run_apply(
            profile="full_lab",
            inference=False,
            gpu=True,
            gpu_backend="cuda",
            model_filename="",
            requested_by="test",
        )
        control._run_apply(
            profile="offline_private",
            inference=False,
            gpu=False,
            gpu_backend="",
            model_filename="",
            requested_by="test",
        )
    finally:
        control.CONFIG = old_config

    assert captured == [
        {
            "SECAI_DIFFUSION_COMPUTE": "cuda",
            "SECAI_DIFFUSION_DEVICE_PREFERENCE": "auto",
            "SECAI_DIFFUSION_CPU_OFFLOAD": "0",
        },
        {
            "SECAI_DIFFUSION_COMPUTE": "cpu",
            "SECAI_DIFFUSION_DEVICE_PREFERENCE": "cpu",
            "SECAI_DIFFUSION_CPU_OFFLOAD": "0",
        },
    ]
    assert os.environ["SECAI_DIFFUSION_COMPUTE"] == "host-default"
    assert os.environ["SECAI_DIFFUSION_DEVICE_PREFERENCE"] == "host-choice"
    assert os.environ["SECAI_DIFFUSION_CPU_OFFLOAD"] == "host-offload"


def test_windows_job_termination_accepts_an_already_exited_root(monkeypatch):
    class ExitedProcess:
        pid = 123
        returncode = 0

        def poll(self):
            return 0

    class EmptyJob:
        calls = 0

        def terminate_and_wait(self, _timeout):
            self.calls += 1
            return True

    process = ExitedProcess()
    job = EmptyJob()
    control._tree_containment_failed.clear()
    control._tree_termination_confirmed.clear()
    monkeypatch.setattr(control, "_running_on_windows", lambda: True)

    assert control._terminate_process_tree(process, job) is True
    assert job.calls == 1
    assert control._tree_termination_confirmed.is_set()
    assert not control._tree_containment_failed.is_set()


def test_windows_job_termination_without_a_job_fails_closed(monkeypatch):
    class ExitedProcess:
        pid = 123

        def poll(self):
            return 0

    control._tree_containment_failed.clear()
    control._tree_termination_confirmed.clear()
    monkeypatch.setattr(control, "_running_on_windows", lambda: True)

    assert control._terminate_process_tree(ExitedProcess()) is False
    assert control._tree_containment_failed.is_set()


def test_windows_start_is_suspended_assigned_then_resumed(monkeypatch):
    events = []

    class Process:
        pid = 321
        returncode = 0

        def poll(self):
            return 0

    class Job:
        def assign(self, _proc):
            events.append("assign")

        def resume(self, _proc):
            events.append("resume")

        def terminate_and_wait(self, _timeout):
            events.append("verify-empty")
            return True

        def close(self):
            events.append("close")

    job = Job()

    def create_job():
        events.append("create-job")
        return job

    def popen(*_args, **kwargs):
        events.append("popen")
        assert kwargs["creationflags"] & control.WINDOWS_CREATE_SUSPENDED
        return Process()

    monkeypatch.setattr(control, "_running_on_windows", lambda: True)
    monkeypatch.setattr(
        control._WindowsJob,
        "create",
        staticmethod(create_job),
    )
    monkeypatch.setattr(control.subprocess, "Popen", popen)
    control._shutdown_requested.clear()

    result = control._run_start_command(["start"])

    assert result == (0, False, False, True)
    assert events == [
        "create-job",
        "popen",
        "assign",
        "resume",
        "verify-empty",
        "close",
    ]


def test_windows_job_resume_verifies_thread_identity_and_suspend_count(
    monkeypatch,
):
    calls = []

    class Kernel:
        def CreateToolhelp32Snapshot(self, _flags, _pid):
            calls.append("snapshot")
            return 100

        def Thread32First(self, _snapshot, entry_pointer):
            entry = entry_pointer._obj
            entry.size = control.ctypes.sizeof(entry)
            entry.owner_process_id = 777
            entry.thread_id = 888
            return 1

        def Thread32Next(self, _snapshot, _entry_pointer):
            return 0

        def OpenThread(self, _rights, _inherit, thread_id):
            calls.append(("open-thread", thread_id))
            return 200

        def GetProcessIdOfThread(self, _thread):
            calls.append("verify-owner")
            return 777

        def ResumeThread(self, _thread):
            calls.append("resume")
            return 1

        def CloseHandle(self, handle):
            calls.append(("close", int(handle)))
            return 1

    class Process:
        pid = 777

    monkeypatch.setattr(
        control.ctypes,
        "get_last_error",
        lambda: control.WINDOWS_ERROR_NO_MORE_FILES,
        raising=False,
    )
    job = control._WindowsJob(Kernel(), 300)

    job.resume(Process())

    assert calls == [
        "snapshot",
        ("close", 100),
        ("open-thread", 888),
        "verify-owner",
        "resume",
        ("close", 200),
    ]


@pytest.mark.parametrize(
    ("owner_pid", "suspend_count", "match"),
    [
        (778, 1, "identity changed"),
        (777, 0, "unexpected thread suspend count"),
        (777, control.WINDOWS_INVALID_SUSPEND_COUNT, "ResumeThread"),
    ],
)
def test_windows_job_resume_fails_closed_on_thread_races(
    monkeypatch,
    owner_pid,
    suspend_count,
    match,
):
    class Kernel:
        def CreateToolhelp32Snapshot(self, _flags, _pid):
            return 100

        def Thread32First(self, _snapshot, entry_pointer):
            entry = entry_pointer._obj
            entry.size = control.ctypes.sizeof(entry)
            entry.owner_process_id = 777
            entry.thread_id = 888
            return 1

        def Thread32Next(self, _snapshot, _entry_pointer):
            return 0

        def OpenThread(self, _rights, _inherit, _thread_id):
            return 200

        def GetProcessIdOfThread(self, _thread):
            return owner_pid

        def ResumeThread(self, _thread):
            return suspend_count

        def CloseHandle(self, _handle):
            return 1

    class Process:
        pid = 777

    monkeypatch.setattr(
        control.ctypes,
        "get_last_error",
        lambda: control.WINDOWS_ERROR_NO_MORE_FILES,
        raising=False,
    )
    job = control._WindowsJob(Kernel(), 300)

    with pytest.raises((OSError, RuntimeError), match=match):
        job.resume(Process())


def test_windows_job_creation_configures_kill_on_close(monkeypatch):
    configured = {}
    closed = []

    class Function:
        def __init__(self, implementation):
            self.implementation = implementation
            self.argtypes = None
            self.restype = None

        def __call__(self, *args):
            return self.implementation(*args)

    class Kernel:
        def __init__(self):
            self.CreateJobObjectW = Function(lambda *_args: 100)
            self.SetInformationJobObject = Function(self.set_information)
            self.AssignProcessToJobObject = Function(lambda *_args: 1)
            self.QueryInformationJobObject = Function(lambda *_args: 1)
            self.TerminateJobObject = Function(lambda *_args: 1)
            self.CloseHandle = Function(self.close_handle)
            self.OpenProcess = Function(lambda *_args: 200)
            self.CreateToolhelp32Snapshot = Function(lambda *_args: 300)
            self.Thread32First = Function(lambda *_args: 0)
            self.Thread32Next = Function(lambda *_args: 0)
            self.OpenThread = Function(lambda *_args: 400)
            self.GetProcessIdOfThread = Function(lambda *_args: 1)
            self.ResumeThread = Function(lambda *_args: 1)

        def set_information(self, handle, info_class, pointer, size):
            configured.update(
                handle=handle.value,
                info_class=info_class,
                size=size,
                flags=pointer._obj.basic_limit_information.limit_flags,
            )
            return 1

        def close_handle(self, handle):
            closed.append(handle.value)
            return 1

    kernel = Kernel()
    monkeypatch.setattr(control, "_running_on_windows", lambda: True)
    monkeypatch.setattr(
        control.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: kernel,
        raising=False,
    )
    monkeypatch.setattr(
        control.ctypes,
        "get_last_error",
        lambda: 5,
        raising=False,
    )

    job = control._WindowsJob.create()
    job.close()

    assert configured == {
        "handle": 100,
        "info_class": 9,
        "size": control.ctypes.sizeof(
            control._WindowsJobExtendedLimitInformation
        ),
        "flags": control.WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    }
    assert closed == [100]


def test_windows_job_close_failure_keeps_handle_for_fail_closed_retry(
    monkeypatch,
):
    class Kernel:
        @staticmethod
        def CloseHandle(_handle):
            return 0

    monkeypatch.setattr(
        control.ctypes,
        "get_last_error",
        lambda: 6,
        raising=False,
    )
    job = control._WindowsJob(Kernel(), 100)

    with pytest.raises(OSError, match="CloseHandle"):
        job.close()

    assert job._handle == 100


def test_windows_assignment_failure_never_resumes_child(monkeypatch):
    events = []

    class Process:
        pid = 321
        returncode = None

        def kill(self):
            events.append("kill-suspended")
            self.returncode = 1

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return self.returncode

    class Job:
        def assign(self, _proc):
            events.append("assign")
            raise OSError("assignment failed")

        def resume(self, _proc):
            events.append("resume")

        def close(self):
            events.append("close")

    monkeypatch.setattr(control, "_running_on_windows", lambda: True)
    monkeypatch.setattr(
        control._WindowsJob,
        "create",
        staticmethod(lambda: Job()),
    )
    monkeypatch.setattr(
        control.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (events.append("popen") or Process()),
    )
    control._shutdown_requested.clear()
    control._tree_containment_failed.clear()

    with pytest.raises(RuntimeError, match="verified Windows containment"):
        control._run_start_command(["start"])

    assert events == [
        "popen",
        "assign",
        "kill-suspended",
        ("wait", control.PROCESS_KILL_TIMEOUT_SECONDS),
        "close",
    ]
    assert "resume" not in events
    assert not control._tree_containment_failed.is_set()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows APIs")
def test_windows_native_win64_structure_layouts():
    assert control.ctypes.sizeof(control.ctypes.c_void_p) == 8
    assert (
        control.ctypes.sizeof(control._WindowsJobExtendedLimitInformation)
        == 144
    )
    assert (
        control.ctypes.sizeof(control._WindowsJobBasicAccountingInformation)
        == 48
    )
    assert control.ctypes.sizeof(control._WindowsThreadEntry) == 28
    assert control._WindowsThreadEntry.owner_process_id.offset == 12


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows APIs")
def test_windows_native_job_object_lifecycle():
    control._shutdown_requested.clear()
    control._tree_containment_failed.clear()
    control._tree_termination_confirmed.clear()

    result = control._run_start_command(
        [sys.executable, "-c", "raise SystemExit(0)"]
    )

    assert result == (0, False, False, True)
    assert control._tree_termination_confirmed.is_set()
    assert not control._tree_containment_failed.is_set()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows APIs")
def test_windows_native_job_terminates_descendant_on_cancellation(
    tmp_path,
    monkeypatch,
):
    old_config = control.CONFIG
    old_active_process = control._active_process
    old_active_windows_job = control._active_windows_job
    control.CONFIG = control.ControlConfig(
        tmp_path,
        tmp_path / "runtime",
        tmp_path / "runtime" / "control-token",
    )
    control._active_process = None
    control._active_windows_job = None
    control._shutdown_requested.clear()
    control._tree_containment_failed.clear()
    control._tree_termination_confirmed.clear()
    monkeypatch.setattr(control, "PROCESS_KILL_TIMEOUT_SECONDS", 5)

    child_pid_path = tmp_path / "windows-child.pid"
    child_code = "import time; time.sleep(30)"
    parent_code = (
        "import pathlib, subprocess, sys, time; "
        f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
        "time.sleep(30)"
    )
    result = []
    worker = threading.Thread(
        target=lambda: result.append(
            control._run_start_command(
                [sys.executable, "-c", parent_code]
            )
        )
    )
    child_pid = 0
    child_handle = 0
    try:
        worker.start()
        deadline = time.monotonic() + 10
        while not child_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        assert control._process_exists(child_pid)

        kernel32 = control._load_windows_dll("kernel32")
        kernel32.OpenProcess.argtypes = [
            control.ctypes.c_ulong,
            control.ctypes.c_int,
            control.ctypes.c_ulong,
        ]
        kernel32.OpenProcess.restype = control.ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [
            control.ctypes.c_void_p,
            control.ctypes.c_ulong,
        ]
        kernel32.WaitForSingleObject.restype = control.ctypes.c_ulong
        kernel32.CloseHandle.argtypes = [control.ctypes.c_void_p]
        kernel32.CloseHandle.restype = control.ctypes.c_int
        child_handle = int(
            kernel32.OpenProcess(
                control.WINDOWS_SYNCHRONIZE
                | control.WINDOWS_PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                child_pid,
            )
        )
        assert child_handle

        control._shutdown_requested.set()
        worker.join(timeout=15)

        assert not worker.is_alive()
        assert result and result[0][2:] == (True, True)
        assert (
            kernel32.WaitForSingleObject(
                control.ctypes.c_void_p(child_handle),
                5_000,
            )
            == control.WINDOWS_WAIT_OBJECT_0
        )
        assert not control._process_exists(child_pid)
        assert control._tree_termination_confirmed.is_set()
        assert not control._tree_containment_failed.is_set()
    finally:
        control._shutdown_requested.set()
        with control._state_lock:
            active = control._active_process
            active_job = control._active_windows_job
        if active is not None:
            with contextlib.suppress(OSError, RuntimeError):
                control._terminate_process_tree(active, active_job)
        worker.join(timeout=15)
        if child_handle:
            assert kernel32.CloseHandle(
                control.ctypes.c_void_p(child_handle)
            )
        worker_stopped = not worker.is_alive()
        if worker_stopped:
            control._shutdown_requested.clear()
            control._tree_containment_failed.clear()
            control._tree_termination_confirmed.clear()
            control._active_process = old_active_process
            control._active_windows_job = old_active_windows_job
            control.CONFIG = old_config
        assert worker_stopped, "Windows containment worker did not stop safely"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows APIs")
def test_windows_native_process_probe_is_non_mutating():
    process = control.subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        assert control._process_exists(process.pid)
    finally:
        process.terminate()
        process.wait(timeout=10)

    assert not control._process_exists(process.pid)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACLs")
def test_windows_native_env_acl_is_owner_only(tmp_path):
    env_path = tmp_path / ".env"

    control._set_env_value(env_path, "TARGET", "value")

    powershell = control._windows_powershell()
    assert powershell
    child_env = os.environ.copy()
    child_env["SECAI_TEST_ACL_PATH"] = str(env_path)
    script = (
        "$acl=Get-Acl -LiteralPath $env:SECAI_TEST_ACL_PATH;"
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "$rules=@($acl.GetAccessRules($true,$true,"
        "[Security.Principal.SecurityIdentifier]));"
        "if(-not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 "
        "-or $rules[0].IdentityReference.Value -ne $sid){exit 41}"
    )
    result = control.subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        env=child_env,
        timeout=30,
    )

    assert result.returncode == 0

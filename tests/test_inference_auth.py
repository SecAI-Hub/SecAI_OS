"""Inference credentials and startup must fail closed before contacting a worker."""
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from common.inference_auth import InferenceCredentialUnavailable, inference_headers

ROOT = Path(__file__).resolve().parents[1]
PREPARER = ROOT / "files/system/usr/libexec/secure-ai/prepare-inference-auth.sh"


def write_key(directory, name, value="a" * 64, mode=0o600):
    path = directory / name
    path.write_bytes(value.encode("ascii"))
    path.chmod(mode)
    return path


def test_inference_reader_has_no_generic_token_fallback(tmp_path, monkeypatch):
    generic = write_key(tmp_path, "generic")
    monkeypatch.setenv("SERVICE_TOKEN_PATH", str(generic))
    monkeypatch.delenv("INFERENCE_TOKEN_PATH", raising=False)
    with pytest.raises(InferenceCredentialUnavailable, match="local inference credential unavailable"):
        inference_headers()


@pytest.mark.parametrize("value", ["", "a" * 63, "a" * 66, "A" * 64, "a" * 64 + "\n\n", "a" * 63 + "\x00", "a" * 64 + "\r"])
def test_inference_reader_rejects_malformed_secret(tmp_path, monkeypatch, value):
    path = write_key(tmp_path, "credential", value)
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(path))
    with pytest.raises(InferenceCredentialUnavailable) as error:
        inference_headers()
    assert str(path) not in str(error.value)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "group-readable", "group-writable"])
def test_inference_reader_rejects_unsafe_files(tmp_path, monkeypatch, kind):
    key = write_key(tmp_path, "key")
    path = key
    if kind == "symlink":
        path = tmp_path / "alias"
        path.symlink_to(key)
    elif kind == "hardlink":
        os.link(key, tmp_path / "alias")
    elif kind == "fifo":
        path = tmp_path / "fifo"
        os.mkfifo(path)
    elif kind == "directory":
        path = tmp_path
    else:
        path.chmod(0o640 if kind == "group-readable" else 0o660)
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(path))
    monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "native")
    with pytest.raises(InferenceCredentialUnavailable):
        inference_headers()


def test_inference_reader_accepts_private_file_or_readonly_sandbox_mount(tmp_path, monkeypatch):
    path = write_key(tmp_path, "key", "b" * 64 + "\n", 0o400)
    monkeypatch.setenv("INFERENCE_TOKEN_PATH", str(path))
    assert inference_headers() == {"Authorization": "Bearer " + "b" * 64}
    path.chmod(0o644)
    monkeypatch.setenv("SECURE_AI_DEPLOYMENT_MODE", "sandbox")
    with pytest.raises(InferenceCredentialUnavailable):
        inference_headers()
    monkeypatch.setattr(os, "fstatvfs", lambda descriptor: SimpleNamespace(f_flag=os.ST_RDONLY))
    assert inference_headers() == {"Authorization": "Bearer " + "b" * 64}


def preparer_environment(tmp_path):
    ui = write_key(tmp_path, "ui", "a" * 64)
    agent = write_key(tmp_path, "agent", "b" * 64 + "\n")
    probe = write_key(tmp_path, "probe", "c" * 64)
    env = dict(os.environ, INFERENCE_UI_TOKEN_PATH=str(ui), INFERENCE_AGENT_TOKEN_PATH=str(agent),
               INFERENCE_PROBE_TOKEN_PATH=str(probe), SECURE_AI_DEPLOYMENT_MODE="native")
    return ui, agent, env


def test_backend_key_file_is_private_and_contains_three_native_roles(tmp_path):
    _, _, env = preparer_environment(tmp_path)
    directory = tmp_path / "runtime"
    result = subprocess.run([str(PREPARER), str(directory)], env=env, capture_output=True, timeout=3)
    assert result.returncode == 0, result.stderr.decode()
    output = Path(result.stdout.decode().strip())
    assert output.parent == directory
    assert output.read_bytes() == b'a' * 64 + b'\n' + b'b' * 64 + b'\n' + b'c' * 64 + b'\n'
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert b'a' * 64 not in result.stdout + result.stderr
    assert b'b' * 64 not in result.stdout + result.stderr
    assert b'c' * 64 not in result.stdout + result.stderr


def test_native_probe_role_cannot_be_omitted_or_reuse_another_role(tmp_path):
    _ui, _agent, env = preparer_environment(tmp_path)
    for value in [None, env['INFERENCE_UI_TOKEN_PATH'], env['INFERENCE_AGENT_TOKEN_PATH']]:
        changed = dict(env)
        if value is None:
            changed.pop('INFERENCE_PROBE_TOKEN_PATH')
        else:
            changed['INFERENCE_PROBE_TOKEN_PATH'] = value
        result = subprocess.run([str(PREPARER), str(tmp_path/'runtime')], env=changed,
                                capture_output=True, timeout=3, check=False)
        assert result.returncode != 0 and result.stdout == b''


def test_explicit_sandbox_retains_only_its_two_backend_roles(tmp_path):
    _ui, _agent, env = preparer_environment(tmp_path)
    env['SECURE_AI_DEPLOYMENT_MODE'] = 'sandbox'
    env.pop('INFERENCE_PROBE_TOKEN_PATH')
    result = subprocess.run([str(PREPARER), str(tmp_path/'runtime')], env=env,
                            capture_output=True, timeout=3, check=False)
    assert result.returncode == 0
    assert Path(result.stdout.decode().strip()).read_bytes() == b'a'*64+b'\n'+b'b'*64+b'\n'


@pytest.mark.parametrize("mutation", ["missing", "empty", "duplicate", "symlink", "hardlink", "permissions", "extra-line", "nul", "fifo", "unsafe-output"])
def test_bad_backend_credentials_cannot_create_key_file(tmp_path, mutation):
    ui, agent, env = preparer_environment(tmp_path)
    directory = tmp_path / "runtime"
    if mutation == "missing":
        del env["INFERENCE_UI_TOKEN_PATH"]
    elif mutation == "empty":
        ui.write_bytes(b'')
    elif mutation == "duplicate":
        agent.write_bytes(ui.read_bytes())
    elif mutation == "symlink":
        ui.unlink()
        ui.symlink_to(agent)
    elif mutation == "hardlink":
        os.link(ui, tmp_path / "alias")
    elif mutation == "permissions":
        ui.chmod(0o644)
    elif mutation == "extra-line":
        ui.write_bytes(b'a' * 64 + b'\n\n')
    elif mutation == "nul":
        ui.write_bytes(b'a' * 64 + b'\x00')
    elif mutation == "fifo":
        ui.unlink()
        os.mkfifo(ui)
    elif mutation == "unsafe-output":
        directory.mkdir(mode=0o755)
    result = subprocess.run([str(PREPARER), str(directory)], env=env, capture_output=True, timeout=3)
    assert result.returncode != 0
    assert result.stdout == b''
    assert not list(directory.glob('.inference-keys.*'))


def test_container_entrypoint_passes_private_key_file_without_secret_arguments(tmp_path):
    _, _, env = preparer_environment(tmp_path)
    model = tmp_path / "model.gguf"
    model.write_bytes(b'fixture')
    recorder = tmp_path / "backend"
    output = tmp_path / "args.json"
    recorder.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["RECORDED_ARGS"]).write_text(json.dumps(sys.argv[1:]))\n')
    recorder.chmod(0o700)
    env.update(MODEL_PATH=str(model), LLAMA_SERVER_BIN=str(recorder), SECAI_INFERENCE_AUTH_HELPER=str(PREPARER), TMPDIR=str(tmp_path), RECORDED_ARGS=str(output), LLAMA_API_KEY="ambient-key-must-not-apply")
    result = subprocess.run(["sh", str(ROOT / "services/inference-worker/entrypoint.sh")], env=env, capture_output=True, timeout=3)
    assert result.returncode == 0, result.stderr.decode()
    args = json.loads(output.read_text())
    assert args.count("--api-key-file") == 1
    assert args.count("--alias") == 1
    assert args[args.index("--alias") + 1] == model.name
    assert "--no-ui" in args
    key_path = Path(args[args.index("--api-key-file") + 1])
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert not any("ambient-key" in arg or "a" * 64 in arg or "b" * 64 in arg for arg in args)


def test_container_entrypoint_rejects_multiple_alias_filename_before_credentials(tmp_path):
    model = tmp_path / "one,two.gguf"
    model.write_bytes(b"fixture")
    result = subprocess.run(
        ["sh", str(ROOT / "services/inference-worker/entrypoint.sh")],
        env=dict(os.environ, MODEL_PATH=str(model), SECAI_INFERENCE_AUTH_HELPER="/must-not-run"),
        capture_output=True, timeout=3,
    )
    assert result.returncode != 0
    assert b"invalid API alias" in result.stderr
    assert b"must-not-run" not in result.stderr

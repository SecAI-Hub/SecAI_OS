"""Native filesystem selection and the narrow systemd action contract."""

import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "files/system/usr/libexec/secure-ai/apply-inference-model.py"
spec = importlib.util.spec_from_file_location("native_inference_selection", HELPER)
control = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = control
spec.loader.exec_module(control)


def test_native_launcher_keeps_fixed_local_model_offline_without_ui(tmp_path):
    # Execute the actual shell argv construction with private helper stubs;
    # no native service, credentials, parser or model is activated.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    model = tmp_path / "reviewed model.gguf"
    key = tmp_path / "keys"
    key.write_text("synthetic credential\n")
    key.chmod(0o600)
    selector = tmp_path / "select-model"
    selector.write_text(
        "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
        f"Path(sys.argv[1]).write_text({('MODEL_PATH=' + shlex.quote(str(model)) + chr(10) + 'GPU_LAYERS=0\nCTX_SIZE=8192\nTHREADS=4\n')!r})\n"
    )
    preparer = tmp_path / "prepare-auth"
    preparer.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(str(key))}\n")
    landlock = tmp_path / "landlock"
    landlock.write_text("#!/bin/sh\n[ \"$1\" = --require ] && [ \"$2\" = inference ] && [ \"$3\" = -- ] || exit 1\nshift 3\nexec \"$@\"\n")
    recorder = tmp_path / "wrapper"
    output = tmp_path / "args.json"
    recorder.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['RECORDED_ARGS']).write_text(json.dumps(sys.argv[1:]))\n")
    for path in (selector, preparer, landlock, recorder):
        path.chmod(0o700)
    launcher = (ROOT / "files/system/usr/libexec/secure-ai/start-inference.sh").read_text()
    for original, replacement in (("select-model.sh", selector), ("prepare-inference-auth.sh", preparer), ("landlock-apply.py", landlock), ("inference-wrapper.sh", recorder)):
        launcher = launcher.replace("/usr/libexec/secure-ai/" + original, shlex.quote(str(replacement)))
    result = subprocess.run(["bash", "-c", launcher], env=dict(os.environ, RUNTIME_DIRECTORY=str(runtime), RECORDED_ARGS=str(output)), capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr.decode()
    args = json.loads(output.read_text())
    assert args.count("--offline") == args.count("--no-ui") == 1
    assert args[args.index("--model") + 1] == str(model)
    assert args[args.index("--alias") + 1] == model.name
    assert args[args.index("--api-key-file") + 1] == str(key)
    assert args[args.index("--host") + 1] == "127.0.0.1"
    assert not any(arg.startswith(("--hf-", "--model-url")) for arg in args)
    unit = (ROOT / "files/system/usr/lib/systemd/system/secure-ai-inference.service").read_text()
    assert "IPAddressDeny=any" in unit and "IPAddressAllow=localhost" in unit


@pytest.fixture
def state(tmp_path, monkeypatch):
    # Use real file metadata/FDs under the test user's UID; production remains UID0.
    monkeypatch.setattr(control, "ROOT_UID", os.getuid())
    for name, mode in [
        ("requests", 0o730),
        ("control", 0o2750),
        ("control/processing", 0o700),
        ("selection", 0o2750),
        ("models", 0o750),
    ]:
        path = tmp_path / name
        path.mkdir()
        path.chmod(mode)
    models = []
    for name in ["a.gguf", "b.gguf"]:
        path = tmp_path / "models" / name
        path.write_bytes(b"GGUF\x03\0\0\0" + name.encode())
        models.append(
            {
                "filename": name,
                "format": "gguf",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "models": models}))
    manifest.chmod(0o644)  # Match registry.saveManifest's explicit production mode.
    return control.Paths(
        requests=tmp_path / "requests",
        control=tmp_path / "control",
        selection=tmp_path / "selection/selection.json",
        manifest=manifest,
        models=tmp_path / "models",
    )


def publish(state, filename="b.gguf", **extra):
    request = {
        "version": 1,
        "request_id": "a" * 32,
        "model_filename": filename,
        **extra,
    }
    path = state.requests / "inference-model-request"
    path.write_text(json.dumps(request))
    path.chmod(0o640)
    return request


def selected(state, name="b.gguf"):
    digest = hashlib.sha256((state.models / name).read_bytes()).hexdigest()
    state.selection.write_text(
        json.dumps(
            {
                "version": 1,
                "request_id": "a" * 32,
                "model_filename": name,
                "sha256": digest,
            }
        )
    )
    state.selection.chmod(0o640)


def test_explicit_cpu_assurance_overrides_detected_gpu(tmp_path, monkeypatch):
    monkeypatch.setattr(control, "ROOT_UID", os.getuid())
    path = tmp_path / "attestation.yaml"
    path.write_text("version: 1\ngpu: {mode: no_gpu}\n")
    path.chmod(0o600)
    assert control.gpu_layers(path, "-1") == "0"


@pytest.mark.parametrize("backend,requested,accepted", [
    ("cuda", "-1", True), ("vulkan", "-1", True),
    ("cpu", "-1", False), ("cuda", "0", False),
    ("vulkan", "0", False), ("unknown", "-1", False),
])
def test_required_gpu_refuses_cpu_launch_or_build(tmp_path, monkeypatch, backend, requested, accepted):
    monkeypatch.setattr(control, "ROOT_UID", os.getuid())
    policy = tmp_path / "attestation.yaml"
    policy.write_text("version: 1\ngpu: {mode: required, bootstrap: {}, runtime: {}}\n")
    policy.chmod(0o600)
    metadata = tmp_path / "gpu-backend.json"
    metadata.write_text(json.dumps({"backend": backend}))
    metadata.chmod(0o644)
    if accepted:
        assert control.gpu_layers(policy, requested, build_metadata=metadata) == "-1"
    else:
        with pytest.raises(control.SelectionError):
            control.gpu_layers(policy, requested, build_metadata=metadata)


@pytest.mark.parametrize("metadata_case", ["missing", "symlink", "writable", "duplicate", "invalid", "wrong_type"])
def test_required_gpu_cannot_use_unsafe_build_metadata(tmp_path, monkeypatch, metadata_case):
    monkeypatch.setattr(control, "ROOT_UID", os.getuid())
    policy = tmp_path / "attestation.yaml"
    policy.write_text("version: 1\ngpu: {mode: required, bootstrap: {}, runtime: {}}\n")
    policy.chmod(0o600)
    metadata = tmp_path / "gpu-backend.json"
    if metadata_case != "missing":
        metadata.write_text('{"backend":"cuda"}')
        metadata.chmod(0o644)
    if metadata_case == "symlink":
        target = tmp_path / "target.json"
        metadata.rename(target)
        metadata.symlink_to(target)
    elif metadata_case == "writable":
        metadata.chmod(0o666)
    elif metadata_case == "duplicate":
        metadata.write_text('{"backend":"cpu","backend":"cuda"}')
    elif metadata_case == "invalid":
        metadata.write_text('invalid')
    elif metadata_case == "wrong_type":
        metadata.write_text('{"backend":[]}')
    with pytest.raises((OSError, control.SelectionError)):
        control.gpu_layers(policy, "-1", build_metadata=metadata)


def test_inference_cli_ignores_unapproved_policy_environment(monkeypatch, capsys):
    monkeypatch.setenv("ATTESTATION_POLICY_PATH", "/unapproved/policy.yaml")
    monkeypatch.setattr(sys, "argv", [str(HELPER), "gpu-layers", "-1"])
    paths = []
    monkeypatch.setattr(
        control, "gpu_layers", lambda path, requested: paths.append(path) or "0"
    )
    assert control.main() == 0
    assert paths == [Path("/etc/secure-ai/policy/attestation.yaml")]
    assert capsys.readouterr().out == "0\n"


@pytest.mark.parametrize(
    "value",
    [
        "version: 1\n",
        "version: 1\ngpu: {mode: auto}\n",
        "version: 1\ngpu: {mode: no_gpu, runtime: {}}\n",
        "version: 1\ngpu: {mode: required}\n",
        "version: 1\ngpu: {mode: no_gpu, mode: required}\n",
    ],
)
def test_gpu_execution_policy_cannot_infer_enrollment(tmp_path, monkeypatch, value):
    monkeypatch.setattr(control, "ROOT_UID", os.getuid())
    path = tmp_path / "attestation.yaml"
    path.write_text(value)
    path.chmod(0o600)
    with pytest.raises(control.SelectionError):
        control.gpu_layers(path, "-1")


def test_no_selection_preserves_first_valid(state):
    assert control.resolve_model(state).name == "a.gguf"


def test_native_handoff_selects_b_and_exact_service_actions(state):
    publish(state)
    actions = []
    assert control.apply_request(state, lambda action: actions.append(action) or True)
    assert actions == ["restart", "is-active"]
    assert control.resolve_model(state).name == "b.gguf"
    result = json.loads((state.control / "result.json").read_text())
    assert result["status"] == "succeeded" and result["request_id"] == "a" * 32
    assert result["model_filename"] == "b.gguf"
    assert "alias" in result["detail"]
    assert state.selection.stat().st_uid == os.getuid()
    assert state.selection.stat().st_mode & 0o777 == 0o640
    assert not (state.requests / "inference-model-request").exists()
    assert not list((state.control / "processing").iterdir())


@pytest.mark.parametrize(
    "failure", ["missing", "bytes", "manifest_hash", "blocked", "duplicate", "symlink"]
)
def test_explicit_selection_never_falls_back_to_a(state, failure):
    selected(state)
    if failure == "missing":
        (state.models / "b.gguf").unlink()
    elif failure == "bytes":
        (state.models / "b.gguf").write_bytes(b"tampered")
    elif failure == "symlink":
        (state.models / "b.gguf").unlink()
        (state.models / "b.gguf").symlink_to(state.models / "a.gguf")
    else:
        data = json.loads(state.manifest.read_text())
        if failure == "manifest_hash":
            data["models"][1]["sha256"] = "0" * 64
        elif failure == "blocked":
            data["models"][1]["blocked"] = True
        else:
            data["models"].append(data["models"][1])
        state.manifest.write_text(json.dumps(data))
    with pytest.raises((control.SelectionError, OSError)):
        control.resolve_model(state)


@pytest.mark.parametrize(
    "failure", ["invalid_json", "writable", "wrong_owner", "symlink"]
)
def test_tampered_selection_fails_closed(state, failure, monkeypatch):
    selected(state)
    if failure == "invalid_json":
        state.selection.write_text('{"version":true}')
    elif failure == "writable":
        state.selection.chmod(0o660)
    elif failure == "wrong_owner":
        monkeypatch.setattr(control, "ROOT_UID", os.getuid() + 1)
    else:
        state.selection.unlink()
        state.selection.symlink_to(state.selection.parent / "absent.json")
    with pytest.raises((control.SelectionError, OSError)):
        control.resolve_model(state)


@pytest.mark.parametrize(
    "payload_change",
    [
        {"version": True},
        {"version": 2},
        {"unit": "sshd.service"},
        {"request_id": "bad"},
        {"model_filename": "../b.gguf"},
        {"model_filename": "a,b.gguf"},
        {"model_filename": "model.safetensors"},
    ],
)
def test_invalid_request_has_no_selection_or_service_side_effect(state, payload_change):
    publish(state, **payload_change)
    actions = []
    assert not control.apply_request(
        state, lambda action: actions.append(action) or True
    )
    assert actions == [] and not state.selection.exists()


def test_unknown_model_keeps_previous_selection_and_reports_failed(state):
    selected(state, "a.gguf")
    before = state.selection.read_bytes()
    publish(state, "unknown.gguf")
    actions = []
    assert not control.apply_request(
        state, lambda action: actions.append(action) or True
    )
    assert not actions and state.selection.read_bytes() == before
    assert json.loads((state.control / "result.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversized", "duplicate_json"])
def test_untrusted_request_objects_are_rejected(state, kind):
    path = state.requests / "inference-model-request"
    if kind == "symlink":
        path.symlink_to(state.manifest)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "oversized":
        path.write_bytes(b"x" * 4097)
        path.chmod(0o640)
    else:
        path.write_text(
            '{"version":1,"version":1,"request_id":"'
            + "a" * 32
            + '","model_filename":"b.gguf"}'
        )
        path.chmod(0o640)
    actions = []
    assert not control.apply_request(
        state, lambda action: actions.append(action) or True
    )
    assert not actions and not state.selection.exists()


@pytest.mark.parametrize("failure", ["restart", "is-active", "stop"])
def test_restart_failure_retains_b_and_truthful_failed_status(state, failure):
    publish(state)
    actions = []

    def action(value):
        actions.append(value)
        return value not in ({"restart", "stop"} if failure == "stop" else {failure})

    assert not control.apply_request(state, action)
    assert actions[-1] == "stop"
    assert control.resolve_model(state).name == "b.gguf"
    result = json.loads((state.control / "result.json").read_text())
    assert result["status"] == "failed"
    assert ("could not be confirmed" in result["detail"]) == (failure == "stop")


def test_systemctl_has_no_arbitrary_command_unit_or_shell(monkeypatch):
    calls = []
    monkeypatch.setattr(
        control.subprocess,
        "run",
        lambda argv, **kw: calls.append((argv, kw)) or SimpleNamespace(returncode=0),
    )
    assert control.systemctl("restart")
    assert calls[0][0] == [
        "/usr/bin/systemctl",
        "--no-pager",
        "--quiet",
        "restart",
        "secure-ai-inference.service",
    ]
    assert calls[0][1].get("shell", False) is False
    with pytest.raises(control.SelectionError):
        control.systemctl("restart sshd.service")
    assert len(calls) == 1


def test_systemctl_timeout_is_reported_failure(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 125)

    monkeypatch.setattr(control.subprocess, "run", timeout)
    assert control.systemctl("restart") is False


def test_existing_serialization_keeps_next_request_queued(state):
    publish(state)
    path = state.control / "control.lock"
    with path.open("w") as held:
        path.chmod(0o600)
        control.fcntl.flock(held, control.fcntl.LOCK_EX)
        assert not control.apply_request(
            state, lambda _action: pytest.fail("must not call systemctl")
        )
        assert (state.requests / "inference-model-request").exists()


def test_image_wires_path_broker_and_selector():
    units = ROOT / "files/system/usr/lib/systemd/system"
    unit = (units / "secure-ai-inference-model.service").read_text()
    assert (
        "CapabilityBoundingSet=\n" in unit
        and "RestrictAddressFamilies=AF_UNIX\n" in unit
    )
    assert (
        "PathExists=/run/secure-ai-ui/inference-model-request"
        in (units / "secure-ai-inference-model.path").read_text()
    )
    assert (
        "- secure-ai-inference-model.path" in (ROOT / "recipes/recipe.yml").read_text()
    )
    selector = (ROOT / "files/system/usr/libexec/secure-ai/select-model.sh").read_text()
    assert 'apply-inference-model.py" resolve' in selector

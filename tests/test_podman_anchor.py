import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "sandbox" / "podman_anchor.py"
)
SPEC = importlib.util.spec_from_file_location("secai_podman_anchor", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
anchor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = anchor
SPEC.loader.exec_module(anchor)


def _anchor_payload(
    state: anchor.AnchorState,
    *,
    running: bool = True,
) -> dict:
    command = [
        "sh",
        "-c",
        'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done',
    ]
    return {
        "Id": state.container_id,
        "Name": anchor.ANCHOR_NAME,
        "ImageDigest": anchor.PINNED_ALPINE_IMAGE.rsplit("@", 1)[1],
        "Path": "sh",
        "Args": command[1:],
        "EffectiveCaps": None,
        "BoundingCaps": None,
        "Mounts": [],
        "Config": {
            "Labels": {
                anchor.ROLE_LABEL: anchor.ANCHOR_ROLE,
                anchor.PROJECT_LABEL: anchor.PROJECT_NAME,
                anchor.LAUNCH_LABEL: state.launch_id,
            },
            "User": "65534:65534",
            "Cmd": command,
            "Volumes": None,
        },
        "HostConfig": {
            "Binds": [],
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapAdd": [],
            "CapDrop": sorted(anchor.DEFAULT_CAPABILITIES),
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": 16,
            "Memory": 33_554_432,
            "MemorySwap": 33_554_432,
            "NanoCpus": 100_000_000,
            "IpcMode": "private",
            "PidMode": "private",
            "UTSMode": "private",
            "AutoRemove": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "PortBindings": {},
            "PublishAllPorts": False,
            "ExtraHosts": [],
            "Devices": [],
        },
        "NetworkSettings": {"Networks": {anchor.NETWORK_NAME: {}}},
        "State": {
            "Status": "running" if running else "exited",
            "Running": running,
        },
    }


def _mock_prepare_prerequisites(monkeypatch):
    monkeypatch.setattr(anchor, "_validate_local_podman", lambda _podman: None)
    monkeypatch.setattr(
        anchor,
        "_ensure_network",
        lambda _podman: ("10.89.0.1", "podman9", "10.89.0.0/24"),
    )
    monkeypatch.setattr(anchor, "_wait_for_gateway", lambda *_args: None)


def test_anchor_hardening_rejects_forged_capability_drop():
    state = anchor.AnchorState("a" * 64, "b" * 64)
    payload = _anchor_payload(state)
    anchor._validate_anchor(payload, state, require_running=True)

    forged = copy.deepcopy(payload)
    forged["HostConfig"]["CapDrop"] = [f"CAP_FAKE_{index}" for index in range(11)]
    with pytest.raises(anchor.AnchorError, match="hardening"):
        anchor._validate_anchor(forged, state, require_running=True)


def test_prepare_replaces_a_verified_stopped_recorded_anchor(
    monkeypatch,
    tmp_path,
):
    _mock_prepare_prerequisites(monkeypatch)
    old_state = anchor.AnchorState("a" * 64, "b" * 64)
    new_state = anchor.AnchorState("c" * 64, "d" * 64)
    removed = []
    written = []
    monkeypatch.setattr(anchor.secrets, "token_hex", lambda _length: "d" * 64)
    monkeypatch.setattr(anchor, "_load_state", lambda _runtime: old_state)
    monkeypatch.setattr(
        anchor,
        "_container_payload",
        lambda _podman, container_id: (
            _anchor_payload(old_state, running=False)
            if container_id == old_state.container_id
            else (
                _anchor_payload(new_state)
                if container_id == new_state.container_id
                else None
            )
        ),
    )
    monkeypatch.setattr(
        anchor,
        "_remove_verified",
        lambda _podman, _runtime, state: removed.append(state),
    )
    monkeypatch.setattr(
        anchor,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            f"{new_state.container_id}\n",
            "",
        ),
    )
    monkeypatch.setattr(
        anchor,
        "_write_state",
        lambda _runtime, state: written.append(state),
    )

    gateway, state, created = anchor.prepare(
        "podman",
        tmp_path,
        anchor.PINNED_ALPINE_IMAGE,
    )

    assert (gateway, state, created) == ("10.89.0.1", new_state, True)
    assert removed == [old_state]
    assert written == [new_state]


def test_prepare_cleans_this_launch_when_hardening_validation_fails(
    monkeypatch,
    tmp_path,
):
    _mock_prepare_prerequisites(monkeypatch)
    new_state = anchor.AnchorState("c" * 64, "d" * 64)
    unsafe_payload = _anchor_payload(new_state)
    unsafe_payload["HostConfig"]["ReadonlyRootfs"] = False
    cleaned = []
    monkeypatch.setattr(anchor.secrets, "token_hex", lambda _length: "d" * 64)
    monkeypatch.setattr(anchor, "_load_state", lambda _runtime: None)
    monkeypatch.setattr(
        anchor,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            f"{new_state.container_id}\n",
            "",
        ),
    )
    monkeypatch.setattr(
        anchor,
        "_container_payload",
        lambda _podman, container_id: (
            unsafe_payload if container_id == new_state.container_id else None
        ),
    )
    monkeypatch.setattr(
        anchor,
        "_remove_new_anchor",
        lambda *args: cleaned.append(args[-2:]),
    )

    with pytest.raises(anchor.AnchorError, match="hardening"):
        anchor.prepare("podman", tmp_path, anchor.PINNED_ALPINE_IMAGE)

    assert cleaned == [(new_state.launch_id, new_state.container_id)]


def test_prepare_recovers_only_an_exact_hardened_unrecorded_anchor(
    monkeypatch,
    tmp_path,
):
    _mock_prepare_prerequisites(monkeypatch)
    orphan_state = anchor.AnchorState("a" * 64, "b" * 64)
    new_state = anchor.AnchorState("c" * 64, "d" * 64)
    orphan_payload = _anchor_payload(orphan_state)
    current_orphan = [copy.deepcopy(orphan_payload)]
    removed = []
    written = []

    def container_payload(_podman, container_id):
        if container_id == anchor.ANCHOR_NAME:
            return current_orphan[0]
        if container_id == new_state.container_id:
            return _anchor_payload(new_state)
        return None

    def remove_new(_podman, _runtime, launch_id, container_id):
        removed.append((launch_id, container_id))
        current_orphan[0] = None

    monkeypatch.setattr(anchor.secrets, "token_hex", lambda _length: "d" * 64)
    monkeypatch.setattr(anchor, "_load_state", lambda _runtime: None)
    monkeypatch.setattr(anchor, "_container_payload", container_payload)
    monkeypatch.setattr(anchor, "_remove_new_anchor", remove_new)
    monkeypatch.setattr(
        anchor,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            f"{new_state.container_id}\n",
            "",
        ),
    )
    monkeypatch.setattr(
        anchor,
        "_write_state",
        lambda _runtime, state: written.append(state),
    )

    current_orphan[0]["ImageDigest"] = "sha256:" + ("0" * 64)
    with pytest.raises(anchor.AnchorError, match="hardening"):
        anchor.prepare("podman", tmp_path, anchor.PINNED_ALPINE_IMAGE)
    assert removed == []

    current_orphan[0] = orphan_payload
    assert anchor.prepare(
        "podman",
        tmp_path,
        anchor.PINNED_ALPINE_IMAGE,
    ) == ("10.89.0.1", new_state, True)
    assert removed == [(orphan_state.launch_id, orphan_state.container_id)]
    assert written == [new_state]


def test_anchor_state_requires_owner_only_permissions(tmp_path):
    tmp_path.chmod(0o700)
    state_path = tmp_path / anchor.STATE_FILENAME
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "container_id": "a" * 64,
                "launch_id": "b" * 64,
            }
        ),
        encoding="ascii",
    )
    state_path.chmod(0o644)
    with pytest.raises(anchor.AnchorError, match="permissions"):
        anchor._load_state(tmp_path)

    state_path.chmod(0o600)
    assert anchor._load_state(tmp_path) == anchor.AnchorState("a" * 64, "b" * 64)

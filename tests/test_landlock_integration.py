"""Regression tests for production-effective Landlock service wiring."""

from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).parent.parent
SYSTEMD = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
POLICY_PATH = (
    REPO_ROOT
    / "files"
    / "system"
    / "etc"
    / "secure-ai"
    / "policy"
    / "landlock.yaml"
)
GPU_PROFILE = (
    REPO_ROOT
    / "services"
    / "gpu-integrity-watch"
    / "profiles"
    / "default-profile.yaml"
)
DIFFUSION_INSTALLER = (
    REPO_ROOT / "files" / "scripts" / "secai-enable-diffusion.sh"
)


def _unit(name: str) -> str:
    return (SYSTEMD / f"secure-ai-{name}.service").read_text(encoding="utf-8")


def _policy_paths(service: str) -> dict[str, str]:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    return {
        entry["path"]: entry["access"]
        for entry in policy["services"][service]["paths"]
    }


def test_long_lived_security_services_inherit_landlock():
    expected = {
        "runtime-attestor": "runtime_attestor",
        "gpu-integrity-watch": "gpu_integrity_watch",
        "search-mediator": "search_mediator",
    }
    for unit_name, policy_name in expected.items():
        content = _unit(unit_name)
        assert (
            f"ExecStart=/usr/libexec/secure-ai/landlock-apply.py --require "
            f"{policy_name} -- "
        ) in content

    inference = (
        REPO_ROOT
        / "files"
        / "system"
        / "usr"
        / "libexec"
        / "secure-ai"
        / "start-inference.sh"
    ).read_text(encoding="utf-8")
    assert (
        "exec /usr/libexec/secure-ai/landlock-apply.py --require inference --"
        in inference
    )


def test_release_baseline_and_tpm_paths_are_inside_attestation_boundaries():
    integrity_paths = _policy_paths("integrity_monitor")
    runtime_paths = _policy_paths("runtime_attestor")

    assert integrity_paths["/usr/share/secure-ai/integrity"] == "ro"
    assert runtime_paths["/usr/share/secure-ai/integrity"] == "ro"
    assert runtime_paths["/dev/tpmrm0"] == "rw"
    assert runtime_paths["/dev/tpm0"] == "rw"


def test_quarantine_scanner_runtimes_are_executable_after_restrict_self():
    paths = _policy_paths("quarantine")
    assert paths["/opt/secure-ai/scanners"] == "exe"
    assert paths["/usr/local/bin"] == "exe"
    assert paths["/usr/bin/env"] == "exe"


def test_airlock_can_use_fedora_trust_store_and_resolver():
    paths = _policy_paths("airlock")
    for path in (
        "/etc/pki",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
    ):
        assert paths[path] == "ro"


def test_gpu_daemon_unit_and_profile_use_one_consistent_contract():
    unit = _unit("gpu-integrity-watch")
    profile = yaml.safe_load(GPU_PROFILE.read_text(encoding="utf-8"))

    assert "/gpu-integrity-watch daemon" in unit
    assert (
        "Environment=INTEGRITY_PROFILE="
        "/etc/secure-ai/gpu-integrity/default-profile.yaml"
    ) in unit
    assert (
        "Environment=AUDIT_LOG="
        "/var/lib/secure-ai/logs/gpu-integrity-audit.jsonl"
    ) in unit
    assert "Environment=PROFILE_PATH=" not in unit
    assert "Environment=AUDIT_LOG_PATH=" not in unit

    assert profile["model_dir"] == "/var/lib/secure-ai/vault/models"
    assert profile["inference_url"] == "http://127.0.0.1:8465"
    assert (
        profile["baseline_file"]
        == "/var/lib/secure-ai/gpu-integrity/baseline.yaml"
    )
    assert profile["daemon"]["bind_addr"] == "127.0.0.1:8495"
    assert all(action["type"] != "quarantine" for action in profile["actions"])


def test_diffusion_override_confines_worker_and_uses_systemd_env_syntax():
    installer = DIFFUSION_INSTALLER.read_text(encoding="utf-8")
    assert (
        "ExecStart=/usr/libexec/secure-ai/landlock-apply.py "
        "--require diffusion -- ${VENV_DIR}/bin/gunicorn"
    ) in installer
    assert "--bind \\${BIND_ADDR}" in installer
    assert "BIND_ADDR:-" not in installer

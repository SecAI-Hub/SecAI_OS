"""Regression tests for production-effective Landlock service wiring."""

from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).parent.parent
SYSTEMD = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
POLICY_PATH = (
    REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "policy" / "landlock.yaml"
)
GPU_PROFILE = (
    REPO_ROOT / "services" / "gpu-integrity-watch" / "profiles" / "default-profile.yaml"
)
DIFFUSION_INSTALLER = REPO_ROOT / "files" / "scripts" / "secai-enable-diffusion.sh"


def _unit(name: str) -> str:
    return (SYSTEMD / f"secure-ai-{name}.service").read_text(encoding="utf-8")


def _policy_paths(service: str) -> dict[str, str]:
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    return {
        entry["path"]: entry["access"] for entry in policy["services"][service]["paths"]
    }


def test_long_lived_security_services_inherit_landlock():
    expected = {
        "runtime-attestor": "runtime_attestor",
        "gpu-integrity-watch": "gpu_integrity_watch",
        "search-mediator": "search_mediator",
        "ui": "ui",
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
    runtime = "/usr/lib/secure-ai/python3.12-venv"
    policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    for service in ("registry", "quarantine", "quarantine_scanner"):
        entries = {
            entry["path"]: entry for entry in policy["services"][service]["paths"]
        }
        guard = entries["/usr/bin/gguf-guard"]
        assert guard["access"] == "exe"
        assert guard["required"] is True
        assert "/usr/local/bin" not in entries

    for service in ("quarantine", "quarantine_scanner"):
        paths = _policy_paths(service)
        assert paths[runtime] == "exe"
        assert paths["/usr/bin/env"] == "exe"
        assert "/opt/secure-ai/scanners" not in paths
        assert "/usr/bin/python3" not in paths


def test_wsgi_policies_execute_only_the_locked_application_runtime():
    runtime = "/usr/lib/secure-ai/python3.12-venv"
    for service in ("ui", "search_mediator"):
        paths = _policy_paths(service)
        assert paths[runtime] == "exe"
        assert "/usr/bin/python3" not in paths
        assert "/usr/bin/gunicorn" not in paths
        assert "/usr/local/bin/gunicorn" not in paths

    ui_paths = _policy_paths("ui")
    assert ui_paths["/var/lib/secure-ai/ui"] == "rw"
    assert ui_paths["/var/lib/secure-ai/import-staging"] == "ro"
    assert ui_paths["/run/secure-ai-ui"] == "rw"


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
        "Environment=AUDIT_LOG=/var/lib/secure-ai/logs/gpu-integrity-audit.jsonl"
    ) in unit
    assert "Environment=PROFILE_PATH=" not in unit
    assert "Environment=AUDIT_LOG_PATH=" not in unit

    assert profile["model_dir"] == "/var/lib/secure-ai/vault/models"
    assert profile["inference_url"] == "http://127.0.0.1:8465"
    assert profile["baseline_file"] == "/var/lib/secure-ai/gpu-integrity/baseline.yaml"
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

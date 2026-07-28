import importlib.util
import os
import re
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.yaml"
NVIDIA_GPU_COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.gpu.nvidia.yaml"
ROCM_GPU_COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.gpu.rocm.yaml"
DOC_PATH = REPO_ROOT / "docs" / "install" / "sandbox.md"
PINNED_ALPINE_HELPER = "docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
VULNERABLE_CVE_2026_45447_BASE_DIGESTS = {
    "5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11",
    "dd4d2bd5b53d9b25a51da13addf2be586beebd5387e289e798e4083d94ca837a",
    "0cff4df29a6597173dc8b813787318150141eb96ac783dc3ff4f5ff52c49a1e2",
    "af366da38c839436746f79c3e52bba671a756d43e2980ecbf37ecf35348faba9",
    "2c0fbbac86b72ebb4bfee15b64d8cd5fd6b49dfe7bb279b5c9f193198a84c1c9",
}


def _load_runtime_renderer():
    module_path = REPO_ROOT / "scripts" / "sandbox" / "render_runtime.py"
    spec = importlib.util.spec_from_file_location(
        "secai_render_runtime_under_test",
        module_path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_control_token_provisioner():
    module_path = (
        REPO_ROOT / "scripts" / "sandbox" / "provision_control_token.py"
    )
    spec = importlib.util.spec_from_file_location(
        "secai_control_token_under_test",
        module_path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_generation_status_helper():
    module_path = (
        REPO_ROOT / "scripts" / "sandbox" / "generation_status.py"
    )
    spec = importlib.util.spec_from_file_location(
        "secai_generation_status_under_test",
        module_path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create_sandbox_runtime(tmp_path: Path) -> Path:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    runtime_dir.chmod(0o700)
    return runtime_dir


def _render_sandbox_runtime(
    runtime_dir: Path,
    *flags: str,
) -> tuple[str, Path]:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "sandbox" / "render_runtime.py"),
            "--repo-root",
            str(REPO_ROOT),
            "--runtime-dir",
            str(runtime_dir),
            *flags,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    generation = result.stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{64}", generation)
    assert (runtime_dir / "active-generation").read_text(
        encoding="ascii"
    ) == generation
    generation_dir = runtime_dir / "generations" / generation
    assert generation_dir.is_dir()
    return generation, generation_dir


def test_sandbox_compose_defines_core_services():
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    services = data["services"]

    for name in [
        "ui",
        "registry",
        "policy-engine",
        "tool-firewall",
        "airlock",
        "quarantine",
        "search-mediator",
        "agent",
        "ui-ingress",
        "tor",
        "searxng",
    ]:
        assert name in services

    ui_env = services["ui"]["environment"]
    assert ui_env["SECURE_AI_DEPLOYMENT_MODE"] == "sandbox"
    assert ui_env["SECURE_AI_ASSURANCE_TIER"] == "evaluation"
    assert ui_env["AGENT_SOCKET"] == "/run/secure-ai/agent.sock"
    assert ui_env["GUNICORN_WORKERS"] == 1
    assert ui_env["SECURE_AI_TMPDIR"] == "/var/lib/secure-ai/import-staging/.tmp"
    assert ui_env["FLASK_SECRET_KEY_PATH"] == "/run/secrets/ui-flask.token"
    assert (
        "./runtime/credentials/ui-flask.token:/run/secrets/ui-flask.token:ro,z"
        in services["ui"]["volumes"]
    )
    assert (
        "./runtime/generations/${SECAI_RUNTIME_GENERATION:?required}/"
        "profile.json:/var/lib/secure-ai/state/profile.json:ro,z"
        in services["ui"]["volumes"]
    )
    assert (
        "./runtime/generations/${SECAI_RUNTIME_GENERATION:?required}/"
        "generation.json:/var/lib/secure-ai/state/generation.json:ro,z"
        in services["ui"]["volumes"]
    )
    assert (
        "./runtime/generation-status:"
        "/run/secure-ai-generation-status:ro,z"
        in services["ui"]["volumes"]
    )
    assert not any(
        volume
        == (
            "./runtime/generations/"
            "${SECAI_RUNTIME_GENERATION:?required}:"
            "/run/secure-ai-runtime-generation:ro,z"
        )
        for volume in services["ui"]["volumes"]
    )
    assert (
        services["ui"]["environment"]["SECAI_RUNTIME_GENERATION"]
        == "${SECAI_RUNTIME_GENERATION:?required}"
    )
    assert services["ui"]["environment"]["SANDBOX_READY_GENERATION_PATH"].endswith(
        "/ready-generation"
    )
    assert services["ui"]["environment"]["SANDBOX_READY_SESSION_PATH"].endswith(
        "/ready-session"
    )

    assert services["agent"]["environment"]["BIND_ADDR"] == "unix:/run/secure-ai/agent.sock"
    assert "secai-run:/run/secure-ai" in services["agent"]["volumes"]
    assert "secai-run:/run/secure-ai" in services["ui"]["volumes"]
    assert "/run/secure-ai-ui:rw,noexec,nosuid,nodev,mode=0770,uid=65534,gid=65534,size=16m" in services["ui"]["tmpfs"]

    for name in [
        "ui",
        "ui-ingress",
        "agent",
        "search-mediator",
        "registry",
        "tool-firewall",
        "airlock",
    ]:
        service = services[name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert "healthcheck" in service
    assert services["ui"]["healthcheck"]["test"][0] == "CMD"
    assert services["agent"]["healthcheck"]["test"][0] == "CMD"
    assert services["search-mediator"]["healthcheck"]["test"][0] == "CMD"
    assert services["search-mediator"]["environment"]["GUNICORN_WORKERS"] == 1

    assert services["ui"]["depends_on"]["agent"]["condition"] == "service_healthy"
    assert services["ui"]["depends_on"]["search-mediator"]["condition"] == "service_healthy"
    assert services["ui-ingress"]["depends_on"]["ui"]["condition"] == "service_healthy"
    assert services["agent"]["depends_on"]["registry"]["condition"] == "service_healthy"
    assert services["tor"]["profiles"] == ["search"]
    assert services["searxng"]["profiles"] == ["search"]
    assert services["searxng"]["depends_on"]["tor"]["condition"] == "service_healthy"
    assert (
        "./runtime/generations/${SECAI_RUNTIME_GENERATION:?required}/policy:"
        "/etc/secure-ai/policy:ro,z"
        in services["registry"]["volumes"]
    )
    assert (
        "./runtime/generations/${SECAI_RUNTIME_GENERATION:?required}/config:"
        "/etc/secure-ai/config:ro,z"
        in services["ui"]["volumes"]
    )
    assert services["search-mediator"]["networks"] == ["default", "search"]

    host_bind_mounts = [
        volume
        for service in services.values()
        for volume in service.get("volumes", [])
        if isinstance(volume, str) and volume.startswith("./")
    ]
    assert host_bind_mounts
    assert all(volume.endswith(":ro,z") for volume in host_bind_mounts)

    assert "secai-run" in data["volumes"]
    assert data["networks"]["default"]["internal"] is True
    assert data["networks"]["ui-link"]["internal"] is True
    assert data["networks"]["search"]["internal"] is True
    assert data["networks"]["ingress"] == {}


def test_sandbox_loopback_ingress_is_credentialless_and_network_scoped(tmp_path):
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    services = data["services"]
    ui = services["ui"]
    ingress = services["ui-ingress"]

    assert "ports" not in ui
    assert ui["expose"] == ["8480"]
    assert ui["networks"] == ["default", "ui-link"]
    assert "extra_hosts" not in ui
    assert ui["environment"]["SANDBOX_CONTROL_URL"] == "http://ui-ingress:8498"

    assert ingress["build"] == {
        "context": "../../services/ui-ingress",
        "dockerfile": "Dockerfile",
    }
    assert ingress["user"] == "65534:65534"
    assert ingress["pids_limit"] == 64
    assert ingress["mem_limit"] == "64m"
    assert ingress["cpus"] == "0.50"
    assert ingress["tmpfs"] == []
    assert ingress["networks"] == ["ui-link", "ingress"]
    assert ingress["extra_hosts"] == [
        "host.docker.internal:${SECAI_CONTROL_HOST_GATEWAY:-host-gateway}"
    ]
    assert ingress["ports"] == [
        "127.0.0.1:${SECAI_UI_PORT:-8480}:8480"
    ]
    assert ingress["expose"] == ["8498"]
    assert ingress["healthcheck"]["test"] == [
        "CMD",
        "/ui-ingress",
        "healthcheck",
    ]
    assert "environment" not in ingress
    assert "volumes" not in ingress

    services_with_host_ports = {
        name for name, service in services.items() if service.get("ports")
    }
    assert services_with_host_ports == {"ui-ingress"}

    source = (REPO_ROOT / "services" / "ui-ingress" / "main.go").read_text(
        encoding="utf-8"
    )
    assert 'uiUpstreamAddress    = "ui:8480"' in source
    assert 'controlUpstream      = "host.docker.internal:8498"' in source
    assert "os.Getenv" not in source

    start_source = (
        REPO_ROOT / "scripts" / "sandbox" / "start.sh"
    ).read_text(encoding="utf-8")
    assert "--host auto" in start_source
    assert '--runtime "$RUNTIME_CMD"' in start_source
    assert "--probe" in start_source
    assert "CONTROL_PORT=8498" in start_source
    assert "requires port 8498" in start_source
    assert "older protocol is running" in start_source
    assert '$RUNTIME_DIR:/overlay:ro,z' not in start_source
    assert "Podman 5.3+" in start_source
    assert "{{.Server.Version}}" in start_source
    assert "Docker Server 28+" in start_source
    assert "CONTROL_PROCESS_PID=$!" in start_source
    assert 'export SECAI_CONTROL_HOST_GATEWAY="$CONTROL_HOST_ALIAS"' in start_source
    assert 'RUNTIME_STATE_FILE="$RUNTIME_DIR/container-runtime"' in start_source
    assert "persist_container_runtime" in start_source
    assert 'ln "$runtime_tmp" "$RUNTIME_STATE_FILE"' in start_source
    assert "A concurrent launcher pinned the sandbox" in start_source
    assert "acquire_launcher_lock" in start_source
    assert "profile apply is already running" in start_source
    assert '[ -L "$RUNTIME_DIR" ]' in start_source
    assert '[ -L "$LAUNCHER_LOCK_DIR" ]' in start_source
    assert "set -C" in start_source
    assert "another PID namespace" in start_source
    assert "manually and retry" in start_source
    assert 'mv "$LAUNCHER_LOCK_DIR"' not in start_source
    assert 'stack_health=healthy' in start_source
    assert "podman_service_container_ids" in start_source
    assert 'podman_service_container_ids "$service_name"' in start_source
    assert "com.docker.compose.project=secai-sandbox" in start_source
    assert "com.docker.compose.service=$service_name" in start_source
    assert '"$@" ps -aq "$service_name"' not in start_source
    assert 'PODMAN_CONTROL_NETWORK="${COMPOSE_PROJECT_NAME}_ingress"' in start_source
    assert "scripts/sandbox/podman_anchor.py" in start_source
    assert '--podman-network "$PODMAN_CONTROL_NETWORK"' in start_source
    assert "remove-owned" in start_source
    assert "remove-recorded" in start_source
    assert "scripts/sandbox/generation_status.py" in start_source
    assert "chown -R 65534:65534 /volumes &&" not in start_source
    assert (
        "chown -R 65534:65534 /volumes/registry "
        "/volumes/promotion /volumes/quarantine"
    ) in start_source
    assert start_source.index("--probe") < start_source.index("--stop")
    assert start_source.index("--stop") < start_source.index(
        "invalidate >/dev/null"
    )
    assert "every nonzero probe result" in start_source
    assert "could not be retired safely" in start_source
    assert start_source.index(
        "invalidate >/dev/null"
    ) < start_source.index(
        "Quiescing existing sandbox services"
    )
    assert start_source.rindex(
        "publish \\"
    ) > start_source.index(
        "Timed out waiting for Podman sandbox health"
    )
    assert start_source.rindex(
        "publish \\"
    ) < start_source.index(
        "SecAI Sandbox is ready"
    )

    function_start = start_source.index("podman_service_container_ids() {")
    function_end = start_source.index("\n}", function_start) + 2
    function_source = start_source[function_start:function_end]
    podman_log = tmp_path / "podman.log"
    fake_podman = tmp_path / "podman"
    fake_podman.write_text(
        """#!/bin/sh
printf '%s\n' "$*" >> "$PODMAN_LOG"
if [ "$1" = "compose" ]; then
    echo "podman-compose ps accepts only -q and --format" >&2
    exit 64
fi
if [ "$1" = "ps" ]; then
    printf '%s\n' "fedora-podman-container-id"
    exit 0
fi
exit 65
""",
        encoding="utf-8",
    )
    fake_podman.chmod(fake_podman.stat().st_mode | stat.S_IXUSR)
    probe = subprocess.run(
        [
            "sh",
            "-c",
            (
                f"{function_source}\n"
                "RUNTIME_CMD=podman\n"
                'podman_service_container_ids "ui-ingress"\n'
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "PODMAN_LOG": str(podman_log),
        },
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout == "fedora-podman-container-id\n"
    podman_args = podman_log.read_text(encoding="utf-8")
    assert podman_args.startswith("ps -aq --no-trunc ")
    assert not podman_args.startswith("compose ")
    assert "label=com.docker.compose.project=secai-sandbox" in podman_args
    assert "label=com.docker.compose.service=ui-ingress" in podman_args

    powershell_start = (
        REPO_ROOT / "scripts" / "sandbox" / "start.ps1"
    ).read_text(encoding="utf-8")
    assert "${runtimeDir}:/overlay:ro,z" not in powershell_start
    assert '"--runtime", $runtimeCmd' in powershell_start
    assert "Select-SandboxContainerRuntime" in powershell_start
    assert "{{.Server.Version}}" in powershell_start
    assert "Start-Process -PassThru" in powershell_start
    assert '$podmanControlNetwork = "secai-sandbox_ingress"' in powershell_start
    assert "--podman-network" in powershell_start
    assert "label=com.docker.compose.service=$serviceName" in powershell_start
    assert "@healthComposeArgs ps -aq" not in powershell_start
    assert "remove-owned" in powershell_start
    assert "remove-recorded" in powershell_start
    assert "$env:SECAI_CONTROL_HOST_GATEWAY" in powershell_start
    assert "Set-SandboxPersistedRuntime" in powershell_start
    assert "A concurrent launcher pinned the sandbox" in powershell_start
    assert "Enter-SandboxLauncherLock" in powershell_start
    assert "Test-SandboxRealDirectory" in powershell_start
    assert "FileAttributes]::ReparsePoint" in powershell_start
    assert "FileMode]::CreateNew" in powershell_start
    assert "another PID namespace" in powershell_start
    assert "manually and retry" in powershell_start
    assert "Move-Item -LiteralPath $launcherLockDir" not in powershell_start
    assert powershell_start.count("--network none") >= 3
    assert powershell_start.count("--read-only") >= 3
    assert "chown -R 65534:65534 /volumes &&" not in powershell_start
    assert (
        "chown -R 65534:65534 /volumes/registry "
        "/volumes/promotion /volumes/quarantine"
    ) in powershell_start
    assert "label=com.docker.compose.project=secai-sandbox" in powershell_start
    assert powershell_start.index(
        "Quiescing existing sandbox services"
    ) < powershell_start.index("$renderOutput = @(")
    assert powershell_start.index(
        "Sandbox project containers remain running"
    ) < powershell_start.index("$renderOutput = @(")
    assert "generation_status.py" in powershell_start
    assert powershell_start.index("--probe") < powershell_start.index("--stop")
    assert powershell_start.index("--stop") < powershell_start.index(
        "invalidate"
    )
    assert "could not be retired safely" in powershell_start
    assert powershell_start.index(
        "invalidate"
    ) < powershell_start.index(
        "Quiescing existing sandbox services"
    )
    assert powershell_start.rindex(
        "publish"
    ) > powershell_start.index(
        "Timed out waiting for Podman sandbox health"
    )
    assert powershell_start.rindex(
        "publish"
    ) < powershell_start.index(
        "SecAI Sandbox is ready"
    )

    control_source = (
        REPO_ROOT / "scripts" / "sandbox" / "control_server.py"
    ).read_text(encoding="utf-8")
    assert "CONTROL_CONNECTION_LIMIT = 16" in control_source
    assert "HEADER_READ_TIMEOUT_SECONDS = 5.0" in control_source
    assert "BoundedThreadingHTTPServer" in control_source
    assert "stdout=subprocess.DEVNULL" in control_source
    assert "protocol_version" in control_source

    stop_source = (
        REPO_ROOT / "scripts" / "sandbox" / "stop.sh"
    ).read_text(encoding="utf-8")
    assert stop_source.index("stop_control_server") < stop_source.rindex(
        "docker compose -f"
    )
    assert "Compose teardown was not attempted" in stop_source
    assert 'RUNTIME_STATE_FILE="$RUNTIME_DIR/container-runtime"' in stop_source
    assert "acquire_launcher_lock" in stop_source
    assert '[ -L "$RUNTIME_DIR" ]' in stop_source
    assert '[ -L "$LAUNCHER_LOCK_DIR" ]' in stop_source
    assert "another PID namespace" in stop_source
    assert 'mv "$LAUNCHER_LOCK_DIR"' not in stop_source
    assert "prepare" in stop_source
    assert "remove-recorded" in stop_source
    assert '--podman-network "$PODMAN_CONTROL_NETWORK"' in stop_source
    teardown_generation = "0" * 64
    assert (
        f'SECAI_RUNTIME_GENERATION="{teardown_generation}"'
        in stop_source
    )
    assert stop_source.index(
        'SECAI_RUNTIME_GENERATION="'
    ) > stop_source.index("stop_control_server")
    assert 'export SECAI_RUNTIME_GENERATION' in stop_source
    assert "scripts/sandbox/generation_status.py" in stop_source
    assert stop_source.index(
        "invalidate >/dev/null"
    ) > stop_source.index(
        "control_status"
    )
    assert stop_source.index(
        "invalidate >/dev/null"
    ) < stop_source.rindex(
        "docker compose -f"
    )

    powershell_stop = (
        REPO_ROOT / "scripts" / "sandbox" / "stop.ps1"
    ).read_text(encoding="utf-8")
    assert powershell_stop.index("$controlCode = Stop-SandboxControlServer") < (
        powershell_stop.rindex("& docker compose -f")
    )
    assert "Compose teardown was not attempted" in powershell_stop
    assert "Enter-SandboxLauncherLock" in powershell_stop
    assert "Test-SandboxRealDirectory" in powershell_stop
    assert "FileAttributes]::ReparsePoint" in powershell_stop
    assert "FileMode]::CreateNew" in powershell_stop
    assert "another PID namespace" in powershell_stop
    assert "Move-Item -LiteralPath $launcherLockDir" not in powershell_stop
    assert "prepare" in powershell_stop
    assert "remove-recorded" in powershell_stop
    assert "--podman-network" in powershell_stop
    assert (
        f'$env:SECAI_RUNTIME_GENERATION = "{teardown_generation}"'
        in powershell_stop
    )
    assert powershell_stop.index(
        '$env:SECAI_RUNTIME_GENERATION = "'
    ) > powershell_stop.index("$controlCode = Stop-SandboxControlServer")
    assert "generation_status.py" in powershell_stop
    assert powershell_stop.index(
        "invalidate"
    ) > powershell_stop.index(
        "$controlCode = Stop-SandboxControlServer"
    )
    assert powershell_stop.index(
        "invalidate"
    ) < powershell_stop.rindex(
        "& docker compose -f"
    )

    assert "export SECAI_RUNTIME_GENERATION" in start_source
    assert "--force-recreate" in start_source
    assert "$RUNTIME_DIR:/overlay:ro,z" not in start_source
    assert start_source.count("--network none") >= 3
    assert start_source.count("--read-only") >= 3
    assert start_source.index(
        "Quiescing existing sandbox services"
    ) < start_source.index(
        'if ! SECAI_RUNTIME_GENERATION=$("$@")'
    )
    assert start_source.index(
        "Sandbox project containers remain running"
    ) < start_source.index(
        'if ! SECAI_RUNTIME_GENERATION=$("$@")'
    )
    assert "$env:SECAI_RUNTIME_GENERATION = $renderOutput[0]" in powershell_start
    assert "--force-recreate" in powershell_start

    command_source = (REPO_ROOT / "secai-sandbox.cmd").read_text(
        encoding="utf-8"
    )
    assert command_source.count(
        f'set "SECAI_RUNTIME_GENERATION={teardown_generation}"'
    ) == 2
    assert command_source.index(":status_stack") < command_source.index(
        f'set "SECAI_RUNTIME_GENERATION={teardown_generation}"'
    ) < command_source.index(
        'docker compose -f "%COMPOSE_FILE%" '
        "--profile search --profile llm --profile diffusion ps"
    )


def test_sandbox_bundle_has_docs_and_helpers():
    assert DOC_PATH.exists()
    for rel_path in [
        "deploy/sandbox/.env.example",
        "deploy/sandbox/compose.gpu.nvidia.yaml",
        "deploy/sandbox/compose.gpu.rocm.yaml",
        "deploy/sandbox/search/torrc",
        "deploy/sandbox/searxng/Dockerfile",
        "deploy/sandbox/tor/Dockerfile",
        "services/diffusion-worker/Dockerfile.sandbox",
        "services/ui-ingress/Dockerfile",
        "services/ui-ingress/go.mod",
        "services/ui-ingress/main.go",
        "services/ui-ingress/main_test.go",
        "services/ui/entrypoint.py",
        "services/search-mediator/entrypoint.py",
        "scripts/sandbox/ui-entrypoint.sh",
        "scripts/sandbox/search-mediator-entrypoint.sh",
        "scripts/sandbox/provision_control_token.py",
        "scripts/sandbox/generation_status.py",
        "scripts/sandbox/render_runtime.py",
        "scripts/sandbox/start.sh",
        "scripts/sandbox/stop.sh",
        "scripts/sandbox/start.ps1",
        "scripts/sandbox/stop.ps1",
        "secai-sandbox.cmd",
    ]:
        assert (REPO_ROOT / rel_path).exists()


def test_sandbox_container_bases_exclude_vulnerable_openssl_pins():
    shell_helper = (REPO_ROOT / "scripts" / "sandbox" / "start.sh").read_text(
        encoding="utf-8"
    )
    powershell_helper = (REPO_ROOT / "scripts" / "sandbox" / "start.ps1").read_text(
        encoding="utf-8"
    )

    assert PINNED_ALPINE_HELPER in shell_helper
    assert PINNED_ALPINE_HELPER in powershell_helper
    assert "docker.io/library/alpine:3.20" not in shell_helper
    assert "docker.io/library/alpine:3.20" not in powershell_helper

    pin_sources = [
        path
        for root in (REPO_ROOT / "services", REPO_ROOT / "deploy")
        for path in root.rglob("Dockerfile*")
        if path.is_file()
    ]
    pin_sources.extend(
        [
            REPO_ROOT / "scripts" / "sandbox" / "start.sh",
            REPO_ROOT / "scripts" / "sandbox" / "start.ps1",
        ]
    )
    pin_corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in pin_sources
    )
    for digest in VULNERABLE_CVE_2026_45447_BASE_DIGESTS:
        assert digest not in pin_corpus


def test_sandbox_start_helpers_bound_docker_wait_time():
    shell_helper = (REPO_ROOT / "scripts" / "sandbox" / "start.sh").read_text(
        encoding="utf-8"
    )
    powershell_helper = (REPO_ROOT / "scripts" / "sandbox" / "start.ps1").read_text(
        encoding="utf-8"
    )

    assert "--wait-timeout 900" in shell_helper
    assert '"--wait-timeout", "900"' in powershell_helper


def test_sandbox_control_server_kills_stale_start_tree():
    control_server = (REPO_ROOT / "scripts" / "sandbox" / "control_server.py").read_text(
        encoding="utf-8"
    )

    assert "SECAI_CONTROL_APPLY_TIMEOUT" in control_server
    assert "WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in control_server
    assert "WINDOWS_CREATE_SUSPENDED" in control_server
    assert "AssignProcessToJobObject" in control_server
    assert "ResumeThread" in control_server
    assert "taskkill" not in control_server
    assert "stdout=subprocess.DEVNULL" in control_server
    assert "stderr=subprocess.DEVNULL" in control_server
    assert "capture_output=True" not in control_server[
        control_server.index("def _run_start_command"):
        control_server.index("def _run_apply")
    ]
    assert "previous sandbox automation was interrupted" in control_server


def test_windows_sandbox_launcher_delegates_to_hardened_helpers():
    launcher = (REPO_ROOT / "secai-sandbox.cmd").read_text(encoding="utf-8")

    assert "scripts\\sandbox\\start.ps1" in launcher
    assert "scripts\\sandbox\\stop.ps1" in launcher
    assert "-ExecutionPolicy Bypass" in launcher
    for option, ps_switch in {
        "--with-search": "-WithSearch",
        "--with-airlock": "-WithAirlock",
        "--with-inference": "-WithInference",
        "--with-diffusion": "-WithDiffusion",
        "--with-gpu": "-WithGpu",
    }.items():
        assert option in launcher
        assert ps_switch in launcher


def test_sandbox_stop_helpers_include_optional_profiles(tmp_path):
    import shutil
    import subprocess
    import sys

    shell_helper = (REPO_ROOT / "scripts" / "sandbox" / "stop.sh").read_text(
        encoding="utf-8"
    )
    powershell_helper = (REPO_ROOT / "scripts" / "sandbox" / "stop.ps1").read_text(
        encoding="utf-8"
    )

    for profile in ("search", "llm", "diffusion"):
        assert f"--profile {profile}" in shell_helper
        assert f"--profile {profile}" in powershell_helper

    lock_case = tmp_path / "lock-symlink"
    lock_script = lock_case / "scripts" / "sandbox" / "stop.sh"
    lock_script.parent.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / "sandbox" / "stop.sh", lock_script)
    lock_runtime = lock_case / "deploy" / "sandbox" / "runtime"
    lock_runtime.mkdir(parents=True)
    outside_lock = lock_case / "outside-lock"
    outside_lock.mkdir()
    outside_pid = outside_lock / "pid"
    outside_pid.write_text("2147483647", encoding="ascii")
    (lock_runtime / "launcher.lock").symlink_to(
        outside_lock,
        target_is_directory=True,
    )
    lock_result = subprocess.run(
        ["/bin/sh", str(lock_script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert lock_result.returncode != 0
    assert "cannot be verified safely" in lock_result.stderr
    assert "manually and retry" in lock_result.stderr
    assert outside_pid.read_text(encoding="ascii") == "2147483647"

    runtime_case = tmp_path / "runtime-symlink"
    runtime_script = runtime_case / "scripts" / "sandbox" / "stop.sh"
    runtime_script.parent.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / "sandbox" / "stop.sh", runtime_script)
    runtime_parent = runtime_case / "deploy" / "sandbox"
    runtime_parent.mkdir(parents=True)
    outside_runtime = runtime_case / "outside-runtime"
    outside_runtime.mkdir()
    sentinel = outside_runtime / "sentinel"
    sentinel.write_text("preserve", encoding="ascii")
    (runtime_parent / "runtime").symlink_to(
        outside_runtime,
        target_is_directory=True,
    )
    runtime_result = subprocess.run(
        ["/bin/sh", str(runtime_script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert runtime_result.returncode != 0
    assert "real directory" in runtime_result.stderr
    assert sentinel.read_text(encoding="ascii") == "preserve"

    interrupted_case = tmp_path / "interrupted-launcher"
    interrupted_script = (
        interrupted_case / "scripts" / "sandbox" / "stop.sh"
    )
    interrupted_script.parent.mkdir(parents=True)
    shutil.copy2(
        REPO_ROOT / "scripts" / "sandbox" / "stop.sh",
        interrupted_script,
    )
    interrupted_lock = (
        interrupted_case / "deploy" / "sandbox" / "runtime" / "launcher.lock"
    )
    interrupted_lock.mkdir(parents=True)
    interrupted_pid = interrupted_lock / "pid"
    interrupted_pid.write_text("2147483647", encoding="ascii")
    orphan_child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
    )
    try:
        interrupted_result = subprocess.run(
            ["/bin/sh", str(interrupted_script)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert interrupted_result.returncode != 0
        assert "another PID namespace" in interrupted_result.stderr
        assert "manually and retry" in interrupted_result.stderr
        assert interrupted_pid.read_text(encoding="ascii") == "2147483647"
        assert orphan_child.poll() is None
    finally:
        orphan_child.terminate()
        orphan_child.wait(timeout=5)


def test_optional_profiles_are_hardened_and_use_production_entrypoints():
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    services = data["services"]

    inference = services["inference"]
    assert inference["read_only"] is True
    assert inference["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in inference["security_opt"]
    assert inference["user"] == "65534:65534"
    assert inference["volumes"] == [
        "secai-registry:/var/lib/secure-ai/registry:ro"
    ]
    assert inference["environment"]["REGISTRY_DIR"] == "/var/lib/secure-ai/registry"
    inference_containerfile = (REPO_ROOT / "services" / "inference-worker" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "/proc/net/tcp" in inference_containerfile
    assert "wget -q" not in inference_containerfile

    diffusion = services["diffusion"]
    assert diffusion["read_only"] is True
    assert diffusion["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in diffusion["security_opt"]
    assert diffusion["build"]["context"] == "../.."
    assert diffusion["build"]["dockerfile"] == "services/diffusion-worker/Dockerfile.sandbox"
    assert diffusion["platform"] == "linux/amd64"
    assert diffusion["environment"]["LANG"] == "C.UTF-8"
    assert diffusion["environment"]["LC_ALL"] == "C.UTF-8"
    assert diffusion["environment"]["GUNICORN_WORKERS"] == 1
    assert diffusion["environment"]["GUNICORN_THREADS"] == 2
    assert diffusion["environment"]["GUNICORN_TIMEOUT"] == 1800
    assert diffusion["environment"]["DIFFUSION_DEVICE_PREFERENCE"] == "${SECAI_DIFFUSION_DEVICE_PREFERENCE:-auto}"
    assert diffusion["environment"]["DIFFUSION_CPU_OFFLOAD"] == "${SECAI_DIFFUSION_CPU_OFFLOAD:-0}"
    assert "/tmp:rw,noexec,nosuid,nodev,size=256m" in diffusion["tmpfs"]

    diffusion_containerfile = (REPO_ROOT / "services" / "diffusion-worker" / "Dockerfile.sandbox").read_text(
        encoding="utf-8"
    )
    assert 'diffusion-${COMPUTE}-py314.lock' in diffusion_containerfile
    expected_torch = {
        "cpu": "torch==2.13.0+cpu",
        "cuda": "torch==2.13.0+cu129",
        "rocm": "torch==2.13.0+rocm7.1",
    }
    for backend, requirement in expected_torch.items():
        lockfile = (
            REPO_ROOT
            / "files"
            / "scripts"
            / f"diffusion-{backend}-py314.lock"
        ).read_text(encoding="utf-8")
        assert requirement in lockfile
        assert "--require-hashes" in diffusion_containerfile


def test_gpu_compose_overrides_are_explicit_and_scoped_to_diffusion():
    nvidia = yaml.safe_load(NVIDIA_GPU_COMPOSE_PATH.read_text())
    rocm = yaml.safe_load(ROCM_GPU_COMPOSE_PATH.read_text())

    assert set(nvidia["services"]) == {"diffusion"}
    nvidia_diffusion = nvidia["services"]["diffusion"]
    assert nvidia_diffusion["build"]["args"]["COMPUTE"] == "cuda"
    assert nvidia_diffusion["environment"]["DIFFUSION_CPU_OFFLOAD"] == "${SECAI_DIFFUSION_CPU_OFFLOAD:-0}"
    assert nvidia_diffusion["environment"]["NVIDIA_DRIVER_CAPABILITIES"] == "${NVIDIA_DRIVER_CAPABILITIES:-compute,utility}"
    devices = nvidia_diffusion["deploy"]["resources"]["reservations"]["devices"]
    assert devices == [{"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}]

    assert set(rocm["services"]) == {"diffusion"}
    rocm_diffusion = rocm["services"]["diffusion"]
    assert rocm_diffusion["build"]["args"]["COMPUTE"] == "rocm"
    assert "/dev/kfd:/dev/kfd" in rocm_diffusion["devices"]
    assert "/dev/dri:/dev/dri" in rocm_diffusion["devices"]


def test_runtime_renderer_can_toggle_search_and_airlock(tmp_path):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    _, generation_dir = _render_sandbox_runtime(
        runtime_dir,
        "--enable-search",
        "--enable-airlock",
    )

    policy = yaml.safe_load(
        (generation_dir / "policy" / "policy.yaml").read_text()
    )
    config = yaml.safe_load(
        (generation_dir / "config" / "appliance.yaml").read_text()
    )
    profile_state = yaml.safe_load(
        (generation_dir / "profile.json").read_text()
    )

    assert policy["search"]["enabled"] is True
    assert policy["airlock"]["enabled"] is True
    assert config["appliance"]["mode"] == "online-augmented"
    assert profile_state["active"] == "research"
    flask_key = runtime_dir / "credentials" / "ui-flask.token"
    assert flask_key.exists()
    assert len(flask_key.read_text(encoding="ascii")) == 64
    assert flask_key.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    "ambiguous_yaml",
    [
        (
            "search:\n"
            "  enabled: false\n"
            "search:\n"
            "  enabled: true\n"
        ),
        (
            "search:\n"
            "  enabled: false\n"
            "  enabled: true\n"
        ),
        (
            "search:\n"
            "  enabled: false\n"
            "!!str search:\n"
            "  enabled: true\n"
        ),
        (
            "search:\n"
            "  enabled: false\n"
            "!<tag:yaml.org,2002:str> search:\n"
            "  enabled: true\n"
        ),
        (
            "search:\n"
            "  enabled: false\n"
            "  ! enabled: true\n"
        ),
        (
            "anchor_key: &k search\n"
            "search:\n"
            "  enabled: false\n"
            "*k:\n"
            "  enabled: true\n"
        ),
        (
            '"search":\n'
            "  enabled: false\n"
        ),
        (
            "search:\n"
            "  'enabled': false\n"
        ),
    ],
)
def test_runtime_renderer_rejects_ambiguous_target_yaml(
    ambiguous_yaml,
):
    renderer = _load_runtime_renderer()

    with pytest.raises(ValueError):
        renderer._replace_in_section(
            ambiguous_yaml,
            "search",
            "enabled",
            "false",
        )


def test_runtime_renderer_provisions_exact_lowercase_hex_credentials(tmp_path):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)

    renderer._provision_target_credentials(runtime_dir)

    credentials_dir = runtime_dir / "credentials"
    expected_names = {
        f"{service}.token" for service in renderer.TARGET_CREDENTIALS
    }
    assert {path.name for path in credentials_dir.iterdir()} == expected_names
    original_payloads = {}
    for target in credentials_dir.iterdir():
        metadata = os.lstat(target)
        assert stat.S_ISREG(metadata.st_mode)
        assert not target.is_symlink()
        payload = target.read_text(encoding="ascii")
        assert re.fullmatch(r"[0-9a-f]{64}", payload)
        original_payloads[target.name] = payload

    renderer._provision_target_credentials(runtime_dir)

    assert {
        target.name: target.read_text(encoding="ascii")
        for target in credentials_dir.iterdir()
    } == original_payloads


def test_runtime_renderer_rejects_hardlinked_credentials(tmp_path):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    renderer._provision_target_credentials(runtime_dir)
    credentials_dir = runtime_dir / "credentials"
    source = credentials_dir / "airlock.token"
    alias = credentials_dir / "agent.token"
    alias.unlink()
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hardlink creation is unavailable: {exc}")

    with pytest.raises(RuntimeError, match="credential"):
        renderer._provision_target_credentials(runtime_dir)

    assert os.lstat(source).st_nlink == 2
    assert os.lstat(alias).st_ino == os.lstat(source).st_ino


def test_runtime_renderer_rejects_duplicate_credential_payloads(tmp_path):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    renderer._provision_target_credentials(runtime_dir)
    credentials_dir = runtime_dir / "credentials"
    source = credentials_dir / "airlock.token"
    duplicate = credentials_dir / "agent.token"
    duplicate.write_bytes(source.read_bytes())

    assert os.lstat(source).st_ino != os.lstat(duplicate).st_ino
    with pytest.raises(RuntimeError, match="independent values"):
        renderer._provision_target_credentials(runtime_dir)


@pytest.mark.parametrize(
    "temporary_kind",
    ["malformed-name", "symlink"],
)
def test_runtime_renderer_rejects_unsafe_credential_temporaries(
    tmp_path,
    monkeypatch,
    temporary_kind,
):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    credentials_dir = runtime_dir / "credentials"
    credentials_dir.mkdir(mode=0o700)
    name = (
        ".airlock.token.bad.tmp"
        if temporary_kind == "malformed-name"
        else ".airlock.token.99999999.0123456789abcdef.tmp"
    )
    temporary = credentials_dir / name
    outside = tmp_path / "outside-token"
    if temporary_kind == "symlink":
        outside.write_bytes(b"a" * 64)
        try:
            temporary.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        temporary.write_bytes(b"a" * 64)
    monkeypatch.setattr(renderer, "_pid_is_alive", lambda _pid: False)

    with pytest.raises(RuntimeError, match="credential"):
        renderer._provision_target_credentials(runtime_dir)

    if temporary_kind == "symlink":
        assert outside.read_bytes() == b"a" * 64


@pytest.mark.parametrize("partial_payload", [b"", b"partial"])
def test_runtime_renderer_removes_dead_partial_prelink_temporary(
    tmp_path,
    monkeypatch,
    partial_payload,
):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    credentials_dir = runtime_dir / "credentials"
    credentials_dir.mkdir(mode=0o700)
    temporary = (
        credentials_dir
        / ".airlock.token.99999999.0123456789abcdef.tmp"
    )
    temporary.write_bytes(partial_payload)
    monkeypatch.setattr(renderer, "_pid_is_alive", lambda _pid: False)

    renderer._provision_target_credentials(runtime_dir)

    assert not temporary.exists()
    assert re.fullmatch(
        rb"[0-9a-f]{64}",
        (credentials_dir / "airlock.token").read_bytes(),
    )


def test_runtime_renderer_windows_pid_probe_never_calls_os_kill(
    monkeypatch,
):
    renderer = _load_runtime_renderer()
    monkeypatch.setattr(renderer.os, "name", "nt")
    monkeypatch.setattr(
        renderer.os,
        "kill",
        lambda *_args: pytest.fail("os.kill must not probe Windows PIDs"),
    )
    monkeypatch.setattr(
        renderer,
        "_windows_process_exists",
        lambda pid: pid == 4242,
    )

    assert renderer._pid_is_alive(4242) is True
    assert renderer._pid_is_alive(4243) is False


@pytest.mark.parametrize(
    "invalid_kind",
    ["empty", "short", "uppercase", "symlink", "directory"],
)
def test_runtime_renderer_rejects_and_preserves_invalid_credentials(
    tmp_path,
    invalid_kind,
):
    renderer = _load_runtime_renderer()
    credentials_dir = tmp_path / "runtime" / "credentials"
    credentials_dir.mkdir(parents=True)
    target = credentials_dir / "airlock.token"
    outside = tmp_path / "outside.token"

    if invalid_kind == "empty":
        target.write_bytes(b"")
    elif invalid_kind == "short":
        target.write_bytes(b"a")
    elif invalid_kind == "uppercase":
        target.write_bytes(b"A" * 64)
    elif invalid_kind == "symlink":
        outside.write_bytes(b"outside-must-not-change")
        try:
            target.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        target.mkdir()

    original_inode = os.lstat(target).st_ino
    original_mode = stat.S_IMODE(os.lstat(target).st_mode)
    original_file_payload = (
        target.read_bytes()
        if invalid_kind in {"empty", "short", "uppercase"}
        else None
    )
    original_link = os.readlink(target) if invalid_kind == "symlink" else None

    with pytest.raises(RuntimeError, match="credential"):
        renderer._provision_target_credentials(tmp_path / "runtime")

    assert os.lstat(target).st_ino == original_inode
    assert stat.S_IMODE(os.lstat(target).st_mode) == original_mode
    if invalid_kind in {"empty", "short", "uppercase"}:
        assert target.read_bytes() == original_file_payload
    elif invalid_kind == "symlink":
        assert target.is_symlink()
        assert os.readlink(target) == original_link
        assert outside.read_bytes() == b"outside-must-not-change"
    else:
        assert target.is_dir()


def test_runtime_renderer_completes_credential_across_partial_writes(
    tmp_path,
    monkeypatch,
):
    renderer = _load_runtime_renderer()
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    target = credentials_dir / "partial.token"
    original_write = os.write
    write_sizes = []

    def partial_write(descriptor, payload):
        chunk = payload[:7]
        written = original_write(descriptor, chunk)
        write_sizes.append(written)
        return written

    monkeypatch.setattr(renderer.os, "write", partial_write)

    renderer._create_credential_atomic(credentials_dir, target)

    payload = target.read_text(encoding="ascii")
    assert re.fullmatch(r"[0-9a-f]{64}", payload)
    assert len(write_sizes) > 1
    assert max(write_sizes) <= 7
    assert list(credentials_dir.iterdir()) == [target]


def test_runtime_renderer_recovers_interrupted_credential_hardlink_install(
    tmp_path,
    monkeypatch,
):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    credentials_dir = runtime_dir / "credentials"
    credentials_dir.mkdir(mode=0o700)
    target = credentials_dir / "airlock.token"
    original_unlink = Path.unlink

    class SimulatedCrash(BaseException):
        pass

    def crash_before_temp_unlink(path, *args, **kwargs):
        if path.name.startswith(".airlock.token."):
            raise SimulatedCrash
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(renderer.Path, "unlink", crash_before_temp_unlink)
    with pytest.raises(SimulatedCrash):
        renderer._create_credential_atomic(credentials_dir, target)
    temporary = next(credentials_dir.glob(".airlock.token.*.tmp"))
    payload = target.read_bytes()
    assert os.lstat(target).st_nlink == 2
    assert os.lstat(temporary).st_ino == os.lstat(target).st_ino

    monkeypatch.setattr(renderer.Path, "unlink", original_unlink)
    renderer._provision_target_credentials(runtime_dir)
    assert target.read_bytes() == payload
    assert os.lstat(target).st_nlink == 1
    assert not list(credentials_dir.glob(".airlock.token.*.tmp"))


def test_runtime_renderer_recovers_prelink_credential_crash(
    tmp_path,
    monkeypatch,
):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    credentials_dir = runtime_dir / "credentials"
    credentials_dir.mkdir(mode=0o700)
    target = credentials_dir / "airlock.token"
    original_unlink = Path.unlink
    original_link = os.link

    class SimulatedCrash(BaseException):
        pass

    def crash_before_link(*_args, **_kwargs):
        raise SimulatedCrash

    def preserve_crash_temp(path, *args, **kwargs):
        if path.name.startswith(".airlock.token."):
            raise SimulatedCrash
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(renderer.os, "link", crash_before_link)
    monkeypatch.setattr(renderer.Path, "unlink", preserve_crash_temp)
    with pytest.raises(SimulatedCrash):
        renderer._create_credential_atomic(credentials_dir, target)
    orphan = next(credentials_dir.glob(".airlock.token.*.tmp"))
    assert os.lstat(orphan).st_nlink == 1
    assert not target.exists()

    monkeypatch.setattr(renderer.os, "link", original_link)
    monkeypatch.setattr(renderer.Path, "unlink", original_unlink)
    monkeypatch.setattr(renderer, "_pid_is_alive", lambda _pid: False)
    renderer._provision_target_credentials(runtime_dir)
    assert target.exists()
    assert not orphan.exists()


def test_runtime_credential_atomic_create_handles_concurrent_first_writers(
    tmp_path,
    monkeypatch,
):
    renderer = _load_runtime_renderer()
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    target = credentials_dir / "airlock.token"
    original_link = os.link
    barrier = threading.Barrier(2)
    errors = []

    def racing_link(source, destination):
        barrier.wait(timeout=5)
        return original_link(source, destination)

    def create():
        try:
            renderer._create_credential_atomic(credentials_dir, target)
        except BaseException as exc:  # pragma: no branch - captured for assert
            errors.append(exc)

    monkeypatch.setattr(renderer.os, "link", racing_link)
    workers = [threading.Thread(target=create) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not errors
    assert all(not worker.is_alive() for worker in workers)
    assert re.fullmatch(rb"[0-9a-f]{64}", target.read_bytes())
    assert os.lstat(target).st_nlink == 1
    assert not list(credentials_dir.glob(".airlock.token.*.tmp"))


def test_runtime_renderer_marks_diffusion_stack_as_full_lab(tmp_path):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    _, generation_dir = _render_sandbox_runtime(
        runtime_dir,
        "--enable-diffusion",
    )

    profile_state = yaml.safe_load(
        (generation_dir / "profile.json").read_text()
    )

    assert profile_state["active"] == "full_lab"


def test_runtime_generations_are_content_addressed_immutable_and_reused(
    tmp_path,
):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    first, first_dir = _render_sandbox_runtime(runtime_dir)
    second, second_dir = _render_sandbox_runtime(runtime_dir)

    assert second == first
    assert second_dir == first_dir
    assert len(list((runtime_dir / "generations").iterdir())) == 1
    manifest = yaml.safe_load((first_dir / "generation.json").read_text())
    assert manifest["version"] == 1
    assert manifest["generation"] == first
    assert {
        entry["path"] for entry in manifest["files"]
    } >= {
        "policy/policy.yaml",
        "config/appliance.yaml",
        "model-catalog.yaml",
        "profile.json",
    }
    if os.name != "nt":
        assert stat.S_IMODE(first_dir.stat().st_mode) == 0o555
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o444
            for path in first_dir.rglob("*")
            if path.is_file()
        )
        assert stat.S_IMODE(
            (runtime_dir / "active-generation").stat().st_mode
        ) == 0o600

    third, third_dir = _render_sandbox_runtime(
        runtime_dir,
        "--enable-search",
    )
    assert third != first
    assert third_dir != first_dir
    assert len(list((runtime_dir / "generations").iterdir())) == 2
    old_policy = yaml.safe_load(
        (first_dir / "policy" / "policy.yaml").read_text()
    )
    new_policy = yaml.safe_load(
        (third_dir / "policy" / "policy.yaml").read_text()
    )
    assert old_policy["search"]["enabled"] is False
    assert new_policy["search"]["enabled"] is True


@pytest.mark.parametrize(
    "link_path",
    ["generations", "policy", "active-generation"],
)
def test_runtime_renderer_rejects_linked_publication_paths(
    tmp_path,
    link_path,
):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    outside = tmp_path / "outside"
    if link_path == "active-generation":
        outside.write_text("a" * 64, encoding="ascii")
    else:
        outside.mkdir()
        (outside / "sentinel").write_text("must-not-change", encoding="utf-8")
    try:
        (runtime_dir / link_path).symlink_to(
            outside,
            target_is_directory=link_path != "active-generation",
        )
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(subprocess.CalledProcessError):
        _render_sandbox_runtime(runtime_dir)

    if link_path == "active-generation":
        assert outside.read_text(encoding="ascii") == "a" * 64
    else:
        assert (outside / "sentinel").read_text() == "must-not-change"


def test_runtime_renderer_rejects_stale_existing_generation(tmp_path):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    _, generation_dir = _render_sandbox_runtime(runtime_dir)
    if os.name != "nt":
        generation_dir.chmod(0o755)
    (generation_dir / "stale.txt").write_text("stale", encoding="utf-8")
    if os.name != "nt":
        (generation_dir / "stale.txt").chmod(0o444)
        generation_dir.chmod(0o555)

    with pytest.raises(subprocess.CalledProcessError):
        _render_sandbox_runtime(runtime_dir)


def test_runtime_generation_commit_keeps_old_pointer_until_atomic_switch(
    tmp_path,
):
    renderer = _load_runtime_renderer()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    old_generation, _ = _render_sandbox_runtime(runtime_dir)
    files = {
        "policy/policy.yaml": b"policy-new\n",
        "config/appliance.yaml": b"config-new\n",
        "model-catalog.yaml": b"catalog-new\n",
        "profile.json": b'{"active":"research"}\n',
    }
    renderer._validate_generation_structure(files)
    new_generation = renderer._generation_digest(files)
    generations_dir = runtime_dir / "generations"

    # A crash after the immutable generation rename but before pointer
    # publication leaves the complete new generation unreferenced.
    renderer._stage_generation(
        generations_dir,
        new_generation,
        files,
    )
    assert renderer.read_active_generation(runtime_dir) == old_generation

    renderer._publish_active_generation(runtime_dir, new_generation)
    assert renderer.read_active_generation(runtime_dir) == new_generation


def test_runtime_renderer_recovers_abandoned_real_stage(tmp_path):
    runtime_dir = _create_sandbox_runtime(tmp_path)
    stage = runtime_dir / ".render-stage-123-0123456789abcdef"
    stage.mkdir()
    (stage / "partial").write_text("not-authoritative", encoding="utf-8")

    _render_sandbox_runtime(runtime_dir)

    assert not stage.exists()


def test_generation_status_publishes_session_bound_ready_pair(tmp_path):
    helper = _load_generation_status_helper()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    control_session = runtime_dir / "control-server-session"
    generation = "a" * 64
    first_session = "b" * 64
    second_session = "c" * 64
    control_session.write_text(first_session, encoding="ascii")
    control_session.chmod(0o600)

    assert helper.publish_ready_state(runtime_dir, generation) is True
    assert helper.read_ready_state(runtime_dir) == (
        generation,
        first_session,
    )
    status_dir = runtime_dir / "generation-status"
    assert stat.S_IMODE(status_dir.stat().st_mode) == 0o755
    assert {
        path.name: path.read_text(encoding="ascii")
        for path in status_dir.iterdir()
    } == {
        "ready-generation": generation,
        "ready-session": first_session,
    }
    if os.name != "nt":
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o644
            for path in status_dir.iterdir()
        )
    assert helper.publish_ready_state(runtime_dir, generation) is False

    control_session.write_text(second_session, encoding="ascii")
    control_session.chmod(0o600)
    assert helper.publish_ready_state(runtime_dir, generation) is True
    assert helper.read_ready_state(runtime_dir) == (
        generation,
        second_session,
    )

    assert helper.invalidate_ready_state(runtime_dir) is True
    assert list(status_dir.iterdir()) == []
    assert helper.invalidate_ready_state(runtime_dir) is False


def test_generation_status_requires_private_control_session(tmp_path):
    helper = _load_generation_status_helper()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    control_session = runtime_dir / "control-server-session"
    control_session.write_text("b" * 64, encoding="ascii")
    if os.name == "nt":
        pytest.skip("POSIX mode enforcement is not available on Windows")
    control_session.chmod(0o644)

    with pytest.raises(RuntimeError, match="owner-private"):
        helper.publish_ready_state(runtime_dir, "a" * 64)

    assert not (runtime_dir / "generation-status").exists()


def test_generation_status_generation_marker_is_commit_point(
    tmp_path,
    monkeypatch,
):
    helper = _load_generation_status_helper()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    control_session = runtime_dir / "control-server-session"
    control_session.write_text("b" * 64, encoding="ascii")
    control_session.chmod(0o600)
    original_publish = helper._publish_marker

    def interrupt_before_generation(status_dir, marker_name, value):
        if marker_name == "ready-generation":
            raise OSError("injected generation commit failure")
        return original_publish(status_dir, marker_name, value)

    monkeypatch.setattr(
        helper,
        "_publish_marker",
        interrupt_before_generation,
    )
    with pytest.raises(OSError, match="injected"):
        helper.publish_ready_state(runtime_dir, "a" * 64)

    status_dir = runtime_dir / "generation-status"
    assert (status_dir / "ready-session").read_text(
        encoding="ascii"
    ) == "b" * 64
    assert not (status_dir / "ready-generation").exists()
    with pytest.raises((FileNotFoundError, RuntimeError)):
        helper.read_ready_state(runtime_dir)


def test_generation_status_rejects_linked_ready_marker(tmp_path):
    helper = _load_generation_status_helper()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    status_dir = runtime_dir / "generation-status"
    status_dir.mkdir(mode=0o755)
    outside = tmp_path / "outside-ready"
    outside.write_text("a" * 64, encoding="ascii")
    marker = status_dir / "ready-generation"
    try:
        marker.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(RuntimeError, match="ready-state marker"):
        helper.invalidate_ready_state(runtime_dir)

    assert outside.read_text(encoding="ascii") == "a" * 64


def test_control_token_provisioner_is_atomic_exact_and_stable(tmp_path):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"

    assert provisioner.provision_control_token(runtime_dir, token_path) is True
    first = token_path.read_bytes()
    assert re.fullmatch(rb"[0-9a-f]{64}", first)
    assert os.lstat(token_path).st_nlink == 1
    if os.name != "nt":
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o604
    assert provisioner.provision_control_token(runtime_dir, token_path) is False
    assert token_path.read_bytes() == first


@pytest.mark.parametrize("invalid_kind", ["symlink", "directory", "fifo"])
def test_control_token_provisioner_rejects_special_or_linked_targets(
    tmp_path,
    invalid_kind,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    outside = tmp_path / "outside-token"
    if invalid_kind == "symlink":
        outside.write_bytes(b"b" * 64)
        try:
            token_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    elif invalid_kind == "directory":
        token_path.mkdir()
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation is unavailable")
        os.mkfifo(token_path)

    with pytest.raises(RuntimeError, match="control token"):
        provisioner.provision_control_token(runtime_dir, token_path)

    if invalid_kind == "symlink":
        assert outside.read_bytes() == b"b" * 64


@pytest.mark.parametrize(
    "temporary_kind",
    ["malformed-name", "symlink"],
)
def test_control_token_provisioner_rejects_unsafe_temporaries(
    tmp_path,
    monkeypatch,
    temporary_kind,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    name = (
        ".control-token.bad.tmp"
        if temporary_kind == "malformed-name"
        else ".control-token.99999999.0123456789abcdef.tmp"
    )
    temporary = runtime_dir / name
    outside = tmp_path / "outside-control-token"
    if temporary_kind == "symlink":
        outside.write_bytes(b"a" * 64)
        try:
            temporary.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
    else:
        temporary.write_bytes(b"a" * 64)
    monkeypatch.setattr(provisioner, "_pid_is_alive", lambda _pid: False)

    with pytest.raises(RuntimeError, match="control-token|control token"):
        provisioner.provision_control_token(runtime_dir, token_path)

    if temporary_kind == "symlink":
        assert outside.read_bytes() == b"a" * 64


@pytest.mark.parametrize("partial_payload", [b"", b"partial"])
def test_control_token_removes_dead_partial_prelink_temporary(
    tmp_path,
    monkeypatch,
    partial_payload,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    temporary = (
        runtime_dir / ".control-token.99999999.0123456789abcdef.tmp"
    )
    temporary.write_bytes(partial_payload)
    monkeypatch.setattr(provisioner, "_pid_is_alive", lambda _pid: False)

    assert provisioner.provision_control_token(
        runtime_dir,
        token_path,
    ) is True

    assert not temporary.exists()
    assert re.fullmatch(rb"[0-9a-f]{64}", token_path.read_bytes())


def test_control_token_windows_pid_probe_never_calls_os_kill(
    monkeypatch,
):
    provisioner = _load_control_token_provisioner()
    monkeypatch.setattr(provisioner.os, "name", "nt")
    monkeypatch.setattr(
        provisioner.os,
        "kill",
        lambda *_args: pytest.fail("os.kill must not probe Windows PIDs"),
    )
    monkeypatch.setattr(
        provisioner,
        "_windows_process_exists",
        lambda pid: pid == 4242,
    )

    assert provisioner._pid_is_alive(4242) is True
    assert provisioner._pid_is_alive(4243) is False


def test_control_token_provisioner_completes_partial_writes(
    tmp_path,
    monkeypatch,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    original_write = os.write
    writes = []

    def partial_write(descriptor, payload):
        written = original_write(descriptor, payload[:7])
        writes.append(written)
        return written

    monkeypatch.setattr(provisioner.os, "write", partial_write)
    assert provisioner.provision_control_token(runtime_dir, token_path) is True
    assert re.fullmatch(rb"[0-9a-f]{64}", token_path.read_bytes())
    assert len(writes) > 1
    assert not list(runtime_dir.glob(".control-token.*.tmp"))


def test_control_token_provisioner_recovers_interrupted_hardlink_install(
    tmp_path,
    monkeypatch,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    original_unlink = Path.unlink

    class SimulatedCrash(BaseException):
        pass

    def crash_before_temp_unlink(path, *args, **kwargs):
        if path.name.startswith(".control-token."):
            raise SimulatedCrash
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(
        provisioner.Path,
        "unlink",
        crash_before_temp_unlink,
    )
    with pytest.raises(SimulatedCrash):
        provisioner.provision_control_token(runtime_dir, token_path)
    temporary = next(runtime_dir.glob(".control-token.*.tmp"))
    payload = token_path.read_bytes()
    assert os.lstat(token_path).st_nlink == 2
    assert os.lstat(temporary).st_ino == os.lstat(token_path).st_ino

    monkeypatch.setattr(provisioner.Path, "unlink", original_unlink)
    assert (
        provisioner.provision_control_token(runtime_dir, token_path)
        is False
    )
    assert token_path.read_bytes() == payload
    assert os.lstat(token_path).st_nlink == 1
    assert not list(runtime_dir.glob(".control-token.*.tmp"))


def test_control_token_provisioner_recovers_prelink_crash(
    tmp_path,
    monkeypatch,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    original_unlink = Path.unlink
    original_link = os.link

    class SimulatedCrash(BaseException):
        pass

    def crash_before_link(*_args, **_kwargs):
        raise SimulatedCrash

    def preserve_crash_temp(path, *args, **kwargs):
        if path.name.startswith(".control-token."):
            raise SimulatedCrash
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(provisioner.os, "link", crash_before_link)
    monkeypatch.setattr(
        provisioner.Path,
        "unlink",
        preserve_crash_temp,
    )
    with pytest.raises(SimulatedCrash):
        provisioner.provision_control_token(runtime_dir, token_path)
    orphan = next(runtime_dir.glob(".control-token.*.tmp"))
    assert os.lstat(orphan).st_nlink == 1
    assert not token_path.exists()

    monkeypatch.setattr(provisioner.os, "link", original_link)
    monkeypatch.setattr(provisioner.Path, "unlink", original_unlink)
    monkeypatch.setattr(provisioner, "_pid_is_alive", lambda _pid: False)
    assert provisioner.provision_control_token(runtime_dir, token_path) is True
    assert token_path.exists()
    assert not orphan.exists()


def test_control_token_atomic_create_handles_concurrent_first_writers(
    tmp_path,
    monkeypatch,
):
    provisioner = _load_control_token_provisioner()
    runtime_dir = _create_sandbox_runtime(tmp_path)
    token_path = runtime_dir / "control-token"
    original_link = os.link
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def racing_link(source, destination):
        barrier.wait(timeout=5)
        return original_link(source, destination)

    def provision():
        try:
            results.append(
                provisioner.provision_control_token(
                    runtime_dir,
                    token_path,
                )
            )
        except BaseException as exc:  # pragma: no branch - captured for assert
            errors.append(exc)

    monkeypatch.setattr(provisioner.os, "link", racing_link)
    workers = [threading.Thread(target=provision) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert not errors
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(results) == [False, True]
    assert re.fullmatch(rb"[0-9a-f]{64}", token_path.read_bytes())
    assert os.lstat(token_path).st_nlink == 1
    assert not list(runtime_dir.glob(".control-token.*.tmp"))

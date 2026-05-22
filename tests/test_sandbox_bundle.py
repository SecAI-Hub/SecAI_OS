from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.yaml"
NVIDIA_GPU_COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.gpu.nvidia.yaml"
ROCM_GPU_COMPOSE_PATH = REPO_ROOT / "deploy" / "sandbox" / "compose.gpu.rocm.yaml"
DOC_PATH = REPO_ROOT / "docs" / "install" / "sandbox.md"
PINNED_ALPINE_HELPER = "docker.io/library/alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"


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

    assert services["agent"]["environment"]["BIND_ADDR"] == "unix:/run/secure-ai/agent.sock"
    assert "secai-run:/run/secure-ai" in services["agent"]["volumes"]
    assert "secai-run:/run/secure-ai" in services["ui"]["volumes"]
    assert "/run/secure-ai-ui:rw,noexec,nosuid,nodev,mode=0770,uid=65534,gid=65534,size=16m" in services["ui"]["tmpfs"]

    for name in ["ui", "agent", "search-mediator", "registry", "tool-firewall", "airlock"]:
        service = services[name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert "healthcheck" in service
    assert services["ui"]["healthcheck"]["test"][0] == "CMD"
    assert services["agent"]["healthcheck"]["test"][0] == "CMD"
    assert services["search-mediator"]["healthcheck"]["test"][0] == "CMD"

    assert services["ui"]["depends_on"]["agent"]["condition"] == "service_healthy"
    assert services["ui"]["depends_on"]["search-mediator"]["condition"] == "service_healthy"
    assert services["agent"]["depends_on"]["registry"]["condition"] == "service_healthy"
    assert services["tor"]["profiles"] == ["search"]
    assert services["searxng"]["profiles"] == ["search"]
    assert services["searxng"]["depends_on"]["tor"]["condition"] == "service_healthy"
    assert "./runtime/policy:/etc/secure-ai/policy:ro" in services["registry"]["volumes"]
    assert "./runtime/config:/etc/secure-ai/config:ro" in services["ui"]["volumes"]
    assert services["search-mediator"]["networks"] == ["default", "search"]

    assert "secai-run" in data["volumes"]
    assert data["networks"]["search"]["internal"] is True


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
        "services/ui/entrypoint.py",
        "services/search-mediator/entrypoint.py",
        "scripts/sandbox/ui-entrypoint.sh",
        "scripts/sandbox/search-mediator-entrypoint.sh",
        "scripts/sandbox/render_runtime.py",
        "scripts/sandbox/start.sh",
        "scripts/sandbox/stop.sh",
        "scripts/sandbox/start.ps1",
        "scripts/sandbox/stop.ps1",
        "secai-sandbox.cmd",
    ]:
        assert (REPO_ROOT / rel_path).exists()


def test_sandbox_start_helpers_use_digest_pinned_alpine():
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
    assert "taskkill" in control_server
    assert 'encoding="utf-8"' in control_server
    assert 'errors="replace"' in control_server
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


def test_sandbox_stop_helpers_include_optional_profiles():
    shell_helper = (REPO_ROOT / "scripts" / "sandbox" / "stop.sh").read_text(
        encoding="utf-8"
    )
    powershell_helper = (REPO_ROOT / "scripts" / "sandbox" / "stop.ps1").read_text(
        encoding="utf-8"
    )

    for profile in ("search", "llm", "diffusion"):
        assert f"--profile {profile}" in shell_helper
        assert f"--profile {profile}" in powershell_helper


def test_optional_profiles_are_hardened_and_use_production_entrypoints():
    data = yaml.safe_load(COMPOSE_PATH.read_text())
    services = data["services"]

    inference = services["inference"]
    assert inference["read_only"] is True
    assert inference["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in inference["security_opt"]
    assert inference["user"] == "65534:65534"
    assert "secai-state:/var/lib/secure-ai:ro" in inference["volumes"]
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
    assert "2.12.0+cu132" in diffusion_containerfile
    assert "2.12.0+cpu" in diffusion_containerfile
    assert "cu124" not in diffusion_containerfile
    assert "rocm6.1" not in diffusion_containerfile


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
    import subprocess
    import sys

    runtime_dir = tmp_path / "runtime"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "sandbox" / "render_runtime.py"),
        "--repo-root",
        str(REPO_ROOT),
        "--runtime-dir",
        str(runtime_dir),
        "--enable-search",
        "--enable-airlock",
    ]
    subprocess.run(cmd, check=True)

    policy = yaml.safe_load((runtime_dir / "policy" / "policy.yaml").read_text())
    config = yaml.safe_load((runtime_dir / "config" / "appliance.yaml").read_text())
    profile_state = yaml.safe_load((runtime_dir / "state" / "profile.json").read_text())

    assert policy["search"]["enabled"] is True
    assert policy["airlock"]["enabled"] is True
    assert config["appliance"]["mode"] == "online-augmented"
    assert profile_state["active"] == "research"


def test_runtime_renderer_marks_diffusion_stack_as_full_lab(tmp_path):
    import subprocess
    import sys

    runtime_dir = tmp_path / "runtime"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "sandbox" / "render_runtime.py"),
        "--repo-root",
        str(REPO_ROOT),
        "--runtime-dir",
        str(runtime_dir),
        "--enable-diffusion",
    ]
    subprocess.run(cmd, check=True)

    profile_state = yaml.safe_load((runtime_dir / "state" / "profile.json").read_text())

    assert profile_state["active"] == "full_lab"

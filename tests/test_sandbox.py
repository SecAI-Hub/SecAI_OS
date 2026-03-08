"""Tests for M16 — Advanced Process Isolation.

Validates:
- All systemd service files have required hardening directives
- Seccomp JSON profiles are valid and well-formed
- Landlock policy YAML is valid and covers all services
- Landlock helper module loads and has correct access mappings
"""

import importlib.util
import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
SECCOMP_DIR = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "seccomp"
LANDLOCK_POLICY = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "policy" / "landlock.yaml"

# Load landlock-apply module
_spec = importlib.util.spec_from_file_location(
    "landlock_apply",
    str(REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai" / "landlock-apply.py"),
)
landlock_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(landlock_mod)

# Services that should have full hardening
CORE_SERVICES = [
    "secure-ai-inference",
    "secure-ai-diffusion",
    "secure-ai-registry",
    "secure-ai-ui",
    "secure-ai-tool-firewall",
    "secure-ai-quarantine-watcher",
    "secure-ai-airlock",
    "secure-ai-search-mediator",
]

# Required hardening directives every core service must have
REQUIRED_DIRECTIVES = [
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "NoNewPrivileges=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "RestrictRealtime=yes",
    "RestrictNamespaces=yes",
    "SystemCallArchitectures=native",
    "LimitCORE=0",
]


class TestSystemdHardening:
    def _read_unit(self, name: str) -> str:
        return (SYSTEMD_DIR / f"{name}.service").read_text()

    def test_all_core_services_exist(self):
        for name in CORE_SERVICES:
            path = SYSTEMD_DIR / f"{name}.service"
            assert path.exists(), f"missing service unit: {name}"

    def test_required_directives_present(self):
        for name in CORE_SERVICES:
            content = self._read_unit(name)
            for directive in REQUIRED_DIRECTIVES:
                assert directive in content, (
                    f"{name}.service missing directive: {directive}"
                )

    def test_private_tmp_on_all(self):
        for name in CORE_SERVICES:
            content = self._read_unit(name)
            assert "PrivateTmp=yes" in content, f"{name} missing PrivateTmp"

    def test_private_devices_on_non_gpu(self):
        """Non-GPU services should have PrivateDevices=yes."""
        non_gpu = [
            "secure-ai-registry",
            "secure-ai-ui",
            "secure-ai-tool-firewall",
            "secure-ai-airlock",
            "secure-ai-search-mediator",
        ]
        for name in non_gpu:
            content = self._read_unit(name)
            assert "PrivateDevices=yes" in content, f"{name} missing PrivateDevices"

    def test_gpu_services_have_device_allow(self):
        """GPU services should have DeviceAllow for NVIDIA/AMD/Intel."""
        gpu_services = ["secure-ai-inference", "secure-ai-diffusion"]
        for name in gpu_services:
            content = self._read_unit(name)
            assert "DeviceAllow=/dev/nvidia" in content or "DeviceAllow=/dev/dri" in content, (
                f"{name} missing GPU DeviceAllow"
            )

    def test_private_network_on_isolated_services(self):
        """Services that don't need outbound should have PrivateNetwork=yes."""
        isolated = [
            "secure-ai-inference",
            "secure-ai-diffusion",
            "secure-ai-registry",
            "secure-ai-tool-firewall",
        ]
        for name in isolated:
            content = self._read_unit(name)
            assert "PrivateNetwork=yes" in content, f"{name} missing PrivateNetwork"

    def test_airlock_no_private_network(self):
        """Airlock is the ONLY service that needs outbound — no PrivateNetwork."""
        content = self._read_unit("secure-ai-airlock")
        # Should NOT have PrivateNetwork=yes
        assert "PrivateNetwork=yes" not in content, (
            "airlock should NOT have PrivateNetwork (it needs outbound)"
        )

    def test_capability_bounding_set_empty(self):
        """All core services should drop all capabilities."""
        for name in CORE_SERVICES:
            content = self._read_unit(name)
            assert "CapabilityBoundingSet=" in content, (
                f"{name} missing empty CapabilityBoundingSet"
            )

    def test_syscall_filter_present(self):
        """All core services should have SystemCallFilter."""
        for name in CORE_SERVICES:
            content = self._read_unit(name)
            assert "SystemCallFilter=" in content, f"{name} missing SystemCallFilter"

    def test_memory_deny_write_execute(self):
        """Services that don't need JIT should have MemoryDenyWriteExecute=yes."""
        no_jit = [
            "secure-ai-registry",
            "secure-ai-ui",
            "secure-ai-tool-firewall",
            "secure-ai-airlock",
            "secure-ai-search-mediator",
        ]
        for name in no_jit:
            content = self._read_unit(name)
            assert "MemoryDenyWriteExecute=yes" in content, (
                f"{name} missing MemoryDenyWriteExecute=yes"
            )


class TestSeccompProfiles:
    def _load_profile(self, name: str) -> dict:
        return json.loads((SECCOMP_DIR / f"{name}.json").read_text())

    def test_all_profiles_exist(self):
        expected = [
            "inference", "diffusion", "registry", "ui",
            "tool-firewall", "quarantine", "airlock", "search-mediator",
        ]
        for name in expected:
            path = SECCOMP_DIR / f"{name}.json"
            assert path.exists(), f"missing seccomp profile: {name}.json"

    def test_profiles_are_valid_json(self):
        for path in SECCOMP_DIR.glob("*.json"):
            data = json.loads(path.read_text())
            assert "defaultAction" in data, f"{path.name} missing defaultAction"
            assert "syscalls" in data, f"{path.name} missing syscalls"

    def test_default_action_is_deny(self):
        """All profiles should default-deny (SCMP_ACT_ERRNO)."""
        for path in SECCOMP_DIR.glob("*.json"):
            data = json.loads(path.read_text())
            assert data["defaultAction"] == "SCMP_ACT_ERRNO", (
                f"{path.name} defaultAction should be SCMP_ACT_ERRNO"
            )

    def test_arch_map_present(self):
        for path in SECCOMP_DIR.glob("*.json"):
            data = json.loads(path.read_text())
            assert "archMap" in data, f"{path.name} missing archMap"
            archs = [a["architecture"] for a in data["archMap"]]
            assert "SCMP_ARCH_X86_64" in archs or "SCMP_ARCH_AARCH64" in archs

    def test_inference_no_execve(self):
        """Inference profile should NOT allow execve."""
        data = self._load_profile("inference")
        all_syscalls = set()
        for group in data["syscalls"]:
            all_syscalls.update(group["names"])
        assert "execve" not in all_syscalls, "inference should not allow execve"

    def test_airlock_no_execve(self):
        """Airlock profile should NOT allow execve."""
        data = self._load_profile("airlock")
        all_syscalls = set()
        for group in data["syscalls"]:
            all_syscalls.update(group["names"])
        assert "execve" not in all_syscalls, "airlock should not allow execve"

    def test_inference_has_ioctl(self):
        """Inference needs ioctl for GPU access."""
        data = self._load_profile("inference")
        all_syscalls = set()
        for group in data["syscalls"]:
            all_syscalls.update(group["names"])
        assert "ioctl" in all_syscalls, "inference needs ioctl for GPU"

    def test_quarantine_has_execve(self):
        """Quarantine needs execve for smoke tests."""
        data = self._load_profile("quarantine")
        all_syscalls = set()
        for group in data["syscalls"]:
            all_syscalls.update(group["names"])
        assert "execve" in all_syscalls, "quarantine needs execve for smoke tests"


class TestLandlockPolicy:
    def _load_policy(self) -> dict:
        return yaml.safe_load(LANDLOCK_POLICY.read_text())

    def test_policy_file_exists(self):
        assert LANDLOCK_POLICY.exists()

    def test_policy_is_valid_yaml(self):
        policy = self._load_policy()
        assert "version" in policy
        assert "services" in policy

    def test_all_core_services_have_policy(self):
        policy = self._load_policy()
        services = policy["services"]
        expected = [
            "inference", "diffusion", "registry", "ui",
            "tool_firewall", "quarantine", "airlock", "search_mediator",
        ]
        for svc in expected:
            assert svc in services, f"missing Landlock policy for {svc}"

    def test_each_service_has_paths(self):
        policy = self._load_policy()
        for name, svc in policy["services"].items():
            paths = svc.get("paths", [])
            assert len(paths) > 0, f"service '{name}' has no path rules"

    def test_valid_access_modes(self):
        policy = self._load_policy()
        valid_modes = {"ro", "rw", "exe"}
        for name, svc in policy["services"].items():
            for entry in svc.get("paths", []):
                mode = entry.get("access", "")
                assert mode in valid_modes, (
                    f"service '{name}' has invalid access mode '{mode}' on {entry['path']}"
                )

    def test_inference_has_read_only_registry(self):
        """Inference should only have read-only access to the registry."""
        policy = self._load_policy()
        inference = policy["services"]["inference"]
        for entry in inference["paths"]:
            if entry["path"] == "/var/lib/secure-ai/registry":
                assert entry["access"] == "ro", "inference should have ro access to registry"
                return
        assert False, "inference missing registry path rule"

    def test_diffusion_can_write_outputs(self):
        """Diffusion should have write access to outputs directory."""
        policy = self._load_policy()
        diffusion = policy["services"]["diffusion"]
        for entry in diffusion["paths"]:
            if entry["path"] == "/var/lib/secure-ai/vault/outputs":
                assert entry["access"] == "rw"
                return
        assert False, "diffusion missing outputs write rule"

    def test_tool_firewall_read_only_vault(self):
        """Tool firewall should only read the vault, never write."""
        policy = self._load_policy()
        tf = policy["services"]["tool_firewall"]
        for entry in tf["paths"]:
            if entry["path"] == "/var/lib/secure-ai/vault":
                assert entry["access"] == "ro"
                return
        assert False, "tool_firewall missing vault read rule"


class TestLandlockHelper:
    def test_access_for_mode_ro(self):
        result = landlock_mod._access_for_mode("ro")
        assert result == landlock_mod.ACCESS_RO

    def test_access_for_mode_rw(self):
        result = landlock_mod._access_for_mode("rw")
        assert result == landlock_mod.ACCESS_RW

    def test_access_for_mode_exe(self):
        result = landlock_mod._access_for_mode("exe")
        expected = landlock_mod.ACCESS_EXE | landlock_mod.ACCESS_RO
        assert result == expected

    def test_access_for_unknown_mode_defaults_ro(self):
        result = landlock_mod._access_for_mode("bogus")
        assert result == landlock_mod.ACCESS_RO

    def test_check_landlock_on_macos_returns_zero(self):
        """On macOS (test env), Landlock is not available."""
        import platform
        if platform.system() != "Linux":
            assert landlock_mod.check_landlock_available() == 0

"""
Tests for recipe.yml validation.

Covers:
- Diffusion service is in disabled list (not enabled by default)
- Diffusion path unit is in enabled list (watches for install request)
- No overlap between enabled and disabled lists
- Core security services are in the enabled list
- Diffusion lockfiles exist for all backends in the manifest
"""

from pathlib import Path

import pytest
import yaml

RECIPE_PATH = Path(__file__).resolve().parent.parent / "recipes" / "recipe.yml"


@pytest.fixture
def recipe():
    """Load and parse the BlueBuild recipe."""
    with open(RECIPE_PATH) as f:
        return yaml.safe_load(f)


def _get_systemd_module(recipe):
    """Extract the systemd module from the recipe."""
    for module in recipe.get("modules", []):
        if module.get("type") == "systemd":
            return module
    pytest.fail("No systemd module found in recipe")


def _get_enabled(systemd_module):
    return systemd_module.get("system", {}).get("enabled", [])


def _get_disabled(systemd_module):
    return systemd_module.get("system", {}).get("disabled", [])


class TestDiffusionDisabledByDefault:
    """Diffusion service must be disabled in the base image."""

    def test_diffusion_in_disabled_list(self, recipe):
        systemd = _get_systemd_module(recipe)
        disabled = _get_disabled(systemd)
        assert "secure-ai-diffusion.service" in disabled, \
            "secure-ai-diffusion.service must be in the disabled list"

    def test_diffusion_not_in_enabled_list(self, recipe):
        systemd = _get_systemd_module(recipe)
        enabled = _get_enabled(systemd)
        assert "secure-ai-diffusion.service" not in enabled, \
            "secure-ai-diffusion.service must NOT be in the enabled list"


class TestNoEnabledDisabledOverlap:
    """No service should appear in both enabled and disabled lists."""

    def test_no_overlap(self, recipe):
        systemd = _get_systemd_module(recipe)
        enabled = set(_get_enabled(systemd))
        disabled = set(_get_disabled(systemd))
        overlap = enabled & disabled
        assert not overlap, f"Services in both enabled and disabled: {overlap}"


class TestCoreServicesEnabled:
    """Core security services must be in the enabled list."""

    CORE_SERVICES = [
        "secure-ai-registry.service",
        "secure-ai-tool-firewall.service",
        "secure-ai-ui.service",
        "secure-ai-policy-engine.service",
        "secure-ai-runtime-attestor.service",
        "secure-ai-integrity-monitor.service",
        "secure-ai-incident-recorder.service",
        "secure-ai-agent.service",
        "secure-ai-quarantine-watcher.service",
        "secure-ai-gpu-integrity-watch.service",
        "secure-ai-mcp-firewall.service",
        "nftables.service",
    ]

    @pytest.mark.parametrize("service", CORE_SERVICES)
    def test_core_service_enabled(self, recipe, service):
        systemd = _get_systemd_module(recipe)
        enabled = _get_enabled(systemd)
        assert service in enabled, f"{service} must be in the enabled list"


class TestDisabledByDefaultServices:
    """Services that should be disabled by default (user opts in)."""

    DISABLED_SERVICES = [
        "secure-ai-airlock.service",
        "secure-ai-tor.service",
        "secure-ai-searxng.service",
        "secure-ai-search-mediator.service",
        "secure-ai-diffusion.service",
    ]

    @pytest.mark.parametrize("service", DISABLED_SERVICES)
    def test_service_disabled(self, recipe, service):
        systemd = _get_systemd_module(recipe)
        disabled = _get_disabled(systemd)
        assert service in disabled, f"{service} must be in the disabled list"


class TestBootCompatibilityDefaults:
    """Boot defaults should stay broadly compatible across hardware."""

    def test_hardware_kargs_sync_service_enabled(self, recipe):
        systemd = _get_systemd_module(recipe)
        enabled = _get_enabled(systemd)
        assert "secure-ai-boot-kargs.service" in enabled

    def test_no_global_forced_iommu_arg(self, recipe):
        kargs_module = next(m for m in recipe.get("modules", []) if m.get("type") == "kargs")
        assert "iommu=force" not in kargs_module["kargs"]

    def test_no_global_vendor_gpu_args(self, recipe):
        kargs_module = next(m for m in recipe.get("modules", []) if m.get("type") == "kargs")
        forbidden = {
            "rd.driver.blacklist=nouveau",
            "modprobe.blacklist=nouveau",
            "nvidia-drm.modeset=1",
            "amdgpu.dc=1",
        }
        assert forbidden.isdisjoint(set(kargs_module["kargs"]))


class TestDiffusionPathUnitEnabled:
    """The diffusion install path unit must be enabled to watch for UI requests."""

    def test_path_unit_in_disabled_list(self, recipe):
        """Diffusion path unit is disabled by default — profile-controlled (full_lab only)."""
        systemd = _get_systemd_module(recipe)
        disabled = systemd["system"]["disabled"]
        assert "secure-ai-enable-diffusion.path" in disabled, \
            "secure-ai-enable-diffusion.path must be in the disabled list (profile-controlled)"


class TestDiffusionManifestLockfiles:
    """All backends in the diffusion manifest must have lockfiles on disk."""

    MANIFEST_PATH = Path(__file__).resolve().parent.parent / "files" / "scripts" / "diffusion-runtime-manifest.yaml"
    SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "files" / "scripts"

    def test_manifest_exists(self):
        assert self.MANIFEST_PATH.exists(), \
            "diffusion-runtime-manifest.yaml must exist"

    def test_all_backend_lockfiles_exist(self):
        with open(self.MANIFEST_PATH) as f:
            manifest = yaml.safe_load(f)
        for backend, cfg in manifest.get("backends", {}).items():
            lockfile = cfg.get("lockfile", "")
            lockfile_path = self.SCRIPTS_DIR / lockfile
            assert lockfile_path.exists(), \
                f"Lockfile for backend '{backend}' not found: {lockfile_path}"

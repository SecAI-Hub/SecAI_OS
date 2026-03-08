"""Tests for M18 — Memory Protection.

Validates:
- sysctl hardening: vm.swappiness=0, core_pattern, core_uses_pid
- Kernel args include zswap.enabled=0
- SecureBuffer mlock helper works correctly
- TEE detection script exists and covers AMD SEV / Intel TDX
- firstboot.sh includes memory protection checks
- appliance.yaml has memory_protection config section
"""

import ctypes
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

REPO_ROOT = Path(__file__).parent.parent
SYSCTL_PATH = REPO_ROOT / "files" / "system" / "etc" / "sysctl.d" / "90-secure-ai.conf"
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"


class TestSysctlHardening:
    def test_swappiness_zero(self):
        content = SYSCTL_PATH.read_text()
        assert "vm.swappiness = 0" in content

    def test_core_pattern_false(self):
        content = SYSCTL_PATH.read_text()
        assert "kernel.core_pattern = |/bin/false" in content

    def test_core_uses_pid(self):
        content = SYSCTL_PATH.read_text()
        assert "kernel.core_uses_pid = 0" in content

    def test_suid_dumpable(self):
        content = SYSCTL_PATH.read_text()
        assert "fs.suid_dumpable = 0" in content

    def test_mmap_min_addr(self):
        content = SYSCTL_PATH.read_text()
        assert "vm.mmap_min_addr = 65536" in content


class TestKernelArgs:
    def test_init_on_free(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        kargs_module = next(m for m in recipe["modules"] if m.get("type") == "kargs")
        assert "init_on_free=1" in kargs_module["append"]

    def test_init_on_alloc(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        kargs_module = next(m for m in recipe["modules"] if m.get("type") == "kargs")
        assert "init_on_alloc=1" in kargs_module["append"]

    def test_zswap_disabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        kargs_module = next(m for m in recipe["modules"] if m.get("type") == "kargs")
        assert "zswap.enabled=0" in kargs_module["append"]

    def test_swap_disabled(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        kargs_module = next(m for m in recipe["modules"] if m.get("type") == "kargs")
        assert "systemd.swap=0" in kargs_module["append"]


class TestTEEDetection:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "detect-tee.sh").exists()

    def test_script_executable(self):
        import os
        assert os.access(SCRIPTS_DIR / "detect-tee.sh", os.X_OK)

    def test_detects_amd_sev(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "detect_amd_sev" in content
        assert "SEV" in content
        assert "sev" in content.lower()

    def test_detects_intel_tdx(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "detect_intel_tdx" in content
        assert "TDX" in content
        assert "tdx_guest" in content or "tdx-guest" in content

    def test_detects_intel_tme(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "detect_intel_tme" in content
        assert "TME" in content

    def test_detects_arm_cca(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "detect_arm_cca" in content
        assert "CCA" in content

    def test_writes_env_file(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "tee.env" in content
        assert "TEE_TYPE" in content
        assert "TEE_ACTIVE" in content
        assert "MEM_ENCRYPT" in content

    def test_sev_snp_detection(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "SEV-SNP" in content

    def test_sev_es_detection(self):
        content = (SCRIPTS_DIR / "detect-tee.sh").read_text()
        assert "SEV-ES" in content


class TestSecureBuffer:
    def test_create_and_read(self):
        from services.common.mlock_helper import SecureBuffer
        data = b"secret-key-material"
        buf = SecureBuffer(data)
        assert buf.read() == data
        buf.close()

    def test_close_zeroes_buffer(self):
        from services.common.mlock_helper import SecureBuffer
        data = b"sensitive-data-1234"
        buf = SecureBuffer(data)
        buf.close()
        # After close, the internal buffer should be zeroed
        raw = bytes(buf._buf)
        assert raw == b"\x00" * len(data)

    def test_read_after_close_raises(self):
        from services.common.mlock_helper import SecureBuffer
        buf = SecureBuffer(b"test")
        buf.close()
        import pytest
        with pytest.raises(ValueError, match="closed"):
            buf.read()

    def test_context_manager(self):
        from services.common.mlock_helper import SecureBuffer
        data = b"context-manager-test"
        with SecureBuffer(data) as buf:
            assert buf.read() == data
        # After exiting, buffer should be closed
        assert buf._closed

    def test_size_property(self):
        from services.common.mlock_helper import SecureBuffer
        data = b"twelve bytes"
        buf = SecureBuffer(data)
        assert buf.size == len(data)
        assert len(buf) == len(data)
        buf.close()

    def test_repr(self):
        from services.common.mlock_helper import SecureBuffer
        buf = SecureBuffer(b"x")
        r = repr(buf)
        assert "SecureBuffer" in r
        assert "size=1" in r
        buf.close()
        assert "closed" in repr(buf)

    def test_double_close_safe(self):
        from services.common.mlock_helper import SecureBuffer
        buf = SecureBuffer(b"data")
        buf.close()
        buf.close()  # should not raise

    def test_get_mlock_limit(self):
        from services.common.mlock_helper import get_mlock_limit
        limit = get_mlock_limit()
        assert isinstance(limit, int)


class TestFirstbootMemoryChecks:
    def test_checks_zswap(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "zswap" in content

    def test_checks_core_pattern(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "core_pattern" in content
        assert "|/bin/false" in content

    def test_checks_swappiness(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "swappiness" in content

    def test_runs_tee_detection(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "detect-tee.sh" in content

    def test_logs_tee_results(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "tee.env" in content
        assert "MEM_ENCRYPT" in content


class TestApplianceConfig:
    def test_memory_protection_section(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "memory_protection" in config

    def test_swap_disabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["memory_protection"]["swap_disabled"] is True

    def test_zswap_disabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["memory_protection"]["zswap_disabled"] is True

    def test_core_dumps_disabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["memory_protection"]["core_dumps_disabled"] is True

    def test_mlock_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["memory_protection"]["mlock_sensitive_data"] is True

    def test_tee_detection_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["memory_protection"]["tee_detection"] is True

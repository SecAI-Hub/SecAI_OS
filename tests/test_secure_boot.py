"""Tests for M17 — Secure Boot Chain + Measured Boot.

Validates:
- MOK generation script exists and is well-formed
- TPM2 seal/unseal script exists and handles all subcommands
- Secure Boot enrollment script exists
- Boot chain verification script exists and produces valid JSON output
- Boot verify systemd service is properly configured
- Firstboot includes TPM2/SB checks
- recipe.yml includes required packages
- appliance.yaml has secure_boot config section
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
BUILD_SCRIPTS = REPO_ROOT / "files" / "scripts"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"


class TestMOKGeneration:
    def test_generate_mok_script_exists(self):
        assert (BUILD_SCRIPTS / "generate-mok.sh").exists()

    def test_generate_mok_creates_correct_files(self):
        content = (BUILD_SCRIPTS / "generate-mok.sh").read_text()
        assert "secureai-mok.key" in content
        assert "secureai-mok.pem" in content
        assert "secureai-mok.der" in content

    def test_generate_mok_uses_rsa4096(self):
        content = (BUILD_SCRIPTS / "generate-mok.sh").read_text()
        assert "rsa:4096" in content

    def test_generate_mok_sets_permissions(self):
        content = (BUILD_SCRIPTS / "generate-mok.sh").read_text()
        assert "chmod 600" in content  # private key


class TestTPM2SealScript:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "tpm2-seal-vault.sh").exists()

    def test_supports_all_subcommands(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "cmd_seal" in content
        assert "cmd_unseal" in content
        assert "cmd_reseal" in content
        assert "cmd_status" in content

    def test_pcr_binding(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        # Should bind to PCR 0, 2, 4, 7
        assert "sha256:0,2,4,7" in content

    def test_checks_tpm2_device(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "/dev/tpmrm0" in content
        assert "/dev/tpm0" in content

    def test_checks_vtpm(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "vtpm" in content or "virtual" in content

    def test_writes_audit_events(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "tpm2-audit.jsonl" in content

    def test_passphrase_fallback(self):
        """On unseal failure, should fall back to passphrase."""
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "passphrase" in content.lower()
        assert "pcr_mismatch" in content

    def test_securely_deletes_key(self):
        content = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "shred" in content


class TestSecureBootEnrollment:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "enroll-secureboot.sh").exists()

    def test_checks_secure_boot_state(self):
        content = (SCRIPTS_DIR / "enroll-secureboot.sh").read_text()
        assert "mokutil --sb-state" in content

    def test_checks_mok_enrollment(self):
        content = (SCRIPTS_DIR / "enroll-secureboot.sh").read_text()
        assert "mokutil --list-enrolled" in content or "mokutil --import" in content

    def test_supports_check_only(self):
        content = (SCRIPTS_DIR / "enroll-secureboot.sh").read_text()
        assert "--check-only" in content


class TestBootChainVerification:
    def test_verify_script_exists(self):
        assert (SCRIPTS_DIR / "verify-boot-chain.sh").exists()

    def test_checks_all_components(self):
        content = (SCRIPTS_DIR / "verify-boot-chain.sh").read_text()
        assert "check_secure_boot" in content
        assert "check_tpm2" in content
        assert "check_kernel_signature" in content
        assert "check_ostree_signature" in content

    def test_writes_json_result(self):
        content = (SCRIPTS_DIR / "verify-boot-chain.sh").read_text()
        assert "boot-verify-last.json" in content

    def test_result_includes_all_checks(self):
        content = (SCRIPTS_DIR / "verify-boot-chain.sh").read_text()
        assert '"secure_boot"' in content
        assert '"tpm2"' in content
        assert '"kernel_signature"' in content
        assert '"ostree_signature"' in content


class TestBootVerifyService:
    def test_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-boot-verify.service").exists()

    def test_runs_before_main_services(self):
        content = (SYSTEMD_DIR / "secure-ai-boot-verify.service").read_text()
        assert "Before=secure-ai-registry.service" in content

    def test_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-boot-verify.service").read_text()
        assert "Type=oneshot" in content

    def test_has_sandboxing(self):
        content = (SYSTEMD_DIR / "secure-ai-boot-verify.service").read_text()
        assert "ProtectHome=yes" in content
        # boot-verify needs privilege escalation for TPM2/EFI access,
        # so NoNewPrivileges is intentionally absent. Check for other hardening.
        assert "ProtectKernelTunables=yes" in content
        assert "SystemCallFilter=" in content


class TestFirstbootIntegration:
    def test_firstboot_checks_secure_boot(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "enroll-secureboot.sh" in content

    def test_firstboot_checks_tpm2(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "tpm2-seal-vault.sh" in content

    def test_firstboot_runs_boot_verify(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "verify-boot-chain.sh" in content

    def test_firstboot_creates_tpm2_dir(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "keys/tpm2" in content

    def test_firstboot_service_keeps_needed_capabilities(self):
        content = (SYSTEMD_DIR / "secure-ai-firstboot.service").read_text()
        assert "CapabilityBoundingSet=CAP_CHOWN" in content
        assert "CAP_SYS_ADMIN" in content
        assert "CAP_NET_ADMIN" in content

    def test_firstboot_service_can_write_kernel_tunables(self):
        content = (SYSTEMD_DIR / "secure-ai-firstboot.service").read_text()
        assert "ProtectKernelTunables=no" in content

    def test_firstboot_service_allows_swapoff(self):
        content = (SYSTEMD_DIR / "secure-ai-firstboot.service").read_text()
        assert "@swap" not in content


class TestRecipeIncludes:
    def test_recipe_includes_mokutil(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        packages = recipe["modules"][0]["install"]
        assert "mokutil" in packages

    def test_recipe_includes_sbsigntools(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        packages = recipe["modules"][0]["install"]
        assert "sbsigntools" in packages

    def test_recipe_includes_tpm2_tools(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        packages = recipe["modules"][0]["install"]
        assert "tpm2-tools" in packages

    def test_recipe_enables_boot_verify(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-boot-verify.service" in enabled


class TestApplianceConfig:
    def test_secure_boot_section_exists(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "secure_boot" in config

    def test_tpm2_pcr_binding(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["secure_boot"]["tpm2_pcr_binding"] == "sha256:0,2,4,7"

    def test_passphrase_fallback_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["secure_boot"]["passphrase_fallback"] is True

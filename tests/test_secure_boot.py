"""Secure Boot and verified systemd TPM2 enrollment tests."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
BUILD_SCRIPTS = REPO_ROOT / "files" / "scripts"
SYSTEMD_DIR = (
    REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
)
CONFIG_PATH = (
    REPO_ROOT
    / "files"
    / "system"
    / "etc"
    / "secure-ai"
    / "config"
    / "appliance.yaml"
)
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"
TPM_HELPER = SCRIPTS_DIR / "secure-tpm-vault.py"
LUKS_HELPER = SCRIPTS_DIR / "secure_luks.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def secure_luks():
    return load_module("secure_luks", LUKS_HELPER)


@pytest.fixture
def secure_tpm(secure_luks):
    del secure_luks
    return load_module("secure_tpm_vault", TPM_HELPER)


class TestMOKUtility:
    def test_generation_is_an_operator_utility_not_a_shipped_key(self):
        content = (BUILD_SCRIPTS / "generate-mok.sh").read_text()
        assert "rsa:4096" in content
        assert "chmod 600" in content
        tracked = {
            path.name
            for path in REPO_ROOT.rglob("secureai-mok.key")
            if ".git" not in path.parts
        }
        assert not tracked

    def test_enrollment_checks_secure_boot_and_mok_state(self):
        content = (SCRIPTS_DIR / "enroll-secureboot.sh").read_text()
        assert "mokutil --sb-state" in content
        assert "mokutil --list-enrolled" in content or "mokutil --import" in content
        assert "--check-only" in content


class TestLUKSConfiguration:
    def test_duplicate_mapper_entries_fail_closed(
        self, tmp_path: Path, secure_luks
    ):
        crypttab = tmp_path / "crypttab"
        crypttab.write_text(
            "secure-ai-vault UUID=11111111-1111 none luks\n"
            "secure-ai-vault UUID=22222222-2222 none luks\n"
        )
        with pytest.raises(secure_luks.LUKSError, match="exactly one"):
            secure_luks.parse_crypttab(crypttab)

    def test_tpm_options_are_updated_atomically(
        self, tmp_path: Path, secure_luks
    ):
        crypttab = tmp_path / "crypttab"
        crypttab.write_text(
            "# vault\nsecure-ai-vault UUID=11111111-1111 none luks,nodev\n"
        )
        crypttab.chmod(0o600)
        secure_luks.update_crypttab_tpm2(
            enabled=True,
            path=crypttab,
            require_root_owner=False,
        )
        enabled = crypttab.read_text()
        assert "tpm2-device=auto" in enabled
        assert "tpm2-pcrs=0+2+4+7" in enabled
        secure_luks.update_crypttab_tpm2(
            enabled=False,
            path=crypttab,
            require_root_owner=False,
        )
        disabled = crypttab.read_text()
        assert "tpm2-device=auto" not in disabled
        assert "tpm2-pcrs=" not in disabled
        assert stat_mode(crypttab) == 0o600

    def test_duplicate_luks_metadata_keys_are_rejected(self, secure_luks):
        def runner(_args, **_kwargs):
            return subprocess.CompletedProcess(
                [],
                0,
                stdout=b'{"keyslots":{},"keyslots":{},"tokens":{}}',
                stderr=b"",
            )

        with pytest.raises(secure_luks.LUKSError, match="invalid JSON"):
            secure_luks.luks_metadata(Path("/dev/fake"), runner=runner)

    def test_tpm_token_count_is_exact(self, secure_luks):
        metadata = {
            "keyslots": {"0": {}, "1": {}},
            "tokens": {
                "0": {"type": "systemd-tpm2"},
                "1": {"type": "other"},
            },
        }
        assert secure_luks.keyslot_count(metadata) == 2
        assert secure_luks.tpm2_token_count(metadata) == 1


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


class TestTPMEnrollment:
    def test_entrypoint_and_helper_are_executable(self):
        for path in (SCRIPTS_DIR / "tpm2-seal-vault.sh", TPM_HELPER, LUKS_HELPER):
            assert path.exists()
            assert os.access(path, os.X_OK)

    def test_uses_native_luks2_systemd_token_enrollment(self):
        content = TPM_HELPER.read_text()
        assert "systemd-cryptenroll" in content
        assert "--wipe-slot=tpm2" in content
        assert "--tpm2-device=auto" in content
        assert "0:sha256+2:sha256+4:sha256+7:sha256" in content
        assert "tpm2_createprimary" not in content
        assert "tpm2_evictcontrol" not in content
        assert "/tmp/secai" not in content
        assert "shred" not in content

    def test_recovery_keyslot_is_verified_after_enrollment(self):
        content = TPM_HELPER.read_text()
        assert "keyslot_count(after) < 2" in content
        assert "passphrase recovery slot" in content

    def test_vtpm_requires_explicit_degraded_acknowledgement(
        self, secure_tpm, monkeypatch
    ):
        monkeypatch.setattr(secure_tpm, "tpm_available", lambda: True)
        monkeypatch.setattr(secure_tpm, "virtualization_type", lambda: "kvm")
        with pytest.raises(secure_tpm.TPMError, match="--allow-vtpm"):
            secure_tpm.enroll(allow_vtpm=False, allow_insecure_boot=False)

    def test_secure_boot_is_required_by_default(self, secure_tpm, monkeypatch):
        monkeypatch.setattr(secure_tpm, "tpm_available", lambda: True)
        monkeypatch.setattr(secure_tpm, "virtualization_type", lambda: "none")
        monkeypatch.setattr(secure_tpm, "secure_boot_enabled", lambda: False)
        with pytest.raises(secure_tpm.TPMError, match="Secure Boot"):
            secure_tpm.enroll(allow_vtpm=False, allow_insecure_boot=False)

    def test_mutating_cli_defaults_are_fail_closed(self, secure_tpm):
        seal = secure_tpm.parse_args(["seal"])
        assert seal.allow_vtpm is False
        assert seal.allow_insecure_boot is False
        wipe = secure_tpm.parse_args(["wipe"])
        assert wipe.destructive_confirmation is None

    def test_no_shell_state_is_sourced(self):
        content = TPM_HELPER.read_text()
        wrapper = (SCRIPTS_DIR / "tpm2-seal-vault.sh").read_text()
        assert "vm.env" not in content
        assert "source " not in wrapper
        assert "eval " not in wrapper


class TestBootChainIntegration:
    def test_boot_verifier_checks_all_components(self):
        content = (SCRIPTS_DIR / "verify-boot-chain.sh").read_text()
        for check in (
            "check_secure_boot",
            "check_tpm2",
            "check_kernel_signature",
            "check_ostree_signature",
        ):
            assert check in content
        assert "boot-verify-last.json" in content

    def test_boot_verifier_is_hardened_and_ordered(self):
        content = (SYSTEMD_DIR / "secure-ai-boot-verify.service").read_text()
        before = next(
            line.removeprefix("Before=").split()
            for line in content.splitlines()
            if line.startswith("Before=")
        )
        assert "secure-ai-registry.service" in before
        assert "secure-ai-tpm-attestation-setup.service" in before
        assert "secure-ai-runtime-attestor.service" in before
        assert "Type=oneshot" in content
        assert "NoNewPrivileges=yes" in content
        assert "CapabilityBoundingSet=" in content
        assert "PrivateNetwork=yes" in content

    def test_firstboot_runs_secure_boot_tpm_and_chain_checks(self):
        content = (SCRIPTS_DIR / "firstboot.sh").read_text()
        assert "enroll-secureboot.sh" in content
        assert "tpm2-seal-vault.sh" in content
        assert "verify-boot-chain.sh" in content


    def test_recipe_has_required_platform_tools(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        rpm_module = next(
            module
            for module in recipe["modules"]
            if module.get("type") == "rpm-ostree"
        )
        packages = rpm_module["install"]
        assert {"mokutil", "sbsigntools", "tpm2-tools"} <= set(packages)

    def test_configuration_preserves_passphrase_fallback(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())["secure_boot"]
        assert config["tpm2_pcr_binding"] == "sha256:0,2,4,7"
        assert config["passphrase_fallback"] is True

def _boot_function(script_name, start, end):
    source = (SCRIPTS_DIR / script_name).read_text()
    return source[source.index(start):source.index(end)]


@pytest.mark.parametrize("state", ["disabled", "unavailable"])
def test_secure_boot_status_reports_negative_states_without_aborting(tmp_path, state):
    command = _boot_function("enroll-secureboot.sh", "cmd_check() {", "cmd_enroll() {")
    script = """
set -euo pipefail
check_secure_boot() { printf '%s\\n' "$REPORTED_STATE"; return 1; }
write_state() { printf '%s:%s:%s\\n' "$@" > "$STATE_FILE"; }
""" + command + "\ncmd_check\n"
    result = subprocess.run(
        ["bash", "-c", script], env={**os.environ, "REPORTED_STATE": state,
                                    "STATE_FILE": str(tmp_path / "state")},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "state").read_text().startswith(state + ":false:")


@pytest.mark.parametrize("message,code,enrolled", [
    ("is already enrolled", 0, True),
    ("is not enrolled", 1, False),
    ("is already in the enrollment request", 0, False),
    ("is already in db", 0, False),
    ("is already in dbx", 0, False),
    ("", 0, False),
    ("is already enrolled", 255, False),
])
def test_mok_enrollment_requires_exact_completed_certificate_result(tmp_path, message, code, enrolled):
    cert = tmp_path / "mok.der"
    cert.write_bytes(b"synthetic certificate fixture")
    function = _boot_function("enroll-secureboot.sh", "check_mok_enrolled() {", "cmd_check() {")
    script = """
set -euo pipefail
mokutil() {
    [[ "$1" == '--test-key' && "$2" == "$MOK_DER" ]] || return 99
    printf '%s %s\\n' "$2" "$TEST_MESSAGE"
    return "$TEST_CODE"
}
""" + function + "\ncheck_mok_enrolled\n"
    result = subprocess.run(
        ["bash", "-c", script], env={**os.environ, "MOK_DER": str(cert),
                                    "TEST_MESSAGE": message, "TEST_CODE": str(code)},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == (0 if enrolled else 1), result.stderr


@pytest.mark.parametrize("state,enrolled,requested", [
    ("enabled", False, True),
    ("disabled", False, True),
    ("unavailable", False, False),
    ("enabled", True, False),
    ("disabled", True, False),
])
def test_explicit_mok_enrollment_handles_platform_status(tmp_path, state, enrolled, requested):
    cert = tmp_path / "mok.der"
    cert.write_bytes(b"synthetic certificate fixture")
    function = _boot_function("enroll-secureboot.sh", "cmd_enroll() {", "# --- Main ---")
    script = """
set -euo pipefail
check_secure_boot() {
    printf '%s\\n' "$REPORTED_STATE"
    [[ "$REPORTED_STATE" == enabled ]]
}
check_mok_enrolled() { [[ "$ALREADY_ENROLLED" == yes ]]; }
log() { printf '%s\\n' "$*"; }
write_state() { printf '%s:%s:%s\\n' "$@" > "$STATE_FILE"; }
mokutil() {
    [[ "$1" == '--import' && "$2" == "$MOK_DER" ]] || return 99
    printf 'requested\\n' > "$REQUEST_MARKER"
}
""" + function + "\ncmd_enroll\n"
    result = subprocess.run(
        ["bash", "-c", script], env={**os.environ, "REPORTED_STATE": state,
                                    "ALREADY_ENROLLED": "yes" if enrolled else "no",
                                    "MOK_DER": str(cert), "STATE_FILE": str(tmp_path / "state"),
                                    "REQUEST_MARKER": str(tmp_path / "request")},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "request").exists() is requested
    recorded = (tmp_path / "state").read_text()
    assert recorded.startswith(state + ":")
    if requested:
        assert ":pending:" in recorded
    if state == "disabled":
        assert "does not enable firmware or shim validation" in result.stdout


@pytest.mark.parametrize("output,code,expected", [
    ("SecureBoot enabled\n", 0, "enabled"),
    ("SecureBoot disabled\n", 0, "disabled"),
    ("SecureBoot enabled\nSecureBoot validation is disabled in shim\n", 0, "disabled"),
    ("SecureBoot enabled\nSecureBoot disabled\n", 0, "disabled"),
    ("SecureBoot enabled\n", 1, "unknown"),
    ("SecureBoot enabled unexpectedly\n", 0, "unknown"),
    ("This system doesn't support Secure Boot\n", 1, "unknown"),
])
def test_shell_secure_boot_consumers_do_not_accept_disabled_validation(tmp_path, output, code, expected):
    environment = {**os.environ, "MOKUTIL_OUTPUT": output, "MOKUTIL_CODE": str(code)}
    mocks = """
function [() {
    if [[ "$*" == '-d /sys/firmware/efi' ]]; then return 0; fi
    builtin [ "$@"
}
mokutil() { printf '%s' "$MOKUTIL_OUTPUT"; return "$MOKUTIL_CODE"; }
"""
    verifier = _boot_function("verify-boot-chain.sh", "check_secure_boot() {", "check_tpm2() {")
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\ndeclare -A checks\n" + mocks + verifier
         + '\ncheck_secure_boot\nprintf "%s\\n" "${checks[secure_boot]}"'],
        env=environment, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected
    enrollment = _boot_function("enroll-secureboot.sh", "check_secure_boot() {", "check_mok_enrolled() {")
    result = subprocess.run(
        ["bash", "-c", mocks + enrollment + "\ncheck_secure_boot"],
        env=environment, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == (0 if expected == "enabled" else 1)
    assert result.stdout.strip() == (expected if expected != "unknown" else "unavailable")


@pytest.mark.parametrize("output,code,enabled", [
    (b"SecureBoot enabled\n", 0, True),
    (b"SecureBoot disabled\n", 0, False),
    (b"SecureBoot enabled\nSecureBoot validation is disabled in shim\n", 0, False),
    (b"SecureBoot enabled\nSecureBoot disabled\n", 0, False),
    (b"SecureBoot enabled\n", 1, False),
    (b"SecureBoot enabled unexpectedly\n", 0, False),
])
def test_tpm_vault_requires_active_secure_boot_validation(secure_tpm, monkeypatch, output, code, enabled):
    monkeypatch.setattr(secure_tpm.shutil, "which", lambda command: "/test/mokutil")
    monkeypatch.setattr(secure_tpm, "run_command", lambda *args, **kwargs:
                        subprocess.CompletedProcess(["mokutil"], code, stdout=output, stderr=b""))
    assert secure_tpm.secure_boot_enabled() is enabled


@pytest.mark.parametrize("secure_boot,certificate,certificate_valid,table_valid,expected", [
    ("enabled", False, False, True, "valid"),
    ("disabled", False, False, True, "unchecked"),
    ("unknown", False, False, True, "unchecked"),
    ("disabled", True, True, True, "valid"),
    ("disabled", True, False, True, "unchecked"),
    ("enabled", False, False, False, "invalid"),
])
def test_kernel_signature_table_alone_is_not_verification(tmp_path, secure_boot, certificate,
                                                         certificate_valid, table_valid, expected):
    cert = tmp_path / "mok.pem"
    if certificate:
        cert.write_text("synthetic test certificate")
    function = _boot_function("verify-boot-chain.sh", "check_kernel_signature() {", "check_module_signatures() {")
    mocks = """
uname() { printf 'test-kernel\\n'; }
running_kernel_path() { printf '/test/vmlinuz\\n'; }
sbverify() {
    if [[ "$1" == '--list' ]]; then return "$TABLE_CODE"; fi
    return "$CERTIFICATE_CODE"
}
"""
    environment = {**os.environ, "MOK_PEM": str(cert), "SECURE_BOOT": secure_boot,
                   "TABLE_CODE": "0" if table_valid else "1",
                   "CERTIFICATE_CODE": "0" if certificate_valid else "1"}
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\ndeclare -A checks\nchecks[secure_boot]=$SECURE_BOOT\n"
         + mocks + function + '\ncheck_kernel_signature\nprintf "%s\\n" "${checks[kernel_sig]}"'],
        env=environment, capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected

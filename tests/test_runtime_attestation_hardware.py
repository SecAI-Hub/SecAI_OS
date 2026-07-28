from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = (
    REPO_ROOT
    / "files/system/usr/libexec/secure-ai/secure-tpm-attestation.py"
)
RUNTIME_UNIT = (
    REPO_ROOT
    / "files/system/usr/lib/systemd/system/secure-ai-runtime-attestor.service"
)
SETUP_UNIT = (
    REPO_ROOT
    / "files/system/usr/lib/systemd/system/"
    "secure-ai-tpm-attestation-setup.service"
)
INCIDENT_UNIT = (
    REPO_ROOT
    / "files/system/usr/lib/systemd/system/secure-ai-incident-recorder.service"
)
FIRSTBOOT_UNIT = (
    REPO_ROOT
    / "files/system/usr/lib/systemd/system/secure-ai-firstboot.service"
)
LANDLOCK = REPO_ROOT / "files/system/etc/secure-ai/policy/landlock.yaml"
ATTESTATION_GATE = (
    REPO_ROOT / "files/system/usr/libexec/secure-ai/attestation-gate.sh"
)


def _load_helper():
    spec = importlib.util.spec_from_file_location("secure_tpm_attestation", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pcr_parser_requires_the_complete_canonical_selection():
    helper = _load_helper()
    output = b"""sha256:
      0 : 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      2 : 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      4 : 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      7 : 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
    values = helper.parse_pcrs(output)
    assert list(sorted(values)) == ["0", "2", "4", "7"]
    assert values["0"] == "0x" + "a" * 64

    with pytest.raises(helper.AttestationSetupError):
        helper.parse_pcrs(output.replace(b"      7 :", b"      2 :"))
    with pytest.raises(helper.AttestationSetupError):
        helper.parse_pcrs(output.replace(b"      7 :", b"      8 :"))


def test_profile_json_parser_rejects_duplicates_and_nonfinite_numbers():
    helper = _load_helper()
    with pytest.raises(ValueError):
        helper.strict_json(b'{"mode":"hardware","mode":"evaluation"}')
    with pytest.raises(ValueError):
        helper.strict_json(b'{"value":NaN}')
    assert helper.strict_json(b'{"mode":"evaluation"}') == {
        "mode": "evaluation"
    }


def test_pcr_reenrollment_rejects_noninteractive_and_ssh_sessions(monkeypatch):
    helper = _load_helper()

    class NotATerminal:
        @staticmethod
        def isatty() -> bool:
            return False

    monkeypatch.setattr(helper.sys, "stdin", NotATerminal())
    monkeypatch.setattr(helper.sys, "stdout", NotATerminal())
    with pytest.raises(helper.AttestationSetupError, match="physical local console"):
        helper.require_physical_local_console()

    class Terminal:
        @staticmethod
        def isatty() -> bool:
            return True

        @staticmethod
        def fileno() -> int:
            return 0

    monkeypatch.setattr(helper.sys, "stdin", Terminal())
    monkeypatch.setattr(helper.sys, "stdout", Terminal())
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 1 127.0.0.1 2")
    with pytest.raises(helper.AttestationSetupError, match="forbidden over SSH"):
        helper.require_physical_local_console()


def test_provisioner_uses_a_persistent_ak_and_verifies_a_fresh_quote(
    monkeypatch,
    tmp_path,
):
    source = HELPER.read_text(encoding="utf-8")
    for command in (
        "tpm2_getcap",
        "tpm2_readpublic",
        "tpm2_createek",
        "tpm2_createak",
        "tpm2_evictcontrol",
        "tpm2_flushcontext",
        "tpm2_pcrread",
        "tpm2_quote",
        "tpm2_checkquote",
    ):
        assert command in source
    assert 'AK_HANDLE = "0x81010020"' in source
    assert 'PCR_SELECTION = "sha256:0,2,4,7"' in source
    assert "persistent handle" in source
    assert "current - previous" in source
    assert "tpm2_flushcontext -t/-s" in source
    assert "os.replace" in source
    assert "os.fsync" in source
    assert "os.umask(0o077)" in source
    assert "0o600" in source
    assert "COMMAND_TIMEOUT_SECONDS = 5" in source
    assert "host-controlled vTPM" in source
    assert "signed deployment differs from the enrolled attestation baseline" in source
    assert "live PCRs differ from the enrolled attestation baseline" in source
    # Definition plus every TPM-generated context/name/public/quote output.
    assert source.count("normalize_generated_file(") >= 11

    helper = _load_helper()
    generated = tmp_path / "tpm-output"
    generated.write_bytes(b"private TPM material")
    generated.chmod(0o666)
    real_fstat = helper.os.fstat

    def root_owned_fstat(descriptor):
        info = real_fstat(descriptor)
        return type(
            "RootOwnedStat",
            (),
            {
                "st_mode": info.st_mode,
                "st_nlink": info.st_nlink,
                "st_uid": 0,
                "st_size": info.st_size,
                "st_dev": info.st_dev,
                "st_ino": info.st_ino,
            },
        )()

    monkeypatch.setattr(helper.os, "fstat", root_owned_fstat)
    helper.normalize_generated_file(generated, maximum=4096)
    assert generated.stat().st_mode & 0o777 == 0o600

    symlink = tmp_path / "tpm-output-link"
    symlink.symlink_to(generated)
    with pytest.raises(helper.AttestationSetupError, match="safely secure"):
        helper.normalize_generated_file(symlink, maximum=4096)

    # Boot-time setup must validate an enrolled baseline, never silently
    # replace it. Only the physical-console reenroll path may mutate it.
    profile = {"mode": "hardware", "ak_public_key_sha256": "a" * 64}
    validated = []
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "ensure_state_directory", lambda: None)
    monkeypatch.setattr(helper, "existing_profile", lambda: profile)
    monkeypatch.setattr(helper, "is_virtual_machine", lambda: False)
    monkeypatch.setattr(helper, "validate_hardware_state", validated.append)
    monkeypatch.setattr(
        helper,
        "enroll_hardware",
        lambda: pytest.fail("setup silently replaced an enrolled PCR baseline"),
    )
    helper.setup()
    assert validated == [profile]


def test_attestation_setup_order_is_explicit_and_acyclic():
    setup = SETUP_UNIT.read_text(encoding="utf-8")
    runtime = RUNTIME_UNIT.read_text(encoding="utf-8")
    firstboot = FIRSTBOOT_UNIT.read_text(encoding="utf-8")

    assert "Requires=secure-ai-credentials.service secure-ai-boot-verify.service secure-ai-firstboot.service" in setup
    assert "Before=secure-ai-runtime-attestor.service" in setup
    assert "secure-ai-tpm-attestation-setup.service" in runtime
    assert "secure-ai-firstboot.service" in runtime
    assert "secure-ai-tpm-attestation-setup.service" in firstboot
    assert "secure-ai-runtime-attestor.service" not in setup.split("After=", 1)[1].splitlines()[0]


def test_runtime_gets_only_enrolled_public_evidence_and_tpm_device_dac():
    runtime = RUNTIME_UNIT.read_text(encoding="utf-8")
    assert "LoadCredential=tpm-attestation-profile:" in runtime
    assert "LoadCredential=tpm-ak-public:" in runtime
    assert "Environment=ATTESTATION_PROFILE_PATH=%d/tpm-attestation-profile" in runtime
    assert "Environment=TPM_AK_PUBLIC_KEY_PATH=%d/tpm-ak-public" in runtime
    assert "SupplementaryGroups=secure-ai-logs tss" in runtime
    assert "DeviceAllow=/dev/tpmrm0 rw" in runtime
    assert "UMask=0077" in runtime

    policy = LANDLOCK.read_text(encoding="utf-8")
    assert "/usr/bin/tpm2_quote" in policy
    assert "/usr/bin/tpm2_checkquote" in policy


def test_incident_recorder_has_least_privilege_bundle_verification_key():
    unit = INCIDENT_UNIT.read_text(encoding="utf-8")
    assert "Environment=ATTESTATION_HMAC_KEY_PATH=%d/attestation-hmac-key" in unit
    assert (
        "LoadCredential=attestation-hmac-key:"
        "/var/lib/secure-ai/credentials/attestation-hmac.key"
    ) in unit


def test_attestation_gate_rejects_curl_config_injection_and_checks_policy():
    source = ATTESTATION_GATE.read_text(encoding="utf-8")
    assert "'^[0-9a-f]{64}$'" in source
    assert "regular\\ file:1:64" in source
    assert ".policy_satisfied == true" in source
    assert "curl --config -" in source
    assert "Bearer %s" in source
    assert "--proto '=http'" in source
    assert "--noproxy '*'" in source
    assert "--max-filesize 1048576" in source
    assert "jq -e" in source

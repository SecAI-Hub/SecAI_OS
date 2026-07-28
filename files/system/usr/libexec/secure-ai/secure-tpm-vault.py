#!/usr/bin/python3
"""TPM2 enrollment for the SecAI LUKS2 vault using systemd's native token format."""

from __future__ import annotations

import argparse
import grp
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from secure_luks import (
    LUKSError,
    configured_device,
    keyslot_count,
    luks_metadata,
    parse_crypttab,
    tpm2_token_count,
    update_crypttab_tpm2,
)

STATE_PATH = Path("/run/secure-ai/tpm2-state.json")
MAPPER_PATH = Path("/dev/mapper/secure-ai-vault")
PCRS = "0:sha256+2:sha256+4:sha256+7:sha256"
PCRS_DISPLAY = "sha256:0,2,4,7"
LEGACY_TPM_DIR = Path("/var/lib/secure-ai/keys/tpm2")
LEGACY_FILES = frozenset(
    {
        "vault-key.sealed",
        "vault-key.sealed.pub",
        "vault-key.sealed.priv",
        "pcr-policy.dat",
        "primary.ctx",
        "pcr-baseline.bin",
    }
)


class TPMError(RuntimeError):
    """TPM enrollment or verification failed."""


def log(message: str) -> None:
    print(f"[tpm2-seal-vault] {message}", flush=True)


def run_command(
    args: Sequence[str],
    *,
    timeout: int = 60,
    interactive: bool = False,
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    try:
        if interactive:
            return subprocess.run(
                list(args),
                check=False,
                timeout=timeout,
            )
        return subprocess.run(
            list(args),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TPMError(f"required command failed to execute: {args[0]}") from error


def virtualization_type() -> str:
    if shutil.which("systemd-detect-virt") is None:
        return "unknown"
    result = run_command(("systemd-detect-virt", "--vm"), timeout=15)
    assert isinstance(result.stdout, bytes)
    if result.returncode == 1:
        return "none"
    if result.returncode == 0:
        value = result.stdout.decode("ascii", "replace").strip().lower()
        if value and all(char.isalnum() or char in "_-" for char in value):
            return value
    return "unknown"


def secure_boot_enabled() -> bool:
    if shutil.which("mokutil") is None:
        return False
    result = run_command(("mokutil", "--sb-state"), timeout=15)
    assert isinstance(result.stdout, bytes)
    output = (result.stdout + result.stderr).decode("utf-8", "replace").lower()
    return result.returncode == 0 and "secureboot enabled" in output


def tpm_available() -> bool:
    if (
        not Path("/dev/tpmrm0").exists()
        and not Path("/dev/tpm0").exists()
    ):
        return False
    for command in ("systemd-cryptenroll", "tpm2_pcrread", "cryptsetup"):
        if shutil.which(command) is None:
            return False
    result = run_command(
        ("tpm2_pcrread", "sha256:0,2,4,7"),
        timeout=30,
    )
    return result.returncode == 0


def atomic_state(value: dict[str, object]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if STATE_PATH.is_symlink():
        raise TPMError("refusing symlink TPM state path")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{STATE_PATH.name}.", dir=STATE_PATH.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o640)
        try:
            group_id = grp.getgrnam("secure-ai-services").gr_gid
        except KeyError as error:
            raise TPMError("secure-ai-services group is unavailable") from error
        os.fchown(descriptor, 0, group_id)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, STATE_PATH)
        directory_descriptor = os.open(
            STATE_PATH.parent, os.O_RDONLY | os.O_DIRECTORY
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def current_state(detail: str = "") -> dict[str, object]:
    vm_type = virtualization_type()
    available = tpm_available()
    enrolled = False
    token_count = 0
    slots = 0
    crypttab_enabled = False
    try:
        device = configured_device()
        metadata = luks_metadata(device)
        token_count = tpm2_token_count(metadata)
        slots = keyslot_count(metadata)
        enrolled = token_count == 1
        _lines, _index, fields = parse_crypttab()
        options = fields[3].split(",") if len(fields) >= 4 else []
        crypttab_enabled = "tpm2-device=auto" in options
    except (LUKSError, OSError):
        device = None

    if vm_type not in {"none", "unknown"}:
        assurance = "virtual_tpm_host_controlled"
    elif not secure_boot_enabled():
        assurance = "secure_boot_not_verified"
    elif available and enrolled and crypttab_enabled:
        assurance = "pcr_bound"
    else:
        assurance = "not_enrolled"

    state: dict[str, object] = {
        "schema_version": 1,
        "checked_at": datetime.now(UTC).isoformat(),
        "tpm2_available": available,
        "enrolled": enrolled,
        "token_count": token_count,
        "keyslot_count": slots,
        "crypttab_tpm2_enabled": crypttab_enabled,
        "pcr_binding": PCRS_DISPLAY,
        "virtualization": vm_type,
        "assurance": assurance,
    }
    if device is not None:
        state["device"] = str(device)
    if detail:
        state["detail"] = detail[:512]
    return state


def remove_legacy_artifacts() -> None:
    if not LEGACY_TPM_DIR.exists():
        return
    if LEGACY_TPM_DIR.is_symlink() or not LEGACY_TPM_DIR.is_dir():
        raise TPMError("legacy TPM artifact directory is unsafe")
    for child in LEGACY_TPM_DIR.iterdir():
        if child.name not in LEGACY_FILES:
            raise TPMError(f"unexpected legacy TPM artifact: {child.name}")
        info = child.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise TPMError(f"legacy TPM artifact is not a regular file: {child.name}")
        child.unlink()


def enroll(*, allow_vtpm: bool, allow_insecure_boot: bool) -> int:
    if not tpm_available():
        raise TPMError("TPM2 device, systemd-cryptenroll, or required PCR bank is unavailable")
    vm_type = virtualization_type()
    if vm_type not in {"none", "unknown"} and not allow_vtpm:
        raise TPMError(
            "vTPM enrollment requires --allow-vtpm because the hypervisor controls its state"
        )
    if not secure_boot_enabled() and not allow_insecure_boot:
        raise TPMError(
            "Secure Boot is not verified; use --allow-insecure-boot only for a degraded lab"
        )

    device = configured_device()
    before = luks_metadata(device)
    if keyslot_count(before) < 1:
        raise TPMError("vault has no existing recovery/passphrase keyslot")

    log("systemd-cryptenroll will request an existing vault passphrase")
    result = run_command(
        (
            "systemd-cryptenroll",
            str(device),
            "--wipe-slot=tpm2",
            "--tpm2-device=auto",
            f"--tpm2-pcrs={PCRS}",
        ),
        timeout=600,
        interactive=True,
    )
    if result.returncode != 0:
        raise TPMError("systemd-cryptenroll failed; existing keyslots were retained")

    after = luks_metadata(device)
    if tpm2_token_count(after) != 1 or keyslot_count(after) < 2:
        raise TPMError(
            "TPM enrollment verification failed or no passphrase recovery slot remains"
        )
    update_crypttab_tpm2(enabled=True)
    remove_legacy_artifacts()
    state = current_state("TPM2 enrollment verified")
    atomic_state(state)
    if not state["enrolled"] or not state["crypttab_tpm2_enabled"]:
        raise TPMError("post-enrollment state verification failed")
    log(f"TPM2 enrollment verified with PCR policy {PCRS_DISPLAY}")
    return 0


def unseal() -> int:
    if not tpm_available():
        raise TPMError("TPM2 is unavailable")
    device = configured_device()
    metadata = luks_metadata(device)
    if tpm2_token_count(metadata) != 1:
        raise TPMError("exactly one systemd-tpm2 LUKS token is required")
    if MAPPER_PATH.exists():
        log("vault mapper is already active")
        return 0
    result = run_command(
        (
            "/usr/lib/systemd/systemd-cryptsetup",
            "attach",
            "secure-ai-vault",
            str(device),
            "none",
            "tpm2-device=auto",
        ),
        timeout=120,
    )
    if result.returncode != 0 or not MAPPER_PATH.exists():
        raise TPMError(
            "TPM unlock failed; enter the recovery passphrase through the normal boot prompt"
        )
    atomic_state(current_state("TPM2 unlock verified"))
    log("vault mapper unlocked through the enrolled TPM2 token")
    return 0


def wipe(confirmation: str | None) -> int:
    if confirmation != "REMOVE-TPM2-UNLOCK":
        raise TPMError(
            "wipe requires --destructive-confirmation REMOVE-TPM2-UNLOCK"
        )
    device = configured_device()
    before = luks_metadata(device)
    count = tpm2_token_count(before)
    if count:
        result = run_command(
            ("systemd-cryptenroll", str(device), "--wipe-slot=tpm2"),
            timeout=120,
        )
        if result.returncode != 0:
            raise TPMError("could not remove TPM2 enrollment")
    after = luks_metadata(device)
    if tpm2_token_count(after) != 0 or keyslot_count(after) < 1:
        raise TPMError("TPM2 removal verification failed or no recovery key remains")
    update_crypttab_tpm2(enabled=False)
    remove_legacy_artifacts()
    atomic_state(current_state("TPM2 enrollment removed; passphrase required"))
    log("TPM2 enrollment removed; passphrase recovery remains")
    return 0


def status() -> int:
    state = current_state()
    try:
        atomic_state(state)
    except (OSError, TPMError):
        # Non-root status remains useful even when it cannot update /run.
        pass
    print(json.dumps(state, sort_keys=True, separators=(",", ":")))
    if state["assurance"] in {"virtual_tpm_host_controlled", "secure_boot_not_verified"}:
        return 2
    return 0 if state["enrolled"] else 1


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="tpm2-seal-vault.sh")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("seal", "reseal"):
        enroll_parser = subparsers.add_parser(command)
        enroll_parser.add_argument("--allow-vtpm", action="store_true")
        enroll_parser.add_argument("--allow-insecure-boot", action="store_true")
    subparsers.add_parser("unseal")
    wipe_parser = subparsers.add_parser("wipe")
    wipe_parser.add_argument("--destructive-confirmation")
    subparsers.add_parser("status")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "status":
        return status()
    if os.geteuid() != 0:
        log("mutating TPM2 commands must run as root")
        return 1
    try:
        if args.command in {"seal", "reseal"}:
            return enroll(
                allow_vtpm=args.allow_vtpm,
                allow_insecure_boot=args.allow_insecure_boot,
            )
        if args.command == "unseal":
            return unseal()
        return wipe(args.destructive_confirmation)
    except (LUKSError, OSError, TPMError) as error:
        log(f"ERROR: {error}")
        try:
            atomic_state(current_state(str(error)))
        except (OSError, TPMError):
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/python3
"""Provision and validate the runtime-attestor TPM AK and PCR baseline.

This helper is intentionally root-only and local. It never accepts key
material, PCR values, or a TPM handle from the network. The hardware profile is
committed only after a fresh AK quote has passed tpm2_checkquote and its quoted
PCR blob has been captured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import secrets
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

STATE_DIR = Path(
    os.environ.get(
        "SECURE_AI_TPM_ATTESTATION_DIR",
        "/var/lib/secure-ai/tpm-attestation",
    )
)
PROFILE_PATH = STATE_DIR / "profile.json"
AK_PUBLIC_PATH = STATE_DIR / "ak-public.pem"
VM_STATE_PATH = Path(
    os.environ.get("SECURE_AI_VM_STATE_PATH", "/var/lib/secure-ai/state/vm.json")
)
BOOT_EVIDENCE_PATH = Path(
    os.environ.get(
        "SECURE_AI_BOOT_EVIDENCE_PATH",
        "/var/lib/secure-ai/logs/boot-verify-last.json",
    )
)
SECURE_BOOT_PATH = Path(
    os.environ.get(
        "SECURE_AI_SECURE_BOOT_PATH",
        "/sys/firmware/efi/efivars/"
        "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    )
)

AK_HANDLE = "0x81010020"
PCR_SELECTION = "sha256:0,2,4,7"
PCR_INDEXES = ("0", "2", "4", "7")
MAX_JSON_BYTES = 1024 * 1024
MAX_PUBLIC_BYTES = 64 * 1024
MAX_COMMAND_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 5
MAX_HANDLES_PER_CAPABILITY = 64
MAX_PROVISIONING_CONTEXTS = 8
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PCR_RE = re.compile(r"^\s*(0|2|4|7)\s*:\s*(0x[0-9a-fA-F]{64})\s*$")
HANDLE_RE = re.compile(r"^\s*-\s*(0x[0-9a-fA-F]{8})\s*$")
PROFILE_FIELDS = frozenset(
    {
        "version",
        "mode",
        "require_tpm",
        "require_secure_boot",
        "ak_handle",
        "ak_public_key_sha256",
        "pcr_selection",
        "expected_pcrs",
        "quoted_pcr_digest_sha256",
        "enrolled_deployment",
        "enrolled_at",
    }
)
TPM_COMMANDS = (
    "tpm2_getcap",
    "tpm2_readpublic",
    "tpm2_createek",
    "tpm2_createak",
    "tpm2_evictcontrol",
    "tpm2_flushcontext",
    "tpm2_pcrread",
    "tpm2_quote",
    "tpm2_checkquote",
)


class AttestationSetupError(RuntimeError):
    """The hardware attestation profile cannot be safely provisioned."""


def log(message: str) -> None:
    print(f"[tpm-attestation] {message}", flush=True)


def strict_json(data: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(
        data,
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {constant}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value is not an object")
    return value


def read_regular(
    path: Path,
    *,
    maximum: int,
    require_root: bool = True,
    require_mode: int | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AttestationSetupError(f"unsafe regular-file contract: {path}")
        if require_root and info.st_uid != 0:
            raise AttestationSetupError(f"unsafe owner for {path}")
        if require_mode is not None and stat.S_IMODE(info.st_mode) != require_mode:
            raise AttestationSetupError(f"unsafe mode for {path}")
        if require_mode is None and info.st_mode & 0o022:
            raise AttestationSetupError(f"group/other-writable trusted file: {path}")
        if info.st_size < 0 or info.st_size > maximum:
            raise AttestationSetupError(f"unsafe size for {path}")
        data = os.read(descriptor, maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            raise AttestationSetupError(f"{path} changed while reading")
        after = os.fstat(descriptor)
        if (
            after.st_dev != info.st_dev
            or after.st_ino != info.st_ino
            or after.st_size != info.st_size
        ):
            raise AttestationSetupError(f"{path} changed while reading")
        return data
    finally:
        os.close(descriptor)


def ensure_state_directory() -> None:
    if STATE_DIR.exists() or STATE_DIR.is_symlink():
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(STATE_DIR, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_nlink != 2
            ):
                raise AttestationSetupError(
                    f"unsafe attestation state directory: {STATE_DIR}"
                )
        finally:
            os.close(descriptor)
        return
    STATE_DIR.mkdir(mode=0o700)
    os.chown(STATE_DIR, 0, 0)
    ensure_state_directory()


def atomic_write(path: Path, data: bytes) -> None:
    ensure_state_directory()
    if path.is_symlink():
        raise AttestationSetupError(f"refusing symlink destination: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=STATE_DIR)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    atomic_write(path, data)


def run_command(
    arguments: Sequence[str],
    *,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    def limit_output_files() -> None:
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (MAX_COMMAND_BYTES, MAX_COMMAND_BYTES),
        )

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                list(arguments),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                preexec_fn=limit_output_files,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AttestationSetupError(
                f"{arguments[0]} could not complete safely: {error}"
            ) from error
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read(MAX_COMMAND_BYTES + 1)
        error_output = stderr.read(MAX_COMMAND_BYTES + 1)
    if len(output) > MAX_COMMAND_BYTES or len(error_output) > MAX_COMMAND_BYTES:
        raise AttestationSetupError(f"{arguments[0]} produced excessive output")
    return subprocess.CompletedProcess(
        list(arguments),
        completed.returncode,
        output,
        error_output,
    )


def require_command(arguments: Sequence[str]) -> bytes:
    result = run_command(arguments)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()[:512]
        raise AttestationSetupError(
            f"{arguments[0]} failed with status {result.returncode}: {detail}"
        )
    return result.stdout


def normalize_generated_file(path: Path, *, maximum: int) -> None:
    """Validate and privatize a file emitted by a TPM command.

    tpm2-tools may choose an explicit output mode instead of honoring the
    caller's umask. All outputs live in a root-only temporary directory, but
    they are still normalized through a no-follow file descriptor before
    another TPM command or this helper is allowed to trust them.
    """

    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
        ):
            raise AttestationSetupError(
                f"unsafe TPM-generated file contract: {path}"
            )
        if before.st_size < 0 or before.st_size > maximum:
            raise AttestationSetupError(f"unsafe TPM-generated file size: {path}")
        os.fchmod(descriptor, 0o600)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise AttestationSetupError(
                f"TPM-generated file changed while securing it: {path}"
            )
    except OSError as error:
        raise AttestationSetupError(
            f"cannot safely secure TPM-generated file {path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_json_state(path: Path) -> dict[str, Any]:
    try:
        data = read_regular(path, maximum=MAX_JSON_BYTES, require_mode=None)
        return strict_json(data)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise AttestationSetupError(f"invalid trusted state {path}: {error}") from error


def is_virtual_machine() -> bool:
    state = load_json_state(VM_STATE_PATH)
    value = state.get("is_vm")
    if type(value) is not bool:
        raise AttestationSetupError("VM state lacks a typed is_vm field")
    return value


def verified_deployment() -> str:
    record = load_json_state(BOOT_EVIDENCE_PATH)
    checks = record.get("checks")
    if record.get("status") != "ok" or not isinstance(checks, dict):
        raise AttestationSetupError("signed boot verification did not pass")
    signature = checks.get("ostree_signature")
    if not isinstance(signature, dict) or signature.get("state") != "valid":
        raise AttestationSetupError("booted deployment signature is not valid")
    commit = signature.get("commit")
    if (
        not isinstance(commit, str)
        or not commit.startswith("sha256:")
        or not SHA256_RE.fullmatch(commit.removeprefix("sha256:"))
    ):
        raise AttestationSetupError("boot evidence lacks a canonical deployment digest")
    return commit


def secure_boot_enabled() -> bool:
    try:
        data = read_regular(
            SECURE_BOOT_PATH,
            maximum=4096,
            require_root=False,
            require_mode=None,
        )
    except OSError:
        return False
    return len(data) >= 5 and data[4] == 1


def persistent_handles() -> set[str]:
    return tpm_handles("handles-persistent")


def tpm_handles(capability: str) -> set[str]:
    output = require_command(("tpm2_getcap", capability))
    handles: set[str] = set()
    for line in output.decode("ascii", "strict").splitlines():
        match = HANDLE_RE.fullmatch(line)
        if match:
            handles.add(match.group(1).lower())
            if len(handles) > MAX_HANDLES_PER_CAPABILITY:
                raise AttestationSetupError(
                    f"TPM returned too many handles for {capability}"
                )
    return handles


def loaded_context_handles() -> set[str]:
    handles: set[str] = set()
    for capability in (
        "handles-transient",
        "handles-loaded-session",
        "handles-saved-session",
    ):
        handles.update(tpm_handles(capability))
    return handles


def flush_new_contexts(previous: set[str], *, required: bool) -> None:
    try:
        current = loaded_context_handles()
    except AttestationSetupError:
        if required:
            raise
        return
    new_handles = current - previous
    if len(new_handles) > MAX_PROVISIONING_CONTEXTS:
        if required:
            raise AttestationSetupError(
                "unexpected number of new TPM contexts during provisioning"
            )
        return
    for handle in sorted(new_handles):
        try:
            result = run_command(("tpm2_flushcontext", handle))
        except AttestationSetupError:
            if required:
                raise
            continue
        if required and result.returncode != 0:
            raise AttestationSetupError(
                f"could not flush provisioning-owned TPM context {handle}"
            )
    if required and loaded_context_handles() != previous:
        raise AttestationSetupError(
            "TPM transient/session context set did not return to its baseline"
        )


def read_ak_public(destination: Path) -> bytes:
    require_command(
        ("tpm2_readpublic", "-c", AK_HANDLE, "-f", "pem", "-o", str(destination))
    )
    normalize_generated_file(destination, maximum=MAX_PUBLIC_BYTES)
    return read_regular(
        destination,
        maximum=MAX_PUBLIC_BYTES,
        require_root=True,
        require_mode=None,
    )


def provision_or_validate_ak(directory: Path) -> bytes:
    candidate = directory / "ak-public.pem"
    handles = persistent_handles()
    if AK_HANDLE in handles:
        public = read_ak_public(candidate)
        if not AK_PUBLIC_PATH.exists():
            raise AttestationSetupError(
                f"persistent handle {AK_HANDLE} is occupied without an enrolled public key"
            )
        enrolled = read_regular(
            AK_PUBLIC_PATH,
            maximum=MAX_PUBLIC_BYTES,
            require_mode=0o600,
        )
        if not secrets.compare_digest(
            hashlib.sha256(public).digest(), hashlib.sha256(enrolled).digest()
        ):
            raise AttestationSetupError(
                f"persistent handle {AK_HANDLE} does not match the enrolled AK"
            )
        return public

    if AK_PUBLIC_PATH.exists():
        raise AttestationSetupError(
            "enrolled AK public key exists but the persistent TPM handle is absent"
        )

    endorsement_key = directory / "ek.ctx"
    transient_ak = directory / "ak.ctx"
    created_public = directory / "ak-created.public"
    name = directory / "ak.name"
    previous_contexts = loaded_context_handles()
    try:
        require_command(
            (
                "tpm2_createek",
                "-G",
                "ecc",
                "-c",
                str(endorsement_key),
            )
        )
        normalize_generated_file(endorsement_key, maximum=MAX_PUBLIC_BYTES)
        require_command(
            (
                "tpm2_createak",
                "-C",
                str(endorsement_key),
                "-G",
                "ecc",
                "-g",
                "sha256",
                "-s",
                "ecdsa",
                "-c",
                str(transient_ak),
                "-u",
                str(created_public),
                "-n",
                str(name),
            )
        )
        normalize_generated_file(transient_ak, maximum=MAX_PUBLIC_BYTES)
        normalize_generated_file(created_public, maximum=MAX_PUBLIC_BYTES)
        normalize_generated_file(name, maximum=4096)
        new_handles = loaded_context_handles() - previous_contexts
        if len(new_handles) == 0 or len(new_handles) > MAX_PROVISIONING_CONTEXTS:
            raise AttestationSetupError(
                "unexpected TPM transient context count after AK creation"
            )
        matching_ak_handles: list[str] = []
        enrolled_name = read_regular(
            name,
            maximum=4096,
            require_root=True,
            require_mode=None,
        )
        for handle in sorted(new_handles):
            candidate_name = directory / f"{handle}.name"
            result = run_command(
                (
                    "tpm2_readpublic",
                    "-c",
                    handle,
                    "-n",
                    str(candidate_name),
                )
            )
            if result.returncode != 0 or not candidate_name.exists():
                continue
            normalize_generated_file(candidate_name, maximum=4096)
            actual_name = read_regular(
                candidate_name,
                maximum=4096,
                require_root=True,
                require_mode=None,
            )
            if secrets.compare_digest(actual_name, enrolled_name):
                matching_ak_handles.append(handle)
        if len(matching_ak_handles) != 1:
            raise AttestationSetupError(
                "could not uniquely identify the provisioning-owned transient AK"
            )
        require_command(
            (
                "tpm2_evictcontrol",
                "-C",
                "o",
                "-c",
                matching_ak_handles[0],
                AK_HANDLE,
            )
        )
        # Flush only contexts created by this invocation. Never use
        # tpm2_flushcontext -t/-s, which could disrupt another TPM client.
        flush_new_contexts(previous_contexts, required=True)
    finally:
        flush_new_contexts(previous_contexts, required=False)
    if AK_HANDLE not in persistent_handles():
        raise AttestationSetupError("new TPM AK did not become persistent")
    persistent_blob = directory / "ak-persistent.public"
    require_command(
        ("tpm2_readpublic", "-c", AK_HANDLE, "-o", str(persistent_blob))
    )
    normalize_generated_file(persistent_blob, maximum=MAX_PUBLIC_BYTES)
    created_blob = read_regular(
        created_public,
        maximum=MAX_PUBLIC_BYTES,
        require_root=True,
        require_mode=None,
    )
    persisted_blob = read_regular(
        persistent_blob,
        maximum=MAX_PUBLIC_BYTES,
        require_root=True,
        require_mode=None,
    )
    if not secrets.compare_digest(created_blob, persisted_blob):
        raise AttestationSetupError(
            "persistent AK public area differs from the newly created AK"
        )
    return read_ak_public(candidate)


def parse_pcrs(output: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.decode("ascii", "strict").splitlines():
        match = PCR_RE.fullmatch(line)
        if not match:
            continue
        index, value = match.groups()
        if index in values:
            raise AttestationSetupError(f"duplicate PCR {index} in tpm2_pcrread")
        values[index] = value.lower()
    if set(values) != set(PCR_INDEXES):
        raise AttestationSetupError("tpm2_pcrread did not return the complete PCR set")
    return values


def capture_verified_quote(directory: Path, ak_public: Path) -> tuple[dict[str, str], str]:
    pcrs = parse_pcrs(require_command(("tpm2_pcrread", PCR_SELECTION)))
    nonce = secrets.token_hex(32)
    message = directory / "quote.message"
    signature = directory / "quote.signature"
    quoted_pcrs = directory / "quote.pcr"
    require_command(
        (
            "tpm2_quote",
            "-c",
            AK_HANDLE,
            "-l",
            PCR_SELECTION,
            "-q",
            nonce,
            "-m",
            str(message),
            "-s",
            str(signature),
            "-o",
            str(quoted_pcrs),
            "-g",
            "sha256",
        )
    )
    normalize_generated_file(message, maximum=MAX_COMMAND_BYTES)
    normalize_generated_file(signature, maximum=MAX_COMMAND_BYTES)
    normalize_generated_file(quoted_pcrs, maximum=MAX_COMMAND_BYTES)
    require_command(
        (
            "tpm2_checkquote",
            "-u",
            str(ak_public),
            "-m",
            str(message),
            "-s",
            str(signature),
            "-f",
            str(quoted_pcrs),
            "-g",
            "sha256",
            "-q",
            nonce,
        )
    )
    pcr_blob = read_regular(
        quoted_pcrs,
        maximum=MAX_JSON_BYTES,
        require_root=True,
        require_mode=None,
    )
    if not pcr_blob:
        raise AttestationSetupError("TPM quote returned an empty PCR blob")
    return pcrs, hashlib.sha256(pcr_blob).hexdigest()


def existing_profile() -> dict[str, Any] | None:
    if not PROFILE_PATH.exists():
        return None
    return load_json_state(PROFILE_PATH)


def validate_profile_envelope(profile: dict[str, Any], mode: str) -> None:
    if set(profile) != PROFILE_FIELDS:
        raise AttestationSetupError("attestation profile fields are not canonical")
    if type(profile.get("version")) is not int or profile["version"] != 1:
        raise AttestationSetupError("attestation profile version is invalid")
    if profile.get("mode") != mode:
        raise AttestationSetupError(
            f"expected a {mode} attestation profile"
        )
    enrolled_at = profile.get("enrolled_at")
    if not isinstance(enrolled_at, str):
        raise AttestationSetupError("attestation enrollment time is invalid")
    try:
        parsed_time = datetime.fromisoformat(enrolled_at)
    except ValueError as error:
        raise AttestationSetupError(
            "attestation enrollment time is invalid"
        ) from error
    if parsed_time.tzinfo is None:
        raise AttestationSetupError("attestation enrollment time lacks a timezone")


def validate_evaluation_profile(profile: dict[str, Any]) -> None:
    validate_profile_envelope(profile, "evaluation")
    expected = {
        "require_tpm": False,
        "require_secure_boot": False,
        "ak_handle": "",
        "ak_public_key_sha256": "",
        "pcr_selection": "",
        "expected_pcrs": {},
        "quoted_pcr_digest_sha256": "",
        "enrolled_deployment": "",
    }
    if any(profile.get(key) != value for key, value in expected.items()):
        raise AttestationSetupError("evaluation attestation profile is invalid")
    public = read_regular(
        AK_PUBLIC_PATH, maximum=MAX_PUBLIC_BYTES, require_mode=0o600
    )
    if public != b"UNAVAILABLE\n":
        raise AttestationSetupError("evaluation AK placeholder is invalid")


def validate_hardware_profile(profile: dict[str, Any]) -> None:
    validate_profile_envelope(profile, "hardware")
    if profile.get("require_tpm") is not True:
        raise AttestationSetupError("hardware profile does not require TPM")
    if profile.get("require_secure_boot") is not True:
        raise AttestationSetupError("hardware profile does not require Secure Boot")
    if profile.get("ak_handle") != AK_HANDLE:
        raise AttestationSetupError("hardware profile AK handle is invalid")
    if profile.get("pcr_selection") != PCR_SELECTION:
        raise AttestationSetupError("hardware profile PCR selection is invalid")
    if not isinstance(profile.get("ak_public_key_sha256"), str) or not SHA256_RE.fullmatch(
        profile["ak_public_key_sha256"]
    ):
        raise AttestationSetupError("hardware profile AK digest is invalid")
    if not isinstance(
        profile.get("quoted_pcr_digest_sha256"), str
    ) or not SHA256_RE.fullmatch(profile["quoted_pcr_digest_sha256"]):
        raise AttestationSetupError("hardware profile quote PCR digest is invalid")
    deployment = profile.get("enrolled_deployment")
    if (
        not isinstance(deployment, str)
        or not deployment.startswith("sha256:")
        or not SHA256_RE.fullmatch(deployment.removeprefix("sha256:"))
    ):
        raise AttestationSetupError("hardware profile deployment digest is invalid")
    expected_pcrs = profile.get("expected_pcrs")
    if not isinstance(expected_pcrs, dict) or set(expected_pcrs) != set(PCR_INDEXES):
        raise AttestationSetupError("hardware profile PCR baseline is incomplete")
    for index in PCR_INDEXES:
        value = expected_pcrs.get(index)
        if (
            not isinstance(value, str)
            or value != value.lower()
            or not re.fullmatch(r"0x[0-9a-f]{64}", value)
        ):
            raise AttestationSetupError(
                f"hardware profile PCR {index} is not canonical"
            )


def require_hardware_prerequisites() -> str:
    deployment = verified_deployment()
    if not secure_boot_enabled():
        raise AttestationSetupError("Secure Boot is not enabled")
    if not Path("/dev/tpmrm0").exists() and not Path("/dev/tpm0").exists():
        raise AttestationSetupError("no TPM2 device is available")
    for command in TPM_COMMANDS:
        if not any(
            os.access(Path(directory) / command, os.X_OK)
            for directory in os.environ.get("PATH", "").split(os.pathsep)
            if directory
        ):
            raise AttestationSetupError(f"required command is unavailable: {command}")
    return deployment


def validate_hardware_state(profile: dict[str, Any]) -> None:
    validate_hardware_profile(profile)
    deployment = require_hardware_prerequisites()
    if not secrets.compare_digest(deployment, profile["enrolled_deployment"]):
        raise AttestationSetupError(
            "signed deployment differs from the enrolled attestation baseline"
        )
    with tempfile.TemporaryDirectory(
        prefix="secure-ai-ak-validate-"
    ) as temporary_name:
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o700)
        public = provision_or_validate_ak(temporary)
        candidate_public = temporary / "verified-ak-public.pem"
        candidate_public.write_bytes(public)
        os.chmod(candidate_public, 0o600)
        pcrs, quoted_pcr_digest = capture_verified_quote(
            temporary, candidate_public
        )
    public_digest = hashlib.sha256(public).hexdigest()
    if not secrets.compare_digest(
        public_digest, profile["ak_public_key_sha256"]
    ):
        raise AttestationSetupError("hardware profile AK digest is inconsistent")
    if pcrs != profile["expected_pcrs"]:
        raise AttestationSetupError(
            "live PCRs differ from the enrolled attestation baseline"
        )
    if not secrets.compare_digest(
        quoted_pcr_digest, profile["quoted_pcr_digest_sha256"]
    ):
        raise AttestationSetupError(
            "quoted PCR evidence differs from the enrolled attestation baseline"
        )


def write_evaluation_profile() -> None:
    previous = existing_profile()
    if previous is not None and previous.get("mode") == "hardware":
        raise AttestationSetupError(
            "refusing to replace an enrolled hardware profile with evaluation mode"
        )
    atomic_write(AK_PUBLIC_PATH, b"UNAVAILABLE\n")
    atomic_json(
        PROFILE_PATH,
        {
            "version": 1,
            "mode": "evaluation",
            "require_tpm": False,
            "require_secure_boot": False,
            "ak_handle": "",
            "ak_public_key_sha256": "",
            "pcr_selection": "",
            "expected_pcrs": {},
            "quoted_pcr_digest_sha256": "",
            "enrolled_deployment": "",
            "enrolled_at": datetime.now(UTC).isoformat(),
        },
    )
    log(
        "explicit evaluation profile installed; hardware verification and "
        "critical-incident re-attestation are unavailable"
    )


def enroll_hardware() -> None:
    deployment = require_hardware_prerequisites()

    with tempfile.TemporaryDirectory(prefix="secure-ai-ak-") as temporary_name:
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o700)
        public = provision_or_validate_ak(temporary)
        candidate_public = temporary / "verified-ak-public.pem"
        candidate_public.write_bytes(public)
        os.chmod(candidate_public, 0o600)
        pcrs, quoted_pcr_digest = capture_verified_quote(
            temporary, candidate_public
        )

    public_digest = hashlib.sha256(public).hexdigest()
    atomic_write(AK_PUBLIC_PATH, public)
    atomic_json(
        PROFILE_PATH,
        {
            "version": 1,
            "mode": "hardware",
            "require_tpm": True,
            "require_secure_boot": True,
            "ak_handle": AK_HANDLE,
            "ak_public_key_sha256": public_digest,
            "pcr_selection": PCR_SELECTION,
            "expected_pcrs": pcrs,
            "quoted_pcr_digest_sha256": quoted_pcr_digest,
            "enrolled_deployment": deployment,
            "enrolled_at": datetime.now(UTC).isoformat(),
        },
    )
    log(
        f"hardware attestation enrolled at {AK_HANDLE}; "
        f"AK SHA-256={public_digest}"
    )


def setup() -> None:
    if os.geteuid() != 0:
        raise AttestationSetupError("root privileges are required")
    ensure_state_directory()
    profile = existing_profile()
    if is_virtual_machine():
        if profile is None:
            write_evaluation_profile()
        else:
            validate_evaluation_profile(profile)
            log("mode=evaluation evidence_verified=false")
        return
    if profile is None:
        enroll_hardware()
        return
    validate_hardware_state(profile)
    log(
        f"mode=hardware ak_handle={AK_HANDLE} "
        f"ak_sha256={profile['ak_public_key_sha256']}"
    )


def require_physical_local_console() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise AttestationSetupError(
            "PCR re-enrollment requires an interactive physical local console"
        )
    if any(
        os.environ.get(variable)
        for variable in ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY")
    ):
        raise AttestationSetupError("PCR re-enrollment is forbidden over SSH")
    try:
        terminal = os.ttyname(sys.stdin.fileno())
    except OSError as error:
        raise AttestationSetupError("cannot identify the local console TTY") from error
    if terminal != "/dev/console" and not re.fullmatch(r"/dev/tty[0-9]+", terminal):
        raise AttestationSetupError(
            "PCR re-enrollment requires /dev/console or a Linux virtual console"
        )


def reenroll(confirmation: str) -> None:
    if os.geteuid() != 0:
        raise AttestationSetupError("root privileges are required")
    require_physical_local_console()
    if confirmation != "ENROLL-ATTESTATION":
        raise AttestationSetupError(
            "local confirmation must exactly equal ENROLL-ATTESTATION"
        )
    if is_virtual_machine():
        raise AttestationSetupError(
            "hardware attestation enrollment is not supported for host-controlled vTPM"
        )
    enroll_hardware()


def status() -> None:
    ensure_state_directory()
    profile = existing_profile()
    if profile is None:
        raise AttestationSetupError("attestation profile is not provisioned")
    mode = profile.get("mode")
    if mode == "evaluation":
        validate_evaluation_profile(profile)
        log("mode=evaluation evidence_verified=false")
        return
    if mode != "hardware":
        raise AttestationSetupError("attestation profile mode is invalid")
    validate_hardware_state(profile)
    log(
        f"mode=hardware ak_handle={AK_HANDLE} "
        f"ak_sha256={profile['ak_public_key_sha256']}"
    )


def main() -> int:
    # TPM tools create context, name, public, quote, and signature artifacts.
    # Enforce private defaults for direct physical-console use as well as the
    # systemd unit, regardless of the invoking administrator's inherited umask.
    os.umask(0o077)
    parser = argparse.ArgumentParser(prog="secure-tpm-attestation.py")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("setup")
    subparsers.add_parser("status")
    reenroll_parser = subparsers.add_parser("reenroll")
    reenroll_parser.add_argument("--confirm", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "setup":
            setup()
        elif arguments.command == "status":
            status()
        else:
            reenroll(arguments.confirm)
    except AttestationSetupError as error:
        log(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

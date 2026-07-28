#!/usr/bin/python3
"""Apply verifiable guest-side VM clipboard controls.

Clipboard sharing is ultimately controlled by the hypervisor.  This helper
therefore never reports a VM as fully isolated based only on guest state.  It
applies the guest controls that can be verified locally and records the
remaining host-side requirement in a root-owned JSON state file.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

STATE_PATH = Path("/var/lib/secure-ai/state/clipboard.json")
KNOWN_SPICE_UNITS = (
    "spice-vdagentd.service",
    "spice-vdagent.service",
)
VMWARE_VM_TYPES = frozenset({"vmware"})
VBOX_VM_TYPES = frozenset({"oracle"})
SPICE_VM_TYPES = frozenset({"kvm", "qemu"})


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""


@dataclass(frozen=True)
class Control:
    name: str
    detected: bool
    attempted: bool
    verified: bool
    detail: str


def log(message: str) -> None:
    print(f"[clipboard-isolate] {message}", flush=True)


def run_command(args: Sequence[str], timeout: int = 15) -> CommandResult:
    """Run an exact command without a shell and return bounded public output."""
    try:
        completed = subprocess.run(
            list(args),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CommandResult(125)
    return CommandResult(completed.returncode, completed.stdout[:4096].strip())


def detect_virtualization() -> str:
    if shutil.which("systemd-detect-virt") is None:
        return "unknown"
    result = run_command(("systemd-detect-virt", "--vm"))
    if result.returncode == 0 and result.stdout:
        value = result.stdout.splitlines()[0].strip().lower()
        if value and all(char.isalnum() or char in "_-" for char in value):
            return value
        return "unknown"
    if result.returncode == 1:
        return "none"
    return "unknown"


def system_unit_exists(unit: str) -> bool:
    result = run_command(
        ("systemctl", "show", "--property=LoadState", "--value", unit)
    )
    return result.returncode == 0 and result.stdout == "loaded"


def disable_system_unit(unit: str) -> Control:
    """Disable, stop, mask, and then independently verify a system unit."""
    disabled = run_command(("systemctl", "disable", "--now", unit))
    masked = run_command(("systemctl", "mask", unit))
    active_state = run_command(("systemctl", "is-active", unit))
    enabled_state = run_command(("systemctl", "is-enabled", unit))
    inactive = active_state.stdout in {"inactive", "failed"} and active_state.returncode != 0
    is_masked = enabled_state.stdout == "masked"
    verified = (
        disabled.returncode == 0
        and masked.returncode == 0
        and inactive
        and is_masked
    )
    return Control(
        name=unit,
        detected=True,
        attempted=True,
        verified=verified,
        detail=(
            "stopped, disabled, and masked"
            if verified
            else "could not verify stopped and masked state"
        ),
    )


def inspect_spice() -> list[Control]:
    controls: list[Control] = []
    loaded_units = [unit for unit in KNOWN_SPICE_UNITS if system_unit_exists(unit)]
    for unit in loaded_units:
        controls.append(disable_system_unit(unit))

    agent_installed = any(
        shutil.which(binary) is not None
        for binary in ("spice-vdagent", "spice-vdagentd")
    )
    if agent_installed and not loaded_units:
        controls.append(
            Control(
                name="spice-vdagent",
                detected=True,
                attempted=False,
                verified=False,
                detail="agent installed without a controllable system unit",
            )
        )
    return controls


def inspect_vmware(vm_type: str) -> list[Control]:
    installed = any(
        shutil.which(binary) is not None
        for binary in ("vmware-user", "vmtoolsd", "vmware-toolbox-cmd")
    )
    if not installed and vm_type not in VMWARE_VM_TYPES:
        return []
    return [
        Control(
            name="vmware-host-clipboard-policy",
            detected=True,
            attempted=False,
            verified=False,
            detail=(
                "set isolation.tools.copy.disable, "
                "isolation.tools.paste.disable, and "
                "isolation.tools.dnd.disable in the VM configuration"
            ),
        )
    ]


def inspect_virtualbox(vm_type: str) -> list[Control]:
    installed = shutil.which("VBoxClient") is not None
    if not installed and vm_type not in VBOX_VM_TYPES:
        return []
    return [
        Control(
            name="virtualbox-host-clipboard-policy",
            detected=True,
            attempted=False,
            verified=False,
            detail="set Shared Clipboard and Drag and Drop to Disabled in VM settings",
        )
    ]


def build_state(
    vm_type: str,
    controls: Sequence[Control],
    *,
    checked_at: str | None = None,
) -> dict[str, object]:
    is_vm = vm_type not in {"none", "unknown"}
    guest_controls = [control for control in controls if control.attempted]
    guest_controls_verified = all(control.verified for control in guest_controls)
    failed_guest_control = any(
        control.attempted and not control.verified for control in controls
    )

    if failed_guest_control:
        status = "failed"
        isolated = False
    elif is_vm or vm_type == "unknown":
        # A guest cannot prove the host-side hypervisor configuration.  Keep
        # this state explicitly unresolved even when every guest control passed.
        status = "requires_hypervisor_verification"
        isolated = False
    else:
        status = "not_applicable"
        isolated = True

    return {
        "schema_version": 1,
        "checked_at": checked_at or datetime.now(UTC).isoformat(),
        "virtualization": {
            "detected": is_vm,
            "type": vm_type,
        },
        "status": status,
        "isolated": isolated,
        "guest_controls_verified": guest_controls_verified,
        "host_verification_required": status == "requires_hypervisor_verification",
        "controls": [asdict(control) for control in controls],
    }


def atomic_write_json(path: Path, value: dict[str, object]) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    parent_stat = parent.stat()
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise RuntimeError(f"state parent is not a directory: {parent}")
    if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
        raise RuntimeError(f"state parent must be root-owned and not writable by group/other: {parent}")
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink state path: {path}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    if os.geteuid() != 0:
        log("must run as root")
        return 1

    vm_type = detect_virtualization()
    controls: list[Control] = []
    controls.extend(inspect_spice())
    controls.extend(inspect_vmware(vm_type))
    controls.extend(inspect_virtualbox(vm_type))
    state = build_state(vm_type, controls)

    try:
        atomic_write_json(STATE_PATH, state)
    except (OSError, RuntimeError) as error:
        log(f"failed to write trusted state: {error}")
        return 1

    status = str(state["status"])
    log(f"virtualization={vm_type}; status={status}")
    for control in controls:
        outcome = "verified" if control.verified else control.detail
        log(f"{control.name}: {outcome}")

    if status == "not_applicable":
        return 0
    if status == "requires_hypervisor_verification":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())

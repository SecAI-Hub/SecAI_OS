#!/usr/bin/python3
"""Conservative, typed hardware detection for first boot and local operators."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

STATE_DIR = Path("/var/lib/secure-ai/state")
VM_STATE = STATE_DIR / "vm.json"
GPU_STATE = STATE_DIR / "gpu.json"
TEE_STATE = STATE_DIR / "tee.json"
INFERENCE_ENV = Path("/var/lib/secure-ai/inference.env")
MAX_STATE_BYTES = 1024 * 1024
HYPERVISOR_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
BACKENDS = frozenset({"cpu", "cuda", "rocm", "xpu", "vulkan"})


class DetectionError(RuntimeError):
    """Typed state could not be safely read or written."""


def log(message: str) -> None:
    print(f"[hardware-detect] {message}", flush=True)


def run_command(
    args: Sequence[str],
    *,
    timeout: int = 15,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(args),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(list(args), 125, b"", b"")


def _clean_display(value: str, fallback: str) -> str:
    cleaned = "".join(
        character if character.isprintable() and character not in "\r\n" else " "
        for character in value
    )
    cleaned = " ".join(cleaned.split())[:200]
    return cleaned or fallback


def _strict_object(data: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    value = json.loads(
        data,
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid constant: {constant}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("state is not an object")
    return value


def read_state(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size > MAX_STATE_BYTES
        ):
            raise DetectionError(f"unsafe typed state: {path}")
        data = os.read(descriptor, MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        return _strict_object(data)
    except (ValueError, json.JSONDecodeError) as error:
        raise DetectionError(f"invalid typed state: {path}") from error


def atomic_bytes(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    parent_info = path.parent.stat()
    if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
        raise DetectionError(f"unsafe state directory: {path.parent}")
    if path.is_symlink():
        raise DetectionError(f"refusing symlink state path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path: Path, value: dict[str, object]) -> None:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    atomic_bytes(path, encoded, 0o644)


def detect_virtualization_type() -> str:
    if shutil.which("systemd-detect-virt"):
        result = run_command(("systemd-detect-virt", "--vm"))
        if result.returncode == 1:
            return "none"
        if result.returncode == 0:
            value = result.stdout.decode("ascii", "replace").strip().lower()
            if HYPERVISOR_RE.fullmatch(value):
                return value

    dmi = " ".join(
        _read_text(path)
        for path in (
            Path("/sys/class/dmi/id/product_name"),
            Path("/sys/class/dmi/id/sys_vendor"),
            Path("/sys/class/dmi/id/board_name"),
        )
    ).lower()
    known = (
        ("virtualbox", "oracle"),
        ("vmware", "vmware"),
        ("qemu", "qemu"),
        ("kvm", "kvm"),
        ("hyper-v", "microsoft"),
        ("parallels", "parallels"),
        ("xen", "xen"),
    )
    for marker, name in known:
        if marker in dmi:
            return name
    if "hypervisor" in _read_text(Path("/proc/cpuinfo")).lower():
        return "unknown"
    return "none"


def _read_text(path: Path, limit: int = 64 * 1024) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def gpu_passthrough_visible() -> bool:
    if Path("/dev/nvidia0").exists() or Path("/dev/kfd").exists():
        return True
    if not shutil.which("lspci"):
        return False
    result = run_command(("lspci",), timeout=20)
    output = result.stdout[:1024 * 1024].decode("utf-8", "replace").lower()
    physical_vendor = any(
        vendor in output for vendor in ("nvidia", "amd", "radeon", "intel arc")
    )
    display_device = any(
        marker in output for marker in ("vga", "3d controller", "display controller")
    )
    virtual_only = all(
        marker not in output
        for marker in ("nvidia", "amd", "radeon", "intel arc")
    )
    return physical_vendor and display_device and not virtual_only


def detect_vm() -> dict[str, object]:
    hypervisor = detect_virtualization_type()
    is_vm = hypervisor != "none"
    passthrough = gpu_passthrough_visible() if is_vm else False
    enabled = False
    try:
        old = read_state(VM_STATE)
        enabled = old.get("gpu_enabled") is True
    except (OSError, DetectionError):
        pass
    if not is_vm or not passthrough:
        enabled = False
    warnings: list[str] = []
    if is_vm:
        warnings = [
            "host_can_inspect_guest_memory",
            "snapshots_can_capture_decrypted_state",
            "host_clipboard_policy_requires_verification",
            "co_tenant_timing_side_channels_remain",
        ]
        if passthrough:
            warnings.extend(
                (
                    "host_can_inspect_gpu_memory",
                    "gpu_dma_expands_trust_boundary",
                )
            )
    return {
        "schema_version": 1,
        "detected_at": datetime.now(UTC).isoformat(),
        "is_vm": is_vm,
        "hypervisor": hypervisor,
        "gpu_passthrough": passthrough,
        "gpu_enabled": enabled,
        "warnings": warnings,
    }


def _nvidia_gpu() -> tuple[str, str, int] | None:
    if not shutil.which("nvidia-smi"):
        return None
    probe = run_command(("nvidia-smi",), timeout=20)
    if probe.returncode != 0:
        return None
    name = run_command(
        (
            "nvidia-smi",
            "--query-gpu=name",
            "--format=csv,noheader,nounits",
        ),
        timeout=20,
    )
    first = name.stdout.decode("utf-8", "replace").splitlines()
    return ("cuda", _clean_display(first[0] if first else "", "NVIDIA GPU"), -1)


def _gpu_hardware() -> tuple[str, str, int]:
    nvidia = _nvidia_gpu()
    if nvidia is not None:
        return nvidia
    if Path("/dev/kfd").exists() and Path("/dev/dri/renderD128").exists():
        name = _read_text(Path("/sys/class/drm/card0/device/product_name"))
        return ("rocm", _clean_display(name, "AMD GPU"), -1)
    if Path("/dev/dri/renderD128").exists():
        vendor = _read_text(Path("/sys/class/drm/card0/device/vendor")).lower()
        if vendor == "0x8086":
            name = _clean_display(
                _read_text(Path("/sys/class/drm/card0/device/product_name")),
                "Intel GPU",
            )
            return ("xpu", name, -1 if "arc" in name.lower() else 0)
    if shutil.which("vulkaninfo"):
        result = run_command(("vulkaninfo", "--summary"), timeout=30)
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            if "deviceName" in line and "=" in line:
                name = _clean_display(line.split("=", 1)[1], "Vulkan GPU")
                return ("vulkan", f"{name} (Vulkan)", -1)
    return ("cpu", "CPU (no supported GPU detected)", 0)


def detect_gpu(*, force_cpu: bool = False) -> dict[str, object]:
    backend, name, layers = _gpu_hardware()
    forced_reason = ""
    try:
        vm = read_state(VM_STATE)
    except (OSError, DetectionError):
        vm = detect_vm()
    if force_cpu:
        backend, name, layers = ("cpu", "CPU (fail-safe override)", 0)
        forced_reason = "operator_or_detection_fail_safe"
    elif vm.get("is_vm") is True and vm.get("gpu_enabled") is not True:
        backend, name, layers = (
            "cpu",
            "CPU (VM GPU disabled by policy)",
            0,
        )
        forced_reason = "vm_gpu_disabled"
    if backend not in BACKENDS or layers not in {-1, 0}:
        raise DetectionError("GPU detector produced an invalid execution policy")
    state: dict[str, object] = {
        "schema_version": 1,
        "detected_at": datetime.now(UTC).isoformat(),
        "backend": backend,
        "name": _clean_display(name, "Unknown"),
        "gpu_layers": layers,
        "qualified": False,
    }
    if forced_reason:
        state["forced_reason"] = forced_reason
    return state


def _dmesg() -> str:
    if not shutil.which("dmesg"):
        return ""
    result = run_command(("dmesg",), timeout=20)
    return result.stdout[:4 * 1024 * 1024].decode("utf-8", "replace").lower()


def detect_tee() -> dict[str, object]:
    tee_type = "none"
    active = False
    evidence = ""
    dmesg = _dmesg()
    if Path("/dev/tdx_guest").exists() or Path("/dev/tdx-guest").exists():
        tee_type, active, evidence = (
            "intel-tdx-guest",
            True,
            "tdx guest device",
        )
    elif Path("/sys/kernel/security/sev").exists() or "sev-snp guest" in dmesg:
        tee_type, active, evidence = (
            "amd-sev-guest",
            True,
            "guest SEV interface",
        )
    elif (
        _read_text(Path("/sys/kernel/mm/mem_encrypt/active")).lower()
        in {"1", "y", "yes"}
    ):
        tee_type, active, evidence = (
            "amd-sme",
            True,
            "kernel memory-encryption active flag",
        )
    elif "memory encryption features active" in dmesg:
        tee_type, active, evidence = (
            "memory-encryption",
            True,
            "kernel reported active memory encryption",
        )

    cpu_flags = _read_text(Path("/proc/cpuinfo")).lower()
    capable = any(flag in cpu_flags for flag in (" sev ", " sme ", " tdx ", " tme "))
    return {
        "schema_version": 1,
        "detected_at": datetime.now(UTC).isoformat(),
        "type": tee_type,
        "active": active,
        "memory_encryption": active,
        "capability_hint": capable,
        "evidence": evidence,
        "verified": active,
    }


def write_gpu_state(state: dict[str, object]) -> None:
    backend = state.get("backend")
    layers = state.get("gpu_layers")
    if backend not in BACKENDS or layers not in {-1, 0}:
        raise DetectionError("refusing invalid inference environment")
    atomic_json(GPU_STATE, state)
    atomic_bytes(
        INFERENCE_ENV,
        f"GPU_BACKEND={backend}\nGPU_LAYERS={layers}\n".encode("ascii"),
        0o644,
    )


def set_vm_gpu(enabled: bool) -> None:
    state = read_state(VM_STATE)
    if state.get("is_vm") is not True:
        raise DetectionError("GPU passthrough policy is only valid inside a VM")
    if state.get("gpu_passthrough") is not True:
        raise DetectionError("no physical GPU passthrough was detected")
    state["gpu_enabled"] = enabled
    state["updated_at"] = datetime.now(UTC).isoformat()
    atomic_json(VM_STATE, state)
    write_gpu_state(detect_gpu())


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="secure-hardware-detect.py")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("vm")
    gpu = subparsers.add_parser("gpu")
    gpu.add_argument("--force-cpu", action="store_true")
    subparsers.add_parser("tee")
    vm_gpu = subparsers.add_parser("vm-gpu")
    vm_gpu.add_argument("state", choices=("enable", "disable"))
    show = subparsers.add_parser("show")
    show.add_argument("state", choices=("vm", "gpu", "tee"))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "show":
        path = {"vm": VM_STATE, "gpu": GPU_STATE, "tee": TEE_STATE}[args.state]
        try:
            print(json.dumps(read_state(path), sort_keys=True, separators=(",", ":")))
            return 0
        except (OSError, DetectionError) as error:
            log(f"ERROR: {error}")
            return 1
    if os.geteuid() != 0:
        log("hardware state changes must run as root")
        return 1
    try:
        if args.command == "vm":
            state = detect_vm()
            atomic_json(VM_STATE, state)
        elif args.command == "gpu":
            state = detect_gpu(force_cpu=args.force_cpu)
            write_gpu_state(state)
        elif args.command == "tee":
            state = detect_tee()
            atomic_json(TEE_STATE, state)
        else:
            set_vm_gpu(args.state == "enable")
            state = read_state(VM_STATE)
        print(json.dumps(state, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, DetectionError, ValueError) as error:
        log(f"ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

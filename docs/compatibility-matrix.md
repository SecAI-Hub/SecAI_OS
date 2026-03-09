# Hardware and Software Compatibility Matrix

This document describes the hardware, software, and platform compatibility for SecAI_OS.

Last updated: 2026-03-08

## Base Operating System

| Component | Value |
|-----------|-------|
| Base image | Fedora Silverblue 42 (uBlue) |
| Image type | Immutable (rpm-ostree) |
| Builder | BlueBuild with cosign signing |

## GPU Compatibility

| Vendor | GPU Family | Backend | LLM Support | Diffusion Support | Status |
|--------|-----------|---------|-------------|-------------------|--------|
| NVIDIA | RTX 50-series | CUDA | Yes | Yes | Supported |
| NVIDIA | RTX 40-series | CUDA | Yes | Yes | Supported |
| NVIDIA | RTX 30-series | CUDA | Yes | Yes | Supported |
| AMD | RDNA3 | ROCm/HIP | Yes | Yes | Supported |
| AMD | RDNA2 | ROCm/HIP | Yes | Yes | Supported |
| AMD | CDNA | ROCm/HIP | Yes | Yes | Supported |
| Intel | Arc A-series | XPU/Vulkan | Yes | Yes | Supported |
| Intel | Arc B-series | XPU/Vulkan | Yes | Yes | Supported |
| Apple | M4/M3/M2/M1 | Metal/MPS | Yes | Yes | Supported |
| Any | CPU only | AVX2/AVX-512/NEON | Yes | Yes (slow) | Supported |

## Inference Engine

| Component | Value |
|-----------|-------|
| LLM inference | llama.cpp (llama-server) |
| Model format | GGUF |
| Multi-GPU | Supported (tensor splitting across devices) |

## Minimum Requirements

| Resource | Minimum | Notes |
|----------|---------|-------|
| RAM | 16 GB | 32 GB recommended for larger models |
| VRAM | 8 GB | For GPU-accelerated inference |
| Storage | 64 GB | SSD strongly recommended; more needed for multiple models |
| CPU | x86_64 with AVX2 or ARM64 | AVX-512 preferred for CPU inference |

## Recommended Specs by Workload

| Workload | RAM | VRAM | Storage | Notes |
|----------|-----|------|---------|-------|
| Small LLMs (7B parameters) | 16 GB | 8 GB | 64 GB | Runs on most modern hardware |
| Medium LLMs (13B-30B parameters) | 32 GB | 16 GB | 128 GB | RTX 4070+ or equivalent recommended |
| Large LLMs (65B+ parameters) | 64 GB | 24 GB+ | 256 GB | RTX 4090/5080 or multi-GPU setup |
| Image generation (diffusion) | 32 GB | 12 GB | 128 GB | Dedicated VRAM for diffusion models |
| Multi-model serving | 64 GB | 24 GB+ | 512 GB | Multiple models loaded simultaneously |

## Virtual Machine Support

| Platform | Format | Status | Notes |
|----------|--------|--------|-------|
| VirtualBox | OVA | Supported | GPU passthrough requires compatible host |
| VMware (Workstation/ESXi) | OVA | Supported | vGPU or passthrough for GPU acceleration |
| KVM/QEMU | QCOW2 | Supported | VFIO passthrough for GPU acceleration |
| Proxmox | QCOW2 | Supported | PCI passthrough for GPU acceleration |

### VM Notes

- GPU passthrough is required for GPU-accelerated inference inside a VM.
- CPU-only inference works in any VM without passthrough.
- Allocate at least 16 GB RAM to the VM.
- Nested virtualization is not required.
- Secure Boot in VM requires the host to support UEFI boot for the guest.

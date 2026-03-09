# Non-Goals

This document lists what SecAI OS intentionally does not attempt to do. These are deliberate design boundaries, not missing features.

---

## Not a General-Purpose OS

SecAI OS is a single-purpose AI inference appliance. It is not designed for web browsing, office work, software development, or any other general computing task. The immutable, locked-down base OS is intentionally restrictive. If you need a general-purpose desktop, use a standard Fedora Workstation or similar distribution.

---

## Not a Cloud AI Platform

SecAI OS runs on local hardware. It does not provide multi-tenant inference serving, API billing, model marketplaces, or cloud deployment features. It is designed for a single user on a single machine, not for serving models to remote clients over the internet.

---

## Not a Multi-User System

SecAI OS assumes a single local user who is the trust principal. There is no role-based access control, no user management beyond the OS-level account, and no concept of shared model access between users. The vault has one passphrase. If you need multi-user AI serving, use a purpose-built platform.

---

## Not a Replacement for Confidential Computing Hardware

SecAI OS applies defense-in-depth through software controls: encrypted storage, sandboxed services, network isolation, and integrity monitoring. However, it cannot protect data in use at the hardware level. It does not provide:

- Memory encryption (AMD SEV, Intel TDX)
- Hardware-enforced process isolation beyond what the Linux kernel provides
- Protection against physical memory extraction (cold boot attacks, DMA attacks)

If your threat model includes a physically present attacker with hardware access, you need confidential computing hardware in addition to (not instead of) SecAI OS.

---

## Not Designed for Training

SecAI OS is an inference and generation platform. It does not support:

- Model training or fine-tuning
- Dataset management for training
- Distributed training across multiple GPUs or nodes
- Gradient computation or backpropagation workloads

The quarantine pipeline and registry are designed for pre-trained models in inference-ready formats (GGUF, Safetensors). If you need to train models, do so on a separate system and import the resulting model into SecAI OS.

---

## Not Hardened Against a Malicious Local User

The user is the trust principal. SecAI OS protects the user from untrusted models, network exposure, and software supply chain attacks. It does not protect against the user themselves.

A local user with root access can:

- Disable firewall rules
- Bypass the quarantine pipeline
- Access the decrypted vault contents
- Modify policy files
- Stop or reconfigure services

This is by design. The user owns the machine and the data. SecAI OS defends the user's interests, not a third party's.

---

## No Guaranteed Prevention of Data-in-Use Leakage

When a model is loaded for inference, its weights reside in RAM and/or VRAM in decrypted form. SecAI OS applies memory protections (mlock, seccomp, process isolation) to reduce the risk of leakage, but cannot guarantee that model data or inference content is never exposed in memory.

Specific limitations:

- **RAM:** Model weights and conversation context exist in plaintext in process memory during inference. A memory dump or swap-to-disk event could expose this data.
- **VRAM:** GPU memory is not encrypted. Other processes with GPU access (in a multi-GPU or shared-GPU scenario) could theoretically access VRAM contents.
- **Swap:** SecAI OS disables swap by default, but this is a software configuration that can be changed.

These are fundamental limitations of running software on commodity hardware without confidential computing extensions.

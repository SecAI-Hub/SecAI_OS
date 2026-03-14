# Glossary

Key terms used in SecAI OS documentation.

---

## Terminology Disambiguation

Three uses of "M" numbering appear in this project. They refer to different
things and must not be confused.

### Project Milestones (Milestone 0 through Milestone 43)

Sequential development checkpoints that track feature implementation. Each
milestone represents a concrete deliverable (e.g., Milestone 3 = quarantine
pipeline, Milestone 7 = CI/CD). The full list is in the README roadmap. In the
codebase, milestones are always written as "Milestone N" (never abbreviated
"MN") to avoid confusion with the M5 security assurance level.

### M5 Security Assurance Level

"M5" refers to the **Stronger Isolation** security bar -- the highest assurance
level defined for SecAI OS. It is **not** the same as Milestone 5 (which
implemented the Airlock). M5 assurance requires:

- All 25+ defense layers enforced (see Security Model in README)
- Adversarial test suite passing (prompt injection, policy bypass, containment)
- Continuous integrity monitoring active
- Automated incident containment operational
- Supply chain provenance verified (SBOMs, cosign, SLSA3)

The M5 security bar is defined in
[docs/m5-control-matrix.md](m5-control-matrix.md) and verified by the
`test_m5_acceptance.py` test suite.

### Acceptance Criteria

The M5 acceptance criteria are the specific conditions that must hold for the
system to meet the M5 security assurance level. These are codified in two
places:

- **[docs/m5-control-matrix.md](m5-control-matrix.md)** -- the control matrix
  listing every required security control, its enforcement mechanism, and how
  an operator verifies it.
- **[tests/test_m5_acceptance.py](../tests/test_m5_acceptance.py)** -- the
  automated test suite that CI runs on every push to assert all M5 controls
  are satisfied.

---

## General Terms

**Airlock**
The sanitized egress proxy service. Controls all outbound network traffic from the appliance. Disabled by default. Enforces destination allowlists, PII scanning, and credential scanning.

**Artifact**
A model file registered in the trusted registry. Each artifact has a name, file path, SHA-256 hash, format, source, and status.

**Canary**
A sentinel value or check embedded in the system to detect tampering or unexpected behavior. Used in integrity monitoring and audit verification.

**Cosign**
A tool for signing and verifying container images and artifacts using Sigstore. Used in the quarantine pipeline (Stage 4) to verify model provenance.

**Diffusion Model**
A type of generative AI model that creates images through an iterative denoising process. Subject to Stage 7 (Diffusion Deep Scan) in the quarantine pipeline.

**Encrypted Vault**
A LUKS-encrypted volume at `/var/lib/secure-ai/vault` that stores models, configuration, and sensitive data. Protected by a user passphrase. Auto-locks after idle timeout.

**First Boot**
The initial setup process that runs after rebasing to SecAI OS. Creates the encrypted vault, initializes the registry, configures firewall rules, and runs health checks.

**GGUF**
GPT-Generated Unified Format. A binary format for storing quantized LLM weights, designed for use with llama.cpp. Successor to GGML. Supports metadata, multiple tensor types, and various quantization levels.

**gguf-guard**
A static analysis tool for GGUF files. Performs weight-level inspection, per-tensor hashing, structural fingerprinting, and anomaly detection. Integrated into the quarantine pipeline at Stage 5.

**Greenboot**
A health-check framework for rpm-ostree systems. Runs checks after each boot and automatically rolls back to the previous deployment if checks fail. Ensures the system always boots into a known-good state.

**Inference Worker**
The llama-server process that loads a promoted model and serves inference requests. Handles chat completions and text generation.

**Landlock**
A Linux Security Module (LSM) that restricts filesystem access for processes. Used in systemd service hardening to limit which paths each service can read and write.

**LUKS**
Linux Unified Key Setup. The disk encryption standard used for the encrypted vault. Provides authenticated encryption of the entire vault partition.

**MOK**
Machine Owner Key. A user-enrolled key in the UEFI Secure Boot chain. SecAI OS uses MOK signing to establish a trusted boot path from firmware through the kernel.

**nftables**
The Linux packet filtering framework (successor to iptables). SecAI OS uses nftables to enforce default-deny egress rules, blocking all outbound traffic except through the Airlock when enabled.

**OVA**
Open Virtual Appliance. A packaging format for virtual machines. SecAI OS may be distributed as an OVA for easy import into VirtualBox, VMware, or other hypervisors.

**Pipeline**
The quarantine pipeline: a 7-stage sequential process that verifies, scans, and scores every model before promotion. See Quarantine.

**Promotion**
The act of moving a model from quarantine to the trusted registry after it passes all pipeline stages. Promoted models become available for inference.

**Quarantine**
The holding area and verification process for untrusted models. Models in quarantine cannot be used for inference. They must pass all 7 pipeline stages to be promoted.

**Registry**
The trusted artifact manifest service (port 8470). Maintains a YAML manifest of all promoted models with their SHA-256 hashes, formats, and metadata. Serves as the single source of truth for which models are available.

**rpm-ostree**
The hybrid image/package system used by Fedora Silverblue and other Fedora Atomic variants. Provides atomic updates, rollback, and an immutable base OS. SecAI OS is delivered as an rpm-ostree image.

**Safetensors**
A safe serialization format for ML tensors developed by Hugging Face. Unlike pickle-based formats, safetensors does not permit arbitrary code execution during loading. An allowed format in the quarantine pipeline.

**SearXNG**
A privacy-respecting metasearch engine. SecAI OS runs a local SearXNG instance that aggregates results from DuckDuckGo, Wikipedia, Stack Overflow, and GitHub. All queries are routed through Tor.

**Seccomp-BPF**
Secure Computing mode with Berkeley Packet Filter. A Linux kernel feature that restricts which system calls a process can make. Applied via systemd service units to reduce attack surface.

**securectl**
The SecAI OS command-line management tool. Provides commands for vault management, service control, policy updates, and system diagnostics.

**Smoke Test**
The behavioral testing stage (Stage 6) of the quarantine pipeline. Runs 22 adversarial prompts across 10 categories to test a language model for unsafe behavior before promotion.

**TPM2**
Trusted Platform Module version 2. A hardware security module that provides secure key storage and measured boot. SecAI OS can seal the vault passphrase to TPM2 PCR values for automatic unlock on trusted boots.

**Tool Firewall**
The policy-gated tool invocation gateway (port 8475). Enforces default-deny policy on all tool calls from the inference worker. Prevents models from executing unauthorized operations.

**Tor**
The Onion Router. An anonymity network that routes traffic through multiple relays. Used by the Search Mediator to hide the appliance's IP address when performing web searches.

**uBlue**
A community project that builds custom Fedora Atomic/Silverblue images using OCI containers. SecAI OS is built on top of uBlue's image infrastructure using BlueBuild.

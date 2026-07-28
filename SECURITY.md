# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecAI OS, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/SecAI-Hub/SecAI_OS/security/advisories/new)
   to report the vulnerability privately.
2. **Email:** Send details to **security@secai-hub.github.io**.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof-of-concept.
- The affected component(s) (e.g., quarantine pipeline, vault, airlock).
- Your suggested severity rating (Critical / High / Medium / Low).

### Response Timeline

| Stage | Timeframe |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Fix for Critical severity | Within 90 days |
| Fix for High severity | Within 90 days |
| Fix for Medium / Low severity | Best effort, typically within 180 days |

We will coordinate disclosure with you and credit reporters unless they prefer
to remain anonymous.

## Supported Versions

As of 2026-07-27, no published SecAI OS release has completed the
release-specific production readiness and hardware qualification process.
`main` is a development branch and v0.3.0 is retained for historical evaluation
only. Neither should be used for sensitive or customer workloads.

Future support begins only when a stable release publishes a non-placeholder
image digest, passing release-verification report, signed provenance, complete
SBOMs, boot/reboot evidence, update/rollback evidence, and signed production
sign-off. Supported versions will then be listed here explicitly.

## Scope

### In Scope

The following components are in scope for security reports:

- **Go services** -- registry, tool-firewall, airlock, policy engine, MCP
  firewall, runtime attestor, integrity monitor, GPU integrity watch, and
  incident recorder
- **Python services** -- quarantine watcher, UI, search mediator, diffusion
  worker, and Agent
- **Quarantine pipeline** -- model scanning, hash verification, GGUF validation
- **Vault** -- LUKS encryption, TPM2 sealing, passphrase authentication
- **Airlock** -- egress controls, allowlist enforcement
- **Firewall** -- nftables rules, DNS leak prevention
- **Firstboot and system hardening** -- seccomp-bpf, Landlock, sysctl, systemd unit policies
- **Secure Boot chain** -- MOK signing, measured boot
- **Audit logging** -- hash-chained tamper-evident logs
- **Tor integration** -- traffic routing, search privacy

### Out of Scope

The following are **not** in scope. Please report these to their respective
upstream projects:

- **Fedora / uBlue base OS** -- kernel, systemd, RPM packages
- **llama.cpp / llama-server** -- inference engine bugs
- **SearXNG** -- search engine vulnerabilities
- **NVIDIA drivers / CUDA runtime**
- **OPA / Rego** (when adopted) -- policy engine core bugs
- **Third-party Python or Go dependencies** -- report upstream defects to their
  maintainer, but report SecAI OS exposure or unsafe integration here as well

If you are unsure whether an issue is in scope, feel free to report it and we
will triage accordingly.

## Threat Boundaries

SecAI OS follows a defense-in-depth architecture. For a detailed description of
the trust boundaries, threat actors, and mitigations, see
[docs/threat-model.md](docs/threat-model.md).

Key boundaries include:

- **Network boundary** -- workloads are denied direct egress; approved
  acquisition is performed by the authenticated Airlock fetch proxy and private
  search is routed through Tor.
- **Model trust boundary** -- all models are untrusted until they pass the
  quarantine pipeline (hash check, GGUF structure scan, tensor audit).
- **Runtime boundary** -- intended appliance controls include systemd
  sandboxing, syscall restrictions, Landlock, and no direct inference egress.
  Each control remains release-evidence dependent.
- **Storage boundary** -- the vault is LUKS-encrypted and optionally
  TPM2-sealed; plaintext secrets never touch persistent storage.

## Coordinated Disclosure

We follow a coordinated disclosure process. We ask that you:

1. Allow us reasonable time to investigate and release a fix before public
   disclosure.
2. Avoid exploiting the vulnerability beyond what is necessary to demonstrate
   the issue.
3. Do not access, modify, or delete data belonging to other users.

Thank you for helping keep SecAI OS secure.

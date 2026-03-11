# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Yes                |
| < 0.2   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in runtime-attestor, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@secai-hub.dev**

Include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Security Design

runtime-attestor follows defense-in-depth principles:

- **Authentication**: All non-health HTTP endpoints require a bearer token (`SERVICE_TOKEN`)
- **Constant-time token comparison**: `crypto/subtle.ConstantTimeCompare` prevents timing attacks
- **Hardened HTTP server**: `http.Server` with read/write timeouts to prevent slowloris
- **Registry hardening**: Response size limits, auth header forwarding, URL scheme validation
- **Filesystem safety**: Symlink rejection via `os.Lstat`, device/FIFO/socket rejection, max file size enforcement
- **Critical collector failures**: Model and policy collector errors escalate to hard "fail" verdicts
- **Privacy redaction**: Reports can strip hostnames, paths, listener addresses, and policy names
- **Ed25519 signing**: Trust reports are signed with Ed25519 keys for tamper detection
- **Rate limiting**: Per-minute request caps prevent abuse of the attestation endpoint
- **Non-root execution**: The container runs as UID 65534 (nobody)
- **Localhost binding**: Daemon defaults to 127.0.0.1:8485

## Threat Model

See the parent project's [threat model](https://github.com/SecAI-Hub/SecAI_OS/blob/main/docs/threat-model.md) for the full system-level analysis.

Key threats specific to runtime-attestor:
- **Report tampering**: Mitigated by Ed25519 signatures
- **Model substitution**: Detected by SHA-256 hash comparison against registry manifest
- **Policy drift**: Detected by policy file hash verification against approved baselines
- **Symlink attacks on vault**: Mitigated by Lstat checks rejecting non-regular files
- **PII leakage in reports**: Mitigated by configurable privacy redaction profiles

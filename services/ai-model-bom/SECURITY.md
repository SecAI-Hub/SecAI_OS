# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Yes                |
| < 0.2   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in ai-model-bom, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@secai-hub.dev**

Include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Security Design

ai-model-bom follows defense-in-depth principles:

- **Authentication**: All non-health HTTP endpoints require a bearer token (`SERVICE_TOKEN` env)
- **Path allowlisting**: The `/v1/generate` endpoint only scans directories listed in `allowed_paths`
- **Symlink rejection**: `os.Lstat` is used to detect and reject symlinks, devices, FIFOs, and sockets
- **File size limits**: Files exceeding 10 GiB are skipped during scanning
- **Request size limits**: HTTP request bodies are capped with `io.LimitReader`
- **Server timeouts**: `http.Server` enforces read and write timeouts
- **Constant-time token comparison**: `crypto/subtle.ConstantTimeCompare` prevents timing attacks
- **Ed25519 signing**: BOMs and attestations are signed with Ed25519 keys
- **Privacy redaction**: Evidence can be stripped of emails, paths, hostnames, and usernames before export
- **Input validation**: URLs, SPDX licenses, timestamps, and enums are validated before use
- **Non-root execution**: The container runs as UID 65534 (nobody)

## Threat Model

See the parent project's [threat model](https://github.com/SecAI-Hub/SecAI_OS/blob/main/docs/threat-model.md) for the full system-level analysis.

Key threats specific to ai-model-bom:
- **BOM tampering**: Mitigated by Ed25519 signatures and SHA-256 hash chains
- **Path traversal**: Mitigated by allowlisted root directories and symlink rejection
- **PII leakage in evidence**: Mitigated by configurable privacy redaction profiles
- **Unauthorized BOM generation**: Mitigated by service token authentication

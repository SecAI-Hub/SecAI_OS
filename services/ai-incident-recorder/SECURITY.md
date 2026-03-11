# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Yes                |
| < 0.2   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in ai-incident-recorder, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@secai-hub.dev**

Include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Security Design

ai-incident-recorder follows defense-in-depth principles:

- **Authentication**: All non-health HTTP endpoints require a bearer token (`SERVICE_TOKEN`)
- **Constant-time token comparison**: `crypto/subtle.ConstantTimeCompare` prevents timing attacks
- **Hardened HTTP server**: `http.Server` with read/write timeouts to prevent slowloris
- **Request body limits**: `http.MaxBytesReader` caps request bodies (1 MiB single, 10 MiB batch)
- **Schema validation**: Events and incidents are validated for severity/status enums, timestamp formats, source/type patterns, and session ID length
- **Retention enforcement**: Configurable max events per session, max sessions, and expiry
- **Hash chain integrity**: SHA-256 hash chains link events for tamper detection
- **Ed25519 signing**: Case bundles are signed with Ed25519 keys for authenticity
- **PII redaction**: Configurable redaction of SSNs, emails, credentials, bearer tokens, and credit cards
- **Privacy profiles**: Named profiles (internal, external-share, legal-review) control bundle redaction levels
- **Redaction consistency**: Both single and batch ingestion apply identical on-record redaction
- **File store hardening**: fsync after writes, corruption-tolerant JSONL loading
- **Rate limiting**: Per-minute request caps prevent abuse
- **Non-root execution**: The container runs as UID 65534 (nobody)
- **Localhost binding**: Daemon defaults to 127.0.0.1:8495

## Threat Model

See the parent project's [threat model](https://github.com/SecAI-Hub/SecAI_OS/blob/main/docs/threat-model.md) for the full system-level analysis.

Key threats specific to ai-incident-recorder:
- **Evidence tampering**: Mitigated by SHA-256 hash chains and Ed25519 bundle signatures
- **PII leakage in bundles**: Mitigated by configurable privacy profiles and redaction patterns
- **Denial-of-service via storage**: Mitigated by retention limits (max events, max sessions, expiry)
- **Slowloris / slow-read attacks**: Mitigated by hardened http.Server with read/write timeouts
- **Schema injection**: Mitigated by structured validation of severity, status, source, type, timestamps

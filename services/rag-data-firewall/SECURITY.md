# Security Design — rag-data-firewall

## Overview

The RAG Data Firewall is a policy-enforced gateway that controls which
document chunks may be returned to AI models and tools during retrieval.
It provides content scanning, PII redaction, and tamper-evident audit logging.

## Authentication

All non-health endpoints require a bearer token (SERVICE_TOKEN). The
token is loaded from `/run/secure-ai/service-token` and compared using
`crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

## Policy Evaluation — Deny-First Precedence

The policy engine uses **deny-first** rule evaluation:

1. All deny rules are checked first, regardless of position in the config
2. If any deny rule matches, the chunk is blocked immediately
3. Non-deny rules (require-approval, redact, allow) are then evaluated in order
4. If no rule matches, the default action applies (deny by default)

This prevents an early allow rule from accidentally overriding a
security-critical deny rule.

## Content Scanning

The scanner detects:

- **Direct prompt injection**: 14 patterns (ignore instructions, role override, etc.)
- **Encoded injection**: Unicode bidi overrides, zero-width hiding, HTML entity tags, hex escapes
- **Instruction smuggling**: Markdown fence injection, HTML comment injection, invisible text, delimiter role switching
- **Data exfiltration**: URL fetch, file protocol, markdown exfil, DNS exfil, send-data instructions
- **Base64-encoded injection**: Decodes base64 strings and checks for embedded injection patterns
- **PII detection**: SSN, email, credit card, credentials, bearer tokens, phone numbers
- **Suspicious patterns**: eval, exec, import os, subprocess, script tags

Each finding produces a structured `RiskReason` with category, pattern,
weight, and detail for explainability.

## Retrieval Scoping

Non-system callers must provide explicit `chunk_ids` or `document_ids`.
Unscoped retrieval (AllChunks fallback) is only available to
`requester_type=system`, preventing tools and users from accessing the
entire corpus without specifying what they need.

## Data Protection

- **Retention limits**: Configurable max documents, max total chunks, and TTL
- **Document deletion**: Documents and their chunks can be deleted via API
- **PII redaction**: Content matching PII patterns is replaced with tagged placeholders
- **fsync durability**: All JSONL writes are followed by fsync

## Tamper-Evident Audit Logging

Every action (ingest, retrieve, delete, reload) is logged to a JSONL
audit file with a SHA-256 hash chain. Each entry includes:

- `hash`: SHA-256 of the entry's canonical fields
- `prev_hash`: hash of the preceding entry

This chain allows detection of any inserted, deleted, or modified entries.

## HTTP Server Hardening

- `http.Server` with configurable read/write/idle timeouts (defaults: 30s/60s/120s)
- `MaxBytesReader` on all request bodies (10 MiB limit)
- Rate limiting (configurable requests per minute)
- Consistent JSON error responses on all endpoints

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Prompt injection in documents | Content scanning with 14+ injection patterns plus encoded/smuggling detection |
| PII leakage via RAG retrieval | PII detection + redaction action in policy rules |
| Unauthorized access to chunks | Bearer token auth on all endpoints + deny-by-default policy |
| Unscoped data access | Retrieval scoping (require explicit chunk/doc IDs for non-system callers) |
| Policy misconfiguration | Deny-first precedence ensures deny rules always take priority |
| Audit log tampering | Hash chain on audit entries |
| Data accumulation | Retention limits + TTL-based expiration + document deletion |

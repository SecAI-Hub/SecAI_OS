# Registry Service

## Overview

- **Purpose:** Trusted artifact manifest and read-only model store
- **Port:** 8470
- **Language:** Go
- **Systemd unit:** secure-ai-registry.service

The Registry is the single source of truth for which models are available for inference. Only models that have passed the full quarantine pipeline can be promoted into the registry. Once promoted, models are served read-only to the inference worker.

---

## API Endpoints

### GET /v1/models

List all registered artifacts.

**Response:** `200 OK`

```json
[
  {
    "name": "mistral-7b-instruct-v0.3.Q4_K_M",
    "path": "/var/lib/secure-ai/models/mistral-7b-instruct-v0.3.Q4_K_M.gguf",
    "sha256": "abc123...",
    "format": "gguf",
    "source": "huggingface",
    "status": "promoted",
    "promoted_at": "2026-03-06T12:00:00Z",
    "gguf_guard_fingerprint": "def456...",
    "gguf_guard_manifest": { ... }
  }
]
```

### GET /v1/model/{name}

Get a single artifact by name.

**Response:** `200 OK` with artifact JSON, or `404 Not Found`.

### POST /v1/promote

Promote a quarantined artifact to the registry. Called by the quarantine pipeline after all stages pass.

**Request body:**

```json
{
  "name": "mistral-7b-instruct-v0.3.Q4_K_M",
  "path": "/var/lib/secure-ai/quarantine/mistral-7b-instruct-v0.3.Q4_K_M.gguf",
  "sha256": "abc123...",
  "format": "gguf",
  "source": "huggingface"
}
```

**Response:** `200 OK` on success, `400 Bad Request` if validation fails.

### DELETE /v1/model/{name}

Remove an artifact from the registry.

**Response:** `200 OK` on success, `404 Not Found` if not registered.

### POST /v1/model/verify-manifest

Verify the integrity of all registered artifacts against their stored SHA-256 hashes.

**Response:** `200 OK` with verification results.

---

## Data Model

The `Artifact` struct represents a registered model:

| Field | Type | Description |
|---|---|---|
| `name` | string | Human-readable model name |
| `path` | string | Absolute filesystem path to the model file |
| `sha256` | string | SHA-256 hash of the model file at promotion time |
| `format` | string | File format (gguf, safetensors, etc.) |
| `source` | string | Origin (huggingface, local, etc.) |
| `status` | string | Current status (promoted, quarantined) |
| `promoted_at` | timestamp | When the model was promoted |
| `gguf_guard_fingerprint` | string | Structural fingerprint from gguf-guard (GGUF only) |
| `gguf_guard_manifest` | object | Per-tensor manifest from gguf-guard (GGUF only) |

---

## Manifest Storage

The registry persists its state to a YAML manifest file:

```
/var/lib/secure-ai/registry/manifest.yaml
```

This file is read on startup and written on every promote/delete operation. It is the authoritative record of all trusted models.

---

## Integrity Monitoring

A systemd timer runs every 15 minutes to verify the SHA-256 hash of every registered model file against the value stored in the manifest. If a mismatch is detected:

1. The affected model is moved to quarantine status.
2. An alert is logged to the audit log.
3. The model becomes unavailable for inference until re-verified.

This detects both accidental corruption and tampering.

---

## Systemd Sandboxing

The registry service runs with hardened systemd settings:

- `ProtectSystem=strict` -- read-only root filesystem
- `ProtectHome=yes` -- no access to home directories
- `PrivateTmp=yes` -- isolated /tmp
- `NoNewPrivileges=yes` -- cannot gain new privileges
- `ReadWritePaths=/var/lib/secure-ai/registry` -- only writable path

# HTTP API Reference

All services communicate over HTTP on localhost. This document covers every endpoint across all SecAI OS services.

---

## Registry API (port 8470)

### GET /v1/models

List all registered model artifacts.

- **Response:** `200 OK` -- JSON array of artifact objects
- **Fields per artifact:** name, path, sha256, format, source, status, promoted_at, gguf_guard_fingerprint, gguf_guard_manifest

### GET /v1/model/{name}

Retrieve a single artifact by name.

- **Response:** `200 OK` -- JSON artifact object
- **Error:** `404 Not Found` -- model not in registry

### POST /v1/promote

Promote a quarantined model to the registry.

- **Request body:**
  ```json
  {
    "name": "model-name",
    "path": "/var/lib/secure-ai/quarantine/model-file",
    "sha256": "hash",
    "format": "gguf",
    "source": "huggingface"
  }
  ```
- **Response:** `200 OK` -- promotion successful
- **Error:** `400 Bad Request` -- validation failed

### DELETE /v1/model/{name}

Remove a model from the registry.

- **Response:** `200 OK` -- model removed
- **Error:** `404 Not Found` -- model not in registry

### POST /v1/model/verify-manifest

Verify SHA-256 integrity of all registered models.

- **Response:** `200 OK` -- JSON object with per-model verification results

---

## Tool Firewall API (port 8475)

### POST /v1/tool/invoke

Invoke a tool through the policy firewall.

- **Request body:**
  ```json
  {
    "tool": "tool_name",
    "arguments": { "key": "value" }
  }
  ```
- **Response:** `200 OK` -- tool invocation allowed and result returned
  ```json
  {
    "status": "allowed",
    "result": { ... }
  }
  ```
- **Error:** `403 Forbidden` -- tool denied by policy
  ```json
  {
    "status": "denied",
    "reason": "description of why the tool was denied"
  }
  ```
- **Error:** `400 Bad Request` -- invalid arguments (blocked pattern, length exceeded)
- **Error:** `429 Too Many Requests` -- rate limit exceeded

---

## Airlock API (port 8490)

### POST /v1/proxy

Proxy an outbound request through the Airlock.

- **Request body:**
  ```json
  {
    "url": "https://example.com/path",
    "method": "GET",
    "headers": {},
    "body": null
  }
  ```
- **Response:** `200 OK` -- proxied response returned
- **Error:** `403 Forbidden` -- destination not allowlisted, PII detected, or credentials detected
  ```json
  {
    "error": "description of block reason"
  }
  ```
- **Error:** `429 Too Many Requests` -- rate limit exceeded
- **Error:** `503 Service Unavailable` -- Airlock is disabled

---

## Agent API (port 8476)

### POST /v1/task

Submit a new task for the agent to plan and execute.

- **Request body:**
  ```json
  {
    "intent": "summarize the documents in my workspace",
    "mode": "standard",
    "workspace": ["user_docs"],
    "preferences": { "read_file": "always" }
  }
  ```
- **Fields:**
  - `workspace`: array of workspace IDs (not raw paths). Available IDs: `user_docs`, `outputs`. Resolved to filesystem paths server-side.
- **Response:** `201 Created` -- task with planned steps
- **Error:** `400 Bad Request` -- missing intent, invalid mode, or unknown workspace ID

### GET /v1/task/{id}

Get task status and step details.

- **Response:** `200 OK` -- task object with steps
- **Error:** `404 Not Found` -- task not found

### POST /v1/task/{id}/approve

Approve pending steps that require user confirmation.

- **Request body:**
  ```json
  {
    "step_ids": ["abc123"],
    "approve_all": false
  }
  ```
- **Response:** `200 OK` -- updated task

### POST /v1/task/{id}/deny

Deny pending steps.

- **Request body:**
  ```json
  {
    "step_ids": ["abc123"],
    "deny_all": false
  }
  ```
- **Response:** `200 OK` -- updated task

### POST /v1/task/{id}/cancel

Cancel a running or pending task.

- **Response:** `200 OK` -- task cancelled
- **Error:** `409 Conflict` -- task already completed/failed/cancelled

### GET /v1/tasks

List all tasks (most recent first).

- **Query params:** `limit` (default 50, max 200)
- **Response:** `200 OK` -- array of task objects

### GET /v1/modes

List available operating modes with descriptions.

- **Response:** `200 OK` -- array of mode objects (offline_only, standard, online_assisted, sensitive)

---

## UI API (port 8480)

### Model Management

#### GET /api/models

List all models (combines registry and quarantine data).

- **Response:** `200 OK` -- JSON array of model objects with status information

#### POST /api/models/download

Initiate a model download through the Airlock.

- **Request body:**
  ```json
  {
    "url": "https://huggingface.co/...",
    "name": "model-name"
  }
  ```
- **Response:** `200 OK` -- download initiated
- **Error:** `400 Bad Request` -- invalid URL or name
- **Error:** `503 Service Unavailable` -- Airlock disabled

#### POST /api/models/import

Import a local model file into quarantine.

- **Request body:** Multipart form data with model file
- **Response:** `200 OK` -- model submitted to quarantine
- **Error:** `400 Bad Request` -- invalid file or format

#### POST /api/models/verify-manifest

Trigger integrity verification of all registered models.

- **Response:** `200 OK` -- verification results

### Chat and Generation

#### POST /api/chat

Send a chat message and receive a response from the active model.

- **Request body:**
  ```json
  {
    "message": "user message text",
    "model": "model-name",
    "conversation_id": "optional-id"
  }
  ```
- **Response:** `200 OK` -- streaming or complete response from the model

#### POST /api/generate

Generate text from a prompt (non-chat completion).

- **Request body:**
  ```json
  {
    "prompt": "prompt text",
    "model": "model-name",
    "max_tokens": 512
  }
  ```
- **Response:** `200 OK` -- generated text

### Vault Management

#### GET /api/vault/status

Get the current vault lock/unlock status.

- **Response:** `200 OK`
  ```json
  {
    "status": "unlocked",
    "locked_at": null,
    "auto_lock_minutes": 15
  }
  ```

#### POST /api/vault/lock

Lock the encrypted vault immediately.

- **Response:** `200 OK` -- vault locked

#### POST /api/vault/unlock

Unlock the encrypted vault with a passphrase.

- **Request body:**
  ```json
  {
    "passphrase": "user-passphrase"
  }
  ```
- **Response:** `200 OK` -- vault unlocked
- **Error:** `401 Unauthorized` -- incorrect passphrase
- **Error:** `429 Too Many Requests` -- rate limited after failed attempts

#### POST /api/vault/keepalive

Reset the vault auto-lock idle timer.

- **Response:** `200 OK` -- timer reset

### Emergency

#### POST /api/emergency/panic

Trigger an emergency panic action (locks vault, optionally shuts down).

- **Response:** `200 OK` -- panic action executed

### Updates

#### GET /api/updates/check

Check for available OS updates.

- **Response:** `200 OK`
  ```json
  {
    "available": true,
    "version": "42.20260308",
    "changelog": "..."
  }
  ```

#### POST /api/updates/stage

Download and stage an update without applying it.

- **Response:** `200 OK` -- update staged

#### POST /api/updates/apply

Apply a staged update (requires reboot).

- **Response:** `200 OK` -- update applied, reboot required

#### POST /api/updates/rollback

Roll back to the previous OS deployment.

- **Response:** `200 OK` -- rollback staged, reboot required

### Hardware

#### POST /api/vm/gpu

Get GPU information and status.

- **Response:** `200 OK`
  ```json
  {
    "detected": true,
    "type": "nvidia",
    "name": "NVIDIA RTX 5080",
    "vram_mb": 16384
  }
  ```

### Security

#### GET /api/security/status

Get the overall security status of the appliance.

- **Response:** `200 OK`
  ```json
  {
    "vault_status": "unlocked",
    "firewall_active": true,
    "airlock_enabled": false,
    "search_enabled": false,
    "integrity_ok": true,
    "last_integrity_check": "2026-03-08T12:00:00Z"
  }
  ```

---

## Search Mediator API (port 8485)

### POST /search

Submit a sanitized web search query.

- **Request body:**
  ```json
  {
    "query": "search terms",
    "max_results": 5
  }
  ```
- **Response:** `200 OK`
  ```json
  {
    "results": [
      {
        "title": "Page Title",
        "url": "https://example.com",
        "snippet": "Relevant text excerpt..."
      }
    ],
    "query_sanitized": true,
    "results_filtered": 0
  }
  ```
- **Error:** `503 Service Unavailable` -- Search Mediator is disabled

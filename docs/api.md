# HTTP API Reference

All production services bind to loopback or a Unix socket. The Docker sandbox binds service ports inside the compose network and only publishes the UI to the host by default.

Mutating service-to-service endpoints require the shared bearer token when the token file is present. Development mode may run without that token for local tests.

---

## Registry API (port 8470)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and model count. |
| GET | `/v1/models` | No | List registered model artifacts. |
| GET | `/v1/model?name=<name>` | No | Retrieve one artifact by name. |
| GET | `/v1/model/path?name=<name>` | No | Return the model file path for a registered artifact. |
| POST | `/v1/model/verify?name=<name>` | No | Recompute and compare one model's SHA-256 hash. |
| POST | `/v1/models/verify-all` | No | Verify every registered model. |
| GET | `/v1/integrity/status` | No | Return aggregate registry integrity state. |
| POST | `/v1/model/verify-manifest?name=<name>` | No | Verify the gguf-guard per-tensor manifest for one GGUF model. |
| POST | `/v1/model/promote` | Token | Promote a quarantined artifact into the registry. |
| DELETE | `/v1/model/delete?name=<name>` | Token | Remove an artifact from the registry manifest. |

Promotion body:

```json
{
  "name": "model-name",
  "filename": "model.gguf",
  "sha256": "sha256...",
  "size_bytes": 123456789,
  "source": "huggingface",
  "scan_results": {},
  "scanner_versions": {}
}
```

---

## Tool Firewall API (port 8475)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness plus request counters. |
| POST | `/v1/evaluate` | No | Evaluate one tool call against policy. |
| GET | `/v1/stats` | No | Policy and request counters. |
| POST | `/v1/reload` | Token | Reload policy from disk. |

Evaluation body:

```json
{
  "tool": "filesystem.read",
  "params": {
    "path": "/vault/user_docs/example.txt"
  }
}
```

`args` is still accepted as a legacy alias for `params`. Responses use `allowed: true|false` and include `reason` when denied.

---

## Airlock API (port 8490)

The Airlock is a policy decision service, not a generic open proxy. The UI checks each model download URL and redirect with the Airlock before downloading the artifact into quarantine.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and enabled state. |
| POST | `/v1/egress/check` | No | Decide whether an outbound request is allowed. |
| GET | `/v1/stats` | No | Request counters and allowlist summary. |
| POST | `/v1/reload` | Token | Reload policy and source allowlist. |

Decision body:

```json
{
  "destination": "https://huggingface.co/org/repo/resolve/main/model.gguf",
  "method": "GET",
  "body": ""
}
```

Responses use `allowed: true|false` and include `reason` when blocked. Disabled Airlock policy returns service-unavailable semantics to callers.

---

## Policy Engine API (port 8500)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness. |
| POST | `/api/v1/decide` | No | Evaluate a unified policy decision. |
| GET | `/api/v1/stats` | No | Decision counters. |
| GET | `/api/v1/digest` | No | Current policy digest. |
| POST | `/api/v1/reload` | Token | Reload main and agent policies. |

---

## MCP Firewall API (port 8496)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness. |
| POST | `/v1/evaluate` | No | Evaluate one MCP tool call. |
| POST | `/v1/evaluate/batch` | No | Evaluate a batch of MCP tool calls. |
| GET | `/v1/servers` | No | Summarize configured MCP servers and tools. |
| GET | `/v1/policy` | No | Summarize loaded policy. |
| GET | `/v1/taint/<session_id>` | No | Return taint state for a session. |
| DELETE | `/v1/taint/<session_id>` | No | Clear taint state for a session. |
| GET | `/v1/audit` | No | Return recent audit entries. |
| GET | `/v1/audit/verify` | No | Verify the hash-chained audit log. |
| GET | `/v1/metrics` | No | Decision and HTTP metrics. |
| POST | `/v1/reload` | Token | Reload MCP policy. |

---

## Verification Services

### Runtime Attestor (port 8505)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and attestation state. |
| GET | `/api/v1/attest` | No | Current attestation bundle. |
| GET | `/api/v1/verify` | No | Startup-gating verification result. |
| GET | `/api/security/status` | No | UI-friendly security status. |
| POST | `/api/v1/refresh` | Token | Refresh attestation state. |

### Integrity Monitor (port 8510)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and integrity state. |
| GET | `/api/v1/status` | No | Current monitor status. |
| GET | `/api/v1/baseline` | No | Current baseline metadata. |
| GET | `/api/v1/verify` | No | Verify current integrity state. |
| POST | `/api/v1/scan` | Token | Trigger an immediate scan. |
| POST | `/api/v1/rebaseline` | Token | Capture a new trusted baseline. |
| POST | `/api/v1/reload` | Token | Reload monitor policy. |

### Incident Recorder (port 8515)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and incident counts. |
| GET | `/api/v1/incidents` | No | List incidents, filterable by `class`, `state`, and `severity`. |
| GET | `/api/v1/incidents/get?id=<id>` | No | Fetch one incident. |
| GET | `/api/v1/stats` | No | Incident statistics. |
| GET | `/api/v1/recovery/status` | No | Pending recovery ceremonies. |
| POST | `/api/v1/incidents/report` | Token | Report a new incident. |
| POST | `/api/v1/incidents/resolve` | Token | Mark an incident resolved. |
| POST | `/api/v1/incidents/acknowledge` | Token | Acknowledge an incident. |
| POST | `/api/v1/recovery/ack` | Token | Acknowledge recovery requirements. |
| POST | `/api/v1/recovery/reattest` | Token | Submit recovery re-attestation. |
| GET | `/api/v1/forensic/export` | Token | Export a signed forensic bundle. |
| POST | `/api/v1/reload` | Token | Reload containment policy. |

### GPU Integrity Watch (port 8495)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness. |
| POST | `/v1/check` | No | Run a probe cycle. |
| GET | `/v1/status` | No | Latest verdict and probe results. |
| GET | `/v1/history` | No | Score history. |
| GET | `/v1/metrics` | No | Probe and action counters. |
| GET | `/v1/attest-state` | No | GPU state for runtime attestation. |
| POST | `/v1/baseline` | Token | Recapture GPU/model baseline. |
| POST | `/v1/reload` | Token | Reload profile and baseline. |

---

## Agent API

Production UI-to-agent traffic uses `/run/secure-ai/agent.sock`. Development TCP fallback is `127.0.0.1:8476`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness. |
| POST | `/v1/task` | Submit a task. |
| GET | `/v1/task/<id>` | Get task status. |
| POST | `/v1/task/<id>/approve` | Approve pending steps. |
| POST | `/v1/task/<id>/deny` | Deny pending steps. |
| POST | `/v1/task/<id>/cancel` | Cancel a task. |
| GET | `/v1/tasks` | List recent tasks. |
| GET | `/v1/modes` | List operating modes. |

The UI exposes authenticated proxy routes under `/api/agent/*` with the same task semantics.

---

## UI API (port 8480)

### Auth, Setup, And Pages

| Method | Path | Description |
|---|---|---|
| GET | `/health` | UI liveness. |
| GET | `/api/auth/status` | Setup/login/session state. |
| POST | `/api/auth/setup` | Create the local passphrase. |
| POST | `/api/auth/login` | Start a session. |
| POST | `/api/auth/logout` | End a session. |
| POST | `/api/auth/change` | Change passphrase. |
| POST | `/api/setup/complete` | Mark setup complete. |

### Models And Catalog

| Method | Path | Description |
|---|---|---|
| GET | `/api/catalog` | Curated model catalog. |
| POST | `/api/catalog/download` | Start a curated model download through Airlock checks. |
| GET | `/api/catalog/downloads` | Active/recent download status. |
| GET | `/api/catalog/auth/status` | Credential/auth guidance for model sources. |
| GET | `/api/models` | Registry and quarantine model summary. |
| GET | `/api/models/quarantine` | Quarantine status. |
| POST | `/api/models/import` | Upload/import a local model into quarantine. |
| POST | `/api/models/verify` | Verify one registered model. |
| POST | `/api/models/verify-manifest` | Verify gguf-guard manifest for one model. |
| POST | `/api/models/delete` | Delete a registered model. |
| GET | `/api/models/fsverity` | Model fs-verity/provenance summary. |
| GET | `/api/integrity/status` | Registry integrity status. |
| POST | `/api/integrity/verify-all` | Verify all registered models. |

### Chat, Search, And Generation

| Method | Path | Description |
|---|---|---|
| GET | `/api/inference/status` | Inference service status and selected model readiness. |
| POST | `/api/chat` | Send one chat request. |
| POST | `/api/chat/stream` | Streaming chat. |
| POST | `/api/search` | Search mediator request. |
| GET | `/api/search/status` | Search availability/profile state. |
| POST | `/api/chat/search` | Chat with search context. |
| POST | `/api/generate/image` | Generate an image. |
| POST | `/api/generate/video` | Generate video frames/clip. |
| POST | `/api/generate/img2img` | Image-to-image generation. |
| GET | `/api/diffusion/models` | Diffusion model inventory. |

### Profiles And Sandbox Automation

| Method | Path | Description |
|---|---|---|
| GET | `/api/profile` | Current privacy profile. |
| POST | `/api/profile/preview` | Preview a profile change. |
| POST | `/api/profile/select` | Select a privacy profile. |
| GET | `/api/profile/status` | Profile application status. |
| GET | `/api/sandbox/control/status` | Sandbox host-controller state. |
| POST | `/api/sandbox/control/apply` | Ask the host controller to restart/apply profile services. |

### Diffusion Runtime Installer

| Method | Path | Description |
|---|---|---|
| GET | `/api/diffusion/runtime/status` | Runtime installed/failed/installable state. |
| POST | `/api/diffusion/runtime/enable` | Request privileged runtime installation via marker file. |
| GET | `/api/diffusion/runtime/progress` | Installer progress after enable is requested. |

### Security, Vault, Updates, And Observability

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Aggregate service health and SLO input. |
| GET | `/api/security/stats` | Security statistics. |
| GET | `/api/observability/appliance-state` | Appliance trust/degraded/recovery state. |
| GET | `/api/observability/slos` | Live SLO compliance metrics. |
| GET | `/api/forensic/export` | Download forensic bundle through the UI. |
| GET | `/api/audit/status` | Audit-chain status. |
| POST | `/api/audit/verify` | Verify audit-chain integrity. |
| GET | `/api/boot/status` | Boot security summary. |
| GET | `/api/boot/tpm2/status` | TPM2 status. |
| GET | `/api/boot/secureboot/status` | Secure Boot status. |
| GET | `/api/vault/status` | Vault state. |
| POST | `/api/vault/lock` | Lock the vault. |
| POST | `/api/vault/unlock` | Unlock the vault. |
| POST | `/api/vault/keepalive` | Reset vault idle timer. |
| GET | `/api/vm/status` | VM/hypervisor status. |
| POST | `/api/vm/gpu` | GPU status. |
| GET | `/api/emergency/status` | Emergency panic state. |
| POST | `/api/emergency/panic` | Trigger panic action. |
| GET | `/api/update/status` | Update state. |
| POST | `/api/update/check` | Check for updates. |
| POST | `/api/update/stage` | Stage an update. |
| POST | `/api/update/apply` | Apply staged update. |
| POST | `/api/update/rollback` | Roll back to previous deployment. |
| GET | `/api/update/health` | Update subsystem health. |

---

## Search Mediator API (port 8485)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness and enabled state. |
| POST | `/search` | Sanitize, route, and return a Tor-routed web search. |

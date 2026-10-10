# HTTP API Reference

All production services bind to loopback or a Unix socket. The Docker sandbox binds service ports inside the compose network and only publishes the UI to the host by default.

Production control-plane endpoints fail closed when their configured bearer credential is unavailable. Registry and incident-recorder authorities are action-scoped; containment credentials are independent. The Docker sandbox may use a shared compatibility credential only when explicitly started in `SECURE_AI_DEPLOYMENT_MODE=sandbox`.

---

## Registry API (port 8470)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Liveness and model count. |
| GET | `/v1/models` | Read or admin | List registered model artifacts. |
| GET | `/v1/model?name=<name>` | Read or admin | Retrieve one artifact by name. |
| GET | `/v1/model/path?name=<name>` | Read or admin | Return the model file path for a registered artifact. |
| POST | `/v1/model/verify?name=<name>` | Verify or admin | Recompute and compare one model's SHA-256 hash. |
| POST | `/v1/models/verify-all` | Verify or admin | Verify every registered model. |
| GET | `/v1/integrity/status` | Verify or admin | Return aggregate registry integrity state. |
| POST | `/v1/model/verify-manifest?name=<name>` | Verify or admin | Verify the gguf-guard per-tensor manifest for one GGUF model. |
| POST | `/v1/model/promote` | Promote | Promote a quarantined artifact into the registry. |
| DELETE | `/v1/model/delete?name=<name>` | Admin | Remove an artifact from the registry manifest. |
| POST | `/api/v1/quarantine` | Containment | Remove one exact enrolled artifact from service. |

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
| GET | `/api/v1/attest` | Service token | Current full HMAC-authenticated attestation bundle. |
| GET | `/api/v1/verify` | Service token | `verified` hardware evidence and distinct `policy_satisfied` startup decision. |
| GET | `/api/security/status` | Service token | Assurance mode, evidence status, and counters. |
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
| GET | `/api/v1/incidents` | Read | List incidents, filterable by `class`, `state`, and `severity`. |
| GET | `/api/v1/incidents/get?id=<id>` | Read | Fetch one incident. |
| GET | `/api/v1/stats` | Read | Incident statistics. |
| GET | `/api/v1/recovery/status` | Recovery admin | Pending recovery ceremonies. |
| POST | `/api/v1/incidents/report` | Source-bound reporter | Report a new incident. |
| POST | `/api/v1/incidents/resolve` | Operator | Mark an incident resolved. |
| POST | `/api/v1/incidents/acknowledge` | Operator | Acknowledge an incident. |
| POST | `/api/v1/recovery/ack` | Recovery admin | Acknowledge recovery requirements. |
| POST | `/api/v1/recovery/reattest` | Recovery admin | Submit recovery re-attestation. |
| GET | `/api/v1/forensic/export` | Forensic | Export a signed forensic bundle. |
| POST | `/api/v1/reload` | Operator | Reload containment policy. |

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
| GET | `/v1/modes` | List modes with their executable action catalog. |
| GET | `/v1/history/policy` | Read effective history storage, readiness, count and age limits. |
| DELETE | `/v1/history/<id>` | Remove one terminal history record. |
| DELETE | `/v1/history` | Remove terminal history; preserve active tasks. |

The UI exposes session-authenticated proxy routes under `/api/agent/*` with the
same task semantics. Cookie-authenticated mutations require the session CSRF
token, including DELETE. The agent requires its separate UI task-control bearer
credential. Task JSON is returned without HTML entity transformation so proposed
file contents, paths and arguments retain their exact bytes; browser consumers
must render strings as text. Responses prohibit caching.

Live task responses include `plan_revision`, `step_hashes`, `approval_scope`,
`approval_budgets`, and each step's `approval_hash`. Approve and deny require an
explicit list of 1–100 unique 12-character lowercase hexadecimal step IDs, the
64-character lowercase hexadecimal `expected_plan_revision` shown to the user,
and a `step_hashes` map containing exactly those selected IDs and their displayed
64-character hashes. `approve_all` and `deny_all` are rejected. The browser sends
one selected step per decision.

Review identities bind the ordered plan, exact action parameters, descriptions,
risk and policy outcome, task and capability session modes, path/tool/network
scope, lifetime, preferences and both budget limit sources. Runtime progress and
results do not invalidate a review. These public hashes grant no authority:
the backend compares against its current plan while holding the task lock and
retains capability and step-signature validation. The client cannot choose which
operation fields are bound.

Malformed selections return `400`; absent revision/hashes with a valid selection
return `409` (`review_required`), and changed revision or hashes return `409`
(`stale_review`) before any step mutation or scheduling. Refresh and review the
new operation before retrying; do not automatically approve the new revision.
A resolved/historical task also rejects decisions; an expired or invalid
capability returns `403`, a failed step-integrity check returns `409`, and exhausted
execution capacity can return `429`. Approval means permission for the selected
operation, not completion: execution starts once all pending steps have decisions.
Read task/step states to distinguish success, partial failure, denied/skipped work
and cancellation. Cancelling does not undo completed effects.

The browser displays concrete paths, destinations, methods, proposed content,
all material parameters, policy/risk, scope and six budget limits before enabling
approval. Review previews are limited to 32,768 JavaScript string units; oversized
or incomplete operations cannot be approved there. Replacement content is shown
as exact JSON; current target contents are not fetched for a diff. Low-risk
actions may run automatically. Draft/report actions can generate and save new
text whose bytes are unknown at planning time, which the interface states.
Returned text can be downloaded as a local plaintext file; saved paths and
untrusted result URLs are never turned into executable or remote links.

The executable catalog is `local_search`, `summarize`, `draft`, `classify`,
`report`, `explain_security`, `read_file`, `write_file`, `overwrite_file`, plus
`outbound_request` in `online_assisted` mode. Model actions require local inference;
file actions remain scoped by the storage gateway; outbound requests require
the airlock and review of the method, destination and body (body redaction can
occur at the gateway). General `tool_invoke`, exports, bulk deletion, trust/scope
changes and tool/security administration have no production execution contract
and are omitted from the planner prompt and catalog. Recognized requests to
invoke tools, export/share data or bulk-delete return `400` before model planning.
This catalog reports implemented
handlers, not model quality or production qualification.

History persists metadata only in every mode. Live in-memory content has
`content_available:true`; restored records have `history_only:true` and
`content_available:false` and cannot be executed, approved, denied or resumed.
Interrupted work requires a fresh submission after restart. The policy endpoint
reports `persistent`, `history_ready`, `legacy_state_blocked`, `max_tasks`,
`ttl_seconds` and `restart_behavior`. The UI explains memory-only configurations
and disables new submissions/history removal when it cannot establish policy
readiness; direct API work may continue in memory when saved history is blocked.

History DELETE requests accept no body or query. One-record deletion returns
`409` for active work and `404` for an unknown record; a failed durable deletion
returns `503` rather than claiming success. A successful response includes
`deleted`, `active_remaining`, `external_backups_deleted:false` and
`audit_evidence_deleted:false`. These operations remove task records and retained
in-memory details, not output files, audit evidence or external copies. Retention
limits and restart/upgrade boundaries are described in [Agent task history](agent-history.md).

---

## UI API (port 8480)

JSON actions require `Content-Type: application/json` and an object body.
Malformed objects or field types return a bounded JSON error before downstream
requests or state changes; unsupported content types return `415`. JSON imports
have the normal 1 MiB JSON ceiling. The separate multipart model upload route
retains its 50 GiB ceiling; authentication bodies are limited to 4 KiB and
generation bodies to 24 MiB. Oversized requests are rejected, including bodies
without a declared content length.

Chat requests contain 1–512 message objects with a supported role and string
`content`; `model` is a string when supplied and the search toggle is a JSON
boolean. Non-finite numbers, invalid Unicode strings and excessively nested
JSON are rejected. These input limits are independent of the model context
window and do not grant permission to use a model.

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
| POST | `/api/inference/select` | Queue an exact trusted GGUF filename for native appliance inference. |
| POST | `/api/chat` | Send one chat request. |
| POST | `/api/chat/stream` | Streaming chat. |
| POST | `/api/search` | Search mediator request. |
| GET | `/api/search/status` | Search availability/profile state. |
| POST | `/api/chat/search` | Chat with search context. |
| POST | `/api/generate/image` | Generate an image. |
| POST | `/api/generate/video` | Generate video frames/clip. |
| POST | `/api/generate/img2img` | Image-to-image generation. |
| GET | `/api/diffusion/models` | Diffusion model inventory. |

Inference clients use separate UI and agent credentials. An absent or unsafe
inference credential prevents the inference RPC; there is no fallback to the
generic service credential. Inference requests ignore ambient proxies and netrc
authentication and do not follow redirects. The backend advertises one explicit
model alias equal to the selected artifact's registry filename. Chat verifies
that exact filename with the registry and sends the verified alias to the backend;
the UI accepts the registry display name as a selection, but does not normalize
untrusted backend paths into filenames.

On a native appliance, choose a trusted model from `chat_models` and POST
`{"model_filename":"beta.gguf"}` to `/api/inference/select`. The route requires
an authenticated session and the usual CSRF token for cookie authentication.
It accepts only this filename field, verifies unambiguous registry membership,
and publishes an audited request for the privileged native controller; the UI
does not run systemd commands. `202` returns `status: "queued"`, `request_id`,
and `model_filename`. A pending request returns `409`; unavailable native control
returns `501`, and unavailable registry/audit/request publication returns `503`.
Invalid selections return `400`; absent or ambiguous registry entries return `404`.

Poll `/api/inference/status` after queuing. Its `model_selection` reports the
controller's `request_id`, `model_filename`, `status` (`pending`, `succeeded`,
or `failed`) and sanitized `detail` when trusted feedback is available. Match
feedback to the queued request ID. `succeeded` acknowledges the service restart;
chat readiness requires the requested filename's `chat_models[].usable` to be
`true`, which requires both an actual loaded backend alias and registry membership.
The chat page keeps the requested model selected while polling, blocks sending
during the switch, and clears readiness evidence if a status read fails. It polls
for up to two minutes and then directs the user to refresh before retrying.
Sandbox deployments retain `/api/sandbox/control/apply` for inference activation.

Chat failures distinguish service availability from model integrity:

| HTTP status | Meaning |
|---|---|
| `403` | The selected artifact failed the integrity/registry check; `integrity_failed: true`. |
| `409` | The requested model is not loaded; `requires_model_switch: true`. |
| `502` | The backend returned a redirect, invalid protocol response, or rejected the request. |
| `503` | The inference credential is unavailable, backend authentication failed (`401`/`403` upstream), the backend is unreachable, or it reported temporary unavailability (`429`/`503` upstream). |
| `504` | The inference request timed out. |

Service failures include `integrity_failed: false` and a sanitized error without
credential values, credential paths, or upstream response bodies. The status
endpoint remains a status document (`200`), with `available: false` and an error
when the backend inventory cannot be read. Only exact registry filename matches
are marked usable. A failed agent completion returns `ok: false` without charging
successful output; the planner retains its heuristic fallback.

Streaming validates upstream status, content type, and the first event before
sending `200`. Subsequent events use SSE `data:` frames and finish with
`data: [DONE]`. A failure after partial output sends a JSON error data frame with
`integrity_failed: false`, then the terminal marker. Callers must treat that turn
as incomplete and must not append a retried response to it; retry only as an
explicit new generation. Disconnection closes the upstream response. Individual
SSE frames are limited to 64 KiB. Whole-response byte limits, total elapsed
deadlines, and per-client admission limits remain qualification work; the current
request timeout is a connect/read timeout. Protocol tests with synthetic models
do not establish installed-service, accelerator, or production qualification.

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
| GET | `/api/observability/appliance-state` | Fresh credentialed producer report summary; reported_healthy is not independent signature verification. |
| GET | `/api/observability/slos` | Browser-triggered observations; continuous compliance remains unverified. |
| GET | `/api/forensic/export` | Returns local-console instructions; the UI does not hold forensic authority. |
| GET | `/api/audit/status` | Validated, fresh root-owned audit report with keyed/unkeyed/syntax coverage. |
| POST | `/api/audit/verify` | Returns local-console verification instructions; no web-held audit authority. |
| GET | `/api/boot/status` | Boot security summary. |
| GET | `/api/boot/tpm2/status` | Recent TPM enrollment report; not proof of hardware unsealing. |
| GET | `/api/boot/secureboot/status` | Fresh attestor-reported verification or explicit nonpassing state. |
| GET | `/api/vault/status` | Vault state. |
| POST | `/api/vault/lock` | Always returns `501` with local-console lock instructions; the UI has no root service-control authority. |
| POST | `/api/vault/unlock` | Always returns `501`; web passphrases are rejected and unlock requires the local console. |
| POST | `/api/vault/keepalive` | Reset vault idle timer. |
| GET | `/api/vm/status` | VM/hypervisor status. |
| POST | `/api/vm/gpu` | GPU status. |
| GET | `/api/emergency/status` | Emergency panic state. |
| POST | `/api/emergency/panic` | Trigger panic action. |
| GET | `/api/update/status` | Update state. |
| POST | `/api/update/check` | Check for updates. |
| POST | `/api/update/stage` | Stage an update. |
| POST | `/api/update/apply` | Apply staged update. |
| GET | `/api/update/health` | Update subsystem health. |

Rollback is deliberately not exposed through the web API. Run
`sudo /usr/libexec/secure-ai/update-verify.sh rollback` from a local root
console.

---

## Search Mediator API (port 8485)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness and enabled state. |
| POST | `/search` | Sanitize, route, and return a Tor-routed web search. |

The UI evidence response schemas, freshness limits, authentication basis and accessibility behavior are specified in [UI evidence and accessibility](ui-assurance-accessibility.md). `/api/profile` includes `network_assurance` independently of its configured `active` profile. The normalized read-only status endpoints return HTTP 200 with explicit nonpassing evidence for missing, stale or unavailable dependencies; session authentication remains required. No credentials, raw producer exceptions or signing keys are included in these normalized responses.

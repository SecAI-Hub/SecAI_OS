# Policy YAML Schema Reference

Policy files under `/etc/secure-ai/policy/` control SecAI OS runtime behavior. The main appliance policy is `policy.yaml`; the agent has a separate `agent.yaml`.

The machine-readable schema for `policy.yaml` lives at [`../schemas/policy.schema.json`](../schemas/policy.schema.json). The packaged defaults live at [`../files/system/etc/secure-ai/policy/policy.yaml`](../files/system/etc/secure-ai/policy/policy.yaml). The sandbox launcher publishes those defaults and its selected-profile changes into an immutable `deploy/sandbox/runtime/generations/<sha256>/policy/policy.yaml`; the owner-only `runtime/active-generation` pointer selects the complete policy/config/catalog/profile candidate. Separate ready-session/generation markers are published only after recreation and health verification. These runtime artifacts are intentionally git-ignored.

---

## policy.yaml

Top-level structure:

```yaml
version: 1
defaults:
  ...
models:
  ...
quarantine:
  ...
gguf_guard:
  ...
tools:
  ...
search:
  ...
airlock:
  ...
```

### defaults

| Field | Type | Default | Description |
|---|---|---|---|
| `network.runtime_egress` | string | `"deny"` | Default runtime egress policy. Production policy should keep this at `deny`. |
| `logging.store_raw_prompts` | boolean | `false` | Store raw prompts in audit logs. Privacy-sensitive; keep disabled unless explicitly needed. |
| `logging.store_raw_responses` | boolean | `false` | Store raw model responses in audit logs. Privacy-sensitive; keep disabled unless explicitly needed. |

Example:

```yaml
defaults:
  network:
    runtime_egress: "deny"
  logging:
    store_raw_prompts: false
    store_raw_responses: false
```

### models

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed_formats` | list | `["gguf", "safetensors"]` | Model formats accepted by quarantine. |
| `deny_formats` | list | `["pickle", "pt", "bin"]` | Unsafe serialization formats rejected before scanning. |
| `require_scan` | constant | `true` | Must remain true; ModelScan is required before promotion. |
| `require_yara` | constant | `true` | Must remain true; YARA and packaged rules are required. |
| `require_modelaudit` | constant | `true` | Must remain true; ModelAudit must complete successfully. |
| `require_behavior_tests` | constant | `true` | Must remain true; adversarial testing is required for GGUF artifacts. |
| `allow_diffusion_directories` | boolean | `true` | Permit the directory pipeline. A passing directory must still match an image-owned `diffusion-models.lock.yaml` entry, exact Hugging Face commit, and canonical per-file manifest; local/TOFU directories are never promoted. |

The pipeline orchestration stages cannot be disabled. Stage 5 runs ModelScan, YARA, format-specific parsing, ModelAudit, entropy analysis, and gguf-guard where applicable. Fickling is retained only for detecting explicitly denied pickle-capable formats; accepted GGUF and safetensors files are non-pickle formats. Garak remains an optional second-opinion behavioral scanner, but an installed Garak must complete successfully.

Example:

```yaml
models:
  allowed_formats: ["gguf", "safetensors"]
  deny_formats: ["pickle", "pt", "bin"]
  require_scan: true
  require_yara: true
  require_modelaudit: true
  require_behavior_tests: true
  allow_diffusion_directories: true
```

### quarantine

| Field | Type | Default | Description |
|---|---|---|---|
| `smoke_test_max_score` | number | `0.3` | Fail above this flagged fraction. Allowed range is `0.0`–`0.3`; lower values only tighten policy. |
| `smoke_test_max_critical` | integer | `1` | Fail above this critical count. Allowed range is `0`–`1`; lower values only tighten policy. |

Source, format, integrity, provenance-recording, static, behavioral, and diffusion deep-scan stages are mandatory in code. There are deliberately no per-stage disable switches.

Example:

```yaml
quarantine:
  smoke_test_max_score: 0.3
  smoke_test_max_critical: 1
```

### gguf_guard

| Field | Type | Default | Description |
|---|---|---|---|
| `required` | constant | `true` | Must remain true; fail closed when gguf-guard is unavailable. |
| `generate_manifest` | boolean | `true` | Generate a per-tensor SHA-256 manifest inside the trusted registry transaction. |
| `generate_fingerprint` | boolean | `true` | Generate a structural fingerprint inside the trusted registry transaction. |
| `verify_on_integrity_check` | boolean | `true` | Verify gguf-guard manifests during periodic integrity checks. |

### tools

| Field | Type | Default | Description |
|---|---|---|---|
| `default` | string | `"deny"` | Default decision for unlisted tools. |
| `rate_limit.requests_per_minute` | integer | `120` | Global tool evaluation rate. |
| `rate_limit.burst_size` | integer | `20` | Burst allowance. |
| `allow` | list | `[]` | Allowed tool rules with optional path and argument constraints. |
| `deny` | list | `[]` | Explicitly denied tool names. Deny wins over allow. |

Allowed tool rules can include `paths_allowlist`, `paths_denylist`, `args_blocklist`, and `max_arg_length`.

Example:

```yaml
tools:
  default: "deny"
  rate_limit:
    requests_per_minute: 120
    burst_size: 20
  allow:
    - name: "filesystem.read"
      paths_allowlist:
        - "/vault/user_docs/**"
      paths_denylist:
        - "/etc/shadow"
      max_arg_length: 4096
  deny:
    - name: "shell.exec"
```

### search

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable Tor-routed web search. |
| `max_query_length` | integer | `200` | Maximum sanitized query length. |
| `max_results` | integer | `5` | Maximum returned results. |
| `max_context_length` | integer | `4000` | Maximum result context injected into the LLM. |
| `strip_pii` | boolean | `true` | Strip PII from outbound queries. |
| `block_high_pii_queries` | boolean | `true` | Block queries where most content is redacted. |
| `detect_injection` | boolean | `true` | Detect prompt-injection patterns in results. |
| `audit` | boolean | `true` | Write hash-chained search audit events. |
| `allowed_engines` | list | `["duckduckgo", "wikipedia", "stackoverflow", "github"]` | SearXNG engines enabled by policy. |
| `differential_privacy.enabled` | boolean | `true` | Enable query privacy protections. |
| `differential_privacy.decoy_count` | integer | `2` | Number of decoy searches per real search. |
| `differential_privacy.uniqueness_mode` | string | `"warn"` | One of `auto-block`, `warn`, or `allow`. |
| `differential_privacy.batch_window` | number | `5.0` | Query batching window in seconds. |

### airlock

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable controlled egress. Disabled by default because it is the largest privacy risk surface. |
| `allowed_destinations` | list | See packaged policy | URL prefixes allowed for outbound requests. |
| `allowed_methods` | list | `["GET", "POST"]` | HTTP methods allowed for egress decisions. |
| `max_body_size` | integer | `10485760` | Maximum request body size in bytes. |
| `rate_limit.requests_per_minute` | integer | `30` | Maximum egress decision requests per minute. |
| `content_rules.block_if_contains` | list | `[]` | Substrings that block an outbound body. |
| `content_rules.scan_for_pii` | boolean | `true` | Block outbound PII. |
| `content_rules.scan_for_credentials` | boolean | `true` | Block outbound credentials and tokens. |

The Airlock service exposes a decision endpoint. The UI asks the Airlock to approve every catalog download URL and redirect before downloading the file into quarantine.

---

## agent.yaml

`agent.yaml` controls Agent Mode and is separate because the agent has its own policy lifecycle.

### Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | integer | `1` | Agent policy schema version. |
| `default_mode` | string | `"standard"` | Default mode: `offline_only`, `standard`, `online_assisted`, or `sensitive`. |

### budgets

Hard budget limits per mode.

| Field | Description |
|---|---|
| `max_steps` | Maximum plan steps per task. |
| `max_tool_calls` | Maximum tool firewall calls per task. |
| `max_tokens` | Maximum LLM tokens consumed per task. |
| `max_wall_clock_seconds` | Maximum wall-clock runtime. |
| `max_files_touched` | Maximum files read or written. |
| `max_output_bytes` | Maximum task output size. |

### workspace

Registered server-side workspace aliases. Clients submit workspace IDs instead of raw paths.

| Field | Description |
|---|---|
| `readable` | Glob patterns for paths the agent may read. |
| `writable` | Glob patterns for paths the agent may write. |

### allowed_tools

Tool identifiers the agent may invoke through the Tool Firewall. They must also be permitted by the main `policy.yaml` tool section.

### configurable_defaults

Default preferences for medium-risk actions. Values are `always`, `ask`, or `never`.

| Field | Default |
|---|---|
| `read_file` | `ask` |
| `write_file` | `ask` |
| `overwrite_file` | `ask` |
| `tool_invoke` | `ask` |

### always_deny

Hard-denied action names, regardless of mode or user preference. `change_security` is always denied.

### hard_approval

Actions that always require explicit approval, including outbound requests, exports, trust changes, batch deletes, scope widening, and tool enablement.

### worker

| Field | Default | Description |
|---|---|---|
| `sensitive_mode_recycle` | `true` | Recycle worker state after sensitive-mode tasks. |
| `tmpfs_scratch` | `true` | Use tmpfs scratch space. |
| `no_ambient_secrets` | `true` | Keep secrets out of worker environments. |

### logging

| Field | Default | Description |
|---|---|---|
| `log_policy_decisions` | `true` | Log allow/ask/deny decisions. |
| `log_step_actions` | `true` | Log executed actions. |
| `log_raw_prompts` | `false` | Privacy risk; keep disabled unless explicitly required. |
| `log_raw_content` | `false` | Privacy risk; keep disabled unless explicitly required. |
| `log_file_paths` | `false` | Disabled by default to reduce audit-log sensitivity. |

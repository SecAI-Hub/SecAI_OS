# Policy YAML Schema Reference

The policy file at `/etc/secure-ai/policy/policy.yaml` controls the behavior of all SecAI OS services. This document describes every section and field.

---

## Top-Level Structure

```yaml
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

---

## defaults

Global defaults applied when service-specific settings are not provided.

| Field | Type | Default | Description |
|---|---|---|---|
| `log_level` | string | `"info"` | Logging verbosity: debug, info, warn, error |
| `audit_log` | string | `"/var/log/secure-ai/audit.log"` | Path to the audit log file |
| `panic_action` | string | `"lock_vault"` | Action on emergency panic: lock_vault, shutdown, both |

**Example:**

```yaml
defaults:
  log_level: info
  audit_log: /var/log/secure-ai/audit.log
  panic_action: lock_vault
```

---

## models

Settings for model management and the inference worker.

| Field | Type | Default | Description |
|---|---|---|---|
| `storage_path` | string | `"/var/lib/secure-ai/models"` | Directory for promoted model files |
| `quarantine_path` | string | `"/var/lib/secure-ai/quarantine"` | Directory for models awaiting verification |
| `max_model_size_gb` | integer | `50` | Maximum allowed model file size in gigabytes |
| `allowed_formats` | list | `["gguf", "safetensors"]` | Accepted model file formats |
| `auto_promote` | boolean | `true` | Automatically promote models that pass quarantine |

**Example:**

```yaml
models:
  storage_path: /var/lib/secure-ai/models
  quarantine_path: /var/lib/secure-ai/quarantine
  max_model_size_gb: 50
  allowed_formats:
    - gguf
    - safetensors
  auto_promote: true
```

---

## quarantine

Settings for the quarantine pipeline stages.

| Field | Type | Default | Description |
|---|---|---|---|
| `source_allowlist` | list | `["huggingface"]` | Allowed model sources |
| `require_signature` | boolean | `true` | Require cosign signature verification |
| `max_flag_rate` | float | `0.3` | Maximum proportion of flagged checks before rejection (0.0-1.0) |
| `max_critical_flags` | integer | `1` | Maximum number of critical-severity flags before rejection |
| `smoke_test_prompts` | integer | `22` | Number of adversarial prompts in smoke test |
| `smoke_test_categories` | integer | `10` | Number of categories for adversarial prompts |
| `entropy_threshold` | float | `7.5` | Entropy threshold for anomaly detection (bits per byte) |
| `timeout_minutes` | integer | `30` | Maximum time for the full pipeline to complete |

**Example:**

```yaml
quarantine:
  source_allowlist:
    - huggingface
  require_signature: true
  max_flag_rate: 0.3
  max_critical_flags: 1
  smoke_test_prompts: 22
  smoke_test_categories: 10
  entropy_threshold: 7.5
  timeout_minutes: 30
```

---

## gguf_guard

Settings for gguf-guard integration in the quarantine pipeline.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enable gguf-guard scanning for GGUF files |
| `binary_path` | string | `"/usr/local/bin/gguf-guard"` | Path to the gguf-guard binary |
| `generate_manifest` | boolean | `true` | Generate per-tensor hash manifests |
| `generate_fingerprint` | boolean | `true` | Generate structural fingerprints |
| `anomaly_detection` | boolean | `true` | Enable tensor metadata anomaly detection |
| `max_scan_time_minutes` | integer | `15` | Maximum scan time per model |

**Example:**

```yaml
gguf_guard:
  enabled: true
  binary_path: /usr/local/bin/gguf-guard
  generate_manifest: true
  generate_fingerprint: true
  anomaly_detection: true
  max_scan_time_minutes: 15
```

---

## tools

Settings for the Tool Firewall.

| Field | Type | Default | Description |
|---|---|---|---|
| `default_policy` | string | `"deny"` | Default action for unlisted tools: deny or allow |
| `allow` | list | `[]` | List of allowed tool names |
| `deny` | list | `[]` | List of explicitly denied tool names (overrides allow) |
| `path_allowlist` | list | `[]` | Directories that tools may access |
| `args_blocklist` | list | `["../", "/etc/", "/usr/"]` | Patterns blocked in tool arguments |
| `max_arg_length` | integer | `4096` | Maximum length of any single argument (bytes) |
| `rate_limit` | integer | `120` | Maximum requests per minute |
| `rate_burst` | integer | `20` | Burst allowance above rate limit |

**Example:**

```yaml
tools:
  default_policy: deny
  allow:
    - read_file
    - write_file
    - list_directory
  deny:
    - exec_shell
    - delete_file
  path_allowlist:
    - /var/lib/secure-ai/data
    - /tmp/secure-ai
  args_blocklist:
    - "../"
    - "/etc/"
    - "/usr/"
  max_arg_length: 4096
  rate_limit: 120
  rate_burst: 20
```

---

## search

Settings for the Search Mediator.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable the Search Mediator |
| `engines` | list | `["duckduckgo", "wikipedia", "stackoverflow", "github"]` | Allowed search engines |
| `max_results` | integer | `5` | Maximum results returned per query |
| `tor_required` | boolean | `true` | Require Tor routing for all queries |
| `pii_strip` | boolean | `true` | Strip PII from queries before submission |
| `injection_detection` | boolean | `true` | Scan results for prompt injection patterns |
| `decoy_queries` | boolean | `true` | Issue decoy queries for differential privacy |
| `query_padding` | boolean | `true` | Pad queries to uniform length |
| `timing_randomization` | boolean | `true` | Add random delays between queries |
| `k_anonymity` | integer | `5` | K-anonymity level for query generalization |

**Example:**

```yaml
search:
  enabled: false
  engines:
    - duckduckgo
    - wikipedia
    - stackoverflow
    - github
  max_results: 5
  tor_required: true
  pii_strip: true
  injection_detection: true
  decoy_queries: true
  query_padding: true
  timing_randomization: true
  k_anonymity: 5
```

---

## airlock

Settings for the Airlock egress proxy.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enable the Airlock |
| `destination_allowlist` | list | `["huggingface.co", "registry.ollama.ai"]` | Allowed destination hosts |
| `pii_scan` | boolean | `true` | Scan outbound data for PII |
| `credential_scan` | boolean | `true` | Scan outbound data for credentials |
| `rate_limit` | integer | `30` | Maximum requests per minute |
| `max_body_size_mb` | integer | `10` | Maximum request body size in megabytes |
| `https_only` | boolean | `true` | Reject non-HTTPS requests |

**Example:**

```yaml
airlock:
  enabled: false
  destination_allowlist:
    - huggingface.co
    - registry.ollama.ai
  pii_scan: true
  credential_scan: true
  rate_limit: 30
  max_body_size_mb: 10
  https_only: true
```

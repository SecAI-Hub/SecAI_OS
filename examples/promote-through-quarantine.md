# Quarantine Pipeline Walkthrough

This document walks through the full quarantine pipeline from start to finish,
showing what happens at each stage and how to diagnose failures.

---

## Step 1: Place the Model in Incoming

Copy your model file to the quarantine incoming directory:

```bash
cp my-model.gguf /var/lib/secure-ai/quarantine/incoming/
```

The quarantine file watcher (a systemd path unit) detects the new file within
seconds and triggers the pipeline service.

## Step 2: Watch the Pipeline Progress

Follow the pipeline in real time:

```bash
journalctl -u secure-ai-quarantine.service -f
```

You will see log entries for each stage:

```
[quarantine] Processing: my-model.gguf
[quarantine] Stage 1/7: source_policy — checking origin...
[quarantine] Stage 1/7: source_policy — PASS
[quarantine] Stage 2/7: format_gate — validating format...
[quarantine] Stage 2/7: format_gate — PASS (gguf)
[quarantine] Stage 3/7: integrity_check — verifying hash...
[quarantine] Stage 3/7: integrity_check — PASS (sha256=abc123...)
[quarantine] Stage 4/7: provenance_check — verifying signature...
[quarantine] Stage 4/7: provenance_check — PASS
[quarantine] Stage 5/7: static_scan — running modelscan + gguf-guard...
[quarantine] Stage 5/7: static_scan — PASS (score=0.00, no anomalies)
[quarantine] Stage 6/7: behavioral_test — running adversarial prompts...
[quarantine] Stage 6/7: behavioral_test — PASS (0/50 flagged, 0 critical)
[quarantine] Stage 7/7: diffusion_deep_scan — SKIP (not a diffusion model)
[quarantine] All stages passed. Promoting my-model.gguf...
[quarantine] PROMOTED: my-model (my-model.gguf) sha256=abc123...
```

## Step 3: Understand Each Stage

### Stage 1: Source Policy

Checks the model's origin against `sources.allowlist.yaml`:

```yaml
# /etc/secure-ai/policy/sources.allowlist.yaml
models:
  - name: "Hugging Face"
    url_prefix: "https://huggingface.co/"
  - name: "Hugging Face CDN"
    url_prefix: "https://cdn-lfs.huggingface.co/"
```

If the model was downloaded via the catalog, the origin URL is recorded.
For manually placed files without a recorded origin, this stage checks
whether source verification is required in policy.yaml.

**Failure example:**
```
Stage 1/7: source_policy — FAIL: origin "https://sketchy-site.com/model.gguf"
           not in sources.allowlist.yaml
```

### Stage 2: Format Gate

Validates the file header matches the claimed format and rejects unsafe formats:

- Allowed: `gguf`, `safetensors`
- Denied: `pickle`, `pt`, `bin`

GGUF files are checked for a valid magic number. Safetensors files are checked
for valid JSON header structure.

**Failure example:**
```
Stage 2/7: format_gate — FAIL: format "pickle" is denied by policy
```

### Stage 3: Integrity Check

Computes the SHA-256 hash of the file. If a pinned hash exists (from a previous
download or from the catalog), it is compared. First-time downloads record
the hash for future verification.

**Failure example:**
```
Stage 3/7: integrity_check — FAIL: hash mismatch
           expected: abc123...
           actual:   def456...
```

### Stage 4: Provenance Check

Verifies cryptographic signatures if available. Uses cosign for container
signatures or GPG for detached signatures.

**Failure example:**
```
Stage 4/7: provenance_check — FAIL: signature verification failed
```

### Stage 5: Static Scan

Runs multiple scanners in sequence:

1. **modelscan** -- checks for known malicious patterns.
2. **Entropy analysis** -- detects anomalous weight distributions that may
   indicate steganographic payloads.
3. **gguf-guard** (if installed) -- deep per-tensor analysis, anomaly scoring,
   quant-format-aware block analysis.

**Failure example:**
```
Stage 5/7: static_scan — FAIL: modelscan detected suspicious pattern
           in tensor "model.layers.0.attn.weight" (confidence=0.92)
```

### Stage 6: Behavioral Test

Loads the model temporarily and runs an adversarial prompt suite (50 prompts
by default). Checks for:

- Jailbreak susceptibility
- Harmful content generation
- Instruction injection vulnerabilities

Results are scored. The model fails if:
- More than 30% of prompts are flagged (`smoke_test_max_score: 0.3`)
- More than 1 critical flag (`smoke_test_max_critical: 1`)

This stage only runs for LLM models, not diffusion models.

**Failure example:**
```
Stage 6/7: behavioral_test — FAIL: 18/50 prompts flagged (36% > 30% threshold)
           2 critical flags (> 1 max)
```

### Stage 7: Diffusion Deep Scan

For diffusion models only (detected by `model_index.json`). Validates:
- Config file integrity
- Component file checksums
- Scheduler configuration

**Skipped for LLM models:**
```
Stage 7/7: diffusion_deep_scan — SKIP (not a diffusion model)
```

## What Happens on Pass

When all stages pass:

1. The model file is moved from `quarantine/scanning/` to the registry
   directory (`/var/lib/secure-ai/registry/`).
2. If gguf-guard is enabled, a per-tensor SHA-256 manifest is generated
   and stored alongside the model.
3. A structural fingerprint is generated for the model.
4. The registry is updated via `POST /v1/model/promote` with the model's
   metadata, scan results, scanner versions, and integrity data.
5. The model appears in `securectl list` and the Web UI.

## What Happens on Fail

When any stage fails:

1. The model file is moved to `quarantine/rejected/`.
2. A rejection report is written to `quarantine/rejected/my-model.gguf.report.json`
   containing:
   - The stage that failed
   - The failure reason
   - Scan output details
   - Timestamp
3. The model does NOT appear in the registry and cannot be used for inference.
4. A CRITICAL audit log entry is written.

## Checking Rejection Reasons

View the rejection report:

```bash
cat /var/lib/secure-ai/quarantine/rejected/my-model.gguf.report.json | python3 -m json.tool
```

Example output:

```json
{
  "filename": "my-model.gguf",
  "rejected_at": "2026-03-08T14:30:00Z",
  "failed_stage": "static_scan",
  "reason": "modelscan detected suspicious pattern in tensor model.layers.0.attn.weight",
  "scan_details": {
    "modelscan_version": "0.8.1",
    "findings": [
      {
        "tensor": "model.layers.0.attn.weight",
        "type": "suspicious_pattern",
        "confidence": 0.92
      }
    ]
  }
}
```

## Re-Scanning a Rejected Model

If you believe a rejection was a false positive and want to re-scan:

1. Move the model back to incoming:

```bash
mv /var/lib/secure-ai/quarantine/rejected/my-model.gguf \
   /var/lib/secure-ai/quarantine/incoming/
```

2. The pipeline will run again automatically.

## Disabling Individual Stages

If you need to skip a stage (for testing only -- not recommended for
production), edit `policy.yaml`:

```yaml
quarantine:
  stages:
    source_policy: true
    format_gate: true
    integrity_check: true
    provenance_check: false    # <-- disabled
    static_scan: true
    behavioral_test: true
    diffusion_deep_scan: true
```

Then restart the quarantine service:

```bash
sudo systemctl restart secure-ai-quarantine.service
```

# Quarantine Pipeline Walkthrough

This document walks through the full quarantine pipeline from start to finish,
showing what happens at each stage and how to diagnose failures.

---

## Step 1: Place the Model in Incoming

Copy your model file to the quarantine incoming directory:

```bash
cp my-model.gguf /var/lib/secure-ai/quarantine/incoming/
```

The continuously running watcher claims the file into a private processing
directory, creates a stable snapshot, and starts the pipeline. Direct local
single-file imports are recorded as local/TOFU unless the filename and digest
already exist in `models.lock.yaml`. Catalog downloads are preferred because
they carry an immutable source revision and hash pin.

## Step 2: Watch the Pipeline Progress

Follow the pipeline in real time:

```bash
journalctl -u secure-ai-quarantine-watcher.service -f
```

The watcher records the artifact digest and terminal decision without copying
model output or raw scanner output into the journal:

```
quarantine processing: 'my-model.gguf'
quarantine sha256: abc123... size: ... source: local
quarantine PROMOTED: 'my-model.gguf' (registered in manifest)
```

## Step 3: Understand Each Stage

### Stage 1: Source Policy

Checks the model's origin against `sources.allowlist.yaml`:

```yaml
# /etc/secure-ai/policy/sources.allowlist.yaml
models:
  - name: "Hugging Face"
    url_prefix: "https://huggingface.co/"
  - name: "Hugging Face Xet CAS Bridge"
    url_prefix: "https://cas-bridge.xethub.hf.co/"
```

If the model was downloaded via the catalog, the origin URL is recorded.
For manually placed single files without a recorded origin, the stage records
`local-import`; it does not invent remote provenance. Diffusion directories
must have the exact catalog-produced source and manifest sidecars and cannot
use local/TOFU admission.

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

Computes the SHA-256 hash of a file and compares it with
`models.lock.yaml`. Every remote file must already have a matching immutable
pin. A local single-file import may be recorded as first-install trust, but
that record is not remote provenance. Every directory must match the canonical
per-file receipt and exact commit in `diffusion-models.lock.yaml`.

**Failure example:**
```
Stage 3/7: integrity_check — FAIL: hash mismatch
           expected: abc123...
           actual:   def456...
```

### Stage 4: Provenance Check

Records source-appropriate provenance. Cosign is used only for supported
container-registry references. Hugging Face artifacts rely on exact revisions
and image-owned hash/manifest pins; missing signatures are not described as
verified.

**Failure example:**
```
Stage 4/7: provenance_check — FAIL: signature verification failed
```

### Stage 5: Static Scan

Runs multiple scanners in sequence:

1. **modelscan** -- checks for known malicious patterns.
2. **YARA** -- applies repo-owned malware signatures to imported artifacts.
3. **fickling** -- inspects pickle-capable artifacts without executing them.
4. **modelaudit** -- provides a second static scanner for artifact structure and metadata.
5. **Entropy analysis** -- detects anomalous weight distributions that may
   indicate steganographic payloads.
6. **gguf-guard** (if installed) -- deep per-tensor analysis, anomaly scoring,
   quant-format-aware block analysis.

**Failure example:**
```
Stage 5/7: static_scan — FAIL: modelscan detected suspicious pattern
           in tensor "model.layers.0.attn.weight" (confidence=0.92)
```

### Stage 6: Behavioral Test

Loads a GGUF model temporarily, CPU-only and inside the credentialless
no-routable-network scanner boundary, then runs the current 41-prompt
adversarial suite. Checks for:

- Jailbreak susceptibility
- Harmful content generation
- Instruction injection vulnerabilities

Results are scored. The model fails if:
- More than 30% of prompts are flagged (`smoke_test_max_score: 0.3`)
- More than 1 critical flag (`smoke_test_max_critical: 1`)

This stage only runs for LLM models, not diffusion models.

**Failure example:**
```
Stage 6/7: behavioral_test — FAIL: 15/41 prompts flagged (37% > 30% threshold)
           2 critical flags (> 1 max)
```

### Stage 7: Diffusion Deep Scan

For diffusion models only (detected by `model_index.json`). Validates:
- Strict, duplicate-key-free configuration and allowed component imports
- Safetensors tensor shapes, offsets, dtypes, and complete byte layout
- Text tokenizer and SentencePiece structure
- No links, special files, hidden paths, embedded code, or network URLs
- Exact file sizes and Git/LFS object IDs from the immutable manifest
- Exact repository, commit, variant, manifest digest, file count, and total size

**Skipped for LLM models:**
```
Stage 7/7: diffusion_deep_scan — SKIP (not a diffusion model)
```

## What Happens on Pass

When all stages pass:

1. The watcher copies the verified private snapshot into an untrusted
   promotion inbox; it never writes the trusted registry directly.
2. The registry independently copies, bounds, hashes, and validates the
   artifact in a private transaction.
3. For GGUF, the registry generates its own tensor manifest and structural
   fingerprint. For a directory, it cross-checks typed provenance against the
   image-owned diffusion lock.
4. The registry atomically commits the artifact and manifest metadata, or
   rolls both back.
5. The model appears in `securectl list` and the Web UI only after commit.

## What Happens on Fail

When any stage fails:

1. The private snapshot is removed after a terminal rejection.
2. A bounded failure class and stage summary are written to the authenticated,
   hash-chained quarantine audit log. Raw model output is not persisted.
3. The model does not appear in the registry and cannot be used for inference.
4. A failed registry transaction retains the private claim for retry while
   discarding the untrusted promotion copy.

## Checking Rejection Reasons

Inspect authenticated watcher events and the service journal:

```bash
journalctl -u secure-ai-quarantine-watcher.service --since today
sudo /usr/libexec/secure-ai/verify-audit-chains.py
```

## Re-Scanning a Rejected Model

If you believe a rejection was a false positive and want to re-scan:

The watcher intentionally does not retain a rejected artifact as a convenient
execution-ready copy. Correct the pin/policy/source problem, then import the
original artifact again:

```bash
cp -- /trusted/import-source/my-model.gguf \
  /var/lib/secure-ai/quarantine/incoming/
```

The complete pipeline runs again automatically. Do not weaken a required stage
to force a false positive through; update a reviewed image-owned lock or rule
with the normal release process.

## Pipeline Stages Cannot Be Disabled

All seven admission stages are mandatory on the appliance. The behavioral
thresholds may be tightened, but production policy and schema validation reject
attempts to disable required scanners or weaken the compiled maximums.

# Quarantine Pipeline

## Overview

- **Purpose:** 7-stage verify, scan, and promote pipeline
- **Language:** Python
- **Systemd unit:** secure-ai-quarantine.service

Every model entering SecAI OS must pass through the quarantine pipeline before it can be used for inference. The pipeline runs seven sequential stages. A failure at any stage halts the pipeline and rejects the model.

---

## Stages

### Stage 1: Source Policy

Verifies the model's origin against the configured source allowlist. Models from unknown or untrusted sources are rejected immediately.

**Checks:**
- Origin URL or identifier matches an entry in the source allowlist
- Source metadata is present and well-formed

### Stage 2: Format Gate

Validates file headers and rejects unsafe serialization formats.

**Allowed formats:**
- GGUF (.gguf)
- Safetensors (.safetensors)

**Rejected formats:**
- Pickle (.pkl, .pickle)
- PyTorch native (.pt, .pth, .bin)
- Any format that permits arbitrary code execution during deserialization

### Stage 3: Integrity Check

Computes the SHA-256 hash of the model file and compares it against the expected hash (if provided). This pins the exact bytes of the model and detects any modification in transit or at rest.

**Checks:**
- SHA-256 hash matches the pinned value
- File size is within expected bounds

### Stage 4: Provenance

Verifies the cryptographic signature of the model using cosign. This confirms the model was published by the claimed author and has not been tampered with since signing.

**Checks:**
- cosign signature is valid
- Signing identity matches expected publisher
- Signature covers the exact file bytes

### Stage 5: Static Scan

Performs deep static analysis of the model file without loading it for inference.

**Tools:**
- **modelscan** -- scans for known malicious patterns in model files
- **YARA** -- applies repo-owned malware signatures to imported artifacts
- **fickling** -- inspects pickle-capable artifacts without executing them
- **modelaudit** -- provides a second static scanner for model artifact structure and metadata
- **Entropy analysis** -- detects anomalous entropy regions that may indicate embedded payloads
- **gguf-guard** (GGUF files only) -- performs weight-level analysis:
  - Per-tensor hash manifest generation
  - Structural fingerprinting
  - Anomaly detection in tensor metadata
  - Format conformance validation

### Stage 6: Behavioral Smoke Test (LLM Only)

Runs the model against a suite of 22 adversarial prompts across 10 categories to test for unsafe behavior.

**Categories:**
- Instruction following
- Refusal compliance
- Prompt injection resistance
- Jailbreak resistance
- Harmful content generation
- PII leakage
- Bias detection
- Hallucination tendency
- Context boundary respect
- Output format compliance

This stage only applies to language models. Non-LLM artifacts skip to Stage 7.

### Stage 7: Diffusion Deep Scan (Diffusion Only)

Performs additional checks specific to diffusion/image-generation models.

**Checks:**
- Config file integrity (no unexpected keys or values)
- Symlink detection (rejects models containing symlinks)
- Component manifest validation

This stage only applies to diffusion models. LLM artifacts that passed Stage 6 proceed directly to scoring.

---

## Scoring

After all applicable stages complete, the pipeline computes a weighted score.

| Criterion | Behavior |
|---|---|
| Category weighting | Each category contributes proportionally to the overall score |
| Max flag rate | Models with more than 30% of checks flagged are rejected |
| Critical flags | Models with more than 1 critical-severity flag are rejected |

---

## gguf-guard Integration

For GGUF-format models, Stage 5 includes a deep analysis pass using gguf-guard:

- **Per-tensor manifests:** Every tensor in the GGUF file gets an individual hash entry, enabling detection of targeted weight poisoning.
- **Structural fingerprints:** A fingerprint of the model's architecture (layer count, tensor shapes, quantization types) is computed and stored. This allows detecting unauthorized structural modifications after promotion.
- **Anomaly detection:** Tensor metadata is checked for values outside expected ranges.

The gguf-guard fingerprint and manifest are stored in the registry alongside the model's SHA-256 hash.

---

## Outcomes

| Result | Action |
|---|---|
| All stages pass | Model is automatically promoted to the registry via POST /v1/promote |
| Any stage fails | Model remains in quarantine, failure reason is logged to the audit log |
| Scoring threshold exceeded | Model remains in quarantine with a detailed score breakdown |

Quarantined models can be manually reviewed and re-submitted, but they cannot be used for inference until promoted.

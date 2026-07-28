# Quarantine Pipeline

## Overview

- **Purpose:** 7-stage verify, scan, and promote pipeline
- **Language:** Python
- **Systemd unit:** `secure-ai-quarantine-watcher.service`

Every model entering SecAI OS must pass through the quarantine pipeline before it can be used for inference. The pipeline runs seven sequential stages. A failure at any stage halts the pipeline and rejects the model.

The long-lived watcher owns the registry promotion credential but does not run
artifact parsers. It first renames an inbox entry into a private claim and
copies a stable, bounded snapshot, preserving at least 2 GiB of free storage.
It then launches a credentialless coordinator under a second, narrower
Landlock policy and a bubblewrap network/PID namespace. Each admission stage
runs in a fresh, reaped subprocess. Those processes can read the snapshot and
scanner binaries, but cannot read service credentials, reach a routable
network, or write promotion staging, audit logs, or the registry. Artifact and
policy-bundle hashes are checked before and after scanning.

---

## Stages

### Stage 1: Source Policy

Verifies a remote model's canonical HTTPS origin against the configured source
allowlist. Explicit local imports are accepted without claiming remote
provenance; that limitation is recorded with the registry entry.

**Checks:**
- Remote origin hostname, standard HTTPS port, and path match an allowlist entry
- Source sidecar is a bounded, single-link regular UTF-8 file
- URL credentials, fragments, control characters, non-HTTPS schemes, and
  textual host-prefix tricks are rejected

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
- Every directory import matches an immutable, image-owned per-file Hugging
  Face manifest and exact commit; ad-hoc/local directory TOFU is rejected
- Directory-tree hashes use a domain-separated, length-delimited encoding
- The scanner rechecks artifact and policy-bundle digests after parsing

### Stage 4: Provenance

Records the provenance evidence available for the source type. Cosign is used
only for supported signed container-registry references. Hugging Face models
use pinned file hashes or an immutable revision manifest. Local imports have no
cryptographic publisher identity and are labeled accordingly.

**Checks:**
- Cosign verification succeeds when the source type supports it
- Remote model bytes match a pinned hash or immutable per-file manifest
- Missing signatures are never described as signature-verified

### Stage 5: Static Scan

Performs deep static analysis of the model file without loading it for inference.

**Tools:**
- **modelscan** -- scans for known malicious patterns in model files
- **YARA** -- applies repo-owned malware signatures to imported artifacts
- **fickling** -- recognizes explicitly denied pickle-capable formats without executing them
- **modelaudit** -- provides a second static scanner for model artifact structure and metadata
- **Entropy analysis** -- detects anomalous entropy regions that may indicate embedded payloads
- **gguf-guard** (GGUF files only) -- performs weight-level analysis:
  - Anomaly detection in tensor metadata
  - Format conformance validation

### Stage 6: Behavioral Smoke Test (LLM Only)

Runs GGUF language models CPU-only against the current 41-prompt suite across
15 categories. The local llama-server inherits the quarantine service's
systemd IP allow/deny policy: loopback is permitted for scanner queries and
routable egress is denied. Invoking the Python function outside that service
does not create a separate network namespace.

**Categories:**
- Command, file, network, and credential exfiltration
- Prompt injection, jailbreak, encoding bypass, and multi-turn manipulation
- Canary, PII, training-data, and system-context leakage
- Tool abuse, privacy probing, and unsafe hallucinated content

This is a bounded behavioral screen, not proof that a model has no hidden
backdoor. Runtime isolation remains necessary even after a passing result.

### Stage 7: Diffusion Deep Scan (Diffusion Only)

Performs additional checks specific to diffusion/image-generation models.

**Checks:**
- Full safetensors header, dtype, shape, offset, and byte-buffer validation
- Bounded, duplicate-key-free JSON configuration
- Restricted component imports with remote-code/custom-pipeline fields denied
- Network URLs, executable content, links, hard links, and special files denied
- Mandatory immutable Hugging Face per-file manifest validation

This stage only applies to diffusion models. LLM artifacts that passed Stage 6 proceed directly to scoring.

---

## Behavioral Decision

Behavioral results use explicit rejection thresholds rather than a weighted
assurance score.

| Criterion | Behavior |
|---|---|
| Max flag rate | Models with more than 30% of checks flagged are rejected |
| Critical flags | Models with more than 1 critical-severity flag are rejected |

Policy may lower either threshold, but cannot raise it above the compiled
production maximum.

---

## gguf-guard Integration

For GGUF-format models, Stage 5 includes a required deep analysis pass using
gguf-guard:

- **Per-tensor manifests:** Every tensor in the GGUF file gets an individual hash entry, enabling detection of targeted weight poisoning.
- **Structural fingerprints:** A fingerprint of the model's architecture (layer count, tensor shapes, quantization types) is computed and stored. This allows detecting unauthorized structural modifications after promotion.
- **Anomaly detection:** Tensor metadata is checked for values outside expected ranges.

The trusted Go registry independently generates and verifies the GGUF
fingerprint and tensor manifest inside its promotion transaction. For
directory artifacts it also rechecks the typed Hugging Face evidence against
the image-owned `diffusion-models.lock.yaml`, the copied directory hash, source
repository, exact revision, file count, and total size. Client-supplied
sidecar paths or fingerprint values are not trusted. The model, sidecar, and
registry metadata are committed or rolled back together.

---

## Outcomes

| Result | Action |
|---|---|
| All stages pass | Model is automatically promoted to the registry via POST /v1/model/promote |
| Any stage fails | Artifact is removed from incoming quarantine and the failure class is added to the authenticated audit chain |
| Promotion transaction fails | Source remains quarantined for a later retry; the untrusted staging copy is discarded |

Rejected models must be deliberately imported again after the cause is
resolved. They cannot be used for inference until a complete promotion
transaction succeeds.

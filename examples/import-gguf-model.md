# Importing a GGUF Model

There are four ways to work with GGUF models in the Secure AI Appliance.
Regardless of method, every model passes through the full quarantine pipeline
before it can be used for inference.

---

## Method 1: One-Click Catalog Download (Web UI)

The Web UI includes a curated catalog of pre-vetted models from Hugging Face.

1. Open the Web UI at `http://127.0.0.1:8480`.
2. Navigate to the **Models** tab.
3. Browse the catalog. Each entry shows model name, size, VRAM requirement,
   and a brief description.
4. Click **Download** on the model you want.
5. The UI will:
   - Check that the airlock is enabled (required for downloads).
   - Verify the download URL is in the destination allowlist.
   - Download the file through the airlock into `quarantine/incoming/`.
   - Start the quarantine pipeline automatically.
6. Watch the progress indicator on the Models page. The model moves through
   stages: source check, format gate, hash pinning, static scan, and
   behavioral test.
7. Once promoted, the model appears in the **Registry** section and is
   available for chat.

If the airlock is disabled, enable it first:

```
# In policy.yaml
airlock:
  enabled: true
```

Then restart the airlock service:

```bash
sudo systemctl restart secure-ai-airlock.service
```

## Method 2: Manual Import via Web UI

For models not in the catalog (e.g., downloaded on another machine):

1. Copy the `.gguf` file to the appliance (USB drive, scp, etc.).
2. Open the Web UI and go to **Models** > **Import**.
3. Enter the filesystem path to the `.gguf` file or use the file picker.
4. Click **Import**.
5. The UI copies the file to `quarantine/incoming/` and starts the pipeline.
6. Monitor progress on the Models page.

## Method 3: CLI (Direct File Placement)

For headless setups or scripting:

1. Copy the GGUF file into the quarantine incoming directory:

```bash
cp /path/to/model.gguf /var/lib/secure-ai/quarantine/incoming/
```

2. The continuously running quarantine watcher claims the new file and starts
   the pipeline automatically.

3. Monitor progress via journalctl:

```bash
journalctl -u secure-ai-quarantine-watcher.service -f
```

4. Check the result. On success you will see:

```
PROMOTED: model-name (model.gguf) sha256=abc123...
```

On failure you will see the rejection reason:

```
REJECTED: model.gguf — stage=static_scan reason="modelscan flagged suspicious patterns"
```

5. Verify the model is in the registry:

```bash
secai-registryctl list
```

Example output:

```
NAME                FORMAT  SIZE      SHA256        PROMOTED
mistral-7b-q4km     gguf    4.4 GB    a1b2c3d4e5f6  2026-03-08T14:30:00Z
```

6. Verify the model's integrity:

```bash
secai-registryctl verify mistral-7b-q4km
```

Expected output:

```
VERIFIED: mistral-7b-q4km (sha256=a1b2c3d4e5f6...)
```

## Method 4: secai-registryctl CLI

The `secai-registryctl` tool provides direct registry management without
overloading the security-critical `securectl` emergency controller:

```bash
# List all models in the registry
secai-registryctl list

# Show full details for a model
secai-registryctl info mistral-7b-q4km

# Verify a model's hash against the manifest
secai-registryctl verify mistral-7b-q4km

# Get the filesystem path
secai-registryctl path mistral-7b-q4km

# Check registry health
secai-registryctl status
```

Note: `secai-registryctl` talks to the Registry API at `http://127.0.0.1:8470`.
You can override this with the `REGISTRY_URL` environment variable.

---

## What Happens at Each Pipeline Stage

When a file lands in `quarantine/incoming/`, the pipeline executes these
stages in order. If any stage fails, the private snapshot is deleted and a
bounded failure event is added to the authenticated quarantine audit chain.
The rejected artifact is not retained as an execution-ready copy.

| Stage | Name              | What It Does                                           |
|-------|-------------------|--------------------------------------------------------|
| 1     | Source Policy      | Checks the model's origin against `sources.allowlist.yaml` |
| 2     | Format Gate        | Validates file headers; rejects pickle, pt, bin formats |
| 3     | Integrity Check    | Verifies SHA-256 hash against pinned values (if known)  |
| 4     | Provenance Check   | Records source-appropriate signature or immutable revision evidence |
| 5     | Static Scan        | Runs ModelScan + YARA + fickling + modelaudit + entropy analysis + gguf-guard |
| 6     | Behavioral Test    | Adversarial prompt suite (LLM models only)              |
| 7     | Diffusion Deep Scan| Config integrity check (diffusion models only)          |

On success, the pipeline:
1. Copies the verified snapshot to an untrusted promotion inbox.
2. Calls the authenticated registry promotion transaction.
3. The registry independently copies, hashes, and validates the artifact.
4. The registry generates the GGUF tensor manifest and structural fingerprint.
5. Artifact and metadata commit atomically; only then is the model available.

# Importing a GGUF Model

There are three ways to bring a GGUF model into the Secure AI Appliance.
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

2. The quarantine file watcher (systemd path unit) detects the new file
   and starts the pipeline automatically.

3. Monitor progress via journalctl:

```bash
journalctl -u secure-ai-quarantine.service -f
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
securectl list
```

Example output:

```
NAME                FORMAT  SIZE      SHA256        PROMOTED
mistral-7b-q4km     gguf    4.4 GB    a1b2c3d4e5f6  2026-03-08T14:30:00Z
```

6. Verify the model's integrity:

```bash
securectl verify mistral-7b-q4km
```

Expected output:

```
VERIFIED: mistral-7b-q4km (sha256=a1b2c3d4e5f6...)
```

## Method 4: securectl CLI

The `securectl` tool provides direct registry management:

```bash
# List all models in the registry
securectl list

# Show full details for a model
securectl info mistral-7b-q4km

# Verify a model's hash against the manifest
securectl verify mistral-7b-q4km

# Get the filesystem path
securectl path mistral-7b-q4km

# Check registry health
securectl status
```

Note: `securectl` talks to the Registry API at `http://127.0.0.1:8470`.
You can override this with the `REGISTRY_URL` environment variable.

---

## What Happens at Each Pipeline Stage

When a file lands in `quarantine/incoming/`, the pipeline executes these
stages in order. If any stage fails, the model is rejected and moved to
`quarantine/rejected/` with a report.

| Stage | Name              | What It Does                                           |
|-------|-------------------|--------------------------------------------------------|
| 1     | Source Policy      | Checks the model's origin against `sources.allowlist.yaml` |
| 2     | Format Gate        | Validates file headers; rejects pickle, pt, bin formats |
| 3     | Integrity Check    | Verifies SHA-256 hash against pinned values (if known)  |
| 4     | Provenance Check   | Validates cosign/signature from the source              |
| 5     | Static Scan        | Runs modelscan + entropy analysis + gguf-guard           |
| 6     | Behavioral Test    | Adversarial prompt suite (LLM models only)              |
| 7     | Diffusion Deep Scan| Config integrity check (diffusion models only)          |

On success, the pipeline:
1. Copies the file to the registry directory.
2. Generates a gguf-guard per-tensor manifest (if enabled).
3. Generates a structural fingerprint (if enabled).
4. Calls `POST /v1/model/promote` on the Registry to register the artifact.
5. The model is now available for inference.

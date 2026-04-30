# Adding a New Allowlisted Model Source

The Secure AI Appliance only accepts models from allowlisted sources.
To add a new source (e.g., a private Hugging Face organization or an
internal model registry), you need to update two configuration files.

---

## Step 1: Edit sources.allowlist.yaml

The source allowlist is at `/etc/secure-ai/policy/sources.allowlist.yaml`.
Add a new entry under the `models` key:

```yaml
models:
  # Existing sources
  - name: "Hugging Face"
    url_prefix: "https://huggingface.co/"
  - name: "Hugging Face CDN"
    url_prefix: "https://cdn-lfs.huggingface.co/"
  - name: "Hugging Face CDN US"
    url_prefix: "https://cdn-lfs-us-1.huggingface.co/"
  - name: "Hugging Face Xet CAS Bridge"
    url_prefix: "https://cas-bridge.xethub.hf.co/"

  # New source
  - name: "My Organization Models"
    url_prefix: "https://models.myorg.example.com/"
```

Each entry has:
- **name** -- A human-readable label for audit logs and UI display.
- **url_prefix** -- The URL prefix that model download URLs must match.
  This is a strict prefix match, so include the trailing slash.

## Step 2: Add to Airlock Allowed Destinations

The airlock must also allow outbound connections to the new source.
Edit `/etc/secure-ai/policy/policy.yaml` and add the URL to
`airlock.allowed_destinations`:

```yaml
airlock:
  enabled: true  # must be enabled for downloads
  allowed_destinations:
    - "https://huggingface.co/"
    - "https://registry.ollama.ai/"
    - "https://cdn-lfs.huggingface.co/"
    - "https://cdn-lfs-us-1.huggingface.co/"
    - "https://cas-bridge.xethub.hf.co/"
    # New source
    - "https://models.myorg.example.com/"
```

The airlock uses the same prefix-matching logic: the destination URL
must start with one of these prefixes.

## Step 3: Reload or Restart Services

### Hot Reload (no restart required)

The airlock supports hot reload of its policy and sources:

```bash
curl -X POST http://127.0.0.1:8490/v1/reload \
  -H "Authorization: Bearer $(cat /run/secure-ai/service-token)"
```

Expected response:

```json
{
  "status": "reloaded"
}
```

### Full Restart

If hot reload is not sufficient or you want to be certain:

```bash
sudo systemctl restart secure-ai-airlock.service
sudo systemctl restart secure-ai-quarantine.service
```

## Step 4: Verify the New Source

Test that the airlock accepts the new destination:

```bash
curl -X POST http://127.0.0.1:8490/v1/egress/check \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "https://models.myorg.example.com/v1/models/test.gguf",
    "method": "GET",
    "body": ""
  }'
```

Expected response:

```json
{
  "allowed": true,
  "reason": ""
}
```

If the response says `"destination not in allowlist"`, double-check that
the URL prefix matches exactly (including https:// and trailing slash).

---

## For Immutable Image Builds

Since SecAI OS is an immutable image (rpm-ostree / BlueBuild), changes to
files under `/etc/` are stored in the overlay and persist across reboots.
However, they will be reset if the system is re-imaged.

To make the source permanent across image rebuilds, add the files to the
image recipe:

1. Edit `files/system/etc/secure-ai/policy/sources.allowlist.yaml` in the
   repository with your new source.

2. Edit `files/system/etc/secure-ai/policy/policy.yaml` to include the
   new airlock destination.

3. Rebuild the image via BlueBuild. The updated files will be baked into
   the next image.

---

## Security Considerations

- Only add sources you trust. Every allowed source is a potential vector
  for malicious models.
- The quarantine pipeline still scans every model from every source.
  Adding a source to the allowlist means "allow download from here",
  not "trust models from here unconditionally".
- Use HTTPS only. The airlock rejects non-HTTPS destinations.
- Be specific with URL prefixes. Instead of allowing `https://example.com/`,
  use `https://example.com/models/` to limit the allowed paths.
- The airlock also scans outbound request bodies for PII and credentials,
  regardless of the destination.

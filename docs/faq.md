# Frequently Asked Questions

---

## How do I import a model into SecAI OS?

There are two ways to import a model:

1. **Through the UI:** Open `http://localhost:8480`, go to the Models page, and use the Import button to upload a local model file (GGUF or Safetensors format).

2. **Through the Airlock:** If the Airlock is enabled, use the Download feature in the UI to fetch a model from HuggingFace or another allowlisted source. The model will pass through the quarantine pipeline automatically.

All imported models must pass the 7-stage quarantine pipeline before they are available for inference. See [Quarantine Pipeline](components/quarantine.md) for details.

---

## Can I use SecAI OS offline?

Yes. SecAI OS is designed for local-first, offline operation. The Airlock (network egress) and Search Mediator are both disabled by default. Once models are imported and promoted, all inference runs locally with no network access required.

The only operations that require network access are:
- Downloading models from remote sources (via the Airlock)
- Web search (via the Search Mediator)
- OS updates (via rpm-ostree)

---

## What GPUs does SecAI OS support?

- **NVIDIA GPUs:** Supported via CUDA. RTX 3000 series and newer are recommended. The RTX 5080 is the primary target hardware.
- **Apple Silicon (M1-M4):** Supported via Metal through llama.cpp. Available when running natively on macOS or in a compatible VM.
- **AMD GPUs:** Not officially supported. ROCm support may work but is not tested.
- **CPU-only:** Inference works without a GPU but will be significantly slower.

---

## How do I enable web search in SecAI OS?

1. Edit `/etc/secure-ai/policy/policy.yaml` and set `search.enabled: true`.
2. Ensure the Tor service is running: `systemctl start tor`.
3. Ensure SearXNG is running: `systemctl start searxng`.
4. Restart the search mediator: `systemctl restart secure-ai-search-mediator`.

Web search routes all queries through Tor to privacy-respecting search engines. See [Search Mediator](components/search-mediator.md) for privacy details.

---

## How do I lock/unlock the vault?

**Lock the vault:**
- Through the UI: Click the Lock button in the security panel.
- Through the API: `curl -X POST http://localhost:8480/api/vault/lock`
- Emergency: `curl -X POST http://localhost:8480/api/emergency/panic`

**Unlock the vault:**
- Through the UI: Enter your passphrase in the unlock dialog.
- Through the API: `curl -X POST http://localhost:8480/api/vault/unlock -d '{"passphrase":"your-passphrase"}'`

The vault auto-locks after a configurable idle period (default: 15 minutes). Activity in the UI resets the idle timer.

---

## What happens if a model fails quarantine?

The model remains in the quarantine directory (`/var/lib/secure-ai/quarantine/`) and is not promoted to the registry. It cannot be used for inference.

The failure reason is logged to the audit log at `/var/log/secure-ai/audit.log`. You can review the specific stage that failed and the reason.

Options after a quarantine failure:
- **Review and accept the risk:** If you understand the failure and accept the risk, you can adjust the policy thresholds and re-submit the model.
- **Discard the model:** Delete the file from the quarantine directory.
- **Report the issue:** If you believe the model is safe and the quarantine result is a false positive, check the specific scanner output for details.

You cannot bypass quarantine. There is no override to promote a model that has not passed all applicable stages.

---

## How do I recover from an emergency panic?

An emergency panic locks the vault and (optionally) shuts down the system. To recover:

1. Boot the system (if it was shut down).
2. Unlock the vault with your passphrase through the UI or API.
3. Verify system integrity: `curl http://localhost:8480/api/security/status`.
4. Review the audit log for the event that triggered the panic.

The panic action does not destroy data. It locks the vault encryption, making model data inaccessible until the correct passphrase is provided.

---

## Can I run SecAI OS in a virtual machine?

Yes, but with security limitations:

- No hardware TPM2 support (vault passphrase cannot be sealed to TPM).
- The hypervisor host can inspect VM memory.
- GPU passthrough requires IOMMU configuration.

See [VM Installation](install/vm.md) for detailed setup instructions.

For production use with sensitive models, bare metal installation is recommended.

---

## Can I run SecAI OS without replacing my host OS?

Yes. The project now includes a compose-based sandbox path for evaluation on an existing workstation.

Use [Sandbox Deployment](install/sandbox.md) when you want the UI, quarantine pipeline, policy engine, tool firewall, airlock, and agent without rebasing the host.

Important limits:

- The host kernel and container runtime can inspect container memory and mounted files.
- There is no TPM2 sealing, Secure Boot, measured boot, or immutable root.
- It is appropriate for evaluation and workflow testing, not sensitive production workloads.

---

## How do I update SecAI OS?

SecAI OS uses rpm-ostree for atomic updates:

1. **Check for updates:** `curl http://localhost:8480/api/updates/check` or use the UI.
2. **Stage the update:** `curl -X POST http://localhost:8480/api/updates/stage`
3. **Apply and reboot:** `curl -X POST http://localhost:8480/api/updates/apply`

Updates are atomic -- the entire OS image is replaced. If an update causes problems, roll back:

```bash
curl -X POST http://localhost:8480/api/updates/rollback
# or from the command line:
rpm-ostree rollback
systemctl reboot
```

Greenboot health checks run after each boot. If checks fail, the system automatically rolls back to the previous deployment.

---

## What is the tool firewall?

The Tool Firewall is a Go service (port 8475) that mediates all tool invocations from the inference worker. It enforces a default-deny policy: only explicitly allowlisted tools can be invoked.

This prevents a model from executing arbitrary operations on the host. For example, even if a model attempts to call a "delete_file" tool, the request is blocked unless "delete_file" is on the allow list with appropriate path restrictions.

See [Tool Firewall](components/tool-firewall.md) for configuration and API details.

---

## How does the quarantine pipeline work?

Every model passes through 7 sequential stages before it can be used:

1. **Source Policy** -- verify origin against allowlist
2. **Format Gate** -- reject unsafe formats (pickle, .pt, .bin)
3. **Integrity Check** -- SHA-256 hash verification
4. **Provenance** -- cosign signature verification
5. **Static Scan** -- modelscan, entropy analysis, gguf-guard
6. **Behavioral Smoke Test** -- 22 adversarial prompts (LLM only)
7. **Diffusion Deep Scan** -- config integrity, symlink detection (diffusion only)

A failure at any stage halts the pipeline and rejects the model. Models that pass all stages are automatically promoted to the registry.

See [Quarantine Pipeline](components/quarantine.md) for full details on each stage.

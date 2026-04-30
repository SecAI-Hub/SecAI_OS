# Sandbox Deployment

Run SecAI OS as a lower-assurance local sandbox on top of Docker or Podman. This path keeps the project usable on an existing workstation without rebasing the whole machine, while making the trust tradeoffs explicit.

## What This Is

The sandbox stack bundles the local UI, registry, quarantine watcher, tool firewall, policy engine, airlock, search mediator, and agent into a compose-based deployment. It is meant for:

- local evaluation
- demos and onboarding
- policy and workflow testing
- model import and quarantine pipeline validation

It is **not** equivalent to the full OS image.

## Security Limits

Compared with the full OS appliance, the sandbox path loses:

- TPM2 vault sealing
- Secure Boot and measured boot
- immutable `rpm-ostree` root
- systemd sandboxing and unit policy
- appliance-wide nftables egress enforcement
- kernel-level isolation from the host

Treat the host OS, container runtime, and anyone with host admin access as fully trusted. They can inspect container memory, mounted files, logs, and network activity.

## Prerequisites

- Docker Compose v2 or Podman with compose support
- 8+ GB RAM recommended for the control plane alone
- 16+ GB RAM recommended if enabling inference or diffusion profiles

## Start The Stack

**Windows (one-command launcher from the repo root)**

```powershell
.\secai-sandbox.cmd start
.\secai-sandbox.cmd open
```

**Linux / macOS**

```bash
bash scripts/sandbox/start.sh
```

**Windows (PowerShell)**

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/start.ps1
```

The helper script will:

1. Create `deploy/sandbox/.env` from the template if needed.
2. Generate a per-stack service token in `deploy/sandbox/runtime/service-token`.
3. Generate a separate host-control token in `deploy/sandbox/runtime/control-token`.
4. Start a loopback-only host controller used by the UI for profile/service automation.
5. Render a runtime policy/config overlay for the selected profiles.
6. Build, harden, and wait for the sandbox services to become healthy.

Then open:

```text
http://127.0.0.1:8480
```

## Optional Profiles

The default stack starts the control plane only. Inference and diffusion are opt-in because they are heavier and usually need user-supplied model paths or extra runtime dependencies.

When the stack is started through `secai-sandbox.cmd` or `scripts/sandbox/start.*`,
the UI can start these profiles for you from **Settings**, **Chat**, **Models**, or
**Generate**. The UI does not receive the Docker socket; it calls a host-side
controller on `127.0.0.1:${SECAI_CONTROL_PORT:-8498}` with a random bearer token
mounted read-only into the UI container. The controller only accepts allowlisted
profile actions.

**Enable local LLM inference**

1. Edit `deploy/sandbox/.env`.
2. Set `SECAI_INFERENCE_MODEL_PATH` to a promoted GGUF path inside the shared state volume such as `/var/lib/secure-ai/registry/my-model.gguf`.
3. Start with the inference profile:

```bash
bash scripts/sandbox/start.sh --with-inference
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/start.ps1 -WithInference
```

**Enable diffusion**

```bash
bash scripts/sandbox/start.sh --with-diffusion
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/start.ps1 -WithDiffusion
```

**Enable Tor-routed web search**

This starts the Tor and SearXNG sidecars and flips the sandbox runtime policy
to `search.enabled: true`. It also enables the airlock policy automatically so
the sandbox reports a coherent online profile state.

```bash
bash scripts/sandbox/start.sh --with-search
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/start.ps1 -WithSearch
```

**Enable airlock-mediated outbound downloads**

This keeps the same sandbox bundle but renders the runtime policy with
`airlock.enabled: true`, which is useful for catalog download testing.

```bash
bash scripts/sandbox/start.sh --with-airlock
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/start.ps1 -WithAirlock
```

You can combine flags when you want both online features and model services, for
example:

```bash
bash scripts/sandbox/start.sh --with-search --with-airlock --with-inference
```

On Windows, the convenience launcher also supports restart options:

```powershell
.\secai-sandbox.cmd restart --with-search --with-inference
```

## Stop The Stack

**Windows (one-command launcher from the repo root)**

```powershell
.\secai-sandbox.cmd stop
```

**Linux / macOS**

```bash
bash scripts/sandbox/stop.sh
```

**Windows (PowerShell)**

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sandbox/stop.ps1
```

## What Works Well Here

- UI-driven model import
- quarantine and promotion workflow
- policy development and tool-firewall evaluation
- airlock configuration and audit-chain validation
- agent workflow testing against local services
- production-style web serving for the UI and search mediator
- Unix-socket agent IPC between the UI and agent containers

## Current Gaps

- Search and airlock remain disabled by default until you opt into their runtime profiles.
- The sandbox path does not claim sensitive-workload protection against the host.
- Inference and diffusion are optional profiles, not guaranteed by the default control-plane bundle.

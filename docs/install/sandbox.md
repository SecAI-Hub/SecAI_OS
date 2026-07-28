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

- Docker Server 28+ with Docker Compose v2 on Linux, macOS, or Windows; or
  rootful Podman Server 5.3+ with compose support on native Linux
- 8+ GB RAM recommended for the control plane alone
- 16+ GB RAM recommended if enabling inference or diffusion profiles

The launcher rejects older or unreachable engines. `SECAI_CONTAINER_RUNTIME`
defaults to `auto`, which prefers a supported rootful Podman service on native
Linux and otherwise uses Docker. It records the selected engine in
`deploy/sandbox/runtime/container-runtime` with owner-only permissions and
uses that exact engine for later UI applies and teardown. An explicit engine
change fails closed until the current stack is stopped successfully.

Start, stop, and UI-driven profile applies also share the owner-only
`deploy/sandbox/runtime/launcher.lock`. Launchers never reclaim an existing
lock automatically: a PID that appears absent may belong to another process
namespace, and an interrupted launcher may have left a Docker or Podman child
running. If the launcher reports an unverifiable lock, first verify that no
SecAI sandbox launcher, profile apply, `docker compose`, or `podman compose`
operation is still active. Then inspect the lock path without following
symlinks and remove only that lock entry manually before retrying. Do not
remove the surrounding runtime directory, control key, or recorded container
runtime as part of lock recovery.

Rendered policy is published as an immutable, content-addressed generation
under `deploy/sandbox/runtime/generations/<sha256>/`. The digest covers every
canonical relative path and file payload for the policy, configuration, model
catalog, and selected profile. A complete staged directory is renamed into the
generation store before the owner-only `active-generation` pointer is replaced
atomically. A crash before that pointer update leaves the previous generation
selected; a crash after it can select only the complete new generation. This
pointer commits an immutable **candidate**, not a claim that its services are
running. Runtime controller status remains separate under `runtime/state/`
and is never swapped with policy.

Before stopping any service, the launchers remove both
`runtime/generation-status/ready-generation` and `ready-session`; removing the
generation marker first is the fail-closed invalidation commit. They then stop
every Compose profile and query the container engine directly to verify that
no running `secai-sandbox` project container remains. Candidate publication is
not attempted if either check fails. They export the validated candidate ID
and force Compose to recreate enabled services, so every restarted bind mount
resolves to the same generation.

Only after Docker `--wait` or the bounded Podman health loop succeeds (and the
temporary Podman anchor is removed) does the launcher publish readiness. The
controller creates a private random `control-server-session`; the launcher
copies that exact ID to the public, non-secret `ready-session` marker and
atomically installs `ready-generation` last as the readiness commit. The UI
accepts a profile only when stable marker reads match its generation, the
read-only `profile.json` matches the unique size/SHA-256 entry in that
generation's read-only `generation.json`, and a live controller challenge
returns valid HMAC proofs for the same session and profile. Missing, stale, or
mismatched proof is shown as **Unknown** with HTTP 503—never as an offline
privacy claim. Rerun the launcher to recover; do not create or edit readiness
markers manually.

This deliberately introduces profile-apply downtime: the UI/ingress
disconnects and must reconnect after health checks and readiness publication
complete.
Old immutable generations remain on disk for audit/recovery rather than being
modified in place. Direct `docker compose up` or `podman compose up` is
unsupported and fails unless the generation variable is supplied; use the
launchers so quiescing, rendering, credential validation, recreation, and
health checks remain one locked operation. `scripts/sandbox/render_runtime.py`
is likewise an internal launcher helper: direct or concurrent mutating
invocation is unsupported because it bypasses the launcher's lock and
quiescence checks. Its `--read-active` mode is read-only and may be used for
inspection.

Rootless Docker and rootless Podman are not supported by the UI-driven host
controller route. Their default networking does not let this container reach a
host-loopback listener, and the launcher does not weaken those defaults.
Podman machines/remotes on macOS and Windows are also outside this path; use
Docker Desktop there. On native Linux, rootful Docker or Podman binds the
controller only to its verified RFC 1918 bridge gateway, and the launcher maps
the relay hostname to that exact recorded address rather than trusting an
engine heuristic. Docker Desktop binds it to host loopback. Explicit bind
overrides accept IPv4 loopback only.

For Podman, that gateway belongs only to the Compose project network
`secai-sandbox_ingress`; the launcher never binds the controller to the
default `podman` network or a LAN address. A digest-pinned, credentialless
Alpine anchor briefly materializes the project bridge before the controller
starts. The anchor has no mounts, secrets, ports, or capabilities; it uses a
read-only filesystem, private namespaces, and tight process, memory, and CPU
limits. Ownership is recorded in an owner-only runtime file and revalidated
against the exact container image, command, labels, network, and hardening
before removal. It remains only until the credentialless UI ingress is healthy.
If all stack containers were stopped out of band, the stop launcher may
recreate the same verified temporary anchor solely to reach and authenticate
the controller shutdown, then removes it before Compose teardown. An ambiguous
name, label, state file, network, or controller response fails closed.

Fedora SELinux enforcing mode is supported and should remain enabled. Every
repository bind mount is read-only and uses the shared `:z` relabel required
when generated policy, configuration, and credential paths are mounted into
multiple containers.

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
2. Generate scoped service credentials under
   `deploy/sandbox/runtime/credentials/`.
3. Generate a separate host-control request-signing key in
   `deploy/sandbox/runtime/control-token`.
4. Probe any recorded controller before mutating the stack. A signed legacy
   protocol is retired through its authenticated shutdown path before startup
   continues. An unverifiable or bearer-only baseline remains fail-closed: use
   its matching legacy launcher, or manually verify the recorded PID's owner
   and `control_server.py` command line, stop only that process, and confirm
   that port `8498` has no listener before retrying. Never expose the control
   token in a legacy Bearer request.
5. Invalidate the prior ready-generation/session pair, stop all existing
   sandbox services, and verify no project container remains running.
6. Start a host-local controller used by the UI for profile/service automation.
7. On native Podman, materialize and validate the project-scoped ingress
   gateway with the temporary hardened anchor described above.
8. Stage and atomically publish an immutable runtime policy/config/catalog/
   profile generation for the selected profiles.
9. Build a credentialless ingress sidecar that is the only container with a
   host-published port. The UI and sensitive services remain on internal-only
   networks; a dedicated internal link lets the sidecar reach only the UI.
10. Build, harden, and wait for every enabled sandbox service to become
   healthy (or running when it has no health check).
11. Publish the exact controller session and generation readiness markers,
    with `ready-generation` installed last.

Then open:

```text
http://127.0.0.1:8480
```

## Optional Profiles

The default stack starts the control plane only. Inference and diffusion are opt-in because they are heavier and usually need user-supplied model paths or extra runtime dependencies.

When the stack is started through `secai-sandbox.cmd` or `scripts/sandbox/start.*`,
the UI can start these profiles for you from **Settings**, **Chat**, **Models**, or
**Generate**. The UI does not receive the container-engine socket; it calls a
host-side controller on fixed port `8498`. A random request-signing key is
mounted read-only into the UI container.

A fixed TCP relay carries the authenticated control request across the
dedicated UI link. The relay has no credential mounted or persisted and has no
container-engine socket. The reusable key never crosses the relay: each request
contains an HMAC over the protocol, timestamp, one-time nonce, method, path, and
body digest. The controller enforces a 30-second clock window and persists a
bounded nonce cache atomically so replay remains blocked across restarts. It
also verifies an existing controller and protocol with a fresh challenge-bound
HMAC. Profile identity additionally requires a second challenge-bound state
HMAC over the controller session, status, profile state, and profile. This
prevents a container restart or stale on-disk marker from claiming a running
profile without the matching live controller. Teardown is refused until the
authenticated current controller confirms that any active apply process tree
has stopped. Only allowlisted profile actions are accepted.

The same relay publishes UI port 8480 on host loopback only. It has a read-only
scratch image, runs as UID/GID 65534, drops all capabilities, mounts no files or
credentials, and cannot resolve or reach registry, vault, quarantine, or policy
services. Its external bridge exists only because Docker cannot publish a port
from an `internal: true` network. Its health check requires both the UI route
and the current host-controller protocol route to respond successfully. The
relay has a 64 MiB memory limit, a 0.5 CPU limit, and a 64-process limit.
Because the external bridge has egress and browser sessions traverse the relay,
the sandbox remains a lower-assurance evaluation path even though sensitive
service networks are not routable from it.

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

For capable NVIDIA or ROCm hosts, add GPU acceleration:

```bash
bash scripts/sandbox/start.sh --with-diffusion --with-gpu
```

```powershell
.\secai-sandbox.cmd start --with-diffusion --with-gpu
```

`--with-gpu` builds the diffusion worker with a GPU PyTorch backend and adds a
GPU-specific compose override. By default it keeps diffusion pipelines resident
on the GPU and leaves CPU offload disabled (`SECAI_DIFFUSION_CPU_OFFLOAD=0`).
Set `SECAI_DIFFUSION_COMPUTE=rocm` for AMD ROCm, or leave it unset for NVIDIA
CUDA auto-detection. GPU passthrough gives the diffusion container access to the
host GPU device, so keep it disabled for sessions that do not need generation
acceleration.

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

The stop launcher first obtains authenticated confirmation that the controller
and any active profile-apply process tree have stopped. It invalidates both
readiness markers before attempting Compose teardown, so a failed `down` is
still reported as Unknown rather than ready. It then validates the
active-generation candidate pointer for Compose parsing. If that pointer is
missing or corrupt, stop uses a fixed all-zero, non-authoritative interpolation
value only for `compose down`; the start launcher never accepts that fallback
for `compose up`.

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

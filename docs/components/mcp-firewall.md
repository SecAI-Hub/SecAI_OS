# MCP gateway

`secure-ai-mcp-firewall.service` serves the authenticated policy API on
`127.0.0.1:8496`. The binary is `/usr/libexec/secure-ai/mcp-firewall` and the
policy is `/etc/secure-ai/mcp-firewall/default-policy.yaml`.

This service evaluates proposed MCP calls and issues signed decisions. It does
not proxy or execute calls. The current agent has no MCP execution integration.
An eventual executor must enforce the exact request digest, receipt signature,
audience, policy digest, expiry, one-use execution, and filesystem boundary in
its own namespace before it performs an action. `require-approval` is not an
execution permit. Filesystem checks in the gateway cannot prevent a later
symlink or mount change at the executor.

The embedded [API and deployment contract](../../services/mcp-firewall/README.md)
and [OpenAPI schema](../../services/mcp-firewall/schemas/openapi.yaml) describe
the authenticated sessions, strict policy, and version 2 receipts.
[UPSTREAM_SYNC.json](../../services/mcp-firewall/UPSTREAM_SYNC.json) binds the
reviewed helper source and tests by SHA-256. The native build uses this embedded
source; a separately downloaded helper cannot shadow it.

The evaluator credential is `mcp-firewall.token`. Administrative reload and
session revocation require the distinct `mcp-firewall-admin.token`; the admin
cannot evaluate calls. `mcp-firewall-signing.key` is a persistent Ed25519 seed.
The credential service provisions all three as root-only inputs and systemd
delivers private copies to the gateway. No private key appears in logs or
environment values. `/health` reports liveness; authenticated `/ready` checks
audit availability and security-context capacity.

Taint follows the authenticated identity across all server sessions and is
reserved durably before returning allow. Failed or missing completions retain
conservative taint. Reconnection, batching, and restart do not reset it. Separate
trusted credential identities provide separate contexts; a shared service token
shares taint. The live clear endpoint returns 409. Completion can be retried
after restart using the original unexpired receipt and session token; completion
records an outcome and never authorizes another execution.

The mode-0600 journal is `/var/lib/secure-ai/logs/mcp-firewall-audit.jsonl`.
The static `secure-ai-mcp` account preserves ownership across boots, while the
systemd sandbox retains `DynamicUser=yes` protections. The log directory's
sticky bit prevents other service users from replacing its file. A single-writer
lock, file identity checks, bounded indexes, append/fsync checks, and a 256 MiB
cap fail closed. Free-form payloads are omitted. The hash chain requires an
external authenticated anchor to detect hostile rewriting or rollback.

Before upgrading an existing deployment, stop MCP callers and the gateway,
preserve and verify the old journal, and let version 1 receipts expire. Do not
delete history to bypass a startup error. Any incompatible legacy journal needs
an explicit reviewed offline migration before reuse; the new daemon refuses
invalid chains. No live journal or credentials were migrated by this source
update. Full systemd/SELinux and executor qualification remain release gates.

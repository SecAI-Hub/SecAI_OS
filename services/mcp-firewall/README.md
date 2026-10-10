# mcp-firewall

A local-first, default-deny policy gateway for Model Context Protocol operations. It evaluates MCP server, tool, resource, argument, session-taint, and trust metadata before a caller executes an operation.

## Security properties

- Every service endpoint except `/health` requires a file-backed credential identity with an exact `evaluator`, `observer`, or isolated `administrator` role.
- Policies must be version 1, strictly parsed, default-deny, bounded, and free of duplicate or invalid rules.
- Unknown servers, tools, methods, malformed identifiers, missing sessions, and dynamic registrations are denied.
- Server and tool rate limits use token buckets.
- Configured MCP server fingerprints must match the fingerprint asserted by the trusted transport integration.
- Filesystem restrictions canonicalize existing path prefixes and reject traversal, prefix lookalikes, symlink escapes, non-absolute paths, null bytes, and Unicode separator confusables.
- Sessions are unpredictable, server-issued, server-bound, call-bounded, and expiring. Caller-chosen identifiers are not accepted by the HTTP execution flow.
- Taint follows the authenticated identity across connections, is reserved durably before allow, and is recovered after restart. Capacity exhaustion denies further evaluations.
- Audit events resume and validate their SHA-256 chain at startup, are synced after each write, recheck path identity/mode/link count/size at runtime, and apply bounded default redaction at the log boundary.
- Ed25519 decision receipts are short-lived and bind a random nonce, audience, key ID, policy digest, request digest, durable audit decision, and batch position. Completion consumes each nonce once, and unexpired consumed-nonce hashes are recovered from the validated audit chain after restart.
- The daemon binds to loopback by default. Remote binding requires `ALLOW_REMOTE_BIND=true` and should only be used behind an authenticated TLS/mTLS proxy.

The firewall makes policy decisions; it does not execute MCP tools. The integrating agent or gateway must refuse execution for every action other than `allow`, and must route `require-approval` through a separate trusted approval mechanism.

## Build and test

```bash
go build -trimpath -o mcp-firewall .
go test -race ./...
go vet ./...
```

Go 1.25 or newer is required. CI uses Go 1.26.5.

## Local setup

```bash
mkdir -p .local
openssl rand -hex 32 > .local/service-token
openssl rand -hex 32 > .local/admin-token
chmod 600 .local/service-token
chmod 600 .local/admin-token

go run . keygen -out .local/signing
# The command never prints private key material.

MCP_FIREWALL_POLICY=policies/default-policy.yaml \
SERVICE_TOKEN_PATH=.local/service-token \
ADMIN_TOKEN_PATH=.local/admin-token \
SIGNING_KEY_PATH=.local/signing.key \
AUDIT_LOG=.local/audit.jsonl \
go run . serve
```

Create a server-bound session, then evaluate with the returned `session_id` and
`binding_token` (the example uses `jq` only to keep the shell snippet compact):

```bash
session="$(curl -sS http://127.0.0.1:8510/v1/sessions \
  -H "Authorization: Bearer $(cat .local/service-token)" \
  -H "Content-Type: application/json" \
  --data '{"server":"filesystem","max_calls":10,"ttl_seconds":900}')"

curl -sS http://127.0.0.1:8510/v1/evaluate \
  -H "Authorization: Bearer $(cat .local/service-token)" \
  -H "Content-Type: application/json" \
  --data '{
    "server": "filesystem",
    "method": "tools/call",
    "tool": "read_file",
    "arguments": {"path": "/home/user/report.txt"},
    "session_id": "'"$(jq -r .session_id <<<"$session")"'",
    "session_token": "'"$(jq -r .binding_token <<<"$session")"'",
    "request_id": "example-request"
  }'
```

Other commands:

```text
mcp-firewall evaluate -policy FILE   Evaluate one JSON request from stdin
mcp-firewall validate -policy FILE   Strictly validate a policy
mcp-firewall audit -log FILE         Validate the complete on-disk audit chain
mcp-firewall keygen -out PREFIX      Create a new private/public Ed25519 keypair
```

Key generation uses exclusive file creation and refuses to overwrite existing keys.
The standalone `evaluate` command is an offline policy-debugging aid: it has no durable
session state and never issues an executable receipt. Production executors must use the
authenticated session/evaluate/completion HTTP flow.

## HTTP API

| Endpoint | Method | Authentication | Purpose |
|---|---|---:|---|
| `/health` | GET | None | Minimal liveness response |
| `/v1/evaluate`, `/v1/evaluate/batch` | POST | `evaluator` | Evaluate bounded MCP requests |
| `/v1/sessions` | POST | `evaluator` | Issue an unpredictable server-bound session |
| `/v1/sessions/{session}` | DELETE | `administrator` | Revoke a session |
| `/ready` | GET | Any configured credential | Check audit and security-context readiness |
| `/v1/executions/complete` | POST | `evaluator` + session token | Record an execution outcome and consume its receipt |
| `/v1/servers`, `/v1/policy` | GET | `observer` | Return non-secret configuration metadata |
| `/v1/taint/{session}` | GET | `observer` | Inspect the authenticated identity's taint (the session is not an authority) |
| `/v1/taint/{session}` | DELETE | `administrator` | Returns 409; live security contexts cannot be cleared |
| `/v1/audit`, `/v1/audit/verify`, `/v1/metrics` | GET | `observer` | Inspect redacted operational state |
| `/v1/reload` | POST | `administrator` | Atomically swap to a validated policy |

Single requests are limited to 1 MiB. Batch bodies are limited to 4 MiB and 100 entries. Unknown JSON fields and trailing JSON values are rejected.
Batch session bindings and call allowances are validated/reserved atomically before any
element is evaluated, so an invalid later binding cannot partially debit earlier sessions.
Once evaluation starts, those policy-evaluation allowances are not refunded if a later
durable audit write fails; this prevents using failures to bypass call limits.

Each authenticated evaluator identity has one monotonic security context shared by all
its server sessions. An allowed operation durably reserves its output taint before returning
a decision, so concurrent, failed, disconnected, or unreported operations cannot create a
clean window. Reconnecting and restarting retain these labels. Configure distinct trusted
credential identities for conversations that require isolation; a shared evaluator token
deliberately shares taint. Only trusted provisioning can introduce a new context. Existing
unattributed evaluation labels are conservatively recovered into every context.

Version 2 receipts bind the authenticated identity and the binding token's SHA-256 digest.
The executor must check the exact request digest, audience, policy, expiration, signature,
and action before executing. Completion only records an outcome; it does not authorize a
second execution. Completion evidence is retained in a separate bounded 11-minute index,
recovered from the journal, independent of the 1,000-entry display cache. A failed audit
append releases the nonce reservation for retry. Unexpired completion survives restart
with the original token; completed replays remain denied after restart. Version 1 receipts
must be drained before upgrading; they are rejected by the new verifier.

Audit storage retains action, policy digest, principal, static taint labels, and opaque
identifier fingerprints. Argument names/values, free-form details, reasons, and evidence
are omitted; raw payloads and queryable hashes of argument values are not stored. The
journal admits only one writer and stops authorizing at its capacity or on I/O failure.
The unkeyed hash chain still requires an external authenticated anchor to detect a hostile
rewrite or rollback; it is not an immutable store.

Signing credentials accept either a base64 Ed25519 private key or a canonical 64-character
hexadecimal seed. Keep the credential mode 0600 and deliver it through systemd credentials
or a private container mount. No key material is accepted through request bodies.
Executors can reproduce `request_digest` with `ComputeRequestDigest`: it is SHA-256 over
the domain `mcp-firewall/request/v1\0` followed by Go's deterministic JSON encoding of
server, asserted server fingerprint, method, tool, resource, string arguments, session ID,
and request ID. The secret session token is deliberately excluded.

The machine-readable API and policy contracts are in
[`schemas/openapi.yaml`](schemas/openapi.yaml) and
[`schemas/policy.schema.json`](schemas/policy.schema.json).

## Container

```bash
podman build -t mcp-firewall .
mkdir -p .local/logs
chmod 700 .local/logs

podman run --rm --user "$(id -u):$(id -g)" --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=64 \
  -p 127.0.0.1:8510:8510 \
  -v "$PWD/policies/default-policy.yaml:/etc/mcp-firewall/policy.yaml:ro" \
  -v "$PWD/.local/service-token:/run/secure-ai/service-token:ro" \
  -v "$PWD/.local/admin-token:/run/secure-ai/admin-token:ro" \
  -v "$PWD/.local/signing.key:/run/secure-ai/signing.key:ro" \
  -v "$PWD/.local/logs:/var/lib/secure-ai/mcp-firewall" \
  -e SIGNING_KEY_PATH=/run/secure-ai/signing.key \
  mcp-firewall
```

The image is built from digest-pinned Go and Alpine bases, runs as UID/GID 65534, includes a health check, and starts the `serve` command. A hardened systemd unit and seccomp profile are under `deploy/`.
The explicit host UID/GID in the bind-mount example keeps credentials and durable audit
files accessible without broadening permissions. On an SELinux-enforcing Fedora/RHEL host,
add the appropriate private `:Z` labels to bind mounts. Keep the published host address on
`127.0.0.1`; the image's wildcard listener exists only so container port publishing works.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `MCP_FIREWALL_POLICY` | `policies/default-policy.yaml` | Strict policy YAML path |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Bearer credential file |
| `ADMIN_TOKEN_PATH` | `/run/secure-ai/admin-token` | Separate administrative Bearer credential file |
| `CREDENTIALS_CONFIG_PATH` | unset | Optional strict YAML identity/role configuration replacing both compatibility credentials |
| `SIGNING_KEY_PATH` | policy `audit.key_path` | Base64 Ed25519 private-key file |
| `AUDIT_LOG` | policy `audit.log_path` | Durable JSONL audit path |
| `BIND_ADDR` | policy value, then `127.0.0.1:8510` | TCP listener |
| `ALLOW_REMOTE_BIND` | unset | Exact `true` permits non-loopback bind |

Without a credential configuration, the service token has evaluator+observer roles and the
distinct administrative token has administrator only. For per-caller credentials, use
[`deploy/credentials.example.yaml`](deploy/credentials.example.yaml): each entry binds a
stable audited identity to explicit roles and an absolute owner-only token file; the
configuration path itself must also be absolute. Token values
and identities must be unique, and administrator cannot be combined with another role.
Credentials contain 32–4096 non-whitespace bytes; only SHA-256 digests remain in the
credential registry, so comparisons are fixed-length. Symlinks and broad permissions are
rejected. The systemd fallback imports its three secrets with `LoadCredential=` and `%d` paths.
Strict policy loading requires signed receipts, an explicit receipt audience, and a receipt
TTL between 1 and 600 seconds; unsigned production policies are rejected.

For `tools/call`, `arg_rules` is also an argument allowlist: arguments not declared by
the selected tool policy are denied. Marking an argument rule with `redact: true` forces
that value to be redacted in decision metadata even when global pattern redaction is off.

## Production checklist

- Keep the listener on loopback or place it behind TLS/mTLS with strict client authentication.
- Mount policy and credentials read-only and the audit directory read-write.
- Run with a read-only root filesystem, all capabilities dropped, no-new-privileges, PID/memory/CPU limits, and the supplied seccomp or systemd policy.
- Restrict the isolated administrative credential to operators; it cannot evaluate or observe and is required for policy reload and session revocation. Live taint deletion is refused.
- Execute only an `allow` decision for the exact request digest, then call `/v1/executions/complete` once. The gateway already reserves output taint before returning allow; failure or missing completion does not declassify the context.
- Rotate or archive the audit log before its 256 MiB hard cap; startup and every append reject path replacement, links, or non-0600 permissions.
- Monitor denied decisions, audit failures, and rate-limit denials.
- Back up audit logs and public signing keys; protect private signing keys separately.
- Pin and verify release checksums, Sigstore signatures, provenance, and container digests.
- Create releases only from annotated strict-SemVer tags on `main`; the release workflow
  resolves the exact tag target and requires a successful CI run for that commit. Images
  receive both an immutable `sha-<full-commit>` tag and a version tag. Because OCI tags do
  not accept SemVer's `+`, build metadata is represented by `_` (for example,
  `v1.2.3+build.5` becomes `v1.2.3_build.5`); this mapping is collision-free because strict
  SemVer does not permit `_`.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the
[security audit](SECURITY_AUDIT.md) before production deployment.

## License

Apache-2.0

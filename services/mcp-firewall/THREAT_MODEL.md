# Threat model

## Trust boundaries

```text
Untrusted agent/request -> mcp-firewall decision boundary -> MCP transport/server
                                  |
                                  +-> durable audit chain
Privileged operator ------> policy, credentials, signing key, and audit storage
```

The agent, MCP server responses, resource contents, arguments, server identity claims,
and external data are untrusted. The firewall process, its policy and credential files,
and its audit destination are trusted. Operators are privileged. The MCP integration is
a separate enforcement boundary: it must not execute denied or altered requests.

## Primary threats and controls

| Threat | Controls |
|---|---|
| Unknown or dynamically introduced tools | Versioned strict policy, explicit server/tool allowlists, default deny, and dynamic-registration denial |
| Policy-rule bypass | Complete semantic validation, duplicate rejection, terminal deny precedence, canonical decoded resource containment, active trust predicates, and atomic runtime replacement |
| Traversal or symlink escape | Absolute paths, decoded/confusable checks, boundary-aware containment, and deepest-existing-prefix symlink resolution |
| Prompt/argument injection | Type/size/count limits, explicit argument rules, deny rules, taint-flow rules, and defense-in-depth pattern matching |
| Cross-session confused deputy | Unpredictable server-issued bindings, server/token/call/expiry validation, atomic batch authorization, and durable identity-scoped taint |
| Decision replay or decision/use substitution | Short-lived Ed25519 receipts bind nonce, request/policy/audit digests, audience, key ID, and batch position; completion consumes nonce once after durable audit |
| Request or state exhaustion | HTTP and batch limits, bounded nested values, token-bucket limits, bounded durable taint state that fails closed at capacity, and service resource limits |
| Credential or signing-key disclosure | File-backed secrets, symlink/regular-file/mode validation, fixed-length token-digest comparison, scoped audited identities, redacted audit data, and no private-key output |
| Audit deletion, fork, or descriptor detachment | Complete bounded chain validation/resumption, path/descriptor identity, exact mode, single-link and runtime-size checks, synced appends, and fail-closed audit errors |
| Network interception | Loopback default; explicit remote opt-in requires an external TLS/mTLS identity boundary |

## Residual risks

- A caller can ignore a decision unless the firewall is made a mandatory execution gateway.
- The filesystem can change after evaluation; only the executor can eliminate the final
  decision/use race with descriptor-relative access and OS sandboxing.
- The executor can lie about completion or execute a request different from the approved
  request unless it independently enforces the receipt request digest.
- Local scoped identities and roles do not prove a tenant or workload instance. Add short-lived
  workload identity or a trusted identity-aware mTLS proxy for cross-host/multi-user use.
- Rate buckets and execution sessions are local to one process. Identity taint, pending decision evidence, and consumed receipt nonces recover from the validated audit journal. Reconnecting cannot reset taint. Journal rollback still requires an external authenticated anchor to detect.
- Regex-based injection detection cannot establish that content is semantically safe.
- A host administrator who can alter the binary, policy, key, or audit file remains trusted.

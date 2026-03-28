# Telemetry Policy

**SecAI OS does not collect telemetry.** No data leaves the device unless explicitly enabled by the user.

## What This Means

| Category | Behavior |
|----------|----------|
| Usage analytics | Not collected |
| Crash reports | Not sent externally |
| Phone-home / heartbeat | None |
| Update checks | Pulled by the device on a schedule, not pushed from a server |
| DNS | Blocked by default (nftables). DNS leak detection runs locally. |
| Model data | Never transmitted. Inference runs entirely on local hardware. |
| Prompts and responses | Never logged to external services. Local audit logging optional. |

## Network Access Requires Explicit Consent

Network access is controlled by the active [profile](../files/system/etc/secure-ai/config/appliance.yaml):

- **offline_private** (default): All egress blocked. No exceptions.
- **research**: Tor-routed web search only, through the search mediator with PII stripping and differential privacy (decoy queries).
- **full_lab**: Filtered outbound through the airlock proxy. All connections logged to the local audit chain.

Switching profiles requires explicit user confirmation. The UI shows the privacy implications before applying.

## Audit Trail

All network-related events are recorded in the tamper-evident audit chain:

- Profile changes (including who changed it and when)
- Airlock connections (destination, sanitization applied, data size)
- Search queries (stripped of PII, with decoy query counts)
- Service state changes (which services started/stopped)

The audit chain is hash-linked — any tampering is detectable via `verify-release.sh` or the Security Dashboard.

## Verification

To confirm no unexpected outbound connections:

```bash
# Check nftables rules (should show default-deny egress)
sudo nft list ruleset | grep -A5 "chain output"

# Check for active connections
ss -tunap | grep -v '127.0.0.1'

# DNS leak check (runs automatically on a timer)
journalctl -u secure-ai-dns-leak-check --no-pager -n 5
```

## Policy Scope

This policy covers the SecAI OS image and all bundled services. It does not cover:

- Third-party models (their behavior during inference is constrained by sandboxing, but not guaranteed)
- User-installed software (if the immutable OS is modified)
- Network traffic from hypervisors when running in a VM

# Service Level Objectives (SLOs)

Defines availability, latency, and correctness targets for all SecAI OS services. These SLOs apply to a properly configured appliance running on supported hardware (see [support-lifecycle.md](support-lifecycle.md)).

Last updated: 2026-03-14

---

## Scope

These SLOs apply to:
- A single-node SecAI OS appliance
- Running on supported hardware with recommended specs (32 GB RAM, NVMe SSD, supported GPU)
- After successful first-boot validation (`first-boot-check.sh` passes)
- During normal operation (not during upgrades, recovery, or emergency panic)

SLOs are **internal targets**, not contractual guarantees. They guide development priorities and operational alerting thresholds.

---

## Service Availability

| Service | Target | Measurement | Notes |
|---------|--------|-------------|-------|
| Policy Engine | 99.9% | `/health` returns 200 | Single point of policy evaluation |
| Registry | 99.9% | `/health` returns 200 | Model store is read-only after promotion |
| Tool Firewall | 99.9% | `/health` returns 200 | Gateway for all tool invocations |
| Runtime Attestor | 99.9% | `/health` returns 200 | Startup gate; degraded mode on failure |
| Integrity Monitor | 99.9% | `/health` returns 200 | Continuous baseline verification |
| Incident Recorder | 99.9% | `/health` returns 200 | Must survive to record own failures |
| MCP Firewall | 99.5% | `/health` returns 200 | Default-deny if unavailable |
| GPU Integrity Watch | 99.5% | `/health` returns 200 | Monitoring; inference continues if degraded |
| Web UI | 99.5% | HTTP 200 on `:8480` | User-facing; non-critical for security |
| Agent | 99.0% | `/health` returns 200 | Optional; disabled tasks on failure |
| Inference Worker | 99.0% | Process running | Restarts between sessions by design |
| Airlock | N/A | Disabled by default | Only measured when explicitly enabled |

**Measurement window:** Rolling 7-day period, measured every 30 seconds.

---

## Latency Targets

| Operation | P50 | P95 | P99 | Notes |
|-----------|-----|-----|-----|-------|
| Policy decision (`/api/v1/decide`) | < 5ms | < 15ms | < 50ms | In-process evaluation |
| Health check (`/health`) | < 2ms | < 5ms | < 10ms | Simple liveness probe |
| Tool firewall evaluation | < 10ms | < 30ms | < 100ms | Includes policy engine call |
| Registry model lookup | < 5ms | < 15ms | < 50ms | In-memory manifest |
| MCP firewall evaluation | < 10ms | < 30ms | < 100ms | Includes taint check |
| Incident creation | < 20ms | < 50ms | < 200ms | Includes disk persistence |
| Attestation verify | < 50ms | < 150ms | < 500ms | HMAC verification |
| Integrity scan cycle | < 5s | < 10s | < 30s | Full baseline comparison |
| Quarantine pipeline (total) | < 5min | < 15min | < 30min | Depends on model size |
| First-boot validation | < 60s | < 120s | < 180s | All checks combined |

---

## Correctness Targets

| Property | Target | Verification |
|----------|--------|-------------|
| Policy decisions match configured rules | 100% | Adversarial test suite in CI |
| Denied operations produce audit records | 100% | Audit chain integrity tests |
| Incident auto-containment fires within SLA | < 5s from detection | Recovery test suite |
| Integrity baseline matches known-good state | 100% after clean boot | First-boot-check.sh |
| Attestation bundle is current | Refreshed every 5 minutes | Runtime attestor periodic refresh |
| Audit log integrity (hash chain) | No gaps or breaks | Periodic verification + CI tests |
| Zero data loss on graceful shutdown | 100% | SIGTERM drain tests in CI |

---

## Failure Modes and Degradation

| Failure | Impact | Automatic Response | Recovery |
|---------|--------|-------------------|----------|
| Policy engine down | All tool calls denied (fail-closed) | systemd auto-restart (2s) | Restart clears; incident logged |
| Registry down | No model loads; existing inference continues | systemd auto-restart (2s) | Restart clears |
| Attestation failure | Appliance enters degraded state | Incident created; startup gating blocks new services | Re-attestation or reboot |
| Integrity violation | Appliance enters degraded state | Model loads frozen; agent frozen; incident created | Recovery ceremony (ack + re-attest) |
| Incident recorder down | No new incidents captured; containment paused | systemd auto-restart (2s); pending events buffered by callers | Restart; disk persistence recovers state |
| GPU integrity warning | Inference quality suspect | Incident created; score degraded | Reboot or driver reinstall |

---

## Alerting Thresholds

Operators should configure monitoring to alert on:

| Condition | Severity | Threshold |
|-----------|----------|-----------|
| Any service health check failing | Critical | > 30 seconds |
| Attestation state not `verified` | Critical | Immediate |
| Integrity state not `clean` | Critical | Immediate |
| Open incident count > 0 | Warning | Immediate |
| Incident count > 5 | Critical | Immediate |
| Disk usage > 80% on `/var/lib/secure-ai/` | Warning | Checked every 5 minutes |
| Disk usage > 95% on `/var/lib/secure-ai/` | Critical | Checked every 5 minutes |
| Service restart count > 3 in 5 minutes | Warning | Per StartLimitInterval |
| Health endpoint latency > 1s | Warning | Per-check basis |

### Monitoring Commands

```bash
# Quick health check (all services)
sudo /usr/libexec/secure-ai/first-boot-check.sh

# Individual service health
curl -sf http://127.0.0.1:8500/health  # Policy Engine
curl -sf http://127.0.0.1:8505/health  # Runtime Attestor
curl -sf http://127.0.0.1:8510/health  # Integrity Monitor
curl -sf http://127.0.0.1:8515/health  # Incident Recorder

# Security posture summary
curl -s http://127.0.0.1:8515/api/v1/stats | python3 -m json.tool
curl -s http://127.0.0.1:8505/api/v1/verify | python3 -m json.tool
curl -s http://127.0.0.1:8510/api/v1/status | python3 -m json.tool

# Journal logs (security events)
journalctl -u 'secure-ai-*' -g 'FAIL\|DENIED\|degraded\|violation' --since today
```

---

## SLO Review Cadence

- **Monthly:** Review service availability against targets using journal logs
- **Per-release:** Validate latency targets using CI test timing data
- **Quarterly:** Review and adjust thresholds based on operational experience
- **On incident:** Post-mortem reviews whether SLOs need updating

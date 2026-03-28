# Audit Quick-Path — M5 Stronger Isolation Verification

This document provides an external auditor with concrete, copy-pasteable commands to verify every M5 security control. Work through each section in order. If any command fails or returns unexpected output, the corresponding control may not be enforced.

Last updated: 2026-03-14

---

## 1. Run These Tests

### M5 Acceptance Suite (Python)

The M5 acceptance suite is the single named test module that certifies the appliance meets the "Stronger Isolation" bar. It covers attestation, integrity, policy, key management, replay resistance, MCP taint, adversarial regression, supply chain, recovery workflow, workspace isolation, and step signatures.

```bash
# From the repository root:
PYTHONPATH=services python -m pytest tests/test_m5_acceptance.py -v
```

Expected: all 20+ tests pass. Every `TestM5_*` class must show `PASSED`.

### Adversarial Tests (Python)

Red-team coverage for bypass attempts: prompt injection, path traversal, symlink escape, token replay, nonce reuse, workspace spoofing, approval flow circumvention, step signature tampering, and blocked paths.

```bash
PYTHONPATH=services python -m pytest tests/test_adversarial.py -v --tb=short
```

Expected: all tests pass. Pay particular attention to `TestPolicyBypass`, `TestStepSignature`, `TestRevalidation`, and `TestBlockedPaths`.

### Go Service Unit Tests (all 9 services)

```bash
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  echo "=== ${svc} ==="
  (cd services/${svc} && go test -v -race -count=1 ./...)
done
```

Expected: every service reports `PASS`.

### MCP Firewall Adversarial Tests (Go)

```bash
cd services/mcp-firewall && go test -v -race -run TestAdversarial ./...
```

Expected: all `TestAdversarial_*` tests pass (44+ tests covering malformed payloads, taint bypass, server spoofing, hash chain tampering).

### Policy Engine Adversarial Tests (Go)

```bash
cd services/policy-engine && go test -v -race -run TestAdversarial ./...
```

Expected: all `TestAdversarial_*` tests pass.

### Incident Recorder Recovery & Forensic Tests (Go)

```bash
cd services/incident-recorder && go test -v -race -run "TestRecovery|TestEscalation|TestForensic|TestLatched" ./...
```

Expected: all recovery ceremony, escalation, forensic bundle, and latched-state tests pass.

### Enforcement Chain Tests (Go)

```bash
cd services/incident-recorder && go test -v -race -run "TestChain" ./...
```

Expected: all end-to-end enforcement chain tests pass (attestation failure -> containment, integrity violation -> freeze, manifest mismatch -> quarantine, bearer token propagation).

---

## 2. Inspect These Logs

All services log to systemd journal under their respective unit names. On a running appliance, use these commands to inspect security-relevant log entries.

### Incident Recorder (central incident hub)

```bash
# All incident recorder output
journalctl -u secure-ai-incident-recorder --no-pager -n 200

# Filter for containment dispatches
journalctl -u secure-ai-incident-recorder --grep "containment:" --no-pager

# Filter for recovery ceremonies
journalctl -u secure-ai-incident-recorder --grep "recovery:" --no-pager

# Filter for severity escalations
journalctl -u secure-ai-incident-recorder --grep "escalation:" --no-pager

# Filter for alerts
journalctl -u secure-ai-incident-recorder --grep "ALERT:" --no-pager
```

What to look for: incident creation lines with `class=`, `severity=`, `state=`, `actions=`. Containment actions should list `freeze_agent`, `disable_airlock`, `force_vault_relock`, or `quarantine_model` as appropriate for the incident class.

### Runtime Attestor (startup gating)

```bash
journalctl -u secure-ai-runtime-attestor --no-pager -n 100

# Look for attestation results
journalctl -u secure-ai-runtime-attestor --grep "attestation" --no-pager
```

What to look for: attestation state transitions (`trusted`, `failed`, `degraded`). Any `attestation_failure` entry means the system entered containment.

### Integrity Monitor (file integrity)

```bash
journalctl -u secure-ai-integrity-monitor --no-pager -n 100

# Look for baseline scan results
journalctl -u secure-ai-integrity-monitor --grep "baseline\|mismatch\|violation" --no-pager
```

What to look for: baseline scan results with pass/fail per file. Any `integrity_violation` means file hashes have diverged from the approved baseline.

### MCP Firewall (deny-by-default + taint)

```bash
journalctl -u secure-ai-mcp-firewall --no-pager -n 100

# Look for denied requests and taint events
journalctl -u secure-ai-mcp-firewall --grep "deny\|taint\|blocked" --no-pager
```

What to look for: denied tool calls, taint propagation entries, and hash chain verification results.

### Policy Engine (centralised decisions)

```bash
journalctl -u secure-ai-policy-engine --no-pager -n 100
```

What to look for: policy decision entries with `decision=allow|deny|ask`, domain, and evidence.

### Agent (capabilities, sandbox, workspace)

```bash
journalctl -u secure-ai-agent --no-pager -n 100

# Look for token and workspace events
journalctl -u secure-ai-agent --grep "token\|workspace\|keystore\|signature" --no-pager
```

What to look for: keystore provider name at startup, token verification events, workspace boundary violations, step signature checks.

### All Security Services (combined view)

```bash
journalctl -u 'secure-ai-*' --since "1 hour ago" --no-pager
```

---

## 3. Verify These Artifacts

### cosign — Image Signature Verification

Verify the container image was signed by the expected identity:

```bash
# Verify image signature
cosign verify \
  --certificate-identity-regexp=".*SecAI-Hub.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/secai-hub/secai_os:latest

# Verify SLSA provenance attestation
cosign verify-attestation \
  --type slsa \
  --certificate-identity-regexp=".*SecAI-Hub.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/secai-hub/secai_os:latest
```

Expected: verification succeeds with no errors. Output shows the signing certificate chain.

### SBOM Generation (per service)

Verify that Software Bill of Materials can be generated for each service:

```bash
# Install syft if not present
# curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate and inspect SBOMs for Go services
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  echo "=== ${svc} ==="
  syft dir:services/${svc} -o cyclonedx-json=sbom-${svc}.json
  echo "Components: $(jq '.components | length' sbom-${svc}.json)"
done

# Generate SBOMs for Python services
for svc in agent ui quarantine common; do
  if [ -d "services/${svc}" ]; then
    syft dir:services/${svc} -o cyclonedx-json=sbom-${svc}.json
    echo "OK: ${svc} — $(jq '.components | length' sbom-${svc}.json) components"
  fi
done
```

Expected: each service produces a valid CycloneDX JSON SBOM with a non-zero component count.

### Checksum Verification (release artifacts)

For tagged releases, verify the checksum file:

```bash
# Download release checksums and verify
curl -sSfL https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS -o SHA256SUMS
curl -sSfL https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS.sig -o SHA256SUMS.sig

# Verify checksum signature
cosign verify-blob \
  --certificate-identity-regexp=".*SecAI-Hub.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --signature SHA256SUMS.sig \
  SHA256SUMS

# Verify individual file checksums
sha256sum -c SHA256SUMS
```

### Automated Release Verification

For a single-command verification of all supply-chain artifacts, use the `verify-release.sh` script:

```bash
# Download release artifacts
mkdir release && cd release
gh release download v1.0.0 -R SecAI-Hub/SecAI_OS

# Place cosign.pub (or set COSIGN_PUB_KEY)
cp /path/to/cosign.pub .

# Run full verification (colored terminal output)
../files/scripts/verify-release.sh ghcr.io/secai-hub/secai_os:v1.0.0

# Generate a human-readable report file
../files/scripts/verify-release.sh --report verification-report.txt \
  ghcr.io/secai-hub/secai_os:v1.0.0

# Machine-readable JSON output (for CI pipelines or tooling)
../files/scripts/verify-release.sh --json ghcr.io/secai-hub/secai_os:v1.0.0
```

The script checks cosign image signature, CycloneDX SBOM attestation, SLSA3 provenance attestation, and SHA256 checksums. See `files/scripts/verify-release.sh --help` for configuration options.

Or via Make:

```bash
make verify-release IMAGE=ghcr.io/secai-hub/secai_os:v1.0.0
```

### Forensic Bundle Integrity

Export and verify a forensic bundle from a running appliance:

```bash
# Export forensic bundle
curl -s http://localhost:8515/api/v1/forensic/export -o forensic-bundle.json

# Inspect bundle structure
jq 'keys' forensic-bundle.json
# Expected keys: exported_at, incidents, audit_entries, system_state, policy_digest, bundle_hash, signature

# Verify bundle hash is present and non-empty
jq -r '.bundle_hash' forensic-bundle.json

# Verify signature is present (indicates signing key was loaded)
jq -r '.signature' forensic-bundle.json
```

### Workflow Configuration Verification

Verify CI/CD workflows contain the required supply-chain steps:

```bash
# Release workflow must have these keywords
for keyword in "sbom-action" "attest-build-provenance" "cosign" "cyclonedx" "SHA256SUMS"; do
  grep -q "${keyword}" .github/workflows/release.yml && echo "OK: release.yml has ${keyword}" \
    || echo "FAIL: release.yml missing ${keyword}"
done

# Build workflow must have these keywords
for keyword in "sbom-action" "cosign attest" "cyclonedx"; do
  grep -q "${keyword}" .github/workflows/build.yml && echo "OK: build.yml has ${keyword}" \
    || echo "FAIL: build.yml missing ${keyword}"
done
```

---

## 4. Confirm These System States

These commands verify that all security services are running and reporting healthy state on a live appliance.

### Service Health Endpoints

```bash
# Registry (model store)
curl -sf http://localhost:8470/health | jq .
# Expected: {"status":"ok", ...}

# Tool Firewall (deny-by-default)
curl -sf http://localhost:8475/health | jq .
# Expected: {"status":"ok", ...}

# Agent (capability-based)
curl -sf http://localhost:8476/health | jq .
# Expected: {"status":"ok", ...}

# Airlock (egress gateway — disabled by default)
curl -sf http://localhost:8490/health | jq .
# Expected: {"status":"ok","enabled":false, ...}

# GPU Integrity Watch
curl -sf http://localhost:8495/health | jq .
# Expected: {"status":"ok", ...}

# MCP Firewall
curl -sf http://localhost:8496/health | jq .
# Expected: {"status":"ok", ...}

# Policy Engine
curl -sf http://localhost:8500/health | jq .
# Expected: {"status":"ok", ...}

# Runtime Attestor
curl -sf http://localhost:8505/health | jq .
# Expected: {"status":"ok", ...}

# Integrity Monitor
curl -sf http://localhost:8510/health | jq .
# Expected: {"status":"ok", ...}

# Incident Recorder
curl -sf http://localhost:8515/health | jq .
# Expected: {"status":"ok","open_incidents":0,"total_incidents":0}
```

### systemctl Status (all security services)

```bash
for svc in registry tool-firewall agent airlock gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  echo "=== secure-ai-${svc} ==="
  systemctl is-active "secure-ai-${svc}.service"
done
```

Expected: every service reports `active`.

### Attestation State

```bash
# Current attestation status
curl -sf http://localhost:8505/api/v1/state | jq .
# Expected: state="trusted" when healthy

# If state is "failed", the system is in containment
```

### Recovery and Incident Status

```bash
# Check for pending recovery ceremonies
curl -sf http://localhost:8515/api/v1/recovery/status | jq .
# Expected: {"pending_recoveries":[],"count":0} when healthy

# Check for open incidents
curl -sf http://localhost:8515/api/v1/incidents?state=open | jq .
# Expected: empty array [] when healthy

# Check incident statistics
curl -sf http://localhost:8515/api/v1/stats | jq .
# Expected: open_incidents=0 when healthy
```

### MCP Audit Chain Integrity

```bash
# Verify the MCP firewall's hash-chained audit log has not been tampered with
curl -sf http://localhost:8496/v1/audit/verify | jq .
# Expected: {"valid":true, ...}
```

### Integrity Baseline State

```bash
# Current integrity baseline status
curl -sf http://localhost:8510/api/v1/state | jq .
# Expected: state="trusted" with scan results showing all files match baseline
```

---

## Quick Validation Script

Run this all-in-one script to validate the test suite and artifact structure from a development checkout:

```bash
#!/bin/bash
set -e
echo "=== M5 Audit Quick Validation ==="

echo "[1/6] M5 acceptance suite..."
PYTHONPATH=services python -m pytest tests/test_m5_acceptance.py -v --tb=short

echo "[2/6] Adversarial tests..."
PYTHONPATH=services python -m pytest tests/test_adversarial.py -v --tb=short

echo "[3/6] Incident recorder recovery/forensic tests..."
(cd services/incident-recorder && go test -v -race -run "TestRecovery|TestEscalation|TestForensic|TestLatched" ./...)

echo "[4/6] MCP firewall adversarial tests..."
(cd services/mcp-firewall && go test -v -race -run TestAdversarial ./...)

echo "[5/6] All Go service tests..."
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  echo "--- ${svc} ---"
  (cd services/${svc} && go test -race -count=1 ./...)
done

echo "[6/6] Release artifact verification..."
if [ -f SHA256SUMS ]; then
  files/scripts/verify-release.sh --report /tmp/secai-verify-report.txt \
    ghcr.io/secai-hub/secai_os:latest
  echo "Report: /tmp/secai-verify-report.txt"
else
  echo "SKIP: No release artifacts found (download with 'gh release download')"
fi

echo "=== All M5 checks passed ==="
```

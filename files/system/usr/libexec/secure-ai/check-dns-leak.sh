#!/usr/bin/env bash
# Explicit maintenance connectivity diagnostic; never evidence of offline silence.
set -euo pipefail
NETWORK_HELPER="${NETWORK_HELPER:-/usr/libexec/secure-ai/network-profile.py}"
"$NETWORK_HELPER" require-maintenance || {
    echo "[dns-leak-check] explicit current maintenance lease required" >&2
    exit 1
}
# No automatic DNS/Tor probes run outside the short administrator lease.
# A failed lookup is unavailable connectivity, not proof of leak prevention.
DNS_REACHABLE=false
if command -v dig >/dev/null 2>&1; then
    if dig +short +timeout=3 +tries=1 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
        DNS_REACHABLE=true
    fi
fi
"$NETWORK_HELPER" require-maintenance || exit 1
python3 - "$DNS_REACHABLE" <<'JSON'
import json,sys
print(json.dumps({"status":"maintenance_diagnostic", "dns_reachable":sys.argv[1]=="true",
                  "dns_leak_detected":None, "nftables_dns":"maintenance",
                  "detail":"Explicit DNS connectivity probe; no offline or Tor assurance"}))
JSON

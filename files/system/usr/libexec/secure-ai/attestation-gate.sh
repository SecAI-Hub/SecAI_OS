#!/usr/bin/env bash
# Block dependent units until runtime evidence is release-bound and verified.
set -euo pipefail
umask 077

token_path="${1:?credential path is required}"
endpoint="${ATTESTATION_VERIFY_URL:-http://127.0.0.1:8505/api/v1/verify}"
if ! printf '%s\n' "$endpoint" |
    LC_ALL=C grep -Eq '^http://127\.0\.0\.1:[1-9][0-9]{0,4}/api/v1/verify$'; then
    echo "attestation gate: verify URL must be an exact numeric loopback HTTP endpoint" >&2
    exit 1
fi
port=$(printf '%s\n' "$endpoint" | sed -E 's#^http://127\.0\.0\.1:([0-9]+)/.*#\1#')
if [ "$port" -gt 65535 ]; then
    echo "attestation gate: verify URL port is out of range" >&2
    exit 1
fi

if [ ! -s "$token_path" ] || [ -L "$token_path" ]; then
    echo "attestation gate: credential is missing or unsafe" >&2
    exit 1
fi

credential_metadata=$(stat -c '%F:%h:%s' -- "$token_path" 2>/dev/null || true)
case "$credential_metadata" in
    regular\ file:1:64) ;;
    regular\ file:1:65)
        if [ "$(tail -c 1 -- "$token_path" | od -An -tx1 | tr -d ' \n')" != "0a" ]; then
            echo "attestation gate: credential has invalid trailing data" >&2
            exit 1
        fi
        ;;
    *)
        echo "attestation gate: credential type, link count, or size is unsafe" >&2
        exit 1
        ;;
esac
token=$(head -c 64 -- "$token_path")
if ! printf '%s\n' "$token" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$'; then
    echo "attestation gate: credential is not canonical lowercase hexadecimal" >&2
    exit 1
fi

# Feed the secret header over stdin so it is not exposed in curl's argv.
for _attempt in $(seq 1 30); do
    response=$(
        printf 'header = "Authorization: Bearer %s"\n' "$token" |
        curl --config - --fail --silent --show-error \
            --proto '=http' --proto-redir '=http' --noproxy '*' \
            --max-filesize 1048576 --connect-timeout 1 --max-time 2 \
            "$endpoint" 2>/dev/null || true
    )
    if [ "${#response}" -le 1048576 ] &&
        printf '%s\n' "$response" |
        jq -e '
            type == "object" and
            .policy_satisfied == true and
            (.verified | type == "boolean") and
            (.evidence_verified | type == "boolean") and
            (.assurance_mode == "hardware" or .assurance_mode == "evaluation")
        ' >/dev/null 2>&1; then
            exit 0
    fi
    sleep 1
done

echo "attestation gate: runtime evidence did not reach verified state" >&2
exit 1

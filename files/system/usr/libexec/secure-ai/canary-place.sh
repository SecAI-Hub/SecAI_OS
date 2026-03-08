#!/usr/bin/env bash
#
# Secure AI Appliance — Canary / Tripwire Placement (M22)
#
# Places canary files in sensitive directories. Each canary contains a unique
# token + creation timestamp. Tokens are hashed and stored in an integrity
# database so the check script can verify them without knowing the plaintext.
#
# Canary locations:
#   /var/lib/secure-ai/vault/.canary
#   /var/lib/secure-ai/registry/.canary
#   /var/lib/secure-ai/keys/.canary
#   /etc/secure-ai/.canary
#
set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
CANARY_DB="${SECURE_AI_ROOT}/canary-db.json"
CANARY_LOCATIONS=(
    "${SECURE_AI_ROOT}/vault/.canary"
    "${SECURE_AI_ROOT}/registry/.canary"
    "${SECURE_AI_ROOT}/keys/.canary"
    "/etc/secure-ai/.canary"
)

log() {
    echo "[canary-place] $*"
    logger -t canary-place "$*" 2>/dev/null || true
}

generate_token() {
    # Generate a 64-char hex token
    head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n'
}

hash_token() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

place_canary() {
    local path="$1"
    local dir
    dir=$(dirname "$path")

    # Create directory if needed
    mkdir -p "$dir" 2>/dev/null || true

    # Generate unique token
    local token
    token=$(generate_token)
    local token_hash
    token_hash=$(hash_token "$token")
    local timestamp
    timestamp=$(date -Iseconds)

    # Write canary file
    cat > "$path" <<EOF
# Secure AI Appliance — Canary File
# DO NOT MODIFY OR DELETE THIS FILE
# Any changes will trigger a security alert.
token: ${token}
created: ${timestamp}
EOF

    # Lock down permissions
    chmod 444 "$path"
    # Store file metadata for verification
    local perms owner
    perms=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || echo "444")
    owner=$(stat -c '%U:%G' "$path" 2>/dev/null || stat -f '%Su:%Sg' "$path" 2>/dev/null || echo "root:root")

    echo "${path}|${token_hash}|${timestamp}|${perms}|${owner}"
}

# --- Main ---
log "=== Placing Canary Files ==="

# Build integrity database
entries=()
for loc in "${CANARY_LOCATIONS[@]}"; do
    entry=$(place_canary "$loc")
    entries+=("$entry")
    log "Placed canary: $loc"
done

# Write integrity database as JSON
cat > "$CANARY_DB" <<'HEADER'
{
  "version": 1,
  "description": "Canary file integrity database — do not modify",
  "canaries": [
HEADER

last_idx=$(( ${#entries[@]} - 1 ))
for i in "${!entries[@]}"; do
    IFS='|' read -r path hash ts perms owner <<< "${entries[$i]}"
    comma=","
    if [ "$i" -eq "$last_idx" ]; then
        comma=""
    fi
    cat >> "$CANARY_DB" <<EOF
    {
      "path": "${path}",
      "token_hash": "${hash}",
      "created": "${ts}",
      "permissions": "${perms}",
      "owner": "${owner}"
    }${comma}
EOF
done

cat >> "$CANARY_DB" <<'FOOTER'
  ]
}
FOOTER

chmod 400 "$CANARY_DB"
log "Integrity database written: ${CANARY_DB}"
log "=== Canary Placement Complete ==="

#!/usr/bin/env bash
#
# Secure AI Appliance — TPM2 Vault Key Sealing
#
# Seals the LUKS vault key to TPM2 PCR values so the vault auto-unlocks
# only when the boot chain is intact. If PCR values change (e.g., firmware
# update, tampered bootloader), the TPM refuses to unseal and the user
# must enter the passphrase manually.
#
# PCR binding:
#   PCR 0  — Platform firmware (BIOS/UEFI)
#   PCR 2  — Option ROM code
#   PCR 4  — Boot manager / bootloader
#   PCR 7  — Secure Boot state (policies + certificates)
#
# Usage:
#   tpm2-seal-vault.sh seal    — seal current LUKS key to TPM2 PCRs
#   tpm2-seal-vault.sh unseal  — attempt TPM2-based vault unlock
#   tpm2-seal-vault.sh reseal  — re-seal after legitimate update
#   tpm2-seal-vault.sh status  — check TPM2 availability and seal state
#
set -euo pipefail

MAPPER_NAME="secure-ai-vault"
MOUNT_POINT="/var/lib/secure-ai"
TPM2_DIR="/var/lib/secure-ai/keys/tpm2"
SEALED_KEY="${TPM2_DIR}/vault-key.sealed"
PCR_POLICY="${TPM2_DIR}/pcr-policy.dat"
TPM2_CTX="${TPM2_DIR}/primary.ctx"
PCR_LIST="sha256:0,2,4,7"
STATE_FILE="/run/secure-ai/tpm2-state"
AUDIT_LOG="/var/lib/secure-ai/logs/tpm2-audit.jsonl"

log() {
    echo "[tpm2-seal-vault] $*"
    logger -t tpm2-seal-vault "$*"
}

audit() {
    local event="$1"; shift
    local entry
    entry="{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"${event}\""
    for kv in "$@"; do
        local key="${kv%%=*}"
        local val="${kv#*=}"
        entry="${entry},\"${key}\":\"${val}\""
    done
    entry="${entry}}"
    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
    echo "$entry" >> "$AUDIT_LOG" 2>/dev/null || true
}

write_state() {
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
    echo "{\"tpm2_available\":$1,\"sealed\":$2,\"detail\":\"$3\"}" > "$STATE_FILE"
}

check_tpm2() {
    # Check if TPM2 device exists
    if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
        return 1
    fi
    # Check if tpm2-tools are installed
    if ! command -v tpm2_pcrread &>/dev/null; then
        return 1
    fi
    # Check if we can read PCRs
    if ! tpm2_pcrread "sha256:0" &>/dev/null; then
        return 1
    fi
    return 0
}

check_vtpm() {
    # Detect virtual TPM (swtpm, Hyper-V vTPM)
    if [ -e /sys/class/tpm/tpm0/device/description ]; then
        local desc
        desc=$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || echo "")
        case "$desc" in
            *MSFT*|*swtpm*|*virtual*|*SW*) echo "vtpm"; return 0 ;;
        esac
    fi
    # Check if in VM with TPM
    if [ -f /var/lib/secure-ai/vm.env ]; then
        # shellcheck source=/dev/null
        source /var/lib/secure-ai/vm.env 2>/dev/null || true
        if [ "${IS_VM:-false}" = "true" ] && [ -e /dev/tpmrm0 ]; then
            echo "vtpm"
            return 0
        fi
    fi
    echo "physical"
    return 0
}

read_current_pcrs() {
    tpm2_pcrread "$PCR_LIST" -o /tmp/secai-pcr-current.bin 2>/dev/null
}

cmd_seal() {
    log "Sealing vault key to TPM2 PCRs..."

    if ! check_tpm2; then
        log "ERROR: TPM2 not available"
        write_state "false" "false" "tpm2_not_available"
        exit 1
    fi

    mkdir -p "$TPM2_DIR"
    chmod 700 "$TPM2_DIR"

    # Read current LUKS keyslot passphrase from stdin
    log "Reading vault passphrase from stdin..."
    local passphrase
    read -rs passphrase

    # Create a random key file
    local keyfile
    keyfile=$(mktemp)
    dd if=/dev/urandom bs=64 count=1 of="$keyfile" 2>/dev/null

    # Add the random key to LUKS (in addition to the passphrase)
    echo "$passphrase" | cryptsetup luksAddKey \
        "$(cryptsetup status "$MAPPER_NAME" 2>/dev/null | grep 'device:' | awk '{print $2}')" \
        "$keyfile" || {
        log "ERROR: failed to add key to LUKS"
        rm -f "$keyfile"
        exit 1
    }

    # Create TPM2 primary key
    tpm2_createprimary -C o -g sha256 -G rsa -c "$TPM2_CTX" 2>/dev/null

    # Create PCR policy
    tpm2_startauthsession -S /tmp/secai-session.ctx 2>/dev/null
    tpm2_policypcr -S /tmp/secai-session.ctx -l "$PCR_LIST" -L "$PCR_POLICY" 2>/dev/null
    tpm2_flushcontext /tmp/secai-session.ctx 2>/dev/null

    # Seal the key file to the PCR policy
    tpm2_create -C "$TPM2_CTX" \
        -g sha256 -G keyedhash \
        -u "${SEALED_KEY}.pub" \
        -r "${SEALED_KEY}.priv" \
        -L "$PCR_POLICY" \
        -i "$keyfile" 2>/dev/null

    # Load the sealed object
    tpm2_load -C "$TPM2_CTX" \
        -u "${SEALED_KEY}.pub" \
        -r "${SEALED_KEY}.priv" \
        -c "$SEALED_KEY" 2>/dev/null

    # Persist the sealed key in TPM NV memory
    tpm2_evictcontrol -C o -c "$SEALED_KEY" 0x81000001 2>/dev/null || {
        log "WARNING: could not persist sealed key (handle may be in use)"
    }

    # Securely delete the plaintext key
    shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"
    rm -f /tmp/secai-session.ctx /tmp/secai-pcr-current.bin

    # Save PCR digest for comparison during reseal
    tpm2_pcrread "$PCR_LIST" -o "${TPM2_DIR}/pcr-baseline.bin" 2>/dev/null

    chmod 600 "$TPM2_DIR"/*

    local tpm_type
    tpm_type=$(check_vtpm)
    audit "tpm2_seal" "pcrs=${PCR_LIST}" "tpm_type=${tpm_type}"
    write_state "true" "true" "sealed_to_pcrs"
    log "Vault key sealed to TPM2 PCRs: ${PCR_LIST}"
    log "TPM type: ${tpm_type}"
}

cmd_unseal() {
    log "Attempting TPM2-based vault unlock..."

    if ! check_tpm2; then
        log "TPM2 not available — falling back to passphrase"
        write_state "false" "false" "tpm2_not_available"
        return 1
    fi

    if [ ! -f "$SEALED_KEY" ] && [ ! -f "${SEALED_KEY}.pub" ]; then
        log "No sealed key found — falling back to passphrase"
        write_state "true" "false" "no_sealed_key"
        return 1
    fi

    # Try to unseal using current PCR values
    local keyfile
    keyfile=$(mktemp)

    # Create auth session with PCR policy
    tpm2_startauthsession --policy-session -S /tmp/secai-unseal.ctx 2>/dev/null
    tpm2_policypcr -S /tmp/secai-unseal.ctx -l "$PCR_LIST" 2>/dev/null

    if tpm2_unseal -c 0x81000001 \
        -p "session:/tmp/secai-unseal.ctx" \
        -o "$keyfile" 2>/dev/null; then

        log "TPM2 unseal successful — boot chain intact"

        # Use the unsealed key to open LUKS
        local partition
        partition=$(grep "^${MAPPER_NAME}" /etc/crypttab 2>/dev/null | awk '{print $2}' || echo "")
        if [ -z "$partition" ]; then
            log "ERROR: cannot find vault partition in crypttab"
            shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"
            return 1
        fi

        # Resolve UUID
        if [[ "$partition" == UUID=* ]]; then
            partition="/dev/disk/by-uuid/${partition#UUID=}"
        fi

        cryptsetup open --key-file="$keyfile" "$partition" "$MAPPER_NAME" && {
            mount "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT" 2>/dev/null || true
            shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"
            rm -f /tmp/secai-unseal.ctx
            audit "tpm2_unseal" "result=success"
            write_state "true" "true" "unlocked_via_tpm2"
            log "Vault unlocked via TPM2"
            return 0
        }

        log "ERROR: LUKS open failed with TPM2 key"
        shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"
    else
        log "TPM2 unseal FAILED — PCR mismatch detected!"
        log "Boot chain may have been modified. Manual passphrase required."
        audit "tpm2_unseal_failed" "reason=pcr_mismatch"
        write_state "true" "true" "pcr_mismatch"
    fi

    rm -f /tmp/secai-unseal.ctx "$keyfile" 2>/dev/null
    return 1
}

cmd_reseal() {
    log "Re-sealing vault key to current PCR values..."
    log "This is used after a legitimate system update."

    if ! check_tpm2; then
        log "ERROR: TPM2 not available"
        exit 1
    fi

    # First, verify the user can unlock the vault (proves they have the passphrase)
    log "Enter vault passphrase to authorize reseal:"
    local passphrase
    read -rs passphrase

    # Verify passphrase against LUKS
    local partition
    partition=$(grep "^${MAPPER_NAME}" /etc/crypttab 2>/dev/null | awk '{print $2}' || echo "")
    if [ -z "$partition" ]; then
        log "ERROR: cannot find vault partition"
        exit 1
    fi
    if [[ "$partition" == UUID=* ]]; then
        partition="/dev/disk/by-uuid/${partition#UUID=}"
    fi

    echo "$passphrase" | cryptsetup open --test-passphrase "$partition" 2>/dev/null || {
        log "ERROR: incorrect passphrase"
        exit 1
    }

    # Remove old sealed key from TPM
    tpm2_evictcontrol -C o -c 0x81000001 2>/dev/null || true

    # Re-seal with current PCRs
    echo "$passphrase" | cmd_seal

    audit "tpm2_reseal" "pcrs=${PCR_LIST}"
    log "Re-seal complete. Vault key bound to current boot state."
}

cmd_status() {
    echo "=== TPM2 Status ==="

    if ! check_tpm2; then
        echo "TPM2: NOT AVAILABLE"
        local tpm_type
        tpm_type=$(check_vtpm)
        echo "TPM type: ${tpm_type}"
        if [ -f /var/lib/secure-ai/vm.env ]; then
            # shellcheck source=/dev/null
            source /var/lib/secure-ai/vm.env 2>/dev/null || true
            if [ "${IS_VM:-false}" = "true" ]; then
                echo "NOTE: Running in VM (${HYPERVISOR:-unknown})"
                echo "  - VMs without vTPM use passphrase-only vault unlock"
                echo "  - For measured boot, configure vTPM in hypervisor"
            fi
        fi
        write_state "false" "false" "not_available"
        return
    fi

    echo "TPM2: AVAILABLE"
    local tpm_type
    tpm_type=$(check_vtpm)
    echo "TPM type: ${tpm_type}"

    if [ -f "$SEALED_KEY" ] || [ -f "${SEALED_KEY}.pub" ]; then
        echo "Sealed key: PRESENT"
        echo "PCR binding: ${PCR_LIST}"
        if [ -f "${TPM2_DIR}/pcr-baseline.bin" ]; then
            echo "PCR baseline: SAVED"
        fi
        write_state "true" "true" "sealed"
    else
        echo "Sealed key: NOT FOUND"
        echo "Vault uses passphrase-only mode"
        write_state "true" "false" "no_sealed_key"
    fi

    echo ""
    echo "Current PCR values:"
    tpm2_pcrread "$PCR_LIST" 2>/dev/null || echo "  (could not read PCRs)"

    echo "=== End TPM2 Status ==="
}

# --- Main ---
case "${1:-status}" in
    seal)   cmd_seal ;;
    unseal) cmd_unseal ;;
    reseal) cmd_reseal ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {seal|unseal|reseal|status}"
        exit 1
        ;;
esac

#!/usr/bin/env bash
#
# Secure AI Appliance — Machine Owner Key (MOK) Generation
#
# Generates a MOK key pair for UEFI Secure Boot signing during image build.
# The private key signs the bootloader and kernel; the public key (DER cert)
# is enrolled in the MOK database on first boot via mokutil.
#
# Usage: generate-mok.sh [output-dir]
#
# Output:
#   <output-dir>/secureai-mok.key   — private key (PEM, keep secret)
#   <output-dir>/secureai-mok.pem   — public certificate (PEM)
#   <output-dir>/secureai-mok.der   — public certificate (DER, for MOK enrollment)
#
set -euo pipefail

OUTPUT_DIR="${1:-/etc/secure-ai/keys}"
MOK_KEY="${OUTPUT_DIR}/secureai-mok.key"
MOK_PEM="${OUTPUT_DIR}/secureai-mok.pem"
MOK_DER="${OUTPUT_DIR}/secureai-mok.der"

CERT_SUBJECT="/CN=SecAI OS Secure Boot Signing Key/O=SecAI"
CERT_DAYS=3650  # 10 years

echo "=== Generating Machine Owner Key (MOK) ==="

mkdir -p "$OUTPUT_DIR"

if [ -f "$MOK_KEY" ] && [ -f "$MOK_DER" ]; then
    echo "MOK already exists at ${OUTPUT_DIR}, skipping generation."
    echo "Delete existing keys to regenerate."
    exit 0
fi

# Generate RSA 4096 key + self-signed certificate
openssl req -new -x509 \
    -newkey rsa:4096 \
    -keyout "$MOK_KEY" \
    -out "$MOK_PEM" \
    -nodes \
    -days "$CERT_DAYS" \
    -subj "$CERT_SUBJECT" \
    -addext "extendedKeyUsage=codeSigning" \
    -sha256

# Convert PEM to DER (required by mokutil)
openssl x509 -in "$MOK_PEM" -outform DER -out "$MOK_DER"

# Restrictive permissions
chmod 600 "$MOK_KEY"
chmod 644 "$MOK_PEM" "$MOK_DER"

echo "MOK generated:"
echo "  Private key: ${MOK_KEY}"
echo "  Certificate: ${MOK_PEM}"
echo "  DER cert:    ${MOK_DER}"
echo ""
echo "To sign a kernel/bootloader:"
echo "  sbsign --key ${MOK_KEY} --cert ${MOK_PEM} --output signed.efi unsigned.efi"
echo ""
echo "To enroll on first boot:"
echo "  mokutil --import ${MOK_DER}"
echo "=== MOK Generation Complete ==="

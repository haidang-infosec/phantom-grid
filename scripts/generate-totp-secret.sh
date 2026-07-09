#!/bin/bash
# Generate TOTP secret for Dynamic SPA
# Usage: ./scripts/generate-totp-secret.sh [output_file]

OUTPUT_FILE="${1:-keys/totp_secret.txt}"

# Create keys directory if it doesn't exist
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Generate 32-byte random secret (base64 encoded)
if command -v openssl &> /dev/null; then
    openssl rand -base64 32 > "$OUTPUT_FILE"
elif command -v python3 &> /dev/null; then
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > "$OUTPUT_FILE"
else
    # Fallback: use /dev/urandom
    head -c 32 /dev/urandom | base64 > "$OUTPUT_FILE"
fi

# Set permissions
chmod 600 "$OUTPUT_FILE"

echo "TOTP secret generated: $OUTPUT_FILE"
echo "Secret length: $(wc -c < "$OUTPUT_FILE") bytes"
echo ""
echo "IMPORTANT:"
echo "1. Copy this secret to all clients"
echo "2. Keep it secure (chmod 600)"
echo "3. Server and clients must use the SAME secret"


#!/bin/sh
# Generate self-signed ML-DSA-65 certificates for C4 (ML-KEM-768 + ML-DSA-65).
# These are for laboratory use only — NOT for production.
# See rules.md §9 — no secrets retained past the debugging session.

set -e

CERT_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERT_DIR"

# Generate ML-DSA-65 server key and self-signed certificate
openssl req -x509 -newkey mldsa65 -keyout "$CERT_DIR/server_mldsa65.key" \
    -out "$CERT_DIR/server_mldsa65.crt" -days 365 -nodes \
    -subj "/CN=tls-server" 2>/dev/null

echo "ML-DSA-65 certificates generated in $CERT_DIR"
echo "  - server_mldsa65.crt (server certificate)"
echo "  - server_mldsa65.key (server private key)"
echo ""
echo "WARNING: These are self-signed lab certificates. Do not use in production."

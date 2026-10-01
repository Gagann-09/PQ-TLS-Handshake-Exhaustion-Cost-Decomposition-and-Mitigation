#!/bin/sh
# Generate self-signed certificates for the TLS server.
# These are for laboratory use only — NOT for production.
# See rules.md §9 — no secrets retained past the debugging session.

set -e

CERT_DIR="$(dirname "$0)/../certs"
mkdir -p "$CERT_DIR"

# Generate CA key and certificate
openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" -days 365 -nodes \
    -subj "/CN=PQ-TLS-Lab-CA" 2>/dev/null

# Generate server key and CSR
openssl req -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -nodes \
    -subj "/CN=tls-server" 2>/dev/null

# Sign server cert with CA
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 2>/dev/null

# Clean up CSR
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

echo "Certificates generated in $CERT_DIR"
echo "  - ca.crt (CA certificate)"
echo "  - server.crt (server certificate)"
echo "  - server.key (server private key)"
echo ""
echo "WARNING: These are self-signed lab certificates. Do not use in production."

#!/bin/bash
# Setup script — initialize the laboratory environment.
# See architecture.md §8 for the repository layout.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== PQ-TLS Handshake Lab Setup ==="

# Check for required tools
for cmd in openssl python3 docker; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: Required command '$cmd' not found."
        exit 1
    fi
done

# Generate certificates
echo "Generating certificates..."
sh "$PROJECT_ROOT/lab/server/generate_certs.sh"

# Create results directories
mkdir -p "$PROJECT_ROOT/results/raw"
mkdir -p "$PROJECT_ROOT/results/processed"
mkdir -p "$PROJECT_ROOT/results/figures"

echo ""
echo "Setup complete. Certificates are in lab/certs/"
echo "Run 'scripts/lab.sh up' to start the lab."

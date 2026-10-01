#!/bin/bash
# Collect results from the laboratory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Collecting Results ==="

RAW_DIR="$PROJECT_ROOT/results/raw"
PROCESSED_DIR="$PROJECT_ROOT/results/processed"

mkdir -p "$PROCESSED_DIR"

# Count result files
COUNT=$(find "$RAW_DIR" -name "*.json" -type f | wc -l)
echo "Found $COUNT raw result file(s) in $RAW_DIR"

# In later phases, this will aggregate results into processed data.
# For Phase 1, we just verify the directory structure exists.

echo "Results collection complete."

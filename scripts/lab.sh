#!/bin/bash
# Lab control script — start/stop the Docker laboratory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

case "${1:-}" in
    up)
        echo "Starting lab..."
        docker compose -f "$PROJECT_ROOT/lab/network/docker-compose.yml" up -d
        echo "Lab started. TLS server available at tls-server:4433"
        ;;
    down)
        echo "Stopping lab..."
        docker compose -f "$PROJECT_ROOT/lab/network/docker-compose.yml" down
        echo "Lab stopped."
        ;;
    status)
        docker compose -f "$PROJECT_ROOT/lab/network/docker-compose.yml" ps
        ;;
    *)
        echo "Usage: $0 {up|down|status}"
        exit 1
        ;;
esac

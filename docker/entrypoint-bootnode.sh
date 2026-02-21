#!/bin/bash
set -euo pipefail

# Platform Bootnode Entrypoint
# BOOTNODE_SECRET_KEY is mapped to VALIDATOR_SECRET_KEY so the binary reads it
# from env via clap. Never pass secret keys as CLI arguments.

echo "=== Platform Bootnode ==="
echo "P2P Port: ${P2P_PORT:-8090}"
echo ""

if [ -z "${BOOTNODE_SECRET_KEY:-}" ]; then
    echo "ERROR: BOOTNODE_SECRET_KEY is required (stable PeerId depends on it)"
    exit 1
fi

export VALIDATOR_SECRET_KEY="${BOOTNODE_SECRET_KEY}"

ARGS="--data-dir ${DATA_DIR:-/data}"
ARGS="$ARGS --listen-addr /ip4/0.0.0.0/tcp/${P2P_PORT:-8090}"
ARGS="$ARGS --netuid ${NETUID:-100}"
ARGS="$ARGS --bootnode"

if [ -n "${BOOTSTRAP_PEERS:-}" ]; then
    IFS=',' read -ra PEERS <<< "${BOOTSTRAP_PEERS}"
    for peer in "${PEERS[@]}"; do
        ARGS="$ARGS --bootstrap ${peer}"
    done
fi

echo "Starting bootnode..."
exec validator-node ${ARGS}

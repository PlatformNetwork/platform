#!/bin/bash
# =============================================================================
# Platform Test Validator Entrypoint
# =============================================================================
# Handles environment variables and starts the validator node
# =============================================================================

set -e

# Build command arguments
ARGS="--data-dir ${DATA_DIR:-/data}"
ARGS="$ARGS --listen-addr ${P2P_LISTEN_ADDR:-/ip4/0.0.0.0/tcp/9000}"

if [ -n "$VALIDATOR_SECRET_KEY" ]; then
    ARGS="$ARGS --secret-key $VALIDATOR_SECRET_KEY"
fi

if [ -n "$NETUID" ]; then
    ARGS="$ARGS --netuid $NETUID"
fi

if [ -n "$BOOTSTRAP_PEERS" ]; then
    # Split by comma and add each peer
    IFS=',' read -ra PEERS <<< "$BOOTSTRAP_PEERS"
    for peer in "${PEERS[@]}"; do
        ARGS="$ARGS --bootstrap $peer"
    done
fi

if [ "$NO_BITTENSOR" = "true" ]; then
    ARGS="$ARGS --no-bittensor"
fi

echo "Starting validator-node with args: $ARGS"
exec validator-node $ARGS

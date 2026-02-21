#!/bin/bash
set -e

# Platform Validator Entrypoint
# VALIDATOR_SECRET_KEY is read directly from env by the binary (clap env binding).
# Never pass secret keys as CLI arguments -- they would be visible in /proc/PID/cmdline.

echo "=== Platform Validator ==="
echo "Version: ${VERSION:-unknown}"
echo "P2P Port: ${P2P_PORT:-8090}"
echo "RPC Port: ${RPC_PORT:-8080}"
echo ""

if [ -z "$VALIDATOR_SECRET_KEY" ]; then
    echo "ERROR: VALIDATOR_SECRET_KEY environment variable is required"
    exit 1
fi

ARGS=""

if [ -n "$P2P_PORT" ]; then
    ARGS="$ARGS --p2p-port $P2P_PORT"
fi

if [ -n "$RPC_PORT" ]; then
    ARGS="$ARGS --rpc-port $RPC_PORT"
fi

if [ -n "$SUBTENSOR_ENDPOINT" ]; then
    ARGS="$ARGS --subtensor-endpoint $SUBTENSOR_ENDPOINT"
fi

if [ -n "$BOOTSTRAP_PEERS" ]; then
    for peer in $BOOTSTRAP_PEERS; do
        ARGS="$ARGS --bootstrap-peer $peer"
    done
fi

if [ -n "$DATA_DIR" ]; then
    ARGS="$ARGS --data-dir $DATA_DIR"
fi

exec /app/validator-node $ARGS "$@"

#!/bin/bash
set -e

# Platform Validator Entrypoint
# VALIDATOR_SECRET_KEY is read directly from env by the binary (clap env binding).
# Never pass secret keys as CLI arguments -- they would be visible in /proc/PID/cmdline.

CRASH_FILE="/data/.last_crash"
CRASH_COOLDOWN=30

# Check for restart loop prevention
if [ -f "$CRASH_FILE" ]; then
    last_crash=$(cat "$CRASH_FILE")
    now=$(date +%s)
    elapsed=$((now - last_crash))
    
    if [ $elapsed -lt $CRASH_COOLDOWN ]; then
        wait_time=$((CRASH_COOLDOWN - elapsed))
        echo "=== Crash detected $elapsed seconds ago ==="
        echo "Waiting ${wait_time}s before restart to prevent restart loop..."
        sleep $wait_time
    fi
fi

echo "=== Platform Validator ==="
echo "Version: ${VERSION:-unknown}"
echo "P2P Port: ${P2P_PORT:-8090}"
echo "RPC Port: ${RPC_PORT:-8080}"
echo ""

if [ -z "$VALIDATOR_SECRET_KEY" ]; then
    echo "ERROR: VALIDATOR_SECRET_KEY environment variable is required"
    exit 1
fi

# Build arguments array (secret key is read from env by clap)
ARGS=()

if [ -n "$DATA_DIR" ]; then
    ARGS+=("--data-dir" "$DATA_DIR")
fi

if [ -n "$P2P_PORT" ]; then
    ARGS+=("--p2p-port" "$P2P_PORT")
fi

if [ -n "$RPC_PORT" ]; then
    ARGS+=("--rpc-port" "$RPC_PORT")
fi

if [ -n "$SUBTENSOR_ENDPOINT" ]; then
    ARGS+=("--subtensor-endpoint" "$SUBTENSOR_ENDPOINT")
fi

if [ -n "$NETUID" ]; then
    ARGS+=("--netuid" "$NETUID")
fi

if [ -n "$P2P_LISTEN_ADDR" ]; then
    ARGS+=("--listen-addr" "$P2P_LISTEN_ADDR")
fi

if [ -n "$BOOTSTRAP_PEERS" ]; then
    IFS=',' read -ra PEERS <<< "$BOOTSTRAP_PEERS"
    for peer in "${PEERS[@]}"; do
        ARGS+=("--bootstrap" "$peer")
    done
fi

# Cleanup crash file on successful start
cleanup() {
    rm -f "$CRASH_FILE"
}

# Record crash time on failure
record_crash() {
    date +%s > "$CRASH_FILE"
    echo "=== Validator crashed at $(date) ==="
}

trap cleanup EXIT
trap record_crash ERR

# Execute validator
exec /app/validator-node "${ARGS[@]}" "$@"

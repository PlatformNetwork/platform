#!/bin/bash
# =============================================================================
# Platform Test Validator Entrypoint
# =============================================================================
# Handles environment variables and starts the validator node
# =============================================================================

set -euo pipefail

HARNESS_PATH="/scripts/test-harness.sh"
if [ -f "${HARNESS_PATH}" ]; then
    # shellcheck source=/scripts/test-harness.sh
    source "${HARNESS_PATH}"
else
    log_info() {
        echo "[INFO] $1"
    }
fi

ARGS="--data-dir ${DATA_DIR:-/data}"
ARGS="$ARGS --listen-addr ${P2P_LISTEN_ADDR:-/ip4/0.0.0.0/tcp/8090}"

if [ "${PLATFORM_TEST_DOCKER_MODE:-auto}" = "required" ] && command -v platform_install_docker_if_needed >/dev/null 2>&1; then
    platform_install_docker_if_needed
fi

# VALIDATOR_SECRET_KEY is read from env by the binary (clap env binding).
# Never pass it as a CLI argument to avoid exposing it in /proc/PID/cmdline.

if [ -n "${NETUID:-}" ]; then
    ARGS="$ARGS --netuid ${NETUID}"
fi

if [ -n "${BOOTSTRAP_PEERS:-}" ]; then
    IFS=',' read -ra PEERS <<< "${BOOTSTRAP_PEERS}"
    for peer in "${PEERS[@]}"; do
        ARGS="$ARGS --bootstrap ${peer}"
    done
fi

if [ -n "${WASM_MODULE_DIR:-}" ]; then
    ARGS="$ARGS --wasm-module-dir ${WASM_MODULE_DIR}"
fi

if [ "${NO_BITTENSOR:-false}" = "true" ]; then
    ARGS="$ARGS --no-bittensor"
fi

log_info "Starting validator-node with args: ${ARGS}"
exec validator-node ${ARGS}

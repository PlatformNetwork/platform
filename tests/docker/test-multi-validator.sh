#!/bin/bash
# =============================================================================
# Platform Multi-Validator Integration Test
# =============================================================================
# Tests multiple validators in a P2P network without Docker build issues
# Uses locally built binary
# Note: This script does not require Docker; see scripts/test-comprehensive.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/test-harness.sh
source "${SCRIPT_DIR}/../../scripts/test-harness.sh"

platform_test_init
trap platform_cleanup_run_dir EXIT
platform_test_init
trap platform_cleanup_run_dir EXIT

VALIDATOR_BINARY="${VALIDATOR_BINARY:-${PLATFORM_TEST_ROOT}/target/release/validator-node}"
NUM_VALIDATORS="${NUM_VALIDATORS:-3}"
BASE_PORT="${BASE_PORT:-9100}"
PLATFORM_TEST_RUN_DIR="${PLATFORM_TEST_RUN_DIR:-${PLATFORM_TEST_TMP_BASE}/multi-validator}"

log_info "Test directory: ${PLATFORM_TEST_RUN_DIR}"
mkdir -p "${PLATFORM_TEST_RUN_DIR}"

if [ ! -x "${VALIDATOR_BINARY}" ]; then
    log_failure "Validator binary not found at ${VALIDATOR_BINARY}"
    log_info "Building..."
    cargo build --release --bin validator-node
fi
log_success "Validator binary found"

declare -a VALIDATOR_PIDS

VALIDATOR_1_DIR="${PLATFORM_TEST_RUN_DIR}/validator-1"
mkdir -p "${VALIDATOR_1_DIR}"
VALIDATOR_1_KEY="0x0000000000000000000000000000000000000000000000000000000000000001"
VALIDATOR_1_PORT="${BASE_PORT}"

log_info "Starting Validator 1 (bootstrap) on port ${VALIDATOR_1_PORT}..."
RUST_LOG=info,validator_node=debug,platform_p2p_consensus=debug \
    "${VALIDATOR_BINARY}" \
    --secret-key "${VALIDATOR_1_KEY}" \
    --data-dir "${VALIDATOR_1_DIR}" \
    --listen-addr "/ip4/127.0.0.1/tcp/${VALIDATOR_1_PORT}" \
    --netuid 100 \
    --no-bittensor \
    > "${VALIDATOR_1_DIR}/output.log" 2>&1 &
VALIDATOR_PIDS+=($!)
log_info "Validator 1 PID: ${VALIDATOR_PIDS[0]}"

sleep 3

if ! kill -0 "${VALIDATOR_PIDS[0]}" 2>/dev/null; then
    log_failure "Validator 1 failed to start"
    tail -50 "${VALIDATOR_1_DIR}/output.log" || true
    exit 1
fi
log_success "Validator 1 started"

for i in $(seq 2 "${NUM_VALIDATORS}"); do
    VALIDATOR_DIR="${PLATFORM_TEST_RUN_DIR}/validator-${i}"
    mkdir -p "${VALIDATOR_DIR}"
    VALIDATOR_KEY="0x000000000000000000000000000000000000000000000000000000000000000${i}"
    VALIDATOR_PORT=$((BASE_PORT + i - 1))

    log_info "Starting Validator ${i} on port ${VALIDATOR_PORT}..."
    RUST_LOG=info,validator_node=debug,platform_p2p_consensus=debug \
        "${VALIDATOR_BINARY}" \
        --secret-key "${VALIDATOR_KEY}" \
        --data-dir "${VALIDATOR_DIR}" \
        --listen-addr "/ip4/127.0.0.1/tcp/${VALIDATOR_PORT}" \
        --bootstrap "/ip4/127.0.0.1/tcp/${VALIDATOR_1_PORT}" \
        --netuid 100 \
        --no-bittensor \
        > "${VALIDATOR_DIR}/output.log" 2>&1 &
    VALIDATOR_PIDS+=($!)
    log_info "Validator ${i} PID: ${VALIDATOR_PIDS[$((i-1))]}"
    sleep 1
done

log_info "Waiting for validators to initialize..."
sleep 5

RUNNING=0
for i in $(seq 1 "${NUM_VALIDATORS}"); do
    if kill -0 "${VALIDATOR_PIDS[$((i-1))]}" 2>/dev/null; then
        log_success "Validator ${i} is running"
        RUNNING=$((RUNNING + 1))
    else
        log_failure "Validator ${i} is not running"
        tail -50 "${PLATFORM_TEST_RUN_DIR}/validator-${i}/output.log" || true
    fi
done

if [ "${RUNNING}" -ne "${NUM_VALIDATORS}" ]; then
    log_failure "Not all validators are running (${RUNNING}/${NUM_VALIDATORS})"
    exit 1
fi

log_info "Checking distributed storage initialization..."
for i in $(seq 1 "${NUM_VALIDATORS}"); do
    DB_FILE="${PLATFORM_TEST_RUN_DIR}/validator-${i}/distributed.db"
    if [ -d "${DB_FILE}" ]; then
        log_success "Validator ${i}: distributed.db exists"
    else
        log_warning "Validator ${i}: distributed.db not found yet"
    fi
done

log_info "Checking P2P network initialization..."
for i in $(seq 1 "${NUM_VALIDATORS}"); do
    LOG_FILE="${PLATFORM_TEST_RUN_DIR}/validator-${i}/output.log"
    if grep -q "P2P network initialized" "${LOG_FILE}" 2>/dev/null; then
        log_success "Validator ${i}: P2P network initialized"
    else
        log_warning "Validator ${i}: P2P initialization message not found"
    fi

    if grep -q "Peer connected\|Peer identified" "${LOG_FILE}" 2>/dev/null; then
        log_success "Validator ${i}: Has peer connections"
    fi
done

log_info "Letting the network stabilize for 10 seconds..."
sleep 10

log_info ""
log_info "==============================================="
log_info "          MULTI-VALIDATOR TEST RESULTS"
log_info "==============================================="

HEALTHY=0
for i in $(seq 1 "${NUM_VALIDATORS}"); do
    if kill -0 "${VALIDATOR_PIDS[$((i-1))]}" 2>/dev/null; then
        DB_FILE="${PLATFORM_TEST_RUN_DIR}/validator-${i}/distributed.db"
        if [ -d "${DB_FILE}" ]; then
            log_success "Validator ${i}: HEALTHY (running + DB initialized)"
            HEALTHY=$((HEALTHY + 1))
        else
            log_warning "Validator ${i}: RUNNING (no DB yet)"
        fi
    else
        log_failure "Validator ${i}: DEAD"
    fi
done

log_info ""
log_info "Summary: ${HEALTHY}/${NUM_VALIDATORS} validators healthy"

log_info ""
log_info "Sample logs from Validator 1:"
tail -30 "${PLATFORM_TEST_RUN_DIR}/validator-1/output.log" || true

if [ "${HEALTHY}" -eq "${NUM_VALIDATORS}" ]; then
    log_success "All validators are healthy!"
    exit 0
fi

log_failure "Some validators are not healthy"
exit 1
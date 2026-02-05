#!/bin/bash
# =============================================================================
# Platform Multi-Validator Integration Test
# =============================================================================
# Tests multiple validators in a P2P network without Docker build issues
# Uses locally built binary
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_failure() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Configuration
VALIDATOR_BINARY="${VALIDATOR_BINARY:-/workspace/target/release/validator-node}"
TEST_DIR="/tmp/platform-test-$$"
NUM_VALIDATORS=${NUM_VALIDATORS:-3}
BASE_PORT=9100

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    for pid in "${VALIDATOR_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Create test directories
mkdir -p "$TEST_DIR"
log_info "Test directory: $TEST_DIR"

# Check binary exists
if [ ! -x "$VALIDATOR_BINARY" ]; then
    log_failure "Validator binary not found at $VALIDATOR_BINARY"
    log_info "Building..."
    cd /workspace && cargo build --release --bin validator-node
fi
log_success "Validator binary found"

# Start validators
declare -a VALIDATOR_PIDS

# Validator 1 (Bootstrap)
VALIDATOR_1_DIR="$TEST_DIR/validator-1"
mkdir -p "$VALIDATOR_1_DIR"
VALIDATOR_1_KEY="0x0000000000000000000000000000000000000000000000000000000000000001"
VALIDATOR_1_PORT=$BASE_PORT

log_info "Starting Validator 1 (bootstrap) on port $VALIDATOR_1_PORT..."
RUST_LOG=info,validator_node=debug,platform_p2p_consensus=debug \
    "$VALIDATOR_BINARY" \
    --secret-key "$VALIDATOR_1_KEY" \
    --data-dir "$VALIDATOR_1_DIR" \
    --listen-addr "/ip4/127.0.0.1/tcp/$VALIDATOR_1_PORT" \
    --netuid 100 \
    --no-bittensor \
    > "$VALIDATOR_1_DIR/output.log" 2>&1 &
VALIDATOR_PIDS+=($!)
log_info "Validator 1 PID: ${VALIDATOR_PIDS[0]}"

# Wait for first validator to initialize
sleep 3

# Check if validator 1 is running
if ! kill -0 "${VALIDATOR_PIDS[0]}" 2>/dev/null; then
    log_failure "Validator 1 failed to start"
    cat "$VALIDATOR_1_DIR/output.log"
    exit 1
fi
log_success "Validator 1 started"

# Start additional validators
for i in $(seq 2 $NUM_VALIDATORS); do
    VALIDATOR_DIR="$TEST_DIR/validator-$i"
    mkdir -p "$VALIDATOR_DIR"
    VALIDATOR_KEY="0x000000000000000000000000000000000000000000000000000000000000000$i"
    VALIDATOR_PORT=$((BASE_PORT + i - 1))
    
    log_info "Starting Validator $i on port $VALIDATOR_PORT..."
    RUST_LOG=info,validator_node=debug,platform_p2p_consensus=debug \
        "$VALIDATOR_BINARY" \
        --secret-key "$VALIDATOR_KEY" \
        --data-dir "$VALIDATOR_DIR" \
        --listen-addr "/ip4/127.0.0.1/tcp/$VALIDATOR_PORT" \
        --bootstrap "/ip4/127.0.0.1/tcp/$VALIDATOR_1_PORT" \
        --netuid 100 \
        --no-bittensor \
        > "$VALIDATOR_DIR/output.log" 2>&1 &
    VALIDATOR_PIDS+=($!)
    log_info "Validator $i PID: ${VALIDATOR_PIDS[$((i-1))]}"
    sleep 1
done

# Wait for all validators to initialize
log_info "Waiting for validators to initialize..."
sleep 5

# Verify all validators are running
RUNNING=0
for i in $(seq 1 $NUM_VALIDATORS); do
    if kill -0 "${VALIDATOR_PIDS[$((i-1))]}" 2>/dev/null; then
        log_success "Validator $i is running"
        ((RUNNING++))
    else
        log_failure "Validator $i is not running"
        cat "$TEST_DIR/validator-$i/output.log" | tail -20
    fi
done

if [ "$RUNNING" -ne "$NUM_VALIDATORS" ]; then
    log_failure "Not all validators are running ($RUNNING/$NUM_VALIDATORS)"
    exit 1
fi

# Check for distributed storage initialization
log_info "Checking distributed storage initialization..."
for i in $(seq 1 $NUM_VALIDATORS); do
    DB_FILE="$TEST_DIR/validator-$i/distributed.db"
    if [ -d "$DB_FILE" ]; then
        log_success "Validator $i: distributed.db exists"
    else
        log_warning "Validator $i: distributed.db not found yet"
    fi
done

# Check logs for P2P initialization
log_info "Checking P2P network initialization..."
for i in $(seq 1 $NUM_VALIDATORS); do
    LOG_FILE="$TEST_DIR/validator-$i/output.log"
    if grep -q "P2P network initialized" "$LOG_FILE" 2>/dev/null; then
        log_success "Validator $i: P2P network initialized"
    else
        log_warning "Validator $i: P2P initialization message not found"
    fi
    
    # Check for peer connections
    if grep -q "Peer connected\|Peer identified" "$LOG_FILE" 2>/dev/null; then
        log_success "Validator $i: Has peer connections"
    fi
done

# Let the network run for a bit longer to establish connections
log_info "Letting the network stabilize for 10 seconds..."
sleep 10

# Final status check
log_info ""
log_info "==============================================="
log_info "          MULTI-VALIDATOR TEST RESULTS"
log_info "==============================================="

HEALTHY=0
for i in $(seq 1 $NUM_VALIDATORS); do
    if kill -0 "${VALIDATOR_PIDS[$((i-1))]}" 2>/dev/null; then
        DB_FILE="$TEST_DIR/validator-$i/distributed.db"
        if [ -d "$DB_FILE" ]; then
            log_success "Validator $i: HEALTHY (running + DB initialized)"
            ((HEALTHY++))
        else
            log_warning "Validator $i: RUNNING (no DB yet)"
        fi
    else
        log_failure "Validator $i: DEAD"
    fi
done

log_info ""
log_info "Summary: $HEALTHY/$NUM_VALIDATORS validators healthy"

# Show sample logs
log_info ""
log_info "Sample logs from Validator 1:"
tail -30 "$TEST_DIR/validator-1/output.log"

if [ "$HEALTHY" -eq "$NUM_VALIDATORS" ]; then
    log_success "All validators are healthy!"
    exit 0
else
    log_failure "Some validators are not healthy"
    exit 1
fi

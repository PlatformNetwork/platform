#!/bin/bash
# =============================================================================
# Platform Comprehensive Test Suite
# =============================================================================
# Runs unit, integration, WASM runtime, and multi-validator tests.
# Docker is required only for phase 8 (multi-validator compose); install via scripts/install-docker.sh.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./test-harness.sh
source "${SCRIPT_DIR}/test-harness.sh"

PASSED=0
FAILED=0
SKIPPED=0

platform_test_init
trap platform_cleanup_run_dir EXIT

log_info "============================================================================="
log_info "                    Platform Comprehensive Test Suite"
log_info "============================================================================="
log_info "Artifacts: ${PLATFORM_TEST_ARTIFACTS_DIR}"
log_info "Run dir: ${PLATFORM_TEST_RUN_DIR}"
log_info "Defaults: nightly toolchain uses -Z threads=0"
log_info "Defaults: fast linker flags opt-in via env"
log_info "Opt-out: PLATFORM_DISABLE_NIGHTLY=1"
log_info "Override: PLATFORM_RUST_NIGHTLY=1"
log_info "Opt-out: PLATFORM_DISABLE_FAST_LINKER=1"
log_info "Override: PLATFORM_FAST_LINKER_RUSTFLAGS/PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN"
log_info "Override: PLATFORM_LINKER_RUSTFLAGS/PLATFORM_LINKER_RUSTFLAGS_DARWIN"
log_info ""

if [ "${PLATFORM_DISABLE_NIGHTLY:-0}" = "1" ]; then
    export PLATFORM_NIGHTLY_RUSTFLAGS=""
    export RUSTUP_TOOLCHAIN=""
    log_info "Nightly Rust disabled via opt-out"
elif [ "${PLATFORM_RUST_NIGHTLY:-0}" = "1" ] || [ "${RUSTUP_TOOLCHAIN:-}" = "nightly" ]; then
    export RUSTUP_TOOLCHAIN="nightly"
    export PLATFORM_NIGHTLY_RUSTFLAGS="${PLATFORM_NIGHTLY_RUSTFLAGS:--Z threads=0}"
    log_info "Nightly Rust enabled (parallel rustc)"
else
    export PLATFORM_NIGHTLY_RUSTFLAGS=""
    log_info "Nightly Rust not requested; clearing nightly flags"
fi

if [ "${PLATFORM_DISABLE_FAST_LINKER:-0}" = "1" ]; then
    export PLATFORM_FAST_LINKER_RUSTFLAGS=""
    export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN=""
    export PLATFORM_LINKER_RUSTFLAGS=""
    export PLATFORM_LINKER_RUSTFLAGS_DARWIN=""
    log_info "Fast linker disabled via opt-out"
fi

log_info "============================================================================="
log_info "Phase 1: Build (cargo build --release)"
log_info "============================================================================="
log_info "Building workspace..."
if cargo build --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/build.log"; then
    log_success "Build completed successfully"
else
    log_failure "Build failed"
    exit 1
fi

log_info "============================================================================="
log_info "Phase 2: Unit Tests (cargo test --workspace)"
log_info "============================================================================="
log_info "Running unit tests..."
if cargo test --workspace --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/unit-tests.log"; then
    log_success "Unit tests completed"
else
    log_failure "Unit tests failed"
fi

log_info "============================================================================="
log_info "Phase 3: WASM Runtime Tests"
log_info "============================================================================="
log_info "Running WASM runtime interface tests..."
if cargo test -p wasm-runtime-interface --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/wasm-runtime.log"; then
    log_success "WASM runtime interface tests passed"
else
    log_failure "WASM runtime interface tests failed"
fi

log_info "============================================================================="
log_info "Phase 4: Bittensor Integration Tests"
log_info "============================================================================="
log_info "Running Bittensor integration tests (requires network)..."
if timeout 120 cargo test -p platform-bittensor --release -- --ignored 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/bittensor.log"; then
    log_success "Bittensor integration tests passed"
else
    log_warning "Bittensor integration tests failed or timed out"
fi

log_info "============================================================================="
log_info "Phase 5: WASM Sandbox Policy Tests"
log_info "============================================================================="
log_info "Verifying WASM sandbox policies..."

log_info "Running challenge registry policy tests..."
if cargo test -p platform-challenge-registry --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/challenge-registry-policy.log"; then
    log_success "Challenge registry policy tests passed"
else
    log_failure "Challenge registry policy tests failed"
fi

log_info "============================================================================="
log_info "Phase 6: P2P Consensus Tests"
log_info "============================================================================="
log_info "Running P2P consensus unit tests..."
if cargo test -p platform-p2p-consensus --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/p2p-tests.log"; then
    log_success "P2P consensus tests completed"
else
    log_failure "P2P consensus tests failed"
fi

log_info "============================================================================="
log_info "Phase 7: Storage Tests"
log_info "============================================================================="
log_info "Running storage tests..."
if cargo test -p platform-storage --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/storage-tests.log"; then
    log_success "Storage tests passed"
else
    log_failure "Storage tests failed"
fi

log_info "Running distributed storage tests..."
if cargo test -p platform-distributed-storage --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/distributed-storage-tests.log"; then
    log_success "Distributed storage tests passed"
else
    log_failure "Distributed storage tests failed"
fi

log_info "============================================================================="
log_info "Phase 8: Multi-validator Docker Compose"
log_info "============================================================================="
if platform_should_run_docker; then
    if platform_require_compose; then
        platform_ensure_network
        log_info "Running multi-validator docker test harness..."
        if "${SCRIPT_DIR}/../tests/docker/test-multi-validator.sh" 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/multi-validator-docker.log"; then
            log_success "Multi-validator docker test completed"
        else
            log_failure "Multi-validator docker test failed"
        fi
    else
        log_skip "Docker Compose not available"
    fi
else
    log_skip "Docker not available, skipping compose tests"
fi

log_info "============================================================================="
log_info "                           Test Summary"
log_info "============================================================================="
log_info "Passed: ${PASSED}"
log_info "Failed: ${FAILED}"
log_info "Skipped: ${SKIPPED}"

if [ "${FAILED}" -eq 0 ]; then
    log_success "All tests passed"
    exit 0
fi

log_failure "Some tests failed"
exit 1
#!/bin/bash
# =============================================================================
# Platform Comprehensive Test Suite
# =============================================================================
# Runs unit, integration, docker, and multi-validator tests.
# Docker is required for phases 3 and 8; install via scripts/install-docker.sh.
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
log_info ""

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
log_info "Phase 3: Docker Integration Tests"
log_info "============================================================================="
if platform_should_run_docker; then
    if platform_require_compose; then
        platform_ensure_network
        log_info "Running secure-container-runtime Docker tests..."
        if cargo test -p secure-container-runtime --release -- --ignored 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/docker-secure-container.log"; then
            log_success "Secure container runtime Docker tests passed"
        else
            log_failure "Secure container runtime Docker tests failed"
        fi

        log_info "Running challenge-orchestrator Docker tests..."
        if cargo test -p challenge-orchestrator --release -- --ignored 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/docker-orchestrator.log"; then
            log_success "Challenge orchestrator Docker tests passed"
        else
            log_failure "Challenge orchestrator Docker tests failed"
        fi
    else
        log_skip "Docker Compose not available"
    fi
else
    log_skip "Docker not available, skipping Docker tests"
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
log_info "Phase 5: Security Policy Tests"
log_info "============================================================================="
log_info "Verifying security policies..."

log_info "Testing Docker socket mount blocking..."
if cargo test -p secure-container-runtime test_default_policy_blocks_docker_socket --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/policy-docker-socket.log"; then
    log_success "Docker socket mount blocking verified"
else
    log_failure "Docker socket mount blocking test failed"
fi

log_info "Testing image whitelist enforcement..."
if cargo test -p secure-container-runtime test_strict_policy_blocks_non_whitelisted_images --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/policy-image-whitelist.log"; then
    log_success "Image whitelist enforcement verified"
else
    log_failure "Image whitelist enforcement test failed"
fi

log_info "Testing resource limit enforcement..."
if cargo test -p secure-container-runtime test_policy_enforces_resource_limits --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/policy-resource-limits.log"; then
    log_success "Resource limit enforcement verified"
else
    log_failure "Resource limit enforcement test failed"
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
        log_info "Starting compose stack..."
        if platform_compose -f "${PLATFORM_TEST_COMPOSE_FILE}" up --build -d 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/compose-up.log"; then
            log_success "Compose stack started"
        else
            log_failure "Compose stack failed to start"
        fi

        log_info "Collecting compose logs..."
        platform_compose -f "${PLATFORM_TEST_COMPOSE_FILE}" logs --no-color 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/compose.log" || true

        log_info "Tearing down compose stack..."
        platform_compose -f "${PLATFORM_TEST_COMPOSE_FILE}" down -v 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/compose-down.log" || true
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
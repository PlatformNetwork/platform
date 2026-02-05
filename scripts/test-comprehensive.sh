#!/bin/bash
# =============================================================================
# Platform Comprehensive Test Suite
# =============================================================================
# Runs all tests including unit tests, integration tests, Docker tests,
# and multi-validator P2P network tests.
#
# Usage:
#   ./scripts/test-comprehensive.sh
#
# Requirements:
#   - Docker daemon running
#   - Rust toolchain installed
#   - Network access for Bittensor integration tests
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test result counters
PASSED=0
FAILED=0
SKIPPED=0

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

# Header
echo "============================================================================="
echo "                    Platform Comprehensive Test Suite"
echo "============================================================================="
echo ""
date
echo ""

# =============================================================================
# Phase 1: Build
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 1: Build (cargo build --release)"
echo "============================================================================="

log_info "Building workspace..."
if cargo build --release 2>&1; then
    log_success "Build completed successfully"
else
    log_failure "Build failed"
    exit 1
fi

# =============================================================================
# Phase 2: Unit Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 2: Unit Tests (cargo test --workspace)"
echo "============================================================================="

log_info "Running unit tests..."
if cargo test --workspace --release 2>&1 | tee /tmp/unit_tests.log; then
    UNIT_RESULTS=$(grep -E "^test result:" /tmp/unit_tests.log | tail -1)
    log_success "Unit tests completed: $UNIT_RESULTS"
else
    log_failure "Unit tests failed"
fi

# =============================================================================
# Phase 3: Docker Integration Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 3: Docker Integration Tests"
echo "============================================================================="

# Check Docker availability
if docker info > /dev/null 2>&1; then
    log_info "Docker daemon available"
    
    # Secure Container Runtime tests
    log_info "Running secure-container-runtime Docker tests..."
    if cargo test -p secure-container-runtime --release -- --ignored 2>&1 | tee /tmp/docker_tests.log; then
        log_success "Secure container runtime Docker tests passed"
    else
        log_failure "Secure container runtime Docker tests failed"
    fi
    
    # Challenge Orchestrator Docker tests
    log_info "Running challenge-orchestrator Docker tests..."
    if cargo test -p challenge-orchestrator --release -- --ignored 2>&1; then
        log_success "Challenge orchestrator Docker tests passed"
    else
        log_failure "Challenge orchestrator Docker tests failed"
    fi
else
    log_skip "Docker not available, skipping Docker tests"
fi

# =============================================================================
# Phase 4: Bittensor Integration Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 4: Bittensor Integration Tests"
echo "============================================================================="

log_info "Running Bittensor integration tests (requires network)..."
if timeout 120 cargo test -p platform-bittensor --release -- --ignored 2>&1; then
    log_success "Bittensor integration tests passed"
else
    log_warning "Bittensor integration tests failed or timed out (may require network)"
fi

# =============================================================================
# Phase 5: Security Policy Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 5: Security Policy Tests"
echo "============================================================================="

log_info "Verifying security policies..."

# Test that Docker socket mounting is blocked
log_info "Testing Docker socket mount blocking..."
if cargo test -p secure-container-runtime test_default_policy_blocks_docker_socket --release 2>&1; then
    log_success "Docker socket mount blocking verified"
else
    log_failure "Docker socket mount blocking test failed"
fi

# Test image whitelist
log_info "Testing image whitelist enforcement..."
if cargo test -p secure-container-runtime test_strict_policy_blocks_non_whitelisted_images --release 2>&1; then
    log_success "Image whitelist enforcement verified"
else
    log_failure "Image whitelist enforcement test failed"
fi

# Test resource limits
log_info "Testing resource limit enforcement..."
if cargo test -p secure-container-runtime test_policy_enforces_resource_limits --release 2>&1; then
    log_success "Resource limit enforcement verified"
else
    log_failure "Resource limit enforcement test failed"
fi

# =============================================================================
# Phase 6: P2P Consensus Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 6: P2P Consensus Tests"
echo "============================================================================="

log_info "Running P2P consensus unit tests..."
if cargo test -p platform-p2p-consensus --release 2>&1 | tee /tmp/p2p_tests.log; then
    P2P_RESULTS=$(grep -E "^test result:" /tmp/p2p_tests.log | tail -1)
    log_success "P2P consensus tests: $P2P_RESULTS"
else
    log_failure "P2P consensus tests failed"
fi

# =============================================================================
# Phase 7: Storage Tests
# =============================================================================
echo ""
echo "============================================================================="
echo "Phase 7: Storage Tests"
echo "============================================================================="

log_info "Running storage tests..."
if cargo test -p platform-storage --release 2>&1; then
    log_success "Storage tests passed"
else
    log_failure "Storage tests failed"
fi

log_info "Running distributed storage tests..."
if cargo test -p platform-distributed-storage --release 2>&1; then
    log_success "Distributed storage tests passed"
else
    log_failure "Distributed storage tests failed"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================================================="
echo "                           Test Summary"
echo "============================================================================="
echo ""
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi

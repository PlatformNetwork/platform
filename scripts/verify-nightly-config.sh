#!/bin/bash
# =============================================================================
# Nightly/Linker Config Verification
# =============================================================================
# Verifies optional nightly + fast linker flags are applied without failing
# on stable toolchains. This is a lightweight check (dry-run build).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./test-harness.sh
source "${SCRIPT_DIR}/test-harness.sh"

platform_test_init
trap platform_cleanup_run_dir EXIT

log_info "Nightly config verification"
log_info "Opt-in: PLATFORM_RUST_NIGHTLY=1 (nightly parallel rustc)"
log_info "Opt-in: PLATFORM_FAST_LINKER=mold|lld"

if [ "${PLATFORM_RUST_NIGHTLY:-0}" = "1" ]; then
    export RUSTUP_TOOLCHAIN="nightly"
    export PLATFORM_NIGHTLY_RUSTFLAGS="${PLATFORM_NIGHTLY_RUSTFLAGS:--Z threads=0}"
    log_info "Nightly Rust enabled (parallel rustc)"
else
    export PLATFORM_NIGHTLY_RUSTFLAGS=""
    log_info "Nightly Rust disabled; stable check"
fi

if [ -n "${PLATFORM_FAST_LINKER:-}" ]; then
    case "${PLATFORM_FAST_LINKER}" in
        mold|lld)
            export PLATFORM_LINKER_RUSTFLAGS="${PLATFORM_LINKER_RUSTFLAGS:--C link-arg=-fuse-ld=${PLATFORM_FAST_LINKER}}"
            log_info "Fast linker enabled: ${PLATFORM_FAST_LINKER}"
            ;;
        *)
            log_warning "Unsupported PLATFORM_FAST_LINKER=${PLATFORM_FAST_LINKER} (expected mold or lld)"
            export PLATFORM_LINKER_RUSTFLAGS=""
            ;;
    esac
else
    export PLATFORM_LINKER_RUSTFLAGS=""
fi

log_info "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-default}"
log_info "PLATFORM_NIGHTLY_RUSTFLAGS=${PLATFORM_NIGHTLY_RUSTFLAGS:-}"
log_info "PLATFORM_LINKER_RUSTFLAGS=${PLATFORM_LINKER_RUSTFLAGS:-}"

log_info "Running cargo check (dry-run build)"
if cargo check --workspace 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/nightly-config-check.log"; then
    log_success "Config verification completed"
else
    log_failure "Config verification failed"
    exit 1
fi
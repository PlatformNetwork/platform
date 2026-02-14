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
log_info "Defaults: nightly toolchain uses parallel rustc"
log_info "Opt-out: PLATFORM_DISABLE_NIGHTLY=1"
log_info "Override: PLATFORM_RUST_NIGHTLY=1"
log_info "Defaults: fast linker flags from config"
log_info "Opt-out: PLATFORM_DISABLE_FAST_LINKER=1"
log_info "Override: PLATFORM_FAST_LINKER_RUSTFLAGS/PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN"
log_info "Override: PLATFORM_LINKER_RUSTFLAGS/PLATFORM_LINKER_RUSTFLAGS_DARWIN"

run_check() {
    local label="$1"
    local log_file="$2"
    shift 2

    PLATFORM_DISABLE_NIGHTLY=0
    PLATFORM_RUST_NIGHTLY=0
    RUSTUP_TOOLCHAIN=""
    PLATFORM_NIGHTLY_RUSTFLAGS=""
    PLATFORM_FAST_LINKER_RUSTFLAGS="${PLATFORM_FAST_LINKER_RUSTFLAGS:-}"
    PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="${PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN:-}"
    PLATFORM_LINKER_RUSTFLAGS="${PLATFORM_LINKER_RUSTFLAGS:-}"
    PLATFORM_LINKER_RUSTFLAGS_DARWIN="${PLATFORM_LINKER_RUSTFLAGS_DARWIN:-}"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --nightly)
                PLATFORM_RUST_NIGHTLY=1
                ;;
            --stable)
                PLATFORM_DISABLE_NIGHTLY=1
                ;;
            *)
                log_failure "Unknown option: $1"
                return 1
                ;;
        esac
        shift
    done

    if [ "${PLATFORM_DISABLE_NIGHTLY:-0}" = "1" ]; then
        PLATFORM_NIGHTLY_RUSTFLAGS=""
        log_info "${label}: Nightly Rust disabled via opt-out"
    elif [ "${PLATFORM_RUST_NIGHTLY:-0}" = "1" ] || [ "${RUSTUP_TOOLCHAIN:-}" = "nightly" ]; then
        RUSTUP_TOOLCHAIN="nightly"
        PLATFORM_NIGHTLY_RUSTFLAGS="${PLATFORM_NIGHTLY_RUSTFLAGS:--Z threads=0}"
        log_info "${label}: Nightly Rust enabled (parallel rustc)"
    else
        log_info "${label}: Nightly Rust not requested; using default toolchain"
    fi

    if [ "${PLATFORM_DISABLE_FAST_LINKER:-0}" = "1" ]; then
        PLATFORM_FAST_LINKER_RUSTFLAGS=""
        PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN=""
        PLATFORM_LINKER_RUSTFLAGS=""
        PLATFORM_LINKER_RUSTFLAGS_DARWIN=""
        log_info "${label}: Fast linker disabled via opt-out"
    fi

    log_info "${label}: Expected toolchain=${RUSTUP_TOOLCHAIN:-default}"
    log_info "${label}: Expected nightly rustflags=${PLATFORM_NIGHTLY_RUSTFLAGS:-<empty>}"
    log_info "${label}: Expected linker rustflags=${PLATFORM_LINKER_RUSTFLAGS:-<empty>}"
    log_info "${label}: Expected linker rustflags darwin=${PLATFORM_LINKER_RUSTFLAGS_DARWIN:-<empty>}"

    export PLATFORM_DISABLE_NIGHTLY
    export PLATFORM_RUST_NIGHTLY
    export RUSTUP_TOOLCHAIN
    export PLATFORM_NIGHTLY_RUSTFLAGS
    export PLATFORM_FAST_LINKER_RUSTFLAGS
    export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN
    export PLATFORM_LINKER_RUSTFLAGS
    export PLATFORM_LINKER_RUSTFLAGS_DARWIN

    log_info "${label}: Running cargo check (dry-run build)"
    if cargo check --workspace 2>&1 | tee "${log_file}"; then
        log_success "${label}: Config verification completed"
    else
        log_failure "${label}: Config verification failed"
        return 1
    fi
}

log_info "Stable verification (nightly opt-out)"
run_check "Stable" "${PLATFORM_TEST_LOG_DIR}/nightly-config-stable.log" --stable

log_info "Nightly verification (defaults apply)"
run_check "Nightly" "${PLATFORM_TEST_LOG_DIR}/nightly-config-nightly.log" --nightly
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

platform_require_command rg
platform_require_command cargo

log_info "Nightly config verification"
log_info "Defaults: nightly toolchain uses -Z threads=0"
log_info "Defaults: fast linker flags from config when set"
log_info "Opt-out: PLATFORM_DISABLE_NIGHTLY=1"
log_info "Override: PLATFORM_RUST_NIGHTLY=1"
log_info "Opt-out: PLATFORM_DISABLE_FAST_LINKER=1"
log_info "Override: PLATFORM_FAST_LINKER_RUSTFLAGS/PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN"
log_info "Override: PLATFORM_LINKER_RUSTFLAGS/PLATFORM_LINKER_RUSTFLAGS_DARWIN"

assert_config_contains() {
    local file_path="$1"
    local expected="$2"

    if rg -F --quiet "${expected}" "${file_path}"; then
        log_success "Config contains: ${expected}"
    else
        log_failure "Missing config entry: ${expected}"
        return 1
    fi
}

verify_config_composition() {
    local cargo_config="${PLATFORM_TEST_ROOT}/.cargo/config.toml"
    local nightly_config="${PLATFORM_TEST_ROOT}/rust-toolchain-nightly.toml"

    log_info "Verifying config composition"
    assert_config_contains "${cargo_config}" 'PLATFORM_LINKER_RUSTFLAGS = { value = "${PLATFORM_FAST_LINKER_RUSTFLAGS}", force = false }'
    assert_config_contains "${cargo_config}" 'PLATFORM_LINKER_RUSTFLAGS_DARWIN = { value = "${PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN}", force = false }'
    assert_config_contains "${cargo_config}" 'RUSTFLAGS = { value = "${PLATFORM_NIGHTLY_RUSTFLAGS} ${PLATFORM_LINKER_RUSTFLAGS}", force = false }'
    assert_config_contains "${cargo_config}" 'RUSTFLAGS = { value = "${PLATFORM_NIGHTLY_RUSTFLAGS} ${PLATFORM_LINKER_RUSTFLAGS_DARWIN}", force = false }'
    assert_config_contains "${nightly_config}" 'PLATFORM_NIGHTLY_RUSTFLAGS = "-Z threads=0"'
}

run_check() {
    local label="$1"
    local log_file="$2"
    local expect_nightly="$3"
    local expect_no_nightly="$4"
    shift 4

    PLATFORM_DISABLE_NIGHTLY=0
    PLATFORM_RUST_NIGHTLY=0
    RUSTUP_TOOLCHAIN=""
    PLATFORM_NIGHTLY_RUSTFLAGS=""
    PLATFORM_FAST_LINKER_RUSTFLAGS="${PLATFORM_FAST_LINKER_RUSTFLAGS:-}"
    PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN="${PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN:-}"
    PLATFORM_LINKER_RUSTFLAGS="${PLATFORM_LINKER_RUSTFLAGS:-}"
    PLATFORM_LINKER_RUSTFLAGS_DARWIN="${PLATFORM_LINKER_RUSTFLAGS_DARWIN:-}"
    PLATFORM_DISABLE_FAST_LINKER="${PLATFORM_DISABLE_FAST_LINKER:-0}"

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
    export PLATFORM_DISABLE_FAST_LINKER

    log_info "${label}: Running cargo check (dry-run build)"
    if cargo check --workspace -v 2>&1 | tee "${log_file}"; then
        log_success "${label}: Config verification completed"
    else
        log_failure "${label}: Config verification failed"
        return 1
    fi

    if [ "${expect_nightly}" -eq 1 ]; then
        if rg -F --quiet "-Z threads=0" "${log_file}"; then
            log_success "${label}: Nightly rustflags detected"
        else
            log_failure "${label}: Nightly rustflags missing"
            return 1
        fi
    fi

    if [ "${expect_no_nightly}" -eq 1 ]; then
        if rg -F --quiet "-Z threads=0" "${log_file}"; then
            log_failure "${label}: Unexpected nightly rustflags detected"
            return 1
        else
            log_success "${label}: Nightly rustflags absent as expected"
        fi
    fi
}

verify_config_composition

log_info "Stable verification (nightly opt-out)"
run_check "Stable" "${PLATFORM_TEST_LOG_DIR}/nightly-config-stable.log" 0 1 --stable

if command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | rg -q '^nightly'; then
    log_info "Nightly verification (defaults apply)"
    run_check "Nightly" "${PLATFORM_TEST_LOG_DIR}/nightly-config-nightly.log" 1 0 --nightly
else
    log_skip "Nightly toolchain not installed; skipping nightly verification"
fi

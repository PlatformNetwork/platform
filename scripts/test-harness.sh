#!/bin/bash
# =============================================================================
# Platform Test Harness Helpers
# =============================================================================
# Shared environment defaults and preflight checks for test entrypoints.
#
# Environment variables:
#   PLATFORM_TEST_ROOT           Repo root (auto-detected)
#   PLATFORM_TEST_ARTIFACTS_DIR  Base artifacts directory
#   PLATFORM_TEST_LOG_DIR        Log output directory
#   PLATFORM_TEST_TMP_BASE       Base temp directory
#   PLATFORM_TEST_RUN_DIR        Specific run directory
#   PLATFORM_TEST_COMPOSE_FILE   Docker compose file path
#   PLATFORM_TEST_COMPOSE_PROJECT Compose project name
#   PLATFORM_TEST_NETWORK        Docker network name
#   PLATFORM_TEST_DOCKER_MODE    auto|skip|required
#   PLATFORM_TEST_PRESERVE_RUN_DIR true to skip cleanup
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    if [ -n "${PASSED+x}" ]; then
        PASSED=$((PASSED + 1))
    fi
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    if [ -n "${FAILED+x}" ]; then
        FAILED=$((FAILED + 1))
    fi
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    if [ -n "${SKIPPED+x}" ]; then
        SKIPPED=$((SKIPPED + 1))
    fi
}

platform_test_init() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    export PLATFORM_TEST_ROOT="${PLATFORM_TEST_ROOT:-$(cd "${script_dir}/.." && pwd)}"
    export PLATFORM_TEST_ARTIFACTS_DIR="${PLATFORM_TEST_ARTIFACTS_DIR:-${PLATFORM_TEST_ROOT}/artifacts/tests}"
    export PLATFORM_TEST_LOG_DIR="${PLATFORM_TEST_LOG_DIR:-${PLATFORM_TEST_ARTIFACTS_DIR}/logs}"
    export PLATFORM_TEST_TMP_BASE="${PLATFORM_TEST_TMP_BASE:-/tmp/platform-tests}"
    export PLATFORM_TEST_COMPOSE_FILE="${PLATFORM_TEST_COMPOSE_FILE:-${PLATFORM_TEST_ROOT}/tests/docker/docker-compose.multi-validator.yml}"
    export PLATFORM_TEST_COMPOSE_PROJECT="${PLATFORM_TEST_COMPOSE_PROJECT:-platform-test}"
    export PLATFORM_TEST_NETWORK="${PLATFORM_TEST_NETWORK:-platform-test}"
    export PLATFORM_TEST_DOCKER_MODE="${PLATFORM_TEST_DOCKER_MODE:-auto}"

    mkdir -p "${PLATFORM_TEST_ARTIFACTS_DIR}" "${PLATFORM_TEST_LOG_DIR}" "${PLATFORM_TEST_TMP_BASE}"

    if [ -z "${PLATFORM_TEST_RUN_DIR:-}" ]; then
        PLATFORM_TEST_RUN_DIR="$(mktemp -d "${PLATFORM_TEST_TMP_BASE}/run-XXXXXX")"
        export PLATFORM_TEST_RUN_DIR
    else
        mkdir -p "${PLATFORM_TEST_RUN_DIR}"
    fi

    if [ -z "${COMPOSE_PROJECT_NAME:-}" ]; then
        export COMPOSE_PROJECT_NAME="${PLATFORM_TEST_COMPOSE_PROJECT}"
    fi
}

platform_cleanup_run_dir() {
    if [ "${PLATFORM_TEST_PRESERVE_RUN_DIR:-false}" != "true" ] && [ -n "${PLATFORM_TEST_RUN_DIR:-}" ]; then
        rm -rf "${PLATFORM_TEST_RUN_DIR}" 2>/dev/null || true
    fi
}

platform_require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_failure "Required command not found: ${cmd}"
        return 1
    fi
}

platform_has_docker() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

platform_require_docker() {
    if ! platform_has_docker; then
        log_failure "Docker daemon not available"
        return 1
    fi
}

platform_has_compose() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        return 0
    fi

    command -v docker-compose >/dev/null 2>&1
}

platform_require_compose() {
    if ! platform_has_compose; then
        log_failure "Docker Compose not available"
        return 1
    fi
}

platform_compose() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        docker compose "$@"
        return
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
        return
    fi

    return 127
}

platform_should_run_docker() {
    case "${PLATFORM_TEST_DOCKER_MODE}" in
        skip)
            return 1
            ;;
        required)
            platform_require_docker
            ;;
        auto)
            platform_has_docker
            ;;
        *)
            log_warning "Unknown PLATFORM_TEST_DOCKER_MODE=${PLATFORM_TEST_DOCKER_MODE}, defaulting to auto"
            platform_has_docker
            ;;
    esac
}

platform_ensure_network() {
    if ! platform_has_docker; then
        return 1
    fi

    if ! docker network inspect "${PLATFORM_TEST_NETWORK}" >/dev/null 2>&1; then
        log_info "Creating docker network ${PLATFORM_TEST_NETWORK}"
        docker network create "${PLATFORM_TEST_NETWORK}" >/dev/null
    fi
}
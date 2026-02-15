#!/bin/bash
# =============================================================================
# Platform Multi-Validator Integration Test (Docker)
# =============================================================================
# Spins up a full multi-validator + mock Subtensor network via Docker Compose.
# Verifies health, distributed DB creation, P2P connectivity, and mock chain
# commit/reveal inspection endpoints. Logs and artifacts are written to
# PLATFORM_TEST_ARTIFACTS_DIR.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/test-harness.sh
source "${SCRIPT_DIR}/../../scripts/test-harness.sh"

platform_test_init

ARTIFACT_DIR="${PLATFORM_TEST_ARTIFACTS_DIR}/multi-validator"
LOG_DIR="${ARTIFACT_DIR}/logs"
mkdir -p "${ARTIFACT_DIR}" "${LOG_DIR}"

COMPOSE_FILE="${PLATFORM_TEST_COMPOSE_FILE}"
COMPOSE_PROJECT="${PLATFORM_TEST_COMPOSE_PROJECT}"

cleanup_compose() {
    if platform_has_compose; then
        platform_compose -f "${COMPOSE_FILE}" logs --no-color > "${LOG_DIR}/compose.log" 2>&1 || true
        platform_compose -f "${COMPOSE_FILE}" down -v > "${LOG_DIR}/compose-down.log" 2>&1 || true
    fi
    platform_cleanup_run_dir
}

trap cleanup_compose EXIT

if ! platform_should_run_docker; then
    log_skip "Docker not available; skipping multi-validator docker test"
    exit 0
fi

platform_require_compose
platform_ensure_network

log_info "Artifacts directory: ${ARTIFACT_DIR}"
log_info "Using compose file: ${COMPOSE_FILE}"
log_info "Compose project: ${COMPOSE_PROJECT}"

log_info "Building docker images..."
platform_compose -f "${COMPOSE_FILE}" build > "${LOG_DIR}/compose-build.log" 2>&1

log_info "Starting compose stack..."
platform_compose -f "${COMPOSE_FILE}" up -d > "${LOG_DIR}/compose-up.log" 2>&1

wait_for_health() {
    local container="$1"
    local timeout_seconds="$2"
    local start
    start=$(date +%s)

    while true; do
        local status
        status=$(docker inspect --format '{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "unknown")
        if [ "${status}" = "healthy" ]; then
            log_success "${container} is healthy"
            return 0
        fi

        local now
        now=$(date +%s)
        if [ $((now - start)) -ge "${timeout_seconds}" ]; then
            log_failure "Timeout waiting for ${container} health (status=${status})"
            return 1
        fi

        sleep 5
    done
}

log_info "Waiting for services to become healthy..."
wait_for_health "platform-mock-subtensor" 180
wait_for_health "platform-validator-1" 180
wait_for_health "platform-validator-2" 180
wait_for_health "platform-validator-3" 180
wait_for_health "platform-validator-4" 180

log_info "Verifying distributed storage initialization..."
for i in 1 2 3 4; do
    if docker exec "platform-validator-${i}" test -f /data/distributed.db; then
        log_success "Validator ${i}: distributed.db created"
    else
        log_failure "Validator ${i}: distributed.db missing"
        exit 1
    fi
done

log_info "Collecting compose logs for connectivity checks..."
platform_compose -f "${COMPOSE_FILE}" logs --no-color > "${LOG_DIR}/compose.log" 2>&1

peer_connections=$(grep -c "Peer connected" "${LOG_DIR}/compose.log" || true)
peer_identified=$(grep -c "Peer identified" "${LOG_DIR}/compose.log" || true)
total_peers=$((peer_connections + peer_identified))

if [ "${total_peers}" -gt 0 ]; then
    log_success "Detected P2P peer activity (${total_peers} events)"
else
    log_failure "No P2P peer activity detected"
    exit 1
fi

log_info "Querying mock-subtensor health endpoint..."
curl -fsS "http://localhost:9944/health" > "${ARTIFACT_DIR}/mock-subtensor-health.json"

log_info "Fetching mock-subtensor neurons for commit/reveal test..."
hotkey_response=$(curl -fsS -X POST "http://localhost:9944/rpc" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"subtensor_getNeurons","params":[100],"id":1}')

echo "${hotkey_response}" > "${ARTIFACT_DIR}/mock-subtensor-neurons.json"

hotkey=$(echo "${hotkey_response}" | grep -m1 -o '"hotkey":"[^"]*"' | cut -d '"' -f4)
if [ -z "${hotkey}" ]; then
    log_failure "Failed to extract hotkey from mock-subtensor response"
    exit 1
fi

log_info "Submitting mock weight commit..."
commit_response=$(curl -fsS -X POST "http://localhost:9944/rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"subtensor_commitWeights\",\"params\":[100,[0,1,2],\"test_commit\",\"${hotkey}\"],\"id\":2}")
echo "${commit_response}" > "${ARTIFACT_DIR}/mock-subtensor-commit.json"

log_info "Submitting mock weight reveal..."
reveal_response=$(curl -fsS -X POST "http://localhost:9944/rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"subtensor_revealWeights\",\"params\":[100,[0,1,2],[65535,65535,65535],\"test_commit\",\"${hotkey}\"],\"id\":3}")
echo "${reveal_response}" > "${ARTIFACT_DIR}/mock-subtensor-reveal.json"

log_info "Inspecting mock-subtensor weight commitments..."
weights_response=$(curl -fsS "http://localhost:9944/test/weights")
echo "${weights_response}" > "${ARTIFACT_DIR}/mock-subtensor-weights.json"

total_revealed=$(echo "${weights_response}" | grep -o '"total_revealed":[0-9]*' | head -1 | cut -d ':' -f2)
if [ -z "${total_revealed}" ] || [ "${total_revealed}" -lt 1 ]; then
    log_failure "No revealed weight commits detected"
    exit 1
fi

log_success "Mock-subtensor commit/reveal flow verified"
log_success "Multi-validator docker test completed successfully"
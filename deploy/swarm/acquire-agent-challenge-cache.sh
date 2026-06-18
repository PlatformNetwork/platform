#!/usr/bin/env bash
#
# acquire-agent-challenge-cache.sh — provision the Terminal-Bench task cache +
# frozen digest manifest onto Docker named volumes for the agent-challenge
# own_runner Swarm Docker-out-of-Docker (DooD) eval jobs.
#
# WHY THIS EXISTS
#   own_runner reads task definitions ONLY from a local cache and performs ZERO
#   network fetch at eval time; it fails closed on any digest mismatch or
#   missing manifest (src/agent_challenge/evaluation/own_runner/taskdefs.py).
#   The runner image deliberately does NOT bake the ~89 task trees, so the
#   broker bind-mounts them read-only into each eval job from named volumes
#   (docker.broker_eval_readonly_mounts in master.yaml). This script fills those
#   volumes from an already-acquired cache and then VERIFIES eval-readiness with
#   the runner image's OWN digest code, so a green run guarantees every manifest
#   task loads under the exact check the eval plane uses.
#
# ACQUISITION SOURCE
#   The cache itself (downloading the pinned terminal-bench-2.1 dataset) is an
#   out-of-band concern by design. Point --source at a directory that already
#   contains the cache layout (``<task_id>/<content_hash>/task.toml`` or
#   ``<task_id>/task.toml`` per task). This script copies + verifies it; it does
#   not download anything.
#
# SAFETY MODEL (mirrors install-swarm.sh)
#   * DEFAULT MODE IS DRY-RUN: with no --apply it prints every mutating command
#     and changes nothing.
#   * Idempotent: re-running re-populates the volumes and re-verifies.
#   * No secrets are read, printed, or required.
#
# Single-node note: named volumes are node-local. On a multi-node Swarm, run
# this on EVERY node that can schedule agent-challenge eval jobs (or back the
# volumes with a shared/cluster volume driver).
#
set -euo pipefail

CACHE_VOLUME="${CACHE_VOLUME:-agent_challenge_task_cache}"
GOLDEN_VOLUME="${GOLDEN_VOLUME:-agent_challenge_golden}"
RUNNER_IMAGE="${RUNNER_IMAGE:-ghcr.io/platformnetwork/agent-challenge-terminal-bench-runner:latest}"

# In-job mount targets. MUST match cli_app/main.py
# (CHALLENGE_OWN_RUNNER_CACHE_ROOT / CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST) and
# master.yaml docker.broker_eval_readonly_mounts.
CACHE_TARGET="/opt/agent-challenge/task-cache"
GOLDEN_TARGET="/opt/agent-challenge/golden"

SOURCE_CACHE=""
GOLDEN_FILE=""
APPLY=false

log() { printf '[acquire-cache] %s\n' "$*" >&2; }

# Run a mutating command only under --apply; otherwise print it.
plan() {
  if [[ "${APPLY}" == "true" ]]; then
    log "RUN: $*"
    "$@"
  else
    log "(dry-run) would: $*"
  fi
}

usage() {
  cat >&2 <<USAGE
Usage: $0 --source <cache_dir> [--golden <dataset-digest.json>] [--apply] [options]

Required:
  --source DIR        Already-acquired task cache root (contains <task_id>/... trees).

Options:
  --golden FILE       Frozen dataset-digest.json (default: <repo>/golden/dataset-digest.json).
  --runner-image IMG  Runner image with own_runner + digest code (default: ${RUNNER_IMAGE}).
  --cache-volume NAME  Named volume for the task cache (default: ${CACHE_VOLUME}).
  --golden-volume NAME Named volume for the digest manifest (default: ${GOLDEN_VOLUME}).
  --apply             Actually create/populate/verify (default: dry-run).
  -h, --help          Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE_CACHE="$2"; shift 2 ;;
    --golden) GOLDEN_FILE="$2"; shift 2 ;;
    --runner-image) RUNNER_IMAGE="$2"; shift 2 ;;
    --cache-volume) CACHE_VOLUME="$2"; shift 2 ;;
    --golden-volume) GOLDEN_VOLUME="$2"; shift 2 ;;
    --apply) APPLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log "unknown argument: $1"; usage; exit 2 ;;
  esac
done

# Default golden path: repo-relative (this script lives in deploy/swarm/).
if [[ -z "${GOLDEN_FILE}" ]]; then
  _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  GOLDEN_FILE="${_script_dir}/../../golden/dataset-digest.json"
fi

# ---------------------------------------------------------------------------
# Validate inputs (cheap guards before any mutation).
# ---------------------------------------------------------------------------
if [[ -z "${SOURCE_CACHE}" ]]; then
  log "ERROR: --source is required"
  usage
  exit 2
fi
if [[ ! -d "${SOURCE_CACHE}" ]]; then
  log "ERROR: --source is not a directory: ${SOURCE_CACHE}"
  exit 2
fi
if ! find "${SOURCE_CACHE}" -maxdepth 3 -name task.toml -print -quit | grep -q .; then
  log "ERROR: no task.toml found under ${SOURCE_CACHE} (is this the cache root?)"
  exit 2
fi
if [[ ! -f "${GOLDEN_FILE}" ]]; then
  log "ERROR: digest manifest not found: ${GOLDEN_FILE}"
  exit 2
fi
SOURCE_CACHE="$(cd "${SOURCE_CACHE}" && pwd)"
GOLDEN_FILE="$(cd "$(dirname "${GOLDEN_FILE}")" && pwd)/$(basename "${GOLDEN_FILE}")"

log "source cache : ${SOURCE_CACHE}"
log "golden file  : ${GOLDEN_FILE}"
log "runner image : ${RUNNER_IMAGE}"
log "cache volume : ${CACHE_VOLUME} -> ${CACHE_TARGET}"
log "golden volume: ${GOLDEN_VOLUME} -> ${GOLDEN_TARGET}"
if [[ "${APPLY}" != "true" ]]; then
  log "DRY-RUN: pass --apply to create/populate/verify the volumes."
fi

# ---------------------------------------------------------------------------
# 1. Create the named volumes (idempotent).
# ---------------------------------------------------------------------------
plan docker volume create "${CACHE_VOLUME}"
plan docker volume create "${GOLDEN_VOLUME}"

# ---------------------------------------------------------------------------
# 2. Populate the volumes (read-only source mount; copy into the volume).
#    The runner image has sh/cp/mkdir; reuse it so no extra image is pulled.
#    All steps run with --network none: acquisition is copy + offline digest
#    verification only, so they never need (and are denied) network egress.
# ---------------------------------------------------------------------------
plan docker run --rm --network none \
  -v "${SOURCE_CACHE}:/src:ro" \
  -v "${CACHE_VOLUME}:${CACHE_TARGET}" \
  "${RUNNER_IMAGE}" \
  sh -ceu "rm -rf ${CACHE_TARGET:?}/* && cp -a /src/. ${CACHE_TARGET}/"

plan docker run --rm --network none \
  -v "${GOLDEN_FILE}:/src/dataset-digest.json:ro" \
  -v "${GOLDEN_VOLUME}:${GOLDEN_TARGET}" \
  "${RUNNER_IMAGE}" \
  sh -ceu "mkdir -p ${GOLDEN_TARGET} && cp /src/dataset-digest.json ${GOLDEN_TARGET}/dataset-digest.json"

# ---------------------------------------------------------------------------
# 3. Verify eval-readiness with own_runner's OWN digest code (fail closed).
#    load_all_tasks resolves + digest-verifies EVERY manifest task against the
#    on-disk cache, so a green run == the eval plane will load every task.
# ---------------------------------------------------------------------------
plan docker run --rm --network none \
  -e CHALLENGE_OWN_RUNNER_CACHE_ROOT="${CACHE_TARGET}" \
  -e CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST="${GOLDEN_TARGET}/dataset-digest.json" \
  -v "${CACHE_VOLUME}:${CACHE_TARGET}:ro" \
  -v "${GOLDEN_VOLUME}:${GOLDEN_TARGET}:ro" \
  "${RUNNER_IMAGE}" \
  python -c "import os; from pathlib import Path; from agent_challenge.evaluation.own_runner.taskdefs import load_all_tasks, load_dataset_digest; m=load_dataset_digest(Path(os.environ['CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST'])); t=load_all_tasks(m, cache_root=Path(os.environ['CHALLENGE_OWN_RUNNER_CACHE_ROOT']), verify_digest=True); print('OK: verified', len(t), 'tasks')"

if [[ "${APPLY}" == "true" ]]; then
  log "DONE: ${CACHE_VOLUME} + ${GOLDEN_VOLUME} populated and digest-verified."
else
  log "DRY-RUN complete. Re-run with --apply to execute the steps above."
fi

#!/usr/bin/env bash
#
# acquire-prism-fineweb-cache.sh — provision the locked FineWeb-Edu splits +
# reference tokenizers onto Docker named volumes for the PRISM evaluator.
#
# WHY THIS EXISTS
#   The prism eval container runs with network=none and reads the locked train
#   split READ-ONLY from a per-slug broker mount (/data/fineweb-edu/train); the
#   host-side scorer reads the SECRET held-out val split READ-ONLY from a
#   separate volume (/secret/val). Neither split is baked into any image and the
#   val/test splits are NEVER mounted into the untrusted eval container. This
#   script fills the named volumes install-swarm.sh mounts, from an already-prepared
#   source tree, and VERIFIES integrity with prism's OWN locked-manifest code
#   (pin SHA + per-shard sha256) so a green run guarantees the staged bytes match
#   the immutable pinned dataset commit.
#
# ACQUISITION SOURCE
#   Producing the source tree (the one-time, network-enabled HuggingFace prep)
#   is an out-of-band concern: run `python -m prism_challenge.evaluator.data_prep
#   --output-dir <dir> --limit N` in a network-enabled prep environment (it pins
#   the immutable commit SHA and the optional HF token comes from a Docker secret
#   file, never a plaintext literal). Point --source at the resulting directory
#   (MANIFEST.json + train/ val/ test/ subdirs). This script copies + verifies it;
#   it does not download anything and needs no network.
#
# SAFETY MODEL (mirrors install-swarm.sh / acquire-agent-challenge-cache.sh)
#   * DEFAULT MODE IS DRY-RUN: with no --apply it prints every mutating command
#     and changes nothing.
#   * Idempotent: re-running re-populates the volumes and re-verifies.
#   * No secrets are read, printed, or required; all steps run --network none.
#   * The SECRET val/test splits are staged into their own volumes; isolation is
#     enforced at MOUNT time (install-swarm.sh mounts val only into the scorer).
#
# Single-node note: named volumes are node-local. On a multi-node Swarm, run this
# on EVERY node that schedules prism eval/scorer work (or back the volumes with a
# shared/cluster volume driver).
#
set -euo pipefail

TRAIN_VOLUME="${TRAIN_VOLUME:-prism_fineweb_edu_train}"
VAL_VOLUME="${VAL_VOLUME:-prism_fineweb_edu_val}"
TEST_VOLUME="${TEST_VOLUME:-prism_fineweb_edu_test}"
TOKENIZER_VOLUME="${TOKENIZER_VOLUME:-prism_reference_tokenizers}"
EVALUATOR_IMAGE="${EVALUATOR_IMAGE:-ghcr.io/baseintelligence/prism-evaluator:latest}"

SOURCE_DIR=""
TOKENIZER_SOURCE=""
APPLY=false

log() { printf '[acquire-prism] %s\n' "$*" >&2; }

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
Usage: $0 --source <prep_dir> [--tokenizers <dir>] [--apply] [options]

Required:
  --source DIR         Prepared locked-dataset root (MANIFEST.json + train/ val/ test/).

Options:
  --tokenizers DIR     Reference-tokenizer cache root to stage (default: skip).
  --evaluator-image IMG  Image with prism_challenge for verification (default: ${EVALUATOR_IMAGE}).
  --train-volume NAME  Named volume for the train split (default: ${TRAIN_VOLUME}).
  --val-volume NAME    Named volume for the SECRET val split (default: ${VAL_VOLUME}).
  --test-volume NAME   Named volume for the SECRET test split (default: ${TEST_VOLUME}).
  --tokenizer-volume NAME Named volume for reference tokenizers (default: ${TOKENIZER_VOLUME}).
  --apply              Actually create/populate/verify (default: dry-run).
  -h, --help           Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --tokenizers) TOKENIZER_SOURCE="$2"; shift 2 ;;
    --evaluator-image) EVALUATOR_IMAGE="$2"; shift 2 ;;
    --train-volume) TRAIN_VOLUME="$2"; shift 2 ;;
    --val-volume) VAL_VOLUME="$2"; shift 2 ;;
    --test-volume) TEST_VOLUME="$2"; shift 2 ;;
    --tokenizer-volume) TOKENIZER_VOLUME="$2"; shift 2 ;;
    --apply) APPLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log "unknown argument: $1"; usage; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Validate inputs (cheap guards before any mutation).
# ---------------------------------------------------------------------------
if [[ -z "${SOURCE_DIR}" ]]; then
  log "ERROR: --source is required"
  usage
  exit 2
fi
if [[ ! -d "${SOURCE_DIR}" ]]; then
  log "ERROR: --source is not a directory: ${SOURCE_DIR}"
  exit 2
fi
if [[ ! -f "${SOURCE_DIR}/MANIFEST.json" ]]; then
  log "ERROR: MANIFEST.json not found under ${SOURCE_DIR} (is this the prep root?)"
  exit 2
fi
for split in train val test; do
  if [[ ! -d "${SOURCE_DIR}/${split}" ]]; then
    log "ERROR: missing split directory: ${SOURCE_DIR}/${split}"
    exit 2
  fi
done
SOURCE_DIR="$(cd "${SOURCE_DIR}" && pwd)"
if [[ -n "${TOKENIZER_SOURCE}" ]]; then
  if [[ ! -d "${TOKENIZER_SOURCE}" ]]; then
    log "ERROR: --tokenizers is not a directory: ${TOKENIZER_SOURCE}"
    exit 2
  fi
  TOKENIZER_SOURCE="$(cd "${TOKENIZER_SOURCE}" && pwd)"
fi

log "source dir    : ${SOURCE_DIR}"
log "evaluator img : ${EVALUATOR_IMAGE}"
log "train volume  : ${TRAIN_VOLUME} -> /data/fineweb-edu/train (eval RO) + /secret/train (scorer RO)"
log "val volume    : ${VAL_VOLUME} -> /secret/val (scorer RO ONLY; never the eval container)"
log "test volume   : ${TEST_VOLUME} (SECRET held-out; not mounted by default)"
log "tokenizer vol : ${TOKENIZER_VOLUME} -> /opt/prism/reference-tokenizers (eval RO)"
if [[ "${APPLY}" != "true" ]]; then
  log "DRY-RUN: pass --apply to create/populate/verify the volumes."
fi

# ---------------------------------------------------------------------------
# 1. Verify the SOURCE integrity with prism's OWN locked-manifest code BEFORE
#    staging: recompute every shard sha256 and assert the immutable pin SHA.
#    Runs offline (--network none); a non-zero exit aborts before any mutation.
# ---------------------------------------------------------------------------
plan docker run --rm --network none \
  -v "${SOURCE_DIR}:/locked:ro" \
  "${EVALUATOR_IMAGE}" \
  python -c "from pathlib import Path; from prism_challenge.evaluator.dataset import load_locked_manifest, verify_locked_manifest_or_raise; r=Path('/locked'); verify_locked_manifest_or_raise(r, load_locked_manifest(r)); print('OK: locked dataset pin + sha256 verified')"

# ---------------------------------------------------------------------------
# 2. Create the named volumes (idempotent).
# ---------------------------------------------------------------------------
plan docker volume create "${TRAIN_VOLUME}"
plan docker volume create "${VAL_VOLUME}"
plan docker volume create "${TEST_VOLUME}"
if [[ -n "${TOKENIZER_SOURCE}" ]]; then
  plan docker volume create "${TOKENIZER_VOLUME}"
fi

# ---------------------------------------------------------------------------
# 3. Populate each split volume from its source subdir (FLAT layout: the shards
#    land at the volume root so the consumer reads <mount>/<split>-*.jsonl).
#    Reuse the evaluator image (has sh/cp/mkdir); every step is --network none.
# ---------------------------------------------------------------------------
_stage_split() {
  local split="$1" volume="$2"
  plan docker run --rm --network none \
    -v "${SOURCE_DIR}/${split}:/src:ro" \
    -v "${volume}:/dst" \
    "${EVALUATOR_IMAGE}" \
    sh -ceu "rm -rf /dst/* && cp -a /src/. /dst/"
}

_stage_split train "${TRAIN_VOLUME}"
_stage_split val "${VAL_VOLUME}"
_stage_split test "${TEST_VOLUME}"

if [[ -n "${TOKENIZER_SOURCE}" ]]; then
  plan docker run --rm --network none \
    -v "${TOKENIZER_SOURCE}:/src:ro" \
    -v "${TOKENIZER_VOLUME}:/dst" \
    "${EVALUATOR_IMAGE}" \
    sh -ceu "rm -rf /dst/* && cp -a /src/. /dst/"
fi

if [[ "${APPLY}" == "true" ]]; then
  log "DONE: locked splits staged + integrity-verified (train/val/test${TOKENIZER_SOURCE:+/tokenizers})."
else
  log "DRY-RUN complete. Re-run with --apply to execute the steps above."
fi

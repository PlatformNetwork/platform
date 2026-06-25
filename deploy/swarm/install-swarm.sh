#!/usr/bin/env bash
#
# install-swarm.sh — single-node Docker Swarm bring-up of the BASE master
# + both challenges (agent-challenge, PRISM) on the validator node.
#
# ============================================================================
# STATUS: DRAFT FOR HUMAN REVIEW. DO NOT EXECUTE BLINDLY.
# ============================================================================
#
# This script brings the BASE master + both challenges up on a single-node
# Docker Swarm (the manager node). Docker Swarm is the only backend — there is
# no Kubernetes. It is meant to be reviewed and then executed STEP BY STEP by an
# operator.
#
# Adding workers: this script brings up only the single manager node. To attach
# CPU/GPU worker nodes, mint a join token on the manager with
# `base master worker token --cpu|--gpu`, run `scripts/install-worker.sh` on
# the worker, then `base master worker label <node> --workload cpu|gpu`.
# See deploy/swarm/README.md.
#
# Safety model (see EXPECTED OUTCOME in the task brief):
#   * DEFAULT MODE IS DRY-RUN. With no flags, the script prints every planned
#     mutating command (via `plan`) and changes NOTHING.
#   * Nothing mutating happens unless `--apply` is passed.
#   * Every DESTRUCTIVE step is behind its OWN explicit flag and is NOT part of
#     the default `--apply` path, so the operator opts in one step at a time:
#         --restart-dockerd       (writes /etc/docker/daemon.json + restarts dockerd)
#         --single-node-placement (non-default placement override; see REVIEW block)
#         --static-challenges     (create challenge services directly here)
#   * Node teardown is OUT OF SCOPE for this script (see the OUT-OF-SCOPE comment
#     block near the bottom). Decommissioning a node is performed separately, by
#     hand, ONLY after human GREEN confirmation.
#
# Secret handling:
#   * NO secret, token, password, GHCR credential, or wallet material is ever
#     hardcoded. All values come from environment variables or files passed at
#     runtime. Secret VALUES are never printed (only the env var NAME is shown
#     in plan output). Values reach `docker secret create` via stdin, never as
#     argv (so they never appear in `ps`/proc).
#
# Deliberately NO docker-compose / stack YAML is produced or consumed
# (tests/unit/test_docker_compose_deploy.py forbids compose files). This script
# is imperative `docker swarm` / `docker service create` / `docker secret`
# / `docker network` only.
#
# ----------------------------------------------------------------------------
# shellcheck disable=SC2310
#   SC2310: functions invoked in `if ... ; then` conditions lose `set -e`
#   inside them. That is intentional here — preflight/health probes are meant
#   to be evaluated as booleans, and each performs its own explicit error
#   handling/return codes rather than relying on `errexit` propagation.
# ----------------------------------------------------------------------------

set -euo pipefail

# ============================================================================
# Configuration (overridable via flags / environment). NO secrets here.
# ============================================================================

# Validator node Swarm advertise address (default = the live validator IP).
ADVERTISE_ADDR="${ADVERTISE_ADDR:-51.83.112.164}"

# Postgres dump + baseline directory produced by the cutover backup step.
BACKUP_DIR="${BACKUP_DIR:-/root/cutover-backups/LATEST}"

# Where the rendered master config is written on the validator host.
MASTER_CONFIG_PATH="${MASTER_CONFIG_PATH:-/etc/base/master.yaml}"

# Repo-relative path to the validator daemon.json template (resolved at runtime).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
DAEMON_JSON_SRC="${DAEMON_JSON_SRC:-${SCRIPT_DIR}/daemon.validator.json}"
DAEMON_JSON_DST="${DAEMON_JSON_DST:-/etc/docker/daemon.json}"

# Container images (LIVE INVENTORY — pinned GHCR tags).
#
# REPRODUCIBILITY CAVEAT — the live broker/prism run LOCAL-ONLY images (M2/M3).
# The working live E2E stack does NOT run these :latest tags for the broker and
# prism; it runs two LOCAL-ONLY images that are NOT on any registry:
#   * base-master-broker -> ghcr.io/baseintelligence/base-master:readonly-data-mount
#   * challenge-prism        -> ghcr.io/baseintelligence/prism:m5
# (M5) challenge-prism is rebuilt from prism HEAD (PRISM v2 forced-init runner + instrumented
# loss + scoring + harness robustness + multi-GPU + M4 anti-cheat/held-out/compute-block + the
# M5 OpenRouter LLM hard gate) as the LOCAL-ONLY tag :m5 and redeployed manager-pinned,
# `--update-order stop-first --no-resolve-image`. Its evaluator stays the LOCAL-ONLY
# ghcr.io/baseintelligence/prism-evaluator:augmented (see below) — UNCHANGED from M2/M3: the
# anti-cheat sandbox/static phase + scoring/manifest authoring run HOST-SIDE in the challenge
# service and the in-container runner.py is injected at run time, so M4/M5 needs no eval-image
# rebuild (the only baked module the runner imports, reference_tokenizers, is unchanged).
# The host-side held-out delta needs BOTH the SECRET val split (manager-local volume
# `prism_fineweb_edu_val`, RO at /secret/val) AND the non-secret TRAIN split (manager-local
# volume `prism_fineweb_edu_train`, RO at /secret/train) present + populated; with the train
# mount the converged-memorization-gap path activates (gap_basis='converged'), else it falls
# back to the prequential reference (no regression). If val is absent the held-out is skipped.
# The broker LOCAL-ONLY image is built from base HEAD and carries the UNPUSHED
# base commits 1142bc53 (cross-node mount materialization for GPU eval jobs) +
# 48ec8c5a (non-root mount extraction + uncapped drain round-trip) + e02ffbab
# (per-slug read-only locked-data mount for the prism slug); challenge-prism overlays
# the same base. The prism eval RO mounts (FineWeb-Edu train split + reference
# tokenizers) are supplied by the broker built-in DEFAULT_PRISM_EVAL_READONLY_MOUNTS,
# so no master.yaml broker_eval_readonly_mounts_by_slug entry is required for them to
# be live. prism pins its base
# dependency by git (pyproject `base @ git+https://github.com/BaseIntelligence/base.git`,
# public HEAD), so until those commits are PUSHED a fresh `docker build` of
# IMAGE_PRISM bundles the OLD published base (lacking mount_transport /
# the drain-restore path / the per-slug prism RO data mount) and the GPU eval
# workspace+artifacts restore and locked-data auto-mount are broken.
# CLEAN CANONICAL BRING-UP: first PUSH base commits 1142bc53 + 48ec8c5a + e02ffbab
# so the prism git-pinned dependency picks them up, then rebuild IMAGE_MASTER + IMAGE_PRISM
# from HEAD normally — the overlay tags above then become unnecessary. The deploy
# CONFIG this script sets (broker node.role==manager pin; prism
# PRISM_ALLOW_INSECURE_SIGNATURES / PRISM_VALIDATOR_HOTKEYS) is independent of the
# image build and reproduces as-is.
IMAGE_MASTER="ghcr.io/baseintelligence/base-master:latest"
IMAGE_AGENT_CHALLENGE="ghcr.io/baseintelligence/agent-challenge:latest"
IMAGE_PRISM="ghcr.io/baseintelligence/prism:latest"
# Prism GPU evaluator (CUDA cu128 torchrun runner). Must satisfy BOTH prism
# docker_allowed_images AND the broker broker_allowed_images (ghcr.io/baseintelligence/);
# pre-pulled on the GPU worker so the broker eval job resolves it locally.
# NB: PRISM v2 forced-init re-execution requires the :augmented tag (bundles sentencepiece +
# offline tiktoken/HF assets for the locked FineWeb-Edu pipeline). The registry :latest is STALE
# and lacks those — it is a LOCAL-ONLY image pre-pulled/built on the GPU node. Do NOT use :latest.
IMAGE_PRISM_EVALUATOR="${IMAGE_PRISM_EVALUATOR:-ghcr.io/baseintelligence/prism-evaluator:augmented}"
IMAGE_POSTGRES="postgres:16-alpine"

# Minimum Docker engine major version required (validator runs 29.x today).
MIN_DOCKER_MAJOR=29

# Swarm overlay networks (MUST match swarm_backend.py constants):
#   DEFAULT_NETWORK_NAME = "base_challenges"     (swarm_backend.py via docker_orchestrator.py:29)
#   DEFAULT_JOB_NETWORK  = "base_jobs_internal"  (swarm_backend.py:87)
#   OVERLAY_MTU          = "1450"                     (swarm_backend.py:88)
NET_CHALLENGES="base_challenges"
NET_JOBS_INTERNAL="base_jobs_internal"
OVERLAY_MTU="1450"

# Secret mount layout INSIDE containers is /run/secrets/base/<name>
#   (docker_orchestrator.py:32 DEFAULT_SECRET_MOUNT_DIR = "/run/secrets/base").
SECRET_MOUNT_DIR="/run/secrets/base"

# Master service network endpoints (LIVE host ports — the live 18xxx stack).
# Overridable via env so a fresh bring-up reproduces the live box exactly; each
# value flows to BOTH the container target + host --publish AND the rendered
# master config (proxy_port/broker_port/broker_url), so the published
# host port, the in-container listen port, and the overlay broker_url stay
# mutually consistent.
#   broker : base master broker  -> docker.broker_*        (18082)
#   proxy  : base master proxy   -> proxy_host:proxy_port  (18080)
# SINGLE PUBLIC API: the proxy also serves the admin/registry surface
# (/v1/registry, /v1/weights/latest, /health) on :18080, so there is no separate
# admin service/port (the former base-master-admin on 18900 is removed).
MASTER_BROKER_PORT="${MASTER_BROKER_PORT:-18082}"
MASTER_PROXY_PORT="${MASTER_PROXY_PORT:-18080}"
# Challenge container-internal listen ports (overlay-internal; NO host publish —
# clients reach them THROUGH the proxy). Separate network namespaces, so these do
# NOT collide with the master host ports above.
AGENT_CHALLENGE_PORT=8000
PRISM_PORT=8080

# Named volumes for stateful postgres data.
VOL_MASTER_PG="base_master_pg"
VOL_AGENT_CHALLENGE_PG="agent_challenge_pg"
VOL_PRISM_PG="prism_pg"

# Shared base secrets volume, mounted by broker/proxy at the master's
# DockerSettings.secret_dir. The master reads each challenge's bearer token and
# the per-challenge docker-broker token from <secret_dir>/<slug>_challenge_token
# (registry.py:_token_path). The PROXY in particular needs this mount or miner
# uploads 500 "Challenge token file is missing" (see "Proxy submission-path
# requirements" in AGENTS.md). Keep SECRET_VOLUME_DIR == DockerSettings.secret_dir.
VOL_BASE_SECRETS="vol_base_secrets"
SECRET_VOLUME_DIR="/var/lib/base/secrets"

# ---- Proxy submission-path config (canonicalizes the M1 live `docker service
# update` fixes; see AGENTS.md "Proxy submission-path requirements"). All values
# below are public (ss58 addresses / image refs), never secrets. ----
#
# Upload allowlist: ss58 hotkeys the proxy MinerUploadVerifier accepts WITHOUT
# on-chain registration (settings.master.upload_extra_registered_hotkeys, env
# BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS). A non-allowlisted hotkey ->
# 401 "unknown hotkey". Parameterizable. Default = the live miner (//AcE2EMiner)
# + owner (//Owner) PLUS two SPARE validator hotkeys (//AcValidator1/2) kept free
# of the agent-challenge 1-submission-per-hotkey-per-3h rate limit for the M1
# user-testing validator (derived ss58 recorded in library/user-testing.md).
UPLOAD_EXTRA_REGISTERED_HOTKEYS="${UPLOAD_EXTRA_REGISTERED_HOTKEYS:-[\"5EWKzomnbVvLKWjHeVqm2BMqMzmckKMiufR11qFXahaUfenR\",\"5FTyuyEQQZs8tCcPTUFqotkm2SYfDnpefn9FitRgmTHnFDBD\",\"5GGboHkKougeE8PqGRbNM32AEwRU7Dsv4MXATm2zukQJ8wrU\",\"5FJAjL6d31QDSfvcZPKkde9ftTLAPu7J5Mo86je5XbziRXSB\"]}"

# agent-challenge own_runner eval allowlist: the worker+api gate the broker DooD
# job image against CHALLENGE_DOCKER_ALLOWED_IMAGES (the default permits only the
# :latest runner). Cover the DEPLOYED runner tag via a ``:*`` glob so a non-:latest
# runner (e.g. the live :own-runner-fixed tag) is allowed; else the eval job fails
# "Docker image is not allowed". AGENT_CHALLENGE_RUNNER_IMAGE is the own_runner job
# image (CHALLENGE_HARBOR_RUNNER_IMAGE) — pin the operator's tag at deploy time.
AGENT_CHALLENGE_RUNNER_IMAGE="${AGENT_CHALLENGE_RUNNER_IMAGE:-ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner:latest}"
CHALLENGE_DOCKER_ALLOWED_IMAGES="${CHALLENGE_DOCKER_ALLOWED_IMAGES:-[\"baseintelligence/swe-forge:*\",\"ghcr.io/baseintelligence/agent-challenge-analyzer:*\",\"ghcr.io/baseintelligence/terminal-bench-harbor-runner:*\",\"ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner:*\"]}"

# Per-call extra env / command override consumed by _deploy_challenge_service
# (reset after each deploy). Declared here so `set -u` never trips on `${#..[@]}`.
CHALLENGE_ENV=()
CHALLENGE_CMD=()
# Per-call extra `--mount` specs consumed by _deploy_challenge_service (e.g. the prism scorer's
# read-only SECRET held-out val volume). Reset after each deploy. Declared here so `set -u`
# never trips on `${#..[@]}`.
CHALLENGE_EXTRA_MOUNTS=()
# Per-call extra `--secret` specs (verbatim `source=...,target=...`) consumed by
# _deploy_challenge_service. Unlike the positional SECRET_SPEC args (which mount under the
# ${SECRET_MOUNT_DIR}/ "base/" subdir), these are passed through UNMODIFIED so a secret can
# be mounted at an exact target the consumer reads from. Used for the prism OpenRouter key, which
# prism reads from /run/secrets/openrouter_api_key (config.py openrouter_api_key_file default),
# i.e. target basename `openrouter_api_key` with NO `base/` prefix. Reset after each deploy.
CHALLENGE_EXTRA_SECRETS=()

# ============================================================================
# Flags (all default to the SAFE / non-mutating / non-destructive value).
# ============================================================================
APPLY=false               # false => dry-run (print only). Mutating requires --apply.
FORCE=false               # allow proceeding even if node already in a swarm.
RESTART_DOCKERD=false      # opt-in: write daemon.json + restart dockerd (DESTRUCTIVE).
SINGLE_NODE_PLACEMENT=false # opt-in: non-default placement override (see REVIEW).
STATIC_CHALLENGES=false    # opt-in: create challenge services directly here.
# Greenfield (no-restore) bring-up. When false (DEFAULT) the behavior is exactly
# as before: preflight HARD-requires the k3s cutover dumps and restore_data loads
# them. When true the script is a fresh-install path — it SKIPS the backup-dump
# preflight requirement AND SKIPS restore_data, so the empty postgres volumes
# initialize via the services' own normal migrations/bootstrap. Required because
# the operator moved off k3s to Swarm, so the k3s dumps will NOT exist at deploy.
GREENFIELD=false           # opt-in: skip backup-dump preflight + restore_data (fresh DBs).

# ============================================================================
# Output helpers
# ============================================================================
log()  { printf '[install-swarm] %s\n' "$*"; }
warn() { printf '[install-swarm][WARN] %s\n' "$*" >&2; }
die()  { printf '[install-swarm][FATAL] %s\n' "$*" >&2; exit 1; }

# `plan CMD...` is the single execution gate.
#   * dry-run (default): print the command, run nothing.
#   * --apply: print, then execute exactly that argv.
# Secret VALUES must never be passed through `plan` as argv — use
# `plan_secret_stdin` for those.
plan() {
  printf '  + %s\n' "$(_quote_argv "$@")"
  if [[ "${APPLY}" == "true" ]]; then
    "$@"
  fi
}

# Render an argv as a copy-pasteable, shell-quoted string for the plan log.
_quote_argv() {
  local out="" arg
  for arg in "$@"; do
    out+="$(printf '%q ' "$arg")"
  done
  printf '%s' "${out% }"
}

# `plan_secret_stdin NAME ENVVAR -- CMD...` runs CMD with the value of $ENVVAR
# fed on stdin. The value is NEVER printed and NEVER placed on argv. In dry-run
# the command is printed with a `<value from $ENVVAR>` placeholder.
plan_secret_stdin() {
  local label="$1" envvar="$2"
  shift 2
  [[ "$1" == "--" ]] || die "plan_secret_stdin: expected -- separator"
  shift
  printf '  + %s   # stdin: value from $%s (hidden)\n' "$(_quote_argv "$@")" "${envvar}"
  if [[ "${APPLY}" == "true" ]]; then
    printf '%s' "${!envvar}" | "$@"
  fi
  : "${label}"  # label is documentation only
}

# ============================================================================
# Argument parsing
# ============================================================================
usage() {
  cat <<'EOF'
Usage: install-swarm.sh [OPTIONS]

Single-node Docker Swarm bring-up of the BASE master + challenges.
DEFAULT MODE IS DRY-RUN (prints planned actions, changes nothing).

Safety flags:
  --apply                 Execute mutating commands. Without this, dry-run only.
  --force                 Proceed even if this node is already a Swarm node.

Opt-in DESTRUCTIVE / non-default steps (each separate, NOT in default --apply):
  --restart-dockerd       Install daemon.validator.json and restart dockerd.
  --single-node-placement Apply the non-default single-node placement override
                          (see the REVIEW block in single_node_placement_fix()).
  --static-challenges     Create challenge services directly instead of letting
                          the master orchestrator create them dynamically.

Bring-up mode:
  --greenfield            Fresh install with NO k3s restore: skip the backup-dump
                          preflight requirement AND skip restore_data, letting the
                          empty postgres volumes initialize via the services' own
                          normal migrations/bootstrap. Without this flag the dumps
                          in --backup-dir are REQUIRED and restored (default).

Configuration:
  --advertise-addr IP     Swarm advertise address (default: 51.83.112.164).
  --backup-dir DIR        pg_dump + baseline dir (default: /root/cutover-backups/LATEST).
  --master-config PATH    Rendered master config path (default: /etc/base/master.yaml).
  -h, --help              Show this help.

Required environment (values NEVER hardcoded; supplied at runtime):
  GHCR_USER, GHCR_TOKEN                      GHCR login for private images.
  BASE_ADMIN_TOKEN                       master admin token.
  AGENT_CHALLENGE_CHALLENGE_TOKEN            agent-challenge challenge token.
  AGENT_CHALLENGE_DOCKER_BROKER_TOKEN        agent-challenge broker token.
  AGENT_CHALLENGE_SUBMISSION_ENV_KEY         agent-challenge submission_env_encryption_key.
  PRISM_CHALLENGE_TOKEN                      prism challenge token.
  PRISM_DOCKER_BROKER_TOKEN                  prism broker token.
  OPENROUTER_API_KEY                         openrouter_api_key.
  MASTER_PG_PASSWORD                         base postgres password.
  AGENT_CHALLENGE_PG_PASSWORD                agent-challenge postgres password.
  PRISM_PG_PASSWORD                          prism postgres password.
  MASTER_DATABASE_URL                        master control-plane DB URL.
  AGENT_CHALLENGE_DATABASE_URL               agent-challenge DB URL.
  PRISM_DATABASE_URL                         prism DB URL.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=true ;;
      --dry-run) APPLY=false ;;
      --force) FORCE=true ;;
      --restart-dockerd) RESTART_DOCKERD=true ;;
      --single-node-placement) SINGLE_NODE_PLACEMENT=true ;;
      --static-challenges) STATIC_CHALLENGES=true ;;
      --greenfield) GREENFIELD=true ;;
      --advertise-addr) ADVERTISE_ADDR="${2:?--advertise-addr needs a value}"; shift ;;
      --backup-dir) BACKUP_DIR="${2:?--backup-dir needs a value}"; shift ;;
      --master-config) MASTER_CONFIG_PATH="${2:?--master-config needs a value}"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
  done
}

# ============================================================================
# 1. preflight()
#    Verify docker >= MIN_DOCKER_MAJOR, NOT already in a swarm (unless --force),
#    backup dir + dump files exist, GHCR_USER/GHCR_TOKEN present. Read-only.
# ============================================================================
preflight() {
  log "STEP 1/12 preflight: validating host + inputs (read-only)"

  command -v docker >/dev/null 2>&1 || die "docker CLI not found on PATH"

  local docker_version major
  docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  [[ -n "${docker_version}" ]] || die "could not query docker server version (is dockerd running?)"
  major="${docker_version%%.*}"
  if [[ ! "${major}" =~ ^[0-9]+$ ]] || (( major < MIN_DOCKER_MAJOR )); then
    die "docker >= ${MIN_DOCKER_MAJOR} required, found ${docker_version}"
  fi
  log "  docker server version ${docker_version} (>= ${MIN_DOCKER_MAJOR}) OK"

  # Already-in-swarm check.
  local swarm_state
  swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unknown)"
  if [[ "${swarm_state}" == "active" ]]; then
    if [[ "${FORCE}" == "true" ]]; then
      warn "node already in a swarm (state=active) — continuing because --force"
    else
      die "node already in a swarm (state=active); re-run with --force to proceed"
    fi
  else
    log "  swarm state '${swarm_state}' OK"
  fi

  # Backup dir + dump files. In --greenfield this requirement is SKIPPED: there
  # are no k3s dumps to restore, so the empty DBs bootstrap via migrations.
  if [[ "${GREENFIELD}" == "true" ]]; then
    log "  --greenfield set: SKIPPING backup-dump preflight (fresh DBs via migrations/bootstrap)"
  else
    [[ -d "${BACKUP_DIR}" ]] || die "backup dir not found: ${BACKUP_DIR}"
    local dump
    for dump in base.sql agent-challenge.sql prism.sql; do
      [[ -f "${BACKUP_DIR}/${dump}" ]] || die "missing dump file: ${BACKUP_DIR}/${dump}"
    done
    log "  backup dumps present in ${BACKUP_DIR} OK (prism.sql may be empty — expected)"
  fi

  # GHCR credentials must be present (values never printed).
  [[ -n "${GHCR_USER:-}" ]] || die "GHCR_USER not set (required for ghcr.io login)"
  [[ -n "${GHCR_TOKEN:-}" ]] || die "GHCR_TOKEN not set (required for ghcr.io login)"
  log "  GHCR_USER / GHCR_TOKEN present OK"

  log "preflight complete"
}

# ============================================================================
# ghcr_login()
#   Private images require `docker login ghcr.io` first. Credentials come from
#   GHCR_USER / GHCR_TOKEN; the token is fed on stdin (never argv, never logged).
# ============================================================================
ghcr_login() {
  log "STEP 1b ghcr_login: authenticating to ghcr.io (token via stdin, hidden)"
  plan_secret_stdin "ghcr-login" GHCR_TOKEN -- \
    docker login ghcr.io --username "${GHCR_USER}" --password-stdin
}

# ============================================================================
# 2. apply_daemon_json()  [DESTRUCTIVE — behind --restart-dockerd]
#    Copy daemon.validator.json to /etc/docker/daemon.json and (only if
#    --restart-dockerd) restart dockerd. Otherwise print the instruction only.
# ============================================================================
apply_daemon_json() {
  log "STEP 2/12 apply_daemon_json"
  [[ -f "${DAEMON_JSON_SRC}" ]] || die "daemon template not found: ${DAEMON_JSON_SRC}"

  if [[ "${RESTART_DOCKERD}" != "true" ]]; then
    log "  --restart-dockerd NOT set: skipping daemon.json install + dockerd restart."
    log "  To apply manually (DESTRUCTIVE — restarts the engine):"
    log "    1) cp ${DAEMON_JSON_SRC} ${DAEMON_JSON_DST}   # merge, do not clobber existing keys"
    log "    2) dockerd --validate --config-file ${DAEMON_JSON_DST}   # must print 'configuration OK'"
    log "    3) systemctl restart docker"
    return 0
  fi

  warn "DESTRUCTIVE: --restart-dockerd set — installing daemon.json and restarting dockerd"
  # Keep a timestamped backup of any existing daemon.json before overwriting.
  if [[ -f "${DAEMON_JSON_DST}" ]]; then
    plan cp -a "${DAEMON_JSON_DST}" "${DAEMON_JSON_DST}.bak.$(date +%Y%m%d%H%M%S)"
  fi
  plan install -m 0644 "${DAEMON_JSON_SRC}" "${DAEMON_JSON_DST}"
  # Validate the candidate config before any restart (Docker >= 23).
  plan dockerd --validate --config-file "${DAEMON_JSON_DST}"
  plan systemctl restart docker
  log "  daemon.json installed and dockerd restarted"
}

# ============================================================================
# 3. swarm_init()
#    `docker swarm init --advertise-addr <ADVERTISE_ADDR>`. Idempotent: skip if
#    the node is already an active swarm manager.
# ============================================================================
swarm_init() {
  log "STEP 3/12 swarm_init (advertise-addr=${ADVERTISE_ADDR})"
  local swarm_state
  swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unknown)"
  if [[ "${swarm_state}" == "active" ]]; then
    log "  swarm already active — skipping init (idempotent)"
    return 0
  fi
  plan docker swarm init --advertise-addr "${ADVERTISE_ADDR}"
}

# ============================================================================
# 4. single_node_placement_fix()
#
#    # REVIEW: single-node placement override — non-default, see Atlas notes
#
#    THE PROBLEM
#    -----------
#    Every Swarm workload defaults to the placement constraint
#    `node.role==worker`:
#        src/base/master/swarm_backend.py:86
#            DEFAULT_PLACEMENT_CONSTRAINT = "node.role==worker"
#    and that default is the value used for BOTH workload paths:
#        * broker jobs   : SwarmBrokerConfig.placement_constraint
#                          (swarm_backend.py:305, applied at :388)
#        * challenge svcs: SwarmChallengeOrchestrator(placement_constraint=...)
#                          (swarm_backend.py:698, applied at :712 and :927)
#    A single-node Swarm has ONLY a manager node. `node.role==worker` therefore
#    matches NOTHING, so every challenge/broker task sits Pending forever (this
#    exact behavior is documented as live QA evidence in the migration
#    learnings: "Single-manager swarm + node.role==worker constraint -> task
#    stays Pending ... forever").
#
#    THE FIX — TWO OPTIONS (option (a) is PREFERRED)
#    -----------------------------------------------
#    (a) PREFERRED: set the placement constraint to empty/None for single-node.
#        The exact config key is `placement_constraint` on the Swarm classes:
#            - SwarmBrokerConfig.placement_constraint  (swarm_backend.py:305)
#            - SwarmChallengeOrchestrator(placement_constraint=...) (swarm_backend.py:698)
#        Its own docstring (swarm_backend.py:299-302) states:
#            "placement_constraint=None disables the constraint flag entirely
#             and exists ONLY for single-node test/QA swarms".
#        Setting it to None makes build_service_create_argv() emit NO
#        `--constraint` flag (swarm_backend.py:228-229), so tasks schedule on
#        the manager.
#
#        *** IMPORTANT CAVEAT (verified against this repo) ***
#        There is currently NO master.yaml / settings.py key that maps to
#        `placement_constraint`. The factory that builds the orchestrator,
#            src/base/orchestration/factory.py:109-119
#        constructs `SwarmChallengeOrchestrator(network_name=..., internal_network=...,
#        docker_broker_url=...)` and does NOT pass placement_constraint, so it
#        always falls back to DEFAULT_PLACEMENT_CONSTRAINT. Likewise the broker
#        (`base master broker`) builds SwarmBrokerConfig with the default.
#        => A pure-CONFIG single-node override is NOT possible today; it needs
#           EITHER a one-line code change in factory.py (pass
#           placement_constraint=None when single-node) and the broker builder,
#           OR the --static-challenges path below which issues `docker service
#           create` directly WITHOUT any `--constraint` flag.
#        This function therefore only DOCUMENTS the preferred config seam and,
#        when --static-challenges is used, deploy_challenges() relies on the
#        no-constraint direct path. The code change itself is intentionally NOT
#        made here (this script must not modify repo source).
#
#    (b) FALLBACK: relabel the manager as role=worker.
#        NOT POSSIBLE. Swarm `node.role` is intrinsic (manager|worker) and
#        cannot be set to `worker` on a manager node via `docker node update`
#        (only `--availability` and `--label-add` custom labels are mutable;
#        the built-in `role` is promote/demote only and a single-node swarm
#        cannot demote its sole manager). So there is no way to make
#        `node.role==worker` match the manager. Documented for completeness.
# ============================================================================
single_node_placement_fix() {
  log "STEP 4/12 single_node_placement_fix"
  if [[ "${SINGLE_NODE_PLACEMENT}" != "true" ]]; then
    log "  --single-node-placement NOT set: leaving default placement (node.role==worker)."
    log "  NOTE: with the default, master-orchestrated challenge tasks will stay Pending"
    log "        on a single-node swarm. Use --single-node-placement AND/OR"
    log "        --static-challenges. See the REVIEW block in this function."
    return 0
  fi

  # REVIEW: single-node placement override — non-default, see Atlas notes
  warn "REVIEW: single-node placement override requested (non-default)."
  log "  Preferred config seam (NO master.yaml key exists today — see comments):"
  log "    swarm_backend.py:305  SwarmBrokerConfig.placement_constraint = None"
  log "    swarm_backend.py:698  SwarmChallengeOrchestrator(placement_constraint=None)"
  log "    factory.py:109-119    does NOT pass placement_constraint -> code change needed,"
  log "                          or use --static-challenges (no --constraint emitted)."
  log "  Fallback (relabel manager role=worker): NOT POSSIBLE — node.role is intrinsic."
  log "  No mutating action taken here; this step is documentation/guard only."
}

# ============================================================================
# 5. create_networks()
#    Encrypted, attachable overlay networks at MTU 1450. Names MUST match the
#    swarm_backend constants (base_challenges, base_jobs_internal).
#    base_jobs_internal is created --internal (no external routes), mirroring
#    swarm_backend's `none`-network substitution.
# ============================================================================
create_networks() {
  log "STEP 5/12 create_networks"
  _create_overlay "${NET_CHALLENGES}" false
  _create_overlay "${NET_JOBS_INTERNAL}" true
}

# _create_overlay NAME INTERNAL(bool) — idempotent overlay create.
_create_overlay() {
  local name="$1" internal="$2"
  if docker network inspect "${name}" >/dev/null 2>&1; then
    log "  network ${name} already exists — skipping (idempotent)"
    return 0
  fi
  local -a argv=(
    docker network create
    --driver overlay
    --attachable
    --opt encrypted
    --opt "com.docker.network.driver.mtu=${OVERLAY_MTU}"
  )
  [[ "${internal}" == "true" ]] && argv+=(--internal)
  argv+=("${name}")
  plan "${argv[@]}"
}

# ============================================================================
# 6. create_secrets()
#    `docker secret create` for each secret. Values come from env vars and are
#    fed via stdin only (never argv, never logged). Names match the secret
#    names the master orchestrator expects.
#
#    NAMING NOTE: SwarmChallengeOrchestrator creates/refreshes its OWN per-slug
#    value-bearing secrets named `base_<safe_slug>_<name>` at challenge
#    start (swarm_backend.py:996-1006, _ensure_secrets). The secrets created
#    here are the ones the master/broker/postgres services consume directly and
#    any `external_secrets` the orchestrator only REFERENCES. We name them with
#    the same `base_<slug>_<name>` convention so a master-orchestrated
#    start can reference them without recreating. Review against the
#    orchestrator's expected secret names before apply.
# ============================================================================
create_secrets() {
  log "STEP 6/12 create_secrets (values via stdin, hidden)"

  # name                                env var                              required?
  _ensure_secret "base_admin_token"                       BASE_ADMIN_TOKEN
  _ensure_secret "base_master_database_url"               MASTER_DATABASE_URL
  _ensure_secret "base_master_pg_password"                MASTER_PG_PASSWORD

  _ensure_secret "base_agent_challenge_challenge_token"   AGENT_CHALLENGE_CHALLENGE_TOKEN
  _ensure_secret "base_agent_challenge_docker_broker_token" AGENT_CHALLENGE_DOCKER_BROKER_TOKEN
  _ensure_secret "base_agent_challenge_submission_env_encryption_key" AGENT_CHALLENGE_SUBMISSION_ENV_KEY
  _ensure_secret "base_agent_challenge_database_url"      AGENT_CHALLENGE_DATABASE_URL
  _ensure_secret "base_agent_challenge_pg_password"       AGENT_CHALLENGE_PG_PASSWORD

  _ensure_secret "base_prism_challenge_token"             PRISM_CHALLENGE_TOKEN
  _ensure_secret "base_prism_docker_broker_token"         PRISM_DOCKER_BROKER_TOKEN
  _ensure_secret "base_prism_database_url"                PRISM_DATABASE_URL
  _ensure_secret "base_prism_pg_password"                 PRISM_PG_PASSWORD

  # openrouter_api_key is shared (used by challenge eval). Named generically.
  _ensure_secret "base_openrouter_api_key"                OPENROUTER_API_KEY
}

# _ensure_secret NAME ENVVAR — idempotent secret create from $ENVVAR (stdin).
# A missing/empty env var is a hard error (we never invent secret material).
_ensure_secret() {
  local name="$1" envvar="$2"
  if [[ -z "${!envvar:-}" ]]; then
    die "required secret env var \$${envvar} is empty (for docker secret '${name}')"
  fi
  if docker secret inspect "${name}" >/dev/null 2>&1; then
    log "  secret ${name} already exists — skipping (idempotent; rotate out-of-band)"
    return 0
  fi
  plan_secret_stdin "${name}" "${envvar}" -- docker secret create "${name}" -
}

# ============================================================================
# 7. deploy_postgres()
#    Three postgres:16-alpine services with named volumes. POSTGRES_DB/USER are
#    literals (db/user from LIVE INVENTORY); POSTGRES_PASSWORD comes from a
#    docker secret via POSTGRES_PASSWORD_FILE (never an env literal).
#      base-master-postgres        : db=base  user=base
#      challenge-agent-challenge-postgres: db=challenge user=challenge
#      challenge-prism-postgres         : db=challenge user=challenge
#    All postgres services are internal (no published host port); reached over
#    the base_challenges overlay by DNS.
# ============================================================================
deploy_postgres() {
  log "STEP 7/12 deploy_postgres"
  _deploy_postgres_service "base-master-postgres" "${VOL_MASTER_PG}" \
    "base" "base" "base_master_pg_password"
  _deploy_postgres_service "challenge-agent-challenge-postgres" "${VOL_AGENT_CHALLENGE_PG}" \
    "challenge" "challenge" "base_agent_challenge_pg_password"
  _deploy_postgres_service "challenge-prism-postgres" "${VOL_PRISM_PG}" \
    "challenge" "challenge" "base_prism_pg_password"
}

# _deploy_postgres_service NAME VOLUME DB USER PW_SECRET
_deploy_postgres_service() {
  local name="$1" volume="$2" db="$3" user="$4" pw_secret="$5"
  if docker service inspect "${name}" >/dev/null 2>&1; then
    log "  service ${name} already exists — skipping (idempotent)"
    return 0
  fi
  plan docker service create \
    --name "${name}" \
    --network "${NET_CHALLENGES}" \
    --replicas 1 \
    --restart-condition any \
    --hostname "${name}" \
    --mount "type=volume,source=${volume},destination=/var/lib/postgresql/data" \
    --secret "source=${pw_secret},target=postgres_password" \
    --env "POSTGRES_DB=${db}" \
    --env "POSTGRES_USER=${user}" \
    --env "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password" \
    --env "PGDATA=/var/lib/postgresql/data/pgdata" \
    "${IMAGE_POSTGRES}"
}

# ============================================================================
# 8. restore_data()
#    Wait for each postgres to accept connections, restore the matching dump,
#    then compare pg_stat_user_tables row counts against the saved baseline
#    (rowcounts-*.txt). FAIL LOUDLY on mismatch. prism.sql is expected empty.
# ============================================================================
restore_data() {
  log "STEP 8/12 restore_data"
  if [[ "${APPLY}" != "true" ]]; then
    log "  (dry-run) would: wait-healthy -> psql restore -> verify row counts for:"
    log "    base-master-postgres        <- ${BACKUP_DIR}/base.sql       (db=base)"
    log "    challenge-agent-challenge-postgres <- ${BACKUP_DIR}/agent-challenge.sql (db=challenge)"
    log "    challenge-prism-postgres        <- ${BACKUP_DIR}/prism.sql          (db=challenge, may be empty)"
    return 0
  fi

  _restore_one "base-master-postgres"        "base"  "base"  "${BACKUP_DIR}/base.sql"        "${BACKUP_DIR}/rowcounts-base.txt"
  _restore_one "challenge-agent-challenge-postgres" "challenge" "challenge" "${BACKUP_DIR}/agent-challenge.sql" "${BACKUP_DIR}/rowcounts-agent-challenge.txt"
  _restore_one "challenge-prism-postgres"         "challenge" "challenge" "${BACKUP_DIR}/prism.sql"           "${BACKUP_DIR}/rowcounts-prism.txt"
}

# _restore_one SERVICE DB USER DUMP BASELINE
_restore_one() {
  local service="$1" db="$2" user="$3" dump="$4" baseline="$5"
  log "  restoring ${service} (db=${db}) from ${dump}"

  local cid
  cid="$(_pg_wait_ready "${service}" "${user}" "${db}")" \
    || die "postgres ${service} did not become ready"

  # prism.sql is expected empty — skip the psql load but still verify (=0 rows).
  if [[ -s "${dump}" ]]; then
    docker exec -i "${cid}" psql -v ON_ERROR_STOP=1 -U "${user}" -d "${db}" <"${dump}" \
      || die "restore failed for ${service}"
  else
    warn "  ${dump} is empty — skipping load (expected for prism)"
  fi

  _verify_rowcounts "${cid}" "${user}" "${db}" "${baseline}" "${service}"
}

# _pg_wait_ready SERVICE USER DB -> echoes the resolved container id on success.
_pg_wait_ready() {
  local service="$1" user="$2" db="$3"
  local cid
  for _ in $(seq 1 60); do
    cid="$(docker ps -q -f "name=${service}" | head -n1)"
    if [[ -n "${cid}" ]] && docker exec "${cid}" pg_isready -U "${user}" -d "${db}" >/dev/null 2>&1; then
      printf '%s' "${cid}"
      return 0
    fi
    sleep 5
  done
  return 1
}

# _verify_rowcounts CID USER DB BASELINE SERVICE
# Baseline format expected (one per line): "<schema.table> <count>".
_verify_rowcounts() {
  local cid="$1" user="$2" db="$3" baseline="$4" service="$5"
  if [[ ! -f "${baseline}" ]]; then
    warn "  no baseline file ${baseline} — skipping row-count verification for ${service}"
    return 0
  fi
  log "  verifying row counts for ${service} against ${baseline}"

  # Live counts from pg_stat_user_tables: "<schema.relname> <n_live_tup>".
  local live
  live="$(docker exec -i "${cid}" psql -At -F' ' -U "${user}" -d "${db}" -c \
    "SELECT schemaname||'.'||relname, n_live_tup FROM pg_stat_user_tables ORDER BY 1;")" \
    || die "row-count query failed for ${service}"

  local mismatches=0 table want got line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    table="${line%% *}"
    want="${line##* }"
    got="$(printf '%s\n' "${live}" | awk -v t="${table}" '$1==t {print $2; found=1} END{if(!found) print "MISSING"}')"
    if [[ "${got}" != "${want}" ]]; then
      warn "  ROW COUNT MISMATCH ${service} ${table}: baseline=${want} live=${got}"
      mismatches=$((mismatches + 1))
    fi
  done <"${baseline}"

  if (( mismatches > 0 )); then
    die "row-count verification FAILED for ${service}: ${mismatches} mismatch(es)"
  fi
  log "  row counts verified OK for ${service}"
}

# ============================================================================
# 9. deploy_master()
#    Render /etc/base/master.yaml (backend=docker, single-node values) then
#    deploy broker/proxy services from the base-master image with the
#    config + secrets mounted and ports published.
#
#    Service name <-> command <-> port:
#      base-master-broker : `base master broker` : 18082 (docker.broker_*)
#      base-master-proxy  : `base master proxy`  : 18080 (proxy_host:proxy_port)
#    The proxy is the SINGLE public API: it serves /v1/registry, /v1/weights/latest,
#    /health, the admin/management routes (token-gated), the signed upload bridge,
#    and the /challenges/* passthrough, AND it runs the orchestrator that creates
#    challenges dynamically (the separate `base master run` admin service on
#    18900 is removed).
#    The broker service MUST be named base-master-broker so the configured
#    broker_url (http://base-master-broker:18082) resolves over the overlay.
# ============================================================================
deploy_master() {
  log "STEP 9/12 deploy_master"
  _render_master_config
  _ensure_master_config_secret
  _seed_proxy_challenge_tokens  # proxy bearer-token files in the shared secrets volume

  # broker — challenge workload broker (frozen contract / Swarm backend).
  _deploy_master_service "base-master-broker" "broker" "${MASTER_BROKER_PORT}" "${MASTER_BROKER_PORT}"
  # proxy — public single API (registry/weights/health + admin + upload bridge +
  # /challenges/* passthrough) and the orchestrator that creates challenges.
  _deploy_master_service "base-master-proxy" "proxy" "${MASTER_PROXY_PORT}" "${MASTER_PROXY_PORT}"
}

# Render the single-node master config to MASTER_CONFIG_PATH. NO secrets inline:
# the DB URL / admin token are mounted as docker secrets/files at runtime.
_render_master_config() {
  log "  rendering master config -> ${MASTER_CONFIG_PATH}"
  # The config is written to a local staging file; in --apply it is also turned
  # into a docker config/secret object below. Render is non-secret, so we always
  # write the staging file (it documents the intended config for the reviewer).
  local staging="${MASTER_CONFIG_PATH}"
  local tmp
  tmp="$(mktemp)"
  cat >"${tmp}" <<EOF
# Rendered by deploy/swarm/install-swarm.sh (single-node Swarm bring-up).
# backend=docker; kubernetes.broker_backend=docker (override live k8s values).
network:
  name: base
  netuid: 100
  chain_endpoint: ''          # empty in prod (no live chain) — keep empty.
  wallet_name: default
  wallet_hotkey: default
  wallet_path: /var/lib/base/wallets
  master_uid: 0

master:
  proxy_host: 0.0.0.0
  proxy_port: ${MASTER_PROXY_PORT}

database:
  # Loaded from the base_master_database_url docker secret at runtime;
  # this placeholder is overridden by the *_FILE indirection in deployment.
  url: postgresql+asyncpg://base@base-master-postgres:5432/base

runtime:
  backend: docker

kubernetes:
  broker_backend: docker

docker:
  network_name: ${NET_CHALLENGES}
  secret_dir: ${SECRET_VOLUME_DIR}
  internal_network: true
  broker_host: 0.0.0.0
  broker_port: ${MASTER_BROKER_PORT}
  broker_url: http://base-master-broker:${MASTER_BROKER_PORT}
  broker_allowed_images:
    - ghcr.io/baseintelligence/
  allow_privileged: true
  broker_privileged_slugs:
    - agent-challenge
  # Non-privileged Docker-out-of-Docker: the agent-challenge own_runner eval job
  # is bind-mounted the host Docker socket (gated to this slug) so it can spawn
  # sibling task containers without --privileged (which Swarm services reject).
  broker_docker_socket_slugs:
    - agent-challenge
  # Read-only task cache + frozen digest manifest handed to the own_runner job
  # from named volumes provisioned out-of-band by
  # deploy/swarm/acquire-agent-challenge-cache.sh (source:target).
  broker_eval_readonly_mounts:
    - agent_challenge_task_cache:/opt/agent-challenge/task-cache
    - agent_challenge_golden:/opt/agent-challenge/golden

security:
  admin_token_file: ${SECRET_MOUNT_DIR}/admin_token

observability:
  log_json: true
EOF

  if [[ "${APPLY}" == "true" ]]; then
    install -D -m 0644 "${tmp}" "${staging}"
    rm -f "${tmp}"
    log "  wrote ${staging}"
  else
    log "  (dry-run) master config that WOULD be written to ${staging}:"
    sed 's/^/      /' "${tmp}"
    rm -f "${tmp}"
  fi
}

# Publish the rendered master.yaml as a docker config object so all three master
# services mount an identical file. Idempotent.
_ensure_master_config_secret() {
  local cfg_obj="base_master_yaml"
  if docker config inspect "${cfg_obj}" >/dev/null 2>&1; then
    log "  docker config ${cfg_obj} already exists — skipping (rotate out-of-band)"
    return 0
  fi
  if [[ "${APPLY}" == "true" ]]; then
    plan docker config create "${cfg_obj}" "${MASTER_CONFIG_PATH}"
  else
    log "  (dry-run) would: docker config create ${cfg_obj} ${MASTER_CONFIG_PATH}"
  fi
}

# Seed the proxy's per-challenge bearer-token files into the shared secrets
# volume. The proxy verifies a miner upload for slug <s> against the bearer token
# it reads from ${SECRET_VOLUME_DIR}/<s>_challenge_token (registry.get_token);
# that file MUST equal the challenge's base_<s>_challenge_token secret value
# or uploads 401 "invalid bearer token". Seed it for BOTH agent-challenge and
# prism from the same env vars used to create the docker secrets. Values flow on
# stdin only (never argv, never logged). The throwaway writer mounts the named
# volume directly so the file exists before the proxy task starts.
_seed_proxy_challenge_tokens() {
  log "  seeding proxy per-challenge bearer-token files into ${VOL_BASE_SECRETS}"
  _seed_challenge_token "agent-challenge" AGENT_CHALLENGE_CHALLENGE_TOKEN
  _seed_challenge_token "prism"           PRISM_CHALLENGE_TOKEN
}

# _seed_challenge_token SLUG ENVVAR — write $ENVVAR into the secrets volume at
# <slug>_challenge_token (mode 600, owner-only). Idempotent (overwrites in place).
#
# Ownership: the master image runs as uid 1000 (the proxy is uid 1000; only the
# broker is --user root), so the proxy reads these files AS uid 1000. The
# writer container runs as root (the default — required because a FRESH
# vol_base_secrets volume root is owned root:root 0755, so a --user 1000:1000
# writer could not create the file), then chowns the file to 1000:1000 keeping
# mode 600. A root-owned 600 file would be UNREADABLE by the proxy on a
# fresh volume (-> 500 "Challenge token file is missing" / 401 "invalid bearer
# token").
_seed_challenge_token() {
  local slug="$1" envvar="$2"
  if [[ -z "${!envvar:-}" ]]; then
    die "required token env var \$${envvar} is empty (proxy seed for slug '${slug}')"
  fi
  local target="${slug}_challenge_token"
  plan_secret_stdin "proxy-token-${slug}" "${envvar}" -- \
    docker run --rm -i \
      --mount "type=volume,source=${VOL_BASE_SECRETS},destination=/secrets" \
      "${IMAGE_POSTGRES}" \
      sh -c "umask 077 && cat > /secrets/${target} && chmod 600 /secrets/${target} && chown 1000:1000 /secrets/${target}"
}

# _deploy_master_service NAME SUBCOMMAND HOST_PORT CONTAINER_PORT
_deploy_master_service() {
  local name="$1" subcommand="$2" host_port="$3" container_port="$4"
  if docker service inspect "${name}" >/dev/null 2>&1; then
    log "  service ${name} already exists — skipping (idempotent)"
    return 0
  fi

  # Common extras for ALL master services:
  #   * shared secrets volume at the master secret_dir (/var/lib/base/secrets):
  #     broker/proxy read per-challenge tokens from here. The PROXY needs
  #     it to load each challenge's bearer token when verifying miner uploads (else
  #     500 "Challenge token file is missing"). Seeded by _seed_proxy_challenge_tokens.
  #   * --update-order stop-first: these are FIXED host-port services (18082/18080,
  #     mode=host); the default start-first ordering causes a transient port collision
  #     (EADDRINUSE) on update. stop-first releases the port before the new task binds.
  local -a extra=(
    --mount "type=volume,source=${VOL_BASE_SECRETS},destination=${SECRET_VOLUME_DIR}"
    --update-order stop-first
  )

  # Broker-only extras (regression guards — do NOT strip these flags):
  #   1. host docker socket: the escape hatch shells out to `docker run` on the
  #      host daemon.
  #   2. workspace bind at the SAME host+container path: the agent tar is
  #      materialized here then mounted via `-v <path>:/workspace/agent` resolved
  #      on the HOST fs; container-private /tmp -> empty mount -> "No module named
  #      'agent'".
  #   3. user=root: DinD writes outputs as root; the broker must rmtree them on
  #      TemporaryDirectory exit or cleanup raises EPERM -> HTTP 500.
  if [[ "${subcommand}" == "broker" ]]; then
    local broker_ws="${BROKER_WORKSPACE_DIR:-/tmp/base-docker-broker}"
    mkdir -p "${broker_ws}"
    extra+=(
      --user root
      --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"
      --mount "type=bind,source=${broker_ws},target=${broker_ws}"
      # MANAGER PIN (required on any multi-node swarm): the broker shells out to
      # `docker service create` to dispatch eval jobs, which REQUIRES a manager's
      # docker.sock; it also binds the manager-local docker.sock + ${broker_ws}
      # workspace and publishes the fixed host port 18082. With no constraint an
      # update (stop-first) can reschedule the broker onto a joined worker (e.g.
      # the GPU node), where it breaks: the manager-only docker API is absent, the
      # local-only image is "No such image", and the workspace bind source does
      # not exist. node.role is intrinsic, so this also matches the sole manager on
      # a single-node swarm (no-op there). Canonicalizes the live M2/M3 pin
      # (verified on base-master-broker; see library/environment.md). Do NOT
      # use --constraint-add on an already-pinned live service (not idempotent —
      # see AGENTS.md "CONSTRAINT-ADD DEDUP GOTCHA").
      --constraint "node.role==manager"
    )
  fi

  # Proxy-only: upload allowlist so the MinerUploadVerifier accepts the miner +
  # owner (+ spare validator) hotkeys without on-chain registration.
  if [[ "${subcommand}" == "proxy" ]]; then
    extra+=(
      --env "BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS=${UPLOAD_EXTRA_REGISTERED_HOTKEYS}"
    )
  fi

  plan docker service create \
    --name "${name}" \
    --network "${NET_CHALLENGES}" \
    --replicas 1 \
    --restart-condition any \
    --hostname "${name}" \
    --publish "published=${host_port},target=${container_port},mode=host" \
    --config "source=base_master_yaml,target=${MASTER_CONFIG_PATH}" \
    --secret "source=base_admin_token,target=admin_token" \
    --secret "source=base_master_database_url,target=master_database_url" \
    --env "BASE_CONFIG=${MASTER_CONFIG_PATH}" \
    "${extra[@]}" \
    "${IMAGE_MASTER}" \
    base master "${subcommand}" --config "${MASTER_CONFIG_PATH}"
}

# ============================================================================
# 10. deploy_challenges()
#     DEFAULT: do NOTHING here — the running master orchestrator (`base
#     master proxy`, deployed above) creates challenge services dynamically via
#     SwarmChallengeOrchestrator (this is the real-system behavior). Only when
#     --static-challenges is set do we create the challenge services directly,
#     for a static single-node bring-up.
#
#     The direct path issues `docker service create` WITHOUT any `--constraint`
#     flag, which is precisely the single-node placement workaround (option (a)
#     fallback from single_node_placement_fix): no constraint => schedules on
#     the manager.
# ============================================================================
deploy_challenges() {
  log "STEP 10/12 deploy_challenges"
  if [[ "${STATIC_CHALLENGES}" != "true" ]]; then
    log "  --static-challenges NOT set (DEFAULT): the master orchestrator will create"
    log "  challenge services dynamically. Nothing to do here."
    log "  (Reminder: master-orchestrated tasks need the single-node placement"
    log "   override to schedule on this single manager node — see STEP 4.)"
    return 0
  fi

  warn "creating challenge services DIRECTLY (--static-challenges); no --constraint emitted"

  # own_runner eval image allowlist + runner image, applied to BOTH the
  # agent-challenge api and the worker so the broker DooD job is permitted to run
  # the deployed (non-:latest) runner tag. Without it the eval job fails
  # "Docker image is not allowed: ...". See "Proxy submission-path requirements".
  local -a ac_eval_env=(
    "CHALLENGE_SLUG=agent-challenge"
    "CHALLENGE_HARBOR_RUNNER_IMAGE=${AGENT_CHALLENGE_RUNNER_IMAGE}"
    "CHALLENGE_DOCKER_ALLOWED_IMAGES=${CHALLENGE_DOCKER_ALLOWED_IMAGES}"
  )

  # agent-challenge primary API service (container port 8000). Overlay-internal —
  # reached over the overlay by the proxy/master; no host publish.
  CHALLENGE_ENV=("${ac_eval_env[@]}")
  _deploy_challenge_service \
    "challenge-agent-challenge" "${IMAGE_AGENT_CHALLENGE}" "${AGENT_CHALLENGE_PORT}" \
    "base_agent_challenge_pg" \
    "base_agent_challenge_challenge_token:challenge_token" \
    "base_agent_challenge_docker_broker_token:docker_broker_token" \
    "base_agent_challenge_submission_env_encryption_key:submission_env_encryption_key" \
    "base_openrouter_api_key:openrouter_api_key"

  # agent-challenge worker sidecar (command `agent-challenge-worker`; see
  # cli_app/main.py worker_command metadata). It runs the own_runner eval loop and
  # dispatches the broker DooD job, so it needs the SAME eval-image allowlist as
  # the api plus the broker backend wiring. (Resolves the prior worker TODO.)
  CHALLENGE_ENV=(
    "${ac_eval_env[@]}"
    "CHALLENGE_BENCHMARK_BACKEND=terminal_bench"
    "CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND=own_runner"
    "CHALLENGE_DOCKER_ENABLED=true"
    "CHALLENGE_DOCKER_BACKEND=broker"
    "CHALLENGE_DOCKER_BROKER_URL=http://base-master-broker:${MASTER_BROKER_PORT}"
    "CHALLENGE_DOCKER_BROKER_TOKEN_FILE=${SECRET_MOUNT_DIR}/docker_broker_token"
    "CHALLENGE_ARTIFACT_ROOT=/data"
  )
  CHALLENGE_CMD=("agent-challenge-worker" "--poll-interval" "5")
  _deploy_challenge_service \
    "challenge-agent-challenge-worker" "${IMAGE_AGENT_CHALLENGE}" "${AGENT_CHALLENGE_PORT}" \
    "base_agent_challenge_pg" \
    "base_agent_challenge_challenge_token:challenge_token" \
    "base_agent_challenge_docker_broker_token:docker_broker_token" \
    "base_agent_challenge_submission_env_encryption_key:submission_env_encryption_key" \
    "base_openrouter_api_key:openrouter_api_key"

  # PRISM service (container port 8080). Overlay-internal — reached over the overlay; no host publish.
  # Prism runtime config for the local E2E + weights dry-run slice (research prism
  # §5,§7,§10): broker dispatch (docker_backend=broker), an ACTIVE GPU lease
  # (base_eval_gpu_count=1), the cu128 evaluator image (allowlisted by both prism
  # and the broker), SQLite on /data, synthetic dataset (the in-container runner trains
  # on random tokens — no download), and the OpenRouter LLM HARD GATE ENABLED
  # (PRISM_LLM_REVIEW_ENABLED=true; model openai/gpt-4o by config default; key from the mounted
  # openrouter_api_key secret on the challenge service ONLY — never the eval container. This
  # script's create_secrets makes base_openrouter_api_key from $OPENROUTER_API_KEY and (via
  # CHALLENGE_EXTRA_SECRETS below) mounts it at /run/secrets/openrouter_api_key — the EXACT path
  # prism reads (config.py openrouter_api_key_file default), NOT the ${SECRET_MOUNT_DIR}/"base/"
  # subdir the other secrets use. This is the SAME mount target the LIVE stack uses for the
  # equivalent pre-existing base_or_key_real secret, so a FRESH install-swarm.sh bring-up wires
  # the LLM-review gate's key to the name/path prism actually consumes — no base_openrouter_api_key
  # vs base_or_key_real mismatch at the consuming path (the docker secret NAME differs only by
  # which key material the operator pre-provisioned; both resolve at /run/secrets/openrouter_api_key).
  # docker_backend already defaults to broker but is set
  # explicitly. The broker token file is the mounted base_prism_docker_broker_token
  # secret; it MUST equal the registry-written <secret_dir>/prism_docker_broker_token the
  # broker reads (registration writes it). prism's docker_allowed_images already permits
  # ghcr.io/baseintelligence/, so the eval image needs no override.
  #
  # Two LOCAL/DEV-ONLY allowances complete the E2E submission path (canonicalized
  # from the live M3 service — see library/environment.md + library/user-testing.md):
  #   * PRISM_ALLOW_INSECURE_SIGNATURES=true — the prism image lacks bittensor, so
  #     real sr25519 verification is impossible in-image; this enables the dev-HMAC
  #     fallback used by the E2E proof + negative cases (do NOT use in production).
  #   * PRISM_VALIDATOR_HOTKEYS — a non-empty JSON array so the validator
  #     self-submission 403 guard is reachable.
  CHALLENGE_ENV=(
    "CHALLENGE_SLUG=prism"
    "CHALLENGE_DOCKER_ENABLED=true"
    "CHALLENGE_DOCKER_BACKEND=broker"
    "CHALLENGE_DOCKER_BROKER_URL=http://base-master-broker:${MASTER_BROKER_PORT}"
    "CHALLENGE_DOCKER_BROKER_TOKEN_FILE=${SECRET_MOUNT_DIR}/docker_broker_token"
    "PRISM_BASE_EVAL_IMAGE=${IMAGE_PRISM_EVALUATOR}"
    "PRISM_BASE_EVAL_GPU_COUNT=1"
    "PRISM_DATABASE_URL=sqlite+aiosqlite:////data/prism.sqlite3"
    # OpenRouter LLM HARD GATE — ENABLED (architecture.md section 7; M5). The strong-model
    # review of both miner scripts is a hard gate that can REJECT before any GPU work. The key
    # is the mounted openrouter_api_key secret (challenge service ONLY, never the eval
    # container); model openai/gpt-4o + base https://openrouter.ai/api/v1 are config defaults.
    "PRISM_LLM_REVIEW_ENABLED=true"
    # Host-side held-out delta + converged anti-memorization gap (m3-heldout-delta /
    # m4-heldout-live-budget-tuning / m4-anticheat-memorization-heldout): the SECRET val split
    # and the non-secret TRAIN split must both be readable by the manager-pinned prism SCORER
    # process (NOT the network=none eval container). Mount each read-only (see
    # CHALLENGE_EXTRA_MOUNTS below) and point the scorer at them. The host reloads the
    # cross-node-returned trained_state.pt, runs the random-twin vs trained val bpb delta, and
    # (when TRAIN_DATA_DIR resolves) re-evaluates the converged train bpb so the memorization
    # gap uses the converged reference (gap_basis='converged') rather than the prequential
    # fallback. If val is absent or the eval exceeds its budget the held-out is gracefully
    # SKIPPED (the scored run never fails on held-out).
    "PRISM_BASE_EVAL_VAL_DATA_DIR=/secret/val"
    "PRISM_BASE_EVAL_TRAIN_DATA_DIR=/secret/train"
    # Bounded, deterministic held-out compute budget so the live delta COMPLETES rather than
    # skipping: a fixed 64 KiB val prefix (identical for twin + trained => comparable, byte-
    # denominator => tokenizer-agnostic) with a raised 600s timeout. These match the m5 image
    # config defaults; set explicitly so the live budget is auditable/self-documenting.
    "PRISM_BASE_EVAL_HELDOUT_VAL_BYTE_BUDGET=65536"
    "PRISM_BASE_EVAL_HELDOUT_TIMEOUT_SECONDS=600"
    # LOCAL/DEV ONLY — do NOT enable in production. The prism service image does
    # NOT bundle bittensor, so real sr25519 signature verification is impossible
    # in-image (verify_hotkey_signature import-fails -> False). This documented
    # allowance lets authenticate_miner fall back to the dev-HMAC path (canonical
    # msg `prism:{hotkey}:{nonce}:{ts}:{sha256hex(body)}` keyed by the 32-byte
    # challenge token) so the local E2E proof + negative cases can drive
    # POST /v1/submissions. Without it EVERY signed submission 401s.
    "PRISM_ALLOW_INSECURE_SIGNATURES=true"
    # Non-empty validator-hotkey list so the self-submission guard can fire: a
    # hotkey in this list submitting -> HTTP 403 "validator hotkey is not allowed
    # to submit". An empty default leaves the guard unreachable. MUST be a JSON
    # array (PrismSettings parses tuple fields as JSON via pydantic-settings).
    # Value = the dev self-submit sentinel used by the prism negative-case proof.
    "PRISM_VALIDATOR_HOTKEYS=[\"5PrismValidatorSelfSubmitDENY\"]"
  )
  # Host-side SCORER read-only mounts on the manager (NOT the eval container): the SECRET
  # held-out val split (matches PRISM_BASE_EVAL_VAL_DATA_DIR) and the non-secret TRAIN split
  # used ONLY for the converged-memorization-gap reference (matches PRISM_BASE_EVAL_TRAIN_DATA_DIR).
  # The val/test splits NEVER enter the network=none eval container; the eval container gets its
  # own copy of the locked TRAIN split via the broker's per-slug RO mount at /data/fineweb-edu/train.
  # Both are manager-local volumes, RO, and must be POPULATED + readable by the scorer uid 1000.
  CHALLENGE_EXTRA_MOUNTS=(
    "type=volume,source=prism_fineweb_edu_val,destination=/secret/val,readonly=true"
    "type=volume,source=prism_fineweb_edu_train,destination=/secret/train,readonly=true"
  )
  # OpenRouter LLM hard-gate key: mounted at the EXACT target prism reads
  # (/run/secrets/openrouter_api_key — config.py openrouter_api_key_file default), NOT the
  # ${SECRET_MOUNT_DIR}/"base/" subdir the positional SECRET_SPECs use. Passed verbatim via
  # CHALLENGE_EXTRA_SECRETS so the `base/` prefix is NOT applied. This matches the LIVE stack
  # (which mounts the pre-existing base_or_key_real at the same target) so the gate resolves
  # its key on a clean install-swarm.sh deploy.
  CHALLENGE_EXTRA_SECRETS=(
    "source=base_openrouter_api_key,target=openrouter_api_key"
  )
  _deploy_challenge_service \
    "challenge-prism" "${IMAGE_PRISM}" "${PRISM_PORT}" \
    "base_prism_pg" \
    "base_prism_challenge_token:challenge_token" \
    "base_prism_docker_broker_token:docker_broker_token"
}

# _deploy_challenge_service NAME IMAGE PORT DATA_VOLUME SECRET_SPEC...
#   SECRET_SPEC = "<docker-secret-name>:<mount-target-basename>"
#   Secrets mount at ${SECRET_MOUNT_DIR}/<basename> to match the *_FILE env
#   paths the challenges expect (docker_orchestrator.py / cli_app/main.py).
_deploy_challenge_service() {
  local name="$1" image="$2" port="$3" data_volume="$4"
  shift 4
  if docker service inspect "${name}" >/dev/null 2>&1; then
    log "  service ${name} already exists — skipping (idempotent)"
    return 0
  fi
  local target_dir="${SECRET_MOUNT_DIR#/run/secrets/}"  # "base"
  local -a argv=(
    docker service create
    --name "${name}"
    --network "${NET_CHALLENGES}"
    --replicas 1
    --restart-condition any
    --update-order stop-first
    --hostname "${name}"
    --mount "type=volume,source=${data_volume},destination=/data"
  )
  # Caller-supplied extra env (e.g. the own_runner eval image allowlist applied to
  # BOTH the agent-challenge api and worker). Reset after the deploy below.
  local env_kv
  if [[ "${#CHALLENGE_ENV[@]}" -gt 0 ]]; then
    for env_kv in "${CHALLENGE_ENV[@]}"; do
      argv+=(--env "${env_kv}")
    done
  fi
  # Caller-supplied extra mounts (e.g. the prism scorer's read-only SECRET held-out val volume
  # so the host-side held-out delta can run; the eval container NEVER mounts val/test).
  local mnt_spec
  if [[ "${#CHALLENGE_EXTRA_MOUNTS[@]}" -gt 0 ]]; then
    for mnt_spec in "${CHALLENGE_EXTRA_MOUNTS[@]}"; do
      argv+=(--mount "${mnt_spec}")
    done
  fi
  local spec secret_name target
  for spec in "$@"; do
    secret_name="${spec%%:*}"
    target="${spec##*:}"
    argv+=(--secret "source=${secret_name},target=${target_dir}/${target}")
  done
  # Caller-supplied extra secrets passed VERBATIM (full `source=...,target=...`), so a secret can
  # be mounted at an exact target OUTSIDE the ${target_dir}/ "base/" subdir (e.g. the prism
  # OpenRouter key at /run/secrets/openrouter_api_key — see CHALLENGE_EXTRA_SECRETS).
  local secret_spec
  if [[ "${#CHALLENGE_EXTRA_SECRETS[@]}" -gt 0 ]]; then
    for secret_spec in "${CHALLENGE_EXTRA_SECRETS[@]}"; do
      argv+=(--secret "${secret_spec}")
    done
  fi
  argv+=("${image}")
  # Optional command override (e.g. the agent-challenge-worker sidecar command).
  if [[ "${#CHALLENGE_CMD[@]}" -gt 0 ]]; then
    argv+=("${CHALLENGE_CMD[@]}")
  fi
  plan "${argv[@]}"
  CHALLENGE_ENV=()
  CHALLENGE_CMD=()
  CHALLENGE_EXTRA_MOUNTS=()
  CHALLENGE_EXTRA_SECRETS=()
  : "${port}"  # port documented in inventory; challenges are overlay-internal
}

# ============================================================================
# 11. healthcheck()
#     Curl each master service's published port for HTTP 200 on /health. Master
#     services publish host ports; challenges are overlay-internal, so they are
#     checked via service-replica convergence + an on-overlay curl probe.
# ============================================================================
healthcheck() {
  log "STEP 11/12 healthcheck"
  if [[ "${APPLY}" != "true" ]]; then
    log "  (dry-run) would HTTP-probe /health on:"
    log "    http://127.0.0.1:${MASTER_BROKER_PORT}/health  (base-master-broker)"
    log "    http://127.0.0.1:${MASTER_PROXY_PORT}/health   (base-master-proxy)"
    log "  and would verify challenge services converge to 1/1 replicas + overlay /health."
    return 0
  fi

  _http_health "base-master-broker" "http://127.0.0.1:${MASTER_BROKER_PORT}/health"
  _http_health "base-master-proxy"  "http://127.0.0.1:${MASTER_PROXY_PORT}/health"

  if [[ "${STATIC_CHALLENGES}" == "true" ]]; then
    _service_converged "challenge-agent-challenge"
    _service_converged "challenge-agent-challenge-worker"  # sidecar: no /health port
    _service_converged "challenge-prism"
    _overlay_health "challenge-agent-challenge" "${AGENT_CHALLENGE_PORT}"
    _overlay_health "challenge-prism" "${PRISM_PORT}"
  else
    log "  challenges are master-orchestrated; verify via 'docker service ls' after the"
    log "  master has reconciled (out of band for this script's default path)."
  fi
  log "healthcheck complete"
}

# _http_health LABEL URL — fail loudly unless HTTP 200.
_http_health() {
  local label="$1" url="$2" code
  for _ in $(seq 1 30); do
    code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      log "  ${label} ${url} -> 200 OK"
      return 0
    fi
    sleep 4
  done
  die "healthcheck FAILED: ${label} ${url} (last code=${code:-none})"
}

# _service_converged NAME — wait until replicas read N/N.
_service_converged() {
  local name="$1" reps
  for _ in $(seq 1 30); do
    reps="$(docker service ls --filter "name=${name}" --format '{{.Replicas}}' | head -n1)"
    if [[ -n "${reps}" && "${reps%%/*}" == "${reps##*/}" && "${reps%%/*}" != "0" ]]; then
      log "  ${name} converged (${reps})"
      return 0
    fi
    sleep 4
  done
  die "service ${name} did not converge (last replicas=${reps:-none})"
}

# _overlay_health NAME PORT — probe /health from a throwaway container on the overlay.
_overlay_health() {
  local name="$1" port="$2" code
  code="$(docker run --rm --network "${NET_CHALLENGES}" curlimages/curl:latest \
    -fsS -o /dev/null -w '%{http_code}' --max-time 5 "http://${name}:${port}/health" 2>/dev/null || true)"
  if [[ "${code}" == "200" ]]; then
    log "  ${name} (overlay) :${port}/health -> 200 OK"
  else
    die "overlay healthcheck FAILED: ${name}:${port}/health (last code=${code:-none})"
  fi
}

# ============================================================================
# 12. OUT OF SCOPE — node teardown
# ============================================================================
#   This script only brings the single manager node up; it performs NO teardown.
#   Decommissioning a node is done separately, by hand (e.g. `docker swarm leave`
#   on the node and `base master worker rm <node>` on the manager), ONLY
#   after a human has confirmed GREEN (master + both challenges healthy on Swarm).
# ============================================================================

# ============================================================================
# main
# ============================================================================
main() {
  parse_args "$@"

  log "============================================================"
  log "BASE single-node Swarm bring-up (DRAFT)"
  if [[ "${APPLY}" == "true" ]]; then
    warn "RUNNING IN --apply MODE: mutating commands WILL execute."
  else
    log "DRY-RUN (default): printing planned actions only. Pass --apply to execute."
  fi
  log "  advertise-addr      : ${ADVERTISE_ADDR}"
  log "  backup-dir          : ${BACKUP_DIR}"
  log "  master-config       : ${MASTER_CONFIG_PATH}"
  log "  restart-dockerd     : ${RESTART_DOCKERD}   (destructive; opt-in)"
  log "  single-node-placement: ${SINGLE_NODE_PLACEMENT}  (non-default; opt-in)"
  log "  static-challenges   : ${STATIC_CHALLENGES}  (opt-in)"
  log "  greenfield          : ${GREENFIELD}  (skip backup-dump preflight + restore_data; opt-in)"
  log "============================================================"

  preflight                  # 1
  ghcr_login                 # 1b (private images)
  apply_daemon_json          # 2  (DESTRUCTIVE behind --restart-dockerd)
  swarm_init                 # 3
  single_node_placement_fix  # 4  (REVIEW; non-default behind --single-node-placement)
  create_networks            # 5
  create_secrets             # 6
  deploy_postgres            # 7
  if [[ "${GREENFIELD}" == "true" ]]; then
    log "STEP 8/12 restore_data: --greenfield set — SKIPPING restore (fresh DBs init via migrations/bootstrap)"
  else
    restore_data             # 8
  fi
  deploy_master              # 9
  deploy_challenges          # 10 (master-orchestrated by default; direct via --static-challenges)
  healthcheck                # 11
  # 12 node teardown: OUT OF SCOPE (see comment block above).

  log "============================================================"
  if [[ "${APPLY}" == "true" ]]; then
    log "Bring-up steps executed. Verify master + both challenges are healthy."
  else
    log "Dry-run complete. Review the planned actions above, then re-run with --apply."
  fi
  log "============================================================"
}

main "$@"

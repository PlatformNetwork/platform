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
# IMAGE PROVENANCE — the broker, master, agent-challenge and prism images below are
# CI-published to ghcr.io/baseintelligence and deployed from their CI `:latest` tags
# (pinned by digest at deploy time). There is NO local rebuild prerequisite and NO
# dependency on unpushed or local-only images: the stack is reproducible from the
# registry alone. The host-side prism held-out delta still needs BOTH the SECRET val
# split (manager-local volume `prism_fineweb_edu_val`, RO at /secret/val) AND the
# non-secret TRAIN split (manager-local volume `prism_fineweb_edu_train`, RO at
# /secret/train) present + populated; with the train mount the
# converged-memorization-gap path activates (gap_basis='converged'), else it falls
# back to the prequential reference (no regression). If val is absent the held-out is
# skipped. The prism eval RO mounts (FineWeb-Edu train split + reference tokenizers)
# are supplied by the broker built-in DEFAULT_PRISM_EVAL_READONLY_MOUNTS, so no
# master.yaml broker_eval_readonly_mounts_by_slug entry is required for them to be
# live. The broker shells out to `docker service create` to dispatch eval jobs, so it
# is pinned to the manager node (docker.sock + workspace bind) — see the manager-pin
# rationale at the broker service-create below. The deploy CONFIG this script sets is
# independent of the image build and reproduces as-is.
IMAGE_MASTER="${IMAGE_MASTER:-ghcr.io/baseintelligence/base-master@sha256:838ed7ca090f276a014a9c04820b84cc48ac3833af9b37c4047dfa8677156cb7}"
IMAGE_AGENT_CHALLENGE="${IMAGE_AGENT_CHALLENGE:-ghcr.io/baseintelligence/agent-challenge@sha256:d12690a39b0a1311ffe237001f9c2fef364303c6162111d37d3b305a8d3159c5}"
IMAGE_PRISM="${IMAGE_PRISM:-ghcr.io/baseintelligence/prism@sha256:e052a3eced0b76424c858fcea5c04e948a6764b051a862a9b99d011a44f9ffd9}"
# Prism GPU evaluator (CUDA cu128 torchrun runner). Must satisfy BOTH prism
# docker_allowed_images AND the broker broker_allowed_images (ghcr.io/baseintelligence/);
# pre-pulled on the GPU worker so the broker eval job resolves it locally.
# Uses the CI-published :latest evaluator image (digest-pinned by the deploy). The
# runtime assets PRISM v2 forced-init re-execution needs (sentencepiece + offline
# tiktoken/HF for the locked FineWeb-Edu pipeline) ship in that published image, so
# no separate locally built evaluator tag is required.
IMAGE_PRISM_EVALUATOR="${IMAGE_PRISM_EVALUATOR:-ghcr.io/baseintelligence/prism-evaluator@sha256:713b39f13af69dbaf229e67fb682df8a2b7ac93dd02d9e60867ff021d4edb3c9}"
IMAGE_POSTGRES="${IMAGE_POSTGRES:-postgres@sha256:0fc5c901ec0a3c55ce70b99b040daeb89d5b35b61febbced1b4b24dbc3153ec8}"

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
#   broker : base master broker  -> docker.broker_*        (8082)
#   proxy  : base master proxy   -> proxy_host:proxy_port  (18080)
# SINGLE PUBLIC API: the proxy also serves the admin/registry surface
# (/v1/registry, /v1/weights/latest, /health) on :18080, so there is no separate
# admin service/port (the former base-master-admin on 18900 is removed).
MASTER_BROKER_PORT="${MASTER_BROKER_PORT:-8082}"
MASTER_PROXY_PORT="${MASTER_PROXY_PORT:-18080}"

# Placement constraint for the proxy (the single public API also serving the
# admin/registry surface). For the NO-CHAIN decentralized deploy the proxy seeds
# the mock metagraph (MOCK_METAGRAPH below) and never reaches a live chain, so it
# is MANAGER-pinned by default — matching the broker's intrinsic node.role==manager
# pin and co-locating the control plane on the manager (hotkey) node. This REPLACES
# the old hard node.role==worker pin, which existed ONLY because the live chain was
# reachable from a worker; with the mock metagraph there is no chain to reach.
# Set empty to drop the pin entirely (e.g. a chain-reachable single-node swarm).
# The no-colon ${VAR-default} form preserves an explicitly-empty value (drop the
# pin) while still defaulting when the var is UNSET. Do NOT --constraint-add on an
# already-pinned live service (not idempotent — see AGENTS.md "CONSTRAINT-ADD DEDUP
# GOTCHA").
MASTER_PROXY_CONSTRAINT="${MASTER_PROXY_CONSTRAINT-node.role==manager}"

# ---- Master LLM gateway (architecture.md §5). `base master proxy` now ALWAYS
# builds the LLM gateway and GatewayTokenAuthority refuses an empty token secret,
# so the proxy FAILS FAST at startup unless the gateway token secret is wired
# (MANDATORY). provider_mode selects the deterministic mock provider (no egress)
# vs the real DeepSeek/OpenRouter clients whose keys the gateway injects
# server-side (validators/eval runtimes hold NO provider key). ----
GATEWAY_PROVIDER_MODE="${GATEWAY_PROVIDER_MODE:-real}"
# Externally-reachable master gateway/proxy ROOT advertised to validators in the
# pull payload, so eval runtimes target the master gateway for
# DEEPSEEK_BASE_URL/OPENROUTER_BASE_URL instead of the WRONG master.registry_url
# (chain registry) fallback. Defaults to the published proxy host:port.
GATEWAY_PUBLIC_BASE_URL="${GATEWAY_PUBLIC_BASE_URL:-http://${ADVERTISE_ADDR}:${MASTER_PROXY_PORT}}"
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

# Runtime uid the master image's proxy/admin run as (Dockerfile.master pins
# `USER 1000:1000`). The master writes per-challenge token files
# (<slug>_challenge_token / <slug>_docker_broker_token) into VOL_BASE_SECRETS when a
# challenge is registered (registry._write_token / _write_broker_token via
# POST /v1/admin/challenges). A FRESH docker volume root dir is owned root:root mode
# 0755, so the NON-root master cannot create new files there and registration 500s
# with PermissionError (discovered live; hot-fixed via `chown 1000:1000` of the
# volume dir). _ensure_secret_volume_writable chowns the volume root to this uid
# before the master starts so a fresh deploy can create the token files. Derived
# from IMAGE_MASTER at runtime (so a rebuilt image with a different runtime user
# stays correct — NOT blindly hardcoded), overridable via env, default 1000.
MASTER_RUNTIME_UID="${MASTER_RUNTIME_UID:-}"

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
#
# LAST ENTRY (5Grwva...HGKutQY) = the well-known //Alice dev keypair, added ONLY
# to exercise the end-to-end prism submission path before launch. MUST-REVIEW-
# BEFORE-T27: remove //Alice from this allowlist before mainnet launch — it is a
# publicly-known test key and must never be miner-registrable in production.
UPLOAD_EXTRA_REGISTERED_HOTKEYS="${UPLOAD_EXTRA_REGISTERED_HOTKEYS:-[\"5EWKzomnbVvLKWjHeVqm2BMqMzmckKMiufR11qFXahaUfenR\",\"5FTyuyEQQZs8tCcPTUFqotkm2SYfDnpefn9FitRgmTHnFDBD\",\"5GGboHkKougeE8PqGRbNM32AEwRU7Dsv4MXATm2zukQJ8wrU\",\"5FJAjL6d31QDSfvcZPKkde9ftTLAPu7J5Mo86je5XbziRXSB\",\"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY\"]}"

# ---- Mock/static metagraph (architecture.md G1; NO-CHAIN decentralized deploy).
# `base master proxy` UNCONDITIONALLY builds the bittensor runtime; on a no-chain
# deploy the runtime factory seeds MetagraphCache from network.mock_metagraph
# (settings.network.mock_metagraph) instead of constructing a live Subtensor, so
# the listed validator hotkeys become permit-eligible with NO chain. Miners stay
# submit-eligible via UPLOAD_EXTRA_REGISTERED_HOTKEYS above, independent of this set.
#
# MOCK_METAGRAPH is a JSON array of {hotkey, validator_permit, stake} objects
# rendered VERBATIM into network.mock_metagraph in the master config (it is NOT a
# secret — ss58 hotkeys are public). EMPTY default ([]) keeps the seam OFF
# (production-safe, inert): the live-metagraph path is unchanged. For the live
# 1 master + 3 validators bring-up, set it to the 3 validator hotkeys with
# validator_permit=true (+ any miner hotkeys with validator_permit=false), e.g.:
#   MOCK_METAGRAPH='[{"hotkey":"5Val1...","validator_permit":true,"stake":1000},
#                    {"hotkey":"5Val2...","validator_permit":true,"stake":1000},
#                    {"hotkey":"5Val3...","validator_permit":true,"stake":1000}]'
MOCK_METAGRAPH="${MOCK_METAGRAPH:-[]}"

# ---- Control-plane supervisor auto-update (architecture.md G4; replaces
# Watchtower). The base-supervisor.service runs the image-updater /
# challenge-image-updater / config-sync / self-update loops on the MANAGER. The
# image-updaters resolve PRIVATE ghcr.io/baseintelligence/* digests using the
# manager's GHCR credentials — by default the docker config.json written by
# ghcr_login (STEP 1b); the supervisor decodes auths["ghcr.io"].auth from it. ----
SUPERVISOR_REGISTRY="${SUPERVISOR_REGISTRY:-ghcr.io}"
SUPERVISOR_DOCKER_CONFIG_PATH="${SUPERVISOR_DOCKER_CONFIG_PATH:-/root/.docker/config.json}"
# Master self-update manifest URL (Task 22). When set, base-supervisor self-update
# is ENABLED + wired to this JSON manifest ({"version":...,"source_url":...}). When
# EMPTY (default) self-update is EXPLICITLY DISABLED — the supervisor does not
# register the self-update task at all (no silent inert half-state). The
# image-updater (service digest-pin roll) is always on regardless of this.
SUPERVISOR_SELF_UPDATE_MANIFEST_URL="${SUPERVISOR_SELF_UPDATE_MANIFEST_URL:-}"
# base-supervisor.service install destinations + release root the unit launches
# through (current -> releases/<version>, a uv-managed checkout; see the unit).
SUPERVISOR_RELEASE_ROOT="${SUPERVISOR_RELEASE_ROOT:-/var/lib/base/supervisor}"
SUPERVISOR_UNIT_SRC="${SUPERVISOR_UNIT_SRC:-${SCRIPT_DIR}/base-supervisor.service}"
SUPERVISOR_UNIT_DST="${SUPERVISOR_UNIT_DST:-/etc/systemd/system/base-supervisor.service}"

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
# Per-call placement `--constraint` exprs consumed by _deploy_challenge_service. CRITICAL for
# multi-node swarms: an agent-challenge api + its worker sidecar both mount the SAME per-node
# `type=volume` at /data (the uploaded-agent artifact dir, base_agent_challenge_pg). Swarm volumes
# are per-NODE, so if api and worker land on DIFFERENT nodes they get DISJOINT /data volumes and the
# worker fails `FileNotFoundError: /data/agents/<sha>` reading a zip the api wrote on its own node.
# Emitting NO constraint only co-locates them by luck on a single-manager node; on multi-node they
# float independently. Setting an IDENTICAL constraint on BOTH guarantees co-location so they share
# the same local /data volume. Default expr matches the dynamic orchestrator's challenge placement
# default (swarm_backend.py DEFAULT_CHALLENGE_CONSTRAINT = node.role==manager). Reset after each deploy.
CHALLENGE_EXTRA_CONSTRAINTS=()

# ============================================================================
# Flags (all default to the SAFE / non-mutating / non-destructive value).
# ============================================================================
APPLY=false               # false => dry-run (print only). Mutating requires --apply.
FORCE=false               # allow proceeding even if node already in a swarm.
RESTART_DOCKERD=false      # opt-in: write daemon.json + restart dockerd (DESTRUCTIVE).
SINGLE_NODE_PLACEMENT=false # opt-in: non-default placement override (see REVIEW).
STATIC_CHALLENGES=false    # opt-in: create challenge services directly here.
INSTALL_SUPERVISOR=false   # opt-in: install + enable base-supervisor.service (systemd).
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

# `_master_runtime_uid` resolves the uid the master image runs as, so ownership of
# the shared secrets volume tracks the image instead of a blind constant. Order:
#   1. explicit MASTER_RUNTIME_UID override (operator escape hatch);
#   2. the image's own USER directive (docker image inspect .Config.User), which is
#      "uid", "uid:gid", or "name[:group]" — take the uid when it is numeric;
#   3. fall back to 1000 (the Dockerfile.master default) when the image is not
#      locally available (e.g. dry-run before the image is pulled).
# Read-only (inspect only); never runs a container, never mutates.
_master_runtime_uid() {
  if [[ -n "${MASTER_RUNTIME_UID}" ]]; then
    printf '%s' "${MASTER_RUNTIME_UID}"
    return 0
  fi
  local user_field uid
  user_field="$(docker image inspect --format '{{.Config.User}}' "${IMAGE_MASTER}" 2>/dev/null || true)"
  uid="${user_field%%:*}"
  if [[ "${uid}" =~ ^[0-9]+$ ]]; then
    printf '%s' "${uid}"
  else
    printf '%s' "1000"
  fi
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
  --install-supervisor    Install + enable base-supervisor.service (the systemd
                          control-plane auto-update unit that REPLACES Watchtower).
                          Decommission Watchtower FIRST (see deploy/swarm/README.md
                          "Watchtower decommission ordering"). Without this flag the
                          install/enable commands are printed as instructions only.

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
  OPENROUTER_API_KEY                         openrouter_api_key (gateway + prism gate).
  GATEWAY_TOKEN                              MANDATORY master LLM-gateway token secret
                                             (gateway_token_secret). The proxy fails
                                             fast at startup without it.
  DEEPSEEK_API_KEY                           DeepSeek provider key the gateway injects
                                             (required when GATEWAY_PROVIDER_MODE=real).
  MASTER_PG_PASSWORD                         base postgres password.
  AGENT_CHALLENGE_PG_PASSWORD                agent-challenge postgres password.
  PRISM_PG_PASSWORD                          prism postgres password.
  MASTER_DATABASE_URL                        master control-plane DB URL.
  AGENT_CHALLENGE_DATABASE_URL               agent-challenge DB URL.
  PRISM_DATABASE_URL                         prism DB URL.

Optional environment:
  CENTRAL_GATEWAY_TOKEN                      Scoped LLM-gateway token (base_gateway_token,
                                             mounted at /run/secrets/base_gateway_token) for
                                             the CENTRAL review gates (agent-challenge analyzer
                                             + prism llm_review). When set, --static-challenges
                                             routes both central gates through the master gateway
                                             (no direct provider key on the challenge services).
                                             Absent => the direct OpenRouter key no-gateway fallback.
  HF_TOKEN                                   HuggingFace token for the prism HF
                                             checkpoint publisher (base_hf_token,
                                             mounted via HF_TOKEN_FILE). Absent => skipped.
  GATEWAY_PROVIDER_MODE                      LLM-gateway provider mode: real (default,
                                             inject DeepSeek/OpenRouter keys) or mock.
  GATEWAY_PUBLIC_BASE_URL                    External master gateway/proxy root URL
                                             advertised to validators (default:
                                             http://<advertise-addr>:<proxy-port>).
  MOCK_METAGRAPH                             JSON array of {hotkey,validator_permit,stake}
                                             entries seeding network.mock_metagraph for
                                             the NO-CHAIN deploy (listed validator hotkeys
                                             become permit-eligible with no live chain).
                                             Empty default ([]) = OFF (live-metagraph path).
  MASTER_PROXY_CONSTRAINT                    Placement constraint for the proxy (default:
                                             node.role==manager for the no-chain deploy;
                                             set empty to drop the pin).
  MASTER_PROXY_PORT / MASTER_BROKER_PORT     Published host ports for the proxy (18080) and
                                             broker (8082); flow into both the --publish and
                                             the rendered master config (proxy_port/broker_*).
  SUPERVISOR_REGISTRY                        Registry the supervisor image-updaters
                                             authenticate against (default: ghcr.io).
  SUPERVISOR_DOCKER_CONFIG_PATH              docker config.json the supervisor decodes GHCR
                                             credentials from to resolve PRIVATE digests
                                             (default: /root/.docker/config.json).
  SUPERVISOR_SELF_UPDATE_MANIFEST_URL        Master self-update manifest URL. Set => self-update
                                             ENABLED + wired; empty (default) => self-update
                                             EXPLICITLY DISABLED (no inert half-state).
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
      --install-supervisor) INSTALL_SUPERVISOR=true ;;
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

  # ---- Master LLM gateway secrets (architecture.md §5; M7 wiring). ----
  # MANDATORY token-signing secret: `base master proxy` ALWAYS builds the LLM
  # gateway and GatewayTokenAuthority rejects an empty secret, so the proxy fails
  # fast at startup without it. Mounted into base-master-proxy at
  # /run/secrets/gateway_token_secret (GatewaySettings.token_secret_file).
  _ensure_secret "base_gateway_token_secret"              GATEWAY_TOKEN
  # Provider keys the gateway injects server-side (validators/eval hold none).
  # Only needed when the gateway runs in provider_mode=real; mock uses canned
  # responses and needs no provider key. DeepSeek -> /run/secrets/deepseek_api_key;
  # OpenRouter reuses base_openrouter_api_key -> /run/secrets/openrouter_api_key.
  if [[ "${GATEWAY_PROVIDER_MODE}" == "real" ]]; then
    _ensure_secret "base_gateway_deepseek_api_key"        DEEPSEEK_API_KEY
  fi

  # Scoped gateway token for the CENTRAL review gates (agent-challenge analyzer
  # LLM review + prism llm_review gpt-4o). The challenge services authenticate to
  # the master LLM gateway with THIS scoped token instead of a direct provider
  # key, so no OpenRouter key reaches the challenge services (architecture.md
  # §5/§11). OPTIONAL: when $CENTRAL_GATEWAY_TOKEN is unset the central gates fall
  # back to the direct OpenRouter key (the no-gateway fallback). Mounted at
  # /run/secrets/base_gateway_token on the prism + agent-challenge challenge
  # services (the path both consumers read by default). The operator mints the
  # scoped token out-of-band with the gateway HMAC secret (base_gateway_token_secret).
  _ensure_optional_secret "base_gateway_token"            CENTRAL_GATEWAY_TOKEN

  # hf_token is OPTIONAL: FineWeb-Edu is a public dataset, so the one-time prep
  # download usually needs no credential. When a token IS supplied (private
  # mirror / rate-limit relief) it MUST travel as a docker secret consumed via
  # HF_TOKEN_FILE (=/run/secrets/hf_token), never a plaintext env/image/CI value.
  # Absent env => skip silently (no hard error, unlike the required secrets).
  _ensure_optional_secret "base_hf_token"                 HF_TOKEN
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

# _ensure_optional_secret NAME ENVVAR — like _ensure_secret but a missing/empty
# env var is NOT an error: it logs and returns 0 (used for credentials that are
# genuinely optional, e.g. a public-dataset HF token).
_ensure_optional_secret() {
  local name="$1" envvar="$2"
  if [[ -z "${!envvar:-}" ]]; then
    log "  optional secret ${name} skipped (\$${envvar} unset)"
    return 0
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
    --with-registry-auth \
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
#      base-docker-broker : `base master broker` : 8082 (docker.broker_*)
#      base-master-proxy  : `base master proxy`  : 18080 (proxy_host:proxy_port)
#    The proxy is the SINGLE public API: it serves /v1/registry, /v1/weights/latest,
#    /health, the admin/management routes (token-gated), the signed upload bridge,
#    and the /challenges/* passthrough, AND it runs the orchestrator that creates
#    challenges dynamically (the separate `base master run` admin service on
#    18900 is removed).
#    The broker service MUST be named base-docker-broker so the configured
#    broker_url (http://base-docker-broker:8082) resolves over the overlay.
# ============================================================================
deploy_master() {
  log "STEP 9/12 deploy_master"
  _render_master_config
  _ensure_master_config_secret
  _ensure_secret_volume_writable  # chown vol_base_secrets root to the master runtime uid (else registration 500s)
  _seed_proxy_challenge_tokens  # proxy bearer-token files in the shared secrets volume

  # broker — challenge workload broker (frozen contract / Swarm backend).
  _deploy_master_service "base-docker-broker" "broker" "${MASTER_BROKER_PORT}" "${MASTER_BROKER_PORT}"
  # proxy — public single API (registry/weights/health + admin + upload bridge +
  # /challenges/* passthrough) and the orchestrator that creates challenges.
  _deploy_master_service "base-master-proxy" "proxy" "${MASTER_PROXY_PORT}" "${MASTER_PROXY_PORT}"
}

# Render the single-node master config to MASTER_CONFIG_PATH. NO secrets inline:
# the DB URL / admin token are mounted as docker secrets/files at runtime.
_render_master_config() {
  log "  rendering master config -> ${MASTER_CONFIG_PATH}"
  # Derive supervisor self-update enablement from the manifest URL: a URL means
  # ENABLED+wired; empty means EXPLICITLY DISABLED (the supervisor never registers
  # an inert self-update task). This avoids a silent "configured but no-op" state.
  local supervisor_self_update_enabled="false"
  [[ -n "${SUPERVISOR_SELF_UPDATE_MANIFEST_URL}" ]] && supervisor_self_update_enabled="true"
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
  # Config-driven static/mock metagraph (architecture.md G1). Non-empty => the
  # proxy seeds MetagraphCache from this set and builds NO live Subtensor, so the
  # listed validator hotkeys (validator_permit=true) are eligible with no chain;
  # this is what makes the NO-CHAIN 1-master + N-validator deploy work. Empty ([])
  # keeps the seam OFF (live-metagraph path unchanged). Rendered verbatim from the
  # public MOCK_METAGRAPH env (ss58 hotkeys are NOT secrets). Miners stay
  # submit-eligible via master.upload_extra_registered_hotkeys, independent of this.
  mock_metagraph: ${MOCK_METAGRAPH}

master:
  proxy_host: 0.0.0.0
  proxy_port: ${MASTER_PROXY_PORT}
  # Validator coordination plane (architecture.md §4): heartbeat cadence + offline
  # timeout, the in-app crash-detection loop interval, and the assignment lease.
  # The plane persists into the same base-master Postgres wired via
  # BASE_DATABASE__URL below (no separate datastore). The live orchestration
  # driver bridges challenge pending work into work_assignments, runs the balanced
  # assignment engine + the full reassignment pass, and folds retry-exhausted units.
  validator_heartbeat_interval_seconds: 60
  validator_heartbeat_timeout_seconds: 180
  validator_health_interval_seconds: 60
  assignment_lease_seconds: 900
  orchestration_interval_seconds: 30

database:
  # Password-less FALLBACK only. The pinned master image's config loader
  # (base.config.loader) has NO *_FILE indirection for database.url and its
  # entrypoint is a direct "base master proxy" (no FILE->env expansion), so the
  # mounted base_master_database_url secret is NOT self-read. The real URL (with
  # password) is injected at deploy time via the name-only BASE_DATABASE__URL env
  # in _deploy_master_service, which the loader maps to database.url. Name-only
  # env keeps the secret value out of the planned/logged argv.
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
  broker_url: http://base-docker-broker:${MASTER_BROKER_PORT}
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
  # Swarm mounts the admin secret at the --secret target (admin_token) below in
  # _deploy_master_service: `--secret source=base_admin_token,target=admin_token`
  # -> /run/secrets/admin_token (NOT the ${SECRET_MOUNT_DIR}/"base/" subdir). The
  # path MUST match that target verbatim or the master admin auth fails closed
  # (GET /v1/validators -> 401), mirroring the working gateway token_secret_file.
  admin_token_file: /run/secrets/admin_token

# Master LLM gateway (architecture.md §5). The proxy ALWAYS builds the gateway;
# provider_mode selects the deterministic mock provider (no egress) vs the real
# DeepSeek/OpenRouter clients whose keys are injected server-side from the secret
# files below (validators/eval runtimes hold NO provider key). public_base_url is
# the external master gateway root advertised to validators in the pull payload so
# eval runtimes set DEEPSEEK_BASE_URL/OPENROUTER_BASE_URL to the gateway, NOT the
# WRONG master.registry_url (chain registry) fallback. The token_secret_file is the
# MANDATORY HMAC secret for scoped gateway tokens (proxy fails fast if absent).
gateway:
  provider_mode: ${GATEWAY_PROVIDER_MODE}
  public_base_url: ${GATEWAY_PUBLIC_BASE_URL}
  token_secret_file: /run/secrets/gateway_token_secret
  deepseek_api_key_file: /run/secrets/deepseek_api_key
  openrouter_api_key_file: /run/secrets/openrouter_api_key

observability:
  log_json: true

# Control-plane supervisor (deploy/swarm/base-supervisor.service; architecture.md
# G4). The image-updater digest-pins base-master-proxy + base-docker-broker, and
# the challenge-image-updater rolls the challenge services, by resolving their
# GHCR tag digests. PRIVATE ghcr.io/baseintelligence/* packages need credentials:
# the supervisor decodes auths["${SUPERVISOR_REGISTRY}"].auth from the docker
# config.json below (written on the manager by ghcr_login / STEP 1b), so no
# extra secret is required. self_update_enabled is derived from
# SUPERVISOR_SELF_UPDATE_MANIFEST_URL: set => self-update wired to that manifest;
# empty => self-update EXPLICITLY DISABLED (the task is not registered — no inert
# no-op). The image-updater (service digest-pin roll) is always on.
supervisor:
  registry: ${SUPERVISOR_REGISTRY}
  registry_docker_config_path: ${SUPERVISOR_DOCKER_CONFIG_PATH}
  self_update_enabled: ${supervisor_self_update_enabled}
  self_update_manifest_url: ${SUPERVISOR_SELF_UPDATE_MANIFEST_URL:-}
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

# Make the shared base-secrets volume (VOL_BASE_SECRETS) WRITABLE by the master
# runtime user BEFORE the master starts. The master proxy/admin (non-root, uid from
# _master_runtime_uid) creates per-challenge token files directly in this volume when
# a challenge is registered (registry._write_token / _write_broker_token ->
# <secret_dir>/<slug>_challenge_token and <slug>_docker_broker_token). A FRESH docker
# volume root dir is owned root:root mode 0755, so the non-root master CANNOT create
# new files there: POST /v1/admin/challenges returns HTTP 500 (PermissionError),
# registering the challenge in the DB with no/partial token files and breaking the
# master->challenge + broker auth wiring (discovered live; hot-fixed via
# `chown 1000:1000` of the volume dir). chown the volume ROOT DIR to the master
# runtime uid so a fresh deploy can create the token files.
#
# This mirrors how the challenge /data volumes end up writable: their image dir
# (e.g. agent-challenge `chown -R challenge:challenge /data`) is owned by the runtime
# user, so a fresh volume mounted there INHERITS that ownership from the image. The
# secrets volume gets no such inheritance — it is first mounted (by the token-seed
# writer) at a path the writer image does NOT own, so its root stays root:root and
# must be chowned explicitly. Runs BEFORE _seed_proxy_challenge_tokens so the dir is
# owned correctly first. Idempotent (re-chown is a no-op). Uses a throwaway ROOT
# container because only root can chown a root-owned dir.
_ensure_secret_volume_writable() {
  local uid
  uid="$(_master_runtime_uid)"
  log "  ensuring ${VOL_BASE_SECRETS} root dir is owned by master runtime uid ${uid}"
  log "    (a fresh volume root is root:root 0755 -> the non-root master cannot create"
  log "     per-challenge token files -> POST /v1/admin/challenges 500 PermissionError)"
  plan docker run --rm \
    --mount "type=volume,source=${VOL_BASE_SECRETS},destination=/secrets" \
    "${IMAGE_POSTGRES}" \
    chown "${uid}:${uid}" /secrets
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
# Ownership: the master image runs as the runtime uid (_master_runtime_uid; the
# proxy is non-root, only the broker is --user root), so the proxy reads these files
# AS that uid. The writer container runs as root (the default — required because a
# FRESH vol_base_secrets volume root is owned root:root 0755, so a --user <uid>
# writer could not create the file), then chowns the file to that uid keeping
# mode 600. A root-owned 600 file would be UNREADABLE by the proxy on a
# fresh volume (-> 500 "Challenge token file is missing" / 401 "invalid bearer
# token"). The uid matches _ensure_secret_volume_writable's chown of the volume root.
_seed_challenge_token() {
  local slug="$1" envvar="$2"
  if [[ -z "${!envvar:-}" ]]; then
    die "required token env var \$${envvar} is empty (proxy seed for slug '${slug}')"
  fi
  local target="${slug}_challenge_token"
  local uid
  uid="$(_master_runtime_uid)"
  plan_secret_stdin "proxy-token-${slug}" "${envvar}" -- \
    docker run --rm -i \
      --mount "type=volume,source=${VOL_BASE_SECRETS},destination=/secrets" \
      "${IMAGE_POSTGRES}" \
      sh -c "umask 077 && cat > /secrets/${target} && chmod 600 /secrets/${target} && chown ${uid}:${uid} /secrets/${target}"
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
  #   * --update-order stop-first: these are FIXED host-port services (8082/18080,
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
    # REGISTRY AUTH FOR EVAL JOBS (Defect E2): the broker shells out to `docker
    # service create --with-registry-auth` to dispatch eval jobs that pull the
    # private ghcr.io/baseintelligence evaluator. `--with-registry-auth` takes the
    # auth from the CLIENT (this broker container's) docker config, so the broker
    # must read the manager's config.json written by ghcr_login (STEP 1b). Bind the
    # manager-host docker config dir read-only at /root/.docker (broker runs
    # --user root) and pin DOCKER_CONFIG to it. Without this the create succeeds but
    # the worker-node pull is unauthorized and the eval task hangs pending forever.
    local docker_cfg_dir="${DOCKER_CONFIG:-${HOME}/.docker}"
    extra+=(
      --user root
      --mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"
      --mount "type=bind,source=${broker_ws},target=${broker_ws}"
      --mount "type=bind,source=${docker_cfg_dir},target=/root/.docker,readonly"
      --env "DOCKER_CONFIG=/root/.docker"
      # MANAGER PIN (required on any multi-node swarm): the broker shells out to
      # `docker service create` to dispatch eval jobs, which REQUIRES a manager's
      # docker.sock; it also binds the manager-local docker.sock + ${broker_ws}
      # workspace and publishes the fixed host port 8082. With no constraint an
      # update (stop-first) can reschedule the broker onto a joined worker (e.g.
      # the GPU node), where it breaks: the manager-only docker API is absent, the
      # pinned image digest may not be present on the worker ("No such image"), and
      # the workspace bind source does
      # not exist. node.role is intrinsic, so this also matches the sole manager on
      # a single-node swarm (no-op there). Canonicalizes the live M2/M3 pin
      # (verified on base-docker-broker; see library/environment.md). Do NOT
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
    # PLACEMENT (no-chain decentralized deploy): the proxy seeds the mock
    # metagraph (network.mock_metagraph rendered above) and builds NO live
    # Subtensor, so it runs on the MANAGER (the control-plane / hotkey node),
    # matching the broker's intrinsic node.role==manager pin and the fixed
    # mode=host port (18080). This REPLACES the old hard node.role==worker pin,
    # which existed only because the live chain was reachable from a worker; with
    # the mock metagraph there is no chain. Configurable via MASTER_PROXY_CONSTRAINT
    # (set empty to drop the pin). Do NOT --constraint-add on an already-pinned live
    # service (not idempotent — see AGENTS.md "CONSTRAINT-ADD DEDUP GOTCHA").
    if [[ -n "${MASTER_PROXY_CONSTRAINT}" ]]; then
      extra+=(--constraint "${MASTER_PROXY_CONSTRAINT}")
    fi
    # LLM gateway secrets consumed by the proxy-built gateway (NOT the broker):
    #   * MANDATORY token-signing secret at /run/secrets/gateway_token_secret;
    #     the proxy fails fast at startup without it (GatewayTokenAuthority).
    #   * In provider_mode=real, the DeepSeek + OpenRouter provider keys the
    #     gateway injects server-side, mounted at the exact paths the gateway
    #     reads (/run/secrets/{deepseek_api_key,openrouter_api_key}).
    extra+=(
      --secret "source=base_gateway_token_secret,target=gateway_token_secret"
    )
    if [[ "${GATEWAY_PROVIDER_MODE}" == "real" ]]; then
      extra+=(
        --secret "source=base_gateway_deepseek_api_key,target=deepseek_api_key"
        --secret "source=base_openrouter_api_key,target=openrouter_api_key"
      )
    fi
  fi

  # Inject the control-plane DB URL (with password) via a NAME-ONLY --env so the
  # value is taken from this process's environment at `docker service create` exec
  # time and never appears in the planned/logged argv (plan() echoes argv). The
  # pinned master image cannot self-read the mounted master_database_url secret
  # (loader has no *_FILE indirection), so this env is what actually authenticates
  # broker+proxy to base-master-postgres. The secret mount below is retained for
  # parity with the live M2/M3 spec but is not self-read by the app.
  export BASE_DATABASE__URL="${MASTER_DATABASE_URL}"

  plan docker service create \
    --name "${name}" \
    --network "${NET_CHALLENGES}" \
    --replicas 1 \
    --restart-condition any \
    --hostname "${name}" \
    --with-registry-auth \
    --publish "published=${host_port},target=${container_port},mode=host" \
    --config "source=base_master_yaml,target=${MASTER_CONFIG_PATH}" \
    --secret "source=base_admin_token,target=admin_token" \
    --secret "source=base_master_database_url,target=master_database_url" \
    --env "BASE_CONFIG=${MASTER_CONFIG_PATH}" \
    --env BASE_DATABASE__URL \
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

  warn "creating challenge services DIRECTLY (--static-challenges); agent-challenge api+worker pinned to node.role==manager for /data co-location"

  # CENTRAL LLM review-gate routing (architecture.md §5/§7/§11). When
  # $CENTRAL_GATEWAY_TOKEN is provisioned (base_gateway_token secret), the
  # agent-challenge analyzer LLM review and the prism llm_review gpt-4o gate route
  # through the MASTER LLM gateway with that scoped token: the gateway injects the
  # provider key server-side, so NO direct OpenRouter key is mounted on the
  # challenge services. The consumer base URL is derived from the same
  # GATEWAY_PUBLIC_BASE_URL the proxy advertises (agent-challenge reads the gateway
  # ROOT and appends /llm/openrouter itself; prism reads the full /llm/openrouter
  # route). Absent => the direct OpenRouter key is the no-gateway fallback.
  local central_gateway_enabled=false
  [[ -n "${CENTRAL_GATEWAY_TOKEN:-}" ]] && central_gateway_enabled=true
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    log "  central gates -> master LLM gateway (${GATEWAY_PUBLIC_BASE_URL}); base_gateway_token mounted, no direct provider key on challenge services"
  else
    log "  central gates -> direct OpenRouter key (no-gateway fallback; \$CENTRAL_GATEWAY_TOKEN unset)"
  fi

  # own_runner eval image allowlist + runner image, applied to BOTH the
  # agent-challenge api and the worker so the broker DooD job is permitted to run
  # the deployed (non-:latest) runner tag. Without it the eval job fails
  # "Docker image is not allowed: ...". See "Proxy submission-path requirements".
  local -a ac_eval_env=(
    "CHALLENGE_SLUG=agent-challenge"
    "CHALLENGE_HARBOR_RUNNER_IMAGE=${AGENT_CHALLENGE_RUNNER_IMAGE}"
    "CHALLENGE_DOCKER_ALLOWED_IMAGES=${CHALLENGE_DOCKER_ALLOWED_IMAGES}"
    "CHALLENGE_VALIDATOR_ROLE=master"
    "CHALLENGE_DATABASE_URL_FILE=${SECRET_MOUNT_DIR}/database_url"
  )
  # Central AST+LLM gate review routing. Gateway mode: point the analyzer at the
  # master gateway ROOT (it appends /llm/openrouter) + read the scoped token from
  # /run/secrets/base_gateway_token. Fallback: the direct OpenRouter key file +
  # the base_openrouter_api_key secret mounted at ${SECRET_MOUNT_DIR}/openrouter_api_key.
  local -a ac_gate_secret_specs=()
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    ac_eval_env+=(
      "CHALLENGE_LLM_GATEWAY_BASE_URL=${GATEWAY_PUBLIC_BASE_URL}"
      "CHALLENGE_LLM_GATEWAY_TOKEN_FILE=/run/secrets/base_gateway_token"
    )
  else
    ac_eval_env+=("CHALLENGE_OPENROUTER_API_KEY_FILE=${SECRET_MOUNT_DIR}/openrouter_api_key")
    ac_gate_secret_specs+=("base_openrouter_api_key:openrouter_api_key")
  fi

  # agent-challenge primary API service (container port 8000). Overlay-internal —
  # reached over the overlay by the proxy/master; no host publish.
  # Co-locate api + worker (next block) on ONE node via an identical constraint so they share the
  # per-node base_agent_challenge_pg /data volume (see CHALLENGE_EXTRA_CONSTRAINTS declaration).
  CHALLENGE_EXTRA_CONSTRAINTS=("node.role==manager")
  CHALLENGE_ENV=("${ac_eval_env[@]}")
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    CHALLENGE_EXTRA_SECRETS=("source=base_gateway_token,target=base_gateway_token")
  fi
  _deploy_challenge_service \
    "challenge-agent-challenge" "${IMAGE_AGENT_CHALLENGE}" "${AGENT_CHALLENGE_PORT}" \
    "base_agent_challenge_pg" \
    "base_agent_challenge_challenge_token:challenge_token" \
    "base_agent_challenge_docker_broker_token:docker_broker_token" \
    "base_agent_challenge_submission_env_encryption_key:submission_env_encryption_key" \
    "base_agent_challenge_database_url:database_url" \
    "${ac_gate_secret_specs[@]}"

  # agent-challenge worker sidecar (command `agent-challenge-worker`; see
  # cli_app/main.py worker_command metadata). It runs the own_runner eval loop and
  # dispatches the broker DooD job, so it needs the SAME eval-image allowlist as
  # the api plus the broker backend wiring. (Resolves the prior worker TODO.)
  # MUST carry the SAME constraint as the api above so both land on one node and share /data.
  CHALLENGE_EXTRA_CONSTRAINTS=("node.role==manager")
  CHALLENGE_ENV=(
    "${ac_eval_env[@]}"
    "CHALLENGE_BENCHMARK_BACKEND=terminal_bench"
    "CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND=own_runner"
    "CHALLENGE_DOCKER_ENABLED=true"
    "CHALLENGE_DOCKER_BACKEND=broker"
    "CHALLENGE_DOCKER_BROKER_URL=http://base-docker-broker:${MASTER_BROKER_PORT}"
    "CHALLENGE_DOCKER_BROKER_TOKEN_FILE=${SECRET_MOUNT_DIR}/docker_broker_token"
    "CHALLENGE_ARTIFACT_ROOT=/data"
  )
  CHALLENGE_CMD=("agent-challenge-worker" "--poll-interval" "5")
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    CHALLENGE_EXTRA_SECRETS=("source=base_gateway_token,target=base_gateway_token")
  fi
  _deploy_challenge_service \
    "challenge-agent-challenge-worker" "${IMAGE_AGENT_CHALLENGE}" "${AGENT_CHALLENGE_PORT}" \
    "base_agent_challenge_pg" \
    "base_agent_challenge_challenge_token:challenge_token" \
    "base_agent_challenge_docker_broker_token:docker_broker_token" \
    "base_agent_challenge_submission_env_encryption_key:submission_env_encryption_key" \
    "base_agent_challenge_database_url:database_url" \
    "${ac_gate_secret_specs[@]}"

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
  local -a prism_env=(
    "CHALLENGE_SLUG=prism"
    "CHALLENGE_DOCKER_ENABLED=true"
    "CHALLENGE_DOCKER_BACKEND=broker"
    "CHALLENGE_DOCKER_BROKER_URL=http://base-docker-broker:${MASTER_BROKER_PORT}"
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
  )
  # Route the prism llm_review gpt-4o gate through the master OpenRouter gateway when
  # a scoped token is provisioned. PRISM_LLM_GATEWAY_URL is the FULL gateway route
  # (prism uses it directly as the chat base_url); the scoped token comes from the
  # base_gateway_token secret mounted above. Absent => direct OpenRouter key fallback.
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    prism_env+=("PRISM_LLM_GATEWAY_URL=${GATEWAY_PUBLIC_BASE_URL}/llm/openrouter")
  fi
  # Host-side SCORER read-only mounts on the manager (NOT the eval container): the SECRET
  # held-out val split (matches PRISM_BASE_EVAL_VAL_DATA_DIR) and the non-secret TRAIN split
  # used ONLY for the converged-memorization-gap reference (matches PRISM_BASE_EVAL_TRAIN_DATA_DIR).
  # The val/test splits NEVER enter the network=none eval container; the eval container gets its
  # own copy of the locked TRAIN split via the broker's per-slug RO mount at /data/fineweb-edu/train.
  # Both are manager-local volumes, RO, and must be POPULATED + readable by the scorer uid 1000.
  local -a prism_scorer_mounts=(
    "type=volume,source=prism_fineweb_edu_val,destination=/secret/val,readonly=true"
    "type=volume,source=prism_fineweb_edu_train,destination=/secret/train,readonly=true"
  )
  # CENTRAL llm_review (gpt-4o) routing. Gateway mode ($CENTRAL_GATEWAY_TOKEN set):
  # mount the scoped base_gateway_token at /run/secrets/base_gateway_token (the
  # PrismSettings.llm_gateway_token_file default) — paired with the
  # PRISM_LLM_GATEWAY_URL set on prism_env above — so the gate routes through the
  # master OpenRouter gateway — NO direct provider key on the challenge services. Fallback (no gateway): mount the
  # OpenRouter key at the EXACT target prism reads (/run/secrets/openrouter_api_key —
  # config.py openrouter_api_key_file default), NOT the ${SECRET_MOUNT_DIR}/"base/"
  # subdir the positional SECRET_SPECs use. Passed verbatim via CHALLENGE_EXTRA_SECRETS
  # so the `base/` prefix is NOT applied. The fallback matches the LIVE stack (which
  # mounts the pre-existing base_or_key_real at the same target).
  local -a prism_extra_secrets=()
  if [[ "${central_gateway_enabled}" == "true" ]]; then
    prism_extra_secrets+=("source=base_gateway_token,target=base_gateway_token")
  else
    prism_extra_secrets+=("source=base_openrouter_api_key,target=openrouter_api_key")
  fi
  # HuggingFace checkpoint-publisher token (architecture.md §7): the prism HF
  # publisher reads it from /run/secrets/hf_token (PrismSettings.hf_token_file
  # default; HF_TOKEN_FILE). OPTIONAL — base_hf_token is only created when
  # $HF_TOKEN is set, so mount it only then (absent => publisher runs token-less,
  # fine for the public FineWeb-Edu repo). Mounted verbatim (no `base/` prefix).
  if [[ -n "${HF_TOKEN:-}" ]]; then
    prism_extra_secrets+=("source=base_hf_token,target=hf_token")
  fi
  # prism API service: manager-pinned (Defect E1) so it shares the per-node
  # base_prism_pg /data volume (SQLite at /data/prism.sqlite3) with the worker
  # below — Swarm volumes are per-node, so an unpinned api could land on a
  # different node from the worker and read a disjoint, empty database.
  CHALLENGE_ENV=("${prism_env[@]}")
  CHALLENGE_EXTRA_MOUNTS=("${prism_scorer_mounts[@]}")
  CHALLENGE_EXTRA_SECRETS=("${prism_extra_secrets[@]}")
  CHALLENGE_EXTRA_CONSTRAINTS=("node.role==manager")
  _deploy_challenge_service \
    "challenge-prism" "${IMAGE_PRISM}" "${PRISM_PORT}" \
    "base_prism_pg" \
    "base_prism_challenge_token:challenge_token" \
    "base_prism_docker_broker_token:docker_broker_token"

  # prism WORKER sidecar (Defect E1): the prism API ships with NO submission
  # processor (its lifespan only inits the DB), so a claimed-nothing submission
  # sits `pending` forever. This standing service runs `prism-worker` — the
  # claim/evaluate loop (worker.py:main, --interval-seconds poll) that dispatches
  # the broker GPU eval job and runs the host-side held-out scorer. It carries the
  # SAME env, scorer held-out mounts, OpenRouter review-gate secret, and the SAME
  # node.role==manager pin as the api so both co-locate on the base_prism_pg /data
  # volume (mirrors the agent-challenge api+worker pattern above).
  CHALLENGE_ENV=("${prism_env[@]}")
  CHALLENGE_EXTRA_MOUNTS=("${prism_scorer_mounts[@]}")
  CHALLENGE_EXTRA_SECRETS=("${prism_extra_secrets[@]}")
  CHALLENGE_EXTRA_CONSTRAINTS=("node.role==manager")
  CHALLENGE_CMD=("prism-worker" "--interval-seconds" "5")
  _deploy_challenge_service \
    "challenge-prism-worker" "${IMAGE_PRISM}" "${PRISM_PORT}" \
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
    --with-registry-auth
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
  local constraint_expr
  if [[ "${#CHALLENGE_EXTRA_CONSTRAINTS[@]}" -gt 0 ]]; then
    for constraint_expr in "${CHALLENGE_EXTRA_CONSTRAINTS[@]}"; do
      argv+=(--constraint "${constraint_expr}")
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
  CHALLENGE_EXTRA_CONSTRAINTS=()
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
    log "    http://127.0.0.1:${MASTER_BROKER_PORT}/health  (base-docker-broker)"
    log "    http://127.0.0.1:${MASTER_PROXY_PORT}/health   (base-master-proxy)"
    log "  and would verify challenge services converge to 1/1 replicas + overlay /health."
    return 0
  fi

  _http_health "base-docker-broker" "http://127.0.0.1:${MASTER_BROKER_PORT}/health"
  _http_health "base-master-proxy"  "http://127.0.0.1:${MASTER_PROXY_PORT}/health"

  if [[ "${STATIC_CHALLENGES}" == "true" ]]; then
    _service_converged "challenge-agent-challenge"
    _service_converged "challenge-agent-challenge-worker"  # sidecar: no /health port
    _service_converged "challenge-prism"
    _service_converged "challenge-prism-worker"  # sidecar: no /health port
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
# 12. deploy_supervisor()
#     Install + enable base-supervisor.service — the systemd control-plane
#     auto-update unit that REPLACES Watchtower (architecture.md G4). It runs the
#     image-updater (digest-pin roll of base-master-proxy + base-docker-broker),
#     challenge-image-updater, config-sync, and (optionally) self-update loops.
#
#     The image-updaters resolve PRIVATE ghcr.io/baseintelligence/* digests using
#     the manager's GHCR credentials (the docker config.json from ghcr_login); the
#     supervisor: block in the rendered master config points at it. The watched
#     images + intervals are enforced by build_scheduled_tasks (image-updater 60s,
#     challenge-image-updater 60s, config-sync 60s, self-update 300s).
#
#     SAFETY: this is a host-level systemd change behind its OWN flag
#     (--install-supervisor), NOT part of the default --apply path. Without the
#     flag it prints the install/enable commands + the MANDATORY Watchtower
#     decommission ordering as instructions only.
# ============================================================================
deploy_supervisor() {
  log "STEP 12/12 deploy_supervisor (control-plane auto-update; REPLACES Watchtower)"
  [[ -f "${SUPERVISOR_UNIT_SRC}" ]] || die "supervisor unit not found: ${SUPERVISOR_UNIT_SRC}"

  # Watched images + intervals the supervisor's scheduled jobs enforce (config
  # rendered into the supervisor: block of ${MASTER_CONFIG_PATH} by deploy_master).
  log "  watched images (image-updater, 60s): base-master-proxy + base-docker-broker -> ${IMAGE_MASTER%@*}@sha256:<digest>"
  log "  watched images (challenge-image-updater, 60s): challenge-* on their GHCR :latest tags -> :latest@sha256:<digest>"
  log "  config-sync interval: 60s; self-update interval: 300s"
  log "  registry digest auth: ${SUPERVISOR_REGISTRY} via ${SUPERVISOR_DOCKER_CONFIG_PATH} (decodes private baseintelligence digests)"
  if [[ -n "${SUPERVISOR_SELF_UPDATE_MANIFEST_URL}" ]]; then
    log "  self-update: ENABLED + wired (manifest_url=${SUPERVISOR_SELF_UPDATE_MANIFEST_URL})"
  else
    log "  self-update: EXPLICITLY DISABLED (no SUPERVISOR_SELF_UPDATE_MANIFEST_URL; task not registered — not inert)"
  fi

  # Watchtower decommission ordering (MANDATORY): the supervisor image-updater and
  # Watchtower must never both manage the same services, or they race
  # `docker service update` on base-master-proxy/base-docker-broker. Stop+remove
  # Watchtower FIRST, then enable the supervisor.
  log "  Watchtower decommission ordering (do BEFORE enabling the supervisor):"
  log "    1) docker service rm platform-watchtower   # or: docker rm -f watchtower (compose/standalone)"
  log "    2) docker ps -a | grep -i watchtower       # confirm NOTHING remains (no racing updater)"
  log "    3) THEN install + enable base-supervisor.service (below)"
  log "  Rollback ordering (reverse): systemctl disable --now base-supervisor.service FIRST, then re-add Watchtower."

  if [[ "${INSTALL_SUPERVISOR}" == "true" ]]; then
    warn "installing + enabling base-supervisor.service (--install-supervisor)"
    plan install -d -m 0755 "${SUPERVISOR_RELEASE_ROOT}"
    plan install -m 0644 "${SUPERVISOR_UNIT_SRC}" "${SUPERVISOR_UNIT_DST}"
    plan systemctl daemon-reload
    plan systemctl enable --now base-supervisor.service
    log "  base-supervisor.service installed + enabled"
  else
    log "  --install-supervisor NOT set: skipping systemd install. To install (AFTER Watchtower is gone):"
    log "    install -d -m 0755 ${SUPERVISOR_RELEASE_ROOT}"
    log "    # stage the release checkout at ${SUPERVISOR_RELEASE_ROOT}/current (uv-managed; see base-supervisor.service)"
    log "    install -m 0644 ${SUPERVISOR_UNIT_SRC} ${SUPERVISOR_UNIT_DST}"
    log "    systemctl daemon-reload"
    log "    systemctl enable --now base-supervisor.service"
  fi
}

# ============================================================================
# 13. OUT OF SCOPE — node teardown
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
  log "  install-supervisor  : ${INSTALL_SUPERVISOR}  (systemd; replaces Watchtower; opt-in)"
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
  deploy_supervisor          # 12 (control-plane auto-update; install/enable behind --install-supervisor)
  # 13 node teardown: OUT OF SCOPE (see comment block above).

  log "============================================================"
  if [[ "${APPLY}" == "true" ]]; then
    log "Bring-up steps executed. Verify master + both challenges are healthy."
  else
    log "Dry-run complete. Review the planned actions above, then re-run with --apply."
  fi
  log "============================================================"
}

main "$@"

#!/usr/bin/env bash
#
# install-worker.sh — enroll THIS host as a CPU or GPU worker into the BASE
# Docker Swarm, using the MANUAL join-token model (NO SSH).
#
# ============================================================================
# STATUS: DRAFT FOR HUMAN REVIEW. DO NOT EXECUTE BLINDLY.
# ============================================================================
#
# Run this ON THE WORKER HOST. It does NOT reach out to the manager over SSH and
# it does NOT fetch the join token for you. The operator obtains the token on the
# manager first:
#
#     # on the MANAGER:
#     base master worker token --cpu      # or --gpu
#       -> prints: docker swarm join --token <TOKEN> <MANAGER_IP>:2377
#
# then runs THIS script on the worker with that token + manager address, and
# finally labels the node back ON THE MANAGER (printed at the end here):
#
#     base master worker label <node> --workload cpu|gpu
#
# What this script does (in order):
#   1. preflight       — docker present, required inputs supplied (read-only).
#   1b. ghcr_login     — authenticate to ghcr.io so deploy-time pulls of the
#                        private ghcr.io/baseintelligence/* images work on this
#                        worker. Credentials come from the RUNTIME env
#                        (GHCR_USER / GHCR_TOKEN); token is fed on stdin (never
#                        argv, never logged, never hardcoded). Non-fatal skip
#                        when the vars are unset (the manager can still ship
#                        creds per-service via `docker service create
#                        --with-registry-auth`). Mirrors install-swarm.sh.
#   2. daemon.json     — prepare the right worker daemon.json:
#                          cpu -> deploy/swarm/daemon.cpu-worker.json (as-is)
#                          gpu -> deploy/swarm/daemon.worker.json with the GPU
#                                 generic-resource UUID(s) substituted from
#                                 `nvidia-smi`. Installed + dockerd restarted
#                                 ONLY behind --restart-dockerd.
#   3. swarm join      — docker swarm join --token <token> <manager-addr>.
#   4. follow-up       — print the manager-side `base master worker label`.
#
# Safety model (mirrors deploy/swarm/install-swarm.sh):
#   * DEFAULT MODE IS DRY-RUN. With no flags the script prints every planned
#     mutating command (via `plan`) and changes NOTHING. Pass --apply to execute.
#   * Engine restart is DESTRUCTIVE and gated behind its OWN flag
#     (--restart-dockerd); the default --apply path does NOT touch dockerd.
#
# Secret handling:
#   * The join token is NEVER hardcoded and NEVER printed. Supply it via the
#     JOIN_TOKEN environment variable (preferred — keeps it off argv/history) or
#     --join-token <token>. Docker provides no stdin form for `docker swarm
#     join`, so under --apply the token is passed on argv to that single command
#     only; it is otherwise redacted in all plan/log output.
#
# shellcheck disable=SC2310
#   SC2310: functions used as `if ...; then` conditions lose `set -e` inside.
#   Intentional — preflight/capability probes are evaluated as booleans.
# ----------------------------------------------------------------------------

set -euo pipefail

# ============================================================================
# Configuration (overridable via flags / environment). NO secrets here.
# ============================================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd -P)"

# Directory holding the worker daemon.json templates.
SWARM_DIR="${SWARM_DIR:-${REPO_ROOT}/deploy/swarm}"

# Destination daemon.json on this host.
DAEMON_JSON_DST="${DAEMON_JSON_DST:-/etc/docker/daemon.json}"

# Placeholder UUID inside daemon.worker.json that gets replaced with the real
# GPU UUID(s) on a GPU worker (MUST match deploy/swarm/daemon.worker.json).
GPU_PLACEHOLDER_UUID="GPU-00000000-0000-0000-0000-000000000000"

# Minimum Docker engine major version expected on a Swarm node.
MIN_DOCKER_MAJOR=29

# ============================================================================
# Flags / inputs (all default to the SAFE / non-mutating value).
# ============================================================================
APPLY=false               # false => dry-run (print only). Mutating requires --apply.
RESTART_DOCKERD=false      # opt-in: install daemon.json + restart dockerd (DESTRUCTIVE).
MANAGER_ADDR=""            # <ip:2377> of the Swarm manager (required).
WORKLOAD=""                # cpu | gpu (required).
JOIN_TOKEN="${JOIN_TOKEN:-}"   # worker join token (env preferred; never logged).
GHCR_USER="${GHCR_USER:-}"     # ghcr.io username for private image pulls (non-secret).
GHCR_TOKEN="${GHCR_TOKEN:-}"   # ghcr.io token; stdin-only, never argv/logged/hardcoded.

# Resolved during prepare_daemon_json().
DAEMON_JSON_STAGED=""      # path to the daemon.json that WOULD be installed.
DAEMON_JSON_TMP=""         # mktemp scratch file to remove on exit (gpu path only).

cleanup() {
  [[ -n "${DAEMON_JSON_TMP}" && -f "${DAEMON_JSON_TMP}" ]] && rm -f "${DAEMON_JSON_TMP}"
  return 0
}
trap cleanup EXIT

# ============================================================================
# Output helpers
# ============================================================================
log()  { printf '[install-worker] %s\n' "$*"; }
warn() { printf '[install-worker][WARN] %s\n' "$*" >&2; }
die()  { printf '[install-worker][FATAL] %s\n' "$*" >&2; exit 1; }

# `plan CMD...` is the single execution gate:
#   * dry-run (default): print the command, run nothing.
#   * --apply: print, then execute exactly that argv.
# The join token must NEVER pass through `plan` (it would be printed) — see
# swarm_join() which redacts it explicitly.
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

plan_secret_stdin() {
  local label="$1" envvar="$2"
  shift 2
  [[ "$1" == "--" ]] || die "plan_secret_stdin: expected -- separator"
  shift
  printf '  + %s   # stdin: value from $%s (hidden)\n' "$(_quote_argv "$@")" "${envvar}"
  if [[ "${APPLY}" == "true" ]]; then
    printf '%s' "${!envvar}" | "$@"
  fi
  : "${label}"
}

# ============================================================================
# Argument parsing
# ============================================================================
usage() {
  cat <<'EOF'
Usage: install-worker.sh --manager-addr <ip:2377> --workload cpu|gpu [OPTIONS]

Enroll THIS host as a CPU or GPU worker into the BASE Docker Swarm using the
manual join-token model (no SSH). DEFAULT MODE IS DRY-RUN (prints planned
actions, changes nothing).

Required:
  --manager-addr <ip:2377>   Swarm manager advertise address to join.
  --workload cpu|gpu         Worker class. Selects the daemon.json template and
                             the label hint printed for the manager.
  Join token                 Supply via JOIN_TOKEN env (preferred) or
                             --join-token <token>. NEVER hardcode it.

Optional (private image pulls):
  GHCR_USER / GHCR_TOKEN     ghcr.io credentials for pulling private
                             ghcr.io/baseintelligence/* images on this worker.
                             Supplied at runtime via env; the token is fed on
                             stdin only (never argv/logged/hardcoded). If unset,
                             the ghcr.io login step is skipped (non-fatal) and
                             the worker relies on the manager's per-service
                             'docker service create --with-registry-auth'.

Safety flags:
  --apply                    Execute mutating commands. Without this, dry-run only.
  --restart-dockerd          Install daemon.json + restart dockerd (DESTRUCTIVE;
                             not part of the default --apply path).

Other:
  --join-token <token>       Worker join token (env JOIN_TOKEN preferred so the
                             value stays off argv / shell history).
  --dry-run                  Force dry-run (default).
  -h, --help                 Show this help.

Get the token first ON THE MANAGER:
  base master worker token --cpu   # or --gpu
After this script joins, label the node ON THE MANAGER:
  base master worker label <node> --workload cpu|gpu
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=true ;;
      --dry-run) APPLY=false ;;
      --restart-dockerd) RESTART_DOCKERD=true ;;
      --manager-addr) MANAGER_ADDR="${2:?--manager-addr needs a value}"; shift ;;
      --join-token) JOIN_TOKEN="${2:?--join-token needs a value}"; shift ;;
      --workload) WORKLOAD="${2:?--workload needs a value}"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
  done
}

# ============================================================================
# 1. preflight() — docker present + required inputs supplied. Read-only.
# ============================================================================
preflight() {
  log "STEP 1/3 preflight: validating host + inputs (read-only)"

  command -v docker >/dev/null 2>&1 || die "docker CLI not found on PATH"

  local docker_version major
  docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  if [[ -n "${docker_version}" ]]; then
    major="${docker_version%%.*}"
    if [[ "${major}" =~ ^[0-9]+$ ]] && (( major < MIN_DOCKER_MAJOR )); then
      warn "  docker server version ${docker_version} < ${MIN_DOCKER_MAJOR} (Swarm worker expects ${MIN_DOCKER_MAJOR}.x)"
    else
      log "  docker server version ${docker_version} OK"
    fi
  else
    warn "  could not query docker server version (is dockerd running?)"
  fi

  [[ -n "${MANAGER_ADDR}" ]] || die "--manager-addr <ip:2377> is required"
  [[ -n "${WORKLOAD}" ]] || die "--workload <cpu|gpu> is required"
  [[ "${WORKLOAD}" == "cpu" || "${WORKLOAD}" == "gpu" ]] \
    || die "--workload must be 'cpu' or 'gpu' (got: '${WORKLOAD}')"
  [[ -n "${JOIN_TOKEN}" ]] \
    || die "join token required: set JOIN_TOKEN env (preferred) or pass --join-token (NEVER hardcode)"

  log "  inputs OK (workload=${WORKLOAD}, manager=${MANAGER_ADDR}, token present)"
}

ghcr_login() {
  log "STEP 1b/3 ghcr_login: authenticate to ghcr.io for private image pulls"
  if [[ -z "${GHCR_USER}" || -z "${GHCR_TOKEN}" ]]; then
    warn "  GHCR_USER/GHCR_TOKEN not set: skipping ghcr.io login."
    warn "  Private ghcr.io/baseintelligence/* pulls on this worker will then rely"
    warn "  on the manager shipping creds per-service ('docker service create"
    warn "  --with-registry-auth'). Set GHCR_USER/GHCR_TOKEN to enable direct"
    warn "  'docker pull' on this node. (Never hardcode the token.)"
    return 0
  fi
  plan_secret_stdin "ghcr-login" GHCR_TOKEN -- \
    docker login ghcr.io --username "${GHCR_USER}" --password-stdin
}

# ============================================================================
# 2a. prepare_daemon_json()
#     Resolve DAEMON_JSON_STAGED — the daemon.json that WOULD be installed.
#       cpu: deploy/swarm/daemon.cpu-worker.json verbatim (no GPU plumbing).
#       gpu: deploy/swarm/daemon.worker.json with the placeholder GPU UUID
#            line replaced by one "NVIDIA-GPU=GPU-<uuid>" entry per physical GPU
#            reported by `nvidia-smi`. Read-only (writes only a temp file).
# ============================================================================
prepare_daemon_json() {
  case "${WORKLOAD}" in
    cpu)
      DAEMON_JSON_STAGED="${SWARM_DIR}/daemon.cpu-worker.json"
      [[ -f "${DAEMON_JSON_STAGED}" ]] || die "daemon template not found: ${DAEMON_JSON_STAGED}"
      log "  cpu worker: using ${DAEMON_JSON_STAGED} (no GPU generic resource, no nvidia runtime)"
      ;;
    gpu)
      local tmpl="${SWARM_DIR}/daemon.worker.json"
      [[ -f "${tmpl}" ]] || die "daemon template not found: ${tmpl}"
      command -v nvidia-smi >/dev/null 2>&1 \
        || die "--workload gpu requires nvidia-smi on PATH (not found)"

      local -a uuids=()
      local u
      while IFS= read -r u; do
        [[ -n "${u}" ]] && uuids+=("${u}")
      done < <(nvidia-smi --query-gpu=uuid --format=csv,noheader 2>/dev/null | grep -E '^GPU-' || true)
      [[ "${#uuids[@]}" -ge 1 ]] \
        || die "nvidia-smi returned no GPU UUIDs; cannot advertise the NVIDIA-GPU generic resource"

      # Build the replacement JSON element lines (4-space indented, comma-joined).
      local repl="" i comma
      for i in "${!uuids[@]}"; do
        comma=","
        [[ $((i + 1)) -eq "${#uuids[@]}" ]] && comma=""
        repl+="    \"NVIDIA-GPU=${uuids[$i]}\"${comma}"$'\n'
      done

      DAEMON_JSON_TMP="$(mktemp)"
      DAEMON_JSON_STAGED="${DAEMON_JSON_TMP}"
      awk -v repl="${repl}" -v ph="${GPU_PLACEHOLDER_UUID}" \
        'index($0, ph) { printf "%s", repl; next } { print }' \
        "${tmpl}" > "${DAEMON_JSON_STAGED}"
      log "  gpu worker: rendered daemon.json with ${#uuids[@]} GPU UUID(s) from nvidia-smi"
      ;;
    *)
      die "--workload must be 'cpu' or 'gpu' (got: '${WORKLOAD}')"
      ;;
  esac
}

# ============================================================================
# 2b. apply_daemon_json()  [engine restart DESTRUCTIVE — behind --restart-dockerd]
#     Install DAEMON_JSON_STAGED to /etc/docker/daemon.json and restart dockerd
#     ONLY when --restart-dockerd is set. Otherwise print the prepared file and
#     the manual steps. `dockerd --validate` runs when dockerd is available.
# ============================================================================
apply_daemon_json() {
  log "STEP 2/3 daemon.json (workload=${WORKLOAD})"

  if [[ "${RESTART_DOCKERD}" != "true" ]]; then
    log "  --restart-dockerd NOT set: not installing daemon.json or restarting dockerd."
    log "  Prepared daemon.json that WOULD be installed to ${DAEMON_JSON_DST}:"
    sed 's/^/      /' "${DAEMON_JSON_STAGED}"
    log "  To apply manually (DESTRUCTIVE — restarts the engine):"
    log "    1) cp ${DAEMON_JSON_STAGED} ${DAEMON_JSON_DST}   # merge, do not clobber existing keys"
    log "    2) dockerd --validate --config-file ${DAEMON_JSON_DST}   # expect 'configuration OK'"
    log "    3) systemctl restart docker"
    if command -v dockerd >/dev/null 2>&1; then
      log "  validating the prepared candidate (read-only, no restart):"
      plan dockerd --validate --config-file "${DAEMON_JSON_STAGED}"
    else
      warn "  dockerd not on PATH — skipping --validate of the prepared candidate"
    fi
    return 0
  fi

  warn "DESTRUCTIVE: --restart-dockerd set — installing daemon.json and restarting dockerd"
  # Keep a timestamped backup of any existing daemon.json before overwriting.
  if [[ -f "${DAEMON_JSON_DST}" ]]; then
    plan cp -a "${DAEMON_JSON_DST}" "${DAEMON_JSON_DST}.bak.$(date +%Y%m%d%H%M%S)"
  fi
  plan install -m 0644 "${DAEMON_JSON_STAGED}" "${DAEMON_JSON_DST}"
  if command -v dockerd >/dev/null 2>&1; then
    plan dockerd --validate --config-file "${DAEMON_JSON_DST}"
  else
    warn "  dockerd not on PATH — skipping --validate (cannot validate ${DAEMON_JSON_DST})"
  fi
  plan systemctl restart docker
  log "  daemon.json installed and dockerd restart requested"
}

# ============================================================================
# 3. swarm_join()
#    docker swarm join --token <token> <manager-addr>. The token is redacted in
#    the plan log and passed on argv only under --apply (Docker has no stdin
#    form for join). Idempotent: skip if already in a swarm.
# ============================================================================
swarm_join() {
  log "STEP 3/3 swarm join -> ${MANAGER_ADDR} (token hidden)"

  local swarm_state
  swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unknown)"
  if [[ "${swarm_state}" == "active" ]]; then
    log "  node already in a swarm (state=active) — skipping join (idempotent)."
    log "  To re-join a different manager: 'docker swarm leave' first, then re-run."
    return 0
  fi

  # shellcheck disable=SC2016  # literal placeholder; $JOIN_TOKEN must NOT expand (token stays hidden)
  printf '  + docker swarm join --token <hidden:$JOIN_TOKEN> %s\n' "$(_quote_argv "${MANAGER_ADDR}")"
  if [[ "${APPLY}" == "true" ]]; then
    docker swarm join --token "${JOIN_TOKEN}" "${MANAGER_ADDR}"
    log "  swarm join executed"
  fi
}

# ============================================================================
# follow-up — manager-side labeling step (NOT run here; printed for operator).
# ============================================================================
print_followup() {
  local node
  node="$(hostname 2>/dev/null || echo '<this-worker-node>')"
  log "============================================================"
  log "NEXT — run ON THE MANAGER node (NOT on this worker):"
  log "  1) Confirm the new node name:   docker node ls"
  log "  2) Label this worker:           base master worker label ${node} --workload ${WORKLOAD}"
  log "     (verify '${node}' against 'docker node ls'; it defaults to this host's hostname)"
  log "============================================================"
}

# ============================================================================
# main
# ============================================================================
main() {
  parse_args "$@"

  log "============================================================"
  log "BASE Swarm worker enrollment (DRAFT)"
  if [[ "${APPLY}" == "true" ]]; then
    warn "RUNNING IN --apply MODE: mutating commands WILL execute."
  else
    log "DRY-RUN (default): printing planned actions only. Pass --apply to execute."
  fi
  log "  manager-addr     : ${MANAGER_ADDR:-<unset>}"
  log "  workload         : ${WORKLOAD:-<unset>}"
  log "  restart-dockerd  : ${RESTART_DOCKERD}   (destructive; opt-in)"
  log "  join token       : $([[ -n "${JOIN_TOKEN}" ]] && echo 'present (hidden)' || echo '<unset>')"
  log "  ghcr.io login    : $([[ -n "${GHCR_USER}" && -n "${GHCR_TOKEN}" ]] && echo 'enabled (token hidden)' || echo 'skipped (no GHCR_USER/GHCR_TOKEN)')"
  log "============================================================"

  preflight            # 1
  ghcr_login           # 1b (ghcr.io auth for private pulls; skip if no creds)
  prepare_daemon_json  # 2a (read-only render)
  apply_daemon_json    # 2b (DESTRUCTIVE behind --restart-dockerd)
  swarm_join           # 3
  print_followup       # manager-side label hint

  log "============================================================"
  if [[ "${APPLY}" == "true" ]]; then
    log "Worker steps executed. Finish by labeling the node on the manager (above)."
  else
    log "Dry-run complete. Review the planned actions above, then re-run with --apply."
  fi
  log "============================================================"
}

main "$@"

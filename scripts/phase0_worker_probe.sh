#!/usr/bin/env bash
# phase0_worker_probe.sh — Phase-0 worker capability verification (READ-ONLY).
#
# Purpose (plan: .omo/plans/platform-docker-migration.md, Task 1):
#   Verify, on GPU worker (default 31.22.104.113), every downstream assumption
#   of the Kubernetes -> Docker Swarm migration BEFORE any mutating step:
#     - dockerd installed + version (expect 29.x)
#     - nvidia-container-toolkit wired into dockerd
#     - GPU visible to containers (single APPROVED ephemeral test container)
#     - Docker 29.x --privileged flag support on `docker run`
#     - Swarm ports 2377/tcp, 7946/tcp+udp, 4789/udp reachable validator<->worker
#     - overlay encryption feasibility (ESP/xfrm kernel support) across public IPs
#     - MTU 1450 viability (1422-byte unfragmented payload + overlay headroom)
#
# POLICY — READ THIS BEFORE RUNNING:
#   * This script is STRICTLY READ-ONLY. It never mutates daemon config, never
#     joins/initializes Swarm, never creates services, networks, volumes, or
#     persistent containers, and never prunes anything.
#   * The ONLY container action permitted is the single ephemeral GPU test:
#         docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
#     This is the explicitly APPROVED EXCEPTION (auto-removed via --rm).
#   * Live SSH to the worker is GO-GATED. Default mode is --report-only, which
#     performs NO ssh and emits every worker-side assumption as BOUNDED BLOCKER.
#     Pass --go ONLY after a human has approved SSH access and provisioned a key.
#
# Usage:
#   Report-only (default; safe, no SSH, exits non-zero with blocker matrix):
#     scripts/phase0_worker_probe.sh --report-only [--worker-ip IP]
#   Live probe (HUMAN GO REQUIRED; key must authenticate to the worker):
#     scripts/phase0_worker_probe.sh --go --ssh-key /path/to/worker.pem \
#         [--worker-ip 31.22.104.113] [--validator-ip 51.83.112.164] \
#         [--ssh-timeout 30]
#
# Output: machine-greppable matrix lines of the form
#   ASSUMPTION | STATUS(VERIFIED|BOUNDED BLOCKER|FAIL) | EVIDENCE/REASON
# Exit codes: 0 = all assumptions VERIFIED; 2 = bounded blockers present;
#             1 = at least one hard FAIL (or usage error).

set -euo pipefail
umask 077

WORKER_IP="31.22.104.113"
VALIDATOR_IP="51.83.112.164"
SSH_KEY=""
SSH_TIMEOUT=30
MODE="report-only"

# Validator-side facts already established by the prior read-only probe of
# 51.83.112.164 (session evidence; /validator.pem authenticates to validator only).
VALIDATOR_DOCKER_VERSION_KNOWN="29.1.3"

GPU_TEST_IMAGE="nvidia/cuda:12.4.1-base-ubuntu22.04"

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-only) MODE="report-only"; shift ;;
    --go)          MODE="go"; shift ;;
    --worker-ip)   WORKER_IP="$2"; shift 2 ;;
    --validator-ip) VALIDATOR_IP="$2"; shift 2 ;;
    --ssh-key)     SSH_KEY="$2"; shift 2 ;;
    --ssh-timeout) SSH_TIMEOUT="$2"; shift 2 ;;
    -h|--help)     usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

if [[ "$MODE" == "go" && -z "$SSH_KEY" ]]; then
  echo "ERROR: --go requires --ssh-key (human-provisioned worker key)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Matrix bookkeeping
# ---------------------------------------------------------------------------
declare -a MATRIX_ROWS=()
HAS_BLOCKER=0
HAS_FAIL=0

row() { # row <assumption> <status> <evidence>
  local assumption="$1" status="$2" evidence="$3"
  MATRIX_ROWS+=("${assumption} | ${status} | ${evidence}")
  case "$status" in
    "BOUNDED BLOCKER") HAS_BLOCKER=1 ;;
    "FAIL")            HAS_FAIL=1 ;;
  esac
}

print_matrix() {
  echo ""
  echo "==================== PHASE-0 GO/NO-GO MATRIX ===================="
  echo "ASSUMPTION | STATUS(VERIFIED|BOUNDED BLOCKER|FAIL) | EVIDENCE/REASON"
  echo "------------------------------------------------------------------"
  local r
  for r in "${MATRIX_ROWS[@]}"; do
    echo "$r"
  done
  echo "------------------------------------------------------------------"
  if [[ "$HAS_FAIL" -eq 1 ]]; then
    echo "VERDICT: NO-GO (hard failure present)"
  elif [[ "$HAS_BLOCKER" -eq 1 ]]; then
    echo "VERDICT: NO-GO (bounded blockers present; awaiting human GO + worker key provisioning)"
  else
    echo "VERDICT: GO (all assumptions verified)"
  fi
  echo "=================================================================="
}

# ---------------------------------------------------------------------------
# SSH helper — the contractual invocation pattern (GO mode only).
# Pattern: timeout -s KILL <N> ssh -i <key> -o BatchMode=yes \
#            -o StrictHostKeyChecking=no -o ConnectTimeout=15 root@<ip> '<cmd>' </dev/null
# READ-ONLY commands only. Never invoked in report-only mode.
# ---------------------------------------------------------------------------
worker_ssh() {
  timeout -s KILL "$SSH_TIMEOUT" \
    ssh -i "$SSH_KEY" \
      -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=15 \
      "root@${WORKER_IP}" "$1" </dev/null
}

# TCP reachability without ssh: pure bash /dev/tcp probe, bounded by timeout.
tcp_reachable() { # tcp_reachable <ip> <port> <timeout-seconds>
  timeout "$3" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# Best-effort UDP probe (UDP is connectionless; absence of ICMP unreachable is
# only weak evidence — recorded as such in the matrix evidence column).
udp_probe() { # udp_probe <ip> <port> <timeout-seconds>
  if command -v nc >/dev/null 2>&1; then
    nc -u -z -w "$3" "$1" "$2" >/dev/null 2>&1
  else
    timeout "$3" bash -c "exec 3<>/dev/udp/$1/$2 && echo probe >&3" 2>/dev/null
  fi
}

BLOCK_REASON="worker SSH publickey-denied; awaiting human GO + key provisioning"

emit_all_worker_blockers() {
  local reason="$1"
  row "worker-ssh-access (root@${WORKER_IP})"                        "BOUNDED BLOCKER" "$reason"
  row "worker-dockerd-installed-29.x"                                 "BOUNDED BLOCKER" "$reason"
  row "worker-nvidia-container-toolkit-wired-to-dockerd"              "BOUNDED BLOCKER" "$reason"
  row "worker-gpu-container-ephemeral-test (docker run --rm --gpus all ${GPU_TEST_IMAGE} nvidia-smi)" \
                                                                      "BOUNDED BLOCKER" "$reason"
  row "worker-docker29-privileged-flag-on-docker-run"                 "BOUNDED BLOCKER" "$reason"
  row "swarm-port-2377-tcp-validator-to-worker"                       "BOUNDED BLOCKER" "$reason; port not probed (no GO)"
  row "swarm-port-7946-tcp-bidirectional"                             "BOUNDED BLOCKER" "$reason; port not probed (no GO)"
  row "swarm-port-7946-udp-bidirectional"                             "BOUNDED BLOCKER" "$reason; port not probed (no GO)"
  row "swarm-port-4789-udp-vxlan-data-plane"                          "BOUNDED BLOCKER" "$reason; port not probed (no GO)"
  row "overlay-encryption-feasible-public-ips (ESP proto 50 / xfrm)"  "BOUNDED BLOCKER" "$reason; kernel module check requires worker SSH"
  row "mtu-1450-viable (ping -M do -s 1422 across path)"              "BOUNDED BLOCKER" "$reason; path MTU not probed (no GO)"
  row "gpu-via-swarm-generic-resource (downstream of toolkit+GPU test)" "BOUNDED BLOCKER" "$reason; depends on unverified worker GPU stack"
}

# ---------------------------------------------------------------------------
# Validator-side known facts (prior read-only probe of ${VALIDATOR_IP}).
# These were verified in an earlier session with /validator.pem (validator only).
# ---------------------------------------------------------------------------
emit_validator_known_facts() {
  row "validator-docker-active-${VALIDATOR_DOCKER_VERSION_KNOWN}" "VERIFIED" \
      "prior read-only probe of ${VALIDATOR_IP}: docker version reported ${VALIDATOR_DOCKER_VERSION_KNOWN}, daemon active"
  row "validator-swarm-currently-inactive" "VERIFIED" \
      "prior read-only probe of ${VALIDATOR_IP}: docker info showed Swarm: inactive (clean precondition)"
  row "validator-nvidia-ctk-absent (expected; validator has no GPU)" "VERIFIED" \
      "prior read-only probe of ${VALIDATOR_IP}: nvidia-ctk not found; acceptable, GPU work runs on worker only"
}

# ---------------------------------------------------------------------------
# GO-mode live checks (all READ-ONLY; single approved ephemeral GPU container).
# ---------------------------------------------------------------------------
run_go_checks() {
  local out

  # A1: SSH access at all
  if out=$(worker_ssh 'echo ssh-ok && uname -r' 2>&1); then
    row "worker-ssh-access (root@${WORKER_IP})" "VERIFIED" "ssh ok; kernel: $(echo "$out" | tail -1)"
  else
    emit_all_worker_blockers "live SSH attempt failed: $(echo "$out" | head -1)"
    return
  fi

  # A2: dockerd installed + version 29.x (read-only version query)
  if out=$(worker_ssh "docker version --format '{{.Server.Version}}'" 2>&1); then
    if [[ "$out" == 29.* ]]; then
      row "worker-dockerd-installed-29.x" "VERIFIED" "docker server version: $out"
    else
      row "worker-dockerd-installed-29.x" "FAIL" "docker server version is '$out', expected 29.x"
    fi
  else
    row "worker-dockerd-installed-29.x" "FAIL" "docker version query failed: $(echo "$out" | head -1)"
  fi

  # A3: nvidia-container-toolkit wired to dockerd (read-only: version + runtime list)
  local ctk_ver runtimes
  ctk_ver=$(worker_ssh 'nvidia-ctk --version 2>/dev/null || echo ABSENT')
  runtimes=$(worker_ssh "docker info --format '{{json .Runtimes}}' 2>/dev/null" || echo '{}')
  if [[ "$ctk_ver" != "ABSENT" && "$runtimes" == *nvidia* ]]; then
    row "worker-nvidia-container-toolkit-wired-to-dockerd" "VERIFIED" \
        "nvidia-ctk: ${ctk_ver}; docker info Runtimes includes nvidia"
  else
    row "worker-nvidia-container-toolkit-wired-to-dockerd" "FAIL" \
        "nvidia-ctk=${ctk_ver}; runtimes=${runtimes} (nvidia runtime not wired)"
  fi

  # A4: APPROVED EXCEPTION — the single ephemeral GPU test container.
  # This is the ONLY container action this script may perform (auto-removed, --rm).
  if out=$(worker_ssh "docker run --rm --gpus all ${GPU_TEST_IMAGE} nvidia-smi" 2>&1); then
    row "worker-gpu-container-ephemeral-test (docker run --rm --gpus all ${GPU_TEST_IMAGE} nvidia-smi)" \
        "VERIFIED" "exit 0; nvidia-smi header: $(echo "$out" | head -1)"
  else
    row "worker-gpu-container-ephemeral-test (docker run --rm --gpus all ${GPU_TEST_IMAGE} nvidia-smi)" \
        "FAIL" "ephemeral GPU test failed: $(echo "$out" | head -1)"
  fi

  # A5: Docker 29.x --privileged support on docker run (READ-ONLY: flag presence
  # in CLI help only; an actual privileged container run is NOT performed here —
  # runtime privileged behavior is exercised later by the GO-gated plan tasks).
  if worker_ssh "docker run --help 2>&1 | grep -q -- '--privileged'"; then
    row "worker-docker29-privileged-flag-on-docker-run" "VERIFIED" \
        "docker run --help advertises --privileged on Docker 29.x (runtime behavior deferred to GO-gated task)"
  else
    row "worker-docker29-privileged-flag-on-docker-run" "FAIL" \
        "--privileged not present in docker run --help output"
  fi

  # A6-A9: Swarm ports validator<->worker. NOTE: before Swarm is initialized
  # nothing listens on these ports, so connection-refused vs filtered must be
  # interpreted by the operator; we record raw reachability evidence.
  if tcp_reachable "$WORKER_IP" 2377 5; then
    row "swarm-port-2377-tcp-validator-to-worker" "VERIFIED" "tcp connect to ${WORKER_IP}:2377 succeeded"
  else
    row "swarm-port-2377-tcp-validator-to-worker" "BOUNDED BLOCKER" \
        "no listener/blocked on ${WORKER_IP}:2377 (expected pre-Swarm; firewall must allow before init)"
  fi
  if tcp_reachable "$WORKER_IP" 7946 5; then
    row "swarm-port-7946-tcp-bidirectional" "VERIFIED" "tcp connect to ${WORKER_IP}:7946 succeeded"
  else
    row "swarm-port-7946-tcp-bidirectional" "BOUNDED BLOCKER" \
        "no listener/blocked on ${WORKER_IP}:7946 (expected pre-Swarm; firewall must allow before init)"
  fi
  if udp_probe "$WORKER_IP" 7946 5; then
    row "swarm-port-7946-udp-bidirectional" "VERIFIED" "udp probe to ${WORKER_IP}:7946 returned no ICMP-unreachable (weak positive)"
  else
    row "swarm-port-7946-udp-bidirectional" "BOUNDED BLOCKER" "udp probe inconclusive/blocked (UDP probing is best-effort)"
  fi
  if udp_probe "$WORKER_IP" 4789 5; then
    row "swarm-port-4789-udp-vxlan-data-plane" "VERIFIED" "udp probe to ${WORKER_IP}:4789 returned no ICMP-unreachable (weak positive)"
  else
    row "swarm-port-4789-udp-vxlan-data-plane" "BOUNDED BLOCKER" "udp probe inconclusive/blocked (UDP probing is best-effort)"
  fi

  # A10: overlay encryption feasibility — read-only kernel capability check on worker.
  if out=$(worker_ssh "lsmod | grep -E 'xfrm|esp4|esp6' || modprobe -n -v esp4 2>/dev/null" 2>&1) && [[ -n "$out" ]]; then
    row "overlay-encryption-feasible-public-ips (ESP proto 50 / xfrm)" "VERIFIED" \
        "worker kernel exposes xfrm/esp support: $(echo "$out" | head -1); ESP-over-public-internet still needs provider firewall allowance"
  else
    row "overlay-encryption-feasible-public-ips (ESP proto 50 / xfrm)" "BOUNDED BLOCKER" \
        "could not confirm xfrm/esp kernel support read-only; verify before enabling encrypted overlay"
  fi

  # A11: MTU 1450 viability — 1422-byte ICMP payload + 28-byte ICMP/IP header = 1450,
  # leaving 50 bytes of VXLAN headroom on a standard 1500 path.
  if out=$(ping -M do -c 3 -W 3 -s 1422 "$WORKER_IP" 2>&1); then
    row "mtu-1450-viable (ping -M do -s 1422 across path)" "VERIFIED" \
        "unfragmented 1422-byte payload delivered to ${WORKER_IP}"
  else
    row "mtu-1450-viable (ping -M do -s 1422 across path)" "FAIL" \
        "DF ping at 1422 bytes failed: $(echo "$out" | tail -1)"
  fi

  # A12: downstream synthesis — GPU via Swarm generic-resource is feasible only
  # if toolkit wiring + ephemeral GPU test both verified above.
  local gpu_row toolkit_row
  gpu_row=$(printf '%s\n' "${MATRIX_ROWS[@]}" | grep 'worker-gpu-container-ephemeral-test' || true)
  toolkit_row=$(printf '%s\n' "${MATRIX_ROWS[@]}" | grep 'worker-nvidia-container-toolkit-wired' || true)
  if [[ "$gpu_row" == *"| VERIFIED |"* && "$toolkit_row" == *"| VERIFIED |"* ]]; then
    row "gpu-via-swarm-generic-resource (downstream of toolkit+GPU test)" "VERIFIED" \
        "toolkit wired + ephemeral GPU test passed; generic-resource advertisement is a config step (GO-gated, not performed here)"
  else
    row "gpu-via-swarm-generic-resource (downstream of toolkit+GPU test)" "BOUNDED BLOCKER" \
        "prerequisite GPU checks not all verified"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "phase0_worker_probe: mode=${MODE} worker=${WORKER_IP} validator=${VALIDATOR_IP}"
echo "policy: READ-ONLY; single approved ephemeral GPU test container only; live SSH is GO-gated"

emit_validator_known_facts

if [[ "$MODE" == "report-only" ]]; then
  echo "report-only mode: NO ssh performed; probing tcp/22 reachability only (bounded 5s)"
  if tcp_reachable "$WORKER_IP" 22 5; then
    REACH_NOTE="tcp/22 reachable but ${BLOCK_REASON}"
  else
    REACH_NOTE="host unreachable on tcp/22 within 5s; ${BLOCK_REASON}"
  fi
  emit_all_worker_blockers "$REACH_NOTE"
else
  echo "GO mode: human-approved live probe (read-only) against root@${WORKER_IP}"
  run_go_checks
fi

print_matrix

if [[ "$HAS_FAIL" -eq 1 ]]; then
  exit 1
elif [[ "$HAS_BLOCKER" -eq 1 ]]; then
  exit 2
fi
exit 0

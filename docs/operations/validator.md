# Validator Operations

Run these commands from the repository root. This runbook covers the normal
validator on-chain submitter and the Docker Swarm services it depends on.

## Install Or Update

The submitter is a systemd service installed from `deploy/swarm/submitter/`. It is
a single process plus the validator hotkey; it needs no orchestrator and no local
database.

```bash
cp deploy/swarm/submitter/run_submitter.py   /var/lib/base/submitter/
cp deploy/swarm/submitter/submitter.yaml     /etc/base/submitter.yaml
cp deploy/swarm/submitter/base-submitter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now base-submitter.service
```

To update, replace the files and restart the unit:

```bash
systemctl restart base-submitter.service
```

Stop the submitter:

```bash
systemctl disable --now base-submitter.service
```

## Submitter Runtime Commands

```bash
systemctl status base-submitter.service
journalctl -u base-submitter.service -f
journalctl -u base-submitter.service --since=30m
```

## Manager Service Commands

Challenge services and the master control plane run as Docker Swarm services on the
manager node. Inspect them with the Swarm CLI:

```bash
docker service ls
docker service ps base-master-proxy base-docker-broker
docker service logs -f base-master-proxy
docker service logs --tail 200 base-docker-broker
docker node ls
```

## Supervisor

The manager-only supervisor runs the broker-health, timeout-reaper, image-updater,
challenge-image-updater, config-sync, and self-update loops:

```bash
systemctl status base-supervisor.service
journalctl -u base-supervisor.service -f
```

## Secret Handling

The only secret the submitter needs is the validator hotkey. Never place coldkey
material on the node. Do not store mnemonics or hotkeys in `.env`, shell history,
support threads, screenshots, or evidence logs.

The submitter reads the hotkey from:

```text
/var/lib/base/wallets/base-validator/hotkeys/validator
```

Keep that file readable only by the submitter service account. Control-plane and
challenge secrets on the manager are Docker secrets mounted at
`/run/secrets/base/<name>`; never print their values.

## Worker Nodes

Worker nodes run short-lived broker jobs and are managed from the manager with the
`base master worker` CLI group:

```bash
base master worker list
base master worker token --cpu
base master worker token --gpu
base master worker label <node> --workload cpu
base master worker label <node> --workload gpu
base master worker drain <node>
base master worker inspect <node>
base master worker rm <node>
```

The broker schedules CPU jobs onto `node.labels.base.workload==cpu` and GPU
jobs onto `node.labels.base.workload==gpu` with `--generic-resource
NVIDIA-GPU=<N>`.

## Agent Challenge Execution Backend Checks

Agent Challenge Terminal-Bench evaluation runs through the `own_runner` backend: the
agent-challenge worker sidecar dispatches a non-privileged Docker-out-of-Docker job to the BASE
broker, which runs the eval inside the
`ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner` image. `own_runner` is the only
supported execution backend; there is no Daytona or `base_sdk` path in production. The public
proxy still exposes only challenge public routes and must block `/internal/*`, `POST
/internal/v1/submissions/{submission_id}/launch`, and generic benchmark execution-shaped routes such
as `/benchmark-executions`; the broker is an internal execution substrate, not a public miner API.

Use placeholder service names only and avoid printing token values:

```bash
docker service ps <agent-challenge-service>
docker service logs <agent-challenge-service> --since=30m | rg 'terminal_bench|own_runner|tb_running'
docker service logs base-docker-broker --since=30m | rg 'run request|created job|agent-challenge-terminal-bench-runner'
curl -sS '<api-base-url>/submissions/<submission-id>/status' | rg '"status":"evaluating"|"phase":"evaluation"|"status":"valid"|"status":"error"'
```

The relevant Agent Challenge knobs are
`CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND=own_runner`, `CHALLENGE_DOCKER_BACKEND=broker`, the
broker URL plus token file, `CHALLENGE_HARBOR_RUNNER_IMAGE` pointing at the deployed
`agent-challenge-terminal-bench-runner` tag, and a scoped allowed-image policy
(`CHALLENGE_DOCKER_ALLOWED_IMAGES`) covering that runner. These are set on both the agent-challenge
API and the worker sidecar; see the agent-challenge repository docs for the full backend reference.

## Validation

```bash
bash -n deploy/swarm/install-swarm.sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=base --cov-report=term-missing --cov-fail-under=80
```

If Docker, the Swarm, or a Python tool is unavailable, record the missing tool as a
blocker instead of marking that surface as tested.

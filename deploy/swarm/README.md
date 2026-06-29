# BASE Docker Swarm deployment (`deploy/swarm`)

The single supported backend is **Docker Swarm**. There is no Kubernetes.

This directory holds the node `daemon.json` variants, the control-plane
supervisor systemd unit, and the single-node bring-up script. Worker enrollment
itself is driven by the `base master worker` CLI plus
`scripts/install-worker.sh` (see **Adding a worker** below).

> **Status: REVIEW BEFORE APPLYING.** The `daemon.json` files and
> `base-supervisor.service` are installed on real hosts by an operator.
> `install-worker.sh` and `install-swarm.sh` both **default to dry-run** and
> change nothing until `--apply` is passed.

## Mainnet deploy prerequisites (secrets, GHCR, placement)

Before a mainnet `install-swarm.sh --apply`, the operator must provide every
required secret in the environment and choose a placement flag. The installer
**hard-fails** (`_ensure_secret` → `die`) the moment a required secret env var is
unset/empty, so a missing secret is caught at `create_secrets` (STEP 6) and never
silently tolerated. Secret VALUES travel via stdin only — they are never placed on
argv and never printed (the plan log shows the env var NAME only).

> Out of scope for this runbook: the actual secret **values** and the GPU
> **FineWeb-Edu dataset staging** (the `prism_fineweb_edu_{train,val}` volumes) are
> operator-lane / user-provided. This section documents WHICH secrets are needed
> and HOW placement must be chosen, not the values themselves.

### Required secrets (14) — installer hard-fails if any is unset

Each is created as the named Docker secret from the listed env var
(`docker secret create <name> -` fed on stdin):

| Docker secret | Env var | Purpose |
|---------------|---------|---------|
| `base_admin_token` | `BASE_ADMIN_TOKEN` | master admin API token (`admin_token_file`; gates `GET /v1/validators`). |
| `base_master_database_url` | `MASTER_DATABASE_URL` | master control-plane Postgres URL (with password). |
| `base_master_pg_password` | `MASTER_PG_PASSWORD` | `base-master-postgres` password. |
| `base_agent_challenge_challenge_token` | `AGENT_CHALLENGE_CHALLENGE_TOKEN` | agent-challenge bearer/challenge token. |
| `base_agent_challenge_docker_broker_token` | `AGENT_CHALLENGE_DOCKER_BROKER_TOKEN` | agent-challenge ↔ broker token. |
| `base_agent_challenge_submission_env_encryption_key` | `AGENT_CHALLENGE_SUBMISSION_ENV_KEY` | agent-challenge `submission_env_encryption_key`. |
| `base_agent_challenge_database_url` | `AGENT_CHALLENGE_DATABASE_URL` | agent-challenge Postgres URL. |
| `base_agent_challenge_pg_password` | `AGENT_CHALLENGE_PG_PASSWORD` | `challenge-agent-challenge-postgres` password. |
| `base_prism_challenge_token` | `PRISM_CHALLENGE_TOKEN` | prism bearer/challenge token. |
| `base_prism_docker_broker_token` | `PRISM_DOCKER_BROKER_TOKEN` | prism ↔ broker token. |
| `base_prism_database_url` | `PRISM_DATABASE_URL` | prism Postgres URL. |
| `base_prism_pg_password` | `PRISM_PG_PASSWORD` | `challenge-prism-postgres` password. |
| `base_openrouter_api_key` | `OPENROUTER_API_KEY` | OpenRouter key (master gateway + prism LLM-review gate). |
| `base_gateway_token_secret` | `GATEWAY_TOKEN` | **MANDATORY** gateway HMAC token-signing secret. `base master proxy` always builds the LLM gateway and `GatewayTokenAuthority` rejects an empty secret, so the proxy **fails fast at startup** without it. |

### Conditional secret (1)

| Docker secret | Env var | When required |
|---------------|---------|---------------|
| `base_gateway_deepseek_api_key` | `DEEPSEEK_API_KEY` | Required **only** when `GATEWAY_PROVIDER_MODE=real` (the default). The gateway injects this server-side so validators/eval runtimes hold no provider key. With `GATEWAY_PROVIDER_MODE=mock` the deterministic mock provider is used and this secret is not required. |

### Optional secrets (2) — never hard-fail

These use `_ensure_optional_secret`: an unset env var logs `optional secret … skipped`
and continues (no error).

| Docker secret | Env var | Effect when absent |
|---------------|---------|--------------------|
| `base_gateway_token` | `CENTRAL_GATEWAY_TOKEN` | Scoped gateway token for the central review gates (agent-challenge analyzer + prism `llm_review`). Absent → the central gates fall back to the direct OpenRouter key (no-gateway fallback). |
| `base_hf_token` | `HF_TOKEN` | HuggingFace token for the prism HF checkpoint publisher (`HF_TOKEN_FILE`). Absent → the publisher runs token-less (fine for the public FineWeb-Edu repo). |

### GHCR credentials path

Private `ghcr.io/baseintelligence/*` images require a registry login. Supply
`GHCR_USER` + `GHCR_TOKEN` in the environment (checked in `preflight`, STEP 1);
the token is fed to `docker login ghcr.io --password-stdin` (never argv/logged) at
`ghcr_login` (STEP 1b). That writes `/root/.docker/config.json`
(`SUPERVISOR_DOCKER_CONFIG_PATH`), which the broker (bind-mounted read-only at
`/root/.docker`, `--with-registry-auth`) and the base-supervisor image-updaters
reuse to resolve/pull the private digests. No separate registry secret object is
created.

### Single-node placement requirement (MUST pass a flag)

On a **single-node** swarm (one manager, no workers) the master-orchestrated
challenge services inherit the default placement constraint
`node.role==worker` (`swarm_backend.py::DEFAULT_PLACEMENT_CONSTRAINT`). A
single-node swarm has **no** worker node, so that constraint matches nothing and
every challenge task sits **Pending forever**. With no placement flag the
installer's STEP 4 leaves this default in place and warns about it.

To schedule challenges on the sole manager you **must** pass at least one of:

- **`--static-challenges`** — the installer creates the challenge services
  directly (api + worker for both agent-challenge and prism), pinned
  `node.role==manager` instead of the stranding `node.role==worker`, so they land
  on the manager and share their per-node `/data` volume.
- **`--single-node-placement`** — the non-default placement override seam (see the
  REVIEW block in `single_node_placement_fix()`); use it when challenges are
  master-orchestrated rather than statically created.

A multi-node swarm (a real GPU/CPU worker joined) needs neither flag: the default
`node.role==worker` constraint matches a real worker.

## Topology

A cluster is one **manager** plus one or more **workers**:

| Node | Swarm role | Runs |
|------|------------|------|
| Manager (also the validator / hotkey node) | `node.role==manager` | The master control plane (proxy / broker) **and** the challenge **services** (agent-challenge, PRISM). |
| CPU worker | `node.role==worker`, label `base.workload=cpu` | Short-lived **CPU broker jobs** dispatched by the manager. |
| GPU worker | `node.role==worker`, label `base.workload=gpu` | Short-lived **GPU broker jobs**; advertises the GPU as a Swarm generic resource. |

The broker runs on the manager and dispatches each evaluation as a short-lived
Swarm **replicated job** to a worker; the long-lived challenge services stay on
the manager.

### Job placement

| Workload | Placement constraint | Extra |
|----------|----------------------|-------|
| Challenge services | `node.role==manager` | — |
| CPU job | `node.labels.base.workload==cpu` | — |
| GPU job (`gpu_count > 0`) | `node.labels.base.workload==gpu` | `--generic-resource NVIDIA-GPU=<N>` |

GPU scheduling matches the requested `NVIDIA-GPU=N` **case-sensitively** against
the `node-generic-resources` advertised in the GPU worker's `daemon.json` (see
below). The resource name `NVIDIA-GPU` is the contract; do not rename it on one
side only.

## PRISM evaluation read-only data mounts

PRISM v2 GPU evals re-execute the miner's training loop on locked FineWeb-Edu
data under a forced random init. The broker delivers that locked data to the eval
container through a **per-slug read-only mount** mechanism that is decoupled from
the Docker-socket allowlist, so the prism eval job gets the data without the
(root-equivalent) host Docker socket:

- `SwarmBrokerConfig.eval_readonly_mounts_by_slug` (`master/swarm_backend.py`) is
  merged with the legacy socket-gated `eval_readonly_mounts` in
  `_eval_readonly_mounts(slug)` (deduplicated, order-preserving). It is configured
  via `docker.broker_eval_readonly_mounts_by_slug` (`config/settings.py`) and
  wired by `cli_app/main.py::_eval_readonly_mounts_by_slug`.
- The prism slug gets a built-in default (`DEFAULT_PRISM_EVAL_READONLY_MOUNTS`),
  so the wiring is live with **no `master.yaml` entry**: the locked train volume
  `prism_fineweb_edu_train` → `/data/fineweb-edu/train` and the offline reference
  tokenizers `prism_reference_tokenizers` → `/opt/prism/reference-tokenizers`,
  both **read-only**.
- Only the `train` split is exposed. The secret `val`/`test` held-out splits are
  never mounted into the eval container, which runs `network=none` on the internal
  `base_jobs_internal` overlay and carries no OpenRouter secret.
- To override the volumes/paths, set `docker.broker_eval_readonly_mounts_by_slug`
  in `master.yaml`:

  ```yaml
  docker:
    broker_eval_readonly_mounts_by_slug:
      prism:
        - prism_fineweb_edu_train:/data/fineweb-edu/train
        - prism_reference_tokenizers:/opt/prism/reference-tokenizers
  ```

  A bare name is a Docker named volume; an absolute host path is a bind mount;
  both are emitted read-only.

### install-swarm.sh PRISM v2 deploy wiring

`install-swarm.sh` canonicalizes the prism eval-plane deploy config on the
challenge service (the broker supplies the eval-container data mounts above):

- **CI-published evaluator image** — `IMAGE_PRISM_EVALUATOR` defaults to
  `ghcr.io/baseintelligence/prism-evaluator:latest` (bundles `sentencepiece` +
  the offline tiktoken cache for the locked pipeline) and is passed as
  `PRISM_BASE_EVAL_IMAGE`. The image is deployed from the registry by digest; no
  locally built evaluator tag is required.
- **Host-side held-out** — the manager-pinned prism scorer (NOT the
  `network=none` eval container) mounts the SECRET val split read-only
  (`prism_fineweb_edu_val` → `/secret/val`) and reads it via
  `PRISM_BASE_EVAL_VAL_DATA_DIR=/secret/val` for the held-out delta. The
  non-secret train split is also mounted at `/secret/train`
  (`PRISM_BASE_EVAL_TRAIN_DATA_DIR`) for the converged memorization-gap
  reference. If val is absent the held-out is gracefully skipped.
- **OpenRouter LLM hard gate** — `PRISM_LLM_REVIEW_ENABLED=true`; the key is
  mounted on the challenge service ONLY at `/run/secrets/openrouter_api_key` (from
  the `base_openrouter_api_key` Docker secret, created from
  `$OPENROUTER_API_KEY`). The eval container never carries the key.

## Files

| File | Target node | Purpose |
|------|-------------|---------|
| `daemon.validator.json` | Manager (validator / hotkey, **no GPU**) | `live-restore` + log rotation only. Deliberately **no** `node-generic-resources` and **no** `runtimes.nvidia` — the manager runs the control plane + challenge services, not GPU jobs. |
| `daemon.cpu-worker.json` | CPU worker | `live-restore` + log rotation only. Same shape as the validator file: **no** GPU generic resource, **no** nvidia runtime. |
| `daemon.worker.json` | GPU worker | Advertise the GPU as a Swarm generic resource, register the NVIDIA runtime, `live-restore`, log rotation. |
| `base-supervisor.service` | Manager | systemd unit for the control-plane supervisor (broker health-gating + scheduled jobs). |
| `install-swarm.sh` | Manager | Single-node bring-up of the master + both challenges (dry-run by default). |
| `../../scripts/install-worker.sh` | Worker | Enroll a CPU/GPU worker via the join-token model (dry-run by default). |

Destination for any `daemon.json` on a node: `/etc/docker/daemon.json` (merged
with existing operator settings — see **Applying a `daemon.json`** below).

## Adding a worker (join-token enrollment, no SSH)

Workers are added **manually** with a Swarm join token. Nothing SSHes into the
worker; the operator runs one command on the manager, one on the worker, then
one back on the manager.

1. **On the MANAGER — mint a join token** for the worker class:

   ```
   base master worker token --cpu      # or --gpu
   ```

   This prints the ready-to-paste command, e.g.:

   ```
   docker swarm join --token <TOKEN> <MANAGER_IP>:2377
   ```

2. **On the WORKER — install the daemon.json and join.** Use
   `scripts/install-worker.sh` (dry-run by default; pass the token via the
   `JOIN_TOKEN` env so it stays off argv/shell history):

   ```
   # dry-run first (prints the plan, changes nothing):
   JOIN_TOKEN=<TOKEN> scripts/install-worker.sh \
       --manager-addr <MANAGER_IP>:2377 --workload cpu     # or gpu

   # then apply, installing the right daemon.json + restarting dockerd:
   JOIN_TOKEN=<TOKEN> scripts/install-worker.sh \
       --manager-addr <MANAGER_IP>:2377 --workload cpu \
       --restart-dockerd --apply
   ```

   For `--workload gpu` the script substitutes the real GPU UUID(s) from
   `nvidia-smi` into `daemon.worker.json` before installing it. The join token is
   never printed.

3. **On the MANAGER — label the new node** so jobs schedule onto it:

   ```
   docker node ls                                          # find the node name
   base master worker label <node> --workload cpu      # or gpu
   ```

Other worker management lives under the same CLI group:

```
base master worker list        # show nodes + workload labels
base master worker inspect <node>
base master worker drain <node>   # cordon + reschedule its jobs
base master worker rm <node>      # remove a (drained) node
```

## Running N decentralized validator agents

A decentralized validator is a long-running `base validator agent` process — it
registers with the master coordination plane, heartbeats, pulls work assignments,
executes them on its **OWN** Docker broker, and posts results. It is **not** the
legacy on-chain weights submitter (that lives under `submitter/`), and it is
**not** a Swarm node (Swarm nodes are the broker's CPU/GPU job executors).

The per-validator config template is [`validator.yaml`](./validator.yaml). Each
validator needs:

- a **distinct** `network.wallet_name` (one bittensor hotkey == one validator ==
  one config == one process), with the wallet staged under `network.wallet_path`;
- that hotkey's **ss58 listed in the master's `network.mock_metagraph` with
  `validator_permit=true`** so the no-chain eligibility auth accepts it. The
  master installer renders that set from its `MOCK_METAGRAPH` env (see
  `install-swarm.sh`);
- `validator.agent.master_url` / `gateway_url` pointing at the manager's published
  proxy (e.g. `http://<manager-ip>:18080`);
- `validator.agent.capabilities`: `["cpu"]` for agent-challenge Terminal-Bench 2.1
  only, or `["gpu","cpu"]` (equivalently `["gpu"]`) for the one validator that also
  runs prism GPU re-execution (concurrency 1). On a single-GPU cluster exactly one
  validator advertises `gpu`;
- `validator.agent.broker_url`: the validator's **own** Docker broker endpoint (it
  never dispatches to the master's broker).
- *(optional)* `validator.agent.display_name` / `validator.agent.logo_url`: the
  validator's **self-declared subnet identity** (display name + logo). On the
  no-chain deploy there is no on-chain identity, so these are threaded UNTRUSTED
  into the agent's `last_seen_meta`; the master reads them back and the public
  validator directory renders them. Equivalently, the operator can seed the same
  identity per entry in the master's `MOCK_METAGRAPH` (`display_name`/`logo_url`
  keys). Omit both for an identicon fallback.

No provider keys live on a validator: the master stamps a scoped per-assignment
gateway token + the `DEEPSEEK_BASE_URL`/`OPENROUTER_BASE_URL` gateway routes into
each pulled assignment, and the agent strips any `*_API_KEY` from the eval env.

### Example: 1 GPU + 2 CPU validators

Copy the template once per validator, giving each a distinct wallet + capabilities:

```
# /etc/base/validator-gpu.yaml   network.wallet_name: gpu    capabilities: ["gpu","cpu"]
# /etc/base/validator-cpu1.yaml  network.wallet_name: cpu1   capabilities: ["cpu"]
# /etc/base/validator-cpu2.yaml  network.wallet_name: cpu2   capabilities: ["cpu"]

base validator agent --config /etc/base/validator-gpu.yaml
base validator agent --config /etc/base/validator-cpu1.yaml
base validator agent --config /etc/base/validator-cpu2.yaml
```

Then seed the master's mock metagraph with all three validator hotkeys (the
installer reads this from `MOCK_METAGRAPH`):

```
MOCK_METAGRAPH='[
  {"hotkey":"<gpu-ss58>","validator_permit":true,"stake":1000,"display_name":"BASE GPU Validator","logo_url":"https://joinbase.ai/logo.svg"},
  {"hotkey":"<cpu1-ss58>","validator_permit":true,"stake":1000,"display_name":"BASE CPU Validator 1"},
  {"hotkey":"<cpu2-ss58>","validator_permit":true,"stake":1000}
]'
```

The optional per-entry `display_name`/`logo_url` are the validators' self-declared
subnet identity (seeded UNTRUSTED into the master identity cache as the no-chain
fallback the public directory renders); entries without them fall back to an
identicon.

Adding a 4th validator later needs no master reconfiguration beyond appending its
hotkey to `MOCK_METAGRAPH`: it registers, heartbeats, and the orchestration driver
picks it up on the next interval (capability-aware balanced assignment).

## Worker / manager `daemon.json` — key-by-key notes

JSON does not allow comments, so all explanation lives here.

### `node-generic-resources` (GPU worker only — `daemon.worker.json`)

```json
"node-generic-resources": ["NVIDIA-GPU=GPU-00000000-0000-0000-0000-000000000000"]
```

- `GPU-00000000-0000-0000-0000-000000000000` is a **placeholder**.
  `scripts/install-worker.sh --workload gpu` replaces it with the real GPU
  UUID(s) from `nvidia-smi --query-gpu=uuid --format=csv,noheader` (one
  `"NVIDIA-GPU=GPU-<uuid>"` entry per physical GPU).
- The resource **name** `NVIDIA-GPU` is the scheduling contract: GPU broker jobs
  emit `--generic-resource "NVIDIA-GPU=N"` and Swarm matches that request against
  this advertisement case-sensitively. Do not rename it on one side only.
- For the generic resource to actually surface the device inside the task, the
  NVIDIA container runtime must also have swarm-resource support enabled
  (`swarm-resource = "DOCKER_RESOURCE_NVIDIA-GPU"` in
  `/etc/nvidia-container-runtime/config.toml`).

### `runtimes.nvidia` (GPU worker only)

```json
"runtimes": {"nvidia": {"path": "nvidia-container-runtime", "runtimeArgs": []}}
```

Registers the NVIDIA runtime so it can be selected per container/service.

**`default-runtime` is intentionally NOT set.** Setting
`"default-runtime": "nvidia"` would route every container on the worker through
the NVIDIA runtime, including plain CPU work and infrastructure containers. GPU
access instead flows through explicit paths — Swarm `--generic-resource` plus
per-container runtime selection (and `--gpus` on the privileged escape hatch).
CPU workloads keep `runc`.

### `live-restore` (all nodes)

```json
"live-restore": true
```

Containers keep running while `dockerd` restarts (daemon upgrades, config
reloads). Required so applying config changes or engine updates does not kill
in-flight challenge evaluations. **Caveat:** live-restore does *not* cover Swarm
task management during the restart window — keep restarts short.

### `log-driver` / `log-opts` (all nodes)

```json
"log-driver": "json-file",
"log-opts": {"max-size": "50m", "max-file": "5"}
```

Caps each container at 5 × 50 MB of JSON logs (≤ 250 MB per container), preventing
unbounded `/var/lib/docker/containers/*/*-json.log` growth. Applies only to
containers created **after** the setting takes effect.

### CPU worker (`daemon.cpu-worker.json`) and manager (`daemon.validator.json`)

Both are `live-restore` + log rotation **only**. They must never gain
`node-generic-resources` or `runtimes.nvidia`: the CPU worker runs only CPU jobs,
and the manager holds the hotkey and runs the control plane + challenge services,
not GPU jobs.

## Networking & firewall

Challenge and job overlays are **encrypted** and created with **MTU 1450** to
leave VXLAN encapsulation headroom on a standard 1500-byte path.

Open these between every pair of nodes (manager ⇄ workers):

| Port / protocol | Purpose |
|-----------------|---------|
| `2377/tcp` | Swarm cluster management |
| `7946/tcp` + `7946/udp` | Node gossip / discovery |
| `4789/udp` | VXLAN overlay data plane |
| IP protocol **50 (ESP)** | Encrypted overlay (IPsec) |

## Applying a `daemon.json` (merge / validate / restart)

`scripts/install-worker.sh --restart-dockerd` automates this on a worker. To do
it by hand on any node:

1. **Merge, don't clobber.** If the node already has `/etc/docker/daemon.json`,
   merge these keys into it rather than overwriting (watch for an existing
   `log-driver` or `runtimes` block). Keep a timestamped backup first.
2. **Validate before restarting** (Docker ≥ 23):

   ```
   dockerd --validate --config-file /etc/docker/daemon.json
   ```

   `configuration OK` is required before any restart.
3. **Restart implications.** Changing `node-generic-resources`, `runtimes`, or
   `live-restore` requires a full daemon **restart** (a `SIGHUP` reload does not
   apply them). With `live-restore: true` already effective, running containers
   survive the restart; on the **first** application live-restore is not yet
   active, so apply it before challenge/job workloads exist on the node.
4. **Verify after restart.** `docker info` shows the nvidia runtime and
   live-restore true (GPU worker); on the manager, `docker node inspect <node>`
   shows the `NVIDIA-GPU` generic resource advertised by a GPU worker.

## Disk hygiene: in-use-safe prune policy

Run on every node, on a schedule (a daily timer is sufficient):

```
docker system prune --force
```

- This variant removes **only dangling images** (untagged layers), stopped
  containers, unused networks, and build cache. It does **not** touch volumes
  (no `--volumes`) and does **not** remove tagged-but-currently-unused images
  (no `--all`), so it is safe while challenge workloads, DinD escape-hatch
  containers, and pinned service images are in use.
- **Never** add `--volumes` (would destroy challenge/DinD state) or `--all`
  (would evict digest-pinned service images and force re-pulls mid-epoch).

## Control-plane supervisor unit (`base-supervisor.service`)

`base-supervisor.service` is the systemd unit template for the control-plane
supervisor that runs on the manager: it health-gates the broker and runs the
scheduled control-plane jobs (reaper, image updaters, config sync, weights,
self-update).

- **`Type=notify` + `WatchdogSec=30s`**: the supervisor speaks the `sd_notify`
  protocol natively (`READY=1` on start, `WATCHDOG=1` heartbeats, `STOPPING=1` on
  shutdown). If the main loop wedges, systemd kills and restarts it
  (`Restart=on-failure`).
- **Health vs load**: the supervisor health-gates the broker via its async
  `/health` endpoint with a short (3 s) timeout and a 3-consecutive-failure
  threshold. Slow `/v1/docker/*` operations are load, not death — they never
  affect the watchdog.
- **Scheduled jobs** plug in via `src/base/supervisor/tasks.py`.
- **Install**: copy to `/etc/systemd/system/`, adjust the `ExecStart` path +
  `User=`, then `systemctl daemon-reload && systemctl enable --now
  base-supervisor.service`. Verify with `systemctl status`.
- **Installer path**: `install-swarm.sh` renders the `supervisor:` block into the
  master config and (behind `--install-supervisor`) plans the unit install +
  `systemctl enable --now`. The image-updater + challenge-image-updater resolve
  PRIVATE `ghcr.io/baseintelligence/*` digests using the manager's GHCR
  credentials decoded from the docker `config.json` written by `ghcr_login`
  (`supervisor.registry_docker_config_path`); no extra secret is needed. Master
  self-update is wired only when `SUPERVISOR_SELF_UPDATE_MANIFEST_URL` is set —
  otherwise it is explicitly disabled (the task is not registered, never inert).

### Auto-update ownership: base-supervisor REPLACES Watchtower

`base-supervisor.service` is the canonical GHCR auto-update path for
`ghcr.io/baseintelligence`. Its image-updater digest-pins `base-master-proxy` +
`base-docker-broker` (and the challenge-image-updater rolls the challenge
services) to `tag@sha256:<digest>`, **rolling a service only when the resolved
digest differs and a no-op when already current** (immutable pin policy). The old
Watchtower deployment performs the same mutation (`docker service update`), so the
two MUST NOT run at the same time or they race each other.

**Watchtower decommission ordering (MANDATORY — do BEFORE enabling the supervisor):**

1. Stop + remove Watchtower so nothing else mutates the services:
   ```
   docker service rm platform-watchtower    # swarm service install
   # or, for a compose/standalone container:
   docker rm -f watchtower
   ```
2. Confirm nothing remains (no racing updater):
   ```
   docker ps -a | grep -i watchtower    # must print NOTHING
   ```
3. Only THEN install + enable `base-supervisor.service` (or run
   `install-swarm.sh ... --install-supervisor`).

**Rollback ordering (reverse):** `systemctl disable --now base-supervisor.service`
FIRST (stop the new updater), then re-add Watchtower. Never have both active.

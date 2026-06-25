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

# Swarm `daemon.json` templates

> **Status: TEMPLATES ONLY.**
> These files are applied **ONLY during the GO-gated cutover (plan Task 28)**.
> Nothing in this directory is to be copied to, or executed on, a live host before
> the cutover runbook (plan Task 27) is approved AND the Phase-0 GO-mode probe
> (`scripts/phase0_worker_probe.sh` in `--go` mode, plan Task 1) has produced an
> **all-VERIFIED** GO/NO-GO matrix. This README intentionally contains **no
> executable apply commands targeting live hosts**.

## Files

| File | Target node | Purpose |
|------|-------------|---------|
| `daemon.worker.json` | GPU worker node (Swarm worker) | Advertise the GPU as a Swarm generic resource, register the NVIDIA runtime, keep containers alive across daemon restarts, rotate logs. |
| `daemon.validator.json` | Validator node (Swarm manager, hotkey, **no GPU**) | `live-restore` + log rotation only. Deliberately has **no** `node-generic-resources` and **no** `runtimes.nvidia` — the validator has no GPU and runs ZERO challenge workloads. |

Destination on each node: `/etc/docker/daemon.json` (merged with any existing
operator settings — see "Merging with an existing daemon.json" below).

## Worker template: key-by-key notes

JSON does not allow comments, so all explanation lives here.

### `node-generic-resources`

```json
"node-generic-resources": ["NVIDIA-GPU=GPU-00000000-0000-0000-0000-000000000000"]
```

- `GPU-00000000-0000-0000-0000-000000000000` is a **placeholder**. During cutover,
  substitute the real GPU UUID obtained on the worker from
  `nvidia-smi --query-gpu=uuid --format=csv,noheader` (the value already looks like
  `GPU-xxxxxxxx-...`, so the advertised string is `NVIDIA-GPU=GPU-<real-uuid>`).
- The resource **name** `NVIDIA-GPU` is the contract: broker GPU scheduling (plan
  Task 10) emits `--generic-resource "NVIDIA-GPU=N"` on `docker service create`,
  and Swarm matches that request against this advertisement **case-sensitively**.
  Do not rename it on one side only.
- One entry per physical GPU. The current worker is single-GPU; add further
  `"NVIDIA-GPU=GPU-<uuid>"` entries only if hardware changes.
- For the generic resource to actually surface the device inside the task, the
  NVIDIA container runtime must also have swarm-resource support enabled
  (`swarm-resource = "DOCKER_RESOURCE_NVIDIA-GPU"` in
  `/etc/nvidia-container-runtime/config.toml`); verify during cutover, it is part
  of the Task 1 GO matrix follow-ups.

### `runtimes.nvidia`

```json
"runtimes": {"nvidia": {"path": "nvidia-container-runtime", "runtimeArgs": []}}
```

Registers the NVIDIA runtime so it can be selected per container/service.

**`default-runtime` is intentionally NOT set.** Tradeoff considered:

- *Setting `"default-runtime": "nvidia"`* makes every container on the worker pass
  through the NVIDIA runtime, including plain CPU jobs and infrastructure
  containers. That silently grants GPU plumbing where it is not requested and
  couples all workloads to the nvidia-container stack's health.
- *Not setting it* (chosen): GPU access flows through the planned, explicit paths —
  Swarm `--generic-resource` (Task 10) plus per-container runtime selection, and
  `--gpus` on the privileged escape hatch (Task 11/13). CPU workloads keep `runc`.
  If a cutover smoke test shows the generic-resource path requires the default
  runtime to inject devices, revisit deliberately in the runbook — do not flip it
  ad hoc.

### `live-restore`

```json
"live-restore": true
```

Containers keep running while `dockerd` restarts (daemon upgrades, config
reloads). Required so applying config changes or engine updates does not kill
in-flight challenge evaluations. **Caveat:** live-restore does *not* cover Swarm
task management during the restart window — the manager may reschedule tasks it
believes lost if the daemon is down too long; keep restarts short and apply
during a quiet window per the cutover runbook.

### `log-driver` / `log-opts`

```json
"log-driver": "json-file",
"log-opts": {"max-size": "50m", "max-file": "5"}
```

Caps each container at 5 × 50 MB of JSON logs (≤ 250 MB per container), preventing
unbounded `/var/lib/docker/containers/*/​*-json.log` growth. Applies only to
containers created **after** the setting takes effect; pre-existing containers
keep their old log config until recreated.

## Validator template

`daemon.validator.json` = `live-restore` + log rotation **only**. It must never
gain `node-generic-resources` or `runtimes.nvidia`: the validator has no GPU
(verified — Docker 29.1.3, Swarm inactive, no nvidia-ctk), holds the hotkey, and
runs no challenge workloads.

## Apply procedure (cutover runbook outline — Task 28 executes this)

> All steps below are performed by the operator during the GO-gated cutover
> window, on each node locally. They are documented here as *procedure text*,
> not as runnable commands against named hosts.

1. **Preconditions (from the Phase-0 matrix, Task 1):**
   - GO-mode probe all-VERIFIED (dockerd 29.x on worker, nvidia-container-toolkit
     wired, ephemeral `--gpus all nvidia-smi` exit 0).
   - Firewall/provider rules open between the two nodes: `2377/tcp` (Swarm
     management), `7946/tcp+udp` (gossip), `4789/udp` (VXLAN data plane), plus
     ESP (IP proto 50) for the encrypted overlay.
   - Overlay MTU plan honored: networks created with MTU **1450** to leave VXLAN
     encapsulation headroom on a 1500 path (the probe's `ping -M do -s 1422`
     check corresponds to this).
2. **Substitute the GPU UUID** in the worker template (see
   `node-generic-resources` above) using the value from `nvidia-smi` on the worker.
3. **Merge, don't clobber:** if a node already has `/etc/docker/daemon.json`,
   merge these keys into it rather than overwriting (watch for an existing
   `log-driver` or `runtimes` block). Keep a timestamped backup of the previous
   file.
4. **Validate before restarting:** on the node, run the Docker config validator
   against the candidate file:

   ```
   dockerd --validate --config-file /etc/docker/daemon.json
   ```

   Exit 0 / `configuration OK` is required before any daemon restart. (Available
   on Docker ≥ 23; both nodes run 29.x.)
5. **Restart implications:** changing `node-generic-resources`, `runtimes`, or
   `live-restore` requires a full daemon **restart** (a `SIGHUP` reload does not
   apply them). With `live-restore: true` already effective, running containers
   survive the restart; on the **first** application live-restore is not yet
   active, so schedule it before challenge workloads exist on the node (cutover
   ordering in Task 28 does exactly this: daemon config → swarm join → workloads).
6. **Verify after restart:** `docker info` shows the nvidia runtime and
   live-restore true (worker); `docker node inspect` on the manager shows the
   `NVIDIA-GPU` generic resource advertised by the worker.

## Disk hygiene: in-use-safe prune policy

Run on both nodes, on a schedule (daily timer is sufficient):

```
docker system prune --force
```

- This variant removes **only dangling images** (untagged layers), stopped
  containers, unused networks, and build cache. It does **not** touch volumes
  (no `--volumes`) and does **not** remove tagged-but-currently-unused images
  (no `--all`), so it is safe while challenge workloads, DinD escape-hatch
  containers (which own their `/var/lib/docker` volume), and pinned service
  images are in use.
- **Never** add `--volumes` (would destroy challenge/DinD state) or `--all`
  (would evict digest-pinned service images and force re-pulls mid-epoch).
- Schedule guidance: daily, off-peak, via a systemd timer owned by the
  supervisor deployment (Wave 3); until the supervisor lands, a plain root
  crontab entry with the exact command above is acceptable.

## Control-plane supervisor unit (`platform-supervisor.service`)

`platform-supervisor.service` is the systemd unit template for the
control-plane supervisor (plan Task 16) that replaces the Kubernetes
CronJobs on the Docker backend. Like everything else in this directory it
is a **template only**, installed during the GO-gated cutover (Task 28).

- **`Type=notify` + `WatchdogSec=30s`**: the supervisor speaks the
  `sd_notify` protocol natively (`READY=1` on start, `WATCHDOG=1`
  heartbeats at `WATCHDOG_USEC/2`, `STOPPING=1` on shutdown). If the main
  loop ever wedges, systemd's watchdog kills and restarts it
  (`Restart=on-failure`).
- **Health vs load**: the supervisor health-gates the broker via the async
  `/health` endpoint with a short (3 s) timeout and a 3-consecutive-failure
  threshold. Slow `/v1/docker/*` operations are load, not death — they never
  affect the watchdog.
- **Run target**: the CLI entrypoint is
  `platform master supervisor --config /etc/platform/master.yaml`; it
  refuses to start unless `runtime.backend: docker`.
- **Scheduled jobs**: the skeleton ships only the broker health probe;
  reaper / image updaters / config sync / weights / self-update plug in via
  `src/platform_network/supervisor/tasks.py` (plan Tasks 17-22).
- **Install (cutover)**: copy to `/etc/systemd/system/`, adjust `ExecStart`
  path + `User=`, then `systemctl daemon-reload && systemctl enable --now
  platform-supervisor.service`. Verify with `systemctl status` (should show
  `Status: ...` ready and watchdog active).

# Security Model

![Platform Banner](../assets/banner.jpg)

## Isolation Rules

- PostgreSQL central is available only to the master.
- Challenges never receive PostgreSQL credentials.
- Normal validators never receive master DB credentials.
- Internal challenge calls require per-challenge shared tokens.
- Public proxy strips sensitive headers.
- Public proxy blocks internal challenge paths.

## Production Policy Boundaries

The production and Kubernetes boundary is stricter than local development:

- Dev, test, and local runs may use SQLite for master state. Production and Kubernetes must use an external PostgreSQL database loaded from a secret or explicit database URL, and SQLite is rejected.
- Dev and local challenge images may be local, mutable, or tagged `latest` while iterating. Production images must include both a semver tag and a `sha256` digest, starting with Platform `3.0.0` for release images. Production rejects `latest`, untagged references, and missing digests.
- Production image allowlists must be scoped to a registry and namespace such as `ghcr.io/platformnetwork/`. Broad prefixes such as `platformnetwork/` are development-only.
- Production remote GPU servers and Kubernetes targets must use TLS verification with `verify_tls=true`. `verify_tls=false` is reserved for local or test-only endpoints.
- Production Kubernetes agent targets must use HTTPS plus `verify_tls=true`. Multi-server routing may reuse a persisted target assignment only when the target still exists, is enabled, is healthy, is not draining, and has remaining GPU capacity.

## Docker Socket Risk

Local Docker Compose paths for `master-admin`, `platform-docker-broker`, `gpu-agent`, and `watchtower` mount `/var/run/docker.sock` when they need to create or update local containers. Access to that socket is equivalent to host Docker daemon control and can become host root access. The socket labels in Compose document the risk, but they don't make the socket safe for production isolation.

Production Kubernetes should use Kubernetes rollout controls and scoped RBAC instead of Docker socket mounts. Broker-created challenge jobs must not receive the host Docker socket.

## Watchtower Boundary

Watchtower is allowed only through `docker/compose.watchtower.yml` for local and staging Compose deployments. The overlay uses the maintained `nickfedor/watchtower:1.17.1` image for Docker 29 API compatibility. It runs with `--label-enable`, and only control-plane services may carry `com.centurylinklabs.watchtower.enable=true`:

- `master-admin`
- `master-proxy`
- `platform-docker-broker`
- `validator`
- `gpu-agent`

Do not add Watchtower labels to challenge containers, broker-created jobs, database services, or Kubernetes manifests. Production uses semver plus digest image pins and Kubernetes rollout or rollback controls instead of background image replacement.

## Kubernetes PID and Swap Boundary

Kubernetes PodSpec in this code path maps CPU and memory requests and limits. It doesn't provide direct parity for Docker-only `pids_limit`, `memory_swap`, or custom Docker network modes. Kubernetes broker jobs and challenge workloads reject non-default PID and swap requests instead of silently accepting fields that Kubernetes won't enforce. If production needs PID or swap ceilings, enforce them with cluster configuration or admission policy and document that policy with the cluster runbook.

## Broker Archive and Cleanup Security

Broker archive uploads are treated as untrusted input. Docker and Kubernetes broker paths reject absolute paths, parent traversal, links, and device members before extraction. Kubernetes broker init containers use a defensive extractor with data-filtered tar extraction, and malformed broker images are rejected before resources are created.

Kubernetes broker runs attempt to delete the Job, NetworkPolicy, and mount Secret in cleanup paths for success, failure, timeout, apply errors, wait errors, and log errors. Evidence should prove cleanup behavior without storing archive payloads, bearer credentials, kubeconfigs, private keys, or credentialed database URLs.

## Secrets

Admin tokens, challenge tokens, kubeconfigs, production database URLs, and registry credentials must come from files, environment variables, or Kubernetes Secrets. Don't store clear text secrets in registry metadata responses, docs, or evidence files.

## Failure Behavior

If a challenge fails health checks or `get_weights`, its contribution is zero for that epoch. The master doesn't auto-disable it.

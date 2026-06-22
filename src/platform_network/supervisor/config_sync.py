"""Supervisor config-sync — Swarm config reconciliation task.

A :class:`ScheduledTask` that fetches YAML config from GitHub, validates it
(ConfigMap-kind-only; Secret manifests rejected), renders the runtime config
payload, digests it, and rolls the Swarm services ONLY when the digest
changed. The pure fetch/validate/render/digest core lives in
:mod:`platform_network.supervisor.config_source` (``ConfigSyncSource``,
``validate_config_text``, ``_runtime_config_payload``, ``_digest`` — all
pure, with zero orchestration coupling).

Apply mechanics (file-on-manager + forced rollouts, NOT rotating
``docker config`` objects): Docker Swarm configs are immutable, so a
named-config approach would need an atomic create-new/update-services/
remove-old dance per change. Instead the rendered payload is written
atomically (tmp + rename) to a configured manager-host path that the
first-party services bind-mount (default ``/etc/platform/master.yaml``),
and each configured rollout target is restarted via ``docker service
update --force`` through the :class:`SwarmCommandRunner` seam.

Idempotency is RESTART-SAFE: the "currently applied" digest lives on
disk, not in process memory — the payload file itself plus a sidecar
(``<target>.digest``) recording the digest through which rollouts
completed. A fresh supervisor over an already-current target is a no-op;
a crash between file write and rollouts leaves the sidecar stale, so the
next tick retries the rollouts (``rollout_retried``).

Result-reason vocabulary: ``already_current`` / ``updated`` /
``rollout_retried`` / ``invalid_config`` (covers fetch failures too) /
``secret_sync_rejected``.

Health-gate note: this job depends on GitHub, the local filesystem, and
dockerd — never the broker — so the shared gate is accepted but
deliberately not consulted.

Rollout targets: the config consumers among Task 18's first-party
service names — ``platform-proxy``/``platform-broker`` (the single-port
consolidation removed the separate ``platform-admin`` service; the
admin/registry surface is now served by the proxy).
``platform-config-sync`` is deliberately absent: under the supervisor,
config-sync is this very task, not a Swarm service, and it must not
force-restart itself. A target that does not exist on the daemon is a
logged skip (treated as rolled out), so partial deployments are safe.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from platform_network.config.settings import Settings
from platform_network.master.swarm_backend import SwarmCliRunner, SwarmCommandRunner
from platform_network.supervisor.config_source import (
    ConfigSyncResult,
    ConfigSyncSource,
    SecretSyncRejected,
    _digest,
    _runtime_config_payload,
    fetch_github_config,
    validate_config_text,
)
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

# One-minute config-sync cadence.
CONFIG_SYNC_INTERVAL_SECONDS = 60.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60.0
# Manager-host path first-party services bind-mount.
DEFAULT_CONFIG_TARGET_PATH = "/etc/platform/master.yaml"
DIGEST_SIDECAR_SUFFIX = ".digest"
# Inputs for the shared payload renderer (release/name derivation).
DEFAULT_CONFIG_MAP_NAME = "platform-config"
DEFAULT_NAMESPACE = "platform-master"

DEFAULT_ROLLOUT_SERVICES: tuple[str, ...] = (
    "platform-proxy",
    "platform-broker",
)

_MISSING_SERVICE_MARKERS = ("no such service", "not found")


class SwarmConfigSync:
    """Fetch → validate → digest-compare → file apply → forced rollouts."""

    def __init__(
        self,
        source: ConfigSyncSource,
        *,
        target_path: Path,
        rollout_services: Sequence[str],
        runner: SwarmCommandRunner,
        docker_bin: str = "docker",
        config_map_name: str = DEFAULT_CONFIG_MAP_NAME,
        namespace: str = DEFAULT_NAMESPACE,
        command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        self._source = source
        self._target_path = target_path
        self._sidecar_path = target_path.with_name(
            target_path.name + DIGEST_SIDECAR_SUFFIX
        )
        self._rollout_services = tuple(rollout_services)
        self._runner = runner
        self._docker_bin = docker_bin
        self._config_map_name = config_map_name
        self._namespace = namespace
        self._command_timeout_seconds = command_timeout_seconds

    def run_once(self) -> None:
        try:
            result = self.sync_once()
        except Exception:
            logger.exception("config-sync: tick failed; will retry next interval")
            return
        if result.reason == "already_current":
            logger.debug("config-sync: %s", result.reason)
        elif result.changed:
            logger.info(
                "config-sync: %s (digest %s -> %s)",
                result.reason,
                result.current_digest,
                result.new_digest,
            )
        else:
            logger.warning("config-sync: skipped (%s)", result.reason)

    def sync_once(self) -> ConfigSyncResult:
        current_digest = self._applied_digest()
        try:
            config_text = self._fetch_config()
            validate_config_text(config_text, allowed_kinds=self._source.allowed_kinds)
        except SecretSyncRejected:
            logger.error(
                "config-sync: refusing to sync Secret manifest from %s@%s",
                self._source.repository,
                self._source.branch,
            )
            return ConfigSyncResult(
                changed=False,
                reason="secret_sync_rejected",
                current_digest=current_digest,
            )
        except Exception:
            logger.warning(
                "config-sync: fetch/validation failed for %s@%s; skipping this tick",
                self._source.repository,
                self._source.branch,
                exc_info=True,
            )
            return ConfigSyncResult(
                changed=False,
                reason="invalid_config",
                current_digest=current_digest,
            )
        config_payload = _runtime_config_payload(
            config_text,
            config_map=self._config_map_name,
            namespace=self._namespace,
        )
        new_digest = _digest(config_payload)
        file_current = self._file_digest() == new_digest
        if current_digest == new_digest and file_current:
            return ConfigSyncResult(
                changed=False,
                reason="already_current",
                current_digest=current_digest,
                new_digest=new_digest,
            )
        if not file_current:
            self._write_target(config_payload)
            logger.info(
                "config-sync: wrote %s (%d bytes, digest %s)",
                self._target_path,
                len(config_payload.encode("utf-8")),
                new_digest,
            )
        if self._rollout_all():
            self._write_sidecar(new_digest)
        return ConfigSyncResult(
            changed=True,
            reason="updated" if not file_current else "rollout_retried",
            current_digest=current_digest,
            new_digest=new_digest,
        )

    def _fetch_config(self) -> str:
        if self._source.fetcher is not None:
            return self._source.fetcher(self._source)
        return fetch_github_config(self._source)

    def _applied_digest(self) -> str | None:
        try:
            value = self._sidecar_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return value or None

    def _file_digest(self) -> str | None:
        try:
            return _digest(self._target_path.read_text(encoding="utf-8"))
        except OSError:
            return None

    def _write_target(self, payload: str) -> None:
        self._target_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._target_path.with_name(self._target_path.name + ".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(self._target_path)

    def _write_sidecar(self, digest: str) -> None:
        self._sidecar_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._sidecar_path.with_name(self._sidecar_path.name + ".tmp")
        tmp_path.write_text(digest + "\n", encoding="utf-8")
        tmp_path.replace(self._sidecar_path)

    def _rollout_all(self) -> bool:
        all_rolled = True
        for service in self._rollout_services:
            if not self._rollout_service(service):
                all_rolled = False
        return all_rolled

    def _rollout_service(self, service: str) -> bool:
        result = self._runner.run(
            [
                self._docker_bin,
                "service",
                "update",
                "--detach",
                "--force",
                service,
            ],
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode == 0:
            logger.info("config-sync: forced rollout of service %r", service)
            return True
        stderr = result.stderr.strip()
        if any(marker in stderr.lower() for marker in _MISSING_SERVICE_MARKERS):
            logger.warning(
                "config-sync: rollout target %r does not exist; skipping", service
            )
            return True
        logger.error(
            "config-sync: docker service update --force failed for %r (rc=%d): %s",
            service,
            result.returncode,
            stderr,
        )
        return False


def build_config_sync_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    source: ConfigSyncSource | None = None,
    target_path: Path | str = DEFAULT_CONFIG_TARGET_PATH,
    rollout_services: Sequence[str] | None = None,
    runner: SwarmCommandRunner | None = None,
    docker_bin: str = "docker",
    interval_seconds: float = CONFIG_SYNC_INTERVAL_SECONDS,
) -> ScheduledTask:
    """Build the config-sync :class:`ScheduledTask`.

    ``settings`` and ``health_gate`` follow the Task-16 builder recipe;
    neither is consulted today (the job depends on GitHub + local file +
    dockerd, not the broker — see module docstring). ``source`` defaults
    to the canonical source (``PlatformNetwork/platform`` @ ``main``,
    ``deploy/swarm/master.yaml``, ``sync_secrets=False``, ConfigMap-only);
    ``runner`` defaults to the existing
    :class:`SwarmCliRunner` subprocess seam.
    """
    del settings, health_gate  # recipe parity; not broker-dependent.
    sync = SwarmConfigSync(
        source if source is not None else ConfigSyncSource.default(),
        target_path=Path(target_path),
        rollout_services=(
            rollout_services
            if rollout_services is not None
            else DEFAULT_ROLLOUT_SERVICES
        ),
        runner=runner if runner is not None else SwarmCliRunner(),
        docker_bin=docker_bin,
    )
    return ScheduledTask(
        name="config-sync",
        interval_seconds=interval_seconds,
        run=sync.run_once,
    )

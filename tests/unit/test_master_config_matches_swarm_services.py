"""Task 12: master config host/port refs MUST match the Swarm services the
installer (``deploy/swarm/install-swarm.sh``) actually creates.

A name/port disagreement between ``deploy/swarm/master.yaml`` (the canonical
master config synced by the supervisor) and the imperative
``docker service create`` calls in ``install-swarm.sh`` means services cannot
resolve each other over the ``base_challenges`` overlay (broker/DB connection
failures at runtime). This test fails loudly if they ever diverge again.

Reconciliation direction (Task 12 investigation, documented in the recovery
notepad):
  * postgres : installer is source of truth -> ``base-master-postgres`` (there is
    NO ``base-postgres`` service created anywhere).
  * broker   : the Python/supervisor canonical (``base-docker-broker:8082``) is
    source of truth -- ``settings.docker.broker_url`` default, the supervisor
    image-updater/config-sync targets, and the COMMITTED Task 6 regression
    (``test_seed_prism_reseed_broker_url``) all brand ``base-master-broker`` the
    stale NXDOMAIN host. The installer was the lone holdout and was realigned.

The assertions cross-check BOTH the checked-in master.yaml AND the config the
installer renders inline against the service names+ports the installer creates.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from base.config.settings import Settings, SupervisorSettings
from base.supervisor.tasks import build_scheduled_tasks

ROOT = Path(__file__).resolve().parents[2]
MASTER_YAML = ROOT / "deploy" / "swarm" / "master.yaml"
INSTALL_SWARM = ROOT / "deploy" / "swarm" / "install-swarm.sh"

POSTGRES_DEFAULT_PORT = 5432
# The live topology + installer publish the public proxy on this port. The live
# master runs on 19080 (the old 18080/51.83.112.164 deploy is decommissioned);
# config-sync overwrites /etc/base/master.yaml from the canonical file, so a
# stale value here would roll the live proxy onto the wrong port on the next sync.
PROXY_PORT_PRODUCTION = 19080
# Live production host advertised in gateway.public_base_url (88.216.198.199; the
# old 51.83.112.164 host is decommissioned) and the live chain network.
ADVERTISE_ADDR_PRODUCTION = "88.216.198.199"
CHAIN_ENDPOINT_PRODUCTION = "finney"
# Values that MUST NOT reappear in the canonical config: they would break the
# live master on a config-sync (old port / decommissioned host).
STALE_TOKENS = ("18080", "51.83.112.164")


def _installer_text() -> str:
    return INSTALL_SWARM.read_text(encoding="utf-8")


def _master_yaml() -> dict:
    return yaml.safe_load(MASTER_YAML.read_text(encoding="utf-8"))


def _host_port_from_url(url: str) -> tuple[str, int]:
    """Extract (host, port) from either a ``scheme://[creds@]host:port`` URL.

    Handles both ``postgresql+asyncpg://base:base@host:5432/db`` and
    ``http://host:8082`` shapes.
    """

    # Prefer the authority that follows an ``@`` (credentials present), else the
    # authority right after ``://``.
    match = re.search(r"@([A-Za-z0-9._-]+):(\d+)", url) or re.search(
        r"://([A-Za-z0-9._-]+):(\d+)", url
    )
    assert match is not None, f"could not parse host:port from {url!r}"
    return match.group(1), int(match.group(2))


def _installer_master_postgres_service() -> str:
    """Name passed to ``_deploy_postgres_service`` for the master PG volume."""

    match = re.search(
        r'_deploy_postgres_service\s+"([^"]+)"\s+"\$\{VOL_MASTER_PG\}"',
        _installer_text(),
    )
    assert match is not None, "could not find the master postgres service create call"
    return match.group(1)


def _installer_broker_service_and_port() -> tuple[str, int]:
    """Name + resolved default port for the broker ``_deploy_master_service`` call."""

    text = _installer_text()
    call = re.search(
        r'_deploy_master_service\s+"([^"]+)"\s+"broker"\s+"\$\{(\w+)\}"',
        text,
    )
    assert call is not None, "could not find the broker service create call"
    name, port_var = call.group(1), call.group(2)

    default = re.search(port_var + r'="\$\{' + port_var + r':-(\d+)\}"', text)
    assert default is not None, f"could not resolve default for ${port_var}"
    return name, int(default.group(1))


def _installer_master_proxy_service() -> str:
    """Name passed to ``_deploy_master_service`` for the public proxy."""

    match = re.search(
        r'_deploy_master_service\s+"([^"]+)"\s+"proxy"\s',
        _installer_text(),
    )
    assert match is not None, "could not find the master proxy service create call"
    return match.group(1)


def _installer_master_proxy_port_default() -> int:
    """Default published proxy port the installer renders into the master config."""

    match = re.search(
        r'MASTER_PROXY_PORT="\$\{MASTER_PROXY_PORT:-(\d+)\}"', _installer_text()
    )
    assert match is not None, "could not resolve MASTER_PROXY_PORT default"
    return int(match.group(1))


def _installer_advertise_addr_default() -> str:
    """Default advertise host the installer renders into gateway.public_base_url."""

    match = re.search(
        r'ADVERTISE_ADDR="\$\{ADVERTISE_ADDR:-([^}"]+)\}"', _installer_text()
    )
    assert match is not None, "could not resolve ADVERTISE_ADDR default"
    return match.group(1)


def _supervisor_autoupdate_services() -> dict[str, set[str]]:
    """Service names the supervisor's PRODUCTION auto-update jobs actually target.

    Reads the live call-site wiring in ``build_scheduled_tasks`` (the override
    that ships in deploys), not the placeholder module defaults, so the guard
    tracks what the supervisor really pins/rolls.
    """

    tasks, _gate = build_scheduled_tasks(Settings())
    image_updater = next(t for t in tasks if t.name == "image-updater")
    config_sync = next(t for t in tasks if t.name == "config-sync")
    updater_services = {
        target.service
        for target in image_updater.run.__self__._targets  # type: ignore[attr-defined]
    }
    rollout_services = set(
        config_sync.run.__self__._rollout_services  # type: ignore[attr-defined]
    )
    return {"image_updater": updater_services, "config_sync": rollout_services}


def _installer_rendered_config_hosts() -> dict[str, str]:
    """Hosts the installer RENDERS into the in-place master config heredoc."""

    text = _installer_text()
    db = re.search(r"url:\s*postgresql\+asyncpg://[^@\s]*@([A-Za-z0-9._-]+):", text)
    broker = re.search(r"broker_url:\s*http://([A-Za-z0-9._-]+):", text)
    assert db is not None, "could not find rendered database url host"
    assert broker is not None, "could not find rendered broker_url host"
    return {"postgres": db.group(1), "broker": broker.group(1)}


def test_master_yaml_postgres_host_matches_installer_created_service() -> None:
    cfg = _master_yaml()
    host, port = _host_port_from_url(cfg["database"]["url"])

    assert host == _installer_master_postgres_service()
    # postgres listens on the standard container port (services are overlay-internal).
    assert port == POSTGRES_DEFAULT_PORT


def test_master_yaml_broker_host_and_port_match_installer_created_service() -> None:
    cfg = _master_yaml()
    host, port = _host_port_from_url(cfg["docker"]["broker_url"])
    service_name, service_port = _installer_broker_service_and_port()

    assert host == service_name
    assert port == service_port
    # broker_port scalar must agree with the broker_url port and the installer.
    assert int(cfg["docker"]["broker_port"]) == service_port


def test_installer_rendered_config_matches_its_own_created_services() -> None:
    """The config the installer writes must reference what the installer creates."""

    rendered = _installer_rendered_config_hosts()

    assert rendered["postgres"] == _installer_master_postgres_service()
    assert rendered["broker"] == _installer_broker_service_and_port()[0]


def test_checked_in_master_config_agrees_with_installer_rendered_config() -> None:
    """deploy/swarm/master.yaml and the installer-rendered config must not drift."""

    cfg = _master_yaml()
    db_host, _ = _host_port_from_url(cfg["database"]["url"])
    broker_host, _ = _host_port_from_url(cfg["docker"]["broker_url"])
    rendered = _installer_rendered_config_hosts()

    assert db_host == rendered["postgres"]
    assert broker_host == rendered["broker"]


def test_supervisor_autoupdate_proxy_target_matches_installer_service() -> None:
    """image-updater + config-sync MUST pin/roll the installer's proxy service.

    The installer creates ``base-master-proxy`` but the supervisor previously
    targeted ``base-proxy``, a name no Swarm service answers to, so the
    digest-pin auto-update and config rollout silently skipped the public API.
    """

    proxy_service = _installer_master_proxy_service()
    targets = _supervisor_autoupdate_services()

    assert proxy_service in targets["image_updater"]
    assert proxy_service in targets["config_sync"]
    # The stale, never-created name must never come back.
    assert "base-proxy" not in targets["image_updater"]
    assert "base-proxy" not in targets["config_sync"]


def test_supervisor_autoupdate_broker_target_matches_installer_service() -> None:
    """image-updater + config-sync MUST pin/roll the installer's broker service."""

    broker_service, _port = _installer_broker_service_and_port()
    targets = _supervisor_autoupdate_services()

    assert broker_service in targets["image_updater"]
    assert broker_service in targets["config_sync"]


def test_supervisor_autoupdate_targets_are_all_installer_created_services() -> None:
    """Every supervisor auto-update target must be a service the installer creates.

    Guards against the auto-update path pointing at phantom service names again.
    """

    installer_services = {
        _installer_master_proxy_service(),
        _installer_broker_service_and_port()[0],
    }
    targets = _supervisor_autoupdate_services()

    assert targets["image_updater"] <= installer_services
    assert targets["config_sync"] <= installer_services


# ---------------------------------------------------------------------------
# Autonomous auto-update (m6, VAL-CODE-AUTO-002): the canonical master.yaml MUST
# carry a supervisor block (so a config-sync tick does not drop self-update) and
# production-correct proxy_port / public_base_url (so config-sync's force-roll
# does not clobber the live deploy onto a wrong port/URL).
# ---------------------------------------------------------------------------


def test_master_yaml_proxy_port_is_production_correct_and_matches_installer() -> None:
    cfg = _master_yaml()
    proxy_port = int(cfg["master"]["proxy_port"])

    # config-sync force-rolls base-master-proxy on any digest change, so a stale
    # port here would roll the live proxy onto the wrong published port.
    assert proxy_port == PROXY_PORT_PRODUCTION
    assert proxy_port == _installer_master_proxy_port_default()


def test_master_yaml_gateway_public_base_url_matches_installer_render() -> None:
    cfg = _master_yaml()
    host, port = _host_port_from_url(cfg["gateway"]["public_base_url"])

    # Installer renders public_base_url as http://${ADVERTISE_ADDR}:${MASTER_PROXY_PORT};
    # the canonical file must agree so config-sync does not clobber it, and the
    # advertised port must equal the port the proxy actually binds to.
    assert host == _installer_advertise_addr_default()
    assert port == _installer_master_proxy_port_default()
    assert port == int(cfg["master"]["proxy_port"])


def test_master_yaml_carries_supervisor_block_for_self_update() -> None:
    cfg = _master_yaml()
    supervisor = cfg.get("supervisor")
    assert isinstance(supervisor, dict), "canonical master.yaml is missing supervisor:"

    # config-sync overwrites /etc/base/master.yaml from this file, so the block
    # must keep self-update ENABLED (not reset to the default-OFF state) and wired
    # to the CI-published manifest, with a registry for credentialed digests.
    assert supervisor["self_update_enabled"] is True
    manifest_url = supervisor["self_update_manifest_url"]
    assert isinstance(manifest_url, str) and manifest_url
    assert manifest_url.endswith("self-update-manifest.json")
    assert supervisor["registry"]


def test_master_yaml_supervisor_block_loads_into_supervisor_settings() -> None:
    # The block must round-trip through the model the supervisor parses, so a
    # config-sync write is consumable when the supervisor restarts.
    cfg = _master_yaml()
    supervisor = SupervisorSettings.model_validate(cfg["supervisor"])

    assert supervisor.self_update_enabled is True
    assert (
        supervisor.self_update_manifest_url
        == cfg["supervisor"]["self_update_manifest_url"]
    )
    assert supervisor.registry == cfg["supervisor"]["registry"]


# ---------------------------------------------------------------------------
# Live-rollout readiness (m9, VAL-CODE-CFG-001): config-sync OVERWRITES
# /etc/base/master.yaml from this canonical file and force-rolls
# base-master-proxy, so the canonical file MUST equal the live working config
# (a sync must be a functional no-op). This guards the exact live values and
# fails if any decommissioned host/port or a null chain endpoint reappears.
# ---------------------------------------------------------------------------


def test_master_yaml_equals_live_production_config() -> None:
    cfg = _master_yaml()

    # master + gateway published proxy endpoint (live 88.216.198.199:19080).
    assert int(cfg["master"]["proxy_port"]) == PROXY_PORT_PRODUCTION
    assert (
        cfg["gateway"]["public_base_url"]
        == f"http://{ADVERTISE_ADDR_PRODUCTION}:{PROXY_PORT_PRODUCTION}"
    )

    # network: live master runs on finney with the mock-metagraph seam OFF.
    assert cfg["network"]["chain_endpoint"] == CHAIN_ENDPOINT_PRODUCTION
    assert cfg["network"]["chain_endpoint"] is not None
    assert cfg["network"]["mock_metagraph"] == []

    # gateway: real providers, keys injected server-side from secret files.
    gateway = cfg["gateway"]
    assert gateway["provider_mode"] == "real"
    assert gateway["token_secret_file"] == "/run/secrets/gateway_token_secret"
    assert gateway["deepseek_api_key_file"] == "/run/secrets/deepseek_api_key"
    assert gateway["openrouter_api_key_file"] == "/run/secrets/openrouter_api_key"

    # broker allowlist matches the live (broad, namespaced) allowlist.
    assert cfg["docker"]["broker_allowed_images"] == ["ghcr.io/baseintelligence/"]

    # database.url stays the env-overridden placeholder (live overrides via
    # BASE_DATABASE__URL); host must be the master postgres service.
    db_host, _ = _host_port_from_url(cfg["database"]["url"])
    assert db_host == _installer_master_postgres_service()

    # supervisor self-update stays ENABLED + wired to the published manifest.
    supervisor = cfg["supervisor"]
    assert supervisor["self_update_enabled"] is True
    assert (
        supervisor["self_update_manifest_url"]
        == "https://raw.githubusercontent.com/BaseIntelligence/base/release/self-update-manifest.json"
    )
    assert supervisor["registry"] == "ghcr.io"
    assert supervisor["registry_docker_config_path"] == "/root/.docker/config.json"

    # Live runs WITHOUT environment=production; flipping it via config-sync would
    # activate policy guards that reject the broad broker allowlist (out of scope).
    assert "environment" not in cfg


def test_master_yaml_has_no_stale_decommissioned_host_or_port() -> None:
    raw = MASTER_YAML.read_text(encoding="utf-8")
    for token in STALE_TOKENS:
        assert token not in raw, f"stale value {token!r} must not appear in master.yaml"

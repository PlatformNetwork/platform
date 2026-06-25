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

ROOT = Path(__file__).resolve().parents[2]
MASTER_YAML = ROOT / "deploy" / "swarm" / "master.yaml"
INSTALL_SWARM = ROOT / "deploy" / "swarm" / "install-swarm.sh"

POSTGRES_DEFAULT_PORT = 5432


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

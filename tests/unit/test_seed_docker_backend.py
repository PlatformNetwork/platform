"""Task 25: seeding on the docker backend + per-slug secret plumbing.

`seed_prism_challenges` is registry-driven and must behave identically when
`runtime.backend == "docker"`: same records, same per-slug token registry
(tokens preserved on re-seed). The runtime controller must carry
record-declared secret names beyond the registry tokens as external Swarm
secret references without ever resolving their values.
"""

from __future__ import annotations

import asyncio
import stat
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import base.cli_app.main as cli_module
import base.supervisor.image_ref as image_ref_module
from base.cli_app.main import DockerRuntimeController
from base.master.registry import ChallengeRegistry, FileChallengeRegistry
from base.schemas.challenge import ChallengeCreate, ChallengeStatus

PINNED_DIGEST = "sha256:" + "c" * 64


@pytest.fixture(autouse=True)
def _offline_digest_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        image_ref_module,
        "resolve_remote_digest",
        lambda image_reference, **kwargs: PINNED_DIGEST,
    )


def _docker_settings() -> SimpleNamespace:
    return SimpleNamespace(
        runtime=SimpleNamespace(backend="docker"),
        docker=SimpleNamespace(broker_url="http://base-docker-broker:8082"),
    )


def _agent_challenge_create() -> ChallengeCreate:
    return ChallengeCreate(
        slug="agent-challenge",
        name="Agent Challenge",
        image="ghcr.io/baseintelligence/agent-challenge:latest",
        version="0.1.0",
        status=ChallengeStatus.ACTIVE,
        emission_percent=Decimal("40"),
    )


def test_seed_on_docker_backend_preserves_per_slug_tokens(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    registry = FileChallengeRegistry(tmp_path / "registry.json", secret_dir)
    _, agent_token = registry.create(_agent_challenge_create())
    agent_broker_token = registry.get_broker_token("agent-challenge")
    settings = _docker_settings()

    first = asyncio.run(cli_module.seed_prism_challenges(registry, settings))
    prism_token = registry.get_token("prism")
    prism_broker_token = registry.get_broker_token("prism")
    second = asyncio.run(cli_module.seed_prism_challenges(registry, settings))

    assert first == {"prism": "created", "agent-challenge": "updated"}
    assert second == {"prism": "updated", "agent-challenge": "updated"}
    assert registry.get_token("agent-challenge") == agent_token
    assert registry.get_broker_token("agent-challenge") == agent_broker_token
    assert registry.get_token("prism") == prism_token
    assert registry.get_broker_token("prism") == prism_broker_token

    prism = registry.get("prism")
    assert prism.secrets == ["challenge_token", "docker_broker_token"]
    assert prism.env["CHALLENGE_DOCKER_BROKER_URL"] == (
        "http://base-docker-broker:8082"
    )
    assert prism.metadata["runtime_database"] == "challenge-local-sqlite"
    assert prism.metadata["workload_class"] == "service"
    agent = registry.get("agent-challenge")
    assert agent.secrets == [
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    ]

    for name in (
        "prism_challenge_token",
        "prism_docker_broker_token",
        "agent-challenge_challenge_token",
        "agent-challenge_docker_broker_token",
    ):
        mode = stat.S_IMODE((secret_dir / name).stat().st_mode)
        assert mode == 0o600, f"{name} must be owner-only, got {oct(mode)}"


def test_runtime_controller_spec_carries_external_secret_names() -> None:
    registry = ChallengeRegistry()
    registry.create(_agent_challenge_create())
    asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))
    controller = DockerRuntimeController(registry, orchestrator=object())

    agent_spec = asyncio.run(controller._spec("agent-challenge"))
    prism_spec = asyncio.run(controller._spec("prism"))

    assert agent_spec.external_secrets == ("submission_env_encryption_key",)
    assert agent_spec.challenge_token == registry.get_token("agent-challenge")
    assert agent_spec.docker_broker_token == (
        registry.get_broker_token("agent-challenge")
    )
    assert agent_spec.secret_names() == (
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    )
    assert prism_spec.external_secrets == ()
    assert prism_spec.secret_names() == ("challenge_token", "docker_broker_token")


def test_seed_agent_challenge_uses_own_runner_execution_plane() -> None:
    registry = ChallengeRegistry()
    registry.create(_agent_challenge_create())
    asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))
    env = registry.get("agent-challenge").env

    # B1: own_runner backend only (the challenge config rejects base_sdk).
    assert env["CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND"] == "own_runner"
    assert "CHALLENGE_BASE_SDK_RUNNER_IMAGE" not in env
    # B4: own_runner reads the runner job image from CHALLENGE_HARBOR_RUNNER_IMAGE.
    assert env["CHALLENGE_HARBOR_RUNNER_IMAGE"] == (
        cli_module.AGENT_CHALLENGE_TERMINAL_BENCH_RUNNER_IMAGE
    )
    # B2/B3: read-only task-cache + frozen digest manifest mount targets (must
    # match docker.broker_eval_readonly_mounts in install-swarm.sh).
    assert env["CHALLENGE_OWN_RUNNER_CACHE_ROOT"] == "/opt/agent-challenge/task-cache"
    assert env["CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST"] == (
        "/opt/agent-challenge/golden/dataset-digest.json"
    )
    # C1: real-time log streaming back to the challenge API over the overlay.
    assert env["CHALLENGE_TERMINAL_BENCH_LOG_STREAM_URL"] == (
        "http://challenge-agent-challenge:8000"
    )
    # The eval JOB runs on the ISOLATED internal overlay (no postgres, no egress),
    # not the broad base_challenges overlay; the api+proxy are multi-homed onto it.
    assert env["CHALLENGE_DOCKER_BROKER_NETWORK"] == "base_jobs_internal"
    assert env["CHALLENGE_DOCKER_BACKEND"] == "broker"


def test_parse_eval_readonly_mounts_filters_malformed() -> None:
    parsed = cli_module._parse_eval_readonly_mounts(
        [
            "agent_challenge_task_cache:/opt/agent-challenge/task-cache",
            "/var/lib/x/golden:/opt/agent-challenge/golden",
            "noslash",  # no colon -> skipped
            "vol:relative/path",  # target not absolute -> skipped
            "",  # empty -> skipped
        ]
    )
    assert parsed == (
        ("agent_challenge_task_cache", "/opt/agent-challenge/task-cache"),
        ("/var/lib/x/golden", "/opt/agent-challenge/golden"),
    )


def test_eval_readonly_mounts_by_slug_includes_prism_train_default() -> None:
    # The prism slug receives its locked-data RO mounts out of the box (the
    # train split + reference tokenizers), so the broker wiring is not inert
    # before the deploy feature populates master.yaml.
    parsed = cli_module._eval_readonly_mounts_by_slug({})
    assert parsed["prism"] == (
        ("prism_fineweb_edu_train", "/data/fineweb-edu/train"),
        ("prism_reference_tokenizers", "/opt/prism/reference-tokenizers"),
    )
    # ONLY the train split is exposed; the held-out splits are never mounted.
    targets = [target for _source, target in parsed["prism"]]
    assert "/data/fineweb-edu/val" not in targets
    assert "/data/fineweb-edu/test" not in targets


def test_eval_readonly_mounts_by_slug_config_overrides_default() -> None:
    parsed = cli_module._eval_readonly_mounts_by_slug(
        {
            "prism": ["prism_fineweb_edu_train:/data/fineweb-edu/train"],
            "other": ["vol:/x", "bad-no-colon"],
        }
    )
    assert parsed["prism"] == (("prism_fineweb_edu_train", "/data/fineweb-edu/train"),)
    assert parsed["other"] == (("vol", "/x"),)


def test_agent_challenge_job_network_is_isolated_internal_overlay() -> None:
    """The eval JOB network is the isolated internal overlay (base_jobs_internal:
    no postgres, no egress), reused from swarm_backend.DEFAULT_JOB_NETWORK as the
    single source of truth rather than a duplicated 'base_challenges' string."""
    from base.master.swarm_backend import DEFAULT_JOB_NETWORK

    assert cli_module.AGENT_CHALLENGE_JOB_NETWORK == "base_jobs_internal"
    assert cli_module.AGENT_CHALLENGE_JOB_NETWORK == DEFAULT_JOB_NETWORK


def test_log_stream_host_matches_agent_challenge_service_name() -> None:
    """CHALLENGE_TERMINAL_BENCH_LOG_STREAM_URL host MUST equal the agent-challenge
    service name reachable on base_jobs_internal, else log streaming fails DNS."""
    from urllib.parse import urlsplit

    from base.master.docker_orchestrator import ChallengeSpec
    from base.master.registry import default_internal_base_url

    service_name = ChallengeSpec(
        slug="agent-challenge", image="ghcr.io/baseintelligence/agent:1"
    ).container_name
    assert service_name == "challenge-agent-challenge"

    constant_host = urlsplit(cli_module.AGENT_CHALLENGE_INTERNAL_BASE_URL).hostname
    assert constant_host == service_name
    assert (
        constant_host == urlsplit(default_internal_base_url("agent-challenge")).hostname
    )

    registry = ChallengeRegistry()
    registry.create(_agent_challenge_create())
    asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))
    env = registry.get("agent-challenge").env
    assert urlsplit(env["CHALLENGE_TERMINAL_BENCH_LOG_STREAM_URL"]).hostname == (
        service_name
    )

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from base.master.docker_orchestrator import (
    DEFAULT_CHALLENGE_PORT,
    DEFAULT_DOCKER_BROKER_URL,
    DEFAULT_SQLITE_PATH,
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
    DockerOrchestrator,
    _safe_secret_name,
    _safe_slug,
    challenge_spec_from_registry,
    combined_mode_env_from_metadata,
    port_from_internal_base_url,
)


@pytest.mark.parametrize(
    "internal_base_url, expected",
    [
        ("http://challenge-prism:8080", 8080),
        ("http://challenge-agent-challenge:8000", 8000),
        ("http://challenge-prism", DEFAULT_CHALLENGE_PORT),
        (None, DEFAULT_CHALLENGE_PORT),
        ("", DEFAULT_CHALLENGE_PORT),
    ],
)
def test_port_from_internal_base_url(
    internal_base_url: str | None, expected: int
) -> None:
    assert port_from_internal_base_url(internal_base_url) == expected


class FakeCollection:
    def __init__(self, created: object) -> None:
        self.created = created
        self.get_calls = 0
        self.create_calls: list[dict[str, object]] = []

    def get(self, name: str) -> object:
        self.get_calls += 1
        if self.get_calls == 1:
            raise RuntimeError("missing")
        return self.created

    def create(self, *args: object, **kwargs: object) -> object:
        self.create_calls.append({"args": args, "kwargs": kwargs})
        return self.created


class FakeImages:
    def __init__(self) -> None:
        self.pulled: list[str] = []

    def pull(self, image: str) -> str:
        self.pulled.append(image)
        return image


class FakeContainers:
    def __init__(self) -> None:
        self.container = SimpleNamespace(id="cid", status="created", start=lambda: None)
        self.runs: list[dict[str, object]] = []

    def get(self, name: str) -> object:
        raise RuntimeError("missing")

    def run(self, image: str, **kwargs: object) -> object:
        self.runs.append({"image": image, **kwargs})
        return self.container


class FakeClient:
    def __init__(self) -> None:
        self.networks = FakeCollection("network")
        self.volumes = FakeCollection("volume")
        self.images = FakeImages()
        self.containers = FakeContainers()


def test_challenge_spec_and_resource_validation() -> None:
    spec = ChallengeSpec(slug=" Demo One ", image="ghcr.io/org/demo:1", port=9000)
    assert spec.safe_slug == "demo-one"
    assert spec.container_name == "challenge-demo-one"
    assert spec.sqlite_volume_name == "base_demo_one_sqlite"
    assert spec.internal_base_url == "http://challenge-demo-one:9000"
    kwargs = ChallengeResources(cpu=1.5, memory="1g").as_container_kwargs()
    assert kwargs["nano_cpus"] == 1_500_000_000
    assert kwargs["mem_limit"] == "1g"
    assert kwargs["memswap_limit"] == "4g"
    assert kwargs["pids_limit"] == 512
    assert kwargs["read_only"] is True
    assert kwargs["init"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=512m"}
    assert ChallengeResources.from_mapping(
        {"cpu": "2", "memory": "512m"}
    ) == ChallengeResources(cpu=2.0, memory="512m")
    assert ChallengeResources.from_mapping({"cpu": "500m"}).cpu == 0.5
    gpu_resources = ChallengeResources.from_mapping(
        {
            "gpu_count": "1",
            "gpu_device_ids": "0,1",
            "gpu_capabilities": "gpu,compute",
        }
    )
    assert gpu_resources.gpu_count == 1
    assert gpu_resources.gpu_device_ids == ("0", "1")
    assert gpu_resources.gpu_capabilities == ("gpu", "compute")
    with pytest.raises(DockerOrchestrationError):
        ChallengeResources(cpu=0).as_container_kwargs()
    with pytest.raises(DockerOrchestrationError):
        ChallengeResources(pids_limit=0).as_container_kwargs()
    with pytest.raises(DockerOrchestrationError):
        ChallengeResources(tmpfs=("tmp:rw",)).as_container_kwargs()
    with pytest.raises(DockerOrchestrationError):
        _ = ChallengeSpec(slug="!!!", image="ghcr.io/x/y:1").safe_slug


def test_orchestrator_client_network_volume_pull_and_env(tmp_path: Path) -> None:
    client = FakeClient()
    orchestrator = DockerOrchestrator(client=client, secret_dir=tmp_path)
    spec = ChallengeSpec(
        slug="demo",
        image="ghcr.io/org/demo:1",
        challenge_token="tok",
        secrets={"api-key": "secret"},
        env={"EXISTING": "1"},
    )
    assert orchestrator.ensure_network() == "network"
    assert orchestrator.ensure_network() == "network"
    assert orchestrator.ensure_sqlite_volume(spec) == "volume"
    assert orchestrator.ensure_sqlite_volume(spec) == "volume"
    assert orchestrator.pull_image(spec.image) == spec.image
    with pytest.raises(DockerOrchestrationError):
        orchestrator.pull_image("docker.io/org/demo:1")

    env = orchestrator._build_environment(spec)  # noqa: SLF001
    assert env["EXISTING"] == "1"
    assert env["CHALLENGE_DATABASE_URL"] == f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}"
    assert env["CHALLENGE_SHARED_TOKEN_FILE"] == "/run/secrets/base/challenge_token"
    paths = orchestrator._write_secret_files(spec)  # noqa: SLF001
    assert paths["challenge_token"].read_text(encoding="utf-8") == "tok"
    assert paths["api-key"].read_text(encoding="utf-8") == "secret"


def test_create_container_honors_worker_command(tmp_path: Path) -> None:
    client = FakeClient()
    orchestrator = DockerOrchestrator(client=client, secret_dir=tmp_path)
    spec = ChallengeSpec(
        slug="demo",
        image="ghcr.io/org/demo:1",
        worker_command=("agent-challenge-worker", "--mode", "x"),
    )

    container = orchestrator._create_container(spec)  # noqa: SLF001

    assert container is client.containers.container
    run_call = client.containers.runs[0]
    assert run_call["image"] == "ghcr.io/org/demo:1"
    assert run_call["command"] == ["agent-challenge-worker", "--mode", "x"]


def test_create_container_without_worker_command_uses_image_default(
    tmp_path: Path,
) -> None:
    client = FakeClient()
    orchestrator = DockerOrchestrator(client=client, secret_dir=tmp_path)
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")
    assert spec.worker_command == ()

    orchestrator._create_container(spec)  # noqa: SLF001

    run_call = client.containers.runs[0]
    assert "command" not in run_call


@pytest.mark.parametrize(
    "metadata, expected",
    [
        ({}, None),
        ({"combined_mode_env": None}, None),
        (
            {"combined_mode_env": "CHALLENGE_COMBINED_WORKER"},
            "CHALLENGE_COMBINED_WORKER",
        ),
        ({"combined_mode_env": "  PRISM_COMBINED_MODE  "}, "PRISM_COMBINED_MODE"),
    ],
)
def test_combined_mode_env_from_metadata(
    metadata: dict[str, object], expected: str | None
) -> None:
    assert combined_mode_env_from_metadata(metadata) == expected


@pytest.mark.parametrize("bad", ["", "   ", 123, ["CHALLENGE_COMBINED_WORKER"]])
def test_combined_mode_env_from_metadata_rejects_invalid(bad: object) -> None:
    with pytest.raises(DockerOrchestrationError, match="combined_mode_env"):
        combined_mode_env_from_metadata({"combined_mode_env": bad})


def test_challenge_spec_from_registry_injects_combined_env_and_no_command() -> None:
    challenge = SimpleNamespace(
        slug="prism",
        image="ghcr.io/o/prism:1",
        version="1",
        env={
            "PRISM_DOCKER_BROKER_URL": "http://base-docker-broker:8082",
            "PRISM_DOCKER_BROKER_TOKEN_FILE": "/run/secrets/base/docker_broker_token",
        },
        resources={"cpu": "2", "memory": "8g"},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={"combined_mode_env": "PRISM_COMBINED_MODE"},
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.env["PRISM_COMBINED_MODE"] == "true"
    assert spec.env["PRISM_DOCKER_BROKER_URL"] == "http://base-docker-broker:8082"
    assert spec.env["PRISM_DOCKER_BROKER_TOKEN_FILE"] == (
        "/run/secrets/base/docker_broker_token"
    )
    assert spec.worker_command == ()
    assert spec.workload_class == "service"
    assert spec.container_name == "challenge-prism"


def test_challenge_spec_from_registry_preserves_explicit_env_override() -> None:
    # An operator-set value in the record env is preserved (setdefault semantics).
    challenge = SimpleNamespace(
        slug="prism",
        image="ghcr.io/o/prism:1",
        version="1",
        env={"PRISM_COMBINED_MODE": "false"},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={"combined_mode_env": "PRISM_COMBINED_MODE"},
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.env["PRISM_COMBINED_MODE"] == "false"


def test_challenge_spec_from_registry_without_combined_env() -> None:
    challenge = SimpleNamespace(
        slug="demo",
        image="ghcr.io/o/demo:1",
        version="1",
        env={"FOO": "bar"},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.env == {"FOO": "bar"}
    assert spec.worker_command == ()


@pytest.mark.parametrize(
    "internal_base_url, expected_port",
    [
        ("http://challenge-prism:8080", 8080),
        ("http://challenge-agent-challenge:8000", 8000),
        ("http://challenge-prism", DEFAULT_CHALLENGE_PORT),
        (None, DEFAULT_CHALLENGE_PORT),
    ],
)
def test_challenge_spec_from_registry_sets_port_from_internal_base_url(
    internal_base_url: str | None, expected_port: int
) -> None:
    challenge = SimpleNamespace(
        slug="prism",
        image="ghcr.io/o/prism:1",
        version="1",
        env={},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
        internal_base_url=internal_base_url,
        secrets=[],
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.port == expected_port
    # ``internal_base_url`` property reflects the parsed port.
    assert spec.internal_base_url == f"http://challenge-prism:{expected_port}"


def test_challenge_spec_from_registry_defaults_port_when_url_attr_absent() -> None:
    # A duck-typed record without an ``internal_base_url`` attribute at all
    # keeps the legacy default port (byte-identical legacy path).
    challenge = SimpleNamespace(
        slug="demo",
        image="ghcr.io/o/demo:1",
        version="1",
        env={},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.port == DEFAULT_CHALLENGE_PORT


def test_challenge_spec_from_registry_references_declared_secrets() -> None:
    # Every registry-declared secret NAME becomes a reference-only external
    # secret; the reconciler never has the token VALUES, so no value-bearing
    # challenge/broker token is set on the spec.
    challenge = SimpleNamespace(
        slug="agent-challenge",
        image="ghcr.io/o/agent-challenge:1",
        version="1",
        env={},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
        internal_base_url="http://challenge-agent-challenge:8000",
        secrets=[
            "challenge_token",
            "docker_broker_token",
            "submission_env_encryption_key",
        ],
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.external_secrets == (
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    )
    # Reference-only: no value-bearing secrets are attached by the reconciler.
    assert spec.challenge_token is None
    assert spec.docker_broker_token is None
    assert spec.all_secrets() == {}
    # Every declared name is visible inside the container as an external ref.
    assert spec.secret_names() == (
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    )


def test_challenge_spec_from_registry_does_not_force_add_provider_key() -> None:
    # A raw provider key rides through ONLY if the record itself declares it;
    # nothing forces openrouter/any provider secret onto every challenge.
    challenge = SimpleNamespace(
        slug="prism",
        image="ghcr.io/o/prism:1",
        version="1",
        env={},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
        internal_base_url="http://challenge-prism:8080",
        secrets=["challenge_token", "docker_broker_token"],
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.external_secrets == ("challenge_token", "docker_broker_token")
    assert not any("openrouter" in name for name in spec.external_secrets)


def test_challenge_spec_from_registry_no_url_or_secrets_keeps_prior_behavior() -> None:
    # Back-compat: a record with no internal_base_url and no secrets yields the
    # legacy spec (default port, no external secrets) - byte-identical.
    challenge = SimpleNamespace(
        slug="demo",
        image="ghcr.io/o/demo:1",
        version="1",
        env={"FOO": "bar"},
        resources={},
        required_capabilities=["get_weights", "proxy_routes"],
        metadata={},
        internal_base_url=None,
        secrets=[],
    )

    spec = challenge_spec_from_registry(challenge)

    assert spec.port == DEFAULT_CHALLENGE_PORT
    assert spec.external_secrets == ()
    assert spec.secret_names() == ()
    assert spec.env == {"FOO": "bar"}
    assert spec.workload_class == "service"


def test_docker_orchestrator_database_url_defaults_to_sqlite_data_volume(
    tmp_path: Path,
) -> None:
    orchestrator = DockerOrchestrator(client=FakeClient(), secret_dir=tmp_path)
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")

    env = orchestrator._build_environment(spec)  # noqa: SLF001
    mounts = orchestrator._build_mounts(spec)  # noqa: SLF001

    assert (
        env["CHALLENGE_DATABASE_URL"] == "sqlite+aiosqlite:////data/challenge.sqlite3"
    )
    assert env["CHALLENGE_DATABASE_URL"] == f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}"
    assert {
        "Target": "/data",
        "Source": spec.sqlite_volume_name,
        "Type": "volume",
        "ReadOnly": False,
    } in mounts


def test_orchestrator_enables_docker_executor_broker(tmp_path: Path) -> None:
    orchestrator = DockerOrchestrator(
        client=FakeClient(),
        secret_dir=tmp_path,
        docker_broker_url="http://broker:8082",
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/org/agent:1",
        required_capabilities=("get_weights", "proxy_routes", "docker_executor"),
    )

    env = orchestrator._build_environment(spec)  # noqa: SLF001
    mounts = orchestrator._build_mounts(spec)  # noqa: SLF001

    assert env["CHALLENGE_DOCKER_ENABLED"] == "true"
    assert env["CHALLENGE_DOCKER_BACKEND"] == "broker"
    assert env["CHALLENGE_DOCKER_BROKER_URL"] == "http://broker:8082"
    assert env["CHALLENGE_DOCKER_BROKER_TOKEN_FILE"] == (
        "/run/secrets/base/docker_broker_token"
    )
    assert DEFAULT_DOCKER_BROKER_URL == "http://base-docker-broker:8082"
    assert "/var/run/docker.sock" not in repr(mounts)


def test_orchestrator_validation_and_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = FakeClient()
    orchestrator = DockerOrchestrator(client=client, secret_dir=tmp_path)
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1", version="1.0.0")
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: (
            {"status": "ok", "slug": spec.slug},
            {
                "api_version": "1.0",
                "challenge_version": "1.0.0",
                "capabilities": ["get_weights", "proxy_routes"],
            },
        ),
    )
    runtime = orchestrator.start_challenge(spec)
    assert runtime.container_name == "challenge-demo"
    assert orchestrator.runtime["demo"].image == spec.image
    run_kwargs = client.containers.runs[0]
    assert run_kwargs["name"] == "challenge-demo"
    assert run_kwargs["nano_cpus"] == 2_000_000_000
    assert run_kwargs["mem_limit"] == "4g"
    assert run_kwargs["memswap_limit"] == "4g"
    assert run_kwargs["pids_limit"] == 512
    assert run_kwargs["init"] is True
    assert run_kwargs["read_only"] is True
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert run_kwargs["security_opt"] == ["no-new-privileges"]
    assert run_kwargs["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=512m"}

    orchestrator._validate_health(spec, {"status": "ok", "slug": "demo"})  # noqa: SLF001
    orchestrator._validate_version(  # noqa: SLF001
        spec,
        {
            "api_version": "1.0",
            "challenge_version": "1.0.0",
            "capabilities": ["get_weights", "proxy_routes"],
        },
    )
    for bad_health in ({"status": "bad"}, {"status": "ok", "slug": "other"}):
        with pytest.raises(DockerOrchestrationError):
            orchestrator._validate_health(spec, bad_health)  # noqa: SLF001
    for bad_version in (
        {"api_version": "2", "challenge_version": "1.0.0", "capabilities": []},
        {"api_version": "1.0", "challenge_version": "2.0.0", "capabilities": []},
        {"api_version": "1.0", "challenge_version": "1.0.0", "capabilities": "bad"},
        {"api_version": "1.0", "challenge_version": "1.0.0", "capabilities": []},
    ):
        with pytest.raises(DockerOrchestrationError):
            orchestrator._validate_version(spec, bad_version)  # noqa: SLF001

    with pytest.raises(DockerOrchestrationError):
        _safe_slug("!!!")
    with pytest.raises(DockerOrchestrationError):
        _safe_secret_name("!!!")
    assert _safe_secret_name("api-key") == "api-key"


def test_get_json_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = DockerOrchestrator(client=FakeClient())

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"ok": True}).encode()

    monkeypatch.setattr(
        "base.master.docker_orchestrator.urlopen",
        lambda *a, **k: Response(),
    )
    assert orchestrator._get_json("http://x") == {"ok": True}  # noqa: SLF001
    monkeypatch.setattr(
        "base.master.docker_orchestrator.urlopen",
        lambda *a, **k: ResponseWithBytes(b"[]"),
    )
    with pytest.raises(DockerOrchestrationError):
        orchestrator._get_json("http://x")  # noqa: SLF001


class ResponseWithBytes:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.data


def test_list_running_challenge_slugs_reads_labels() -> None:
    # VAL-CODE-REG-006: cross-restart self-heal discovers actually-running
    # challenge containers by their ``base.component=challenge`` label and reads
    # the original slug from ``base.challenge.slug``.
    class _Container:
        def __init__(self, labels: dict[str, str]) -> None:
            self.labels = labels

    class _ListContainers:
        def __init__(self) -> None:
            self.filters: dict[str, str] | None = None

        def list(self, *, filters: dict[str, str]) -> list[object]:
            self.filters = filters
            return [
                _Container(
                    {"base.component": "challenge", "base.challenge.slug": "prism"}
                ),
                _Container(
                    {
                        "base.component": "challenge",
                        "base.challenge.slug": "agent-challenge",
                    }
                ),
                _Container({"base.component": "challenge"}),  # no slug -> skipped
            ]

    class _Client:
        def __init__(self) -> None:
            self.containers = _ListContainers()

    client = _Client()
    orchestrator = DockerOrchestrator(client=client)

    slugs = orchestrator.list_running_challenge_slugs()

    assert slugs == frozenset({"prism", "agent-challenge"})
    assert client.containers.filters == {"label": "base.component=challenge"}

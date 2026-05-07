from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from platform_network.master.docker_orchestrator import (
    DEFAULT_DOCKER_BROKER_URL,
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
    DockerOrchestrator,
    _safe_secret_name,
    _safe_slug,
)


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
    assert spec.sqlite_volume_name == "platform_demo_one_sqlite"
    assert spec.internal_base_url == "http://challenge-demo-one:9000"
    assert ChallengeResources(cpu=1.5, memory="1g").as_container_kwargs() == {
        "nano_cpus": 1_500_000_000,
        "mem_limit": "1g",
    }
    assert ChallengeResources.from_mapping(
        {"cpu": "2", "memory": "512m"}
    ) == ChallengeResources(cpu=2.0, memory="512m")
    with pytest.raises(DockerOrchestrationError):
        ChallengeResources(cpu=0).as_container_kwargs()
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
    assert env["CHALLENGE_SHARED_TOKEN_FILE"] == "/run/secrets/platform/challenge_token"
    paths = orchestrator._write_secret_files(spec)  # noqa: SLF001
    assert paths["challenge_token"].read_text(encoding="utf-8") == "tok"
    assert paths["api-key"].read_text(encoding="utf-8") == "secret"


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
        "/run/secrets/platform/challenge_token"
    )
    assert DEFAULT_DOCKER_BROKER_URL == "http://platform-docker-broker:8082"
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
    assert client.containers.runs[0]["name"] == "challenge-demo"

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
        "platform_network.master.docker_orchestrator.urlopen",
        lambda *a, **k: Response(),
    )
    assert orchestrator._get_json("http://x") == {"ok": True}  # noqa: SLF001
    monkeypatch.setattr(
        "platform_network.master.docker_orchestrator.urlopen",
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

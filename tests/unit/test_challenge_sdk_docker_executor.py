from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from platform_network.challenge_sdk.executors.docker import (
    DockerContainerInfo,
    DockerExecutor,
    DockerExecutorError,
    DockerLimits,
    DockerMount,
    DockerRunSpec,
)


def test_build_run_command_has_security_flags(tmp_path: Path) -> None:
    spec = DockerRunSpec(
        image="platformnetwork/swe-forge:task",
        command=("bash", "/workspace/forge/evaluate.sh"),
        mounts=(DockerMount(tmp_path, "/workspace/forge"),),
        workdir="/workspace/repo",
        labels={"platform.job": "job-1", "platform.task": "task-1"},
        limits=DockerLimits(cpus=1.5, memory="512m", pids_limit=64),
    )
    executor = DockerExecutor(
        challenge="agent", allowed_images=("platformnetwork/swe-forge:",)
    )

    cmd = executor.build_run_command(spec, "agent-job-task")

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network" in cmd and "none" in cmd
    assert "--cpus" in cmd and "1.5" in cmd
    assert "--memory" in cmd and "512m" in cmd
    assert "--pids-limit" in cmd and "64" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges" in cmd
    assert "--read-only" in cmd
    assert "--init" in cmd
    assert "--memory-swap" in cmd and "512m" in cmd
    assert "--ulimit" in cmd and "nofile=1024:1024" in cmd
    assert "--label" in cmd and "platform.challenge=agent" in cmd
    assert "platform.challenge=evil" not in cmd
    assert f"{tmp_path.resolve()}:/workspace/forge:ro" in cmd
    assert cmd[-3:] == [
        "platformnetwork/swe-forge:task",
        "bash",
        "/workspace/forge/evaluate.sh",
    ]


def test_docker_limits_default_to_hardened_runtime_controls() -> None:
    limits = DockerLimits(cpus=1, memory="512m", pids_limit=1)

    assert limits.init is True
    assert limits.read_only is True
    assert limits.cap_drop == ("ALL",)
    assert limits.security_opt == ("no-new-privileges",)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cpus": 0},
        {"memory": ""},
        {"memory_swap": ""},
        {"pids_limit": 0},
        {"cap_drop": ()},
        {"security_opt": ()},
    ],
)
def test_docker_limits_reject_unsafe_values(kwargs: dict[str, Any]) -> None:
    with pytest.raises(DockerExecutorError):
        DockerLimits(**kwargs)


def test_reserved_labels_cannot_be_overridden(tmp_path: Path) -> None:
    spec = DockerRunSpec(
        image="platformnetwork/swe-forge:task",
        command=("true",),
        mounts=(DockerMount(tmp_path, "/workspace/forge"),),
        labels={"platform.challenge": "evil", "platform.job": "job-1"},
    )
    cmd = DockerExecutor(
        challenge="agent", allowed_images=("platformnetwork/",)
    ).build_run_command(spec, "name")

    assert "platform.challenge=agent" in cmd
    assert "platform.challenge=evil" not in cmd


@pytest.mark.parametrize(
    "image",
    ["-v", "bad image", "../../bad"],
)
def test_rejects_unsafe_image_refs(tmp_path: Path, image: str) -> None:
    spec = DockerRunSpec(
        image=image,
        command=("true",),
        mounts=(DockerMount(tmp_path, "/x"),),
    )
    with pytest.raises(DockerExecutorError):
        DockerExecutor(challenge="agent").build_run_command(spec, "name")


def test_rejects_images_outside_allowlist(tmp_path: Path) -> None:
    spec = DockerRunSpec(
        image="docker.io/library/python:latest",
        command=("true",),
        mounts=(DockerMount(tmp_path, "/x"),),
    )
    with pytest.raises(DockerExecutorError):
        DockerExecutor(challenge="agent", allowed_images=("platformnetwork/",)).run(
            spec, timeout_seconds=1
        )


def test_allows_default_network_for_broker_compatible_jobs(tmp_path: Path) -> None:
    spec = DockerRunSpec(
        image="platformnetwork/swe-forge:task",
        command=("true",),
        mounts=(DockerMount(tmp_path, "/x"),),
        limits=DockerLimits(network="default"),
    )

    cmd = DockerExecutor(
        challenge="agent", allowed_images=("platformnetwork/",)
    ).build_run_command(spec, "name")

    assert "--network" in cmd and "default" in cmd


def test_cleanup_job_uses_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(cmd)
        if cmd[:3] == ["docker", "ps", "-aq"]:
            return SimpleNamespace(stdout="abc\ndef\n", stderr="", returncode=0)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    DockerExecutor(challenge="agent").cleanup_job("job-1")

    assert calls[0] == [
        "docker",
        "ps",
        "-aq",
        "--filter",
        "label=platform.challenge=agent",
        "--filter",
        "label=platform.job=job-1",
    ]
    assert calls[1] == ["docker", "rm", "-f", "abc", "def"]


def test_list_containers_uses_challenge_and_job_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(cmd)
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "ID": "abc",
                    "Names": "agent-job",
                    "Image": "python:3.12",
                    "Status": "Up",
                    "CreatedAt": "now",
                    "Labels": "platform.challenge=agent,platform.job=job-1",
                }
            )
            + "\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    containers = DockerExecutor(challenge="agent").list_containers("job-1")

    assert calls[0] == [
        "docker",
        "ps",
        "-a",
        "--filter",
        "label=platform.challenge=agent",
        "--filter",
        "label=platform.job=job-1",
        "--format",
        "{{json .}}",
    ]
    assert containers == [
        DockerContainerInfo(
            container_id="abc",
            container_name="agent-job",
            image="python:3.12",
            status="Up",
            job_id="job-1",
            created="now",
            labels={"platform.challenge": "agent", "platform.job": "job-1"},
        )
    ]


def test_broker_backend_posts_run_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import platform_network.challenge_sdk.executors.docker as module

    (tmp_path / "input.txt").write_text("ok", encoding="utf-8")
    captured: dict[str, Any] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "container_name": "agent-job",
                    "stdout": "ok",
                    "stderr": "",
                    "returncode": 0,
                    "timed_out": False,
                }
            ).encode()

    def fake_urlopen(request: object, timeout: int) -> Response:
        captured["timeout"] = timeout
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["headers"] = dict(request.headers.items())  # type: ignore[attr-defined]
        captured["payload"] = json.loads(request.data.decode())  # type: ignore[attr-defined]
        return Response()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    result = DockerExecutor(
        challenge="agent",
        backend="broker",
        broker_url="http://broker",
        broker_token="tok",
        allowed_images=("python:",),
    ).run(
        DockerRunSpec(
            image="python:3.12-slim",
            command=("python", "-V"),
            mounts=(DockerMount(tmp_path, "/mnt"),),
            labels={"platform.job": "job-1"},
        ),
        timeout_seconds=20,
    )

    assert result.returncode == 0
    assert captured["url"] == "http://broker/v1/docker/run"
    headers = cast(dict[str, str], captured["headers"])
    assert headers["Authorization"] == "Bearer tok"
    payload = cast(dict[str, Any], captured["payload"])
    assert payload["image"] == "python:3.12-slim"
    assert payload["mounts"][0]["target"] == "/mnt"
    assert payload["timeout_seconds"] == 20


def test_broker_backend_lists_containers(monkeypatch: pytest.MonkeyPatch) -> None:
    import platform_network.challenge_sdk.executors.docker as module

    captured: dict[str, Any] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "containers": [
                        {
                            "container_id": "abc",
                            "container_name": "agent-job",
                            "image": "python",
                            "status": "running",
                            "job_id": "job-1",
                            "labels": {"platform.challenge": "agent"},
                        }
                    ]
                }
            ).encode()

    def fake_urlopen(request: object, timeout: int) -> Response:
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["payload"] = json.loads(request.data.decode())  # type: ignore[attr-defined]
        return Response()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    containers = DockerExecutor(
        challenge="agent",
        backend="broker",
        broker_url="http://broker",
        broker_token="tok",
    ).list_containers("job-1")

    assert captured["url"] == "http://broker/v1/docker/list"
    assert cast(dict[str, Any], captured["payload"]) == {"job_id": "job-1"}
    assert containers[0].container_name == "agent-job"


def test_broker_backend_cleanup_posts_job_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import platform_network.challenge_sdk.executors.docker as module

    captured: dict[str, Any] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"status": "ok"}).encode()

    def fake_urlopen(request: object, timeout: int) -> Response:
        captured["timeout"] = timeout
        captured["url"] = request.full_url  # type: ignore[attr-defined]
        captured["headers"] = dict(request.headers.items())  # type: ignore[attr-defined]
        captured["payload"] = json.loads(request.data.decode())  # type: ignore[attr-defined]
        return Response()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    DockerExecutor(
        challenge="agent",
        backend="broker",
        broker_url="http://broker",
        broker_token="tok",
    ).cleanup_job("job-1")

    assert captured["url"] == "http://broker/v1/docker/cleanup"
    assert captured["headers"]["Authorization"] == "Bearer tok"
    assert cast(dict[str, Any], captured["payload"]) == {"job_id": "job-1"}
    assert captured["timeout"] == 30


def test_template_executor_matches_shared_sdk() -> None:
    root = Path(__file__).resolve().parents[2]
    shared = root / "src/platform_network/challenge_sdk/executors/docker.py"
    template = (
        root
        / "src/platform_network/templates/challenge/src"
        / "__package_name__/sdk/executors/docker.py.j2"
    )
    assert template.read_text(encoding="utf-8") == shared.read_text(encoding="utf-8")

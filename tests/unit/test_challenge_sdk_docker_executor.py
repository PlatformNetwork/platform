from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from platform_network.challenge_sdk.executors.docker import (
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
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges" in cmd
    assert "--read-only" in cmd
    assert "--init" in cmd
    assert "--memory-swap" in cmd and "512m" in cmd
    assert "--ulimit" in cmd and "nofile=1024:1024" in cmd
    assert "--label" in cmd and "platform.challenge=agent" in cmd
    assert f"{tmp_path.resolve()}:/workspace/forge:ro" in cmd
    assert cmd[-3:] == [
        "platformnetwork/swe-forge:task",
        "bash",
        "/workspace/forge/evaluate.sh",
    ]


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


def test_broker_backend_posts_run_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import platform_network.challenge_sdk.executors.docker as module

    (tmp_path / "input.txt").write_text("ok", encoding="utf-8")
    captured: dict[str, object] = {}

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
    assert captured["headers"]["Authorization"] == "Bearer tok"
    payload = captured["payload"]
    assert payload["image"] == "python:3.12-slim"
    assert payload["mounts"][0]["target"] == "/mnt"
    assert payload["timeout_seconds"] == 20


def test_template_executor_matches_shared_sdk() -> None:
    root = Path(__file__).resolve().parents[2]
    shared = root / "src/platform_network/challenge_sdk/executors/docker.py"
    template = (
        root
        / "src/platform_network/templates/challenge/src"
        / "__package_name__/sdk/executors/docker.py.j2"
    )
    assert template.read_text(encoding="utf-8") == shared.read_text(encoding="utf-8")

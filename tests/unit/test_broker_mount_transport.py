"""Cross-node broker mount transport: bootstrap, drain parsing, and the
executor's writable-mount round-trip.

These cover Risk #1 — a GPU eval job runs on the remote GPU worker where the
broker-node bind sources do not exist — at the unit level (no dockerd). The
filename carries the ``broker`` selector token so the milestone gate runs it.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

import platform_network.challenge_sdk.executors.docker as executor_module
from platform_network.challenge_sdk.executors.docker import (
    DockerExecutor,
    DockerLimits,
    DockerMount,
    DockerRunSpec,
)
from platform_network.challenge_sdk.mount_transport import (
    MAX_ENV_CHUNK_BYTES,
    TransportMount,
    build_bootstrap_command,
    encode_dir_archive,
    encode_mount_in_env,
    extract_archive_to_dir,
    mount_in_env_var,
    parse_drained_archives,
    strip_drain_sections,
)


def _drain_section(index: int, source: Path) -> str:
    """A stdout drain section exactly as the bootstrap emits for one mount."""

    blob = encode_dir_archive(source)
    return (
        f"@@PLATFORM_BROKER_MOUNT_OUT[{index}]:BEGIN@@\n"
        f"{blob}\n"
        f"@@PLATFORM_BROKER_MOUNT_OUT[{index}]:END@@\n"
    )


def test_broker_bootstrap_wraps_command_and_drains_only_writable() -> None:
    command = build_bootstrap_command(
        ["torchrun", "/workspace/runner.py", "/workspace/payload.json"],
        (
            TransportMount(index=0, target="/workspace", writable=False),
            TransportMount(index=1, target="/artifacts", writable=True),
        ),
    )

    # Original argv is preserved verbatim as positionals after the sh $0.
    assert command[0] == "sh"
    assert command[1] == "-c"
    assert command[3] == "sh"
    assert command[4:] == (
        "torchrun",
        "/workspace/runner.py",
        "/workspace/payload.json",
    )

    script = command[2]
    # Both mounts are extracted IN; only the writable one is drained OUT.
    assert mount_in_env_var(0, 0) in script
    assert mount_in_env_var(1, 0) in script
    assert "base64 -d | tar -xzf - -C '/workspace'" in script
    assert "base64 -d | tar -xzf - -C '/artifacts'" in script
    assert "tar -czf - -C '/artifacts' . | base64" in script
    assert "tar -czf - -C '/workspace' . | base64" not in script
    assert 'exit $__platform_rc' in script


def test_broker_drain_parse_strip_and_extract_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "artifacts"
    source.mkdir()
    (source / "prism_run_manifest.v1.json").write_text(
        json.dumps({"schema_version": "prism_run_manifest.v1"}), encoding="utf-8"
    )

    stdout = (
        "PRISM_METRICS_JSON={\"q_arch\":0.0}\n" + _drain_section(1, source)
    )

    archives = parse_drained_archives(stdout)
    assert set(archives) == {1}

    restored = tmp_path / "restored"
    extract_archive_to_dir(archives[1], restored)
    assert (restored / "prism_run_manifest.v1.json").read_text(
        encoding="utf-8"
    ) == json.dumps({"schema_version": "prism_run_manifest.v1"})

    cleaned = strip_drain_sections(stdout)
    assert "PLATFORM_BROKER_MOUNT_OUT" not in cleaned
    assert "PRISM_METRICS_JSON=" in cleaned


def test_broker_encode_mount_in_env_chunks_large_archive(tmp_path: Path) -> None:
    import base64
    import os

    source = tmp_path / "ws"
    source.mkdir()
    # Incompressible payload so the base64 archive comfortably exceeds one chunk
    # and exercises the MAX_ARG_STRLEN-avoiding split.
    (source / "blob.bin").write_bytes(os.urandom(400 * 1024))

    env = encode_mount_in_env(0, source)

    assert len(env) > 1
    assert all(len(value) <= MAX_ENV_CHUNK_BYTES for value in env.values())
    assert set(env) == {mount_in_env_var(0, c) for c in range(len(env))}

    # Concatenating the chunks in order (as the bootstrap does) reconstitutes
    # the original archive.
    rejoined = "".join(env[mount_in_env_var(0, c)] for c in range(len(env)))
    restored = tmp_path / "restored"
    extract_archive_to_dir(base64.b64decode(rejoined), restored)
    assert (restored / "blob.bin").read_bytes() == (source / "blob.bin").read_bytes()


def test_broker_drain_parse_skips_garbled_section() -> None:
    stdout = (
        "@@PLATFORM_BROKER_MOUNT_OUT[1]:BEGIN@@\n"
        "not~valid~base64~\n"
        "@@PLATFORM_BROKER_MOUNT_OUT[1]:END@@\n"
    )
    assert parse_drained_archives(stdout) == {}


def test_broker_encode_dir_archive_drops_symlink(tmp_path: Path) -> None:
    source = tmp_path / "ws"
    source.mkdir()
    (source / "real.txt").write_text("ok", encoding="utf-8")
    (source / "evil").symlink_to("/etc/passwd")

    restored = tmp_path / "out"
    extract_archive_to_dir(_archive_bytes(encode_dir_archive(source)), restored)

    assert (restored / "real.txt").read_text(encoding="utf-8") == "ok"
    assert not (restored / "evil").exists()


def _archive_bytes(b64: str) -> bytes:
    import base64

    return base64.b64decode(b64)


def test_broker_encode_dir_archive_has_no_root_dot_member(tmp_path: Path) -> None:
    import base64
    import io
    import tarfile

    source = tmp_path / "ws"
    (source / "sub").mkdir(parents=True)
    (source / "payload.json").write_text("{}", encoding="utf-8")
    (source / "sub" / "f.txt").write_text("x", encoding="utf-8")

    raw = base64.b64decode(encode_dir_archive(source))
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        names = tar.getnames()
    # No root-dir member ('.' / './...'): tar would try to chmod/utime the
    # pre-existing root-owned 1777 mount root, which the non-root eval uid
    # cannot do (-> tar exit 2 under the bootstrap's `set -e`).
    assert "." not in names
    assert not any(name == "./" or name.startswith("./") for name in names)
    assert "payload.json" in names
    assert "sub/f.txt" in names

    empty = tmp_path / "empty"
    empty.mkdir()
    raw_empty = base64.b64decode(encode_dir_archive(empty))
    with tarfile.open(fileobj=io.BytesIO(raw_empty), mode="r:gz") as tar:
        assert tar.getnames() == []


def _non_root_account() -> tuple[int, int] | None:
    """A non-root ``(uid, gid)`` to drop to, or ``None`` if none exists."""

    for name in ("nobody", "daemon", "bin"):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        if entry.pw_uid != 0:
            return entry.pw_uid, entry.pw_gid
    return None


@pytest.mark.skipif(
    os.geteuid() != 0, reason="needs root to drop privileges to a non-root uid"
)
def test_broker_bootstrap_extracts_as_non_root_into_sticky_tmpfs(
    tmp_path: Path,
) -> None:
    account = _non_root_account()
    if account is None:
        pytest.skip("no non-root account available to drop to")
    uid, gid = account

    source = tmp_path / "workspace"
    (source / "project").mkdir(parents=True)
    (source / "payload.json").write_text('{"sentinel":"READ-OK"}', encoding="utf-8")
    (source / "project" / "runner.py").write_text("print('ok')\n", encoding="utf-8")

    # Root-owned, world-writable + sticky (mode 1777) mount root reachable by
    # the dropped uid: the cross-node materialization tmpfs shape. Built under
    # /tmp (world-traversable) so the non-root child can reach it.
    target_root = Path(tempfile.mkdtemp(dir="/tmp"))
    target = target_root / "mount"
    target.mkdir()
    os.chmod(target_root, 0o1777)
    os.chmod(target, 0o1777)
    try:
        env = dict(os.environ)
        in_env = encode_mount_in_env(0, source)
        env.update(in_env)
        transport = (
            TransportMount(
                index=0, target=str(target), writable=False, in_chunks=len(in_env)
            ),
        )
        command = build_bootstrap_command(
            ["cat", str(target / "payload.json")], transport
        )

        proc = subprocess.run(
            list(command),
            env=env,
            capture_output=True,
            text=True,
            user=uid,
            group=gid,
            extra_groups=[],
        )

        assert proc.returncode == 0, proc.stderr
        assert "READ-OK" in proc.stdout
        assert (target / "payload.json").read_text(
            encoding="utf-8"
        ) == '{"sentinel":"READ-OK"}'
        assert (target / "project" / "runner.py").exists()
    finally:
        shutil.rmtree(target_root, ignore_errors=True)


class _BrokerResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> _BrokerResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


def _broker_executor() -> DockerExecutor:
    return DockerExecutor(
        challenge="prism",
        backend="broker",
        broker_url="http://broker",
        broker_token="tok",
        allowed_images=("ghcr.io/platformnetwork/",),
    )


def _gpu_spec(workspace: Path, artifacts: Path) -> DockerRunSpec:
    return DockerRunSpec(
        image="ghcr.io/platformnetwork/prism-evaluator:latest",
        command=("torchrun", "/workspace/runner.py", "/workspace/payload.json"),
        mounts=(
            DockerMount(workspace, "/workspace"),
            DockerMount(artifacts, "/artifacts", read_only=False),
        ),
        workdir="/workspace",
        labels={"platform.job": "sub-1"},
        limits=DockerLimits(network="none", gpu_count=1),
    )


def test_broker_backend_restores_drained_writable_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "payload.json").write_text("{}", encoding="utf-8")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    # The container (on the remote node) produced a manifest; emulate the
    # broker handing it back drained through stdout.
    produced = tmp_path / "produced"
    produced.mkdir()
    (produced / "prism_run_manifest.v1.json").write_text(
        '{"schema_version":"prism_run_manifest.v1"}', encoding="utf-8"
    )
    stdout = "PRISM_METRICS_JSON={}\n" + _drain_section(1, produced)

    def fake_urlopen(request: object, timeout: int) -> _BrokerResponse:
        return _BrokerResponse(
            {
                "container_name": "prism-sub-1",
                "stdout": stdout,
                "stderr": "",
                "returncode": 0,
                "timed_out": False,
            }
        )

    monkeypatch.setattr(executor_module, "urlopen", fake_urlopen)

    result = _broker_executor().run(_gpu_spec(workspace, artifacts), timeout_seconds=30)

    # Artifact round-tripped into the caller's writable mount source.
    assert (artifacts / "prism_run_manifest.v1.json").read_text(
        encoding="utf-8"
    ) == '{"schema_version":"prism_run_manifest.v1"}'
    # The read-only workspace source is untouched.
    assert not (workspace / "prism_run_manifest.v1.json").exists()
    # Drain sections are stripped from the returned logs; real output kept.
    assert "PLATFORM_BROKER_MOUNT_OUT" not in result.stdout
    assert "PRISM_METRICS_JSON=" in result.stdout
    assert result.returncode == 0


def test_broker_backend_ignores_drain_targeting_readonly_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    produced = tmp_path / "produced"
    produced.mkdir()
    (produced / "stolen.txt").write_text("nope", encoding="utf-8")
    # Index 0 is the READ-ONLY workspace mount; a drain for it must be ignored.
    stdout = _drain_section(0, produced)

    monkeypatch.setattr(
        executor_module,
        "urlopen",
        lambda request, timeout: _BrokerResponse(
            {
                "container_name": "prism-sub-1",
                "stdout": stdout,
                "stderr": "",
                "returncode": 0,
                "timed_out": False,
            }
        ),
    )

    _broker_executor().run(_gpu_spec(workspace, artifacts), timeout_seconds=30)

    assert not (workspace / "stolen.txt").exists()
    assert not (artifacts / "stolen.txt").exists()

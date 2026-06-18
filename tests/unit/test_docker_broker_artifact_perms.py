from __future__ import annotations

import base64
import io
import stat
import tarfile
from pathlib import Path

from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
)
from platform_network.schemas.docker_broker import BrokerMount


def _archive_dir(path: Path) -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        tar.add(path, arcname=".")
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _service(tmp_path: Path) -> DockerBrokerService:
    return DockerBrokerService(
        DockerBrokerConfig(workspace_dir=tmp_path / "work")
    )


def test_writable_directory_mount_is_world_writable_with_sticky(
    tmp_path: Path,
) -> None:
    src = tmp_path / "artifacts"
    src.mkdir()
    (src / "seed.txt").write_text("ok", encoding="utf-8")
    service = _service(tmp_path)
    root = tmp_path / "root"
    root.mkdir()

    mount = BrokerMount(
        target="/artifacts",
        read_only=False,
        source_type="directory",
        archive_b64=_archive_dir(src),
    )

    result = service._materialize_mount(root, 0, mount)

    mode = stat.S_IMODE(result.source.stat().st_mode)
    assert mode == 0o1777, f"expected 0o1777, got {oct(mode)}"


def test_read_only_directory_mount_is_not_world_writable(
    tmp_path: Path,
) -> None:
    src = tmp_path / "inputs"
    src.mkdir()
    (src / "seed.txt").write_text("ok", encoding="utf-8")
    service = _service(tmp_path)
    root = tmp_path / "root"
    root.mkdir()

    mount = BrokerMount(
        target="/inputs",
        read_only=True,
        source_type="directory",
        archive_b64=_archive_dir(src),
    )

    result = service._materialize_mount(root, 0, mount)

    mode = stat.S_IMODE(result.source.stat().st_mode)
    assert mode != 0o1777, f"read-only mount must not be 1777, got {oct(mode)}"
    assert not (mode & stat.S_IWOTH), f"world-writable bit set: {oct(mode)}"

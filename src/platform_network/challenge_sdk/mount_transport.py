"""Cross-node mount transport for broker eval jobs.

A broker eval job may be scheduled on a different Swarm node than the broker
process: GPU jobs land on the GPU worker while the broker runs on the manager.
A host bind-mount source materialized on the broker node does not exist on the
worker, so the job's ``/workspace`` would be empty and writable ``/artifacts``
would never round-trip back to a manager-visible location.

This module moves mount content across nodes without any shared filesystem,
using only channels Swarm already distributes (env / argv) and collects
(``docker service logs``):

* IN  — each mount's content is handed to the container as a base64 gzip-tar
  value carried in environment variables and extracted into a node-local
  writable mount (tmpfs) by a POSIX-sh bootstrap that wraps the original
  command. The archive is split across numbered chunk vars so no single value
  exceeds the kernel's per-string ``MAX_ARG_STRLEN`` (128 KiB) ceiling; the
  bootstrap concatenates the chunks before decoding. The total still rides in
  the process environment, so this mechanism targets code-sized workspaces
  (well under ``ARG_MAX``), not multi-GiB checkpoint mounts.
* OUT — after the wrapped command exits, the bootstrap tars each *writable*
  mount and prints it to stdout between unique sentinels. The broker (for the
  manager-visible round-trip) and the challenge-side executor (to repopulate
  the caller's mount source) decode those sections to recover the artifacts.

The sentinels and env-var names are shared here so the producer (bootstrap),
the broker, and the executor agree byte-for-byte.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_ENV_PREFIX = "PLATFORM_BROKER_MOUNT_IN_"
#: Per-chunk cap, comfortably under the kernel's 128 KiB ``MAX_ARG_STRLEN``
#: single-string limit on argv/env entries.
MAX_ENV_CHUNK_BYTES = 96 * 1024
_OUT_BEGIN = "@@PLATFORM_BROKER_MOUNT_OUT[{index}]:BEGIN@@"
_OUT_END = "@@PLATFORM_BROKER_MOUNT_OUT[{index}]:END@@"
_OUT_RE = re.compile(
    r"@@PLATFORM_BROKER_MOUNT_OUT\[(\d+)\]:BEGIN@@(.*?)"
    r"@@PLATFORM_BROKER_MOUNT_OUT\[\1\]:END@@",
    re.DOTALL,
)

#: Tar member kinds the bootstrap must never extract on the remote node (a
#: symlink could resolve to an attacker-chosen path such as ``/run/secrets``).
_NON_REGULAR_CHECKS = ("issym", "islnk", "isdev", "ischr", "isblk", "isfifo")


@dataclass(frozen=True)
class TransportMount:
    """One mount to ship to (and, when writable, drain from) the container."""

    index: int
    target: str
    writable: bool
    in_chunks: int = 1


def mount_in_env_var(index: int, chunk: int = 0) -> str:
    """Name of the env var carrying chunk ``chunk`` of mount ``index``."""

    return f"{_ENV_PREFIX}{index}_{chunk}"


def encode_mount_in_env(index: int, source: Path) -> dict[str, str]:
    """Env mapping carrying mount ``index``'s inbound archive, split into
    ``MAX_ENV_CHUNK_BYTES`` chunks so no single value trips ``MAX_ARG_STRLEN``.

    Always yields at least one (possibly empty) chunk so an empty source mount
    still produces a var the bootstrap can concatenate.
    """

    blob = encode_dir_archive(source)
    chunks = [
        blob[start : start + MAX_ENV_CHUNK_BYTES]
        for start in range(0, len(blob), MAX_ENV_CHUNK_BYTES)
    ] or [""]
    return {mount_in_env_var(index, chunk): part for chunk, part in enumerate(chunks)}


def encode_dir_archive(source: Path) -> str:
    """Base64 gzip-tar of ``source``'s contents (non-regular members dropped).

    Each top-level child is archived under its own name rather than adding
    ``source`` itself as a ``.`` member. The remote mount root is a root-owned
    ``tmpfs-mode=1777`` dir; a ``.`` member makes the extracting non-root eval
    uid try to chmod/utime that root-owned root, which fails and (under the
    bootstrap's ``set -e``) aborts before the wrapped command runs. Nested dirs
    are instead created by tar owned by the extracting uid, so their metadata is
    settable; an empty source yields a members-less (but valid) archive that
    extracts as a no-op.
    """

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for child in sorted(source.iterdir()):
            tar.add(child, arcname=child.name, filter=_drop_non_regular)
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _drop_non_regular(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if any(getattr(info, check)() for check in _NON_REGULAR_CHECKS):
        return None
    return info


def _shq(value: str) -> str:
    """POSIX single-quote a value for safe embedding in an ``sh -c`` script."""

    return "'" + value.replace("'", "'\\''") + "'"


def build_bootstrap_command(
    original_command: Sequence[str], mounts: Sequence[TransportMount]
) -> tuple[str, ...]:
    """Wrap ``original_command`` so it self-extracts inbound mounts and drains
    writable mounts to stdout.

    The original argv is passed verbatim as positional parameters after the
    ``sh`` ``$0`` placeholder and invoked via ``"$@"`` so no re-quoting of the
    real command is required. The wrapper preserves the command's exit code.
    """

    lines = ["set -e"]
    for mount in mounts:
        target = _shq(mount.target)
        concat = "; ".join(
            f'printf %s "${{{mount_in_env_var(mount.index, chunk)}}}"'
            for chunk in range(max(mount.in_chunks, 1))
        )
        lines.append(f"mkdir -p {target}")
        lines.append(f"{{ {concat}; }} | base64 -d | tar -xzf - -C {target}")
    lines.append("set +e")
    lines.append('"$@"')
    lines.append("__platform_rc=$?")
    for mount in mounts:
        if not mount.writable:
            continue
        target = _shq(mount.target)
        begin = _shq(_OUT_BEGIN.format(index=mount.index))
        end = _shq(_OUT_END.format(index=mount.index))
        lines.append(f"printf '%s\\n' {begin}")
        lines.append(f"tar -czf - -C {target} . | base64")
        lines.append(f"printf '%s\\n' {end}")
    lines.append("exit $__platform_rc")
    script = "\n".join(lines)
    return ("sh", "-c", script, "sh", *original_command)


def parse_drained_archives(stdout: str) -> dict[int, bytes]:
    """Decode the writable-mount archives emitted to ``stdout`` by the bootstrap.

    Returns ``{mount_index: gzip_tar_bytes}``. Sections whose base64 fails to
    decode are skipped rather than raising, so a truncated/garbled log can
    never crash the broker's post-run handling.
    """

    archives: dict[int, bytes] = {}
    for match in _OUT_RE.finditer(stdout):
        index = int(match.group(1))
        blob = "".join(match.group(2).split())
        if not blob:
            archives[index] = b""
            continue
        try:
            archives[index] = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
    return archives


def strip_drain_sections(stdout: str) -> str:
    """Remove the sentinel-delimited drain sections from ``stdout``."""

    return _OUT_RE.sub("", stdout)


def extract_drain_sections(stdout: str) -> str:
    """Return the sentinel-delimited drain sections from ``stdout`` verbatim.

    Complement of :func:`strip_drain_sections`. These sections carry the
    writable-mount archives the executor restores, so a caller capping the
    human-readable log can re-append them uncapped (a drained checkpoint can far
    exceed any log cap, and truncating its base64 would break restoration).
    """

    return "".join(match.group(0) for match in _OUT_RE.finditer(stdout))


def extract_archive_to_dir(archive: bytes, dest: Path) -> None:
    """Safely extract a gzip-tar archive into ``dest`` (regular members only)."""

    dest.mkdir(parents=True, exist_ok=True)
    if not archive:
        return
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        tar.extractall(dest, filter="data")

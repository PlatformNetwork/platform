from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest

from platform_network.kubernetes.client import KubernetesClient
from platform_network.kubernetes.names import (
    POSTGRES_SECRET_KEY_DATABASE_URL,
    challenge_name,
    challenge_postgres_names,
)
from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.master.kubernetes_orchestrator import KubernetesOrchestrator

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = str(os.getpid())
CLUSTER = f"platform-managed-postgres-{RUN_ID}"
NAMESPACE = f"platform-managed-postgres-{RUN_ID}"
SLUG = "agent-challenge"
VALUE = "metis-widget-001"
IMAGE = f"platform-managed-postgres-runtime:{RUN_ID}"
RUN_ENV_VAR = "PLATFORM_RUN_KIND_MANAGED_POSTGRES_TEST"
KUBECONFIG: str | None = None


def _run(
    cmd: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 120,
    redact: str | None = None,
) -> str:
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        stdout = result.stdout
        stderr = result.stderr
        if redact:
            stdout = stdout.replace(redact, "<redacted>")
            stderr = stderr.replace(redact, "<redacted>")
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return result.stdout


def _tool(name: str) -> None:
    if shutil.which(name) is None:
        pytest.skip(f"{name} is not installed")


def _docker(*args: str, timeout: int = 120) -> str:
    return _run(["docker", *args], timeout=timeout)


def _kind(*args: str, timeout: int = 120) -> str:
    return _run(["kind", *args], timeout=timeout)


def _kubectl(*args: str, timeout: int = 120) -> str:
    base = ["kubectl"]
    if KUBECONFIG is None:
        base.extend(["--context", f"kind-{CLUSTER}"])
    else:
        base.extend(["--kubeconfig", KUBECONFIG])
    return _run([*base, *args], timeout=timeout)


def _create_cluster() -> None:
    _kind("delete", "cluster", "--name", CLUSTER, timeout=120)
    _kind("create", "cluster", "--name", CLUSTER, timeout=240)


def _write_kubeconfig(path: Path) -> None:
    kubeconfig = _kind("get", "kubeconfig", "--name", CLUSTER, timeout=60)
    path.write_text(kubeconfig, encoding="utf-8")
    path.chmod(0o600)


def _build_runtime_image(tmp: Path) -> None:
    (tmp / "Dockerfile").write_text(
        dedent(
            """
            FROM python:3.12-slim
            RUN pip install --no-cache-dir fastapi uvicorn \
                'sqlalchemy[asyncio]>=2.0' asyncpg
            RUN useradd --create-home --uid 1000 appuser
            WORKDIR /app
            COPY app.py /app/app.py
            USER 1000
            CMD ["python", "/app/app.py"]
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp / "app.py").write_text(_runtime_app(), encoding="utf-8")
    _docker("build", "-t", IMAGE, str(tmp), timeout=300)


def _runtime_app() -> str:
    return "\n".join(
        [
            "import os",
            "from contextlib import asynccontextmanager",
            "from pathlib import Path",
            "",
            "import uvicorn",
            "from fastapi import FastAPI",
            "from sqlalchemy import text",
            "from sqlalchemy.ext.asyncio import create_async_engine",
            "",
            'TABLE = "platform_kind_managed_postgres_items"',
            "",
            "",
            "@asynccontextmanager",
            "async def lifespan(app):",
            '    engine = create_async_engine(os.environ["CHALLENGE_DATABASE_URL"])',
            "    try:",
            "        async with engine.begin() as connection:",
            "            sql = (",
            '                f"CREATE TABLE IF NOT EXISTS {TABLE} "',
            '                "(id text PRIMARY KEY)"',
            "            )",
            "            await connection.execute(text(sql))",
            '        marker = Path("/data/runtime-data-marker")',
            '        marker.write_text("runtime-data\\n", encoding="utf-8")',
            "        yield",
            "    finally:",
            "        await engine.dispose()",
            "",
            "",
            "app = FastAPI(lifespan=lifespan)",
            "",
            "",
            '@app.get("/health")',
            "async def health():",
            '    return {"status": "ok"}',
            "",
            "",
            '@app.get("/version")',
            "async def version():",
            "    return {",
            '        "api_version": "1.0",',
            '        "capabilities": ["get_weights", "proxy_routes"],',
            "    }",
            "",
            "",
            'if __name__ == "__main__":',
            '    uvicorn.run(app, host="0.0.0.0", port=8000)',
            "",
        ]
    )


class KindPostgresClient(KubernetesClient):
    def __init__(self, *, namespace: str, kubeconfig: str) -> None:
        super().__init__(namespace=namespace, kubeconfig=kubeconfig, in_cluster=False)

    def check_postgres_ready(
        self, *, slug: str, service_name: str, database_url: str
    ) -> None:
        del service_name, database_url
        self.run_database_check(slug=slug, action="ready")

    def run_database_check(self, *, slug: str, action: str) -> None:
        job_name = f"postgres-check-{action}-{int(time.time() * 1000)}"
        job = _database_job(slug=slug, job_name=job_name, action=action)
        self.apply(job)
        status = self.wait_job_complete(job_name, timeout_seconds=180)
        logs = self.pod_logs_for_job(job_name, tail_lines=200)
        self.delete("Job", job_name)
        if status != 0:
            raise AssertionError(
                f"database check job {job_name} failed with status {status}:\n{logs}"
            )
        assert "db-check-ok" in logs


def _database_job(*, slug: str, job_name: str, action: str) -> dict[str, Any]:
    names = challenge_postgres_names(slug)
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": NAMESPACE,
            "labels": {"platform.component": "managed-postgres-test"},
        },
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 180,
            "template": {
                "metadata": {"labels": {"platform.component": "managed-postgres-test"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "name": "check",
                            "image": IMAGE,
                            "command": ["python", "-c", _database_check_script()],
                            "env": [
                                {
                                    "name": POSTGRES_SECRET_KEY_DATABASE_URL,
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": names.secret_name,
                                            "key": POSTGRES_SECRET_KEY_DATABASE_URL,
                                        }
                                    },
                                },
                                {"name": "CHECK_ACTION", "value": action},
                                {"name": "CHECK_VALUE", "value": VALUE},
                            ],
                        }
                    ],
                },
            },
        },
    }


def _database_check_script() -> str:
    return dedent(
        """
        import asyncio
        import os

        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        TABLE = "platform_kind_managed_postgres_items"


        async def main():
            engine = create_async_engine(os.environ["CHALLENGE_DATABASE_URL"])
            try:
                async with engine.begin() as connection:
                    await connection.execute(text("SELECT 1"))
                    await connection.execute(
                        text(
                            f"CREATE TABLE IF NOT EXISTS {TABLE} "
                            "(id text PRIMARY KEY)"
                        )
                    )
                    if os.environ["CHECK_ACTION"] == "insert":
                        await connection.execute(
                            text(
                                f"INSERT INTO {TABLE} (id) VALUES (:value) "
                                "ON CONFLICT (id) DO NOTHING"
                            ),
                            {"value": os.environ["CHECK_VALUE"]},
                        )
                    count = await connection.scalar(
                        text(f"SELECT count(*) FROM {TABLE} WHERE id = :value"),
                        {"value": os.environ["CHECK_VALUE"]},
                    )
                if os.environ["CHECK_ACTION"] in {"insert", "read"} and count != 1:
                    raise SystemExit(f"expected one persisted row, found {count}")
                print("db-check-ok")
            finally:
                await engine.dispose()


        asyncio.run(main())
        """
    ).strip()


def _challenge_pod_name() -> str:
    pods = json.loads(
        _kubectl(
            "-n",
            NAMESPACE,
            "get",
            "pods",
            "-l",
            f"app.kubernetes.io/instance={challenge_name(SLUG)}",
            "-o",
            "json",
        )
    ).get("items", [])
    assert pods, "challenge pod was not observed"
    return str(pods[0]["metadata"]["name"])


def _assert_data_volume_is_separate() -> None:
    names = challenge_postgres_names(SLUG)
    pod_name = _challenge_pod_name()
    _kubectl(
        "-n",
        NAMESPACE,
        "exec",
        pod_name,
        "--",
        "test",
        "-f",
        "/data/runtime-data-marker",
    )
    _kubectl(
        "-n", NAMESPACE, "exec", pod_name, "--", "test", "!", "-e", "/data/PG_VERSION"
    )
    pvcs = json.loads(_kubectl("-n", NAMESPACE, "get", "pvc", "-o", "json")).get(
        "items", []
    )
    pvc_names = {item["metadata"]["name"] for item in pvcs}
    challenge_pvc = f"challenge-data-{challenge_name(SLUG)}-0"
    postgres_pvc = f"{names.data_claim_name}-{names.statefulset_name}-0"
    assert challenge_pvc in pvc_names
    assert postgres_pvc in pvc_names
    assert challenge_pvc != postgres_pvc


def _cluster_debug() -> str:
    parts: list[str] = []
    commands = [
        ("pods", ["-n", NAMESPACE, "get", "pods", "-o", "wide"]),
        ("statefulsets", ["-n", NAMESPACE, "get", "statefulsets", "-o", "wide"]),
        ("events", ["-n", NAMESPACE, "get", "events", "--sort-by=.lastTimestamp"]),
    ]
    for label, command in commands:
        try:
            parts.append(f"## {label}\n{_kubectl(*command, timeout=60)}")
        except Exception as exc:
            parts.append(f"## {label}\nfailed to collect: {exc}")
    names = challenge_postgres_names(SLUG)
    try:
        parts.append(
            "## postgres statefulset\n"
            + _kubectl(
                "-n",
                NAMESPACE,
                "describe",
                f"statefulset/{names.statefulset_name}",
                timeout=60,
            )
        )
    except Exception as exc:
        parts.append(f"## postgres statefulset\nfailed to collect: {exc}")
    try:
        parts.append(
            "## postgres logs\n"
            + _kubectl(
                "-n",
                NAMESPACE,
                "logs",
                f"statefulset/{names.statefulset_name}",
                "--tail=120",
                timeout=60,
            )
        )
    except Exception as exc:
        parts.append(f"## postgres logs\nfailed to collect: {exc}")
    try:
        parts.append(
            "## challenge statefulset\n"
            + _kubectl(
                "-n",
                NAMESPACE,
                "describe",
                f"statefulset/{challenge_name(SLUG)}",
                timeout=60,
            )
        )
    except Exception as exc:
        parts.append(f"## challenge statefulset\nfailed to collect: {exc}")
    try:
        parts.append(
            "## challenge logs\n"
            + _kubectl(
                "-n",
                NAMESPACE,
                "logs",
                f"statefulset/{challenge_name(SLUG)}",
                "--tail=120",
                "--previous",
                timeout=60,
            )
        )
    except Exception as exc:
        parts.append(f"## challenge logs\nfailed to collect: {exc}")
    return "\n\n".join(parts)


def _start_challenge_with_debug(
    orchestrator: KubernetesOrchestrator, spec: ChallengeSpec
) -> None:
    try:
        orchestrator.start_challenge(spec)
    except Exception as exc:
        raise AssertionError(f"{exc}\n{_cluster_debug()}") from exc


def test_kind_managed_postgres_persists_across_runtime_recreate() -> None:
    global KUBECONFIG

    if os.environ.get(RUN_ENV_VAR) != "1":
        pytest.skip(f"set {RUN_ENV_VAR}=1 to run kind managed Postgres test")
    for tool in ["docker", "kind", "kubectl"]:
        _tool(tool)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        kubeconfig = tmp / "kubeconfig"
        _build_runtime_image(tmp)
        _create_cluster()
        try:
            _write_kubeconfig(kubeconfig)
            KUBECONFIG = str(kubeconfig)
            _kind("load", "docker-image", IMAGE, "--name", CLUSTER, timeout=180)
            _kubectl("create", "namespace", NAMESPACE, timeout=60)
            client = KindPostgresClient(namespace=NAMESPACE, kubeconfig=str(kubeconfig))
            orchestrator = KubernetesOrchestrator(
                client=client,
                namespace=NAMESPACE,
                mode="statefulset",
                storage_size="128Mi",
                pull_ghcr_only=False,
                health_check_mode="service_proxy",
                request_timeout_seconds=5,
                health_retries=45,
                health_retry_delay_seconds=2,
                autoscaling_enabled=False,
                managed_postgres_image="postgres:16-alpine",
                managed_postgres_storage_size="1Gi",
            )
            spec = ChallengeSpec(
                slug=SLUG,
                image=IMAGE,
                resources=ChallengeResources(cpu=0.25, memory="256Mi"),
            )

            _start_challenge_with_debug(orchestrator, spec)
            client.run_database_check(slug=SLUG, action="insert")
            _assert_data_volume_is_separate()

            names = challenge_postgres_names(SLUG)
            orchestrator.stop_challenge(SLUG, remove=True)
            _kubectl(
                "-n",
                NAMESPACE,
                "wait",
                "--for=delete",
                f"statefulset/{challenge_name(SLUG)}",
                "--timeout=120s",
                timeout=150,
            )
            _kubectl(
                "-n",
                NAMESPACE,
                "wait",
                "--for=delete",
                f"statefulset/{names.statefulset_name}",
                "--timeout=120s",
                timeout=150,
            )

            _start_challenge_with_debug(orchestrator, spec)
            client.run_database_check(slug=SLUG, action="read")
            _assert_data_volume_is_separate()
        finally:
            try:
                _kubectl(
                    "delete",
                    "namespace",
                    NAMESPACE,
                    "--ignore-not-found=true",
                    timeout=60,
                )
            finally:
                _kind("delete", "cluster", "--name", CLUSTER, timeout=120)
                KUBECONFIG = None
                subprocess.run(
                    ["docker", "image", "rm", "-f", IMAGE],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

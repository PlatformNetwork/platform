"""Prove /health cannot be starved by threadpool-exhausting sync broker ops."""

from __future__ import annotations

import inspect
import threading
import time

import anyio.to_thread
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from platform_network.master.docker_broker import create_docker_broker_app
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerListRequest,
    BrokerListResponse,
    BrokerRunRequest,
    BrokerRunResponse,
)

THREADPOOL_TOKENS = 4
HEALTH_BUDGET_SECONDS = 1.0


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


class BlockingService:
    """BrokerService whose run() blocks until released, holding its thread."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.active = 0

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        with self._lock:
            self.active += 1
        assert self.release.wait(timeout=30), "test never released blocked runs"
        return BrokerRunResponse(
            container_name=f"{challenge_slug}-{request.job_id}",
            stdout="ok",
            stderr="",
            returncode=0,
            timed_out=False,
        )

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        return BrokerCleanupResponse()

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        return BrokerListResponse(containers=[])


def _shrink_threadpool() -> None:
    anyio.to_thread.current_default_thread_limiter().total_tokens = THREADPOOL_TOKENS


def _post_run(client: TestClient, results: list[int]) -> None:
    response = client.post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-slow",
            "image": "ghcr.io/platformnetwork/agent:latest",
            "command": ["sleep", "infinity"],
            "timeout_seconds": 60,
        },
    )
    results.append(response.status_code)


def test_health_handler_is_native_async() -> None:
    app = create_docker_broker_app(registry=Registry(), service=BlockingService())
    health_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == "/health"
    ]
    assert len(health_routes) == 1
    assert inspect.iscoroutinefunction(health_routes[0].endpoint)


def test_health_responds_while_threadpool_is_saturated() -> None:
    service = BlockingService()
    app = create_docker_broker_app(registry=Registry(), service=service)
    with TestClient(app) as client:
        assert client.portal is not None
        client.portal.call(_shrink_threadpool)

        results: list[int] = []
        workers = [
            threading.Thread(target=_post_run, args=(client, results))
            for _ in range(THREADPOOL_TOKENS)
        ]
        for worker in workers:
            worker.start()
        try:
            deadline = time.monotonic() + 10
            while service.active < THREADPOOL_TOKENS:
                if time.monotonic() > deadline:
                    pytest.fail(
                        f"threadpool never saturated: {service.active}"
                        f"/{THREADPOOL_TOKENS} runs in flight"
                    )
                time.sleep(0.01)

            started = time.monotonic()
            response = client.get("/health")
            elapsed = time.monotonic() - started
        finally:
            service.release.set()
            for worker in workers:
                worker.join(timeout=30)

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert elapsed < HEALTH_BUDGET_SECONDS, (
            f"/health took {elapsed:.3f}s while {THREADPOOL_TOKENS} slow sync "
            "ops held every threadpool token"
        )
        assert results == [200] * THREADPOOL_TOKENS

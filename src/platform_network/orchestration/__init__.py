"""Backend-selection seam for challenge orchestration (kubernetes | docker).

This package owns the single dispatch point that maps the configured
``runtime.backend`` to a concrete orchestration implementation. The
Kubernetes implementation wraps the pre-existing call flow unchanged;
the Docker implementation is a thin shell that Wave 2 (Task 9) replaces
with the Swarm-backed orchestrator.
"""

from platform_network.orchestration.factory import (
    DockerOrchestrationBackend,
    KubernetesOrchestrationBackend,
    OrchestrationBackend,
    create_backend,
)

__all__ = [
    "DockerOrchestrationBackend",
    "KubernetesOrchestrationBackend",
    "OrchestrationBackend",
    "create_backend",
]

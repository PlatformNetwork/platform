from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

KubernetesTargetMode = Literal["direct", "agent"]


class KubernetesTargetCreate(BaseModel):
    id: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    mode: KubernetesTargetMode = "direct"
    api_url: str | None = None
    agent_url: str | None = None
    namespace: str = Field(default="platform", min_length=1)
    service_account: str | None = "platform-master"
    kubeconfig: str | None = None
    kubeconfig_file: str | None = None
    agent_token: str | None = None
    agent_token_file: str | None = None
    enabled: bool = True
    draining: bool = False
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    description: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    gpu_count: int = Field(default=0, ge=0)
    storage_class: str | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    tolerations: list[dict[str, object]] = Field(default_factory=list)
    runtime_class_name: str | None = None

    @model_validator(mode="after")
    def validate_connection_material(self) -> KubernetesTargetCreate:
        if self.mode == "direct" and not (self.kubeconfig or self.kubeconfig_file):
            raise ValueError("direct Kubernetes targets require kubeconfig material")
        if self.mode == "agent" and not self.agent_url:
            raise ValueError("agent Kubernetes targets require agent_url")
        return self


class KubernetesTargetUpdate(BaseModel):
    mode: KubernetesTargetMode | None = None
    api_url: str | None = None
    agent_url: str | None = None
    namespace: str | None = Field(default=None, min_length=1)
    service_account: str | None = None
    kubeconfig: str | None = None
    kubeconfig_file: str | None = None
    agent_token: str | None = None
    agent_token_file: str | None = None
    enabled: bool | None = None
    draining: bool | None = None
    verify_tls: bool | None = None
    timeout_seconds: float | None = None
    description: str | None = None
    labels: dict[str, str] | None = None
    gpu_count: int | None = Field(default=None, ge=0)
    storage_class: str | None = None
    node_selector: dict[str, str] | None = None
    tolerations: list[dict[str, object]] | None = None
    runtime_class_name: str | None = None


class KubernetesTargetRecord(BaseModel):
    id: str
    mode: KubernetesTargetMode = "direct"
    api_url: str | None = None
    agent_url: str | None = None
    namespace: str = "platform"
    service_account: str | None = "platform-master"
    kubeconfig_file: str | None = None
    agent_token_hint: str | None = None
    enabled: bool = True
    draining: bool = False
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    description: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    gpu_count: int = 0
    storage_class: str | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    tolerations: list[dict[str, object]] = Field(default_factory=list)
    runtime_class_name: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class KubernetesTargetView(BaseModel):
    id: str
    mode: KubernetesTargetMode
    api_url: str | None = None
    agent_url: str | None = None
    namespace: str
    service_account: str | None = None
    kubeconfig_file: str | None = None
    agent_token_hint: str | None = None
    enabled: bool
    draining: bool
    verify_tls: bool
    timeout_seconds: float
    description: str | None = None
    labels: dict[str, str]
    gpu_count: int
    storage_class: str | None = None
    node_selector: dict[str, str]
    tolerations: list[dict[str, object]]
    runtime_class_name: str | None = None
    created_at: datetime
    updated_at: datetime


class KubernetesTargetHealth(BaseModel):
    id: str
    status: str
    detail: str | None = None

"""Phase 2 runtime interfaces and immutable ADR 0006 security contracts."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from .controller import DeploymentPlan


@dataclass(frozen=True)
class HealthContract:
    liveness_path: str = "/livez"
    liveness_process_only: bool = True
    readiness_path: str = "/readyz"
    readiness_requires_runtime_configuration: bool = True
    readiness_requires_database_connectivity: bool = True
    readiness_requires_migration_state: bool = True


@dataclass(frozen=True)
class ContainerSecurityContract:
    non_root_uid_gid: bool = True
    read_only_root_filesystem: bool = True
    dropped_capabilities: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    writable_tmpfs_only: bool = True
    docker_socket_mounted: bool = False
    runtime_secrets_outside_image: bool = True
    application_host_published: bool = False
    database_host_published: bool = False


HEALTH_CONTRACT = HealthContract()
CONTAINER_SECURITY_CONTRACT = ContainerSecurityContract()
NETWORK_PATH = (
    "ingress", "nginx", "frontend_network", "application", "backend_network", "postgresql",
)


class MigrationLock(Protocol):
    """Acquire the eventual per-environment serialization boundary."""

    def acquire(self, stage: str) -> AbstractContextManager[None]:
        ...


class MigrationExecutor(Protocol):
    """Execute one verified migration explicitly before candidate readiness."""

    def execute(
        self, *, stage: str, exact_image_reference: str, identity: str, checksum: str,
    ) -> None:
        ...


class RuntimeAdapter(Protocol):
    """Phase 2 implementation boundary; Phase 1 provides no implementation."""

    def start_candidate(self, plan: DeploymentPlan) -> None:
        ...

    def check_liveness(self, stage: str, slot: str) -> bool:
        ...

    def check_readiness(self, stage: str, slot: str) -> bool:
        ...

    def validate_application(self, stage: str, slot: str) -> bool:
        ...

    def validate_nginx(self, stage: str) -> bool:
        ...

    def switch_traffic(self, stage: str, slot: str) -> None:
        ...

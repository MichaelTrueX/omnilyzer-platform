"""deployment/installation_contract.py — inert DEV host installation contract.

Purpose: declaratively link the C11 ``DevExecutorComposition`` and C12
``GitHubDevBrokerComposition`` identity inputs with the reviewed DEV state,
replay, audit, and executor-socket resource contracts. C13 is declarative only:
import and construction perform no host I/O, provision no resources, and do not
activate deployment authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .audit import AUDIT_PATH
from .replay_sqlite import (
    DATABASE_MODE,
    DIRECTORY_MODE as REPLAY_DIRECTORY_MODE,
    MAX_UID_GID,
    PRODUCTION_REPLAY_DATABASE,
)
from .state_store import (
    PRODUCTION_DEV_STATE_PATH,
    STATE_DIRECTORY_MODE,
    STATE_FILE_MODE,
)
from .unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


__all__ = ("DevHostInstallationContract", "HostResourceRequirement")

_AUDIT_DIRECTORY_MODE = 0o700
_AUDIT_FILE_MODE = 0o600
_EXECUTOR_SOCKET_MODE = 0o660
_RESOURCE_KINDS = frozenset({
    "directory", "regular_file", "sqlite_database", "unix_socket",
})
_LIFECYCLES = frozenset({
    "must-exist-before-activation",
    "must-contain-canonical-no-active-state-before-activation",
    "must-exist-before-replay-initialization",
    "future-reviewed-replay-initialization-only",
    "may-be-created-on-first-audit-append",
    "future-reviewed-runtime-service-creation-only",
})
_IDENTITY_ERROR = "DEV host installation identity is invalid"
_RESOURCE_ERROR = "DEV host resource requirement is invalid"


def _identity(value: object, *, positive: bool) -> int:
    """Return one strict bounded numeric host identity or fail closed."""

    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= MAX_UID_GID:
        raise TypeError(_IDENTITY_ERROR)
    return value


def _supplementary_groups(primary_gid: int, *required: int) -> tuple[int, ...]:
    """Return required non-primary group IDs once, in declared order."""

    return tuple(dict.fromkeys(gid for gid in required if gid != primary_gid))


@dataclass(frozen=True, slots=True)
class HostResourceRequirement:
    """Describe one fixed host resource without inspecting or creating it."""

    path: str
    kind: str
    mode: int
    owner_uid: int
    group_gid: int
    lifecycle: str

    def __post_init__(self) -> None:
        """Validate one immutable resource description using pure values only."""

        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or self.path.startswith("//")
            or "\x00" in self.path
            or str(PurePosixPath(self.path)) != self.path
            or type(self.kind) is not str
            or self.kind not in _RESOURCE_KINDS
            or type(self.mode) is not int
            or not 0 <= self.mode <= 0o7777
            or type(self.owner_uid) is not int
            or not 0 <= self.owner_uid <= MAX_UID_GID
            or type(self.group_gid) is not int
            or not 0 <= self.group_gid <= MAX_UID_GID
            or type(self.lifecycle) is not str
            or self.lifecycle not in _LIFECYCLES
        ):
            raise TypeError(_RESOURCE_ERROR)


@dataclass(frozen=True, slots=True, kw_only=True)
class DevHostInstallationContract:
    """Specify coherent C11/C12 DEV host identities and fixed resources."""

    broker_uid: int
    broker_gid: int
    executor_uid: int
    executor_gid: int
    replay_group_gid: int
    socket_group_gid: int
    broker_required_group_gids: tuple[int, ...] = field(init=False)
    executor_required_group_gids: tuple[int, ...] = field(init=False)
    _resources: tuple[HostResourceRequirement, ...] = field(
        init=False, repr=False,
    )

    def __post_init__(self) -> None:
        """Validate identities and derive immutable relationships without I/O."""

        broker_uid = _identity(self.broker_uid, positive=True)
        broker_gid = _identity(self.broker_gid, positive=True)
        executor_uid = _identity(self.executor_uid, positive=False)
        executor_gid = _identity(self.executor_gid, positive=False)
        replay_gid = _identity(self.replay_group_gid, positive=True)
        socket_gid = _identity(self.socket_group_gid, positive=True)
        if broker_uid == executor_uid or socket_gid == executor_gid:
            raise ValueError(_IDENTITY_ERROR)

        object.__setattr__(
            self,
            "broker_required_group_gids",
            _supplementary_groups(broker_gid, replay_gid, socket_gid),
        )
        object.__setattr__(
            self,
            "executor_required_group_gids",
            _supplementary_groups(executor_gid, replay_gid),
        )
        object.__setattr__(self, "_resources", (
            HostResourceRequirement(
                str(PurePosixPath(PRODUCTION_DEV_STATE_PATH).parent),
                "directory", STATE_DIRECTORY_MODE, executor_uid, executor_gid,
                "must-exist-before-activation",
            ),
            HostResourceRequirement(
                PRODUCTION_DEV_STATE_PATH, "regular_file", STATE_FILE_MODE,
                executor_uid, executor_gid,
                "must-contain-canonical-no-active-state-before-activation",
            ),
            HostResourceRequirement(
                str(PRODUCTION_REPLAY_DATABASE.parent), "directory",
                REPLAY_DIRECTORY_MODE, 0, replay_gid,
                "must-exist-before-replay-initialization",
            ),
            HostResourceRequirement(
                str(PRODUCTION_REPLAY_DATABASE), "sqlite_database", DATABASE_MODE,
                0, replay_gid, "future-reviewed-replay-initialization-only",
            ),
            HostResourceRequirement(
                str(AUDIT_PATH.parent), "directory", _AUDIT_DIRECTORY_MODE,
                executor_uid, executor_gid, "must-exist-before-activation",
            ),
            HostResourceRequirement(
                str(AUDIT_PATH), "regular_file", _AUDIT_FILE_MODE,
                executor_uid, executor_gid,
                "may-be-created-on-first-audit-append",
            ),
            HostResourceRequirement(
                PRODUCTION_EXECUTOR_SOCKET_PATH, "unix_socket",
                _EXECUTOR_SOCKET_MODE, executor_uid, socket_gid,
                "future-reviewed-runtime-service-creation-only",
            ),
        ))

    def broker_composition_kwargs(self) -> dict[str, int]:
        """Return fresh identity arguments for GitHubDevBrokerComposition."""

        return {
            "expected_replay_directory_uid": 0,
            "expected_replay_directory_gid": self.replay_group_gid,
            "expected_broker_uid": self.broker_uid,
            "expected_executor_uid": self.executor_uid,
            "expected_executor_gid": self.executor_gid,
            "expected_socket_group_gid": self.socket_group_gid,
        }

    def executor_composition_identity_kwargs(self) -> dict[str, int]:
        """Return fresh host-identity arguments for DevExecutorComposition."""

        return {
            "expected_state_owner_uid": self.executor_uid,
            "expected_state_group_gid": self.executor_gid,
            "expected_replay_directory_uid": 0,
            "expected_replay_directory_gid": self.replay_group_gid,
            "expected_broker_uid": self.broker_uid,
            "expected_broker_gid": self.broker_gid,
            "expected_socket_owner_uid": self.executor_uid,
            "expected_socket_group_gid": self.socket_group_gid,
        }

    def resource_requirements(self) -> tuple[HostResourceRequirement, ...]:
        """Return the immutable fixed DEV resource requirements in path order."""

        return self._resources

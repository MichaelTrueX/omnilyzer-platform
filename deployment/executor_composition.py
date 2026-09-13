"""deployment/executor_composition.py — inert Task 014 DEV executor composition.

This file composes ``deployment.state_store``, ``deployment.replay_sqlite``,
``deployment.audit``, ``deployment.docker_runtime``,
``deployment.deployment_operation``, ``deployment.executor``,
``deployment.executor_server``, and ``deployment.executor_listener`` into one
closed executor boundary. It internally binds the reviewed Docker Compose
candidate client and runtime adapter to one command runner and exact image.
Import and construction are inert: they do not create, bind, or listen on
sockets; install or initialize infrastructure; probe a candidate; or execute
deployment infrastructure. Only an explicit ``serve_once()`` call delegates
to the already-reviewed listener boundary.
"""

from __future__ import annotations

from .audit import FilesystemAuditSink as _FilesystemAuditSink
from .deployment_operation import DevDeploymentOperation as _DevDeploymentOperation
from .docker_runtime import (
    DockerComposeCandidateHttpClient as _DockerComposeCandidateHttpClient,
    DockerRuntimeAdapter as _DockerRuntimeAdapter,
    SubprocessCommandRunner as _SubprocessCommandRunner,
)
from .executor import RestrictedPrivilegedExecutor as _RestrictedPrivilegedExecutor
from .executor_listener import UnixExecutorListener as _UnixExecutorListener
from .executor_server import UnixExecutorConnectionHandler as _UnixExecutorConnectionHandler
from .replay_sqlite import (
    PRODUCTION_REPLAY_DATABASE as _PRODUCTION_REPLAY_DATABASE,
    SQLiteReplayGuard as _SQLiteReplayGuard,
)
from .state_store import FilesystemDeploymentStateStore as _FilesystemDeploymentStateStore


__all__ = ("DevExecutorComposition",)


class DevExecutorComposition:
    """Own one closed DEV executor graph with only single-accept delegation."""

    __slots__ = ("_serve_once",)

    def __init__(
        self, *, listener: object, clock: object, canary_image: str,
        reviewed_commit: str,
        runtime_configuration_sha256: str,
        ingress_file_sha256: tuple[str, str, str],
        expected_state_owner_uid: int, expected_state_group_gid: int,
        expected_replay_directory_uid: int, expected_replay_directory_gid: int,
        expected_broker_uid: int, expected_broker_gid: int,
        expected_socket_owner_uid: int, expected_socket_group_gid: int,
    ) -> None:
        """Construct the reviewed graph without invoking an operational method."""

        state_store = _FilesystemDeploymentStateStore(
            expected_owner_uid=expected_state_owner_uid,
            expected_group_gid=expected_state_group_gid,
        )
        replay_guard = _SQLiteReplayGuard(
            _PRODUCTION_REPLAY_DATABASE,
            expected_directory_uid=expected_replay_directory_uid,
            expected_directory_gid=expected_replay_directory_gid,
        )
        audit_sink = _FilesystemAuditSink()
        command_runner = _SubprocessCommandRunner()
        candidate_http_client = _DockerComposeCandidateHttpClient(
            command_runner, canary_image=canary_image,
        )
        runtime = _DockerRuntimeAdapter(
            command_runner, candidate_http_client, canary_image=canary_image,
        )
        operation = _DevDeploymentOperation(
            runtime=runtime,
            state_store=state_store,
            audit_sink=audit_sink,
            clock=clock,
            reviewed_commit=reviewed_commit,
            runtime_configuration_sha256=runtime_configuration_sha256,
            ingress_file_sha256=ingress_file_sha256,
        )
        executor = _RestrictedPrivilegedExecutor(
            replay_guard=replay_guard, operation=operation,
        )
        handler = _UnixExecutorConnectionHandler(
            executor=executor,
            expected_broker_uid=expected_broker_uid,
            expected_broker_gid=expected_broker_gid,
        )
        executor_listener = _UnixExecutorListener(
            listener=listener,
            handler=handler,
            expected_socket_owner_uid=expected_socket_owner_uid,
            expected_socket_group_gid=expected_socket_group_gid,
        )
        object.__setattr__(self, "_serve_once", executor_listener.serve_once)

    def __setattr__(self, name: str, value: object) -> None:
        """Reject supported-API mutation of the captured listener boundary."""

        raise AttributeError("DEV executor composition is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject supported-API deletion of the captured listener boundary."""

        raise AttributeError("DEV executor composition is immutable")

    def serve_once(self) -> None:
        """Delegate exactly once to the composed existing-listener boundary."""

        result = object.__getattribute__(self, "_serve_once")()
        if result is not None:
            raise TypeError("DEV executor listener returned an invalid result")

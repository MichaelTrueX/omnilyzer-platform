"""deployment/executor_composition.py — inert Task 014 DEV executor composition.

This file composes ``deployment.state_store``, ``deployment.replay_sqlite``,
``deployment.audit``, ``deployment.docker_runtime``,
``deployment.deployment_operation``, ``deployment.executor``,
``deployment.executor_server``, and ``deployment.executor_listener`` into one
closed executor boundary.  Import and construction are inert: they do not
create, bind, or listen on sockets; install or initialize infrastructure; or
execute deployment infrastructure.  Only an explicit ``serve_once()`` call
delegates to the already-reviewed listener boundary.
"""

from __future__ import annotations

import types as _types

from .audit import FilesystemAuditSink as _FilesystemAuditSink
from .deployment_operation import DevDeploymentOperation as _DevDeploymentOperation
from .docker_runtime import (
    CandidateHttpClient as _CandidateHttpClient,
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

_CONFIGURATION_MESSAGE = "DEV executor composition configuration is invalid"


def _validate_candidate_http_client(client: object) -> None:
    """Validate the candidate client's one reviewed HTTP method shape."""

    if client is None:
        raise TypeError(_CONFIGURATION_MESSAGE)
    try:
        hierarchy = type.__getattribute__(type(client), "__mro__")
    except (AttributeError, TypeError):
        raise TypeError(_CONFIGURATION_MESSAGE) from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if "get" in namespace:
            descriptor = namespace["get"]
            break
    if type(descriptor) is not _types.FunctionType:
        raise TypeError(_CONFIGURATION_MESSAGE)
    code = descriptor.__code__
    keyword_start = code.co_argcount
    keyword_end = keyword_start + code.co_kwonlyargcount
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != 3
        or tuple(code.co_varnames[1:3]) != ("slot", "path")
        or code.co_kwonlyargcount != 2
        or tuple(code.co_varnames[keyword_start:keyword_end])
        != ("timeout", "max_bytes")
        or code.co_flags & (0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200)
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError(_CONFIGURATION_MESSAGE)


class DevExecutorComposition:
    """Own one closed DEV executor graph with only single-accept delegation."""

    __slots__ = ("_serve_once",)

    def __init__(
        self, *, listener: object, candidate_http_client: _CandidateHttpClient,
        clock: object, canary_image: str, reviewed_commit: str,
        runtime_configuration_sha256: str,
        ingress_file_sha256: tuple[str, str, str],
        expected_state_owner_uid: int, expected_state_group_gid: int,
        expected_replay_directory_uid: int, expected_replay_directory_gid: int,
        expected_broker_uid: int, expected_broker_gid: int,
        expected_socket_owner_uid: int, expected_socket_group_gid: int,
    ) -> None:
        """Construct the reviewed graph without invoking an operational method."""

        _validate_candidate_http_client(candidate_http_client)
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

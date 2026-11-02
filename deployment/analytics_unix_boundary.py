"""File: deployment/analytics_unix_boundary.py

Purpose: Product-scoped, inert Task014 Analytics private Unix executor
         transport and connected-socket receiver. Reuse original peer, socket,
         deadline, framing, SCM_RIGHTS and response validation without
         modifying the currently installed canary control plane.
Related: deployment/unix_transport.py, deployment/executor_server.py,
         deployment/private_registry_fd.py, deployment/analytics_execution.py,
         deployment/analytics_executor.py,
         deployment/executor_listener.py (original single accept),
         deployment/tests/test_analytics_unix_boundary.py.

Sections: fixed dedicated Analytics socket transport, strict receiver adapter.

SECURITY: This is NOT installed or listening. Root-owned runtime deployment
must supply reviewed hash authority and approved separate socket listener.
This code intentionally refuses the original canary socket, request grammar,
and credential. It fails closed if the original internal secured tuple changes.
No general-purpose pluggable route or generic framework is introduced.
"""
from __future__ import annotations

from .analytics_execution import (
    MAX_ANALYTICS_REQUEST_BYTES, parse_analytics_request,
)
from .analytics_executor import AnalyticsPrivilegedExecutor
from .analytics_signed_release_consumer import PINNED_IMAGE
from .executor_server import UnixExecutorConnectionHandler
from .executor_listener import (
    UnixExecutorListener, PRODUCTION_EXECUTOR_SOCKET_PATH as CANARY_LISTENER_PATH,
)
from .execution import parse_canonical_request
from .private_registry_fd import read_sealed_credential
from .unix_transport import (
    PRODUCTION_EXECUTOR_SOCKET_PATH, UnixExecutorTransport, _validate_path,
    ExecutorTransportUnavailableError, TRANSPORT_UNAVAILABLE_MESSAGE,
)

#570s normal work +75s independent stop cleanup +30s manifest preflight and
# replay/response margin fit here. The unchanged900s edge also covers the
# original117s broker prefix:117+720=837s. Canary remains600s.
ANALYTICS_RESPONSE_TIMEOUT_MS = 720_000
from .policy import validate_sha256, validate_source_sha

ANALYTICS_EXECUTOR_SOCKET_PATH = "/run/omnilyzer/deployment/analytics-executor.sock"
_FIELDS = frozenset({
    "reviewed_installed_commit", "reviewed_compose_sha256",
    "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
})
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


def _root_reviewed_source(source: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Recheck four already root-controlled installed input identities."""
    try:
        if type(source) is not dict or set(source) != _FIELDS:
            raise ValueError
        selected = dict(source)
        selected["reviewed_installed_commit"] = validate_source_sha(
            selected["reviewed_installed_commit"]
        )
        for name in _FIELDS - {"reviewed_installed_commit"}:
            selected[name] = validate_sha256(selected[name], name)
        return tuple(sorted(selected.items()))
    except _CONTROL:
        raise
    except Exception:
        raise TypeError("Analytics Unix authority is invalid") from None


class AnalyticsUnixExecutorTransport(UnixExecutorTransport):
    """Use original verified Unix transport on ONE separate product socket."""

    __slots__ = ("_reviewed_source",)

    def __init__(
        self, *, expected_executor_uid: int, expected_executor_gid: int,
        expected_socket_group_gid: int, reviewed_installed_source: dict[str, str],
        timeout_ms: int = 3000,
    ) -> None:
        """Select exact separate socket, never an untrusted path or URL."""
        source = _root_reviewed_source(reviewed_installed_source)
        super().__init__(
            expected_executor_uid=expected_executor_uid,
            expected_executor_gid=expected_executor_gid,
            expected_socket_group_gid=expected_socket_group_gid,
            timeout_ms=timeout_ms,
        )
        settings = list(object.__getattribute__(self, "_configuration"))
        # All source/peer/metadata/deadline checks remain ORIGINAL. Fail closed
        # rather than replace arbitrary indices if its reviewed tuple changes.
        if (
            len(settings) != 28
            or settings[4] != 600_000
            or settings[5] != PRODUCTION_EXECUTOR_SOCKET_PATH
            or settings[6] != _validate_path(PRODUCTION_EXECUTOR_SOCKET_PATH)[1]
        ):
            raise TypeError("Analytics Unix transport boundary has changed")
        path, encoded = _validate_path(ANALYTICS_EXECUTOR_SOCKET_PATH)
        if path == PRODUCTION_EXECUTOR_SOCKET_PATH:
            raise TypeError("Analytics socket may not equal canary socket")
        settings[4] = ANALYTICS_RESPONSE_TIMEOUT_MS
        settings[5], settings[6] = path, encoded
        object.__setattr__(self, "_configuration", tuple(settings))
        object.__setattr__(self, "_reviewed_source", source)

    def send(self, canonical_request: bytes) -> bytes:
        """Uncredentialed or generic send is forbidden for Analytics."""
        raise ExecutorTransportUnavailableError(
            TRANSPORT_UNAVAILABLE_MESSAGE
        ) from None

    def _send_private(
        self, canonical_request: bytes, *, credential_fd: int,
    ) -> bytes:
        """Do not allow inherited canary private route on Analytics socket."""
        raise ExecutorTransportUnavailableError(
            TRANSPORT_UNAVAILABLE_MESSAGE
        ) from None

    def _send_analytics_private(
        self, canonical_request: bytes, *, credential_fd: int,
    ) -> bytes:
        """Validate exact product request and sealed credential before socket."""
        try:
            request = parse_analytics_request(
                canonical_request,
                **dict(object.__getattribute__(self, "_reviewed_source")),
            )
            if request.exact_image_reference != PINNED_IMAGE:
                raise ValueError("wrong immutable signed image")
            read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=PINNED_IMAGE, product_id="analytics",
            )
        except _CONTROL:
            raise
        except Exception:
            raise ExecutorTransportUnavailableError(
                TRANSPORT_UNAVAILABLE_MESSAGE
            ) from None
        return UnixExecutorTransport._send(
            self, canonical_request, credential_fd=credential_fd,
        )


class AnalyticsUnixExecutorConnectionHandler(UnixExecutorConnectionHandler):
    """Adapt the original SO_PEERCRED+SCM_RIGHTS receiver to Analytics only."""

    __slots__ = ()

    def __init__(
        self, *, executor: AnalyticsPrivilegedExecutor,
        expected_broker_uid: int, expected_broker_gid: int,
        reviewed_installed_source: dict[str, str],
        timeout_ms: int = 3000,
    ) -> None:
        """Capture exact Analytics parser/FD at construction, never per-call."""
        if type(executor) is not AnalyticsPrivilegedExecutor:
            raise TypeError("Analytics receiver must have exact executor type")
        source = _root_reviewed_source(reviewed_installed_source)
        super().__init__(
            executor=executor, expected_broker_uid=expected_broker_uid,
            expected_broker_gid=expected_broker_gid,
            timeout_ms=timeout_ms, private_registry_transfer=True,
        )
        settings = list(object.__getattribute__(self, "_configuration"))
        if (
            len(settings) != 32
            or settings[28] is not True
            or settings[31] is not parse_canonical_request
            or settings[30] is not read_sealed_credential
        ):
            raise TypeError("Analytics Unix receiver boundary has changed")

        def parse_analytics(raw: bytes):
            """Reparse exact canonical product bytes before reading the FD."""
            return parse_analytics_request(raw, **dict(source))

        def read_analytics(fd: int, *, canonical_request: bytes, image: str):
            """Require the original kernel-sealed FD to match ONLY Analytics."""
            return read_sealed_credential(
                fd, canonical_request=canonical_request,
                image=image, product_id="analytics",
            )

        settings[13] = MAX_ANALYTICS_REQUEST_BYTES
        settings[30] = read_analytics
        settings[31] = parse_analytics
        object.__setattr__(self, "_configuration", tuple(settings))


class AnalyticsUnixExecutorListener(UnixExecutorListener):
    """Original single-accept inode and procfs checks on exact Analytics socket.

    No systemd socket is created, installed, enabled or bound here. The
    immutable parent class performs its existing credential-free listener
    security checks, accept, deadline, close and handler dispatch.
    """

    __slots__ = ()

    def __init__(
        self, *, listener: object, handler: AnalyticsUnixExecutorConnectionHandler,
        expected_socket_owner_uid: int, expected_socket_group_gid: int,
        accept_timeout_ms: int = 3000,
    ) -> None:
        """Bind one exact Analytics-only listener; never choose a caller path."""
        if type(handler) is not AnalyticsUnixExecutorConnectionHandler:
            raise TypeError("Analytics listener requires its exact receiver")
        super().__init__(
            listener=listener, handler=handler,
            expected_socket_owner_uid=expected_socket_owner_uid,
            expected_socket_group_gid=expected_socket_group_gid,
            accept_timeout_ms=accept_timeout_ms,
        )
        settings = list(object.__getattribute__(self, "_configuration"))
        if (
            len(settings) != 38
            or settings[26] != CANARY_LISTENER_PATH
            or settings[27] != (
                "/", "/run", "/run/omnilyzer", "/run/omnilyzer/deployment",
            )
        ):
            raise TypeError("Original Task014 listener contract has changed")
        # The only permitted path is this exact product-specific socket.
        new_path, _encoded = _validate_path(ANALYTICS_EXECUTOR_SOCKET_PATH)
        if new_path == CANARY_LISTENER_PATH:
            raise TypeError("Analytics may not attach to the canary socket")
        settings[26] = new_path
        object.__setattr__(self, "_configuration", tuple(settings))


__all__ = (
    "ANALYTICS_EXECUTOR_SOCKET_PATH", "AnalyticsUnixExecutorTransport",
    "AnalyticsUnixExecutorConnectionHandler", "AnalyticsUnixExecutorListener",
)

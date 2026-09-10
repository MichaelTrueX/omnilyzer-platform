"""Inert bounded handler for one already-connected executor Unix socket.

This module creates no socket or listener and performs no installation,
filesystem, runtime, registry, application, or deployment action.  A future
separately reviewed listener may pass one connected Unix stream socket to the
closed handler boundary.
"""

from __future__ import annotations

import math
import socket
import struct
import threading
import time
import types
from typing import Any, Callable

from .broker import MAX_EXECUTOR_RESPONSE_BYTES
from .execution import MAX_CANONICAL_REQUEST_BYTES
from .executor import ExecutorResponse, parse_canonical_response
from .unix_transport import MAX_TIMEOUT_MS


EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE = "executor connection is unavailable"
MAX_IDENTITY_VALUE = 2**32 - 2
_PEER_CREDENTIALS = struct.Struct("=iII")


class ExecutorConnectionUnavailableError(Exception):
    """One connected broker exchange did not complete trustworthily."""


def _make_handling_gate() -> tuple[
    Callable[[object], bool], Callable[[object], None],
]:
    active: set[int] = set()
    lock = threading.Lock()

    def enter(instance: object) -> bool:
        identity = id(instance)
        with lock:
            if identity in active:
                return False
            active.add(identity)
            return True

    def leave(instance: object) -> None:
        with lock:
            active.remove(id(instance))

    return enter, leave


_ENTER_HANDLING, _LEAVE_HANDLING = _make_handling_gate()


class _MonotonicValidator:
    __slots__ = ("_clock", "_isfinite", "_last")

    def __init__(
        self, clock: Callable[[], object],
        isfinite: Callable[[object], bool] = math.isfinite,
    ) -> None:
        self._clock = clock
        self._isfinite = isfinite
        self._last: float | None = None

    def __call__(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not self._isfinite(value) or value < 0:
            raise OSError("invalid monotonic clock")
        normalized = float(value)
        if self._last is not None and normalized < self._last:
            raise OSError("monotonic clock moved backward")
        self._last = normalized
        return normalized


class _Deadline:
    __slots__ = ("_clock", "_deadline", "_isfinite", "_last")

    def __init__(
        self, clock: Callable[[], object], timeout_ms: int,
        isfinite: Callable[[object], bool] = math.isfinite,
    ) -> None:
        self._clock = clock
        self._isfinite = isfinite
        start = self._sample(None)
        self._last = start
        self._deadline = start + timeout_ms / 1000.0
        if not self._isfinite(self._deadline) or self._deadline <= start:
            raise OSError("invalid monotonic deadline")

    def _sample(self, prior: float | None) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not self._isfinite(value) or value < 0:
            raise OSError("invalid monotonic clock")
        normalized = float(value)
        if prior is not None and normalized < prior:
            raise OSError("monotonic clock moved backward")
        return normalized

    def remaining(self) -> float:
        current = self._sample(self._last)
        self._last = current
        remaining = self._deadline - current
        if not self._isfinite(remaining) or remaining <= 0:
            raise TimeoutError("executor connection deadline elapsed")
        return remaining


def _configuration_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_IDENTITY_VALUE:
        raise TypeError("executor connection handler configuration is invalid")
    return value


def _ordinary_execute(executor: object) -> Callable[[bytes], object]:
    if executor is None:
        raise TypeError("executor connection handler configuration is invalid")
    cls = type(executor)
    try:
        hierarchy = type.__getattribute__(cls, "__mro__")
    except (AttributeError, TypeError):
        raise TypeError("executor connection handler configuration is invalid") from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if "execute" in namespace:
            descriptor = namespace["execute"]
            break
    if type(descriptor) is not types.FunctionType:
        raise TypeError("executor connection handler configuration is invalid")
    code = descriptor.__code__
    disallowed_flags = 0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != 2
        or code.co_kwonlyargcount != 0
        or tuple(code.co_varnames[1:2]) != ("canonical_request",)
        or code.co_flags & disallowed_flags
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError("executor connection handler configuration is invalid")
    return types.MethodType(descriptor, executor)


def _connection_operations(connection: object) -> tuple[Callable[..., Any], ...]:
    try:
        operations = tuple(
            object.__getattribute__(connection, name)
            for name in (
                "get_inheritable", "getsockopt", "settimeout", "recv", "send",
                "shutdown",
            )
        )
    except (AttributeError, TypeError):
        raise OSError("invalid executor connection") from None
    if not all(callable(operation) for operation in operations):
        raise OSError("invalid executor connection")
    return operations


def _timed_call(
    settimeout: Callable[[float], object], operation: Callable[..., Any],
    deadline: _Deadline, *arguments: object,
) -> Any:
    while True:
        settimeout(deadline.remaining())
        try:
            result = operation(*arguments)
        except InterruptedError:
            deadline.remaining()
            continue
        deadline.remaining()
        return result


def _receive_exact(
    recv: Callable[[int], object], settimeout: Callable[[float], object],
    size: int, deadline: _Deadline,
) -> bytes:
    remaining = size
    pieces: list[bytes] = []
    while remaining:
        piece = _timed_call(settimeout, recv, deadline, remaining)
        if type(piece) is not bytes or not piece or len(piece) > remaining:
            raise OSError("truncated executor request")
        pieces.append(piece)
        remaining -= len(piece)
    return b"".join(pieces)


def _send_exact(
    send: Callable[[object], object], settimeout: Callable[[float], object],
    value: bytes, deadline: _Deadline,
) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(value):
        sent = _timed_call(settimeout, send, deadline, view[offset:])
        if type(sent) is not int or not 1 <= sent <= len(value) - offset:
            raise OSError("truncated executor response send")
        offset += sent


class UnixExecutorConnectionHandler:
    """Authenticate and serve exactly one already-connected broker socket."""

    __slots__ = ("_configuration",)

    def __init__(
        self, *, executor: object, expected_broker_uid: int,
        expected_broker_gid: int, timeout_ms: int = 3000,
    ) -> None:
        execute = _ordinary_execute(executor)
        uid = _configuration_integer(expected_broker_uid)
        gid = _configuration_integer(expected_broker_gid)
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise TypeError("executor connection handler configuration is invalid")
        object.__setattr__(self, "_configuration", (
            execute, uid, gid, timeout_ms, socket.AF_UNIX, socket.SOCK_STREAM,
            socket.SOL_SOCKET, getattr(socket, "SO_DOMAIN", None), socket.SO_TYPE,
            getattr(socket, "SO_PEERCRED", None), socket.SHUT_WR,
            _PEER_CREDENTIALS.size, _PEER_CREDENTIALS.unpack,
            MAX_CANONICAL_REQUEST_BYTES, MAX_EXECUTOR_RESPONSE_BYTES,
            time.monotonic, _MonotonicValidator, _Deadline,
            _connection_operations, _timed_call, _receive_exact, _send_exact,
            parse_canonical_response, ExecutorResponse,
            _ENTER_HANDLING, _LEAVE_HANDLING,
            ExecutorConnectionUnavailableError,
            EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE,
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("executor connection handler configuration is immutable")

    def handle(self, connection: object) -> None:
        (
            execute, expected_uid, expected_gid, timeout_ms, af_unix, sock_stream,
            sol_socket, so_domain, so_type, so_peercred, shut_wr, peer_size,
            peer_unpack, request_bound, response_bound, monotonic,
            monotonic_validator, deadline_factory, connection_operations,
            timed_call, receive_exact, send_exact, parse_response, response_type,
            enter_handling, leave_handling, error_type, error_message,
        ) = object.__getattribute__(self, "_configuration")

        close: Callable[[], object] | None = None
        request_deadline = None
        response_deadline = None
        request_complete = False
        entered = False
        completed = False
        failed = False
        control: tuple[BaseException, object] | None = None

        try:
            close_candidate = object.__getattribute__(connection, "close")
            if not callable(close_candidate):
                raise OSError("invalid executor connection")
            close = close_candidate
            operations = connection_operations(connection)
            (
                get_inheritable, getsockopt, settimeout, recv, send, shutdown,
            ) = operations
            entered = enter_handling(self)
            if not entered:
                raise OSError("executor connection handler is already active")

            validated_monotonic = monotonic_validator(monotonic)
            request_deadline = deadline_factory(validated_monotonic, timeout_ms)
            if get_inheritable() is not False:
                raise OSError("inheritable executor connection")
            request_deadline.remaining()
            if so_domain is None or so_peercred is None:
                raise OSError("required Linux socket controls unavailable")
            actual_domain = timed_call(
                settimeout, getsockopt, request_deadline, sol_socket, so_domain,
            )
            if type(actual_domain) is not int or actual_domain != af_unix:
                raise OSError("wrong executor connection domain")
            actual_type = timed_call(
                settimeout, getsockopt, request_deadline, sol_socket, so_type,
            )
            if type(actual_type) is not int or actual_type != sock_stream:
                raise OSError("wrong executor connection type")
            credentials = timed_call(
                settimeout, getsockopt, request_deadline, sol_socket, so_peercred,
                peer_size,
            )
            if type(credentials) is not bytes or len(credentials) != peer_size:
                raise OSError("invalid broker peer credentials")
            peer_pid, peer_uid, peer_gid = peer_unpack(credentials)
            if (
                type(peer_pid) is not int
                or type(peer_uid) is not int
                or type(peer_gid) is not int
                or peer_pid <= 0
                or peer_uid != expected_uid
                or peer_gid != expected_gid
            ):
                raise OSError("unexpected broker peer credentials")

            header = receive_exact(recv, settimeout, 4, request_deadline)
            request_length = int.from_bytes(header, "big", signed=False)
            if request_length == 0 or request_length > request_bound:
                raise OSError("invalid executor request length")
            canonical_request = receive_exact(
                recv, settimeout, request_length, request_deadline,
            )
            trailing = timed_call(settimeout, recv, request_deadline, 1)
            if type(trailing) is not bytes or trailing != b"":
                raise OSError("executor request contains trailing data")
            request_complete = True

            response = execute(canonical_request)
            response_deadline = deadline_factory(validated_monotonic, timeout_ms)
            if type(response) is not bytes or not response or len(response) > response_bound:
                raise OSError("invalid executor response")
            parsed_response = parse_response(response)
            if type(parsed_response) is not response_type:
                raise OSError("invalid executor response")

            response_header = len(response).to_bytes(4, "big", signed=False)
            send_exact(send, settimeout, response_header, response_deadline)
            send_exact(send, settimeout, response, response_deadline)
            timed_call(settimeout, shutdown, response_deadline, shut_wr)
            completed = True
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
            control = (exc, exc.__traceback__)
        except Exception:
            failed = True
        finally:
            cleanup_deadline = response_deadline
            if not request_complete and cleanup_deadline is None:
                cleanup_deadline = request_deadline
            if close is not None:
                if cleanup_deadline is not None:
                    try:
                        cleanup_deadline.remaining()
                    except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                        if control is None:
                            control = (exc, exc.__traceback__)
                    except Exception:
                        failed = True
                try:
                    close()
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except Exception:
                    failed = True
                if cleanup_deadline is not None:
                    try:
                        cleanup_deadline.remaining()
                    except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                        if control is None:
                            control = (exc, exc.__traceback__)
                    except Exception:
                        failed = True
            if entered:
                leave_handling(self)

        if control is not None:
            error, traceback = control
            raise error.with_traceback(traceback)
        if failed or not completed:
            raise error_type(error_message) from None
        return None


__all__ = (
    "EXECUTOR_CONNECTION_UNAVAILABLE_MESSAGE",
    "ExecutorConnectionUnavailableError",
    "UnixExecutorConnectionHandler",
)

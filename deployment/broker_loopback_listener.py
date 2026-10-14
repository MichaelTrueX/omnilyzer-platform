"""Explicit, inert sequential DEV broker loopback HTTP/1.0 mechanics.

Import and construction do not create sockets. Explicit lifecycle operations
alone bind the fixed numeric IPv4 loopback address.
"""

from __future__ import annotations

import math
import re
import socket
import threading
import time
from typing import Callable

from .broker_https_ingress import (
    BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, PROMOTION_PATH,
    IngressResponse, dispatch_inert_dev_promotion_ingress,
)
from .broker_integration import MAX_PROMOTION_REQUEST_BYTES
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES


LISTENER_UNAVAILABLE_MESSAGE = "deployment listener is unavailable"
READ_TIMEOUT_SECONDS = 5
WRITE_TIMEOUT_SECONDS = 5
ACCEPT_TIMEOUT_SECONDS = 5
LISTEN_BACKLOG = 2
MAX_HEADER_BYTES = 3 * MAX_COMPACT_TOKEN_BYTES + 1024
MAX_HEADER_COUNT = 9  # seven valid fields plus two extra for C32Q rejection
_REQUEST_LINE = b"POST " + PROMOTION_PATH.encode("ascii") + b" HTTP/1.0"
_HEADER_NAME = re.compile(rb"[A-Za-z0-9-]+\Z")
_DECIMAL = re.compile(rb"[1-9][0-9]*\Z")
_HOP_HEADERS = frozenset({b"transfer-encoding", b"te", b"trailer",
                          b"upgrade", b"proxy-connection", b"keep-alive"})
_REJECTED = IngressResponse(403, b'{"status":"rejected"}\n')
_UNAVAILABLE = IngressResponse(503, b'{"status":"unavailable"}\n')
_STATUS = {202: b"Accepted", 403: b"Forbidden", 503: b"Service Unavailable"}


class BrokerLoopbackListenerError(Exception):
    """One fixed external listener/cleanup failure."""


class _FramingRejected(Exception):
    """Private malformed transport signal; carries no request data."""


class BrokerStopController:
    """Call-local process stop state; never derived from an HTTP request."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        object.__setattr__(self, "_event", threading.Event())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("broker stop controller is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("broker stop controller is immutable")

    def request_stop(self) -> None:
        object.__getattribute__(self, "_event").set()

    def is_stopping(self) -> bool:
        return object.__getattribute__(self, "_event").is_set()


class _Deadline:
    __slots__ = ("_clock", "_limit", "_last")

    def __init__(self, clock: Callable[[], object], seconds: int) -> None:
        self._clock = clock
        self._last: float | None = None
        start = self._sample()
        self._limit = start + seconds
        if not math.isfinite(self._limit) or self._limit <= start:
            raise OSError("invalid deadline")

    def _sample(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise OSError("invalid monotonic time")
        normalized = float(value)
        if self._last is not None and normalized < self._last:
            raise OSError("monotonic time moved backward")
        self._last = normalized
        return normalized

    def remaining(self) -> float:
        remaining = self._limit - self._sample()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("deadline elapsed")
        return remaining


def _recv(connection: object, count: int, deadline: _Deadline) -> bytes:
    if type(count) is not int or not 1 <= count <= 4096:
        raise OSError("invalid read bound")
    connection.settimeout(deadline.remaining())
    data = connection.recv(count)
    deadline.remaining()
    if type(data) is not bytes or len(data) > count:
        raise OSError("invalid socket read")
    return data


def _parse_head(head: bytes) -> tuple[list[tuple[str, str]], int]:
    lines = head.split(b"\r\n")
    if (not lines or lines[0] != _REQUEST_LINE
            or not 2 <= len(lines) - 1 <= MAX_HEADER_COUNT
            or any(b"\r" in line or b"\n" in line for line in lines)):
        raise _FramingRejected()
    semantic: list[tuple[str, str]] = []
    connection_count = 0
    lengths: list[bytes] = []
    for line in lines[1:]:
        name, separator, value = line.partition(b": ")
        if (not separator or not name or _HEADER_NAME.fullmatch(name) is None
                or len(name) > 64
                or len(value) > MAX_COMPACT_TOKEN_BYTES + len("Bearer ")
                or b":" in value or not value
                or any(byte < 32 or byte > 126 for byte in value)):
            raise _FramingRejected()
        lowered = name.lower()
        if lowered in _HOP_HEADERS:
            raise _FramingRejected()
        if lowered == b"connection":
            connection_count += 1
            if value != b"close":
                raise _FramingRejected()
            continue
        if lowered == b"content-length":
            lengths.append(value)
        semantic.append((name.decode("ascii"), value.decode("ascii")))
    if connection_count != 1 or len(lengths) != 1:
        raise _FramingRejected()
    raw_length = lengths[0]
    if _DECIMAL.fullmatch(raw_length) is None or len(raw_length) > 4:
        raise _FramingRejected()
    length = int(raw_length)
    if length > MAX_PROMOTION_REQUEST_BYTES:
        raise _FramingRejected()
    return semantic, length


def _read_request(connection: object, deadline: _Deadline) -> tuple[list[tuple[str, str]], bytes]:
    buffered = bytearray()
    separator = -1
    while separator < 0:
        chunk = _recv(connection, 4096, deadline)
        if not chunk:
            raise _FramingRejected()
        buffered.extend(chunk)
        separator = buffered.find(b"\r\n\r\n")
        if ((separator < 0 and len(buffered) > MAX_HEADER_BYTES)
                or (separator >= 0 and separator + 4 > MAX_HEADER_BYTES)
                or (b"\r\n" not in buffered
                    and len(buffered) > len(_REQUEST_LINE) + 2)):
            raise _FramingRejected()
    headers, length = _parse_head(bytes(buffered[:separator]))
    body = bytes(buffered[separator + 4:])
    if len(body) > length:
        raise _FramingRejected()  # already-buffered pipelining/early data
    while len(body) < length:
        chunk = _recv(connection, min(4096, length - len(body)), deadline)
        if not chunk:
            raise _FramingRejected()
        body += chunk
    return headers, body


def _received_at(clock: Callable[[], object]) -> int:
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise OSError("invalid receipt time")
    result = int(value)
    if result < 0:
        raise OSError("invalid receipt time")
    return result


def _response_bytes(response: IngressResponse) -> bytes:
    if type(response) is not IngressResponse or response.status not in _STATUS:
        raise OSError("invalid ingress response")
    # Revalidate even a forged frozen instance before sending anything.
    IngressResponse(response.status, response.body, response.content_type)
    data = (b"HTTP/1.0 " + str(response.status).encode("ascii") + b" "
            + _STATUS[response.status] + b"\r\n"
            + b"Content-Type: application/json\r\n"
            + b"Content-Length: " + str(len(response.body)).encode("ascii") + b"\r\n"
            + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
            + response.body)
    if len(data) > 256:
        raise OSError("invalid response bound")
    return data


def _write_response(connection: object, response: IngressResponse,
                    deadline: _Deadline) -> None:
    data = _response_bytes(response)
    position = 0
    while position < len(data):
        connection.settimeout(deadline.remaining())
        count = connection.send(data[position:])
        deadline.remaining()
        if type(count) is not int or not 1 <= count <= len(data) - position:
            raise OSError("invalid socket write")
        position += count


class DevBrokerLoopbackListener:
    """Sequential requests; no socket exists until an explicit serve operation."""

    __slots__ = ("_handler", "_socket_factory", "_wall_clock", "_monotonic", "_gate")

    def __init__(
        self, handler: object, *,
        socket_factory: Callable[..., object] = socket.socket,
        wall_clock: Callable[[], object] = time.time,
        monotonic: Callable[[], object] = time.monotonic,
    ) -> None:
        if handler is None or not all(callable(item) for item in (
                socket_factory, wall_clock, monotonic)):
            raise TypeError("broker listener collaborator is invalid")
        object.__setattr__(self, "_handler", handler)
        object.__setattr__(self, "_socket_factory", socket_factory)
        object.__setattr__(self, "_wall_clock", wall_clock)
        object.__setattr__(self, "_monotonic", monotonic)
        object.__setattr__(self, "_gate", threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("broker listener authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("broker listener authority is immutable")

    def serve_once(self) -> int:
        """Bind fixed loopback, accept/handle one request, then close both sockets."""

        gate = object.__getattribute__(self, "_gate")
        if not gate.acquire(blocking=False):
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None
        try:
            return self._serve_once_locked()
        finally:
            gate.release()

    def serve_until_stopped(self, stop_controller: BrokerStopController) -> None:
        """Hold one listener and process complete requests until stop is requested."""

        if type(stop_controller) is not BrokerStopController:
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None
        gate = object.__getattribute__(self, "_gate")
        if not gate.acquire(blocking=False):
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None
        try:
            self._serve_persistent_locked(stop_controller)
        finally:
            gate.release()

    def _open_server(self) -> object:
        server = None
        try:
            server = object.__getattribute__(self, "_socket_factory")(
                socket.AF_INET, socket.SOCK_STREAM)
            if (server.family != socket.AF_INET
                    or server.type & 0xf != socket.SOCK_STREAM):
                raise OSError("wrong listener socket type")
            server.set_inheritable(False)
            if server.get_inheritable() is not False:
                raise OSError("inheritable listener")
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT))
            if server.getsockname() != (BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT):
                raise OSError("wrong listener binding")
            server.listen(LISTEN_BACKLOG)
            server.settimeout(ACCEPT_TIMEOUT_SECONDS)
            return server
        except BaseException:
            if server is not None:
                try:
                    server.close()
                except Exception:
                    pass
            raise

    def _handle_connection(self, connection: object, peer: object) -> int:
        outcome = None
        failed = False
        control: BaseException | None = None
        try:
            if (connection.family != socket.AF_INET
                    or connection.type & 0xf != socket.SOCK_STREAM):
                raise OSError("wrong accepted socket type")
            if (type(peer) is not tuple or len(peer) != 2
                    or type(peer[0]) is not str or peer[0] != BROKER_LOOPBACK_HOST
                    or type(peer[1]) is not int or not 1 <= peer[1] <= 65535):
                raise OSError("wrong loopback peer")
            connection.set_inheritable(False)
            if connection.get_inheritable() is not False:
                raise OSError("inheritable connection")
            try:
                headers, body = _read_request(
                    connection, _Deadline(object.__getattribute__(self, "_monotonic"),
                                          READ_TIMEOUT_SECONDS),
                )
                # Receipt time is sampled only after the complete body arrived.
                received_at = _received_at(object.__getattribute__(self, "_wall_clock"))
                connection.settimeout(None)  # handler has its own operation limits
                response = dispatch_inert_dev_promotion_ingress(
                    object.__getattribute__(self, "_handler"),
                    method="POST", path=PROMOTION_PATH,
                    headers=headers, body=body, received_at=received_at,
                )
            except _FramingRejected:
                response = _REJECTED
            except (TimeoutError, OSError):
                response = _UNAVAILABLE
            _write_response(connection, response,
                            _Deadline(object.__getattribute__(self, "_monotonic"),
                                      WRITE_TIMEOUT_SECONDS))
            outcome = response.status
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
            control = error
        except Exception:
            failed = True
        finally:
            try:
                connection.close()
            except Exception:
                failed = True
        if control is not None:
            raise control
        if failed or outcome is None:
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None
        return outcome

    def _serve_once_locked(self) -> int:
        server = None
        outcome = None
        failed = False
        control: BaseException | None = None
        try:
            server = self._open_server()
            connection, peer = server.accept()
            outcome = self._handle_connection(connection, peer)
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
            control = error
        except Exception:
            failed = True
        finally:
            if server is not None:
                try:
                    server.close()
                except Exception:
                    failed = True
        if control is not None:
            raise control
        if failed or outcome is None:
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None
        return outcome

    def _serve_persistent_locked(self, stop_controller: BrokerStopController) -> None:
        server = None
        failed = False
        control: BaseException | None = None
        try:
            if stop_controller.is_stopping():
                return
            server = self._open_server()
            while not stop_controller.is_stopping():
                try:
                    connection, peer = server.accept()
                except TimeoutError:
                    continue
                self._handle_connection(connection, peer)
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as error:
            control = error
        except Exception:
            failed = True
        finally:
            if server is not None:
                try:
                    server.close()
                except Exception:
                    failed = True
        if control is not None:
            raise control
        if failed:
            raise BrokerLoopbackListenerError(LISTENER_UNAVAILABLE_MESSAGE) from None


__all__ = ("DevBrokerLoopbackListener", "BrokerLoopbackListenerError", "BrokerStopController",
           "LISTENER_UNAVAILABLE_MESSAGE", "READ_TIMEOUT_SECONDS",
           "WRITE_TIMEOUT_SECONDS", "ACCEPT_TIMEOUT_SECONDS",
           "LISTEN_BACKLOG", "MAX_HEADER_BYTES")

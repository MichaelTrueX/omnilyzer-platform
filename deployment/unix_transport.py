"""Inert bounded client transport for the future privileged executor.

This module implements no listener, installation, service management, or
deployment operation.  Import and construction do not inspect or open the
production socket.
"""

from __future__ import annotations

import math
import os
import posixpath
import socket
import struct
import time
from typing import Callable

from .broker import MAX_EXECUTOR_RESPONSE_BYTES
from .execution import MAX_CANONICAL_REQUEST_BYTES


PRODUCTION_EXECUTOR_SOCKET_PATH = "/run/omnilyzer/deployment/executor.sock"
TRANSPORT_UNAVAILABLE_MESSAGE = "executor transport is unavailable"
MAX_IDENTITY_VALUE = 2**32 - 2
MAX_TIMEOUT_MS = 3000
MAX_UNIX_PATH_BYTES = 107
_PEER_CREDENTIALS = struct.Struct("=iII")


class ExecutorTransportUnavailableError(Exception):
    """The executor exchange did not produce one trustworthy response."""


def _validate_configuration_integer(value: object, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise TypeError("executor transport configuration is invalid")
    return value


def _validate_path(path: object) -> tuple[str, bytes]:
    if type(path) is not str or not path.startswith("/") or path.startswith("//"):
        raise TypeError("executor transport configuration is invalid")
    if "\x00" in path or posixpath.normpath(path) != path:
        raise TypeError("executor transport configuration is invalid")
    components = path.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise TypeError("executor transport configuration is invalid")
    try:
        encoded = os.fsencode(path)
    except Exception:
        raise TypeError("executor transport configuration is invalid") from None
    if (type(encoded) is not bytes or not encoded or encoded.startswith(b"\x00")
            or b"\x00" in encoded or len(encoded) > MAX_UNIX_PATH_BYTES):
        raise TypeError("executor transport configuration is invalid")
    return path, encoded


def _metadata(
    info: object, *, owner_uid: int, group_gid: int,
    stat_result_type: type[os.stat_result] = os.stat_result,
) -> tuple[int, int]:
    if type(info) is not stat_result_type or tuple.__len__(info) < 6:
        raise OSError("invalid socket metadata")
    mode = tuple.__getitem__(info, 0)
    inode = tuple.__getitem__(info, 1)
    device = tuple.__getitem__(info, 2)
    links = tuple.__getitem__(info, 3)
    uid = tuple.__getitem__(info, 4)
    gid = tuple.__getitem__(info, 5)
    if (not all(type(value) is int for value in (mode, inode, device, links, uid, gid))
            or mode & 0o170000 != 0o140000
            or mode & 0o7777 != 0o660
            or links != 1 or uid != owner_uid or gid != group_gid
            or inode < 0 or device < 0):
        raise OSError("invalid socket metadata")
    return device, inode


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
        if not self._isfinite(self._deadline):
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
            raise TimeoutError("executor deadline elapsed")
        return remaining


class UnixExecutorTransport:
    """One request and one response over a verified local Unix socket."""

    __slots__ = ("_configuration",)

    def __init__(
        self, *, expected_executor_uid: int, expected_executor_gid: int,
        expected_socket_group_gid: int, timeout_ms: int = 3000,
    ) -> None:
        uid = _validate_configuration_integer(
            expected_executor_uid, maximum=MAX_IDENTITY_VALUE,
        )
        gid = _validate_configuration_integer(
            expected_executor_gid, maximum=MAX_IDENTITY_VALUE,
        )
        socket_gid = _validate_configuration_integer(
            expected_socket_group_gid, maximum=MAX_IDENTITY_VALUE,
        )
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise TypeError("executor transport configuration is invalid")
        path, encoded_path = _validate_path(PRODUCTION_EXECUTOR_SOCKET_PATH)
        socket_kind = socket.SOCK_STREAM
        if hasattr(socket, "SOCK_CLOEXEC"):
            socket_kind |= socket.SOCK_CLOEXEC
        object.__setattr__(self, "_configuration", (
            uid, gid, socket_gid, timeout_ms, path, encoded_path,
            os.lstat, socket.socket, time.monotonic, socket_kind,
            socket.AF_UNIX, socket.SOCK_STREAM, socket.SOL_SOCKET,
            getattr(socket, "SO_DOMAIN", None), socket.SO_TYPE,
            getattr(socket, "SO_PEERCRED", None), socket.SHUT_WR,
            MAX_CANONICAL_REQUEST_BYTES, MAX_EXECUTOR_RESPONSE_BYTES,
            _metadata, _Deadline, _PEER_CREDENTIALS.size,
            _PEER_CREDENTIALS.unpack, UnixExecutorTransport._receive_exact,
            ExecutorTransportUnavailableError, TRANSPORT_UNAVAILABLE_MESSAGE,
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("executor transport configuration is immutable")

    def send(self, canonical_request: bytes) -> bytes:
        (
            expected_uid, expected_gid, socket_group_gid, timeout_ms, path,
            _encoded_path, lstat, socket_factory, monotonic, socket_kind,
            af_unix, sock_stream, sol_socket, so_domain, so_type, so_peercred,
            shut_wr, request_bound, response_bound, metadata_validator,
            deadline_factory, peer_size, peer_unpack, receive_exact,
            error_type, error_message,
        ) = object.__getattribute__(self, "_configuration")
        if (type(canonical_request) is not bytes or not canonical_request
                or len(canonical_request) > request_bound):
            raise error_type(error_message) from None
        client = None
        response = None
        failed = False
        control: tuple[BaseException, object] | None = None
        deadline = None

        try:
            deadline = deadline_factory(monotonic, timeout_ms)
            before = lstat(path)
            before_identity = metadata_validator(
                before, owner_uid=expected_uid, group_gid=socket_group_gid,
            )
            deadline.remaining()
            client = socket_factory(af_unix, socket_kind)
            deadline.remaining()
            client.set_inheritable(False)
            if client.get_inheritable() is not False:
                raise OSError("inheritable socket")
            if so_domain is None or so_peercred is None:
                raise OSError("required Linux socket controls unavailable")
            actual_domain = client.getsockopt(sol_socket, so_domain)
            if type(actual_domain) is not int or actual_domain != af_unix:
                raise OSError("wrong socket domain")
            actual_type = client.getsockopt(sol_socket, so_type)
            if type(actual_type) is not int or actual_type != sock_stream:
                raise OSError("wrong socket type")

            client.settimeout(deadline.remaining())
            client.connect(path)
            client.settimeout(deadline.remaining())
            credentials = client.getsockopt(
                sol_socket, so_peercred, peer_size,
            )
            if type(credentials) is not bytes or len(credentials) != peer_size:
                raise OSError("invalid peer credentials")
            peer_pid, peer_uid, peer_gid = peer_unpack(credentials)
            if (peer_pid <= 0 or peer_uid != expected_uid
                    or peer_gid != expected_gid):
                raise OSError("unexpected peer credentials")

            after = lstat(path)
            after_identity = metadata_validator(
                after, owner_uid=expected_uid, group_gid=socket_group_gid,
            )
            if after_identity != before_identity:
                raise OSError("socket path changed")

            request_header = len(canonical_request).to_bytes(4, "big", signed=False)
            client.settimeout(deadline.remaining())
            client.sendall(request_header)
            client.settimeout(deadline.remaining())
            client.sendall(canonical_request)
            client.settimeout(deadline.remaining())
            client.shutdown(shut_wr)

            response_header = receive_exact(client, 4, deadline)
            response_length = int.from_bytes(response_header, "big", signed=False)
            response_header = b""
            if response_length > response_bound:
                raise OSError("response is oversized")
            response = receive_exact(client, response_length, deadline)
            client.settimeout(deadline.remaining())
            trailing = client.recv(1)
            if type(trailing) is not bytes or trailing != b"":
                raise OSError("response contains trailing data")
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
            control = (exc, exc.__traceback__)
        except Exception:
            failed = True

        if client is not None:
            if deadline is not None:
                try:
                    deadline.remaining()
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    control = (exc, exc.__traceback__)
                except Exception:
                    failed = True
            try:
                client.close()
            except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                control = (exc, exc.__traceback__)
            except Exception:
                failed = True
            if deadline is not None:
                try:
                    deadline.remaining()
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    control = (exc, exc.__traceback__)
                except Exception:
                    failed = True

        if control is not None:
            error, traceback = control
            raise error.with_traceback(traceback)
        if failed or type(response) is not bytes:
            raise error_type(error_message) from None
        return response

    @staticmethod
    def _receive_exact(client: object, size: int, deadline: _Deadline) -> bytes:
        remaining = size
        pieces: list[bytes] = []
        while remaining:
            client.settimeout(deadline.remaining())
            piece = client.recv(remaining)
            if type(piece) is not bytes or not piece or len(piece) > remaining:
                raise OSError("truncated executor response")
            pieces.append(piece)
            remaining -= len(piece)
        return b"".join(pieces)


__all__ = (
    "ExecutorTransportUnavailableError",
    "PRODUCTION_EXECUTOR_SOCKET_PATH",
    "TRANSPORT_UNAVAILABLE_MESSAGE",
    "UnixExecutorTransport",
)

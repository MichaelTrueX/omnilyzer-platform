"""Inert boundary for one accept on an already-bound executor listener.

Import and construction create no socket and perform no filesystem or listener
operation.  A future separately reviewed installation layer must create and
own the production Unix socket before supplying it to this boundary.
"""

from __future__ import annotations

import math
import os
import socket
import stat
import threading
import time
import types
from typing import Any, Callable


PRODUCTION_EXECUTOR_SOCKET_PATH = "/run/omnilyzer/deployment/executor.sock"
EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE = "executor listener is unavailable"
MAX_ACCEPT_TIMEOUT_MS = 3000
MAX_IDENTITY_VALUE = 2**32 - 2
_MAX_PROC_UNIX_BYTES = 1024 * 1024


class ExecutorListenerUnavailableError(Exception):
    """The bound listener could not accept one connection trustworthily."""


def _make_serving_gate() -> tuple[
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


_ENTER_SERVING, _LEAVE_SERVING = _make_serving_gate()


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
            raise OSError("invalid listener deadline")

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
            raise TimeoutError("listener deadline elapsed")
        return remaining


def _configuration_integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_IDENTITY_VALUE:
        raise TypeError("executor listener configuration is invalid")
    return value


def _ordinary_method(
    dependency: object, name: str, positional: tuple[str, ...],
) -> Callable[..., Any]:
    if dependency is None:
        raise TypeError("executor listener configuration is invalid")
    cls = type(dependency)
    try:
        hierarchy = type.__getattribute__(cls, "__mro__")
    except (AttributeError, TypeError):
        raise TypeError("executor listener configuration is invalid") from None
    descriptor: object | None = None
    for base in hierarchy:
        namespace = type.__getattribute__(base, "__dict__")
        if name in namespace:
            descriptor = namespace[name]
            break
    if type(descriptor) is not types.FunctionType:
        raise TypeError("executor listener configuration is invalid")
    code = descriptor.__code__
    disallowed = 0x04 | 0x08 | 0x20 | 0x80 | 0x100 | 0x200
    if (
        code.co_posonlyargcount != 0
        or code.co_argcount != len(positional) + 1
        or code.co_kwonlyargcount != 0
        or tuple(code.co_varnames[1:code.co_argcount]) != positional
        or code.co_flags & disallowed
        or descriptor.__defaults__ is not None
        or descriptor.__kwdefaults__ is not None
    ):
        raise TypeError("executor listener configuration is invalid")
    return types.MethodType(descriptor, dependency)


def _listener_operations(listener: object) -> tuple[Callable[..., Any], ...]:
    names = (
        ("get_inheritable", ()), ("getsockopt", ("level", "option")),
        ("getsockname", ()), ("fileno", ()), ("gettimeout", ()),
        ("settimeout", ("value",)), ("accept", ()),
    )
    if type(listener) is socket.socket:
        try:
            operations = tuple(object.__getattribute__(listener, name) for name, _ in names)
        except (AttributeError, TypeError):
            raise TypeError("executor listener configuration is invalid") from None
        if not all(callable(operation) for operation in operations):
            raise TypeError("executor listener configuration is invalid")
        return operations
    return tuple(_ordinary_method(listener, name, arguments) for name, arguments in names)


def _handler_operation(handler: object) -> Callable[[object], object]:
    return _ordinary_method(handler, "handle", ("connection",))


def _metadata_values(
    info: object, stat_result_type: type[os.stat_result] = os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    if type(info) is not stat_result_type or tuple.__len__(info) < 6:
        raise OSError("invalid listener metadata")
    values = tuple(tuple.__getitem__(info, index) for index in range(6))
    if not all(type(value) is int for value in values):
        raise OSError("invalid listener metadata")
    mode, inode, device, links, uid, gid = values
    if inode < 0 or device < 0 or links < 1 or uid < 0 or gid < 0:
        raise OSError("invalid listener metadata")
    return mode, inode, device, links, uid, gid


def _path_snapshot(
    checked_call: Callable[..., Any], deadline: _Deadline,
    lstat: Callable[[str], object], owner_uid: int, group_gid: int,
    path: str, ancestors: tuple[str, ...],
    metadata_values: Callable[[object], tuple[int, int, int, int, int, int]],
    is_directory: Callable[[int], bool], is_symlink: Callable[[int], bool],
    is_socket: Callable[[int], bool], file_mode: Callable[[int], int],
) -> tuple[tuple[int, int], ...]:
    identities: list[tuple[int, int]] = []
    for ancestor in ancestors:
        mode, inode, device, _links, _uid, _gid = metadata_values(
            checked_call(deadline, lstat, ancestor),
        )
        if not is_directory(mode) or is_symlink(mode):
            raise OSError("unsafe listener ancestor")
        identities.append((device, inode))
    mode, inode, device, links, uid, gid = metadata_values(
        checked_call(deadline, lstat, path),
    )
    if (
        not is_socket(mode)
        or is_symlink(mode)
        or file_mode(mode) != 0o660
        or links != 1
        or uid != owner_uid
        or gid != group_gid
    ):
        raise OSError("invalid listener socket path")
    identities.append((device, inode))
    return tuple(identities)


def _checked_call(
    deadline: _Deadline, operation: Callable[..., Any], *arguments: object,
) -> Any:
    deadline.remaining()
    result = operation(*arguments)
    deadline.remaining()
    return result


def _timeout_value(
    value: object, isfinite: Callable[[object], bool] = math.isfinite,
) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or not isfinite(value) or value < 0:
        raise OSError("invalid listener timeout state")
    return float(value)


def _read_proc_unix(
    path: str, opener: Callable[..., Any] = open,
    maximum: int = _MAX_PROC_UNIX_BYTES,
) -> bytes:
    with opener(path, "rb", buffering=0) as stream:
        value = stream.read(maximum + 1)
    if type(value) is not bytes or len(value) > maximum:
        raise OSError("invalid Unix socket inventory")
    return value


def _require_proc_binding(value: object, descriptor_inode: int, path: str) -> None:
    if type(value) is not bytes:
        raise OSError("invalid Unix socket inventory")
    try:
        lines = value.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise OSError("invalid Unix socket inventory") from None
    path_inodes: list[int] = []
    for line in lines[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) != 8:
            continue
        try:
            inode = int(fields[6], 10)
        except ValueError:
            continue
        if (
            fields[7] == path
            and fields[3] == "00010000"
            and fields[4] == "0001"
            and fields[5] == "01"
        ):
            path_inodes.append(inode)
    if path_inodes != [descriptor_inode]:
        raise OSError("listener descriptor binding is unavailable")


def _accepted_close(
    connection: object, socket_type: type[socket.socket],
    socket_close: Callable[[socket.socket], object],
    ordinary_method: Callable[..., Callable[..., Any]],
) -> Callable[[], object]:
    if isinstance(connection, socket_type):
        return lambda: socket_close(connection)
    try:
        return ordinary_method(connection, "close", ())
    except TypeError:
        raise OSError("invalid accepted connection") from None


def _require_socket(connection: object, socket_type: type[socket.socket]) -> None:
    if type(connection) is not socket_type:
        raise OSError("invalid accepted connection")


def _validate_listener(
    *, deadline: _Deadline, checked_call: Callable[..., Any],
    get_inheritable: Callable[[], object], getsockopt: Callable[[int, int], object],
    getsockname: Callable[[], object], fileno: Callable[[], object],
    lstat: Callable[[str], object], fstat: Callable[[int], object],
    owner_uid: int, group_gid: int, sol_socket: int, so_domain: int | None,
    so_type: int, so_acceptconn: int | None, af_unix: int, sock_stream: int,
    path: str, ancestors: tuple[str, ...],
    metadata_values: Callable[[object], tuple[int, int, int, int, int, int]],
    path_snapshot: Callable[..., tuple[tuple[int, int], ...]],
    is_directory: Callable[[int], bool], is_symlink: Callable[[int], bool],
    is_socket: Callable[[int], bool], file_mode: Callable[[int], int],
    proc_path: str, read_proc_unix: Callable[[str], object],
    require_proc_binding: Callable[[object, int, str], None],
) -> tuple[tuple[int, int], ...]:
    if so_domain is None or so_acceptconn is None:
        raise OSError("required Linux listener controls unavailable")
    if checked_call(deadline, get_inheritable) is not False:
        raise OSError("inheritable listener")
    domain = checked_call(deadline, getsockopt, sol_socket, so_domain)
    kind = checked_call(deadline, getsockopt, sol_socket, so_type)
    accepting = checked_call(deadline, getsockopt, sol_socket, so_acceptconn)
    if (
        type(domain) is not int or domain != af_unix
        or type(kind) is not int or kind != sock_stream
        or type(accepting) is not int or accepting != 1
    ):
        raise OSError("invalid listener descriptor")
    name = checked_call(deadline, getsockname)
    descriptor = checked_call(deadline, fileno)
    if type(name) is not str or str.__ne__(name, path):
        raise OSError("wrong listener path")
    if type(descriptor) is not int or descriptor < 0:
        raise OSError("invalid listener descriptor")
    descriptor_mode, descriptor_inode, descriptor_device, *_ = metadata_values(
        checked_call(deadline, fstat, descriptor),
    )
    if not is_socket(descriptor_mode):
        raise OSError("listener descriptor is not a socket")
    proc_value = checked_call(deadline, read_proc_unix, proc_path)
    require_proc_binding(proc_value, descriptor_inode, path)
    deadline.remaining()
    snapshot = path_snapshot(
        checked_call, deadline, lstat, owner_uid, group_gid, path, ancestors,
        metadata_values, is_directory, is_symlink, is_socket, file_mode,
    )
    return ((descriptor_device, descriptor_inode),) + snapshot


class UnixExecutorListener:
    """Validate an existing listener and accept at most one connection."""

    __slots__ = ("_configuration",)

    def __init__(
        self, *, listener: object, handler: object,
        expected_socket_owner_uid: int, expected_socket_group_gid: int,
        accept_timeout_ms: int = 3000,
    ) -> None:
        operations = _listener_operations(listener)
        handle = _handler_operation(handler)
        owner_uid = _configuration_integer(expected_socket_owner_uid)
        group_gid = _configuration_integer(expected_socket_group_gid)
        if (
            type(accept_timeout_ms) is not int
            or not 1 <= accept_timeout_ms <= MAX_ACCEPT_TIMEOUT_MS
        ):
            raise TypeError("executor listener configuration is invalid")
        object.__setattr__(self, "_configuration", (
            operations, handle, owner_uid, group_gid, accept_timeout_ms,
            os.lstat, os.fstat, time.monotonic, _Deadline, _checked_call,
            _validate_listener, _accepted_close, _require_socket, _timeout_value,
            _metadata_values, _path_snapshot, stat.S_ISDIR, stat.S_ISLNK,
            stat.S_ISSOCK, stat.S_IMODE, socket.socket, socket.socket.close,
            _ordinary_method, _read_proc_unix, _require_proc_binding,
            "/proc/self/net/unix",
            "/run/omnilyzer/deployment/executor.sock",
            ("/", "/run", "/run/omnilyzer", "/run/omnilyzer/deployment"),
            socket.AF_UNIX, socket.SOCK_STREAM, socket.SOL_SOCKET,
            getattr(socket, "SO_DOMAIN", None), socket.SO_TYPE,
            getattr(socket, "SO_ACCEPTCONN", None),
            _ENTER_SERVING, _LEAVE_SERVING,
            ExecutorListenerUnavailableError, EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE,
        ))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("executor listener configuration is immutable")

    def serve_once(self) -> None:
        (
            operations, handle, owner_uid, group_gid, timeout_ms,
            lstat, fstat, monotonic, deadline_factory, checked_call,
            validate_listener, accepted_close, require_socket, timeout_value,
            metadata_values, path_snapshot, is_directory, is_symlink,
            is_socket, file_mode, socket_type, socket_close, ordinary_method,
            read_proc_unix, require_proc_binding, proc_path, path, ancestors,
            af_unix, sock_stream, sol_socket, so_domain, so_type, so_acceptconn,
            enter_serving, leave_serving, error_type, error_message,
        ) = object.__getattribute__(self, "_configuration")
        (
            get_inheritable, getsockopt, getsockname, fileno, gettimeout,
            settimeout, accept,
        ) = operations

        entered = False
        timeout_attempted = False
        original_timeout: float | None = None
        connection: object | None = None
        close_connection: Callable[[], object] | None = None
        dispatched = False
        completed = False
        failed = False
        control: tuple[BaseException, object] | None = None
        deadline: _Deadline | None = None

        try:
            entered = enter_serving(self)
            if not entered:
                raise OSError("executor listener is already active")
            deadline = deadline_factory(monotonic, timeout_ms)
            original_timeout = timeout_value(checked_call(deadline, gettimeout))
            before = validate_listener(
                deadline=deadline, checked_call=checked_call,
                get_inheritable=get_inheritable, getsockopt=getsockopt,
                getsockname=getsockname, fileno=fileno, lstat=lstat, fstat=fstat,
                owner_uid=owner_uid, group_gid=group_gid, sol_socket=sol_socket,
                so_domain=so_domain, so_type=so_type, so_acceptconn=so_acceptconn,
                af_unix=af_unix, sock_stream=sock_stream,
                path=path, ancestors=ancestors, metadata_values=metadata_values,
                path_snapshot=path_snapshot, is_directory=is_directory,
                is_symlink=is_symlink, is_socket=is_socket, file_mode=file_mode,
                proc_path=proc_path, read_proc_unix=read_proc_unix,
                require_proc_binding=require_proc_binding,
            )
            timeout_attempted = True
            if settimeout(deadline.remaining()) is not None:
                raise OSError("listener timeout update failed")
            deadline.remaining()
            accepted = accept()
            accepted_length = -1
            if isinstance(accepted, tuple):
                accepted_length = tuple.__len__(accepted)
                if accepted_length:
                    connection = tuple.__getitem__(accepted, 0)
            elif isinstance(accepted, list):
                accepted_length = list.__len__(accepted)
                if accepted_length:
                    connection = list.__getitem__(accepted, 0)
            if connection is not None:
                close_connection = accepted_close(
                    connection, socket_type, socket_close, ordinary_method,
                )
            deadline.remaining()
            if type(accepted) is not tuple or accepted_length != 2:
                raise OSError("invalid accept result")
            require_socket(connection, socket_type)
            address = tuple.__getitem__(accepted, 1)
            if type(address) is not str or str.__ne__(address, ""):
                raise OSError("invalid accepted address")
            after = validate_listener(
                deadline=deadline, checked_call=checked_call,
                get_inheritable=get_inheritable, getsockopt=getsockopt,
                getsockname=getsockname, fileno=fileno, lstat=lstat, fstat=fstat,
                owner_uid=owner_uid, group_gid=group_gid, sol_socket=sol_socket,
                so_domain=so_domain, so_type=so_type, so_acceptconn=so_acceptconn,
                af_unix=af_unix, sock_stream=sock_stream,
                path=path, ancestors=ancestors, metadata_values=metadata_values,
                path_snapshot=path_snapshot, is_directory=is_directory,
                is_symlink=is_symlink, is_socket=is_socket, file_mode=file_mode,
                proc_path=proc_path, read_proc_unix=read_proc_unix,
                require_proc_binding=require_proc_binding,
            )
            if type(before) is not tuple or type(after) is not tuple or before != after:
                raise OSError("listener identity changed")
            if settimeout(original_timeout) is not None:
                raise OSError("listener timeout restoration failed")
            restored = timeout_value(gettimeout())
            deadline.remaining()
            if restored != original_timeout:
                raise OSError("listener timeout restoration failed")
            timeout_attempted = False
            dispatched = True
            if handle(connection) is not None:
                raise OSError("executor handler returned invalid result")
            completed = True
        except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
            control = (exc, exc.__traceback__)
        except BaseException:
            failed = True
        finally:
            if connection is not None and not dispatched and close_connection is not None:
                try:
                    close_connection()
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except BaseException:
                    failed = True
            if timeout_attempted:
                if deadline is not None:
                    try:
                        deadline.remaining()
                    except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                        if control is None:
                            control = (exc, exc.__traceback__)
                    except BaseException:
                        failed = True
                try:
                    if settimeout(original_timeout) is not None:
                        failed = True
                    restored = timeout_value(gettimeout())
                    if restored != original_timeout:
                        failed = True
                except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                    if control is None:
                        control = (exc, exc.__traceback__)
                except BaseException:
                    failed = True
                if deadline is not None:
                    try:
                        deadline.remaining()
                    except (KeyboardInterrupt, SystemExit, GeneratorExit) as exc:
                        if control is None:
                            control = (exc, exc.__traceback__)
                    except BaseException:
                        failed = True
            if entered:
                leave_serving(self)

        if control is not None:
            error, traceback = control
            raise error.with_traceback(traceback)
        if failed or not completed:
            raise error_type(error_message) from None
        return None


__all__ = (
    "EXECUTOR_LISTENER_UNAVAILABLE_MESSAGE",
    "ExecutorListenerUnavailableError",
    "MAX_ACCEPT_TIMEOUT_MS",
    "PRODUCTION_EXECUTOR_SOCKET_PATH",
    "UnixExecutorListener",
)

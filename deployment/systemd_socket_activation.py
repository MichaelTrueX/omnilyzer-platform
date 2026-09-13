"""deployment/systemd_socket_activation.py — closed executor FD handoff.

This module provides the narrow handoff from future systemd socket activation
to C9's ``UnixExecutorListener`` and, later, C15's ``DevExecutorComposition``.
C13's host installation contract remains authoritative for the socket resource.
This module never creates, binds, or listens on a socket. Import is inert; only
explicit acquisition consumes systemd process state. No systemd asset is
created, installed, enabled, or started here.
"""

from __future__ import annotations

import os as _os
import re as _re
import socket as _socket


__all__ = (
    "ExecutorSocketActivationError",
    "acquire_systemd_executor_listener",
)

_ACTIVATION_ERROR = "executor socket activation is unavailable"
_ACTIVATION_VARIABLES = (
    "LISTEN_PID",
    "LISTEN_PIDFDID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
)
_DESCRIPTOR_NAME = "omnilyzer-executor"
_SYSTEMD_LISTEN_FDS_START = 3
_MISSING = object()
_POSITIVE_DECIMAL = _re.compile(r"[1-9][0-9]*\Z")


class ExecutorSocketActivationError(Exception):
    """The inherited executor listener could not be claimed trustworthily."""


def _consume_activation_environment() -> dict[str, object]:
    """Remove and return the one-shot systemd activation process state."""

    return {
        name: _os.environ.pop(name, _MISSING)
        for name in _ACTIVATION_VARIABLES
    }


def _positive_decimal(value: object) -> int:
    """Parse one exact canonical positive decimal built-in string."""

    if type(value) is not str or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise ValueError
    parsed = int(value)
    if parsed <= 0 or str(parsed) != value:
        raise ValueError
    return parsed


def _validate_pidfd_identity(raw_identity: object, process_id: int) -> None:
    """Verify an optional systemd PID-file-descriptor inode and close its FD."""

    expected_inode = _positive_decimal(raw_identity)
    pidfd_open = getattr(_os, "pidfd_open", None)
    if not callable(pidfd_open):
        raise OSError
    pidfd = pidfd_open(process_id, 0)
    if type(pidfd) is not int or pidfd < 0:
        raise OSError
    try:
        status = _os.fstat(pidfd)
        inode = status.st_ino
        if type(inode) is not int or inode <= 0 or inode != expected_inode:
            raise OSError
    finally:
        _os.close(pidfd)


def _close_failed_listener(listener: object) -> None:
    """Close exactly once a listener claimed by an unsuccessful handoff."""

    try:
        listener.close()  # type: ignore[attr-defined]
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        pass


def acquire_systemd_executor_listener() -> _socket.socket:
    """Claim systemd's sole named FD 3 during early single-threaded bootstrap.

    The activation environment is process-global and is consumed on every
    attempt, so callers must invoke this once before application-created threads
    exist. On success, the caller owns the returned non-inheritable listener.
    """

    try:
        activation = _consume_activation_environment()
        process_id = _os.getpid()
        if type(process_id) is not int or process_id <= 0:
            raise ValueError
        if _positive_decimal(activation["LISTEN_PID"]) != process_id:
            raise ValueError
        if type(activation["LISTEN_FDS"]) is not str or activation["LISTEN_FDS"] != "1":
            raise ValueError
        if (
            type(activation["LISTEN_FDNAMES"]) is not str
            or activation["LISTEN_FDNAMES"] != _DESCRIPTOR_NAME
        ):
            raise ValueError
        pidfd_identity = activation["LISTEN_PIDFDID"]
        if pidfd_identity is not _MISSING:
            _validate_pidfd_identity(pidfd_identity, process_id)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise ExecutorSocketActivationError(_ACTIVATION_ERROR) from None

    try:
        listener = _socket.socket(fileno=_SYSTEMD_LISTEN_FDS_START)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise ExecutorSocketActivationError(_ACTIVATION_ERROR) from None

    try:
        listener.set_inheritable(False)
        if listener.get_inheritable() is not False:
            raise OSError
        descriptor = listener.fileno()
        if type(descriptor) is not int or descriptor != _SYSTEMD_LISTEN_FDS_START:
            raise OSError
        return listener
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        _close_failed_listener(listener)
        raise
    except Exception:
        _close_failed_listener(listener)
        raise ExecutorSocketActivationError(_ACTIVATION_ERROR) from None

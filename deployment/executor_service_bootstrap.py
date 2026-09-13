"""deployment/executor_service_bootstrap.py — inert C19 DEV service bridge.

Purpose: connect one C18 hardened configuration load, C17's existing C15
projection, one C16 inherited-listener acquisition, and one C15 executor
composition/``serve_once`` invocation. Import is inert. No systemd asset is
installed or started, and no socket is created, bound, or placed into listening
state. The explicit entrypoint handles at most one C15 ``serve_once`` call and
closes the inherited listener before returning. No deployment authority is
automatically activated.
"""

from __future__ import annotations

import datetime as _datetime

from .executor_composition import DevExecutorComposition as _DevExecutorComposition
from .executor_service_config import (
    DevExecutorServiceConfiguration as _DevExecutorServiceConfiguration,
)
from .executor_service_config_loader import (
    load_dev_executor_service_configuration as _load_configuration,
)
from .systemd_socket_activation import (
    acquire_systemd_executor_listener as _acquire_listener,
)


__all__ = (
    "ExecutorServiceBootstrapError",
    "run_dev_executor_service_once",
)

_ERROR = "DEV executor service bootstrap is unavailable"
_CONTROL_EXCEPTIONS = (KeyboardInterrupt, SystemExit, GeneratorExit)


class ExecutorServiceBootstrapError(Exception):
    """One explicit DEV executor service bootstrap attempt failed."""


def _utc_audit_clock() -> str:
    """Return the fixed second-precision UTC timestamp used below C15."""

    return (
        _datetime.datetime.now(_datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _close_listener(listener: object) -> tuple[bool, BaseException | None]:
    """Attempt one listener close and report ordinary or control-flow failure."""

    try:
        result = listener.close()  # type: ignore[attr-defined]
    except _CONTROL_EXCEPTIONS as exc:
        return False, exc
    except Exception:
        return True, None
    return result is not None, None


def run_dev_executor_service_once() -> None:
    """Load, compose, and serve at most one inherited-listener connection."""

    listener: object | None = None
    owns_listener = False
    try:
        configuration = _load_configuration()
        if type(configuration) is not _DevExecutorServiceConfiguration:
            raise TypeError
        projection = configuration.executor_composition_kwargs()
        if (
            type(projection) is not dict
            or "listener" in projection
            or "clock" in projection
        ):
            raise TypeError
        listener = _acquire_listener()
        owns_listener = True
        composition = _DevExecutorComposition(
            listener=listener,
            clock=_utc_audit_clock,
            **projection,
        )
        if composition.serve_once() is not None:
            raise TypeError
    except _CONTROL_EXCEPTIONS:
        if owns_listener:
            _close_listener(listener)
        raise
    except Exception:
        cleanup_control: BaseException | None = None
        if owns_listener:
            _cleanup_failed, cleanup_control = _close_listener(listener)
        if cleanup_control is not None:
            raise cleanup_control
        raise ExecutorServiceBootstrapError(_ERROR) from None

    cleanup_failed, cleanup_control = _close_listener(listener)
    if cleanup_control is not None:
        raise cleanup_control
    if cleanup_failed:
        raise ExecutorServiceBootstrapError(_ERROR) from None

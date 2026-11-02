"""File: deployment/analytics_executor_service_bootstrap.py

Purpose: A single, explicitly owner-installed Task014 Analytics systemd socket
         activation using existing original C17 root-owned authorization,
         actual source hashes and original executor composition.
Related: deployment/analytics_executor_service_config.py,
         deployment/systemd_socket_activation.py (original inherited fd logic),
         deployment/analytics_executor_composition.py,
         deployment/analytics_executor_service_entrypoint.py,
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.socket,
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service,
         deployment/tests/test_analytics_executor_service_bootstrap.py.

Sections: fixed named systemd FD acquisition; single-source installation
          admission; original one-accept service composition and FD cleanup.

SECURITY: Import/construction are inert. The root-owned installed config and
all exact product source SHA hashes MUST pass before touching LISTEN_FDS.
No HTTP client, unsigned review receipt or caller-supplied source mapping can
start this service. A valid service configuration does not approve a GitHub
promotion; original broker OIDC, real signature and replay remain mandatory.
"""
from __future__ import annotations

import os
import socket
import sys

from .analytics_executor_composition import AnalyticsExecutorComposition
from .analytics_executor_service_config import load_analytics_executor_service_config
from .systemd_socket_activation import (
    _consume_activation_environment, _positive_decimal,
    _validate_pidfd_identity, _MISSING,
)

_ERROR = "Task014 Analytics executor service is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_NAMED_SOCKET = "omnilyzer-analytics-executor"


class AnalyticsExecutorBootstrapError(Exception):
    """A redacted, closed Analytics DEV socket-activated start failure."""


def _acquire_analytics_systemd_socket() -> socket.socket:
    """Consume EXACT one systemd FD3 with Analytics-specific immutable name.

    Reuse the original Task014 process/PIDFD controls rather than creating
    another listener, binding a socket, or accepting the canary FD name.
    """
    try:
        env = _consume_activation_environment()
        pid = os.getpid()
        if (
            type(pid) is not int or pid <= 0
            or _positive_decimal(env["LISTEN_PID"]) != pid
            or env["LISTEN_FDS"] != "1"
            or type(env["LISTEN_FDS"]) is not str
            or type(env["LISTEN_FDNAMES"]) is not str
            or env["LISTEN_FDNAMES"] != _NAMED_SOCKET
        ):
            raise ValueError
        if env["LISTEN_PIDFDID"] is not _MISSING:
            _validate_pidfd_identity(env["LISTEN_PIDFDID"], pid)
        listener = socket.socket(fileno=3)
        try:
            listener.set_inheritable(False)
            if listener.fileno() != 3 or listener.get_inheritable() is not False:
                raise ValueError
        except BaseException:
            listener.close()
            raise
        return listener
    except _CONTROL:
        raise
    except Exception:
        raise AnalyticsExecutorBootstrapError(_ERROR) from None


def run_analytics_executor_service_once() -> None:
    """Verify root-owned source first; then original private socket graph.

    Does not bind/open a second socket or start anything without one inherited
    FD from a separately authorized, installed systemd Analytics socket unit.
    """
    listener: socket.socket | None = None
    phase = "installed_source"
    try:
        source, identities = load_analytics_executor_service_config()
        if (
            type(source) is not dict or type(identities) is not dict
            or set(source) != {
                "reviewed_installed_commit", "reviewed_compose_sha256",
                "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
            }
        ):
            raise TypeError
        identity_keys = {
            "expected_replay_directory_uid", "expected_replay_directory_gid",
            "expected_broker_uid", "expected_broker_gid",
            "expected_executor_uid", "expected_executor_gid",
            "expected_socket_owner_uid", "expected_socket_group_gid",
        }
        if type(identities) is not dict or set(identities) != identity_keys:
            raise TypeError
        phase = "systemd_socket"
        listener = _acquire_analytics_systemd_socket()
        phase = "executor_composition"
        composition = AnalyticsExecutorComposition(
            listener=listener, reviewed_installed_source=source, **identities,
        )
        phase = "executor_once"
        if composition.serve_once() is not None:
            raise TypeError
    except _CONTROL:
        raise
    except Exception:
        # No untrusted source bytes, privilege IDs, token or registry data.
        sys.stderr.write(f"TASK014_ANALYTICS_BOOTSTRAP_DENIED phase={phase}\n")
        raise AnalyticsExecutorBootstrapError(_ERROR) from None
    finally:
        if listener is not None:
            listener.close()
    return None


__all__ = (
    "AnalyticsExecutorBootstrapError", "run_analytics_executor_service_once",
)

"""File: deployment/analytics_private_registry.py

Purpose: Product-specific original Task014 rootless Docker Zot read adapter
         for the one immutable signed Analytics 0.15.0 image. Uses original
         sealed Linux credential, mandatory original rootless socket/volatile
         Docker config, isolated original subprocess runner and bound request.
Related: deployment/analytics_executor.py (preflight before replay),
         deployment/analytics_unix_boundary.py (root-reviewed source inputs),
         deployment/private_registry_pull.py (original canary implementation),
         deployment/private_registry_fd.py (product-scoped sealed FD),
         deployment/docker_runtime.py (original rootless authority and runner),
         deployment/tests/test_analytics_private_registry.py.

Sections: constructor/source capture, read-only manifest preflight, scoped
          private pull and exact local digest verification.

SECURITY: Inert at import/constructor; only explicit methods execute Docker.
Does not install a product, activate Compose, provision secrets, change a DB or
route public traffic. Unapproved host rootless socket fails closed. Token is
never in argv/env/audit and is only temporarily in a 0600 Docker config inside
a 0700 volatile runtime directory, removed on all paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import time

from .analytics_execution import (
    AnalyticsExecutorRequest, parse_analytics_request,
)
from .analytics_signed_release_consumer import PINNED_IMAGE
from .analytics_unix_boundary import _root_reviewed_source
from .docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, CommandResult, WORKING_DIRECTORY,
    _candidate_command_run, _require_rootless_socket,
)
from .private_registry_fd import read_sealed_credential
from .private_registry_pull import (
    MIN_POST_PREFLIGHT_VALIDITY_SECONDS, MIN_VALIDITY_SECONDS,
    PRIVATE_PULL_TIMEOUT_SECONDS, PROBE, PULL,
    _command, _private_runtime_directory, _write_config,
    current_private_zot_request,
)

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
ERROR = "Analytics private Zot read is unavailable"


class AnalyticsPrivateRegistryError(Exception):
    """Redacted product-only private image read or pull failure."""


class AnalyticsPrivateZotPullAdapter:
    """One exact Analytics OCI image, rootless Docker only, no canary scope."""

    __slots__ = ("_runner", "_source")

    def __init__(
        self, runner: object, *, reviewed_installed_source: dict[str, str],
    ) -> None:
        """Capture original closed runner and independently reviewed sources."""
        try:
            bound = _candidate_command_run(runner)
            source = _root_reviewed_source(reviewed_installed_source)
            object.__setattr__(self, "_runner", bound)
            object.__setattr__(self, "_source", source)
        except _CONTROL:
            raise
        except Exception:
            raise TypeError(ERROR) from None

    def __setattr__(self, name: str, value: object) -> None:
        """Reject late substitution of runner or reviewed immutable image."""
        raise AttributeError("Analytics registry adapter is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject removal of original rootless runtime authority."""
        raise AttributeError("Analytics registry adapter is immutable")

    def _reviewed_request(self, raw: bytes) -> AnalyticsExecutorRequest:
        """Accept only canonical signed-0.15.0-shaped request bytes."""
        request = parse_analytics_request(
            raw, **dict(object.__getattribute__(self, "_source")),
        )
        if request.exact_image_reference != PINNED_IMAGE:
            raise AnalyticsPrivateRegistryError(ERROR)
        return request

    def _run_private(self, raw: bytes, credential_fd: int, operation: str) -> None:
        """Use original rootless/volatile Docker controls and sealed scoped FD."""
        phase = "request_validation"
        try:
            if type(operation) is not str or operation not in (PROBE, PULL):
                raise ValueError("unreviewed private operation")
            self._reviewed_request(raw)
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=raw, image=PINNED_IMAGE,
                product_id="analytics", now=now,
            )
            threshold = (
                MIN_POST_PREFLIGHT_VALIDITY_SECONDS
                if operation == PROBE else MIN_VALIDITY_SECONDS
            )
            if credential.expires_at - now < threshold:
                raise ValueError("private credential budget too short")

            phase = "runtime_directory"
            directory = _private_runtime_directory()
            phase = "rootless_socket"
            _require_rootless_socket()
            with tempfile.TemporaryDirectory(
                prefix=".analytics-zot-read-", dir=str(directory),
            ) as temporary:
                workspace = Path(temporary)
                os.chmod(workspace, 0o700)
                phase = "volatile_config"
                _write_config(workspace, credential.token)
                argv = _command(workspace, PINNED_IMAGE, operation)
                phase = "docker_command"
                output = object.__getattribute__(self, "_runner")(
                    argv, cwd=WORKING_DIRECTORY,
                    environment={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "ANALYTICS_IMAGE": PINNED_IMAGE,
                        "HOME": str(workspace),
                    },
                    timeout=(
                        PRIVATE_PULL_TIMEOUT_SECONDS
                        if operation == PULL else COMMAND_TIMEOUT_SECONDS
                    ),
                )
                if (
                    type(output) is not CommandResult
                    or type(output.returncode) is not int
                    or output.returncode != 0
                ):
                    raise ValueError("private Docker operation unsuccessful")
        except _CONTROL:
            raise
        except Exception:
            sys.stderr.write(
                "TASK014_ANALYTICS_ZOT_DENIED "
                + ("operation=manifest" if operation == PROBE else
                   "operation=pull" if operation == PULL else "operation=invalid")
                + f" phase={phase}\n"
            )
            raise AnalyticsPrivateRegistryError(ERROR) from None

    def preflight_analytics(
        self, canonical_request: bytes, credential_fd: int,
    ) -> None:
        """Authenticated manifest inspection before executor replay begins."""
        self._run_private(canonical_request, credential_fd, PROBE)

    def pull_analytics(self, request: AnalyticsExecutorRequest) -> None:
        """Pull exact digest via the original executor's short-lived FD scope."""
        try:
            if type(request) is not AnalyticsExecutorRequest:
                raise ValueError("incorrect product request type")
            raw = request.canonical_bytes()
            self._reviewed_request(raw)
            scoped = current_private_zot_request()
            if type(scoped) is not tuple or len(scoped) != 2:
                raise ValueError("unsigned or unscoped Docker pull")
            credential_fd, canonical_request = scoped
            if canonical_request != raw:
                raise ValueError("request differs from broker-bound credential")
        except _CONTROL:
            raise
        except Exception:
            raise AnalyticsPrivateRegistryError(ERROR) from None
        self._run_private(raw, credential_fd, PULL)


__all__ = (
    "AnalyticsPrivateRegistryError", "AnalyticsPrivateZotPullAdapter",
)

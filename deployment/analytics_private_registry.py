"""File: deployment/analytics_private_registry.py

Purpose: Preserve original Task014 rootless Docker Zot read/pull
         adapter for immutable signed Analytics 0.15.0 and add a separate
         preflight-only exact schema-3 successor manifest inspection.
         The same sealed FD, volatile credential and rootless CLI rules apply.
Related: deployment/analytics_executor.py (preflight before replay),
         deployment/analytics_execution.py (successor request),
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
import math
import os
from pathlib import Path
import sys
import tempfile
import time

from .analytics_execution import (
    AnalyticsExecutorRequest, AnalyticsSuccessorRequest,
    parse_analytics_request,
)
from .analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
from .analytics_unix_boundary import _root_reviewed_source
from .docker_runtime import (
    COMMAND_TIMEOUT_SECONDS, CommandResult, WORKING_DIRECTORY,
    _candidate_command_run, _require_rootless_socket,
)
from .private_registry_fd import (
    _successor_request_image, read_sealed_credential,
)
from .private_registry_pull import (
    MIN_POST_PREFLIGHT_VALIDITY_SECONDS, MIN_VALIDITY_SECONDS,
    PROBE, PULL,
    _command, _private_runtime_directory, _write_config,
    current_private_zot_request,
)

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
ERROR = "Analytics private Zot read is unavailable"
# Analytics' cold image can outlive the original Canary pull window. This
# bounds one already-admitted operation, not the OIDC/FD credential lifetime.
# Zot still rejects every new HTTP request whose token has expired.
# The225s preflight threshold remains a fresh-admission requirement here;
# unlike Canary's180s path it is not a promise of whole-pull JWT validity.
ANALYTICS_PULL_TIMEOUT_SECONDS = 500.0


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

    def _run_private(
        self, raw: bytes, credential_fd: int, operation: str,
        *, pull_timeout: float = ANALYTICS_PULL_TIMEOUT_SECONDS,
        successor_preflight: bool = False,
        successor_pull: bool = False,
    ) -> None:
        """Reuse original rootless Docker read, exact FD and bounded cleanup.

        Original Analytics V1 remains pinned to its reviewed OCI. Successor
        PROBE is read-only; the explicit successor PULL is separately gated
        by a fixed-UID, root-trusted Ed25519 source check and by the original
        sealed, task-local Zot request FD. Neither successor method is wired
        into the active schema-2 executor or permitted to start a container.
        """
        phase = "request_validation"
        try:
            if type(operation) is not str or operation not in (PROBE, PULL):
                raise ValueError("unreviewed private operation")
            if (type(pull_timeout) is not float or not math.isfinite(pull_timeout)
                    or not 0 < pull_timeout <= ANALYTICS_PULL_TIMEOUT_SECONDS):
                raise ValueError("invalid bounded Analytics pull duration")
            if (
                type(successor_preflight) is not bool
                or type(successor_pull) is not bool
                or (successor_preflight and successor_pull)
            ):
                raise ValueError("invalid successor mode")
            if successor_preflight or successor_pull:
                if ((successor_preflight and operation != PROBE)
                        or (successor_pull and operation != PULL)):
                    raise ValueError("wrong successor Docker operation")
                if successor_pull and (
                    os.getuid() != 991 or os.geteuid() != 991
                    or os.getgid() != 991 or os.getegid() != 991
                ):
                    raise ValueError("not the original rootless product executor")
                image = _successor_request_image(raw)
                product_scope = "analytics-successor"
            else:
                self._reviewed_request(raw)
                image = PINNED_IMAGE
                product_scope = "analytics"
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=raw, image=image,
                product_id=product_scope, now=now,
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
                argv = _command(workspace, image, operation)
                phase = "docker_command"
                output = object.__getattribute__(self, "_runner")(
                    argv, cwd=WORKING_DIRECTORY,
                    environment={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "ANALYTICS_IMAGE": image,
                        "HOME": str(workspace),
                    },
                    timeout=(
                        pull_timeout
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

    def preflight_analytics_successor(
        self, canonical_request: bytes, credential_fd: int,
    ) -> None:
        """Probe immutable successor manifest with scoped FD, without deploy.

        This is a low-level read-only registry check. It does NOT prove
        Ed25519, OIDC, Sigstore/Cosign, active state or replay, and it cannot
        install, pull or switch any image. The installed executor does not
        invoke this method until separately reviewed successor integration.
        """
        self._run_private(
            canonical_request, credential_fd, PROBE, successor_preflight=True,
        )

    def pull_analytics_successor(
        self, request: AnalyticsSuccessorRequest,
        *, timeout: float = ANALYTICS_PULL_TIMEOUT_SECONDS,
    ) -> None:
        """Download the exact source-approved successor image, without running.

        This **uninstalled** future Task014 stage reuses the original volatile
        rootless Zot config, image-by-digest Docker pull and bounded cleanup.
        The parent executor must complete authenticated broker admission and
        durable replay before invocation; this method independently requires
        UID991, genuine root-trusted owner Ed25519 approval and one matching
        task-scoped successor FD. It never starts Compose, installs a service,
        switches a route or reports release acceptance.
        """
        try:
            if type(request) is not AnalyticsSuccessorRequest:
                raise ValueError("wrong release generation")
            if (
                os.getuid() != 991 or os.geteuid() != 991
                or os.getgid() != 991 or os.getegid() != 991
            ):
                raise ValueError("untrusted rootless product principal")
            raw = request.canonical_bytes()
            _successor_request_image(raw)
            from .analytics_executor import _verify_executor_owner_source
            from .analytics_active_state_review import (
                AnalyticsActiveState, inspect_analytics_active_state,
                verify_empty_analytics_successor_slot,
            )
            _verify_executor_owner_source(request.to_dict())
            # The first signed successor must be a genuine blue-0.15.0 to
            # green upgrade. Prevent pulling into an already active/ambiguous
            # or stale candidate. A missing 3142 route alone is insufficient.
            observed = inspect_analytics_active_state()
            if (
                type(observed) is not AnalyticsActiveState
                or observed.active_slot != "blue"
                or observed.active_image != PINNED_IMAGE
                or observed.active_digest != PINNED_DIGEST
                or observed.private_ingress_port != 3141
                or observed.candidate_slot != "green"
                or observed.candidate_port != 3142
                or observed.candidate_probe_present is not False
                or observed.candidate_digest is not None
                or observed.candidate_container_id is not None
                or observed.deployment_authorized is not False
                or observed.read_only is not True
            ):
                raise ValueError("unreviewed previous product release")
            verify_empty_analytics_successor_slot()
            scoped = current_private_zot_request()
            if type(scoped) is not tuple or len(scoped) != 2:
                raise ValueError("missing scoped successor credential")
            credential_fd, original = scoped
            if original != raw:
                raise ValueError("successor request differs from scoped FD")
        except _CONTROL:
            raise
        except Exception:
            raise AnalyticsPrivateRegistryError(ERROR) from None
        self._run_private(
            raw, credential_fd, PULL, pull_timeout=timeout,
            successor_pull=True,
        )
        # A pulled image does not authorize container start. Confirm the
        # original active writer and candidate absence did not drift during
        # the bounded pull, otherwise deny further staging/cutover.
        try:
            if inspect_analytics_active_state() != observed:
                raise ValueError("active Analytics changed during pull")
            verify_empty_analytics_successor_slot()
        except _CONTROL:
            raise
        except Exception:
            raise AnalyticsPrivateRegistryError(ERROR) from None

    def pull_analytics(
        self, request: AnalyticsExecutorRequest,
        *, timeout: float = ANALYTICS_PULL_TIMEOUT_SECONDS,
    ) -> None:
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
        self._run_private(raw, credential_fd, PULL, pull_timeout=timeout)


__all__ = (
    "AnalyticsPrivateRegistryError", "AnalyticsPrivateZotPullAdapter",
)

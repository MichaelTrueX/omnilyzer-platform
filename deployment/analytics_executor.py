"""File: deployment/analytics_executor.py

Purpose: Closed Analytics-only Task014 private executor boundary for the signed
         0.15.0 first-install request; independently reparses request and sealed
         Zot FD, performs authenticated immutable-image preflight and full
         pull-time-budget check, then original durable replay begin/finish.
Related: deployment/analytics_execution.py (exact reviewed request grammar),
         deployment/private_registry_fd.py (original sealed Linux credential),
         deployment/executor_server.py (SO_PEERCRED and SCM_RIGHTS handler),
         deployment/executor.py (original response and replay primitives),
         deployment/analytics_promotion_broker.py (caller, not a trust anchor),
         deployment/tests/test_analytics_executor.py.

Sections: root-reviewed input capture, exact FD+request preflight, original
          replay transitions and protected product-only operation.

NOT A DEPLOYMENT: This class is not installed in the Task014 application
source set; no host listener, rootless runtime, secret, DB, Docker or release
promotion is activated. A future root-owned installation MUST bind operation
and preflight to the reviewed immutable Analytics runtime, not test mocks.
A public constructible request or signed-review dataclass is never accepted
as an authorization token.
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import Any

from .analytics_execution import (
    AnalyticsExecutorRequest, AnalyticsRequestError,
    parse_analytics_request,
)
from .analytics_signed_release_consumer import PINNED_IMAGE
from .executor import (
    EXECUTOR_REJECTED_MESSAGE, EXECUTOR_UNAVAILABLE_MESSAGE,
    ExecutorRejectedError, ExecutorUnavailableError, _ordinary_bound_method,
    _build_success_response, _ENTER_EXECUTION, _LEAVE_EXECUTION,
)
from .identity import ReplayError, ReplayUnavailableError
from .private_registry_fd import read_sealed_credential
from .private_registry_pull import (
    MIN_POST_PREFLIGHT_VALIDITY_SECONDS, scoped_private_zot_request,
)
from .policy import validate_sha256, validate_source_sha


_SOURCE_FIELDS = frozenset({
    "reviewed_installed_commit", "reviewed_compose_sha256",
    "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
})
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsPrivilegedExecutor:
    """Exact first-install receiver; no generic or canary deployment method."""

    __slots__ = ("_replay", "_preflight", "_deploy", "_rollback",
                 "_reviewed_source")

    def __init__(
        self, *, replay_guard: object, private_registry_preflight: object,
        operation: object, reviewed_installed_source: dict[str, str],
    ) -> None:
        """Capture original replay functions and reviewed product callbacks.

        The four source authority values must originate in the protected
        installed host manifest/profile checks, never in the incoming request.
        This constructor does not itself prove root ownership or install.
        """
        try:
            if (
                type(reviewed_installed_source) is not dict
                or set(reviewed_installed_source) != _SOURCE_FIELDS
            ):
                raise ValueError("invalid source authority")
            source = dict(reviewed_installed_source)
            source["reviewed_installed_commit"] = validate_source_sha(
                source["reviewed_installed_commit"]
            )
            for name in _SOURCE_FIELDS - {"reviewed_installed_commit"}:
                source[name] = validate_sha256(source[name], name)
            preflight = _ordinary_bound_method(
                private_registry_preflight, "preflight_analytics",
                positional=("canonical_request", "credential_fd"),
            )
            deploy = _ordinary_bound_method(
                operation, "deploy_analytics", positional=("request",),
            )
            rollback = _ordinary_bound_method(
                operation, "rollback_first_analytics", positional=("request",),
            )
            replay = (
                _ordinary_bound_method(
                    replay_guard, "begin_execution", positional=("jti",),
                    keyword_only=("request_hash", "run_id", "run_attempt"),
                ),
                _ordinary_bound_method(
                    replay_guard, "finish_execution", positional=("jti",),
                    keyword_only=("request_hash", "run_id", "run_attempt"),
                ),
            )
            object.__setattr__(self, "_replay", replay)
            object.__setattr__(self, "_preflight", preflight)
            object.__setattr__(self, "_deploy", deploy)
            object.__setattr__(self, "_rollback", rollback)
            object.__setattr__(self, "_reviewed_source", tuple(sorted(source.items())))
        except _CONTROL:
            raise
        except Exception:
            raise TypeError("Analytics executor authority is invalid") from None

    def __setattr__(self, name: str, value: object) -> None:
        """Disallow mutation of captured privileged collaborators."""
        raise AttributeError("Analytics executor is immutable")

    def __delattr__(self, name: str) -> None:
        """Disallow deletion of captured privileged collaborators."""
        raise AttributeError("Analytics executor is immutable")

    def _stop_unfinished_first_install(self, request: AnalyticsExecutorRequest) -> None:
        """Fail safe after deployment or durable replay finalization failure."""
        try:
            if object.__getattribute__(self, "_rollback")(request) is not None:
                raise ValueError("invalid rollback outcome")
        except _CONTROL:
            raise
        except Exception:
            sys.stderr.write(
                "TASK014_ANALYTICS_EXECUTOR_UNAVAILABLE phase=rollback_unconfirmed\n"
            )

    def execute_private(
        self, canonical_request: bytes, *, credential_fd: int,
    ) -> bytes:
        """Recheck exact review, credential, preflight, TTL and durable replay.

        The sender is already authenticated by UnixExecutorConnectionHandler
        with Linux SO_PEERCRED; this function does not trust that check to
        substitute for its own request/FD/replay/operation validation.
        """
        if type(credential_fd) is not int or credential_fd < 0:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        try:
            request = parse_analytics_request(
                canonical_request,
                **dict(object.__getattribute__(self, "_reviewed_source")),
            )
            if (
                type(request) is not AnalyticsExecutorRequest
                or request.exact_image_reference != PINNED_IMAGE
            ):
                raise AnalyticsRequestError("invalid product request")
        except AnalyticsRequestError:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        try:
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=PINNED_IMAGE, product_id="analytics", now=now,
            )
            if credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS:
                raise ValueError("insufficient private pull lifetime")
            preflight = object.__getattribute__(self, "_preflight")
            if preflight(canonical_request, credential_fd) is not None:
                raise TypeError("invalid registry preflight outcome")
            # Recheck budget immediately after preflight, BEFORE replay begin.
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=PINNED_IMAGE, product_id="analytics", now=now,
            )
            if credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS:
                raise ValueError("credential expires before immutable pull")
        except _CONTROL:
            raise
        except Exception:
            # No untrusted host error, token or OCI text appears in response.
            sys.stderr.write(
                "TASK014_ANALYTICS_EXECUTOR_UNAVAILABLE phase=private_preflight\n"
            )
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        request_hash = hashlib.sha256(canonical_request).hexdigest()
        replay_begin, replay_finish = object.__getattribute__(self, "_replay")
        if not _ENTER_EXECUTION(self):
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
        try:
            try:
                begin = replay_begin(
                    request.oidc_jti, request_hash=request_hash,
                    run_id=request.github_run_id,
                    run_attempt=request.github_run_attempt,
                )
                if begin is not None:
                    raise ValueError("invalid replay begin")
            except ReplayError:
                raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
            except _CONTROL:
                raise
            except Exception:
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

            try:
                # Runtime operation is the explicit, root-bound Analytics
                # deployment and MUST preserve DB writes on rollback.
                # Reuse original Task014 task-local scoped FD; neither token
                # nor secret value appears in request, process argv, or logs.
                with scoped_private_zot_request(credential_fd, canonical_request):
                    result = object.__getattribute__(self, "_deploy")(request)
                if result is not None:
                    raise TypeError("invalid Analytics deployment result")
            except _CONTROL:
                self._stop_unfinished_first_install(request)
                raise
            except Exception:
                self._stop_unfinished_first_install(request)
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            try:
                finished = replay_finish(
                    request.oidc_jti, request_hash=request_hash,
                    run_id=request.github_run_id,
                    run_attempt=request.github_run_attempt,
                )
                if finished is not None:
                    raise TypeError("invalid replay finish")
            except _CONTROL:
                self._stop_unfinished_first_install(request)
                raise
            except Exception:
                self._stop_unfinished_first_install(request)
                raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
            return _build_success_response(request_hash)
        finally:
            _LEAVE_EXECUTION(self)


__all__ = ("AnalyticsPrivilegedExecutor",)

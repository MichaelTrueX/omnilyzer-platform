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

Sections: root-reviewed input capture, original FD+request execution, separate
          first-successor read-only live OCI/manifest proof, original replay
          transitions and protected product-only operation.

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
    ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
    parse_analytics_request,
)
from .analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
from .private_registry_fd import _successor_request_image
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

    __slots__ = ("_replay", "_preflight", "_preflight_successor",
                 "_deploy", "_rollback", "_reviewed_source")

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
            # Only the original product-specific Zot adapter provides this
            # additional manifest PROBE. Never synthesize a fallback that
            # could mistake original 0.15.0 authorization for a successor.
            try:
                successor_preflight = _ordinary_bound_method(
                    private_registry_preflight, "preflight_analytics_successor",
                    positional=("canonical_request", "credential_fd"),
                )
            except TypeError:
                successor_preflight = None
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
            object.__setattr__(self, "_preflight_successor", successor_preflight)
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

    def preflight_first_successor_without_deployment(
        self, canonical_request: bytes, *, credential_fd: int,
    ) -> None:
        """Read-only first-successor proof against the *actual* UID991 host.

        This is NOT an executable promotion receiver: it deliberately has no
        replay begin/finish, pull, OCI install, 3141 switch, rollback mutation
        or success response. The broker must independently authenticate OIDC,
        owner Ed25519 and signed release before future forwarding; a forged
        caller-constructible schema-3 JSON or this local result grants nothing.
        Exact sealed FD, local live OCI digest, private candidate 3142 and
        actual Zot manifest are rechecked by the restricted UID991 executor.
        """
        if type(credential_fd) is not int or credential_fd < 0:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        try:
            from .analytics_active_state_review import (
                AnalyticsActiveState, inspect_analytics_active_state,
            )
            # A root script may review host state independently but MUST NOT
            # use this executor method. Only the existing UID991 principal.
            if os.geteuid() != 991:
                raise ValueError("not the approved product executor")
            image = _successor_request_image(canonical_request)
            if image == PINNED_IMAGE:
                raise ValueError("same image cannot be a successor")
            import json

            def no_duplicates(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate request key")
                    value[key] = item
                return value

            parsed = json.loads(
                canonical_request.decode("ascii"), object_pairs_hook=no_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
            )
            observed = inspect_analytics_active_state()
            if (
                type(observed) is not AnalyticsActiveState
                or observed.read_only is not True
                or observed.deployment_authorized is not False
                or observed.active_slot != "blue"
                or observed.active_digest != PINNED_DIGEST
                or observed.active_image != PINNED_IMAGE
                or observed.private_ingress_port != 3141
                or observed.candidate_slot != "green"
                or observed.candidate_port != ANALYTICS_SUCCESSOR_CANDIDATE_PORT
                or observed.candidate_probe_present is not True
                or observed.candidate_digest != parsed["manifest_digest"]
                or type(observed.candidate_container_id) is not str
                or len(observed.candidate_container_id) != 64
                or parsed["rollback_reference"] != {
                    "kind": "switch-private-slot-preserve-writes",
                    "previous_digest": PINNED_DIGEST,
                    "previous_slot": "blue",
                    "preserve_database_writes": True,
                }
                or parsed["ingress_reference"] != {
                    "kind": "private-no-public-ingress",
                    "slot": "green", "loopback_address": "127.0.0.1",
                    "loopback_port": ANALYTICS_SUCCESSOR_CANDIDATE_PORT,
                    "backend_network": "omnilyzer-analytics-backend-dev",
                    "public_origin": None, "active_slot": "blue",
                }
            ):
                raise ValueError("independently observed OCI state does not match")
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=image, product_id="analytics-successor", now=now,
            )
            if credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS:
                raise ValueError("private registry credential TTL insufficient")
            preflight = object.__getattribute__(self, "_preflight_successor")
            if preflight is None or preflight(canonical_request, credential_fd) is not None:
                raise ValueError("no verified immutable successor manifest")
            # Reinspect the still-active signed 0.15.0 and the candidate
            # after the bounded remote registry read; reject any TOCTOU drift.
            if inspect_analytics_active_state() != observed:
                raise ValueError("host state changed during review")
            return None
        except _CONTROL:
            raise
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

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

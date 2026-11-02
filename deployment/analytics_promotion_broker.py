"""File: deployment/analytics_promotion_broker.py

Purpose: Original Task014 OIDC -> signed Analytics v1 release verification ->
         closed Analytics first-install request -> sealed Zot read credential ->
         durable replay -> private Analytics transport, never canary transport.
Related: deployment/analytics_registry_review_composition.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/analytics_execution.py, deployment/private_registry_fd.py,
         deployment/registry_oidc_credentials.py, deployment/broker.py,
         deployment/tests/test_analytics_promotion_broker.py.

Sections: root-controlled authority capture, verified signed input checks,
          exact Zot credential handoff, replay and bounded private transport.

NOT INSTALLED: This module is outside the original Task014 source set, and
no private Analytics executor receiver yet exists. A privileged deployment
must first verify the reviewed source set, SO_PEERCRED, exact request, sealed
credential, rootless runtime, secrets, PG roles and audited rollback. The public
review dataclasses and test mocks must never be deployment grants.
"""
from __future__ import annotations

import hashlib
import os
import time

from .analytics_execution import (
    AnalyticsRequestError, MAX_ANALYTICS_REQUEST_BYTES,
    bind_analytics_request_to_identity,
    bind_analytics_request_to_verified_evidence,
    parse_analytics_request,
)
from .analytics_registry_review_composition import InertAnalyticsSignedReleaseReviewHandler
from .analytics_signed_release_consumer import PINNED_IMAGE
from .broker import (
    BrokerRejectedError, BrokerUnavailableError, IDENTITY_FIELDS,
    MAX_EXECUTOR_RESPONSE_BYTES, REJECTED_MESSAGE, UNAVAILABLE_MESSAGE,
    _bound_operation, _normalize_identity,
)
from .identity import (
    OIDCAuthorizationError, ReplayError, authorize_verified_github_oidc,
    validate_expected_workflow_sha,
)
from .jwks import OIDCVerificationError, OIDCVerificationUnavailable
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES
from .private_registry_fd import create_sealed_credential
from .private_registry_pull import MIN_POST_PREFLIGHT_VALIDITY_SECONDS
from .registry_oidc_credentials import (
    GitHubRegistryCredentialVerifier, RegistryCredentialRejectedError,
    VerifiedRegistryCredentials,
)
from .policy import validate_sha256, validate_source_sha

_REVIEWED_FIELDS = frozenset({
    "reviewed_installed_commit", "reviewed_compose_sha256",
    "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
})
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsPrivatePromotionBroker:
    """Exact Analytics-only Task014-style broker, not registered in any service."""

    __slots__ = (
        "_verify", "_review", "_registry", "_replay", "_transport",
        "_expected_workflow_sha", "_reviewed_source",
    )

    def __init__(
        self, *, expected_workflow_sha: str, verifier: object,
        signed_review_handler: InertAnalyticsSignedReleaseReviewHandler,
        replay_guard: object, analytics_transport: object,
        reviewed_installed_source: dict[str, str],
        jwks_cache: object | None = None,
    ) -> None:
        """Bind collaborators; expected source hashes must be root-owned inputs."""
        if (
            type(signed_review_handler) is not InertAnalyticsSignedReleaseReviewHandler
            or type(reviewed_installed_source) is not dict
            or set(reviewed_installed_source) != _REVIEWED_FIELDS
        ):
            raise TypeError("Analytics broker authority is invalid")
        try:
            workflow = validate_expected_workflow_sha(expected_workflow_sha)
            if object.__getattribute__(signed_review_handler, "_workflow") != workflow:
                raise ValueError("reviewed workflow differs")
            source = dict(reviewed_installed_source)
            source["reviewed_installed_commit"] = validate_source_sha(
                source["reviewed_installed_commit"]
            )
            for key in _REVIEWED_FIELDS - {"reviewed_installed_commit"}:
                source[key] = validate_sha256(source[key], key)
            registry = GitHubRegistryCredentialVerifier(
                expected_workflow_sha=workflow, jwks_cache=jwks_cache,
            )
            object.__setattr__(self, "_verify", _bound_operation(verifier, "verify"))
            object.__setattr__(
                self, "_review", _bound_operation(signed_review_handler, "review")
            )
            object.__setattr__(self, "_registry", _bound_operation(registry, "verify"))
            object.__setattr__(self, "_replay", _bound_operation(replay_guard, "consume"))
            # Deliberately no fallback to the existing canary send/private sender.
            object.__setattr__(
                self, "_transport",
                _bound_operation(analytics_transport, "_send_analytics_private"),
            )
            object.__setattr__(self, "_expected_workflow_sha", workflow)
            object.__setattr__(self, "_reviewed_source", tuple(sorted(source.items())))
        except _CONTROL:
            raise
        except Exception:
            raise TypeError("Analytics broker authority is invalid") from None

    def __setattr__(self, name: str, value: object) -> None:
        """Reject post-construction collaborator replacement."""
        raise AttributeError("Analytics broker is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject post-construction collaborator removal."""
        raise AttributeError("Analytics broker is immutable")

    def authorize_and_forward(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        canonical_request: bytes, received_at: int,
    ) -> bytes:
        """Authorize exact request, seal Zot token, consume replay, send privately.

        All cryptographic verification is initiated in this function, not
        supplied as an externally constructible evidence/review object.
        """
        if (
            type(received_at) is not int or received_at < 0
            or type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= MAX_ANALYTICS_REQUEST_BYTES
            or any(type(value) is not str or not value.isascii()
                   or not 1 <= len(value) <= MAX_COMPACT_TOKEN_BYTES
                   for value in (compact_token, zot_token, forgejo_token))
        ):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            request = parse_analytics_request(
                canonical_request,
                **dict(object.__getattribute__(self, "_reviewed_source")),
            )
        except AnalyticsRequestError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None

        try:
            identity = _normalize_identity(
                object.__getattribute__(self, "_verify")(
                    compact_token, received_at=received_at
                ),
                received_at=received_at,
                expected_workflow_sha=object.__getattribute__(
                    self, "_expected_workflow_sha"
                ),
                authorization=authorize_verified_github_oidc,
                expected_fields=IDENTITY_FIELDS,
            )
            bind_analytics_request_to_identity(request, identity)
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except (OIDCVerificationError, OIDCAuthorizationError, AnalyticsRequestError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            # This runs the original OIDC, registry JWT, Sigstore/Cosign and
            # signed source consumers internally; never accepts a caller receipt.
            verified_release = object.__getattribute__(self, "_review")(
                compact_token=compact_token, zot_token=zot_token,
                forgejo_token=forgejo_token, received_at=received_at,
            )
            bind_analytics_request_to_verified_evidence(request, verified_release)
        except BrokerRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            registry = object.__getattribute__(self, "_registry")(
                identity, zot_token=zot_token, forgejo_token=forgejo_token,
                received_at=received_at,
            )
            if type(registry) is not VerifiedRegistryCredentials:
                raise ValueError("unverified registry context")
            zot = registry.zot_read_credential()
            now = int(time.time())
            if (
                type(zot.expires_at) is not int
                or zot.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS
            ):
                raise ValueError("short credential budget")
            descriptor = create_sealed_credential(
                zot.token, expires_at=zot.expires_at,
                image=PINNED_IMAGE, canonical_request=canonical_request,
                product_id="analytics", now=now,
            )
        except RegistryCredentialRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        # A successful replay consume only occurs AFTER independent signature,
        # registry audience, source/hash, token TTL and sealed FD checks.
        try:
            try:
                outcome = object.__getattribute__(self, "_replay")(
                    identity.jti, expires_at=identity.expires_at,
                    request_hash=hashlib.sha256(canonical_request).hexdigest(),
                    run_id=identity.run_id, run_attempt=identity.run_attempt,
                )
                if outcome is not None:
                    raise ValueError("unexpected replay result")
            except ReplayError:
                raise BrokerRejectedError(REJECTED_MESSAGE) from None
            except _CONTROL:
                raise
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            try:
                result = object.__getattribute__(self, "_transport")(
                    canonical_request, credential_fd=descriptor,
                )
                if type(result) is not bytes or len(result) > MAX_EXECUTOR_RESPONSE_BYTES:
                    raise TypeError("invalid executor response")
                return result
            except _CONTROL:
                raise
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        finally:
            os.close(descriptor)


__all__ = ("AnalyticsPrivatePromotionBroker",)

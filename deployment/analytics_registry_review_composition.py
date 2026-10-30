"""File: deployment/analytics_registry_review_composition.py

Purpose: Separate, inert Analytics-only Task014 signed release review adapter.
         Compose the ORIGINAL broker OIDC verifier, registry JWT validator,
         bounded TLS readers, Sigstore and constructor-scoped Cosign without
         modifying the installed original canary registry composition.
Related: deployment/registry_promotion_composition.py (UNCHANGED),
         deployment/broker.py, deployment/broker_integration.py,
         deployment/registry_oidc_credentials.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/oci_verifier.py,
         deployment/tests/test_analytics_review_composition.py.

This file is intentionally OUTSIDE the installed Task014 application source
set. Read-only review has NO request forwarding, replay mutation, privileged
executor, rootless runtime, host secret access or deployment authorization.
"""
from __future__ import annotations

from .analytics_signed_release_consumer import (
    AnalyticsSignedEvidenceReview, acquire_and_review_analytics_release,
)
from .broker import (
    BrokerRejectedError, BrokerUnavailableError, REJECTED_MESSAGE,
    UNAVAILABLE_MESSAGE, IDENTITY_FIELDS, _bound_operation,
    _normalize_identity,
)
from .broker_integration import _CapturedSignature, _RegistryOIDCTokens
from .broker_service_config import DevBrokerServiceConfiguration
from .identity import (
    OIDCAuthorizationError, authorize_verified_github_oidc,
    validate_expected_workflow_sha,
)
from .jwks import OIDCVerificationError, OIDCVerificationUnavailable
from .oidc_verifier import MAX_COMPACT_TOKEN_BYTES
from .oci_verifier import CosignOCISignatureVerifier
from .registry_oidc_credentials import (
    GitHubRegistryCredentialVerifier, VerifiedRegistryCredentials,
)
from .registry_promotion_composition import _RegistryContextVerifier
from .release_consumer import ReleaseBlobSignatureVerifier, _connection


class InertAnalyticsSignedReleaseReviewHandler:
    """Read-only original-broker OIDC + registry + signer proof composition.

    This is NOT a deployment broker, promotion handler, replay authority,
    executor or factory for privileged requests. A valid review receipt
    cannot be sent to the original canary-only executor.
    """

    __slots__ = (
        "_verify", "_context", "_signatures", "_workflow", "_cosign",
        "_zot_connection", "_forgejo_connection", "_oci_runner",
    )

    def __init__(
        self, *, configuration: DevBrokerServiceConfiguration,
        verifier: object, blob_signatures: ReleaseBlobSignatureVerifier,
        jwks_cache: object | None = None,
        zot_connection_factory: object = _connection,
        forgejo_connection_factory: object = _connection,
        oci_runner: object | None = None,
    ) -> None:
        """Bind exactly original reviewed collaborators without doing I/O."""
        if (type(configuration) is not DevBrokerServiceConfiguration
                or not callable(zot_connection_factory)
                or not callable(forgejo_connection_factory)):
            raise TypeError("Analytics signed release review authority is invalid")
        validated = DevBrokerServiceConfiguration.from_dict(configuration.to_dict())
        workflow = validate_expected_workflow_sha(
            validated.oidc_authorization_kwargs()["expected_workflow_sha"]
        )
        credentials = GitHubRegistryCredentialVerifier(
            expected_workflow_sha=workflow, jwks_cache=jwks_cache,
        )
        object.__setattr__(self, "_verify", _bound_operation(verifier, "verify"))
        object.__setattr__(self, "_context", _RegistryContextVerifier(credentials).verify)
        object.__setattr__(self, "_signatures", _CapturedSignature(blob_signatures))
        object.__setattr__(self, "_workflow", workflow)
        object.__setattr__(self, "_cosign", tuple(validated.blob_verifier_kwargs().items()))
        object.__setattr__(self, "_zot_connection", zot_connection_factory)
        object.__setattr__(self, "_forgejo_connection", forgejo_connection_factory)
        object.__setattr__(self, "_oci_runner", oci_runner)

    def __setattr__(self, name: str, value: object) -> None:
        """Never allow retargeting a captured verifier or repository."""
        raise AttributeError("Analytics signed release review is immutable")

    def __delattr__(self, name: str) -> None:
        """Never allow removal of a captured verifier or repository."""
        raise AttributeError("Analytics signed release review is immutable")

    def review(
        self, *, compact_token: str, zot_token: str,
        forgejo_token: str, received_at: int,
    ) -> AnalyticsSignedEvidenceReview:
        """Verify three ORIGINAL workload JWTs, then original signed v1.

        No replay entry is consumed and no broker/executor is contacted.
        This function is never a replacement for the privileged promotion
        path, even when original Sigstore/Cosign verification succeeds.
        """
        if (type(received_at) is not int or received_at < 0
                or any(type(value) is not str or not value.isascii()
                       or not 1 <= len(value) <= MAX_COMPACT_TOKEN_BYTES
                       for value in (compact_token, zot_token, forgejo_token))):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            verified_identity = object.__getattribute__(self, "_verify")(
                compact_token, received_at=received_at,
            )
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except OIDCVerificationError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            authorized = _normalize_identity(
                verified_identity, received_at=received_at,
                expected_workflow_sha=object.__getattribute__(self, "_workflow"),
                authorization=authorize_verified_github_oidc,
                expected_fields=IDENTITY_FIELDS,
            )
        except OIDCAuthorizationError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            context = object.__getattribute__(self, "_context")(
                authorized, _RegistryOIDCTokens(zot_token, forgejo_token),
                received_at=received_at,
            )
            if type(context) is not VerifiedRegistryCredentials:
                raise TypeError("unverified registry credentials")
        except BrokerRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            verifier = CosignOCISignatureVerifier(
                **dict(object.__getattribute__(self, "_cosign")),
                zot_credential_provider=context,
                runner=object.__getattribute__(self, "_oci_runner"),
                product_id="analytics",
            )
            reviewed = acquire_and_review_analytics_release(
                context, context,
                object.__getattribute__(self, "_signatures"), verifier,
                received_at=received_at,
                zot_factory=object.__getattribute__(self, "_zot_connection"),
                forgejo_factory=object.__getattribute__(self, "_forgejo_connection"),
            )
            if (type(reviewed) is not AnalyticsSignedEvidenceReview
                    or reviewed.deployment_authorized is not False):
                raise TypeError("invalid review response")
            return reviewed
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None


__all__ = ("InertAnalyticsSignedReleaseReviewHandler",)

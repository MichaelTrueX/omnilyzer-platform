"""File: deployment/analytics_registry_review_composition.py

Purpose: Reuse the original read-only Analytics Task014 OIDC/registry/
         Sigstore/Cosign chain for immutable 0.15.0 and an independently
         owner-signed successor, without extending the installed broker.
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

from pathlib import Path
import hashlib
import os

from release.analytics_owner_source_selection import (
    AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
    expected_owner_approval_bytes, load_and_verify_owner_signed_source,
    verify_owner_signed_source_proof,
)
from .analytics_signed_release_consumer import (
    AnalyticsSignedEvidenceReview, acquire_and_review_analytics_release,
    acquire_and_review_owner_approved_analytics_release,
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


# Section: fixed, private, best-effort production release error classification.
# Neither exception messages nor JWTs/claims, hashes, URLs, paths, JTI, actor
# IDs, user content or dynamic formatting are permitted in these records.
# All categories are compile-time audited and do not alter existing denials.
_ANALYTICS_RELEASE_OBSERVABILITY_PHASES = frozenset({
    "verify_oidc", "authorize_oidc", "owner_signature",
    "registry_audiences", "signature_verifier", "signed_successor_evidence",
    "signed_evidence_shape", "signed_owner_binding",
    "broker_request_shape", "broker_verify_oidc", "broker_original_evidence",
    "broker_successor_evidence", "broker_signed_shape",
    "broker_registry_audiences", "broker_rollback_hint",
    "broker_signed_request_binding", "broker_sender",
    "broker_signed_review", "broker_selected_request",
    "broker_reverify_oidc", "broker_verify_registry",
    "broker_zot_lifetime", "broker_sealed_fd",
    "broker_replay_consume", "broker_unix_send",
    "broker_executor_receipt", "router_signed_response",
})
_ANALYTICS_RELEASE_OBSERVABILITY_OUTCOMES = frozenset({
    "unavailable", "rejected", "passed",
})


def _emit_analytics_release_boundary(phase: str, outcome: str) -> None:
    """Emit one fixed, secret-free status for the original UID990 service.

    This function must never change admission outcome if journald/stdout is
    unavailable. Unknown dynamic phase/category values are silently ignored.
    It is private to the existing original Analytics release modules.
    """
    try:
        if (type(phase) is not str or type(outcome) is not str
                or phase not in _ANALYTICS_RELEASE_OBSERVABILITY_PHASES
                or outcome not in _ANALYTICS_RELEASE_OBSERVABILITY_OUTCOMES):
            return
        os.write(
            2,
            ("TASK014_ANALYTICS_BROKER_BOUNDARY phase=" + phase
             + " outcome=" + outcome + "\n").encode("ascii"),
        )
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        # Diagnostics must never overwrite an original security rejection.
        pass


class InertAnalyticsSignedReleaseReviewHandler:
    """Read-only original-broker OIDC + registry + signer proof composition.

    This is NOT a deployment broker, promotion handler, replay authority,
    executor or factory for privileged requests. A valid review receipt
    cannot be sent to the original canary-only executor.
    """

    __slots__ = (
        "_verify", "_context", "_signatures", "_workflow", "_cosign",
        "_zot_connection", "_forgejo_connection", "_oci_runner",
        "_owner_files",
    )

    def __init__(
        self, *, configuration: DevBrokerServiceConfiguration,
        verifier: object, blob_signatures: ReleaseBlobSignatureVerifier,
        jwks_cache: object | None = None,
        zot_connection_factory: object = _connection,
        forgejo_connection_factory: object = _connection,
        oci_runner: object | None = None,
        owner_approval_file: Path | None = None,
        owner_signature_file: Path | None = None,
    ) -> None:
        """Bind original collaborators and optional root-review owner file paths."""
        if (type(configuration) is not DevBrokerServiceConfiguration
                or not callable(zot_connection_factory)
                or not callable(forgejo_connection_factory)
                or (owner_approval_file is None) != (owner_signature_file is None)
                or (owner_approval_file is not None and (
                    not isinstance(owner_approval_file, Path)
                    or not isinstance(owner_signature_file, Path)
                ))):
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
        object.__setattr__(
            self, "_owner_files",
            None if owner_approval_file is None
            else (owner_approval_file, owner_signature_file),
        )

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
        """Keep original 0.15.0 independent OIDC/registry/signature verifier."""
        return self._review_mode(
            compact_token=compact_token, zot_token=zot_token,
            forgejo_token=forgejo_token, received_at=received_at,
            successor=False,
        )

    def review_successor(
        self, *, compact_token: str, zot_token: str,
        forgejo_token: str, received_at: int,
        owner_source_proof: str | None = None,
    ) -> tuple[
        AnalyticsSignedEvidenceReview,
        AnalyticsOwnerSourceSelection,
        AnalyticsOwnerSignatureReceipt,
    ]:
        """Verify successor through independent root trust and original verifiers.

        Return a read-only tuple. Broker/installed executor are not wired to
        this method and cannot use it as authority on its own.
        """
        return self._review_mode(
            compact_token=compact_token, zot_token=zot_token,
            forgejo_token=forgejo_token, received_at=received_at,
            successor=True, owner_source_proof=owner_source_proof,
        )

    def _review_mode(
        self, *, compact_token: str, zot_token: str,
        forgejo_token: str, received_at: int, successor: bool,
        owner_source_proof: str | None = None,
    ) -> AnalyticsSignedEvidenceReview | tuple[
        AnalyticsSignedEvidenceReview,
        AnalyticsOwnerSourceSelection,
        AnalyticsOwnerSignatureReceipt,
    ]:
        """Reuse original triple-OIDC, registry JWT, Sigstore and Cosign path."""
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
            if successor:
                _emit_analytics_release_boundary("verify_oidc", "unavailable")
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except OIDCVerificationError:
            if successor:
                _emit_analytics_release_boundary("verify_oidc", "rejected")
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            if successor:
                _emit_analytics_release_boundary("verify_oidc", "unavailable")
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            authorized = _normalize_identity(
                verified_identity, received_at=received_at,
                expected_workflow_sha=object.__getattribute__(self, "_workflow"),
                authorization=authorize_verified_github_oidc,
                expected_fields=IDENTITY_FIELDS,
            )
        except OIDCAuthorizationError:
            if successor:
                _emit_analytics_release_boundary("authorize_oidc", "rejected")
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            if successor:
                _emit_analytics_release_boundary("authorize_oidc", "unavailable")
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        # Section: successor must be anchored in independent DEV root-owned
        # owner-signature trust BEFORE any private Zot/Forgejo registry access.
        # Missing trusted owner files deny rather than falling back to 0.15.0.
        selected_owner = None
        if successor:
            try:
                files = object.__getattribute__(self, "_owner_files")
                if owner_source_proof is not None:
                    selected_owner = verify_owner_signed_source_proof(owner_source_proof)
                else:
                    if files is None:
                        raise ValueError("root owner source not configured")
                    selected_owner = load_and_verify_owner_signed_source(*files)
                if (
                    type(selected_owner) is not tuple
                    or len(selected_owner) != 2
                    or type(selected_owner[0]) is not AnalyticsOwnerSourceSelection
                    or type(selected_owner[1]) is not AnalyticsOwnerSignatureReceipt
                    or selected_owner[1].owner_signature_verified is not True
                ):
                    raise ValueError("unverified owner source")
                selected, owner = selected_owner
                if (
                    owner.source_commit != selected.source_commit
                    or owner.source_tree != selected.source_tree
                    or owner.release_version != selected.release_version
                    or owner.approval_sha256 != hashlib.sha256(
                        expected_owner_approval_bytes(selected)
                    ).hexdigest()
                    or selected.release_authorized is not False
                    or selected.deployment_authorized is not False
                    or owner.release_authorized is not False
                    or owner.deployment_authorized is not False
                ):
                    raise ValueError("owner signature cannot bind source")
            except Exception:
                _emit_analytics_release_boundary("owner_signature", "unavailable")
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            context = object.__getattribute__(self, "_context")(
                authorized, _RegistryOIDCTokens(zot_token, forgejo_token),
                received_at=received_at,
            )
            if type(context) is not VerifiedRegistryCredentials:
                raise TypeError("unverified registry credentials")
        except BrokerRejectedError:
            if successor:
                _emit_analytics_release_boundary("registry_audiences", "rejected")
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except Exception:
            if successor:
                _emit_analytics_release_boundary("registry_audiences", "unavailable")
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        phase = "signature_verifier"
        try:
            verifier = CosignOCISignatureVerifier(
                **dict(object.__getattribute__(self, "_cosign")),
                zot_credential_provider=context,
                runner=object.__getattribute__(self, "_oci_runner"),
                product_id="analytics",
            )
            if successor:
                phase = "signed_successor_evidence"
                files = object.__getattribute__(self, "_owner_files")
                reviewed = acquire_and_review_owner_approved_analytics_release(
                    context, context,
                    object.__getattribute__(self, "_signatures"), verifier,
                    received_at=received_at,
                    approval_file=None if files is None else files[0],
                    signature_file=None if files is None else files[1],
                    **({} if owner_source_proof is None else
                       {'owner_source_proof': owner_source_proof}),
                    zot_factory=object.__getattribute__(self, "_zot_connection"),
                    forgejo_factory=object.__getattribute__(self, "_forgejo_connection"),
                )
            else:
                reviewed = acquire_and_review_analytics_release(
                    context, context,
                    object.__getattribute__(self, "_signatures"), verifier,
                    received_at=received_at,
                    zot_factory=object.__getattribute__(self, "_zot_connection"),
                    forgejo_factory=object.__getattribute__(self, "_forgejo_connection"),
                )
            if successor:
                phase = "signed_evidence_shape"
            if (type(reviewed) is not AnalyticsSignedEvidenceReview
                    or reviewed.deployment_authorized is not False):
                raise TypeError("invalid review response")
            if successor:
                phase = "signed_owner_binding"
                selected, owner = selected_owner
                if (
                    reviewed.release_version != selected.release_version
                    or reviewed.source.source_commit != selected.source_commit
                    or reviewed.source.source_tree != selected.source_tree
                    or reviewed.image != "oci-dev.omnilyzer.ai/omnilyzer/analytics@" + reviewed.source.oci_manifest_digest
                    or reviewed.source.release_authorized is not False
                    or reviewed.source.deployment_authorized is not False
                    or owner.release_version != selected.release_version
                    or owner.source_commit != selected.source_commit
                    or owner.source_tree != selected.source_tree
                ):
                    raise ValueError("signed release differs from approved owner source")
                _emit_analytics_release_boundary("signed_owner_binding", "passed")
                return reviewed, selected, owner
            return reviewed
        except Exception:
            if successor:
                _emit_analytics_release_boundary(phase, "unavailable")
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None


__all__ = ("InertAnalyticsSignedReleaseReviewHandler",)

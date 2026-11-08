"""File: deployment/analytics_promotion_broker.py

Purpose: Preserve original Task014 OIDC -> signed 0.15.0 release ->
         sealed Zot credential -> replay -> private first-install transport,
         and read-only verify first-successor signed source and the original
         rollback hint WITHOUT Docker access, plus an UNINSTALLED positive
         source-only replay/FD handoff that requires future owner approval.
Related: deployment/analytics_registry_review_composition.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/analytics_execution.py,
         deployment/analytics_active_state_review.py,
         deployment/private_registry_fd.py,
         deployment/registry_oidc_credentials.py, deployment/broker.py,
         deployment/tests/test_analytics_promotion_broker.py.

Sections: root-controlled authority capture; canonical successor and
          signed-original/owner/GitHub/registry read-only review;
          original sealed Zot handoff, replay and bounded private transport;
          future independently signed schema3 broker replay/FD handoff.

NOT ACTIVATED FOR SUCCESSORS: The original Analytics executor systemd
socket is installed and listens, but its signed 0.15.0 receiver cannot admit
schema 3. Candidate successor code on this branch is NOT installed. A later
independently approved update must verify the protected source set, SO_PEERCRED,
sealed credential, rootless runtime, secrets, PG roles and recoverable rollback.
The public review dataclasses and test mocks are not deployment grants.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from .analytics_execution import (
    AnalyticsRequestError, MAX_ANALYTICS_REQUEST_BYTES,
    AnalyticsSuccessorRequest,
    bind_analytics_request_to_identity,
    bind_analytics_request_to_verified_evidence,
    parse_analytics_request,
    parse_analytics_successor_request,
)
from .analytics_registry_review_composition import InertAnalyticsSignedReleaseReviewHandler
from .analytics_signed_release_consumer import (
    PINNED_DIGEST, PINNED_IMAGE, PINNED_VERSION, PINNED_RUN_ID,
)
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
from .private_registry_fd import (
    create_sealed_credential, create_sealed_successor_review_credentials,
)
from .private_registry_pull import MIN_POST_PREFLIGHT_VALIDITY_SECONDS
from .registry_oidc_credentials import (
    GitHubRegistryCredentialVerifier, RegistryCredentialRejectedError,
    VerifiedRegistryCredentials,
)
from .policy import canonical_bytes, validate_sha256, validate_source_sha

_REVIEWED_FIELDS = frozenset({
    "reviewed_installed_commit", "reviewed_compose_sha256",
    "reviewed_product_profile_sha256", "reviewed_runtime_profile_sha256",
})
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class AnalyticsPrivatePromotionBroker:
    """Exact Analytics-only Task014-style broker, not registered in any service."""

    __slots__ = (
        "_verify", "_review", "_review_successor",
        "_registry", "_replay", "_transport", "_successor_transport",
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
            object.__setattr__(
                self, "_review_successor",
                _bound_operation(signed_review_handler, "review_successor"),
            )
            object.__setattr__(self, "_registry", _bound_operation(registry, "verify"))
            object.__setattr__(self, "_replay", _bound_operation(replay_guard, "consume"))
            # Deliberately no fallback to the existing canary send/private sender.
            object.__setattr__(
                self, "_transport",
                _bound_operation(analytics_transport, "_send_analytics_private"),
            )
            # Original signed 0.15.0 tests may use a transport that has no
            # successor method. That original production contract stays valid;
            # successor is *not* registered if no exact kernel sender exists.
            try:
                successor_sender = _bound_operation(
                    analytics_transport, "_send_analytics_successor_private",
                )
            except TypeError:
                successor_sender = None
            object.__setattr__(self, "_successor_transport", successor_sender)
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

    # Section: private read-only first-successor admission, not an executor
    # path. Reuses protected original OIDC and signed 0.15.0 trust chain.
    def review_first_successor_without_forwarding(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        canonical_request: bytes, received_at: int,
    ) -> AnalyticsSuccessorRequest:
        """Verify signed old/new releases, not the inaccessible Docker route.

        The broker runs as omnilyzer-broker, a separate restricted systemd
        principal with NO rootless Docker/RootlessKit socket access. This is
        the FIRST successor only: it binds the rollback hint to the original
        immutable SIGNED 0.15.0 image/blue slot, but cannot assert that this
        image is currently installed. The authenticated UID991 executor MUST
        observe the actual active image/route before any replay or operation.
        No durable replay is consumed, FD sealed, or executor contacted here.
        Returning a canonical request is NEVER a deployment grant.
        """
        if (
            type(received_at) is not int or received_at < 0
            or type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= MAX_ANALYTICS_REQUEST_BYTES
            or any(
                type(value) is not str or not value.isascii()
                or not 1 <= len(value) <= MAX_COMPACT_TOKEN_BYTES
                for value in (compact_token, zot_token, forgejo_token)
            )
        ):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        try:
            # Reject noncanonical JSON, duplicates, NaN and wrong scope
            # before touching any OIDC, registry or Docker collaborator.
            def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON field")
                    result[key] = value
                return result

            raw = json.loads(
                canonical_request.decode("ascii"),
                object_pairs_hook=unique,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError),
            )
            if (
                type(raw) is not dict
                or type(raw.get("schema_version")) is not int
                or raw["schema_version"] != 3
                or raw.get("product_id") != "analytics"
                or raw.get("stage") != "dev"
                or canonical_bytes(raw) != canonical_request
            ):
                raise ValueError("wrong request")
        except _CONTROL:
            raise
        except Exception:
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
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except (OIDCVerificationError, OIDCAuthorizationError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        try:
            previous = object.__getattribute__(self, "_review")(
                compact_token=compact_token, zot_token=zot_token,
                forgejo_token=forgejo_token, received_at=received_at,
            )
            next_release = object.__getattribute__(
                self, "_review_successor"
            )(
                compact_token=compact_token, zot_token=zot_token,
                forgejo_token=forgejo_token, received_at=received_at,
            )
            from .analytics_signed_release_consumer import (
                AnalyticsSignedEvidenceReview,
            )
            from release.analytics_owner_source_selection import (
                AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
            )
            if (
                type(previous) is not AnalyticsSignedEvidenceReview
                or previous.image != PINNED_IMAGE
                or previous.release_version != PINNED_VERSION
                or previous.release_run_id != PINNED_RUN_ID
                or previous.deployment_authorized is not False
                or type(next_release) is not tuple
                or len(next_release) != 3
                or type(next_release[0]) is not AnalyticsSignedEvidenceReview
                or type(next_release[1]) is not AnalyticsOwnerSourceSelection
                or type(next_release[2]) is not AnalyticsOwnerSignatureReceipt
            ):
                raise ValueError("invalid signed original or successor")
            registry = object.__getattribute__(self, "_registry")(
                identity, zot_token=zot_token, forgejo_token=forgejo_token,
                received_at=received_at,
            )
            if type(registry) is not VerifiedRegistryCredentials:
                raise ValueError("unverified independent registry audiences")
            # The broker has no Docker privilege. For this FIRST successor
            # the previously signed image must be exactly the accepted blue
            # 0.15.0; the rollback fields are STILL ONLY REQUEST HINTS.
            # UID991 executor must re-read actual routing and image before
            # any future replay/activation. No transport is available here.
            if (
                type(raw.get("rollback_reference")) is not dict
                or raw["rollback_reference"].get("previous_digest")
                    != PINNED_DIGEST
                or raw["rollback_reference"].get("previous_slot") != "blue"
            ):
                raise ValueError("unreviewed previous release hint")
            accepted = parse_analytics_successor_request(
                canonical_request,
                **dict(object.__getattribute__(self, "_reviewed_source")),
                signed_release=next_release[0], selected=next_release[1],
                owner_approval=next_release[2], identity=identity,
                observed_active_digest=PINNED_DIGEST,
                observed_active_slot="blue",
            )
            if type(accepted) is not AnalyticsSuccessorRequest:
                raise ValueError("unverified successor shape")
            return accepted
        except BrokerRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None


    def forward_verified_first_successor_probe_without_deployment(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        canonical_request: bytes, received_at: int,
    ) -> None:
        """Carry independently re-verifiable OIDC/Forgejo/Zot JWTs over sealed FD.

        NOT registered in the installed HTTPS promotion router. Even a fully
        verified request is sent only to the read-only UID991 probe, which
        always rejects. No broker replay consume, no executor replay begin,
        no OCI pull, no Docker/route mutation, and no success response is
        permitted. An absent successor sender fails BEFORE any network read.
        """
        sender = object.__getattribute__(self, "_successor_transport")
        if sender is None:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        # This existing review runs real GitHub OIDC, original signed 0.15.0,
        # owner-held detached Ed25519 source, successor Sigstore/Cosign,
        # independent Zot/Forgejo registry audiences and exact request binding.
        selected = self.review_first_successor_without_forwarding(
            compact_token=compact_token, zot_token=zot_token,
            forgejo_token=forgejo_token, canonical_request=canonical_request,
            received_at=received_at,
        )
        if (type(selected) is not AnalyticsSuccessorRequest
                or selected.canonical_bytes() != canonical_request):
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        # Recheck the same independently authorized OIDC identity before
        # binding a *new* short-lived manifest-only Zot credential to the
        # exact signed successor image (not legacy PINNED_IMAGE).
        try:
            identity = _normalize_identity(
                object.__getattribute__(self, "_verify")(
                    compact_token, received_at=received_at,
                ),
                received_at=received_at,
                expected_workflow_sha=object.__getattribute__(
                    self, "_expected_workflow_sha"
                ),
                authorization=authorize_verified_github_oidc,
                expected_fields=IDENTITY_FIELDS,
            )
            # Original bind_analytics_request_to_identity intentionally
            # accepts EXACT schema-2 class only. Preserve that restriction:
            # independently compare all nine GitHub OIDC identity fields
            # for exact schema-3 instead of broadening the legacy binder.
            if (
                type(selected) is not AnalyticsSuccessorRequest
                or (
                    selected.requested_by_actor_id,
                    selected.github_repository_id,
                    selected.github_workflow_ref,
                    selected.github_workflow_sha,
                    selected.github_run_id,
                    selected.github_run_attempt,
                    selected.oidc_jti,
                    selected.oidc_issued_at,
                    selected.oidc_expires_at,
                ) != (
                    identity.actor_id, identity.repository_id,
                    identity.workflow_ref, identity.workflow_sha,
                    identity.run_id, identity.run_attempt, identity.jti,
                    identity.issued_at, identity.expires_at,
                )
            ):
                raise AnalyticsRequestError("successor OIDC identity changed")
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except (OIDCVerificationError, OIDCAuthorizationError, AnalyticsRequestError):
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
                raise ValueError("unverified registry audience")
            scoped = registry.zot_read_credential()
            now = int(time.time())
            if (type(scoped.expires_at) is not int
                    or scoped.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS):
                raise ValueError("insufficient credential lifetime")
            descriptor = create_sealed_successor_review_credentials(
                scoped.token, forgejo_token=forgejo_token,
                github_oidc_token=compact_token,
                expires_at=scoped.expires_at,
                image=selected.exact_image_reference,
                canonical_request=canonical_request, now=now,
            )
        except RegistryCredentialRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        try:
            try:
                # UID991 can never report a deployment success from this
                # probe; a forged positive response is treated as UNAVAILABLE.
                sender(canonical_request, credential_fd=descriptor)
            except _CONTROL:
                raise
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        finally:
            os.close(descriptor)

    # Section: future source-only original broker replay/FD/Unix handoff
    # for the independently reviewed first successor. NOT installed in
    # HTTPS routing; the original active receiver remains DENY-only.
    def authorize_and_forward_first_successor(
        self, *, compact_token: str, zot_token: str, forgejo_token: str,
        canonical_request: bytes, received_at: int,
    ) -> bytes:
        """Consume the ORIGINAL broker JTI only after signed review and FD.

        This is the second half of the first-successor source transaction.
        Independently verify original GitHub actor/run/workflow and both signed
        original/next release proofs, then bind three scoped source JWTs in one
        kernel-sealed FD. The original SQLite replay consume occurs BEFORE
        sending to the exact Analytics-successor Unix transport; a wrong,
        partial or forged executor success is always UNAVAILABLE, never GO.
        The current live HTTPS router NEVER calls this method and the root
        UID991 generation-2 Unix receiver is still signed-review DENY-only.

        Do not install/enable this path without original root-owned V2,
        protected positive UID991 coordinator, explicit owner approval and
        independently accepted restart recovery; no generic public API added.
        """
        from .executor import parse_canonical_response
        sender = object.__getattribute__(self, "_successor_transport")
        if sender is None:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        # Section: mandatory complete original broker signing admission.
        # This performs original owner Ed25519, OIDC, Cosign, provenance, OCI
        # SBOM, zero-High and exact original 0.15.0 rollback source binding.
        selected = self.review_first_successor_without_forwarding(
            compact_token=compact_token, zot_token=zot_token,
            forgejo_token=forgejo_token,
            canonical_request=canonical_request, received_at=received_at,
        )
        if (
            type(selected) is not AnalyticsSuccessorRequest
            or selected.canonical_bytes() != canonical_request
            or selected.exact_image_reference == PINNED_IMAGE
        ):
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        # Re-verify original signed OIDC for the second replay transition,
        # never accept request fields or a caller-created receipt as identity.
        try:
            identity = _normalize_identity(
                object.__getattribute__(self, "_verify")(
                    compact_token, received_at=received_at,
                ),
                received_at=received_at,
                expected_workflow_sha=object.__getattribute__(
                    self, "_expected_workflow_sha",
                ),
                authorization=authorize_verified_github_oidc,
                expected_fields=IDENTITY_FIELDS,
            )
            if (
                (
                    selected.requested_by_actor_id,
                    selected.github_repository_id,
                    selected.github_workflow_ref,
                    selected.github_workflow_sha,
                    selected.github_run_id,
                    selected.github_run_attempt,
                    selected.oidc_jti,
                    selected.oidc_issued_at,
                    selected.oidc_expires_at,
                ) != (
                    identity.actor_id, identity.repository_id,
                    identity.workflow_ref, identity.workflow_sha,
                    identity.run_id, identity.run_attempt, identity.jti,
                    identity.issued_at, identity.expires_at,
                )
            ):
                raise AnalyticsRequestError("changed signed identity")
        except OIDCVerificationUnavailable:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        except (OIDCVerificationError, OIDCAuthorizationError, AnalyticsRequestError):
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        # Section: three original signed JWTs bound to exact immutable OCI
        # digest and canonical schema3 request. Reuse the original narrow
        # registry-audience verifier and sealed kernel memfd schema2.
        try:
            registry = object.__getattribute__(self, "_registry")(
                identity, zot_token=zot_token, forgejo_token=forgejo_token,
                received_at=received_at,
            )
            if type(registry) is not VerifiedRegistryCredentials:
                raise ValueError("unverified registry audiences")
            scoped = registry.zot_read_credential()
            now = int(time.time())
            if (
                type(scoped.expires_at) is not int
                or scoped.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS
            ):
                raise ValueError("expired future pull window")
            descriptor = create_sealed_successor_review_credentials(
                scoped.token, forgejo_token=forgejo_token,
                github_oidc_token=compact_token, expires_at=scoped.expires_at,
                image=selected.exact_image_reference,
                canonical_request=canonical_request, now=now,
            )
        except RegistryCredentialRejectedError:
            raise BrokerRejectedError(REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None

        # Section: the exact original cross-process broker replay store must
        # CONSUME before any private executor message is sent. An executor
        # failure consumes the JTI, prevents replay, and never grants success.
        request_hash = hashlib.sha256(canonical_request).hexdigest()
        try:
            try:
                consumed = object.__getattribute__(self, "_replay")(
                    identity.jti, expires_at=identity.expires_at,
                    request_hash=request_hash,
                    run_id=identity.run_id,
                    run_attempt=identity.run_attempt,
                )
                if consumed is not None:
                    raise ValueError("invalid replay consume")
            except ReplayError:
                raise BrokerRejectedError(REJECTED_MESSAGE) from None
            except _CONTROL:
                raise
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
            try:
                result = sender(
                    canonical_request, credential_fd=descriptor,
                )
                if (
                    type(result) is not bytes
                    or not 0 < len(result) <= MAX_EXECUTOR_RESPONSE_BYTES
                    or parse_canonical_response(result).executor_request_sha256
                        != request_hash
                ):
                    raise ValueError("wrong signed executor receipt")
                return result
            except _CONTROL:
                raise
            except Exception:
                raise BrokerUnavailableError(UNAVAILABLE_MESSAGE) from None
        finally:
            os.close(descriptor)

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

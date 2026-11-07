"""File: deployment/analytics_executor.py

Purpose: Closed Analytics-only Task014 private executor boundary for the signed
         0.15.0 first-install request; independently reparses request and sealed
         Zot FD, performs authenticated immutable-image preflight and full
         pull-time-budget check, then original durable replay begin/finish.
Related: deployment/analytics_execution.py (exact reviewed request grammar),
         deployment/private_registry_fd.py (legacy and successor sealed JWTs),
         deployment/oidc_verifier.py and registry_oidc_credentials.py,
         deployment/executor_server.py (SO_PEERCRED and SCM_RIGHTS handler),
         deployment/executor.py (original response and replay primitives),
         deployment/analytics_promotion_broker.py (caller, not a trust anchor),
         deployment/tests/test_analytics_first_successor_transaction.py,
         deployment/analytics_loopback_guard.py and analytics_route_journal.py.

Sections: root-reviewed input capture, original FD+request execution, separate
          first-successor read-only live OCI/manifest proof and independent
         three-JWT successor identity verification, original replay
          transitions, protected product-only operation and source-only
          end-to-end first-successor staging/cutover/rollback coordinator.

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
from pathlib import Path
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
# These are the SAME fixed root-controlled DEV approval files used by the
# signed source reviewer, not release/OCI bytes supplied over the Unix socket.
# A missing file or missing trusted signer is a mandatory rejection.
_OWNER_APPROVAL_FILE = Path(
    "/etc/omnilyzer/deployment/dev/analytics-owner-source-approval.json"
)
_OWNER_SIGNATURE_FILE = Path(
    "/etc/omnilyzer/deployment/dev/analytics-owner-source-approval.json.sig"
)


def _verify_executor_owner_source(request: dict[str, object]) -> None:
    """Independently check owner-held Ed25519 exact-source approval at UID991.

    The existing root-owned public-key trust anchor and OpenSSH verification
    are used unmodified. A broker-provided Python receipt, claimed SHA,
    registry token or request-shaped JSON never substitutes for root-trusted
    signature verification. No network, filesystem write or deployment.
    This is ONE mandatory source proof, NOT complete signed Task013 evidence,
    OIDC authorization, durable replay or successor deployment permission.
    """
    from release.analytics_owner_source_selection import (
        AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
        expected_owner_approval_bytes, load_and_verify_owner_signed_source,
    )
    if type(request) is not dict:
        raise ValueError("invalid executor request")
    selected, proof = load_and_verify_owner_signed_source(
        _OWNER_APPROVAL_FILE, _OWNER_SIGNATURE_FILE,
    )
    if (
        type(selected) is not AnalyticsOwnerSourceSelection
        or type(proof) is not AnalyticsOwnerSignatureReceipt
        or proof.owner_signature_verified is not True
        or proof.independent_review_verified is not False
        or proof.release_authorized is not False
        or proof.deployment_authorized is not False
        or selected.release_authorized is not False
        or selected.deployment_authorized is not False
        or selected.source_commit != request.get("product_source_sha")
        or selected.platform_workflow_commit != request.get("source_sha")
        or selected.release_version != request.get("release_version")
        or proof.source_commit != selected.source_commit
        or proof.source_tree != selected.source_tree
        or proof.release_version != selected.release_version
        or proof.approval_sha256 != request.get("owner_approval_sha256")
        or proof.approval_sha256 != hashlib.sha256(
            expected_owner_approval_bytes(selected)
        ).hexdigest()
    ):
        raise ValueError("owner-approved source does not match request")
    return None


def _verified_executor_successor_identity_and_credentials(
    canonical_request: bytes, credential_fd: int, *,
    expected_workflow_sha: str, jwks_cache: object | None = None,
    received_at: int | None = None,
) -> None:
    """Verify and retain the original three-token executor registry context.

    This scoped, in-memory result is NOT release authorization. All three
    original OIDC/JWT issuer, signature, audience and run claims are verified
    independently of the broker against an independently root-reviewed
    workflow SHA. Returning the validated context enables the future UID991
    release reader to fetch original signed Task013 evidence without trusting
    a broker-created receipt. This performs no I/O, replay or deployment.
    """
    try:
        from .identity import AuthorizedGitHubIdentity
        from .oidc_verifier import GitHubOIDCVerifier
        from .registry_oidc_credentials import (
            GitHubRegistryCredentialVerifier, VerifiedRegistryCredentials,
        )
        # Local-only import protects the original frozen Analytics 0.15.0
        # installation, which has the historical schema-1 FD module.
        from .private_registry_fd import (
            _successor_request_image, read_sealed_successor_review_credentials,
        )
        from .policy import canonical_bytes
        import json

        if (
            type(credential_fd) is not int or credential_fd < 0
            or type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= 16 * 1024
            or type(expected_workflow_sha) is not str
            or received_at is not None and (
                type(received_at) is not int or received_at < 0
            )
        ):
            raise ValueError("unreviewed proof input")
        workflow = validate_source_sha(expected_workflow_sha)
        if workflow == "0" * 40:
            raise ValueError("zero workflow authority")

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            """Reject duplicate nested request fields before any signature."""
            result: dict[str, object] = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate signed-request field")
                result[name] = value
            return result

        request = json.loads(
            canonical_request.decode("ascii"), object_pairs_hook=unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError),
        )
        if (
            type(request) is not dict
            or canonical_bytes(request) != canonical_request
            or request.get("schema_version") != 3
            or type(request.get("schema_version")) is not int
            or request.get("stage") != "dev"
            or request.get("product_id") != "analytics"
            or request.get("github_workflow_sha") != workflow
        ):
            raise ValueError("not an authorized successor request")
        image = _successor_request_image(canonical_request)
        now = int(time.time()) if received_at is None else received_at
        sealed = read_sealed_successor_review_credentials(
            credential_fd, canonical_request=canonical_request,
            image=image, now=now,
        )
        # An omitted/untrusted JWKS source never becomes a fallback to
        # broker-provided decoded claims: only the actual JWT verification.
        deployment = GitHubOIDCVerifier(
            expected_workflow_sha=workflow, jwks_cache=jwks_cache,
        ).verify(sealed.github_oidc_token, received_at=now)
        if type(deployment) is not AuthorizedGitHubIdentity:
            raise ValueError("unverified deployment identity")
        registry = GitHubRegistryCredentialVerifier(
            expected_workflow_sha=workflow, jwks_cache=jwks_cache,
        ).verify(
            deployment, zot_token=sealed.zot.token,
            forgejo_token=sealed.forgejo_token, received_at=now,
        )
        if type(registry) is not VerifiedRegistryCredentials:
            raise ValueError("unverified registry identity")
        zot = registry.zot_read_credential()
        forgejo = registry.forgejo_read_credential()
        # The registry verifier's OAuth/JWT policy is separate from the
        # original one-use sealed FD request hash and exact immutable OCI.
        if (
            type(zot.expires_at) is not int
            or zot.expires_at != sealed.zot.expires_at
            or zot.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS
            or type(forgejo.expires_at) is not int
            or forgejo.expires_at <= now
            or (
                request.get("requested_by_actor_id"),
                request.get("github_repository_id"),
                request.get("github_workflow_ref"),
                request.get("github_workflow_sha"),
                request.get("github_run_id"),
                request.get("github_run_attempt"),
                request.get("oidc_jti"),
                request.get("oidc_issued_at"),
                request.get("oidc_expires_at"),
            ) != (
                deployment.actor_id, deployment.repository_id,
                deployment.workflow_ref, deployment.workflow_sha,
                deployment.run_id, deployment.run_attempt, deployment.jti,
                deployment.issued_at, deployment.expires_at,
            )
        ):
            raise ValueError("signed identities do not match request")
        # Internal only: the original verified pair remains in memory and
        # cannot represent an executor deployment or release success response.
        return deployment, registry
    except _CONTROL:
        raise
    except Exception:
        # Never log/return compact JWTs, expected SHA or decoded claims.
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None


def _verify_executor_successor_identity(
    canonical_request: bytes, credential_fd: int, *,
    expected_workflow_sha: str, jwks_cache: object | None = None,
    received_at: int | None = None,
) -> None:
    """Preserve the existing read-only three-JWT check and DENY-only contract.

    A verified registry context must never become success just because the
    original Unix handler has validated signatures. Complete independent
    signed Task013 evidence, replay and rollout remain separate gates.
    """
    _verified_executor_successor_identity_and_credentials(
        canonical_request, credential_fd,
        expected_workflow_sha=expected_workflow_sha,
        jwks_cache=jwks_cache, received_at=received_at,
    )
    return None


def _review_executor_successor_signed_release(
    canonical_request: bytes, credential_fd: int, *,
    expected_workflow_sha: str,
    reviewed_installed_source: dict[str, str],
    received_at: int | None = None,
    jwks_cache: object | None = None,
):
    """Independently read and verify full original Task013 evidence at UID991.

    This UNINSTALLED, read-only helper obtains all original JWTs from the
    single sealed kernel FD, verifies their issuer/signature/audience/workflow
    using the independent root-reviewed V2 workflow SHA, and THEN reads the
    original Forgejo archive and Zot OCI subject with the same immutable
    Sigstore/Cosign/provenance/SBOM/zero-High policy as the UID990 broker.

    The future root-installed UID991 service must mount separately root-
    approved, exact-hash Cosign/TrustedRoot resource copies inside its OWN
    private mount namespace at the unchanged original verifier paths. The
    original signer code and the UID990 broker's filesystem view remain
    byte-identical. No shared broker group membership, requester path, env
    or unsigned receipt grants access. The original independently owner-signed source and live private
    blue 0.15.0 are rebound to the candidate request BEFORE returning.

    Returning a parsed read-only request is NOT deployment authority. No
    replay, Docker pull, 3142 route, 3141 switch, journal write, service
    start or success response occurs. The actual Unix receiver remains
    DENY-only until this and the independent rollback/operation chain are
    securely installed and accepted.
    """
    try:
        import json
        from .analytics_active_state_review import (
            AnalyticsActiveState, inspect_analytics_active_state,
        )
        from .analytics_execution import (
            AnalyticsSuccessorRequest, parse_analytics_successor_request,
        )
        from .analytics_signed_release_consumer import (
            AnalyticsSignedEvidenceReview,
            acquire_and_review_owner_approved_analytics_release,
        )
        from .analytics_unix_boundary import _root_reviewed_source
        from .blob_verifier import CosignReleaseBlobVerifier
        from .oci_verifier import CosignOCISignatureVerifier
        from .policy import canonical_bytes
        from .sigstore_authority_provenance import (
            DevSigstoreVerificationProvenance,
        )
        from release.analytics_owner_source_selection import (
            AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
            load_and_verify_owner_signed_source,
        )

        if (
            (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
            or type(expected_workflow_sha) is not str
            or type(credential_fd) is not int or credential_fd < 0
            or type(canonical_request) is not bytes
            or received_at is not None and (
                type(received_at) is not int or received_at < 0
            )
        ):
            raise ValueError("untrusted Analytics signed review principal")
        source = dict(_root_reviewed_source(reviewed_installed_source))
        _successor_request_image(canonical_request)

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            """Reject ambiguous source/owner/signature references recursively."""
            found: dict[str, object] = {}
            for name, value in pairs:
                if name in found:
                    raise ValueError("ambiguous canonical Analytics request")
                found[name] = value
            return found

        request = json.loads(
            canonical_request.decode("ascii"), object_pairs_hook=unique,
            parse_constant=lambda _name: (_ for _ in ()).throw(ValueError),
        )
        if type(request) is not dict or canonical_bytes(request) != canonical_request:
            raise ValueError("untrusted signed-request bytes")

        # Owner approval and actual live writer are checked BEFORE any remote
        # registry read. Current active blue 0.15.0 must remain the sole writer.
        _verify_executor_owner_source(request)
        previous = inspect_analytics_active_state()
        if (
            type(previous) is not AnalyticsActiveState
            or previous.read_only is not True
            or previous.deployment_authorized is not False
            or previous.active_slot != "blue"
            or previous.active_digest != PINNED_DIGEST
            or previous.active_image != PINNED_IMAGE
            or previous.private_ingress_port != 3141
            or previous.candidate_slot != "green"
            or previous.candidate_port != ANALYTICS_SUCCESSOR_CANDIDATE_PORT
            or previous.candidate_probe_present is not False
            or previous.candidate_digest is not None
            or previous.candidate_container_id is not None
        ):
            raise ValueError("active Analytics source has changed")

        now = int(time.time()) if received_at is None else received_at
        identity, registry = _verified_executor_successor_identity_and_credentials(
            canonical_request, credential_fd,
            expected_workflow_sha=expected_workflow_sha,
            jwks_cache=jwks_cache, received_at=now,
        )

        # Zero-input immutable C32I provenance pins the SAME actual Cosign
        # executable and TrustedRoot SHA as UID990. UID991 must see separately
        # approved root-owned READ-ONLY copies via an authorized private
        # systemd mount, under the unchanged original verifier paths.
        # The original signer implementation, policy and runtime checks
        # remain unchanged; there is NO new verifier framework.
        # No input/request/FD/env can supply either digest or asset path.
        toolchain = dict(
            DevSigstoreVerificationProvenance().broker_service_configuration_kwargs()
        )
        if set(toolchain) != {
            "cosign_version", "cosign_binary_sha256",
            "sigstore_trusted_root_sha256",
        }:
            raise ValueError("unknown verification toolchain")
        verifier_config = {
            "expected_cosign_version": toolchain["cosign_version"],
            "expected_binary_sha256": toolchain["cosign_binary_sha256"],
            "expected_trusted_root_sha256":
                toolchain["sigstore_trusted_root_sha256"],
            "broker_uid": 991, "broker_gid": 991,
        }
        blob = CosignReleaseBlobVerifier(**verifier_config)
        oci = CosignOCISignatureVerifier(
            **verifier_config, zot_credential_provider=registry,
            product_id="analytics",
        )
        signed = acquire_and_review_owner_approved_analytics_release(
            registry, registry, blob, oci, received_at=now,
            approval_file=_OWNER_APPROVAL_FILE,
            signature_file=_OWNER_SIGNATURE_FILE,
        )
        selected, owner = load_and_verify_owner_signed_source(
            _OWNER_APPROVAL_FILE, _OWNER_SIGNATURE_FILE,
        )
        if (
            type(signed) is not AnalyticsSignedEvidenceReview
            or type(selected) is not AnalyticsOwnerSourceSelection
            or type(owner) is not AnalyticsOwnerSignatureReceipt
            or owner.owner_signature_verified is not True
        ):
            raise ValueError("unsigned Analytics release")
        parsed = parse_analytics_successor_request(
            canonical_request, **source,
            signed_release=signed, selected=selected, owner_approval=owner,
            identity=identity,
            observed_active_digest=previous.active_digest,
            observed_active_slot=previous.active_slot,
        )
        if (
            type(parsed) is not AnalyticsSuccessorRequest
            or parsed.exact_image_reference != signed.image
            or inspect_analytics_active_state() != previous
        ):
            raise ValueError("release/host drift during verified source review")
        return parsed
    except _CONTROL:
        raise
    except Exception:
        # No original JWT, GitHub claim, registry data, verifier argv, owner
        # signature, host/container state or exception detail crosses UID991.
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None


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
        candidate_ready: bool = True,
    ) -> None:
        """Read-only two-stage successor proof against the *actual* UID991 host.

        The strict default verifies a staged green candidate before traffic
        cutover. An explicitly internal `candidate_ready=False` check verifies
        the original blue source and Zot manifest BEFORE cold image pull.
        This avoids requiring an already-running candidate before the only
        authorized code would be able to create one. Neither phase grants
        pull, replay, routing, DB, systemd or deployment authority.

        This is NOT an executable promotion receiver: it deliberately has no
        replay begin/finish, pull, OCI install, 3141 switch, rollback mutation
        or success response. The broker must independently authenticate OIDC,
        owner Ed25519 and signed release before future forwarding; a forged
        caller-constructible schema-3 JSON or this local result grants nothing.
        Exact independently root-anchored owner signature, sealed FD, local
        live OCI digest, private candidate 3142 and actual Zot manifest are
        rechecked by the restricted UID991 executor.
        """
        if type(credential_fd) is not int or credential_fd < 0:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        if type(candidate_ready) is not bool:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        try:
            from .analytics_active_state_review import (
                AnalyticsActiveState, inspect_analytics_active_state,
                verify_empty_analytics_successor_slot,
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
            # Mandatory *independent* owner Ed25519 verification at UID991.
            # Do this before any Docker/RootlessKit/registry access. The two
            # root-controlled files cannot be selected by the broker/request.
            _verify_executor_owner_source(parsed)
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
                or (candidate_ready and (
                    observed.candidate_probe_present is not True
                    or observed.candidate_digest != parsed["manifest_digest"]
                    or type(observed.candidate_container_id) is not str
                    or len(observed.candidate_container_id) != 64
                ))
                or (not candidate_ready and (
                    observed.candidate_probe_present is not False
                    or observed.candidate_digest is not None
                    or observed.candidate_container_id is not None
                ))
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
            # No 3142 route is not enough: stale/stopped green containers
            # must be rejected, not silently adopted or overwritten.
            if not candidate_ready:
                verify_empty_analytics_successor_slot()
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
            if not candidate_ready:
                verify_empty_analytics_successor_slot()
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


# Section 7b: exact UID991 owner-approved restart reconciliation.
# This source-only helper is invoked only by the root-owned generation3
# service before accepting the inherited broker Unix socket.
def _reconcile_interrupted_first_successor_before_receive() -> None:
    """Restore original signed blue0.15 from a provable incomplete journal.

    The original signed 0.15.0 is a known immutable trust anchor. Only a
    generation3 root-owned source and UID991 may inspect this protected
    per-product durable journal. PREPARED/CANDIDATE_READY/ROLLBACK_PENDING
    means the signed first successor never completed a replay-confirmed
    transition. Reuse the existing exact RootlessKit/Canary/old-container
    recovery, then HARD HOLD for independent review. Do not infer success
    from an incomplete journal, stop a possibly serving green container,
    erase data/volume writes, or switch public ingress.

    SWITCHED could mean replay.finish committed before service interruption;
    without a verified replay status it is intentionally HOLD with NO route
    mutation. A finished or restored journal is also HOLD until the next
    source-reviewed transition is separately approved; only an empty journal
    permits this first-release-only service to receive a new request.
    """
    from .analytics_executor_service_config import (
        load_analytics_executor_service_config,
    )
    from .analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )
    from .analytics_loopback_guard import (
        _recover_reviewed_private_route, _SUCCESSOR_SCOPE,
        _SUCCESSOR_REPOSITORY,
    )
    from .analytics_active_state_review import inspect_committed_analytics_route
    try:
        if (
            (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
            or os.environ.get(_SUCCESSOR_SCOPE) != "1"
        ):
            raise ValueError("no protected positive supervisor")
        source, identities = load_analytics_executor_service_config(
            require_successor=True,
        )
        if (
            type(source) is not dict
            or type(identities) is not dict
            or identities.get("owner_authorized_first_successor") is not True
            or identities.get("expected_executor_uid") != 991
            or identities.get("expected_executor_gid") != 991
        ):
            raise ValueError("no root-reviewed positive generation")
        journal = AnalyticsRouteJournal(
            ROUTE_JOURNAL_DIRECTORY, expected_uid=991, expected_gid=991,
        )
        intent = journal.read()
        if intent is None:
            return None
        if (
            type(intent) is not dict
            or intent.get("previous_slot") != "blue"
            or intent.get("previous_image") != PINNED_IMAGE
            or intent.get("next_slot") != "green"
            or not isinstance(intent.get("next_image"), str)
            or not intent["next_image"].startswith(_SUCCESSOR_REPOSITORY)
        ):
            raise ValueError("foreign route generation")
        if intent.get("phase") in (
            "prepared", "candidate_ready", "rollback_pending",
        ):
            _recover_reviewed_private_route(
                journal=journal,
                request_sha256=intent["request_sha256"],
                previous_slot="blue", previous_image=PINNED_IMAGE,
                previous_id=intent["previous_container_id"],
                next_slot="green", next_image=intent["next_image"],
                next_id=intent["next_container_id"],
            )
            observed = inspect_committed_analytics_route(
                journal=journal, reviewed_image=PINNED_IMAGE,
                reviewed_slot="blue",
                reviewed_container_id=intent["previous_container_id"],
                reviewed_request_sha256=intent["request_sha256"],
            )
            if (
                getattr(observed, "active_slot", None) != "blue"
                or getattr(observed, "active_image", None) != PINNED_IMAGE
            ):
                raise ValueError("restored writer not independently verified")
            sys.stderr.write(
                "TASK014_ANALYTICS_SUCCESSOR_HOLD phase=restart_blue_restored\n"
            )
        # An already SWITCHED transaction is ambiguous with a finished JTI.
        # Do NOT roll it back without the exact independently verified replay
        # status and owner-approved future new-release recovery workflow.
        raise ValueError("previous signed successor requires review")
    except _CONTROL:
        raise
    except Exception:
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None


# Section 8: exact first signed successor coordinator, UNINSTALLED and never
# selected by the existing SO_PEERCRED/SCM_RIGHTS listener. This is deliberately
# Analytics-specific, not a generic release orchestration framework.
def _execute_reviewed_first_successor_transaction(
    canonical_request: bytes, *, credential_fd: int,
    expected_workflow_sha: str, executor: AnalyticsPrivilegedExecutor,
    candidate_operation: object, journal: object,
) -> bytes:
    """Complete one original-blue0.15 -> signed-green private DEV transaction.

    Reuse original UID991 independent Task013 owner/OIDC/Zot/Forgejo/Cosign
    verification, original SQLite replay, sealed FD and hardened Docker
    candidate, then original private 3142 probe and journaled 3141 cutover.
    Verify the committed writer BEFORE finishing replay or returning success.

    On failure after candidate creation, restore the verified old writer
    BEFORE stopping the exact green container. A crash is never interpreted as
    success; the protected journal retains the original request and unfinished
    phase for an independently authorized recovery. No database rollback,
    public port mutation, canary removal, unsignaled image adoption or token
    logging is permitted.

    The real Unix handler remains full-signed-review DENY-only. This helper is
    NOT installed, registered as a request handler or exposed as an operator
    CLI. A future separately owner-approved root-owned service installation
    and independent M04 acceptance must authorize actual invocation.
    """
    from .analytics_active_state_review import (
        AnalyticsActiveState, inspect_analytics_active_state,
        inspect_committed_analytics_route,
        verify_empty_analytics_successor_slot,
    )
    from .analytics_execution import AnalyticsSuccessorRequest
    from .analytics_executor_service_config import (
        load_analytics_executor_service_config,
    )
    from .analytics_first_install import AnalyticsSuccessorCandidateOperation
    from .analytics_loopback_guard import (
        _recover_reviewed_private_route,
        _rollback_committed_private_successor,
        _stage_reviewed_private_candidate_probe,
        _switch_reviewed_private_route,
    )
    from .analytics_private_registry import AnalyticsPrivateZotPullAdapter
    from .analytics_route_journal import (
        AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY,
    )
    from .identity import validate_expected_workflow_sha

    # Section: reject unreviewed generations, collaborators and principals
    # BEFORE reading any host state, registry, journal, replay or Docker.
    try:
        if (
            type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= 16 * 1024
            or type(credential_fd) is not int or credential_fd < 0
            or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
            or type(executor) is not AnalyticsPrivilegedExecutor
            or type(candidate_operation) is not AnalyticsSuccessorCandidateOperation
            or type(journal) is not AnalyticsRouteJournal
            or object.__getattribute__(journal, "_directory")
                != ROUTE_JOURNAL_DIRECTORY
            or object.__getattribute__(journal, "_uid") != 991
            or object.__getattribute__(journal, "_gid") != 991
        ):
            raise ValueError("unreviewed private release principal")
        workflow = validate_expected_workflow_sha(expected_workflow_sha)
        source = dict(object.__getattribute__(executor, "_reviewed_source"))
        if (
            object.__getattribute__(candidate_operation, "_source")
                != tuple(sorted(source.items()))
        ):
            raise ValueError("candidate has a different installed source")
        preflight = object.__getattribute__(executor, "_preflight_successor")
        pull = object.__getattribute__(candidate_operation, "_pull")
        if (
            preflight is None
            or type(preflight.__self__) is not AnalyticsPrivateZotPullAdapter
            or type(pull.__self__) is not AnalyticsPrivateZotPullAdapter
            or preflight.__self__ is not pull.__self__
        ):
            raise ValueError("successor registry/pull uses a different authority")
        # The root-installed source manifest is the ONLY workflow selector,
        # not the request's source_sha field or an environmental variable.
        installed_source, identities = load_analytics_executor_service_config(
            require_successor=True,
        )
        if (
            type(installed_source) is not dict
            or installed_source != source
            or type(identities) is not dict
            or identities.get("expected_workflow_sha") != workflow
            or identities.get("expected_executor_uid") != 991
            or identities.get("expected_executor_gid") != 991
            or identities.get("owner_authorized_first_successor") is not True
        ):
            raise ValueError("no root-approved successor service source")
    except _CONTROL:
        raise
    except Exception:
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    # Section: independently verify signed Task013 evidence and all three
    # original JWTs with the root-pinned workflow and actual signed blue.
    # Never accept a caller-built AnalyticsSuccessorRequest as authority.
    request = _review_executor_successor_signed_release(
        canonical_request, credential_fd,
        expected_workflow_sha=workflow,
        reviewed_installed_source=source,
    )
    if (
        type(request) is not AnalyticsSuccessorRequest
        or request.canonical_bytes() != canonical_request
        or request.exact_image_reference == PINNED_IMAGE
    ):
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    request_hash = hashlib.sha256(canonical_request).hexdigest()
    route = None
    candidate_id = None
    began = False
    replay_begin, replay_finish = object.__getattribute__(executor, "_replay")

    # Section: no replay or mutation before original live-state and sealed
    # credential / registry preflight. The source and original JWTs have
    # already been independently authenticated by the same UID991.
    try:
        original = inspect_analytics_active_state()
        if (
            type(original) is not AnalyticsActiveState
            or original.active_slot != "blue"
            or original.active_image != PINNED_IMAGE
            or original.active_digest != PINNED_DIGEST
            or original.private_ingress_port != 3141
            or original.candidate_slot != "green"
            or original.candidate_probe_present is not False
            or original.candidate_container_id is not None
            or original.candidate_digest is not None
            or original.read_only is not True
            or original.deployment_authorized is not False
        ):
            raise ValueError("original private writer not verified")
        verify_empty_analytics_successor_slot()
        executor.preflight_first_successor_without_deployment(
            canonical_request, credential_fd=credential_fd,
            candidate_ready=False,
        )
        now = int(time.time())
        credential = read_sealed_credential(
            credential_fd, canonical_request=canonical_request,
            image=request.exact_image_reference,
            product_id="analytics-successor", now=now,
        )
        if (
            credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS
            or inspect_analytics_active_state() != original
        ):
            raise ValueError("original state or sealed capability changed")
    except _CONTROL:
        raise
    except Exception:
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    # Section: one original process-local execution gate and SQLite JTI
    # transition. No candidate or route can start until the broker's
    # original durable consume and this executor's begin both succeed.
    if not _ENTER_EXECUTION(executor):
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
    try:
        try:
            result = replay_begin(
                request.oidc_jti, request_hash=request_hash,
                run_id=request.github_run_id,
                run_attempt=request.github_run_attempt,
            )
            if result is not None:
                raise ValueError("invalid replay transition")
            began = True
        except ReplayError:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        # Section: candidate->3142->3141->replay finish. The original
        # scoped FD never enters subprocess argv or service environment.
        try:
            with scoped_private_zot_request(credential_fd, canonical_request):
                candidate_id = candidate_operation.stage_first_successor_green(
                    request,
                )
            if (
                type(candidate_id) is not str
                or len(candidate_id) != 64
                or any(c not in "0123456789abcdef" for c in candidate_id)
            ):
                raise ValueError("unreviewed candidate container identity")
            route = dict(
                previous_slot="blue",
                previous_image=PINNED_IMAGE,
                previous_id=original.active_container_id,
                next_slot="green",
                next_image=request.exact_image_reference,
                next_id=candidate_id,
                journal=journal,
                request_sha256=request_hash,
            )
            if _stage_reviewed_private_candidate_probe(**route) is not None:
                raise ValueError("candidate probe not durably staged")
            # The existing preflight rechecks original Ed25519 source,
            # private 3142 health, actual container digest and signed Zot.
            executor.preflight_first_successor_without_deployment(
                canonical_request, credential_fd=credential_fd,
                candidate_ready=True,
            )
            if _switch_reviewed_private_route(**route) is not None:
                raise ValueError("3141 cutover not durably switched")
            final = inspect_committed_analytics_route(
                journal=journal, reviewed_image=request.exact_image_reference,
                reviewed_slot="green", reviewed_container_id=candidate_id,
                reviewed_request_sha256=request_hash,
            )
            if (
                type(final) is not AnalyticsActiveState
                or final.active_slot != "green"
                or final.active_container_id != candidate_id
            ):
                raise ValueError("green writer does not match durable journal")
            if replay_finish(
                request.oidc_jti, request_hash=request_hash,
                run_id=request.github_run_id,
                run_attempt=request.github_run_attempt,
            ) is not None:
                raise ValueError("invalid replay completion")
            return _build_success_response(request_hash)
        except _CONTROL:
            # Leave the exact fsync journal for a separately reviewed restart
            # recovery after a crash. Never report success during interruption.
            raise
        except Exception:
            # Section: recovery on post-replay failure, avoiding a false
            # rollback claim. A candidate is NEVER stopped while a route
            # could still be serving it. Preserve database writes and Canary.
            if candidate_id is not None and route is not None:
                try:
                    record = journal.read()
                    if (
                        type(record) is not dict
                        or record.get("request_sha256") != request_hash
                        or record.get("previous_container_id")
                            != original.active_container_id
                        or record.get("next_container_id") != candidate_id
                        or record.get("previous_image") != PINNED_IMAGE
                        or record.get("next_image") != request.exact_image_reference
                    ):
                        raise ValueError("foreign or lost route journal")
                    if record["phase"] == "switched":
                        _rollback_committed_private_successor(**route)
                    elif record["phase"] in ("prepared", "candidate_ready", "rollback_pending"):
                        _recover_reviewed_private_route(**route)
                    elif record["phase"] != "restored":
                        raise ValueError("unknown journal recovery state")
                    if journal.read().get("phase") != "restored":
                        raise ValueError("unconfirmed 3141 restoration")
                    inspect_committed_analytics_route(
                        journal=journal, reviewed_image=PINNED_IMAGE,
                        reviewed_slot="blue",
                        reviewed_container_id=original.active_container_id,
                        reviewed_request_sha256=request_hash,
                    )
                    candidate_operation.rollback_staged_successor(
                        request, candidate_id,
                    )
                except _CONTROL:
                    raise
                except Exception:
                    sys.stderr.write(
                        "TASK014_ANALYTICS_SUCCESSOR_HOLD phase=recovery_unconfirmed\n"
                    )
            elif candidate_id is not None:
                # A failure before the route dictionary was constructed.
                # Stop only when independent route inspection proves the
                # unchanged original writer and ABSENT 3142 candidate probe.
                try:
                    observed = inspect_analytics_active_state()
                    if observed != original:
                        raise ValueError("unreviewed route after stage failure")
                    candidate_operation.rollback_staged_successor(
                        request, candidate_id,
                    )
                except _CONTROL:
                    raise
                except Exception:
                    sys.stderr.write(
                        "TASK014_ANALYTICS_SUCCESSOR_HOLD phase=candidate_unconfirmed\n"
                    )
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
    finally:
        _LEAVE_EXECUTION(executor)


__all__ = ("AnalyticsPrivilegedExecutor",)

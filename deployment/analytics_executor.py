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
          end-to-end first-successor staging/cutover/rollback coordinator;
          isolated ordinary signed prior/new release and live-route preflight;
          read-only gen2+ completed-replay restart reconciliation.

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

# Section: closed, local-only generation3 failure observation. Only static
# identifiers may leave the UID991 executor; never an exception or request.
_UID991_FAILURE_PHASES = frozenset({
    "installed_authority", "owner_blue", "signed_identity",
    "sigstore_evidence", "signed_release_binding", "signed_live_recheck",
    "private_preflight",
    "private_principal", "private_owner", "private_active",
    "private_slot", "private_credential", "private_manifest",
    "private_stability", "replay_begin",
    "candidate_stage", "candidate_identity", "candidate_probe",
    "candidate_ready_preflight", "private_route_switch",
    "private_route_verify", "execution_receipt", "replay_finish", "completion_certificate", "signed_success_reply",
})


def _emit_uid991_successor_failure_phase(phase: str) -> None:
    """Best-effort one-line failure stage; never change a rejected decision.

    Only trusted UID991 generation3 call sites select an identifier. Log no
    exception, secret, JTI, signed claim, path, registry status or request ID.
    Failed local stderr must not supersede the original rejected request.
    """
    try:
        if (
            type(phase) is not str or phase not in _UID991_FAILURE_PHASES
            or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
        ):
            return
        sys.stderr.write("TASK014_ANALYTICS_UID991_HOLD phase=" + phase + "\n")
    except _CONTROL:
        raise
    except Exception:
        # Logging and identity checks may not obscure the original denial.
        pass


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
    if 'owner_source_proof' in request:
        from release.analytics_owner_source_selection import verify_owner_signed_source_proof
        selected, proof = verify_owner_signed_source_proof(request['owner_source_proof'])
    else:
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
    trace_generation3: bool = False,
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
    securely installed and accepted. Only the real generation3 transaction
    requests a static local-only failure phase; generation2 stays silent.
    """
    phase = "owner_blue"
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

        phase = "signed_identity"
        now = int(time.time()) if received_at is None else received_at
        identity, registry = _verified_executor_successor_identity_and_credentials(
            canonical_request, credential_fd,
            expected_workflow_sha=expected_workflow_sha,
            jwks_cache=jwks_cache, received_at=now,
        )

        phase = "sigstore_evidence"
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
        public_proof = ({'owner_source_proof': request['owner_source_proof']}
                        if 'owner_source_proof' in request else {})
        signed = acquire_and_review_owner_approved_analytics_release(
            registry, registry, blob, oci, received_at=now,
            approval_file=_OWNER_APPROVAL_FILE,
            signature_file=_OWNER_SIGNATURE_FILE,
            **public_proof,
        )
        if public_proof:
            from release.analytics_owner_source_selection import verify_owner_signed_source_proof
            selected, owner = verify_owner_signed_source_proof(request['owner_source_proof'])
        else:
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
        phase = "signed_release_binding"
        parsed = parse_analytics_successor_request(
            canonical_request, **source,
            signed_release=signed, selected=selected, owner_approval=owner,
            identity=identity,
            observed_active_digest=previous.active_digest,
            observed_active_slot=previous.active_slot,
        )
        # The signed request must pass the unchanged strict parser before
        # a second independent live-state read. Separate fixed local-only
        # failure phases without changing either deny condition or exposing
        # request/JWT/signature/host details.
        if (
            type(parsed) is not AnalyticsSuccessorRequest
            or parsed.exact_image_reference != signed.image
        ):
            raise ValueError("release/host drift during verified source review")
        phase = "signed_live_recheck"
        if inspect_analytics_active_state() != previous:
            raise ValueError("release/host drift during verified source review")
        return parsed
    except _CONTROL:
        raise
    except Exception:
        # The generation2 signed-review-only helper preserves its historic
        # silent behavior; generation3 emits one fixed local-only stage.
        if trace_generation3 is True:
            _emit_uid991_successor_failure_phase(phase)
        # No original JWT, GitHub claim, registry data, verifier argv, owner
        # signature, host/container state or exception detail crosses UID991.
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None


# Section: independent ordinary successor signed predecessor + live route review.
def _review_executor_ordinary_signed_release(
    canonical_request: bytes, credential_fd: int, *,
    expected_workflow_sha: str, reviewed_installed_source: dict[str, str],
    received_at: int | None = None, jwks_cache: object | None = None,
    retirement_journal: object | None = None,
):
    """Independently establish both signed releases and real UID991 active slot.

    This is a read-only ordinary-successor preflight, not a public endpoint,
    replay authority, or installed executor rollout. The prior signed release
    comes exclusively from root-owned approval files, never caller hints.
    OIDC, Zot, Forgejo and Sigstore verification follow the unchanged Task014
    implementation. The actual active Docker/RootlessKit route must match.
    """
    try:
        import json
        from .analytics_active_state_review import (
            AnalyticsActiveState, inspect_analytics_active_state,
            inspect_dormant_analytics_candidate,
        )
        from .analytics_execution import (
            AnalyticsSuccessorRequest, review_analytics_successor_with_live_active,
        )
        from .analytics_signed_release_consumer import (
            AnalyticsSignedEvidenceReview,
            acquire_and_review_owner_approved_analytics_release,
        )
        from .analytics_route_journal import AnalyticsRouteJournal
        from .analytics_unix_boundary import _root_reviewed_source
        from .blob_verifier import CosignReleaseBlobVerifier
        from .oci_verifier import CosignOCISignatureVerifier
        from .policy import canonical_bytes
        from .sigstore_authority_provenance import DevSigstoreVerificationProvenance
        from release.analytics_owner_source_selection import (
            AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
            load_and_verify_owner_signed_source,
            verify_owner_signed_source_proof, expected_owner_approval_bytes,
        )
        if (
            (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
            or type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= 16 * 1024
            or type(credential_fd) is not int or credential_fd < 0
            or type(expected_workflow_sha) is not str
            or received_at is not None and (
                type(received_at) is not int or received_at < 0
            )
        ):
            raise ValueError("invalid ordinary signed executor principal")
        source = dict(_root_reviewed_source(reviewed_installed_source))

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            """Reject duplicate signed request keys at every level."""
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate signed request field")
                result[key] = value
            return result

        request = json.loads(
            canonical_request.decode("ascii"), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
        )
        if (
            type(request) is not dict or canonical_bytes(request) != canonical_request
            or type(request.get("owner_source_proof")) is not str
            or not 0 < len(request["owner_source_proof"]) <= 2048
        ):
            raise ValueError("invalid signed ordinary request")
        _successor_request_image(canonical_request)
        _verify_executor_owner_source(request)
        live = inspect_analytics_active_state()
        if (
            type(live) is not AnalyticsActiveState
            or live.read_only is not True
            or live.deployment_authorized is not False
            or live.active_slot not in ("blue", "green")
            or live.candidate_slot == live.active_slot
            or live.candidate_probe_present
            or live.private_ingress_port != 3141
            or live.candidate_port != ANALYTICS_SUCCESSOR_CANDIDATE_PORT
        ):
            raise ValueError("unreviewed current active writer")

        now = int(time.time()) if received_at is None else received_at
        identity, registry = _verified_executor_successor_identity_and_credentials(
            canonical_request, credential_fd,
            expected_workflow_sha=expected_workflow_sha,
            jwks_cache=jwks_cache, received_at=now,
        )
        toolchain = dict(
            DevSigstoreVerificationProvenance().broker_service_configuration_kwargs()
        )
        if set(toolchain) != {
            "cosign_version", "cosign_binary_sha256",
            "sigstore_trusted_root_sha256",
        }:
            raise ValueError("unreviewed signature tools")
        verifier = dict(
            expected_cosign_version=toolchain["cosign_version"],
            expected_binary_sha256=toolchain["cosign_binary_sha256"],
            expected_trusted_root_sha256=toolchain["sigstore_trusted_root_sha256"],
            broker_uid=991, broker_gid=991,
        )
        blob = CosignReleaseBlobVerifier(**verifier)
        oci = CosignOCISignatureVerifier(
            **verifier, zot_credential_provider=registry, product_id="analytics",
        )
        previous_selected, previous_owner = load_and_verify_owner_signed_source(
            _OWNER_APPROVAL_FILE, _OWNER_SIGNATURE_FILE,
        )
        previous_signed = acquire_and_review_owner_approved_analytics_release(
            registry, registry, blob, oci, received_at=now,
            approval_file=_OWNER_APPROVAL_FILE,
            signature_file=_OWNER_SIGNATURE_FILE,
        )
        new_selected, new_owner = verify_owner_signed_source_proof(
            request["owner_source_proof"],
        )
        new_signed = acquire_and_review_owner_approved_analytics_release(
            registry, registry, blob, oci, received_at=now,
            approval_file=None, signature_file=None,
            owner_source_proof=request["owner_source_proof"],
        )
        for signed, selected, owner in (
            (previous_signed, previous_selected, previous_owner),
            (new_signed, new_selected, new_owner),
        ):
            if (
                type(signed) is not AnalyticsSignedEvidenceReview
                or type(selected) is not AnalyticsOwnerSourceSelection
                or type(owner) is not AnalyticsOwnerSignatureReceipt
                or owner.owner_signature_verified is not True
                or signed.release_version != selected.release_version
                or selected.release_version != owner.release_version
                or signed.source.source_commit != selected.source_commit
                or signed.source.source_tree != selected.source_tree
                or selected.source_commit != owner.source_commit
                or selected.source_tree != owner.source_tree
                or owner.approval_sha256 != hashlib.sha256(
                    expected_owner_approval_bytes(selected)
                ).hexdigest()
                or signed.deployment_authorized is not False
            ):
                raise ValueError("previous/new signed source mismatch")
        # Before the next blue slot can become empty, its exact stopped
        # historical rollback container must be authenticated read-only.
        # The default review still requires a genuinely EMPTY candidate.
        original_route = None
        if retirement_journal is not None:
            if (
                type(retirement_journal) is not AnalyticsRouteJournal
                or retirement_journal.exclusive_active() is not True
            ):
                raise ValueError("no protected pre-retirement journal custody")
            original_route = retirement_journal.read()
            if (
                type(original_route) is not dict
                or original_route.get("phase") != "switched"
                or original_route.get("next_slot") != live.active_slot
                or original_route.get("next_image") != previous_signed.image
                or original_route.get("next_container_id") != live.active_container_id
                or original_route.get("previous_slot") != live.candidate_slot
                # The ORIGINAL Task013 0.15 signed release is a concrete
                # existing trust pin, not a caller-controlled prior image.
                or original_route.get("previous_image") != PINNED_IMAGE
                or original_route.get("previous_container_id") == live.active_container_id
            ):
                raise ValueError("unknown previously signed dormant writer")
            inspect_dormant_analytics_candidate(
                active=live, expected_slot=live.candidate_slot,
                expected_image=PINNED_IMAGE,
                expected_container_id=original_route["previous_container_id"],
                allow_running_standby=True,
            )
            if retirement_journal.read() != original_route:
                raise ValueError("historical signed rollback journal changed")
        if (
            previous_signed.image == new_signed.image
            or tuple(map(int, previous_signed.release_version.split("."))) >=
               tuple(map(int, new_signed.release_version.split(".")))
            or previous_signed.image != live.active_image
            or previous_signed.source.oci_manifest_digest != live.active_digest
        ):
            raise ValueError("signed prior image differs from actual writer")
        reviewed = review_analytics_successor_with_live_active(
            canonical_request, signed_previous=previous_signed,
            signed_release=new_signed, selected=new_selected,
            owner_approval=new_owner, identity=identity,
            require_empty_candidate=(retirement_journal is None), **source,
        )
        if (
            type(reviewed) is not AnalyticsSuccessorRequest
            or reviewed.canonical_bytes() != canonical_request
            or inspect_analytics_active_state() != live
            or (retirement_journal is not None
                and retirement_journal.read() != original_route)
        ):
            raise ValueError("ordinary source or active route changed")
        return reviewed
    except _CONTROL:
        raise
    except Exception:
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
        candidate_ready: bool = True, trace_generation3: bool = False,
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
        if type(candidate_ready) is not bool or type(trace_generation3) is not bool:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        # Only approved generation3 opts into one constant local-only phase;
        # original read-only/legacy callers remain silent by default.
        phase = "private_principal"
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
            # public proof is checked against the same fixed root-controlled
            # signer; legacy file paths cannot be selected by the request.
            phase = "private_owner"
            _verify_executor_owner_source(parsed)
            phase = "private_active"
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
            phase = "private_slot"
            if not candidate_ready:
                verify_empty_analytics_successor_slot()
            phase = "private_credential"
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=image, product_id="analytics-successor", now=now,
            )
            if credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS:
                raise ValueError("private registry credential TTL insufficient")
            phase = "private_manifest"
            preflight = object.__getattribute__(self, "_preflight_successor")
            if preflight is None or preflight(canonical_request, credential_fd) is not None:
                raise ValueError("no verified immutable successor manifest")
            # Reinspect the still-active signed 0.15.0 and the candidate
            # after the bounded remote registry read; reject any TOCTOU drift.
            phase = "private_stability"
            if inspect_analytics_active_state() != observed:
                raise ValueError("host state changed during review")
            if not candidate_ready:
                verify_empty_analytics_successor_slot()
            return None
        except _CONTROL:
            raise
        except Exception:
            if trace_generation3 is True:
                _emit_uid991_successor_failure_phase(phase)
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
def _read_analytics_execution_status(guard: object, request_hash: str) -> str | None:
    """Read one completion through the unchanged C13 store custody checks.

    Analytics owns this consumer; the frozen shared Canary source/API is not
    widened. This result alone authenticates neither an image nor a container.
    """
    import re
    import sqlite3
    from .identity import ReplayUnavailableError
    from .replay_sqlite import REPLAY_FILENAME, SQLiteReplayGuard
    if (type(guard) is not SQLiteReplayGuard or type(request_hash) is not str
            or re.fullmatch(r'[0-9a-f]{64}', request_hash) is None
            or request_hash == '0' * 64):
        raise ReplayUnavailableError('replay storage is unavailable')
    directory_descriptor: int | None = None
    database_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    failed = False
    observed_status = None
    try:
        directory_descriptor = guard._open_directory()
        guard._validate_quiescent_filesystem(directory_descriptor)
        database_descriptor = os.open(
            REPLAY_FILENAME, os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=directory_descriptor,
        )
        guard._validate_bound_file(directory_descriptor, database_descriptor)
        bound_path = Path(f"/proc/self/fd/{database_descriptor}")
        connection = sqlite3.connect(
            bound_path.as_uri() + "?mode=ro", uri=True,
            timeout=guard._busy_timeout_ms / 1000, isolation_level=None,
        )
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute(f"PRAGMA busy_timeout={guard._busy_timeout_ms}")
        guard._validate_bound_file(directory_descriptor, database_descriptor)
        connection.execute("BEGIN")
        guard._validate_open_store(connection, require_connection_limit=False)
        if request_hash is not None:
            rows = connection.execute(
                "SELECT status FROM consumptions WHERE executor_request_sha256 = ?",
                (request_hash,),
            ).fetchmany(2)
            if len(rows) > 1:
                raise ReplayUnavailableError('replay storage is unavailable')
            if rows:
                observed_status = rows[0][0]
        connection.execute("ROLLBACK")
        guard._validate_quiescent_filesystem(directory_descriptor)
        guard._validate_bound_file(directory_descriptor, database_descriptor)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        failed = True
    finally:
        if connection is not None:
            try:
                connection.close()
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                failed = True
        if database_descriptor is not None:
            try:
                os.close(database_descriptor)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                failed = True
        if directory_descriptor is not None:
            try:
                os.close(directory_descriptor)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                failed = True
    if failed:
        raise ReplayUnavailableError('replay storage is unavailable') from None
    return observed_status


# Section: exact original signed0.16.0 after owner-approved generation2 OAT.
def _review_root_attested_legacy_0160_restart(
    *, journal: object, intent: dict[str, object], identities: dict[str, object],
) -> None:
    """Read-only legacy OAT migration gate; NO replay resurrection.

    This is the ONLY accepted exception to generation2 schema3-completion
    requirements. The UID991 reader must verify a separately ROOT-minted
    root:991 0440 certificate whose creation requires full historical root
    receipts. No caller, release token, arbitrary image or journal alone may
    mint or select it. A consumed/in-progress original replay always denies.
    """
    from .analytics_route_journal import AnalyticsRouteJournal
    from .analytics_active_state_review import inspect_committed_analytics_route
    from .analytics_route_journal import (
        LEGACY_REQUEST, LEGACY_IMAGE, LEGACY_GREEN, LEGACY_VERSION,
        LEGACY_SOURCE, LEGACY_PLATFORM_SOURCE, LEGACY_FINAL_SHA,
        read_root_legacy_certificate,
    )
    from .replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
    # This is an exceptional ROOT-ATTESTED HISTORICAL OAT, not a new
    # release request. The exact archived signed0.16.0 final root receipt
    # was independently verified at root with its pinned SHA during the
    # one-time certificate mint. New ordinary releases still verify BOTH
    # live Ed25519 owner-signed identities from canonical schema3 evidence.
    if (
        type(journal) is not AnalyticsRouteJournal
        or type(intent) is not dict or type(identities) is not dict
        or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
            != (991, 991, 991, 991)
        or intent.get("generation") != 2
        or intent.get("phase") != "switched"
        or intent.get("request_sha256") != LEGACY_REQUEST
        or intent.get("next_image") != LEGACY_IMAGE
        or intent.get("next_container_id") != LEGACY_GREEN
        or intent.get("next_slot") != "green"
    ):
        raise ValueError("untrusted legacy release lineage")
    replay = SQLiteReplayGuard(
        PRODUCTION_REPLAY_DATABASE,
        expected_directory_uid=identities["expected_replay_directory_uid"],
        expected_directory_gid=identities["expected_replay_directory_gid"],
        expected_broker_uid=identities["expected_broker_uid"],
        expected_executor_uid=identities["expected_executor_uid"],
    )
    status = _read_analytics_execution_status(replay, LEGACY_REQUEST)
    if status not in (None, "finished"):
        raise ValueError("legacy release was not completed")
    certificate = read_root_legacy_certificate(journal, intent)
    if type(certificate) is not dict:
        raise ValueError("legacy root completion certificate unavailable")
    # The historical 0.16.0 signer bytes were verified in the ORIGINAL
    # signed Task014 and are now preserved by the exact root-owned final
    # receipt SHA256, not by the generic pre-existing 0.15.0 owner file.
    # The latter cannot prove this different historical signed version.
    if (
        certificate.get("final_release_receipt_sha256") != LEGACY_FINAL_SHA
        or certificate.get("owner_approved_product_source") != LEGACY_SOURCE
        or certificate.get("owner_approved_platform_source")
            != LEGACY_PLATFORM_SOURCE
    ):
        raise ValueError("root-attested original signed release is not approved")
    observed = inspect_committed_analytics_route(
        journal=journal, reviewed_image=LEGACY_IMAGE,
        reviewed_slot="green", reviewed_container_id=LEGACY_GREEN,
        reviewed_request_sha256=LEGACY_REQUEST,
    )
    if (
        getattr(observed, "active_slot", None) != "green"
        or getattr(observed, "active_image", None) != LEGACY_IMAGE
        or getattr(observed, "active_container_id", None) != LEGACY_GREEN
        or journal.read() != intent
        or read_root_legacy_certificate(journal, intent) != certificate
        or _read_analytics_execution_status(replay, LEGACY_REQUEST)
            not in (None, "finished")
    ):
        raise ValueError("legacy signed route changed during review")
    return None


# Section: root-proven second-and-later successful private route restart.
def _review_completed_ordinary_successor_restart(
    *, journal: object, intent: dict[str, object], identities: dict[str, object],
) -> None:
    """Admit only fully finished, signed, exact-route ordinary deployment.

    An offline restart has no fresh CI OIDC/registry JWT to re-fetch Task013.
    Therefore it MUST reuse independently protected root owner signatures,
    the exact original signed request persisted before replay.finish, the
    original durable FINISHED SQLite replay, verified local OCI RepoDigests,
    Canary and unchanged RootlessKit routing. A missing previous/next signer
    or changed request/receipt fails closed; no Docker/route mutation or
    replacement credential is minted. Incomplete gen2+ is hard HOLD until
    separately authorized recovery, not an accidental promotion.
    """
    from .analytics_route_journal import AnalyticsRouteJournal
    from .analytics_active_state_review import inspect_committed_analytics_route
    from .replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
    from release.analytics_owner_source_selection import (
        AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
        load_and_verify_owner_signed_source,
        verify_owner_signed_source_proof, expected_owner_approval_bytes,
    )
    from .policy import canonical_bytes
    import json
    if (
        type(journal) is not AnalyticsRouteJournal
        or type(intent) is not dict
        or type(identities) is not dict
        or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
            != (991, 991, 991, 991)
        or type(intent.get("generation")) is not int
        or intent["generation"] < 2
        or intent.get("phase") != "switched"
        or intent.get("previous_slot") not in ("blue", "green")
        or intent.get("next_slot") not in ("blue", "green")
        or intent["previous_slot"] == intent["next_slot"]
        or intent.get("request_sha256") == "0" * 64
    ):
        raise ValueError("ordinary restart not independently authorized")
    # The exact UID991/UID990 shared replay database is the SAME one used
    # in the original protected first successor; never a new success store.
    replay = SQLiteReplayGuard(
        PRODUCTION_REPLAY_DATABASE,
        expected_directory_uid=identities["expected_replay_directory_uid"],
        expected_directory_gid=identities["expected_replay_directory_gid"],
        expected_broker_uid=identities["expected_broker_uid"],
        expected_executor_uid=identities["expected_executor_uid"],
    )
    request_hash = intent["request_sha256"]
    status = _read_analytics_execution_status(replay, request_hash)
    completed = journal.read_completed_release(request_hash)
    # A pruned historical FINISHED replay is NOT a live authorization; only
    # a prior immutable post-FINISHED certificate, with the full original
    # owner/source/live-route review below, can prove this old completion.
    if status not in (None, "finished") or type(completed) is not dict:
        # Even a still-retained FINISHED row is not sufficient alone for a
        # future ordinary release. A crash between replay.finish and fsynced
        # completion must HOLD now, not work once then fail after TTL pruning.
        raise ValueError("no durable ordinary signed completion")
    proof = journal.read_execution(request_hash)
    if (
        type(proof) is not dict
        or proof.get("image") != intent["next_image"]
        or proof.get("container_id") != intent["next_container_id"]
        or type(proof.get("canonical_request")) is not bytes
        or hashlib.sha256(proof["canonical_request"]).hexdigest() != request_hash
    ):
        raise ValueError("ordinary journal differs from protected replay")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Reject all duplicate nested source/owner or rollback fields."""
        seen: dict[str, object] = {}
        for name, value in pairs:
            if name in seen:
                raise ValueError("ambiguous protected signed request")
            seen[name] = value
        return seen

    raw = json.loads(
        proof["canonical_request"].decode("ascii"),
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError),
    )
    if (
        type(raw) is not dict
        or canonical_bytes(raw) != proof["canonical_request"]
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 3
        or raw.get("stage") != "dev"
        or raw.get("product_id") != "analytics"
        or raw.get("exact_image_reference") != intent["next_image"]
        or raw.get("manifest_digest") != intent["next_image"].rsplit("@", 1)[-1]
        or type(raw.get("owner_source_proof")) is not str
        or not 0 < len(raw["owner_source_proof"]) <= 2048
        or type(raw.get("rollback_reference")) is not dict
        or raw["rollback_reference"].get("previous_digest")
            != intent["previous_image"].rsplit("@", 1)[-1]
        or raw["rollback_reference"].get("previous_slot") != intent["previous_slot"]
        or type(raw.get("ingress_reference")) is not dict
        or raw["ingress_reference"].get("active_slot") != intent["previous_slot"]
        or raw["ingress_reference"].get("slot") != intent["next_slot"]
    ):
        raise ValueError("ordinary executed request does not bind private route")
    # Verify BOTH owner approvals using the same original protected root trust,
    # never accept an unsigned durable request as source of release identity.
    prior, prior_owner = load_and_verify_owner_signed_source(
        _OWNER_APPROVAL_FILE, _OWNER_SIGNATURE_FILE,
    )
    selected, owner = verify_owner_signed_source_proof(raw["owner_source_proof"])
    for selection, receipt in ((prior, prior_owner), (selected, owner)):
        if (
            type(selection) is not AnalyticsOwnerSourceSelection
            or type(receipt) is not AnalyticsOwnerSignatureReceipt
            or receipt.owner_signature_verified is not True
            or selection.release_authorized is not False
            or selection.deployment_authorized is not False
            or receipt.release_authorized is not False
            or receipt.deployment_authorized is not False
            or selection.source_commit != receipt.source_commit
            or selection.source_tree != receipt.source_tree
            or selection.release_version != receipt.release_version
            or receipt.approval_sha256 != hashlib.sha256(
                expected_owner_approval_bytes(selection)
            ).hexdigest()
        ):
            raise ValueError("untrusted prior or next owner signature")
    if (
        tuple(map(int, prior.release_version.split("."))) >=
            tuple(map(int, selected.release_version.split(".")))
        or selected.release_version != raw.get("release_version")
        or selected.source_commit != raw.get("product_source_sha")
        or selected.platform_workflow_commit != raw.get("source_sha")
        or owner.approval_sha256 != raw.get("owner_approval_sha256")
        or raw.get("source_sha") == "0" * 40
    ):
        raise ValueError("signed release owner identity changed after commit")
    observed = inspect_committed_analytics_route(
        journal=journal, reviewed_image=proof["image"],
        reviewed_slot=intent["next_slot"],
        reviewed_container_id=proof["container_id"],
        reviewed_request_sha256=request_hash,
    )
    if (
        getattr(observed, "active_slot", None) != intent["next_slot"]
        or getattr(observed, "active_image", None) != intent["next_image"]
        or getattr(observed, "active_container_id", None) != intent["next_container_id"]
        or journal.read() != intent
        or journal.read_execution(request_hash) != proof
        or _read_analytics_execution_status(replay, request_hash)
            not in (None, "finished")
        or completed.get("request_sha256") != request_hash
        or completed.get("image") != intent["next_image"]
        or completed.get("container_id") != intent["next_container_id"]
        or completed.get("canonical_request_sha256") != request_hash
        or journal.read_completed_release(request_hash) != completed
    ):
        raise ValueError("ordinary signed active route changed during restart")
    return None


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

    SWITCHED plus an immutable independently recorded request/container proof,
    its exact protected FINISHED replay and unchanged verified live route
    permits a read-only restart. Legacy/missing/ambiguous completion is still
    HOLD without route mutation. This does not replay the old request
    or widen the first-successor-only admission contract for a new release.
    A restored journal still requires separately authorized recovery.
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
            or not (
                identities.get("owner_authorized_first_successor") is True
                or identities.get("owner_authorized_ordinary_successor") is True
            )
            or (
                identities.get("owner_authorized_first_successor") is True
                and identities.get("owner_authorized_ordinary_successor") is True
            )
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
        # Preserve the original generation1 blue0.15->green contract exactly.
        # Later generations must prove signed prior/current source, durable
        # FINISHED replay and actual immutable OCI+Canary private route.
        if type(intent) is dict and type(intent.get("generation")) is int and intent["generation"] >= 2:
            # One exact owner-approved maintenance OAT, never a forged
            # second Task014. Root 0440 lineage attestation MUST exist;
            # without it the historical incident remains hard HOLD.
            from .analytics_route_journal import LEGACY_REQUEST
            if (intent["generation"] == 2
                    and intent.get("request_sha256") == LEGACY_REQUEST):
                return _review_root_attested_legacy_0160_restart(
                    journal=journal, intent=intent, identities=identities,
                )
            return _review_completed_ordinary_successor_restart(
                journal=journal, intent=intent, identities=identities,
            )
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
        if intent.get("phase") == "switched":
            from .replay_sqlite import PRODUCTION_REPLAY_DATABASE, SQLiteReplayGuard
            replay = SQLiteReplayGuard(
                PRODUCTION_REPLAY_DATABASE,
                expected_directory_uid=identities['expected_replay_directory_uid'],
                expected_directory_gid=identities['expected_replay_directory_gid'],
                expected_broker_uid=identities['expected_broker_uid'],
                expected_executor_uid=identities['expected_executor_uid'],
            )
            request_hash = intent['request_sha256']
            if _read_analytics_execution_status(replay, request_hash) != 'finished':
                raise ValueError('committed route has no proven completed execution')
            proof = journal.read_execution(request_hash)
            if (intent['next_image'] != proof['image']
                    or intent['next_container_id'] != proof['container_id']):
                raise ValueError('route intent differs from completed signed request')
            observed = inspect_committed_analytics_route(
                journal=journal, reviewed_image=proof['image'],
                reviewed_slot='green',
                reviewed_container_id=proof['container_id'],
                reviewed_request_sha256=request_hash,
            )
            if (
                getattr(observed, 'active_slot', None) != 'green'
                or getattr(observed, 'active_image', None) != proof['image']
                or getattr(observed, 'active_container_id', None)
                    != proof['container_id']
                or journal.read() != intent
                or journal.read_execution(request_hash) != proof
                or _read_analytics_execution_status(replay, request_hash) != 'finished'
            ):
                raise ValueError('completed execution or live route changed')
            return None
        # No recovery mutation or new request is inferred from restored or
        # ambiguous records. Original signature/OIDC/replay admission remains.
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
        _emit_uid991_successor_failure_phase("installed_authority")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    # Section: independently verify signed Task013 evidence and all three
    # original JWTs with the root-pinned workflow and actual signed blue.
    # Never accept a caller-built AnalyticsSuccessorRequest as authority.
    request = _review_executor_successor_signed_release(
        canonical_request, credential_fd,
        expected_workflow_sha=workflow,
        reviewed_installed_source=source,
        trace_generation3=True,
    )
    if (
        type(request) is not AnalyticsSuccessorRequest
        or request.canonical_bytes() != canonical_request
        or request.exact_image_reference == PINNED_IMAGE
    ):
        _emit_uid991_successor_failure_phase("signed_release_binding")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    request_hash = hashlib.sha256(canonical_request).hexdigest()
    route = None
    candidate_id = None
    began = False
    replay_begin, replay_finish = object.__getattribute__(executor, "_replay")

    # Section: no replay or mutation before original live-state and sealed
    # credential / registry preflight. The source and original JWTs have
    # already been independently authenticated by the same UID991.
    # A traced inner rejection already emits its own single fixed phase.
    # The outer phase is reserved for failures outside that inner call.
    inner_preflight_pending = False
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
        inner_preflight_pending = True
        executor.preflight_first_successor_without_deployment(
            canonical_request, credential_fd=credential_fd,
            candidate_ready=False, trace_generation3=True,
        )
        inner_preflight_pending = False
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
        if not inner_preflight_pending:
            _emit_uid991_successor_failure_phase("private_preflight")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    # Section: one original process-local execution gate and SQLite JTI
    # transition. No candidate or route can start until the broker's
    # original durable consume and this executor's begin both succeed.
    if not _ENTER_EXECUTION(executor):
        _emit_uid991_successor_failure_phase("replay_begin")
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
            _emit_uid991_successor_failure_phase("replay_begin")
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        except _CONTROL:
            raise
        except Exception:
            _emit_uid991_successor_failure_phase("replay_begin")
            raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

        # Section: candidate->3142->3141->replay finish. The original
        # scoped FD never enters subprocess argv or service environment.
        # The phase is fixed code-owned data, never derived from request or
        # registry. Recovery failure is logged separately below.
        phase = "candidate_stage"
        try:
            with scoped_private_zot_request(credential_fd, canonical_request):
                candidate_id = candidate_operation.stage_first_successor_green(
                    request,
                )
            phase = "candidate_identity"
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
            phase = "candidate_probe"
            if _stage_reviewed_private_candidate_probe(**route) is not None:
                raise ValueError("candidate probe not durably staged")
            # The existing preflight rechecks original Ed25519 source,
            # private 3142 health, actual container digest and signed Zot.
            phase = "candidate_ready_preflight"
            executor.preflight_first_successor_without_deployment(
                canonical_request, credential_fd=credential_fd,
                candidate_ready=True, trace_generation3=True,
            )
            phase = "private_route_switch"
            if _switch_reviewed_private_route(**route) is not None:
                raise ValueError("3141 cutover not durably switched")
            phase = "private_route_verify"
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
            phase = "execution_receipt"
            journal.record_execution(canonical_request, candidate_id)
            phase = "replay_finish"
            if replay_finish(
                request.oidc_jti, request_hash=request_hash,
                run_id=request.github_run_id,
                run_attempt=request.github_run_attempt,
            ) is not None:
                raise ValueError("invalid replay completion")
            phase = "signed_success_reply"
            return _build_success_response(request_hash)
        except _CONTROL:
            # Leave the exact fsync journal for a separately reviewed restart
            # recovery after a crash. Never report success during interruption.
            raise
        except Exception:
            # Report the originating failure BEFORE any recovery actions. The
            # existing strict stop/rollback/journal rules remain unchanged.
            _emit_uid991_successor_failure_phase(phase)
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


# Section 9: ordinary signed previous->next private DEV transaction.
# This is a proposed, UNINSTALLED source-only coordinator. Its invocation
# requires a distinct root-reviewed source generation and independent M04
# authorization. The current schema-2 Unix receiver does NOT call it.
def _execute_reviewed_ordinary_successor_transaction(
    canonical_request: bytes, *, credential_fd: int,
    expected_workflow_sha: str, executor: AnalyticsPrivilegedExecutor,
    candidate_operation: object, journal: object,
) -> bytes:
    """Reuse original UID991 signed release, replay, private route and rollback.

    Historical stopped rollback containers are only removed by exact ID AFTER
    durable intent and independent dual-signed source verification. Never
    delete images, volumes, databases or alter Canary3020. A crash or failed
    rollback cannot return success. This function does not install itself.
    """
    from .analytics_active_state_review import (
        AnalyticsActiveState, inspect_analytics_active_state,
        inspect_committed_analytics_route,
    )
    from .analytics_executor_service_config import load_analytics_executor_service_config
    from .analytics_first_install import AnalyticsSuccessorCandidateOperation
    from .analytics_private_registry import AnalyticsPrivateZotPullAdapter
    from .analytics_route_journal import AnalyticsRouteJournal, ROUTE_JOURNAL_DIRECTORY
    from .analytics_loopback_guard import (
        _SUCCESSOR_SCOPE, _verified_slot,
        _stage_reviewed_private_candidate_probe,
        _switch_reviewed_private_route,
        _recover_reviewed_private_route,
        _rollback_committed_private_successor,
    )
    from .identity import validate_expected_workflow_sha
    from .private_registry_pull import scoped_private_zot_request
    # Section: exact protected runtime, source and type boundary before I/O.
    try:
        if (
            type(canonical_request) is not bytes
            or not 0 < len(canonical_request) <= 16 * 1024
            or type(credential_fd) is not int or credential_fd < 0
            or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (991, 991, 991, 991)
            or os.environ.get(_SUCCESSOR_SCOPE) != "1"
            or type(executor) is not AnalyticsPrivilegedExecutor
            or type(candidate_operation) is not AnalyticsSuccessorCandidateOperation
            or type(journal) is not AnalyticsRouteJournal
            or object.__getattribute__(journal, "_directory") != ROUTE_JOURNAL_DIRECTORY
            or object.__getattribute__(journal, "_uid") != 991
            or object.__getattribute__(journal, "_gid") != 991
        ):
            raise ValueError("unauthorized ordinary source principal")
        workflow = validate_expected_workflow_sha(expected_workflow_sha)
        source = dict(object.__getattribute__(executor, "_reviewed_source"))
        preflight = object.__getattribute__(executor, "_preflight_successor")
        pull = object.__getattribute__(candidate_operation, "_pull")
        if (
            object.__getattribute__(candidate_operation, "_source")
                != tuple(sorted(source.items()))
            or preflight is None
            or type(preflight.__self__) is not AnalyticsPrivateZotPullAdapter
            or type(pull.__self__) is not AnalyticsPrivateZotPullAdapter
            or preflight.__self__ is not pull.__self__
        ):
            raise ValueError("unreviewed successor registry or source")
        installed, identities = load_analytics_executor_service_config(
            require_successor=True,
        )
        if (
            type(installed) is not dict or installed != source
            or type(identities) is not dict
            or identities.get("expected_workflow_sha") != workflow
            or identities.get("owner_authorized_ordinary_successor") is not True
            or identities.get("owner_authorized_first_successor") is True
            or identities.get("expected_executor_uid") != 991
            or identities.get("expected_executor_gid") != 991
        ):
            raise ValueError("root-owned generation is not approved")
    except _CONTROL:
        raise
    except Exception:
        _emit_uid991_successor_failure_phase("installed_authority")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    # Section: historical signed release, dormant image and active writer
    # must be verified BEFORE the schema3 JTI begins and any Docker mutation.
    try:
        with journal.exclusive():
            request = _review_executor_ordinary_signed_release(
                canonical_request, credential_fd,
                expected_workflow_sha=workflow,
                reviewed_installed_source=source,
                retirement_journal=journal,
            )
            if request.canonical_bytes() != canonical_request:
                raise ValueError("changed reviewed signed request")
            historical = journal.read()
            old = inspect_analytics_active_state()
            if (
                type(old) is not AnalyticsActiveState
                or historical.get("phase") != "switched"
                or historical["next_image"] != old.active_image
                or historical["next_container_id"] != old.active_container_id
                or historical["next_slot"] != old.active_slot
                or historical["previous_slot"] != old.candidate_slot
                or old.active_digest != request.rollback_reference["previous_digest"]
                or old.active_slot != request.rollback_reference["previous_slot"]
                or old.candidate_slot != request.ingress_reference["slot"]
            ):
                raise ValueError("historical active release mismatch")
            now = int(time.time())
            credential = read_sealed_credential(
                credential_fd, canonical_request=canonical_request,
                image=request.exact_image_reference,
                product_id="analytics-successor", now=now,
            )
            if credential.expires_at - now < MIN_POST_PREFLIGHT_VALIDITY_SECONDS:
                raise ValueError("short registry credential lifetime")
            if preflight(canonical_request, credential_fd) is not None:
                raise ValueError("signed immutable registry preflight failed")
            if inspect_analytics_active_state() != old or journal.read() != historical:
                raise ValueError("active writer changed during registry proof")
    except _CONTROL:
        raise
    except Exception:
        _emit_uid991_successor_failure_phase("private_preflight")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None

    request_hash = hashlib.sha256(canonical_request).hexdigest()
    replay_begin, replay_finish = object.__getattribute__(executor, "_replay")
    if not _ENTER_EXECUTION(executor):
        _emit_uid991_successor_failure_phase("replay_begin")
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
    candidate_id = None
    route = None
    phase = "replay_begin"
    try:
        try:
            if replay_begin(
                request.oidc_jti, request_hash=request_hash,
                run_id=request.github_run_id, run_attempt=request.github_run_attempt,
            ) is not None:
                raise ValueError("invalid replay begin result")
        except ReplayError:
            raise ExecutorRejectedError(EXECUTOR_REJECTED_MESSAGE) from None
        phase = "candidate_stage"
        with journal.exclusive():
            # Recheck the originally authenticated current signed writer.
            if inspect_analytics_active_state() != old or journal.read() != historical:
                raise ValueError("old writer drifted before durable retirement")
            journal.prepare_slot_retirement(
                request_sha256=request_hash,
                active_slot=old.active_slot,
                active_image=old.active_image,
                active_container_id=old.active_container_id,
                dormant_slot=historical["previous_slot"],
                dormant_image=historical["previous_image"],
                dormant_container_id=historical["previous_container_id"],
                next_image=request.exact_image_reference,
            )
            candidate_operation.retire_dormant_rollback_container(
                request=request, journal=journal,
            )
            with scoped_private_zot_request(credential_fd, canonical_request):
                candidate_id = candidate_operation.stage_ordinary_successor(
                    request, journal=journal,
                )
            if (
                type(candidate_id) is not str or len(candidate_id) != 64
                or any(ch not in "0123456789abcdef" for ch in candidate_id)
            ):
                raise ValueError("candidate ID is not exact")
            phase = "candidate_identity"
            next_slot = request.ingress_reference["slot"]
            next_ip = _verified_slot(
                next_slot, request.exact_image_reference, candidate_id,
            )
            journal.begin_after_retirement(
                request_sha256=request_hash,
                next_container_id=candidate_id, next_ip=next_ip,
            )
        route = dict(
            previous_slot=old.active_slot, previous_image=old.active_image,
            previous_id=old.active_container_id,
            next_slot=request.ingress_reference["slot"],
            next_image=request.exact_image_reference,
            next_id=candidate_id, journal=journal,
            request_sha256=request_hash,
        )
        # Section: existing 3142 health, durable 3141 cutover and replay proof.
        phase = "candidate_probe"
        if _stage_reviewed_private_candidate_probe(**route) is not None:
            raise ValueError("private candidate probe was not recorded")
        phase = "candidate_ready_preflight"
        staged = inspect_analytics_active_state()
        if (
            type(staged) is not AnalyticsActiveState
            or staged.active_slot != old.active_slot
            or staged.active_image != old.active_image
            or staged.active_container_id != old.active_container_id
            or staged.candidate_slot != request.ingress_reference["slot"]
            or staged.candidate_probe_present is not True
            or staged.candidate_digest != request.manifest_digest
            or staged.candidate_container_id != candidate_id
            or journal.read().get("phase") != "candidate_ready"
        ):
            raise ValueError("staged candidate signed OCI mismatch")
        phase = "private_route_switch"
        if _switch_reviewed_private_route(**route) is not None:
            raise ValueError("signed candidate private cutover failed")
        phase = "private_route_verify"
        actual = inspect_committed_analytics_route(
            journal=journal, reviewed_image=request.exact_image_reference,
            reviewed_slot=request.ingress_reference["slot"],
            reviewed_container_id=candidate_id,
            reviewed_request_sha256=request_hash,
        )
        if (
            type(actual) is not AnalyticsActiveState
            or actual.active_slot != request.ingress_reference["slot"]
            or actual.active_container_id != candidate_id
        ):
            raise ValueError("committed writer does not match release")
        phase = "execution_receipt"
        journal.record_execution(canonical_request, candidate_id)
        phase = "replay_finish"
        if replay_finish(
            request.oidc_jti, request_hash=request_hash,
            run_id=request.github_run_id,
            run_attempt=request.github_run_attempt,
        ) is not None:
            raise ValueError("replay did not commit")
        # Durable success is separate from expiring JWT/JTI replay retention.
        # Do not answer success until the signed completion is fsynced.
        phase = "completion_certificate"
        journal.record_completed_release(
            canonical_request, candidate_id,
            replay_guard=replay_begin.__self__,
        )
        return _build_success_response(request_hash)
    except _CONTROL:
        raise
    except Exception:
        _emit_uid991_successor_failure_phase(phase)
        # Recovery is deliberately narrowly attempted only with a verified
        # complete route and still-present signed writer. Earlier partial
        # retirement intent remains durable and blocks further promotions.
        if candidate_id is not None:
            try:
                if route is not None:
                    record = journal.read()
                    if (
                        type(record) is not dict
                        or record.get("request_sha256") != request_hash
                        or record.get("previous_image") != old.active_image
                        or record.get("previous_container_id") != old.active_container_id
                        or record.get("next_container_id") != candidate_id
                    ):
                        raise ValueError("untrusted recovery journal")
                    if record["phase"] == "switched":
                        _rollback_committed_private_successor(**route)
                    elif record["phase"] in ("prepared", "candidate_ready", "rollback_pending"):
                        _recover_reviewed_private_route(**route)
                    elif record["phase"] != "restored":
                        raise ValueError("unconfirmed ordinary recovery")
                    if journal.read().get("phase") != "restored":
                        raise ValueError("writer not restored")
                    inspect_committed_analytics_route(
                        journal=journal, reviewed_image=old.active_image,
                        reviewed_slot=old.active_slot,
                        reviewed_container_id=old.active_container_id,
                        reviewed_request_sha256=request_hash,
                    )
                elif inspect_analytics_active_state() != old:
                    raise ValueError("ambiguous pre-route stage")
                candidate_operation.rollback_staged_successor(request, candidate_id)
            except _CONTROL:
                raise
            except Exception:
                sys.stderr.write(
                    "TASK014_ANALYTICS_SUCCESSOR_HOLD phase=recovery_unconfirmed\n"
                )
        raise ExecutorUnavailableError(EXECUTOR_UNAVAILABLE_MESSAGE) from None
    finally:
        _LEAVE_EXECUTION(executor)


__all__ = ("AnalyticsPrivilegedExecutor",)
__all__ = ("AnalyticsPrivilegedExecutor",)

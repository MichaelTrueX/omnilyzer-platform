"""File: deployment/analytics_signed_source_pin.py

Purpose: Compare the ORIGINAL Task014 verified signed-source projection with
         the independently reviewed M01 Analytics Git, OCI and product profile
         identities. A valid signature from the correct release workflow is
         necessary but NOT sufficient to admit a different Analytics revision.

Related: deployment/promotion.py (M05 PR234 SignedExternalSource and
         original Sigstore/OCI verification), deployment/saas_product_contract.py,
         deployment/saas_product_runtime.py,
         deployment/products/analytics-dev.json,
         deployment/products/analytics-runtime-dev.json,
         release/products/analytics-source.json,
         original Task014 broker/executor and policy.py (unchanged).

This is a pure, fail-closed REVIEW boundary; it NEVER returns a release or
deployment permission, constructs a TrustedRelease, or trusts an unsigned claim.
It is not a new verification service, signer or broker admission. The caller
MUST obtain TrustedRelease via original verify_release_evidence after actual
trusted Sigstore + OCI verification, not instantiate the public dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from release.analytics_owner_source_selection import (
    AnalyticsOwnerSignatureReceipt, AnalyticsOwnerSourceSelection,
    AnalyticsOwnerSourceSelectionDenied, expected_owner_approval_bytes,
)

from .policy import (
    APPROVED_OCI_HOST,
    EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER,
    EXPECTED_RELEASE_WORKFLOW,
    DeploymentPolicyError,
    validate_digest,
    validate_sha256,
    validate_source_sha,
    validate_semver,
)
from .promotion import SignedExternalSource, TrustedRelease
from .saas_product_contract import load_reviewed_profile
from .saas_product_runtime import load_review_profile


# Section 1: pinned original M01 acceptance identity. Changing product code
# requires independent review, not a mutable branch / latest tag.
SOURCE_REPOSITORY = "MichaelTrueX/omnilyzer"
SOURCE_COMMIT = "4cdda7faeba57abb3388f9be5c450fe6afb1140d"
SOURCE_TREE = "5c71020a6d9b66b5010386f2743111936a164daa"
CONTEXT_SHA256 = "c4474ae71ac2acf58876c9ab502e009c866fbeb29862ce991374b8396abf092f"
SOURCE_MANIFEST_SHA256 = "d5a8b056581e4f30d4e352d04492b0bf8f8b2560b3b01eda1c679a8b1a0d9a3e"
OCI_REPOSITORY = "omnilyzer/analytics"
ERROR = "Analytics signed source does not match reviewed product identity"
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class AnalyticsSourceReviewReceipt:
    """An inert inspection receipt, not a Task014 deployment grant."""

    source_commit: str
    source_tree: str
    oci_manifest_digest: str
    claim_sha256: str
    product_profile_sha256: str
    runtime_profile_sha256: str
    release_authorized: bool = False
    deployment_authorized: bool = False


def _load_pinned_source() -> dict[str, Any]:
    """Read the packaged immutable original-platform source contract.

    This local trusted file is from the installed reviewed platform source.
    The file is NOT supplied by the remote release request, OCI layers, or
    the caller. Strict key/data equality is validated by this function.
    """
    path = ROOT / "release/products/analytics-source.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise DeploymentPolicyError(ERROR)
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Deny duplicate source-policy fields, even in local review metadata."""
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DeploymentPolicyError(ERROR)
            result[key] = value
        return result

    try:
        data = json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (OSError, ValueError, UnicodeError) as exc:
        raise DeploymentPolicyError(ERROR) from exc
    if (
        type(data) is not dict
        or data.get("source_repository") != SOURCE_REPOSITORY
        or data.get("source_commit") != SOURCE_COMMIT
        or data.get("source_manifest_sha256") != SOURCE_MANIFEST_SHA256
        or type(data.get("source_critical_files")) is not dict
        or len(data["source_critical_files"]) != 49
        or not {"Dockerfile.analytics", ".dockerignore", "lib/server-api-auth.ts",
                "app/readyz/route.ts", "prisma/schema.prisma"}.issubset(
                    data["source_critical_files"]
                )
        or data.get("product") != "analytics"
        or data.get("authorization") != "review-only-not-a-signed-release"
        or not isinstance(data.get("runtime"), dict)
        or data["runtime"].get("http_ready_path") != "/readyz"
        or data["runtime"].get("auth") != "json-bearer-localstorage"
    ):
        raise DeploymentPolicyError(ERROR)
    return data


def _review_exact_signed_analytics_source(
    release: TrustedRelease, *,
    expected_source_commit: str, expected_source_tree: str,
    expected_context_sha256: str,
) -> AnalyticsSourceReviewReceipt:
    """Check signed source/OCI and installed profile boundaries without grants.

    Caller must first validate source approval and original Sigstore/Cosign
    evidence. This helper is deliberately NOT an authorization primitive.
    """
    if type(release) is not TrustedRelease or type(release.external_source) is not SignedExternalSource:
        raise DeploymentPolicyError(ERROR)
    claim = release.external_source
    try:
        validate_semver(release.release_version)
        validate_source_sha(release.source_sha)
        validate_digest(release.manifest_digest)
        validate_digest(claim.oci_manifest_digest)
        validate_sha256(claim.build_context_sha256, "source context")
        validate_sha256(claim.product_profile_sha256, "product profile")
        validate_sha256(claim.runtime_profile_sha256, "runtime profile")
        validate_sha256(claim.oci_archive_sha256, "archive hash")
        validate_sha256(claim.claim_sha256, "claim hash")
        validate_source_sha(claim.source_commit)
        validate_source_sha(claim.source_tree)
    except (TypeError, ValueError) as exc:
        raise DeploymentPolicyError(ERROR) from exc

    product = load_reviewed_profile(ROOT / "deployment/products/analytics-dev.json")
    runtime = load_review_profile(ROOT / "deployment/products/analytics-runtime-dev.json")
    if (
        release.oci_repository != OCI_REPOSITORY
        or release.release_workflow != EXPECTED_RELEASE_WORKFLOW
        or release.certificate_identity != EXPECTED_CERTIFICATE_IDENTITY
        or release.certificate_issuer != EXPECTED_CERTIFICATE_ISSUER
        or release.exact_image_reference != (
            f"{APPROVED_OCI_HOST}/{OCI_REPOSITORY}@{release.manifest_digest}"
        )
        or claim.product_id != "analytics"
        or claim.source_repository != SOURCE_REPOSITORY
        or claim.source_commit != expected_source_commit
        or claim.source_tree != expected_source_tree
        or claim.build_context_sha256 != expected_context_sha256
        or claim.oci_manifest_digest != release.manifest_digest
        or claim.product_profile_sha256 != product.sha256()
        or claim.runtime_profile_sha256 != runtime.sha256()
        or product.source_repository != SOURCE_REPOSITORY
        or product.source_commit != SOURCE_COMMIT
        or product.product_id != "analytics"
        or product.oci_repository != OCI_REPOSITORY
        or runtime.product_id != "analytics"
        or runtime.oci_repository != OCI_REPOSITORY
        or product.app_port != runtime.container_port
        or runtime.container_port != 3000
        or runtime.live_path != "/livez"
        or product.readiness_path != "/readyz"
        or runtime.ready_path != "/readyz"
        or product.secret_names != runtime.runtime_secret_names
    ):
        raise DeploymentPolicyError(ERROR)
    return AnalyticsSourceReviewReceipt(
        source_commit=expected_source_commit,
        source_tree=expected_source_tree,
        oci_manifest_digest=release.manifest_digest,
        claim_sha256=claim.claim_sha256,
        product_profile_sha256=product.sha256(),
        runtime_profile_sha256=runtime.sha256(),
    )


# Section 2: separate read-only successor comparison. No production gate is
# changed. Installed 0.15.0 still calls the old exact-source function above.
def review_signed_analytics_source(release: TrustedRelease) -> AnalyticsSourceReviewReceipt:
    """Retain original 0.15.0 accepted static source and profile identity."""
    _load_pinned_source()
    return _review_exact_signed_analytics_source(
        release, expected_source_commit=SOURCE_COMMIT,
        expected_source_tree=SOURCE_TREE,
        expected_context_sha256=CONTEXT_SHA256,
    )


def review_owner_selected_signed_analytics_source(
    release: TrustedRelease, *, selected: AnalyticsOwnerSourceSelection,
    owner_approval: AnalyticsOwnerSignatureReceipt,
) -> AnalyticsSourceReviewReceipt:
    """Compare owner-bound successor identity with signed Task013 source claim.

    The owner signature receipt must result from real root-key verification,
    NOT caller input. This pure helper CANNOT prove receipt provenance,
    validate original Sigstore/OCI signatures or authorize execution.
    Task014 must call trusted verification before entering this helper.
    """
    try:
        if (
            type(selected) is not AnalyticsOwnerSourceSelection
            or type(owner_approval) is not AnalyticsOwnerSignatureReceipt
            or type(release) is not TrustedRelease
            or selected.release_authorized is not False
            or selected.deployment_authorized is not False
            or selected.independent_review_verified is not False
            or owner_approval.owner_signature_verified is not True
            or owner_approval.release_authorized is not False
            or owner_approval.deployment_authorized is not False
            or owner_approval.independent_review_verified is not False
            or owner_approval.source_commit != selected.source_commit
            or owner_approval.source_tree != selected.source_tree
            or owner_approval.release_version != selected.release_version
            or release.release_version != selected.release_version
            or release.source_sha != selected.platform_workflow_commit
            or selected.owner_actor_id != "130741173"
            or selected.source_commit == SOURCE_COMMIT
            or tuple(map(int, selected.release_version.split("."))) <= (0, 15, 0)
            or validate_sha256(
                owner_approval.signature_sha256, "owner signature hash"
            ) == "0" * 64
            or owner_approval.approval_sha256 != hashlib.sha256(
                expected_owner_approval_bytes(selected)
            ).hexdigest()
            or release.external_source is None
            or release.external_source.owner_approval_sha256
               != owner_approval.approval_sha256
        ):
            raise DeploymentPolicyError(ERROR)
        # Product profile/secret/health/OCI contracts are still checked by
        # original common reviewer. Source context is signed by Task013;
        # its production producer must independently validate the exact Git
        # tree/context and provide authenticated original release evidence.
        if type(release.external_source) is not SignedExternalSource:
            raise DeploymentPolicyError(ERROR)
        return _review_exact_signed_analytics_source(
            release, expected_source_commit=selected.source_commit,
            expected_source_tree=selected.source_tree,
            expected_context_sha256=release.external_source.build_context_sha256,
        )
    except (AnalyticsOwnerSourceSelectionDenied, ValueError, TypeError, AttributeError):
        raise DeploymentPolicyError(ERROR) from None

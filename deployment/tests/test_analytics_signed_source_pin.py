"""File: deployment/tests/test_analytics_signed_source_pin.py

Purpose: Verify independent reviewed Git/source→OCI/profile binding AFTER
         original Task014 signed-release verification and deny source drift.
Related: deployment/analytics_signed_source_pin.py, deployment/promotion.py,
         deployment/saas_product_contract.py, deployment/saas_product_runtime.py.
No actual signature/registry is fabricated or called; positive result is
inert REVIEW only, and never grants broker/executor deployment permission.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment.analytics_signed_source_pin import (
    AnalyticsSourceReviewReceipt,
    review_signed_analytics_source, review_owner_selected_signed_analytics_source,
    SOURCE_COMMIT, SOURCE_TREE, CONTEXT_SHA256,
)
from deployment.policy import (
    DeploymentPolicyError,
    APPROVED_OCI_HOST,
    EXPECTED_RELEASE_WORKFLOW,
    EXPECTED_CERTIFICATE_IDENTITY,
    EXPECTED_CERTIFICATE_ISSUER,
    validate_repository,
)
from deployment.promotion import SignedExternalSource, TrustedRelease
from deployment.saas_product_contract import load_reviewed_profile
from deployment.saas_product_runtime import load_review_profile

from release.analytics_owner_source_selection import (
    AnalyticsOwnerSourceSelection, AnalyticsOwnerSignatureReceipt,
    expected_owner_approval_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64


def fixture() -> TrustedRelease:
    """Create an explicitly synthetic projection for local deny/shape tests."""
    p = load_reviewed_profile(ROOT / "deployment/products/analytics-dev.json")
    r = load_review_profile(ROOT / "deployment/products/analytics-runtime-dev.json")
    claim = SignedExternalSource(
        product_id="analytics",
        source_repository="MichaelTrueX/omnilyzer",
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        build_context_sha256=CONTEXT_SHA256,
        product_profile_sha256=p.sha256(),
        runtime_profile_sha256=r.sha256(),
        oci_archive_sha256="b" * 64,
        oci_manifest_digest=DIGEST,
        claim_sha256="c" * 64,
    )
    return TrustedRelease(
        release_version="0.14.7",
        source_sha="8d321e12ff85d25bf1ea4b8ff4dd0adc7bb8dbf4",
        oci_repository="omnilyzer/analytics",
        manifest_digest=DIGEST,
        exact_image_reference=f"{APPROVED_OCI_HOST}/omnilyzer/analytics@{DIGEST}",
        release_workflow=EXPECTED_RELEASE_WORKFLOW,
        certificate_identity=EXPECTED_CERTIFICATE_IDENTITY,
        certificate_issuer=EXPECTED_CERTIFICATE_ISSUER,
        external_source=claim,
    )


class AnalyticsSignedSourcePinTests(unittest.TestCase):
    """Prevent arbitrary signed Analytics source from reaching product stage."""

    def test_exact_review_identity_yields_no_deployment_permission(self):
        """A matching fixture is an inspection receipt only, NOT a signature."""
        value = review_signed_analytics_source(fixture())
        self.assertIs(type(value), AnalyticsSourceReviewReceipt)
        self.assertEqual(value.source_commit, SOURCE_COMMIT)
        self.assertEqual(value.source_tree, SOURCE_TREE)
        self.assertFalse(value.release_authorized)
        self.assertFalse(value.deployment_authorized)
        with self.assertRaises(DeploymentPolicyError):
            validate_repository("omnilyzer/analytics")

    def test_missing_signed_source_and_wrong_object_denied(self):
        """No unbound canary or arbitrary dictionary accepted as signed claim."""
        good = fixture()
        for candidate in (object(), replace(good, external_source=None),
                          replace(good, external_source={"source_commit": SOURCE_COMMIT})):
            with self.subTest(candidate=type(candidate)), self.assertRaises(DeploymentPolicyError):
                review_signed_analytics_source(candidate)

    def test_unknown_git_revision_or_tree_denied(self):
        """A correctly signed but different Analytics commit still requires review."""
        good = fixture()
        for field, value in (("source_commit", "f" * 40),
                             ("source_tree", "f" * 40),
                             ("build_context_sha256", "f" * 64),
                             ("source_repository", "MichaelTrueX/other")):
            with self.subTest(field=field), self.assertRaises(DeploymentPolicyError):
                review_signed_analytics_source(
                    replace(good, external_source=replace(good.external_source, **{field: value}))
                )

    def test_oci_manifest_and_signer_identity_denied_if_mismatched(self):
        """No cross-registry/certificate/workflow ambiguity or digest substitution."""
        good = fixture()
        mutations = (
            replace(good, oci_repository="omnilyzer/task013-release-canary"),
            replace(good, exact_image_reference="other.invalid/omnilyzer/analytics@" + DIGEST),
            replace(good, release_workflow="wrong"),
            replace(good, certificate_issuer="other.invalid"),
            replace(good, manifest_digest="sha256:" + "d" * 64),
            replace(good, external_source=replace(good.external_source, oci_manifest_digest="sha256:" + "e" * 64)),
        )
        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(DeploymentPolicyError):
                review_signed_analytics_source(candidate)

    def test_profile_fingerprints_and_missing_claim_hash_denied(self):
        """Signed claim must name exactly the installed reviewed product/runtime."""
        good = fixture()
        for field, value in (("product_profile_sha256", "d" * 64),
                             ("runtime_profile_sha256", "e" * 64),
                             ("claim_sha256", "not-a-sha"),
                             ("product_id", "cybersecurity")):
            with self.subTest(field=field), self.assertRaises(DeploymentPolicyError):
                review_signed_analytics_source(replace(
                    good, external_source=replace(good.external_source, **{field: value})
                ))

    def test_mutated_local_review_profile_denied(self):
        """No drift between committed M01 source binding and signed source."""
        good = fixture()
        with patch("deployment.analytics_signed_source_pin._load_pinned_source",
                   side_effect=DeploymentPolicyError("unreviewed source")):
            with self.assertRaises(DeploymentPolicyError):
                review_signed_analytics_source(good)

    def successor_fixture(self):
        """Synthetic signatures are only shape tests, never actual approval."""
        source_sha = "f" * 40
        tree_sha = "e" * 40
        next_version = "0.15.1"
        workflow_sha = "d" * 40
        selected = AnalyticsOwnerSourceSelection(
            source_commit=source_sha, source_tree=tree_sha,
            release_version=next_version,
            platform_workflow_commit=workflow_sha,
            owner_actor_id="130741173",
        )
        owner = AnalyticsOwnerSignatureReceipt(
            source_commit=source_sha, source_tree=tree_sha,
            release_version=next_version,
            approval_sha256=hashlib.sha256(
                expected_owner_approval_bytes(selected)
            ).hexdigest(),
            signature_sha256="a" * 64,
            owner_signature_verified=True,
        )
        previous = fixture()
        successor = replace(
            previous, source_sha=workflow_sha, release_version=next_version,
            external_source=replace(
                previous.external_source,
                source_commit=source_sha, source_tree=tree_sha,
                build_context_sha256="d" * 64,
                owner_approval_sha256=owner.approval_sha256,
            ),
        )
        return selected, owner, successor

    def test_owner_reviewed_successor_matches_original_signed_profile_contract(self):
        """Read-only compare: source/version chosen, old profile and OCI still checked."""
        selected, owner, successor = self.successor_fixture()
        with self.assertRaises(DeploymentPolicyError):
            review_signed_analytics_source(successor)
        review = review_owner_selected_signed_analytics_source(
            successor, selected=selected, owner_approval=owner,
        )
        self.assertEqual(review.source_commit, selected.source_commit)
        self.assertEqual(review.source_tree, selected.source_tree)
        self.assertEqual(review.oci_manifest_digest, DIGEST)
        self.assertFalse(review.release_authorized)
        self.assertFalse(review.deployment_authorized)

    def test_successor_rejects_source_version_workflow_signature_and_oci_drift(self):
        """No source/tree/version/workflow replay or substitution of signed claim."""
        selected, owner, signed = self.successor_fixture()
        examples = (
            (selected, replace(owner, signature_sha256="bad"), signed),
            (selected, replace(owner, owner_signature_verified=False), signed),
            (selected, replace(owner, independent_review_verified=True), signed),
            (selected, replace(owner, release_authorized=True), signed),
            (selected, replace(owner, approval_sha256="0" * 64), signed),
            (selected, replace(owner, source_commit=SOURCE_COMMIT), signed),
            (replace(selected, source_commit=SOURCE_COMMIT), owner, signed),
            (replace(selected, source_tree="d" * 40), owner, signed),
            (replace(selected, release_version="0.15.0"), owner, signed),
            (selected, owner, replace(signed, release_version="0.15.2")),
            (selected, owner, replace(signed, source_sha="c" * 40)),
            (selected, owner, replace(signed, oci_repository="omnilyzer/canary")),
            (selected, owner, replace(signed, manifest_digest="sha256:" + "b" * 64)),
            (selected, owner, replace(signed, certificate_issuer="other.invalid")),
            (selected, owner, replace(signed, external_source=replace(
                signed.external_source, source_tree="c" * 40,
            ))),
            (selected, owner, replace(signed, external_source=replace(
                signed.external_source, product_profile_sha256="0" * 64,
            ))),
            (selected, owner, replace(signed, external_source=replace(
                signed.external_source, runtime_profile_sha256="0" * 64,
            ))),
        )
        for selection_, approval_, release_ in examples:
            with self.subTest(variant=(selection_, approval_, release_)), self.assertRaises(
                DeploymentPolicyError
            ):
                review_owner_selected_signed_analytics_source(
                    release_, selected=selection_, owner_approval=approval_,
                )

    def test_successor_cannot_promote_fake_receipt_as_deployment_permission(self):
        """Even matching public dataclasses cannot authenticate a signer."""
        selected, owner, signed = self.successor_fixture()
        forged = AnalyticsOwnerSignatureReceipt(
            source_commit=selected.source_commit,
            source_tree=selected.source_tree,
            release_version=selected.release_version,
            approval_sha256=owner.approval_sha256,
            signature_sha256=owner.signature_sha256,
            owner_signature_verified=True,
        )
        # The pure reviewer is NOT an authority: a constructed receipt can
        # reproduce it. Only real root trust verification may provide authority.
        report = review_owner_selected_signed_analytics_source(
            signed, selected=selected, owner_approval=forged,
        )
        self.assertFalse(report.release_authorized)
        self.assertFalse(report.deployment_authorized)

    def test_string_not_trusted_source(self):
        """Neither unsigned JSON mapping nor a forged user token is authority."""
        with self.assertRaises(DeploymentPolicyError):
            review_signed_analytics_source({"product_id": "analytics"})


if __name__ == "__main__":
    unittest.main()

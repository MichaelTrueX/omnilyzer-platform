"""File: deployment/tests/test_m05_14_analytics_signed_admission.py

Purpose: Test the Analytics-only signed-source admission contract against
         realistic immutable release projections and tampered source bindings.
Links: deployment/saas_product_contract.py, deployment/promotion.py,
       deployment/saas_product_runtime.py, deployment/products/*.json.
These synthetic tests do not grant release/deployment authority.
"""
from dataclasses import replace
from pathlib import Path
import unittest

from deployment.policy import (
    APPROVED_OCI_HOST, EXPECTED_RELEASE_WORKFLOW,
    EXPECTED_CERTIFICATE_IDENTITY, EXPECTED_CERTIFICATE_ISSUER,
    DeploymentPolicyError,
)
from deployment.promotion import SignedExternalSource, TrustedRelease
from deployment.saas_product_contract import load_reviewed_profile, validate_existing_signed_release
from deployment.saas_product_runtime import load_review_profile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "products/analytics-dev.json"
RUNTIME = ROOT / "products/analytics-runtime-dev.json"
DIGEST = "sha256:" + "a" * 64


class SignedAnalyticsAdmissionTests(unittest.TestCase):
    """No Analytics identity is authorized without matching signed claim."""

    def setUp(self):
        """Construct synthetic values shaped like the original verified result."""
        self.product = load_reviewed_profile(PROFILE)
        self.runtime = load_review_profile(RUNTIME)
        claim = SignedExternalSource(
            product_id="analytics", source_repository=self.product.source_repository,
            source_commit=self.product.source_commit, source_tree="b" * 40,
            build_context_sha256="c" * 64,
            product_profile_sha256=self.product.sha256(),
            runtime_profile_sha256=self.runtime.sha256(),
            oci_archive_sha256="d" * 64, oci_manifest_digest=DIGEST,
            claim_sha256="e" * 64,
        )
        self.release = TrustedRelease(
            release_version="0.15.0", source_sha="f" * 40,
            oci_repository=self.product.oci_repository, manifest_digest=DIGEST,
            exact_image_reference=f"{APPROVED_OCI_HOST}/omnilyzer/analytics@{DIGEST}",
            release_workflow=EXPECTED_RELEASE_WORKFLOW,
            certificate_identity=EXPECTED_CERTIFICATE_IDENTITY,
            certificate_issuer=EXPECTED_CERTIFICATE_ISSUER,
            external_source=claim,
        )

    def test_exact_signed_projection_matches_reviewed_profiles(self):
        """Only exact reviewed source, digest and runtime can pass the filter."""
        self.assertEqual(
            validate_existing_signed_release(self.product, self.release),
            self.release.exact_image_reference,
        )

    def test_no_unsigned_supplied_mapping_can_substitute_for_signed_claim(self):
        """An arbitrary JSON source claim does not override signed evidence."""
        with self.assertRaises(DeploymentPolicyError):
            validate_existing_signed_release(
                self.product, replace(self.release, external_source=None),
                signed_external_source={"source_commit": self.product.source_commit},
            )

    def test_tampering_each_binding_is_denied(self):
        """Reject wrong commit, repository, hashes, OCI digest and signer."""
        mutations = (
            ("source_commit", "0" * 40),
            ("source_repository", "MichaelTrueX/other"),
            ("product_profile_sha256", "0" * 64),
            ("runtime_profile_sha256", "0" * 64),
            ("oci_manifest_digest", "sha256:" + "0" * 64),
            ("product_id", "canary"),
        )
        for key, value in mutations:
            with self.subTest(field=key), self.assertRaises(DeploymentPolicyError):
                validate_existing_signed_release(
                    self.product,
                    replace(self.release, external_source=replace(
                        self.release.external_source, **{key: value},
                    )),
                )
        for mutation in (
            {"certificate_identity": "https://attacker.invalid/workflow"},
            {"oci_repository": "omnilyzer/task013-release-canary"},
            {"exact_image_reference": f"{APPROVED_OCI_HOST}/omnilyzer/analytics:latest"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(DeploymentPolicyError):
                validate_existing_signed_release(self.product, replace(self.release, **mutation))


if __name__ == "__main__":
    unittest.main()

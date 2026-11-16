"""File: deployment/tests/test_direct_dev_prod_preflight.py

Purpose: Source-only negative and positive tests for direct DEV -> PROD
    identity prerequisite without changing the frozen live DEV controller.
Related: deployment/direct_dev_prod_preflight.py, deployment/promotion.py,
    deployment/audit.py, docs/adr/0012-direct-dev-prod-delivery.md.
No actual image, client, audit store or production server is accessed.
"""
from __future__ import annotations

from dataclasses import replace
import unittest

from deployment.direct_dev_prod_preflight import (
    DirectProdPrerequisite,
    check_direct_prod_prerequisite,
)
from deployment.policy import DeploymentPolicyError
from deployment.promotion import verify_release_evidence
from deployment.tests.fixtures import (
    OTHER_DIGEST,
    event,
    evidence,
    oci_signature_result,
    request,
    sigstore_result,
)


def verified():
    """Use the existing synthetic Sigstore/OCI evidence verifier in tests."""
    manifest, provenance = evidence()
    return verify_release_evidence(
        request("prod"), manifest, provenance,
        sigstore_result(), oci_signature_result(),
    )


class DirectProdPromotionTests(unittest.TestCase):
    """Retain immutable identity and reject any non-DEV promotion shortcut."""

    def test_matching_dev_event_is_sufficient_without_staging(self):
        """The new two-host prerequisite has no historical STAGING hop."""
        result = check_direct_prod_prerequisite(
            request("prod"), verified(), [event("dev")],
        )
        self.assertIsInstance(result, DirectProdPrerequisite)
        self.assertEqual(result.dev_event_id, event("dev").event_id)
        self.assertEqual(result.digest, request("prod").manifest_digest)
        self.assertIs(result.can_deploy, False)

    def test_staging_only_cannot_authorize_prod(self):
        """Historical STAGING records do not substitute for real DEV success."""
        with self.assertRaises(DeploymentPolicyError):
            check_direct_prod_prerequisite(
                request("prod"), verified(), [event("staging")],
            )

    def test_historical_staging_is_ignored_when_dev_matches(self):
        """Keep historical schema compatibility, without an extra live stage."""
        result = check_direct_prod_prerequisite(
            request("prod"), verified(), [event("dev"), event("staging")],
        )
        self.assertFalse(result.can_deploy)

    def test_no_dev_success_is_denied(self):
        """Never promote without concrete success evidence from DEV."""
        with self.assertRaises(DeploymentPolicyError):
            check_direct_prod_prerequisite(request("prod"), verified(), [])

    def test_duplicate_matching_dev_success_is_denied(self):
        """Prevent ambiguous or replayed duplicate success markers."""
        with self.assertRaises(DeploymentPolicyError):
            check_direct_prod_prerequisite(
                request("prod"), verified(), [event("dev"), event("dev")],
            )

    def test_different_digest_is_denied(self):
        """The DEV evidence must match the complete immutable PROD digest."""
        with self.assertRaises(DeploymentPolicyError):
            check_direct_prod_prerequisite(
                request("prod"), verified(), [event("dev", OTHER_DIGEST)],
            )

    def test_different_version_or_source_is_denied(self):
        """Version and source SHA are part of exact signed release identity."""
        for field, value in (
            ("release_version", "0.20.0"),
            ("source_sha", "f" * 40),
            ("oci_repository", "an-untrusted-repository"),
        ):
            with self.subTest(field=field), self.assertRaises(DeploymentPolicyError):
                check_direct_prod_prerequisite(
                    request("prod"), replace(verified(), **{field: value}),
                    [event("dev")],
                )

    def test_dev_target_is_not_prod_approval(self):
        """Reject a DEV release request through the direct PROD check."""
        with self.assertRaises(DeploymentPolicyError):
            check_direct_prod_prerequisite(
                request("dev"), verified(), [event("dev")],
            )

    def test_untrusted_object_or_iterator_rejected(self):
        """Do not accept arbitrary audit dictionaries or streaming input."""
        for events in ([{"stage": "dev"}], (event("dev") for _ in range(1)), None):
            with self.subTest(value=type(events).__name__):
                with self.assertRaises(DeploymentPolicyError):
                    check_direct_prod_prerequisite(
                        request("prod"), verified(), events,
                    )

    def test_no_forgeable_approval_or_environment_access(self):
        """A matched preflight is not a signature, owner GO or traffic switch."""
        result = check_direct_prod_prerequisite(
            request("prod"), verified(), [event("dev")],
        )
        self.assertFalse(result.can_deploy)
        self.assertFalse(hasattr(result, "owner_approved"))
        self.assertFalse(hasattr(result, "activate"))
        self.assertFalse(hasattr(result, "rollback"))


if __name__ == "__main__":
    unittest.main()

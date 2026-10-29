"""File: deployment/tests/test_analytics_signed_source_evidence.py

Purpose: Independently exercise the ORIGINAL Task013/014 verified-release
evidence chain when optional Analytics external-source proof is present.
All signatures here are synthetic verifier test results, NOT real Cosign
signatures or approval to promote a product.

Links: deployment/promotion.py (modified original signed evidence parser);
deployment/policy.py (unchanged, canary-only allowlist);
deployment/saas_product_contract.py (still deployment NO-GO);
release/analytics_release_source_binding.py and M05 PR233.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest

from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.promotion import (
    ANALYTICS_REPOSITORY, PromotionRequest, verify_release_evidence,
)
from deployment.tests.fixtures import (
    DIGEST, SOURCE_SHA, evidence, oci_signature_result,
    request, sigstore_result,
)

CLAIM = {
    "schema_version": 1,
    "product_id": "analytics",
    "platform_source_commit": SOURCE_SHA,
    "platform_tree": "a" * 40,
    "source_repository": "MichaelTrueX/omnilyzer",
    "source_commit": "df40b4632a088232de4699d5826641e0cf269dc8",
    "source_tree": "b6b4f5f210d61d2cfef25cfe3f04b55eb8f509a8",
    "source_manifest_sha256": "a" * 64,
    "source_binding_sha256": "b" * 64,
    "source_files_verified": 77,
    "dockerfile_sha256": "c" * 64,
    "dockerignore_sha256": "d" * 64,
    "oci_test_source_sha256": "e" * 64,
    "build_context_sha256": "f" * 64,
    "oci_repository": "omnilyzer/analytics",
    "oci_archive_sha256": "0" * 64,
    "oci_manifest_digest": DIGEST,
    "product_profile_sha256": "1" * 64,
    "runtime_profile_sha256": "2" * 64,
    "readiness_path": "/readyz",
}


def _fixture(*, manifest_claim: dict | None = None,
             provenance_claim: dict | None = None,
             mismatched_archive: bool = False) -> tuple:
    """Create original signed-schema-shaped but UNSIGNED Analytics test blobs."""
    manifest_raw, provenance_raw = evidence()
    manifest = json.loads(manifest_raw)
    provenance = json.loads(provenance_raw)
    manifest["oci"]["repository"] = ANALYTICS_REPOSITORY
    manifest["oci"]["deployment_identity"] = ANALYTICS_REPOSITORY + "@" + DIGEST
    manifest["external_source"] = CLAIM.copy() if manifest_claim is None else manifest_claim
    provenance["external_source"] = CLAIM.copy() if provenance_claim is None else provenance_claim
    provenance["subjects"]["oci_archive_sha256"] = (
        "b" * 64 if mismatched_archive else CLAIM["oci_archive_sha256"]
    )
    provenance_raw = canonical_bytes(provenance)
    manifest["provenance"]["sha256"] = hashlib.sha256(provenance_raw).hexdigest()
    manifest_raw = canonical_bytes(manifest)
    req = replace(
        request(),
        oci_repository=ANALYTICS_REPOSITORY,
        exact_image_reference=f"oci-dev.omnilyzer.ai/{ANALYTICS_REPOSITORY}@{DIGEST}",
        release_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        provenance_sha256=hashlib.sha256(provenance_raw).hexdigest(),
    )
    oci = oci_signature_result()
    oci["repository"] = ANALYTICS_REPOSITORY
    return req, manifest_raw, provenance_raw, sigstore_result(), oci


class AnalyticsSignedExternalSourceTests(unittest.TestCase):
    """Preserve old canary and validate optional signed source post-verification."""

    def test_original_canary_remains_accepted_without_external_source(self) -> None:
        """No new claim required on the unchanged synthetic Task013 canary."""
        manifest, provenance = evidence()
        trusted = verify_release_evidence(
            request(), manifest, provenance, sigstore_result(), oci_signature_result(),
        )
        self.assertIsNone(trusted.external_source)
        self.assertEqual(trusted.oci_repository, "omnilyzer/task013-release-canary")

    def test_analytics_claim_extracted_only_from_original_verified_chain(self) -> None:
        """Both signed blobs must carry the same immutable external Git claim."""
        args = _fixture()
        trusted = verify_release_evidence(*args)
        self.assertEqual(trusted.oci_repository, ANALYTICS_REPOSITORY)
        self.assertEqual(trusted.external_source.source_commit, CLAIM["source_commit"])
        self.assertEqual(trusted.external_source.source_tree, CLAIM["source_tree"])
        self.assertEqual(trusted.external_source.build_context_sha256, CLAIM["build_context_sha256"])
        self.assertEqual(trusted.external_source.oci_archive_sha256, CLAIM["oci_archive_sha256"])
        self.assertEqual(trusted.external_source.product_profile_sha256, CLAIM["product_profile_sha256"])
        self.assertEqual(trusted.external_source.claim_sha256,
                         hashlib.sha256(canonical_bytes(CLAIM)).hexdigest())
        with self.assertRaises(FrozenInstanceError):
            trusted.external_source.source_commit = "a" * 40

    def test_original_canonical_promotion_parser_still_denies_analytics(self) -> None:
        """No product runtime authority is created by recognizing provenance."""
        req = _fixture()[0]
        with self.assertRaises(DeploymentPolicyError):
            PromotionRequest.from_dict(req.to_dict())

    def test_claim_missing_fields_or_added_fields_denied(self) -> None:
        """Require the exact approved source contract with no unknown fields."""
        bad = dict(CLAIM)
        bad.pop("runtime_profile_sha256")
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(*_fixture(manifest_claim=bad, provenance_claim=bad))
        bad = dict(CLAIM, attacker="allowed")
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(*_fixture(manifest_claim=bad, provenance_claim=bad))

    def test_changed_source_claim_in_one_signed_blob_denied(self) -> None:
        """Manifest and provenance cannot disagree on the externally built source."""
        bad = dict(CLAIM, source_commit="f" * 40)
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(*_fixture(provenance_claim=bad))

    def test_wrong_platform_source_and_product_denied(self) -> None:
        """A different platform sha or repository cannot impersonate protected main."""
        for mutation in (
            {"platform_source_commit": "a" * 40},
            {"product_id": "website"},
            {"source_repository": "attacker/example"},
            {"oci_repository": "omnilyzer/task013-release-canary"},
            {"source_files_verified": 50},
            {"readiness_path": "/"},
            {"source_commit": "a" * 39},
            {"build_context_sha256": "bad"},
            {"oci_manifest_digest": "sha256:" + "f" * 64},
        ):
            bad = dict(CLAIM, **mutation)
            with self.subTest(mutation=mutation), self.assertRaises(DeploymentPolicyError):
                verify_release_evidence(*_fixture(manifest_claim=bad, provenance_claim=bad))

    def test_full_oci_archive_digest_differs_from_original_subject_denied(self) -> None:
        """The external Git+OCI claim must bind the entire original build artifact."""
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(*_fixture(mismatched_archive=True))

    def test_invalid_original_signer_results_denied(self) -> None:
        """No signed external claim can replace the existing Cosign checks."""
        req, m, p, sig, oci = _fixture()
        bad_sig = dict(sig, provenance_verified=False)
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(req, m, p, bad_sig, oci)
        bad_oci = dict(oci, verified=False)
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(req, m, p, sig, bad_oci)
        bad_issuer = dict(sig, issuer="https://untrusted.example")
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(req, m, p, bad_issuer, oci)

    def test_original_canary_refuses_any_external_source_field(self) -> None:
        """A future product extension may not loosen canary evidence grammar."""
        manifest_raw, provenance_raw = evidence()
        p = json.loads(provenance_raw)
        m = json.loads(manifest_raw)
        p["external_source"] = CLAIM
        m["external_source"] = CLAIM
        provenance_raw = canonical_bytes(p)
        m["provenance"]["sha256"] = hashlib.sha256(provenance_raw).hexdigest()
        manifest_raw = canonical_bytes(m)
        req = replace(
            request(),
            release_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            provenance_sha256=hashlib.sha256(provenance_raw).hexdigest(),
        )
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(
                req, manifest_raw, provenance_raw,
                sigstore_result(), oci_signature_result(),
            )


if __name__ == "__main__":
    unittest.main()

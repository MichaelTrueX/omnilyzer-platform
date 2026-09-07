from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.promotion import PromotionRequest, verify_release_evidence
from deployment.controller import require_stage_order

from deployment.tests.fixtures import (
    DIGEST,
    OTHER_DIGEST,
    SOURCE_SHA,
    VERSION,
    evidence,
    event,
    oci_signature_result,
    request,
    sigstore_result,
)


class PromotionIdentityTests(unittest.TestCase):
    def test_valid_exact_digest_and_evidence_are_accepted(self) -> None:
        candidate = request()
        manifest, provenance = evidence()
        trusted = verify_release_evidence(
            candidate, manifest, provenance, sigstore_result(), oci_signature_result(),
        )
        self.assertEqual(trusted.exact_image_reference, candidate.exact_image_reference)

    def test_mutable_tag_alone_is_rejected(self) -> None:
        value = request().to_dict()
        value["manifest_digest"] = "0.13.4"
        value["exact_image_reference"] = "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary:0.13.4"
        with self.assertRaises(DeploymentPolicyError):
            PromotionRequest.from_dict(value)

    def test_malformed_digest_is_rejected(self) -> None:
        value = request().to_dict()
        value["manifest_digest"] = "sha256:1234"
        with self.assertRaises(DeploymentPolicyError):
            PromotionRequest.from_dict(value)

    def test_unknown_request_field_is_rejected(self) -> None:
        value = request().to_dict()
        value["credential"] = "not-allowed"
        with self.assertRaises(DeploymentPolicyError):
            PromotionRequest.from_dict(value)

    def test_request_canonical_hash_is_deterministic(self) -> None:
        candidate = request()
        reversed_value = dict(reversed(list(candidate.to_dict().items())))
        self.assertEqual(candidate.canonical_bytes(), PromotionRequest.from_dict(reversed_value).canonical_bytes())
        self.assertEqual(candidate.sha256(), PromotionRequest.from_dict(reversed_value).sha256())

    def test_source_or_version_evidence_mismatch_is_rejected(self) -> None:
        manifest, provenance = evidence()
        for field, value in (("source_commit", "f" * 40), ("platform_version", "0.13.5")):
            document = json.loads(manifest)
            document[field] = value
            changed = canonical_bytes(document)
            candidate = replace(request(), release_manifest_sha256=hashlib.sha256(changed).hexdigest())
            with self.subTest(field=field):
                with self.assertRaises(DeploymentPolicyError):
                    verify_release_evidence(
                        candidate, changed, provenance, sigstore_result(), oci_signature_result(),
                    )

    def test_evidence_digest_mismatch_is_rejected(self) -> None:
        manifest, provenance = evidence()
        document = json.loads(manifest)
        document["oci"]["manifest_digest"] = OTHER_DIGEST
        changed = canonical_bytes(document)
        candidate = replace(request(), release_manifest_sha256=hashlib.sha256(changed).hexdigest())
        with self.assertRaises(DeploymentPolicyError):
            verify_release_evidence(
                candidate, changed, provenance, sigstore_result(), oci_signature_result(),
            )

    def test_untrusted_workflow_issuer_or_signature_is_rejected(self) -> None:
        manifest, provenance = evidence()
        cases = []
        bad_sigstore = sigstore_result()
        bad_sigstore["issuer"] = "https://attacker.invalid"
        cases.append((bad_sigstore, oci_signature_result()))
        bad_oci = oci_signature_result()
        bad_oci["verified"] = False
        cases.append((sigstore_result(), bad_oci))
        for sigstore, oci in cases:
            with self.subTest(sigstore=sigstore, oci=oci):
                with self.assertRaises(DeploymentPolicyError):
                    verify_release_evidence(request(), manifest, provenance, sigstore, oci)


class StageOrderTests(unittest.TestCase):
    def test_dev_initial_promotion_is_allowed(self) -> None:
        require_stage_order(request("dev"), [])

    def test_staging_without_matching_dev_success_is_rejected(self) -> None:
        with self.assertRaises(DeploymentPolicyError):
            require_stage_order(request("staging"), [])

    def test_prod_without_matching_staging_success_is_rejected(self) -> None:
        with self.assertRaises(DeploymentPolicyError):
            require_stage_order(request("prod"), [event("dev")])

    def test_same_exact_digest_dev_staging_prod_is_accepted(self) -> None:
        require_stage_order(request("dev"), [])
        require_stage_order(request("staging"), [event("dev")])
        require_stage_order(request("prod"), [event("staging")])

    def test_changed_digest_between_stages_is_rejected(self) -> None:
        with self.assertRaises(DeploymentPolicyError):
            require_stage_order(request("staging"), [event("dev", OTHER_DIGEST)])


if __name__ == "__main__":
    unittest.main()

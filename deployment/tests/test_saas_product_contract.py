"""File: deployment/tests/test_saas_product_contract.py

Purpose: Fail-closed regression tests of Task 013/014 Analytics product admission.
Related: deployment/saas_product_contract.py, deployment/products/analytics-dev.json,
deployment/policy.py, deployment/promotion.py.

No registry, signing key, Docker daemon, broker, environment variable, network,
database or DEV service is accessed by these tests.
"""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError, EXPECTED_CERTIFICATE_IDENTITY
from deployment.policy import EXPECTED_CERTIFICATE_ISSUER, EXPECTED_RELEASE_WORKFLOW
from deployment.promotion import TrustedRelease
from deployment.saas_product_contract import (
    SaaSProductProfile, load_reviewed_profile, validate_existing_signed_release,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deployment/products/analytics-dev.json"
SOURCE_SHA = "2472d5265688b4f1e18d91f140afe61307ea371b"
DIGEST = "sha256:" + "a" * 64


class SaaSProductContractTest(unittest.TestCase):
    """Check descriptor identity, no-secret constraints and signed admission."""

    def setUp(self) -> None:
        """Load only the real tracked, review-only Analytics descriptor."""
        self.base = json.loads(PROFILE.read_text())
        self.profile = SaaSProductProfile.from_dict(self.base)

    def malformed(self, mutate) -> None:
        """Reject one mutated descriptor rather than silently coercing it."""
        modified = copy.deepcopy(self.base)
        mutate(modified)
        with self.assertRaises(DeploymentPolicyError):
            SaaSProductProfile.from_dict(modified)

    def test_pinned_candidate_round_trip(self) -> None:
        """Accept only the expected cross-repository source and runtime."""
        self.assertEqual(self.profile.product_id, "analytics")
        self.assertEqual(self.profile.source_commit, SOURCE_SHA)
        self.assertEqual(self.profile.readiness_path, "/readyz")
        self.assertEqual(self.profile.oci_repository, "omnilyzer/analytics")
        self.assertEqual(self.profile.to_dict(), self.base)
        self.assertRegex(self.profile.sha256(), r"^[0-9a-f]{64}$")

    def test_source_substitution_rejected(self) -> None:
        """Reject a different source repository, even with a valid SHA."""
        self.malformed(lambda x: x["source"].update(repository="MichaelTrueX/other"))

    def test_invalid_source_commit_rejected(self) -> None:
        """Reject SHA abbreviation and mutable branch identifiers."""
        self.malformed(lambda x: x["source"].update(commit="main"))

    def test_unknown_product_rejected(self) -> None:
        """Do not authorize future SaaS modules by wildcard."""
        self.malformed(lambda x: x.update(product_id="cybersecurity"))

    def test_tagged_oci_repository_rejected(self) -> None:
        """Allow only the reviewed immutable-release repository name."""
        self.malformed(lambda x: x["artifact"].update(repository="omnilyzer/analytics:latest"))

    def test_canary_repo_cannot_impersonate_analytics(self) -> None:
        """The existing Task 013 canary is never an Analytics artifact."""
        self.malformed(lambda x: x["artifact"].update(repository="omnilyzer/task013-release-canary"))

    def test_registry_substitution_rejected(self) -> None:
        """Reject alternate, unaudited registries."""
        self.malformed(lambda x: x["artifact"].update(registry="https://evil.invalid"))

    def test_prod_stage_rejected(self) -> None:
        """The descriptor authorizes metadata review in DEV only."""
        self.malformed(lambda x: x["runtime"].update(stage="prod"))

    def test_wrong_port_rejected(self) -> None:
        """Protect the fixed private Next.js interface."""
        self.malformed(lambda x: x["runtime"].update(app_port=3451))

    def test_port_bool_rejected(self) -> None:
        """A JSON boolean cannot pass as a numeric port."""
        self.malformed(lambda x: x["runtime"].update(app_port=True))

    def test_wrong_probe_rejected(self) -> None:
        """Do not use an admin or unsafe path as an anonymous health probe."""
        self.malformed(lambda x: x["runtime"].update(readiness_path="/api/v1/admin/system-health"))

    def test_legacy_api_readiness_endpoint_rejected(self) -> None:
        """Reject the superseded endpoint absent from the canonical product image."""
        self.malformed(
            lambda value: value["runtime"].update(readiness_path="/api/v1/readyz")
        )

    def test_deprecated_analytics_source_is_not_pinned(self) -> None:
        """Ensure the reviewed descriptor names the OCI-packaged PR42 child."""
        self.assertNotEqual(
            self.profile.source_commit,
            "fad21c3cb63c3befe719298137455f0b86b92c0b",
        )

    def test_database_namespace_rejected(self) -> None:
        """Other products' databases cannot silently replace Analytics PG."""
        self.malformed(lambda x: x["runtime"].update(database="shared-mysql"))

    def test_secret_values_rejected(self) -> None:
        """No secret may be embedded as a runtime config value."""
        self.malformed(lambda x: x["runtime"].update(DATABASE_URL="postgres://exposed"))

    def test_required_secret_names_fixed(self) -> None:
        """All required runtime secret references must be present."""
        self.malformed(lambda x: x["runtime"].update(secret_names=["DATABASE_URL"]))

    def test_unknown_field_rejected(self) -> None:
        """Do not interpret extra unsigned release claims."""
        self.malformed(lambda x: x.update(trusted=True))

    def test_duplicate_json_field_rejected(self) -> None:
        """Avoid last-value-wins in JSON signed evidence input."""
        raw = PROFILE.read_bytes().replace(
            b'"product_id": "analytics",',
            b'"product_id": "analytics", "product_id": "cybersecurity",',
        )
        with self.assertRaises(DeploymentPolicyError):
            SaaSProductProfile.from_json_bytes(raw)

    def test_oversized_json_rejected(self) -> None:
        """Cap metadata before JSON allocation or processing."""
        with self.assertRaises(DeploymentPolicyError):
            SaaSProductProfile.from_json_bytes(b"x" * 4097)

    def test_committed_contract_file_reads(self) -> None:
        """The real native pathlib file path must pass, not only JSON dict parsing."""
        loaded = load_reviewed_profile(PROFILE)
        self.assertEqual(loaded, self.profile)
        self.assertEqual(loaded.sha256(), self.profile.sha256())

    def test_string_input_path_denied(self) -> None:
        """Reject arbitrary non-Path caller inputs without path coercion."""
        with self.assertRaises(DeploymentPolicyError):
            load_reviewed_profile(str(PROFILE))

    def test_profile_file_symlink_rejected(self) -> None:
        """Prevent a mutable symlink redirect to a different descriptor."""
        with tempfile.TemporaryDirectory(prefix="m05-profile-") as d:
            link = Path(d) / "candidate.json"
            link.symlink_to(PROFILE)
            with self.assertRaises(DeploymentPolicyError):
                load_reviewed_profile(link)

    def test_existing_canary_trustedrelease_denied(self) -> None:
        """Even genuine Task 014 canary evidence may not deploy Analytics."""
        release = TrustedRelease(
            release_version="0.14.6",
            source_sha="8d321e12ff85d25bf1ea4b8ff4dd0adc7bb8dbf4",
            oci_repository="omnilyzer/task013-release-canary",
            manifest_digest=DIGEST,
            exact_image_reference=(
                "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@" + DIGEST
            ),
            release_workflow=EXPECTED_RELEASE_WORKFLOW,
            certificate_identity=EXPECTED_CERTIFICATE_IDENTITY,
            certificate_issuer=EXPECTED_CERTIFICATE_ISSUER,
        )
        with self.assertRaises(DeploymentPolicyError):
            validate_existing_signed_release(self.profile, release)

    def test_forged_analytics_release_still_denied(self) -> None:
        """A manually constructed TrustedRelease and unsigned external-source
        mapping never bypass missing Task 013 signed source binding.
        """
        forged = TrustedRelease(
            release_version="0.14.7",
            source_sha="8d321e12ff85d25bf1ea4b8ff4dd0adc7bb8dbf4",
            oci_repository="omnilyzer/analytics",
            manifest_digest=DIGEST,
            exact_image_reference="oci-dev.omnilyzer.ai/omnilyzer/analytics@" + DIGEST,
            release_workflow=EXPECTED_RELEASE_WORKFLOW,
            certificate_identity=EXPECTED_CERTIFICATE_IDENTITY,
            certificate_issuer=EXPECTED_CERTIFICATE_ISSUER,
        )
        with self.assertRaisesRegex(DeploymentPolicyError, "signed external-source provenance"):
            validate_existing_signed_release(
                self.profile,
                forged,
                signed_external_source={
                    "repository": "MichaelTrueX/omnilyzer",
                    "commit": SOURCE_SHA,
                },
            )


if __name__ == "__main__":
    unittest.main()

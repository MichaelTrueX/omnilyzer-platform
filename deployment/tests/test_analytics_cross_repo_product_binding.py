"""File: deployment/tests/test_analytics_cross_repo_product_binding.py

Purpose: Guard one coherent final Analytics source/profile/runtime identity
         across M01 PR225 + M05 PR226/PR227, without creating a second
         release signer, broker, deployer, or policy registry.
Related: release/analytics_source_admission.py,
         release/products/analytics-source.json,
         deployment/products/analytics-dev.json,
         deployment/products/analytics-runtime-dev.json,
         deployment/saas_product_contract.py,
         deployment/saas_product_runtime.py, Task013/014 acceptance docs.

All tests use immutable local tracked JSON. The optional one requiring
OMNILYZER_ANALYTICS_CHECKOUT verifies actual Git blobs, without network.
These assertions are NOT a signature or authorization to deploy.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import unittest

from deployment.policy import DeploymentPolicyError, validate_repository
from deployment.saas_product_contract import (
    SaaSProductProfile, load_reviewed_profile, validate_existing_signed_release,
)
from deployment.saas_product_runtime import load_review_profile
from release.analytics_source_admission import AnalyticsAdmissionError, verify_source

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "release/products/analytics-source.json"
CONTRACT = ROOT / "deployment/products/analytics-dev.json"
RUNTIME = ROOT / "deployment/products/analytics-runtime-dev.json"
FINAL_SOURCE = "4cdda7faeba57abb3388f9be5c450fe6afb1140d"


def validate_local_consistency(source: dict, contract: SaaSProductProfile, runtime) -> None:
    """Reject drift between source pin, signed product claim plan and runtime."""
    if (
        source.get("source_repository") != contract.source_repository
        or source.get("source_commit") != contract.source_commit
        or contract.source_commit != FINAL_SOURCE
        or source.get("product") != contract.product_id
        or contract.product_id != runtime.product_id
        or source.get("runtime", {}).get("http_ready_path") != contract.readiness_path
        or contract.readiness_path != runtime.ready_path
        or runtime.live_path != "/livez"
        or contract.oci_repository != runtime.oci_repository
        or contract.app_port != runtime.container_port
        or contract.secret_names != runtime.runtime_secret_names
        or source.get("authorization") != "review-only-not-a-signed-release"
    ):
        raise DeploymentPolicyError("Analytics cross-repository product contract mismatch")


class AnalyticsCrossRepositoryProductBindingTests(unittest.TestCase):
    """Keep Task013 source, SaaS product plan and Task014 runtime coherent."""

    @classmethod
    def setUpClass(cls):
        """Open actual complete checked-in config files through public loaders."""
        cls.source = json.loads(SOURCE.read_text(encoding="utf-8"))
        cls.contract = load_reviewed_profile(CONTRACT)
        cls.runtime = load_review_profile(RUNTIME)

    def test_real_three_contracts_agree(self):
        """Exercise actual native file read and full route/OCI/secret identity."""
        validate_local_consistency(self.source, self.contract, self.runtime)
        self.assertEqual(self.contract.app_port, 3000)
        self.assertEqual(self.runtime.product_id, "analytics")
        self.assertEqual(self.source["runtime"]["auth"], "json-bearer-localstorage")

    def test_previous_analytics_source_rejected(self):
        """Old PR42 or changing source commit cannot bypass full PR45 admission."""
        bad = copy.deepcopy(self.source)
        bad["source_commit"] = "597a3415dfee76cc63f6ba70d3660f287a09b0c8"
        with self.assertRaises(DeploymentPolicyError):
            validate_local_consistency(bad, self.contract, self.runtime)

    def test_root_or_wrong_readiness_denied(self):
        """A public page responding 200 is not a dual-database /readyz."""
        bad = copy.deepcopy(self.source)
        bad["runtime"]["http_ready_path"] = "/"
        with self.assertRaises(DeploymentPolicyError):
            validate_local_consistency(bad, self.contract, self.runtime)

    def test_profile_oci_or_secret_drift_denied(self):
        """OCI identity and four runtime secret references must agree exactly."""
        bad = copy.deepcopy(self.contract.to_dict())
        bad["runtime"]["secret_names"] = ["DATABASE_URL"]
        with self.assertRaises(DeploymentPolicyError):
            SaaSProductProfile.from_dict(bad)
        bad_runtime = copy.deepcopy(self.runtime.to_dict())
        bad_runtime["oci_repository"] = "omnilyzer/task013-release-canary"
        from deployment.saas_product_runtime import SaaSRuntimeProfile
        with self.assertRaises(DeploymentPolicyError):
            SaaSRuntimeProfile.from_dict(bad_runtime)

    def test_review_only_is_not_release_authority(self):
        """A coherent product descriptor MUST NOT loosen the original executor."""
        validate_local_consistency(self.source, self.contract, self.runtime)
        with self.assertRaises(DeploymentPolicyError):
            validate_repository("omnilyzer/analytics")
        with self.assertRaises(DeploymentPolicyError):
            validate_existing_signed_release(self.contract, object())

    def test_exact_packaged_git_source_optional(self):
        """When a fresh source checkout is provided, verify all 77 real Git blobs."""
        path = os.environ.get("OMNILYZER_ANALYTICS_CHECKOUT")
        if not path:
            self.skipTest("exact trusted Analytics checkout not supplied")
        receipt = verify_source(Path(path), self.source)
        self.assertEqual(receipt["source_files_verified"], 77)
        self.assertEqual(receipt["source_commit"], FINAL_SOURCE)
        self.assertFalse(receipt["release_authorized"])
        self.assertFalse(receipt["deployment_authorized"])


if __name__ == "__main__":
    unittest.main()

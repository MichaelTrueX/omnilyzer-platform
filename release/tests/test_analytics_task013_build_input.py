"""File: release/tests/test_analytics_task013_build_input.py

Purpose: Source/OCI/profile negative and deterministic review-input tests.
Links: release/analytics_task013_build_input.py, M01 source admission,
M05 OCI PR45, M01 product/runtime PR230, original Task013 signer and Task014.
No registry, Docker daemon, privileged executor or live database is accessed.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.saas_product_contract import load_reviewed_profile
from deployment.saas_product_runtime import load_review_profile
from release.analytics_task013_build_input import (
    ROOT, ERROR, _coherent_profiles, _load_object, build_input,
)

SOURCE = ROOT / "release/products/analytics-source.json"
PRODUCT = ROOT / "deployment/products/analytics-dev.json"
RUNTIME = ROOT / "deployment/products/analytics-runtime-dev.json"


class AnalyticsTask013BuildInputTests(unittest.TestCase):
    """Exercise existing signed boundary without claiming any signed release."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load actual reviewed platform JSON files and native profile loaders."""
        cls.source = json.loads(SOURCE.read_text(encoding="utf-8"))
        cls.product = load_reviewed_profile(PRODUCT)
        cls.runtime = load_review_profile(RUNTIME)

    def test_current_three_review_profiles_are_coherent(self) -> None:
        """Prove final PR45 source, /readyz, OCI repo and secrets match."""
        _coherent_profiles(self.source, self.product, self.runtime)
        self.assertEqual(self.source["source_commit"], "df40b4632a088232de4699d5826641e0cf269dc8")

    def test_old_unpacked_git_revision_is_denied(self) -> None:
        """PR42 alone cannot become a signed OCI artifact by profile drift."""
        bad = dict(self.source, source_commit="597a3415dfee76cc63f6ba70d3660f287a09b0c8")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_private_readiness_cannot_use_marketing_root(self) -> None:
        """The root landing page must not satisfy app+collector DB readiness."""
        bad = dict(self.source)
        bad["runtime"] = dict(bad["runtime"], http_ready_path="/")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_changing_oci_repositories_is_denied(self) -> None:
        """No canary repository alias or attacker-controlled module ID."""
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, replace(self.product, oci_repository="omnilyzer/task013-release-canary"), self.runtime)

    def test_port_and_secret_names_are_exact(self) -> None:
        """Secret reference *names*, never values, are part of the review contract."""
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, self.product, replace(self.runtime, container_port=8080))
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(self.source, self.product, replace(self.runtime, runtime_secret_names=("DATABASE_URL",)))

    def test_no_review_profile_can_grant_authority(self) -> None:
        """A caller changing review-only authorization is rejected."""
        bad = dict(self.source, authorization="release-authorized")
        with self.assertRaises(DeploymentPolicyError):
            _coherent_profiles(bad, self.product, self.runtime)

    def test_duplicate_json_members_are_rejected(self) -> None:
        """Reject duplicate-key ambiguity at the input-document boundary."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "review.json"
            path.write_bytes(b'{"product":"analytics","product":"canary"}')
            with self.assertRaises(DeploymentPolicyError):
                _load_object(path)

    def test_local_symlink_review_file_is_denied(self) -> None:
        """Do not load a replaced review profile through a symlink."""
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "real.json"
            link = Path(root) / "link.json"
            source.write_bytes(b'{}')
            link.symlink_to(source)
            with self.assertRaises(DeploymentPolicyError):
                _load_object(link)

    def test_invalid_path_types_denied_without_network(self) -> None:
        """Reject untrusted caller input rather than guessing a checkout."""
        with self.assertRaises(DeploymentPolicyError):
            build_input("/tmp/not-a-path")  # type: ignore[arg-type]
        with self.assertRaises(DeploymentPolicyError):
            build_input(ROOT, platform_root="bad")  # type: ignore[arg-type]

    def test_original_platform_checkout_is_not_analytics(self) -> None:
        """A platform checkout cannot impersonate the separate product source."""
        with self.assertRaises((DeploymentPolicyError, ValueError)):
            build_input(ROOT)

    def test_real_pr45_git_source_and_unsigned_receipt_when_supplied(self) -> None:
        """Read exact 72 pinned Git objects and prove deterministic nonauthority."""
        source = os.environ.get("OMNILYZER_ANALYTICS_CHECKOUT")
        if not source:
            self.skipTest("optional verified local Analytics PR45 checkout not supplied")
        first = build_input(Path(source))
        second = build_input(Path(source))
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first["source_files_verified"], 77)
        self.assertEqual(first["analytics_source_commit"], self.source["source_commit"])
        self.assertEqual(first["readiness_path"], "/readyz")
        self.assertEqual(first["oci_repository"], "omnilyzer/analytics")
        self.assertFalse(first["release_authorized"])
        self.assertFalse(first["deployment_authorized"])
        self.assertEqual(len(first["analytics_tree"]), 40)
        self.assertEqual(len(first["dockerfile_sha256"]), 64)
        self.assertNotIn("manifest_digest", first)
        self.assertNotIn("JWT_SECRET", canonical_bytes(first).decode("utf-8"))
        self.assertNotIn("DATABASE_URL", canonical_bytes(first).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

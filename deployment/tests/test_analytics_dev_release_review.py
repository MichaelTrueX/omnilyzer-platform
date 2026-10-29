"""File: deployment/tests/test_analytics_dev_release_review.py

Purpose: Protect the review-only Analytics Task014 product-specific runtime
         configuration, exact immutable OCI refs, blue/green isolation,
         secret-reference permissions and write-preserving rollback metadata.

Links: deployment/analytics_dev_release_review.py,
       deployment/runtime/dev/analytics.compose.review.yaml,
       deployment/runtime/dev/compose.yaml (original canary unchanged),
       deployment/products/analytics-runtime-dev.json,
       deployment/promotion.py and original Task014 broker/executor.

All inputs are synthetic and local. No product deployment or image signing.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_dev_release_review import (
    ERROR, REQUIRED_SECRET_NAMES, AnalyticsDevRolloutReview,
    compose_image_variables, review_dev_rollout, review_private_secret_paths,
)
from deployment.policy import DeploymentPolicyError, validate_repository

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
CANARY_PATH = Path(__file__).resolve().parents[1] / "runtime/dev/compose.yaml"
ANALYTICS_PATH = Path(__file__).resolve().parents[1] / "runtime/dev/analytics.compose.review.yaml"


class AnalyticsDevRuntimeReviewTests(unittest.TestCase):
    """Verify every review result is inert and distinct from installed canary."""

    def test_first_deployment_is_no_rollback_yet(self):
        """New blue slot has no invented previous release and is not authorized."""
        p = review_dev_rollout(
            release_version="0.15.0", candidate_digest=DIGEST_A, target_slot="blue",
        )
        self.assertIs(type(p), AnalyticsDevRolloutReview)
        self.assertIs(p.release_authorized, False)
        self.assertIs(p.deployment_authorized, False)
        self.assertEqual(p.existing_image, None)
        self.assertEqual(p.existing_slot, None)
        self.assertEqual(p.secret_names, REQUIRED_SECRET_NAMES)
        self.assertEqual(p.ready_path, "/readyz")
        self.assertEqual(p.source_commit, "2472d5265688b4f1e18d91f140afe61307ea371b")
        self.assertEqual(compose_image_variables(p), {
            "ANALYTICS_BLUE_IMAGE": p.proposed_image,
            "ANALYTICS_GREEN_IMAGE": p.proposed_image,
        })
        self.assertNotIn("JWT_SECRET=", json.dumps(p.to_dict()))
        self.assertEqual(p.rollback_kind, "original-task014-immutable-digest-preserve-database-writes")

    def test_next_release_retains_exact_prior_digest_on_other_slot(self):
        """Rollback target is original immutable digest, never a mutable tag."""
        p = review_dev_rollout(
            release_version="0.15.1", candidate_digest=DIGEST_B,
            target_slot="green", active_slot="blue", active_digest=DIGEST_A,
        )
        e = compose_image_variables(p)
        self.assertEqual(e["ANALYTICS_BLUE_IMAGE"], p.existing_image)
        self.assertEqual(e["ANALYTICS_GREEN_IMAGE"], p.proposed_image)
        self.assertIn("@sha256:", e["ANALYTICS_BLUE_IMAGE"])
        self.assertIn("@sha256:", e["ANALYTICS_GREEN_IMAGE"])
        self.assertNotEqual(p.proposed_image, p.existing_image)

    def test_invalid_or_unsafe_inputs_rejected(self):
        """No wrong slot/stage/mutable image/ref/same digest/partial state."""
        base = dict(release_version="0.15.1", candidate_digest=DIGEST_B,
                    target_slot="green", active_slot="blue", active_digest=DIGEST_A)
        bad = [
            dict(candidate_digest=":latest"),
            dict(candidate_digest="sha256:" + "A" * 64),
            dict(candidate_digest="oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@" + DIGEST_B),
            dict(candidate_digest="sha256:" + "0" * 10),
            dict(target_slot="canary-blue"),
            dict(target_slot="blue"),
            dict(active_slot=None),
            dict(active_digest=None),
            dict(active_digest=DIGEST_B),
            dict(release_version="0.15.1-rc1"),
            dict(release_version="latest"),
        ]
        for mutation in bad:
            with self.subTest(mutation=mutation), self.assertRaises(DeploymentPolicyError):
                review_dev_rollout(**{**base, **mutation})
        with self.assertRaises(DeploymentPolicyError):
            validate_repository("omnilyzer/analytics")
        with self.assertRaises(DeploymentPolicyError):
            compose_image_variables(replace(
                review_dev_rollout(release_version="0.15.0", candidate_digest=DIGEST_A,
                                   target_slot="blue"), release_authorized=True,
            ))

    def test_original_canary_compose_is_still_separate_and_unmodified(self):
        """Different project, service, port and secret mechanism from canary."""
        canary = CANARY_PATH.read_text()
        analytics = ANALYTICS_PATH.read_text()
        self.assertIn("name: omnilyzer-task014-dev", canary)
        self.assertIn("127.0.0.1:3020:8080", canary)
        self.assertIn("name: omnilyzer-analytics-dev", analytics)
        self.assertNotIn("127.0.0.1:3020:", analytics)
        self.assertIn("127.0.0.1:3141:3000", analytics)
        self.assertIn("127.0.0.1:3142:3000", analytics)
        self.assertIn("profiles: [\"blue\"]", analytics)
        self.assertIn("profiles: [\"green\"]", analytics)
        self.assertIn('user: "10001:10001"', analytics)
        self.assertIn("read_only: true", analytics)
        self.assertIn("no-new-privileges:true", analytics)
        self.assertIn("external: true", analytics)
        self.assertNotIn("canary-blue", analytics)
        self.assertNotIn("canary-green", analytics)
        self.assertNotIn("JWT_SECRET=sample", analytics)

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose not installed")
    def test_real_docker_compose_config_is_one_profile_only_and_no_secret_values(self):
        """Parse actual Compose config; never start a container or modify host."""
        p = review_dev_rollout(
            release_version="0.15.1", candidate_digest=DIGEST_B,
            target_slot="green", active_slot="blue", active_digest=DIGEST_A,
        )
        env = dict(os.environ, **compose_image_variables(p))
        for selected, excluded in (("green", "analytics-blue"), ("blue", "analytics-green")):
            result = subprocess.run(
                ["docker", "compose", "-f", str(ANALYTICS_PATH),
                 "--profile", selected, "config", "--format", "json"],
                env=env, capture_output=True, text=True, check=True, timeout=20,
            )
            config = json.loads(result.stdout)
            self.assertEqual(config["name"], "omnilyzer-analytics-dev")
            self.assertNotIn(excluded, config["services"])
            service = config["services"]["analytics-" + selected]
            self.assertEqual(service["user"], "10001:10001")
            self.assertEqual(service["image"], compose_image_variables(p)[
                "ANALYTICS_" + selected.upper() + "_IMAGE"])
            self.assertEqual(service["ports"][0]["host_ip"], "127.0.0.1")
            self.assertEqual(len(service["secrets"]), 4)
            for secret in service["secrets"]:
                self.assertEqual(secret["uid"], "10001")
                self.assertEqual(secret["gid"], "10001")
                self.assertEqual(secret["mode"], "0400")
            self.assertFalse(service.get("privileged", False))
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("JWT_SECRET", service["environment"])
            self.assertNotIn("DATABASE_URL", service["environment"])
            self.assertEqual(config["networks"]["analytics_backend"]["name"],
                             "omnilyzer-analytics-backend-dev")
            self.assertTrue(config["networks"]["analytics_backend"]["external"])

    def test_private_owner_only_secret_paths_metadata_only(self):
        """Never read or leak four secrets; only report approved reference names."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "secrets"
            directory.mkdir(mode=0o700)
            for name in REQUIRED_SECRET_NAMES:
                f = directory / name
                f.write_text(name + "=synthetic-only-never-production\n")
                f.chmod(0o600)
            with patch("deployment.analytics_dev_release_review.SECRET_DIRECTORY", directory):
                self.assertEqual(review_private_secret_paths(
                    directory=directory, owner_uid=os.getuid(),
                ), REQUIRED_SECRET_NAMES)
                with self.assertRaises(DeploymentPolicyError):
                    review_private_secret_paths(directory=directory, owner_uid=0)
                f = directory / "JWT_SECRET"
                f.chmod(0o644)
                with self.assertRaises(DeploymentPolicyError):
                    review_private_secret_paths(directory=directory, owner_uid=os.getuid())
                f.chmod(0o600)
                f.unlink()
                f.symlink_to(directory / "DATABASE_URL")
                with self.assertRaises(DeploymentPolicyError):
                    review_private_secret_paths(directory=directory, owner_uid=os.getuid())
                with self.assertRaises(DeploymentPolicyError):
                    review_private_secret_paths(directory=directory / "not-a-secret-dir",
                                                owner_uid=os.getuid())

    def test_existing_canary_oci_allowlist_unmodified(self):
        """Review-only config never broadens the active original Task014 policy."""
        from deployment.execution import ExecutorRequest, DEV_OCI_REPOSITORY
        self.assertEqual(DEV_OCI_REPOSITORY, "omnilyzer/task013-release-canary")
        self.assertEqual(ExecutorRequest.__annotations__["secrets_reference"],
                         "NoSecretsReference")
        with self.assertRaises(DeploymentPolicyError):
            validate_repository("omnilyzer/analytics")


if __name__ == "__main__":
    unittest.main()

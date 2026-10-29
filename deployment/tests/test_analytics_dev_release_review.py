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
        self.assertEqual(p.source_commit, "4cdda7faeba57abb3388f9be5c450fe6afb1140d")
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
            # Compose ignores uid/gid/mode for local file secrets; security
            # comes from host 0600 ownership plus actual rootless UID tests.
            for secret in service["secrets"]:
                self.assertNotIn("uid", secret)
                self.assertNotIn("gid", secret)
                self.assertNotIn("mode", secret)
            self.assertFalse(service.get("privileged", False))
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("JWT_SECRET", service["environment"])
            self.assertNotIn("DATABASE_URL", service["environment"])
            self.assertEqual(config["networks"]["analytics_backend"]["name"],
                             "omnilyzer-analytics-backend-dev")
            self.assertTrue(config["networks"]["analytics_backend"]["external"])

    @unittest.skipUnless(
        os.getenv("M05_REAL_COMPOSE_SECRET_TEST") == "1",
        "explicit Docker opt-in; test starts ONLY isolated no-network containers",
    )
    def test_actual_compose_uid10001_secrets_read_and_wrong_owner_denied(self):
        """Test actual file-secret mounts under UID10001, not YAML-only claims.

        Test-only: temp Compose project, no host ports or external network,
        official pinned Node22 image, four synthetic 0600 secrets; no real
        product image, credentials, installer, Task014 authority or canary.
        Root in a setup-only container creates synthetic ownership; the
        actual Compose service keeps cap_drop=ALL and no-new-privileges.
        """
        try:
            import yaml
        except ImportError as exc:
            self.skipTest("PyYAML required by explicit real Compose probe")
        image = (
            "node:22.23.4-bookworm@sha256:"
            "78bc820a7a6148e8c48731eca18dbb9b6b2c05ac4a52138479be565f2831682d"
        )
        # Fail if the pinned image is unavailable; do not fetch or build.
        present = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=15, check=False,
        )
        if present.returncode != 0:
            self.skipTest("pinned synthetic Node22 image not cached")
        with tempfile.TemporaryDirectory(prefix="m05-compose-secret-proof-") as tmp:
            root = Path(tmp)
            source = root / "secrets"
            source.mkdir(mode=0o700)
            expected = [str(name) for name in REQUIRED_SECRET_NAMES]
            for name in expected:
                secret = source / name
                secret.write_text(f"{name}=m05_synthetic_{name}\n")
                secret.chmod(0o600)

            parsed = yaml.safe_load(ANALYTICS_PATH.read_text())
            service = dict(parsed["services"]["analytics-blue"])
            self.assertEqual(service["user"], "10001:10001")
            self.assertEqual(service["cap_drop"], ["ALL"])
            for field in ("profiles", "ports", "networks", "healthcheck"):
                service.pop(field, None)
            service["network_mode"] = "none"
            service["restart"] = "no"
            service["image"] = image
            service["command"] = [
                "node", *(f"--env-file=/run/secrets/{name}" for name in expected),
                "-e",
                'const keys=["COLLECTOR_DATABASE_URL","DATABASE_URL",'
                '"JWT_REFRESH_SECRET","JWT_SECRET"];'
                'if(keys.some(k=>process.env[k]!=="m05_synthetic_"+k))'
                'process.exit(31);console.log("M05_REAL_COMPOSE_SECRET_PASS")',
            ]
            project = "m05-pr50-secrets-" + root.name[-8:].lower()
            parsed["name"] = project
            parsed["services"] = {"analytics-blue": service}
            parsed.pop("networks", None)
            for ref in parsed["secrets"].values():
                name = Path(ref["file"]).name
                self.assertIn(name, expected)
                ref["file"] = str(source / name)
            compose = root / "isolated-compose.yaml"
            compose.write_text(yaml.safe_dump(parsed, sort_keys=False))

            def run(args, *, check=True):
                return subprocess.run(
                    list(args), capture_output=True, text=True, check=check,
                    timeout=45, env=dict(os.environ, DOCKER_CLI_HINT="opt-in"),
                )

            def change_owner(name, uid):
                run([
                    "docker", "run", "--rm", "--pull", "never",
                    "--network", "none", "--mount",
                    f"type=bind,src={source / name},dst=/proof",
                    "--user", "0:0", image, "chown", f"{uid}:{uid}", "/proof",
                ])

            compose_cmd = ["docker", "compose", "-p", project, "-f", str(compose)]
            try:
                for name in expected:
                    change_owner(name, 10001)
                data = json.loads(run([
                    *compose_cmd, "config", "--format", "json",
                ]).stdout)
                self.assertEqual(data["services"]["analytics-blue"]["network_mode"], "none")
                self.assertNotIn("ports", data["services"]["analytics-blue"])
                success = run([
                    *compose_cmd, "run", "--rm", "--no-deps", "-T",
                    "analytics-blue",
                ])
                self.assertIn("M05_REAL_COMPOSE_SECRET_PASS", success.stdout)
                # The Docker Compose local-file mount ignores uid/gid/mode;
                # the ONLY permission boundary here is host file ownership.
                change_owner("JWT_SECRET", 0)
                refused = run([
                    *compose_cmd, "run", "--rm", "--no-deps", "-T",
                    "analytics-blue",
                ], check=False)
                self.assertNotEqual(refused.returncode, 0)
                self.assertNotIn("M05_REAL_COMPOSE_SECRET_PASS", refused.stdout)
            finally:
                run([*compose_cmd, "down", "--remove-orphans", "--volumes"], check=False)

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

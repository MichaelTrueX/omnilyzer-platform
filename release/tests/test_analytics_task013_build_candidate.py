"""File: release/tests/test_analytics_task013_build_candidate.py

Purpose: Test original Task013 local source-to-OCI build admission and denial
         without spawning Docker/OCI registry or changing installed platform.
Related: release/analytics_task013_build_candidate.py, M05 PR231 archive
         verifier, release/analytics_oci_context.py, Task013 builder_versions.py.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from deployment.policy import DeploymentPolicyError
from release.analytics_task013_build_candidate import (
    _preflight_builder, build_candidate, EXPECTED_SOURCE, OCI_REPOSITORY,
)

INPUT = {
    "analytics_source_commit": EXPECTED_SOURCE,
    "analytics_tree": "a" * 40,
    "oci_repository": OCI_REPOSITORY,
    "release_authorized": False,
    "deployment_authorized": False,
}
BUILDX = "github.com/docker/buildx v0.36.1 1d8dde89b8aba914e05e45366770736fea1fd690\n"
BUILDKIT = (
    "Name: tmp-builder\n"
    "Driver:        docker-container\n"
    "BuildKit version: v0.24.0\n"
)


class OriginalTask013CandidateBuildTests(unittest.TestCase):
    """Protect the build-input boundary and keep authority false."""

    def test_builder_name_is_closed(self):
        """No path, arbitrary Docker CLI flags or shell-like builder names."""
        for value in ("", "--push", "../runtime", "default;rm", "A", "x" * 100):
            with self.subTest(value=value), self.assertRaises(DeploymentPolicyError):
                _preflight_builder(value)

    @patch("release.analytics_task013_build_candidate.subprocess.run")
    def test_original_builder_versions_and_driver_enforced(self, run):
        """Reuse pinned original BuildKit docker-container, never daemon builder."""
        run.side_effect = [
            MagicMock(stdout=BUILDX),
            MagicMock(stdout=BUILDKIT),
        ]
        _preflight_builder("m01-analytics-ci")
        self.assertEqual(run.call_count, 2)

    @patch("release.analytics_task013_build_candidate.subprocess.run")
    def test_docker_driver_denied(self, run):
        """Default engine driver does not imply pinned Task013 build isolation."""
        run.side_effect = [
            MagicMock(stdout=BUILDX),
            MagicMock(stdout=BUILDKIT.replace("docker-container", "docker")),
        ]
        with self.assertRaises(DeploymentPolicyError):
            _preflight_builder("m01-analytics-ci")

    @patch("release.analytics_task013_build_candidate.subprocess.run")
    def test_wrong_buildkit_denied(self, run):
        """Must retain exact original Task013 BuildKit version v0.24.0."""
        run.side_effect = [
            MagicMock(stdout=BUILDX),
            MagicMock(stdout=BUILDKIT.replace("v0.24.0", "v0.25.0")),
        ]
        with self.assertRaises(DeploymentPolicyError):
            _preflight_builder("m01-analytics-ci")

    @patch("release.analytics_task013_build_candidate._preflight_builder")
    @patch("release.analytics_task013_build_candidate.build_input")
    def test_review_only_never_builds(self, admission, preflight):
        """Without explicit --build, no Docker image or archive is created."""
        admission.return_value = dict(INPUT)
        value = build_candidate(Path("/synthetic/future"), "m01-ci")
        self.assertEqual(value["status"], "reviewed-build-input-only")
        self.assertIs(value["release_authorized"], False)
        self.assertIs(value["deployment_authorized"], False)
        preflight.assert_called_once_with("m01-ci")

    @patch("release.analytics_task013_build_candidate._preflight_builder")
    @patch("release.analytics_task013_build_candidate.build_input")
    def test_unsigned_override_denied_before_builder(self, admission, preflight):
        """Never trust a caller or test to re-label local OCI as authorized."""
        for mutation in (dict(INPUT, release_authorized=True),
                         dict(INPUT, deployment_authorized=True),
                         dict(INPUT, analytics_source_commit="0" * 40),
                         dict(INPUT, oci_repository="omnilyzer/task013-release-canary")):
            admission.return_value = mutation
            with self.subTest(mutation=mutation), self.assertRaises(DeploymentPolicyError):
                build_candidate(Path("/synthetic/future"), "m01-ci")
        preflight.assert_not_called()

    @patch("release.analytics_task013_build_candidate.verify_archive")
    @patch("release.analytics_task013_build_candidate.snapshot_committed_tree")
    @patch("release.analytics_task013_build_candidate.subprocess.run")
    @patch("release.analytics_task013_build_candidate._preflight_builder")
    @patch("release.analytics_task013_build_candidate.build_input")
    def test_existing_builder_only_and_verified_oci_required(
        self, admission, preflight, build, snapshot, verify,
    ):
        """BuildKit is given Git TAR on stdin; output stays local and unsigned."""
        admission.return_value = dict(INPUT)
        paths = []

        def source_only(checkout, sha, target):
            target.write_bytes(b"only-committed-source")
            paths.append(target)
            return {"context_sha256": "e" * 64, "release_authorized": False}

        snapshot.side_effect = source_only
        build.return_value = MagicMock(returncode=0)
        verify.return_value = {
            "release_authorized": False,
            "deployment_authorized": False,
            "source_commit": EXPECTED_SOURCE,
            "source_tree": INPUT["analytics_tree"],
            "oci_repository": OCI_REPOSITORY,
            "local_manifest_digest": "sha256:" + "a" * 64,
            "archive_sha256": "b" * 64,
        }
        receipt = build_candidate(Path("/synthetic/trusted-Git"), "m01-ci", execute=True)
        self.assertEqual(receipt["status"], "verified-local-oci-unsigned")
        self.assertEqual(receipt["source_context_sha256"], "e" * 64)
        self.assertFalse(receipt["release_authorized"])
        self.assertFalse(receipt["deployment_authorized"])
        argv = build.call_args.args[0]
        self.assertEqual(argv[:3], ["docker", "buildx", "build"])
        self.assertEqual(argv[-1], "-")
        self.assertIn("--builder", argv)
        self.assertIn("m01-ci", argv)
        self.assertIn("--provenance=false", argv)
        self.assertIn("--sbom=false", argv)
        self.assertNotIn("--push", argv)
        self.assertNotIn("--tag", argv)
        self.assertNotIn("DATABASE_URL", " ".join(argv))
        self.assertNotIn("JWT_SECRET", " ".join(argv))
        self.assertTrue(build.call_args.kwargs["stdin"].closed)
        self.assertTrue(paths)
        self.assertTrue(all(not path.exists() for path in paths))

    @patch("release.analytics_task013_build_candidate.verify_archive")
    @patch("release.analytics_task013_build_candidate.snapshot_committed_tree")
    @patch("release.analytics_task013_build_candidate.subprocess.run")
    @patch("release.analytics_task013_build_candidate._preflight_builder")
    @patch("release.analytics_task013_build_candidate.build_input")
    def test_failed_build_cannot_emit_a_signed_or_local_digest(
        self, admission, preflight, build, snapshot, verify,
    ):
        """Any BuildKit failure aborts verification and deletes temporary input."""
        admission.return_value = dict(INPUT)
        paths = []

        def source_only(checkout, sha, target):
            target.write_bytes(b"only-committed-source")
            paths.append(target)
            return {"context_sha256": "e" * 64, "release_authorized": False}

        snapshot.side_effect = source_only
        build.return_value = MagicMock(returncode=20)
        with self.assertRaises(DeploymentPolicyError):
            build_candidate(Path("/synthetic/trusted-Git"), "m01-ci", execute=True)
        verify.assert_not_called()
        self.assertTrue(paths)
        self.assertTrue(all(not path.exists() for path in paths))

    @patch("release.analytics_task013_build_candidate._preflight_builder")
    @patch("release.analytics_task013_build_candidate.build_input")
    def test_execute_flag_requires_actual_bool(self, admission, preflight):
        """No implicit truthy strings become a real Docker build invocation."""
        admission.return_value = dict(INPUT)
        with self.assertRaises(DeploymentPolicyError):
            build_candidate(Path("/synthetic/future"), "m01-ci", execute="true")
        preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()

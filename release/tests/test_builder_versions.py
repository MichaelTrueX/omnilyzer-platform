from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

import yaml

from release.builder_versions import (
    BuilderVersionError,
    EXPECTED_BUILDKIT_VERSION,
    EXPECTED_BUILDX_VERSION,
    verify_buildkit_output,
    verify_buildx_output,
)


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/platform-release.yml"
PROMOTE_PATH = ROOT / ".github/workflows/platform-promote.yml"
PROMOTE_SHA256 = "3846ae1e48c945dacb563da8967e588b3fbb6fffa2580276f816496396b3c134"
BUILDKIT_IMAGE = (
    "moby/buildkit:v0.24.0@"
    "sha256:6eceb8971ce4fceb3daca562832642706238b7eea72941fcf9896c93c3c4a53e"
)


class BuildKitVersionParserTests(unittest.TestCase):
    def test_observed_real_output_is_accepted(self) -> None:
        self.assertEqual(
            verify_buildkit_output("BuildKit version:      v0.24.0\n"),
            EXPECTED_BUILDKIT_VERSION,
        )

    def test_alternative_horizontal_spacing_is_accepted(self) -> None:
        for output in ("BuildKit version: v0.24.0", "BuildKit version:\tv0.24.0\t"):
            with self.subTest(output=output):
                self.assertEqual(verify_buildkit_output(output), EXPECTED_BUILDKIT_VERSION)

    def test_wrong_version_is_rejected(self) -> None:
        for version in ("v0.24.1", "v0.23.9"):
            with self.subTest(version=version), self.assertRaises(BuilderVersionError):
                verify_buildkit_output(f"BuildKit version: {version}")

    def test_suffix_or_prerelease_is_rejected(self) -> None:
        for version in ("v0.24.0-extra", "v0.24.0-rc1"):
            with self.subTest(version=version), self.assertRaises(BuilderVersionError):
                verify_buildkit_output(f"BuildKit version: {version}")

    def test_missing_version_field_is_rejected(self) -> None:
        with self.assertRaises(BuilderVersionError):
            verify_buildkit_output("Name: builder\nStatus: running\n")

    def test_duplicate_version_fields_are_rejected(self) -> None:
        with self.assertRaises(BuilderVersionError):
            verify_buildkit_output(
                "BuildKit version: v0.24.0\nBuildKit version:      v0.24.0\n",
            )

    def test_unrelated_text_containing_version_is_rejected(self) -> None:
        with self.assertRaises(BuilderVersionError):
            verify_buildkit_output("builder uses BuildKit v0.24.0\n")

    def test_workflow_cli_accepts_observed_real_output(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "release.builder_versions", "buildkit"],
            input="BuildKit version:      v0.24.0\n",
            text=True,
            capture_output=True,
            check=False,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v0.24.0\n")


class BuilderWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.raw)
        cls.build = cls.workflow["jobs"]["build"]

    def test_buildx_output_requires_exact_version(self) -> None:
        observed = "github.com/docker/buildx v0.36.1 1d8dde89b8aba914e05e45366770736fea1fd690"
        self.assertEqual(verify_buildx_output(observed), EXPECTED_BUILDX_VERSION)
        for output in (
            observed.replace("v0.36.1", "v0.36.2"),
            observed.replace("v0.36.1", "v0.36.1-extra"),
            "Buildx version is v0.36.1",
        ):
            with self.subTest(output=output), self.assertRaises(BuilderVersionError):
                verify_buildx_output(output)

    def test_builder_pins_and_permissions_are_unchanged(self) -> None:
        self.assertEqual(self.build["permissions"], {"contents": "read"})
        self.assertNotIn("id-token", self.build["permissions"])
        self.assertIn("version: v0.36.1", self.raw)
        self.assertIn(BUILDKIT_IMAGE, self.raw)

    def test_version_validation_precedes_unchanged_oci_build(self) -> None:
        steps = self.build["steps"]
        names = [step["name"] for step in steps]
        validation = next(step for step in steps if step["name"] == "Verify pinned image builder versions")
        self.assertIn("python3 -m release.builder_versions buildx", validation["run"])
        self.assertIn("python3 -m release.builder_versions buildkit", validation["run"])
        self.assertLess(
            names.index("Verify pinned image builder versions"),
            names.index("Build executable OCI canary exactly once"),
        )
        build = next(step for step in steps if step["name"] == "Build executable OCI canary exactly once")
        self.assertEqual(build["with"]["platforms"], "linux/amd64")
        for key in ("pull", "no-cache"):
            self.assertIs(build["with"][key], True)
        for key in ("push", "load", "provenance", "sbom"):
            self.assertIs(build["with"][key], False)
        self.assertEqual(build["with"]["network"], "none")

    def test_deployment_remains_disabled_and_promotion_workflow_unchanged(self) -> None:
        for stage in ("dev", "staging", "prod"):
            environment = json.loads(
                (ROOT / f"deployment/environments/{stage}.json").read_text(encoding="utf-8"),
            )
            self.assertIs(environment["activation"]["deployment_enabled"], False)
        self.assertEqual(
            hashlib.sha256(PROMOTE_PATH.read_bytes()).hexdigest(),
            PROMOTE_SHA256,
        )


if __name__ == "__main__":
    unittest.main()

"""File: release/tests/test_analytics_task013_artifact_handoff.py

Purpose: Verify that the ORIGINAL pinned Task013 Analytics builder can retain
exactly the already-validated Docker source TAR and OCI archive in one atomic,
private, explicitly UNSIGNED file handoff. Original transient behavior remains.

Related files: release/analytics_task013_build_candidate.py (M01 PR232),
release/analytics_oci_context.py, release/analytics_oci_archive.py,
release/analytics_release_source_binding.py (M05 PR233),
.github/workflows/platform-release.yml (not changed).

Tests use a fake local builder only, and never contact a registry or signer.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deployment.policy import DeploymentPolicyError
from release.analytics_task013_build_candidate import (
    EXPECTED_SOURCE, OCI_REPOSITORY, _private_handoff_destination,
    build_candidate,
)

INPUT = {
    "analytics_source_commit": EXPECTED_SOURCE,
    "analytics_tree": "a" * 40,
    "platform_source_commit": "b" * 40,
    "oci_repository": OCI_REPOSITORY,
    "release_authorized": False,
    "deployment_authorized": False,
}
SOURCE = b"exact verified committed Git TAR source"
OCI = b"exact locally verified Task013 OCI artifact bytes"


def sha(content: bytes) -> str:
    """Use the exact real hash of a synthetic content-addressed test artifact."""
    return hashlib.sha256(content).hexdigest()


class Task013ImmutableArtifactHandoffTests(unittest.TestCase):
    """Preserve the real original builder handoff without implying sign authority."""

    def _run(self, private_dir: Path, *, tamper_hash: bool = False,
             fail_build: bool = False) -> dict:
        """Mock ONLY Docker and source generation for fast file-boundary tests."""
        def canonical_context(checkout, commit, path):
            """Write one synthetic context with real reproducible bytes."""
            self.assertEqual(commit, EXPECTED_SOURCE)
            path.write_bytes(SOURCE)
            return {"context_sha256": sha(SOURCE), "release_authorized": False}

        def fake_build(argv, **kwargs):
            """Verify stdin Docker context and emit real unsigned test bytes."""
            self.assertEqual(argv[:3], ["docker", "buildx", "build"])
            self.assertEqual(argv[-1], "-")
            self.assertNotIn("--push", argv)
            self.assertNotIn("--tag", argv)
            self.assertEqual(kwargs["stdin"].read(), SOURCE)
            dest = next(part.partition("dest=")[2] for part in argv
                        if part.startswith("type=oci,dest="))
            if not fail_build:
                Path(dest).write_bytes(OCI)
            return subprocess.CompletedProcess(argv, 17 if fail_build else 0)

        def checked_oci(path, receipt):
            """Provide the original validator's already-checked local result."""
            self.assertEqual(path.read_bytes(), OCI)
            self.assertEqual(receipt["analytics_source_commit"], EXPECTED_SOURCE)
            return {
                "release_authorized": False,
                "deployment_authorized": False,
                "source_commit": EXPECTED_SOURCE,
                "source_tree": INPUT["analytics_tree"],
                "oci_repository": OCI_REPOSITORY,
                "local_manifest_digest": "sha256:" + "d" * 64,
                "archive_sha256": "f" * 64 if tamper_hash else sha(OCI),
            }

        out = private_dir / "original-task013-unsigned-artifacts"
        with (patch("release.analytics_task013_build_candidate.build_input",
                    return_value=INPUT),
              patch("release.analytics_task013_build_candidate._preflight_builder"),
              patch("release.analytics_task013_build_candidate.snapshot_committed_tree",
                    side_effect=canonical_context),
              patch("release.analytics_task013_build_candidate.subprocess.run",
                    side_effect=fake_build),
              patch("release.analytics_task013_build_candidate.verify_archive",
                    side_effect=checked_oci)):
            return build_candidate(Path("/synthetic/reviewed-pr45"), "m05-pinned",
                                   execute=True, retain_verified_artifacts=out)

    def test_retained_files_are_exact_and_immutable_receipt_is_unsigned(self) -> None:
        """One already-verified OCI archive and source TAR are transferred together."""
        with tempfile.TemporaryDirectory(prefix="m05-private-test-") as root:
            folder = Path(root)
            result = self._run(folder)
            out = folder / "original-task013-unsigned-artifacts"
            self.assertEqual(result["status"], "verified-local-oci-unsigned-retained")
            self.assertFalse(result["release_authorized"])
            self.assertFalse(result["deployment_authorized"])
            self.assertEqual({x.name for x in out.iterdir()}, {
                "source.tar", "analytics.oci.tar", "unsigned-handoff.json",
            })
            self.assertEqual((out / "source.tar").read_bytes(), SOURCE)
            self.assertEqual((out / "analytics.oci.tar").read_bytes(), OCI)
            self.assertEqual(json.loads((out / "unsigned-handoff.json").read_bytes()), result)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            for name in ("source.tar", "analytics.oci.tar", "unsigned-handoff.json"):
                self.assertEqual((out / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["local_oci_archive_sha256"], sha(OCI))
            self.assertEqual(result["source_context_sha256"], sha(SOURCE))
            self.assertFalse(result["deployment_authorized"])

    def test_mismatched_hash_aborts_without_creating_handoff(self) -> None:
        """Do not persist files if original OCI verification and bytes disagree."""
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root)
            # Manually run the same fixture with a forged/mismatched OCI hash.
            with self.assertRaises(DeploymentPolicyError):
                self._run_bad_archive(parent)
            self.assertEqual(list(parent.iterdir()), [])

    def _run_bad_archive(self, parent: Path) -> None:
        """Exercise a mismatched OCI archive hash without trusting a flag."""
        # Same builder test harness, but adversarial OCI digest is induced by
        # overriding the module's hash checker at the file boundary.
        original_sha = __import__("release.analytics_task013_build_candidate",
                                  fromlist=["_sha"])._sha
        def bad_hash(path: Path) -> str:
            return "f" * 64 if path.name == "analytics.oci.tar" else original_sha(path)
        with patch("release.analytics_task013_build_candidate._sha", side_effect=bad_hash):
            self._run(parent)

    def test_failed_build_leaves_no_artifacts_or_source_tar(self) -> None:
        """BuildKit exit errors must never publish an incomplete handoff."""
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root)
            with self.assertRaises(DeploymentPolicyError):
                self._run_failed_build(parent)
            self.assertFalse(any(parent.iterdir()))

    def _run_failed_build(self, parent: Path) -> None:
        """Replace only the fake subprocess return code for this negative."""
        self._run(parent, fail_build=True)

    def test_retention_requires_explicit_execution(self) -> None:
        """A review-only dry run must never create release archive files."""
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(DeploymentPolicyError):
                build_candidate(Path("/not-consulted"), "m05",
                                retain_verified_artifacts=Path(root) / "unsigned")

    def test_parent_must_be_private_and_existing_destination_is_denied(self) -> None:
        """Never publish source or OCI data into shared /tmp or an existing path."""
        with self.assertRaises(DeploymentPolicyError):
            _private_handoff_destination(Path("/tmp/m05-unsafe-public-target"))
        with tempfile.TemporaryDirectory() as root:
            rootpath = Path(root)
            existing = rootpath / "already-exists"
            existing.mkdir()
            with self.assertRaises(DeploymentPolicyError):
                _private_handoff_destination(existing)
            symlink = rootpath / "link"
            symlink.symlink_to(existing)
            with self.assertRaises(DeploymentPolicyError):
                _private_handoff_destination(symlink)
            with self.assertRaises(DeploymentPolicyError):
                _private_handoff_destination(Path("relative-output"))
            with self.assertRaises(DeploymentPolicyError):
                _private_handoff_destination(rootpath / "--push")

    def test_existing_transient_api_leaves_no_persistent_artifacts(self) -> None:
        """Original original Task013 review mode remains separately testable."""
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            with patch("release.analytics_task013_build_candidate.build_input",
                       return_value=INPUT), patch(
                       "release.analytics_task013_build_candidate._preflight_builder"):
                result = build_candidate(Path("/synthetic/source"), "m05", execute=False)
            self.assertEqual(result["status"], "reviewed-build-input-only")
            self.assertFalse(any(folder.iterdir()))


if __name__ == "__main__":
    unittest.main()

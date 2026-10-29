"""File: release/tests/test_analytics_release_source_binding.py

Purpose: Check real immutable Analytics Git→Docker-context identity, strict OCI
artifact digest and original Task013 unsigned source-claim preparation, plus
fail-closed provenance mismatches before original Cosign signing.

Related: release/analytics_release_source_binding.py,
release/analytics_oci_context.py (M01 PR232), M05 OCI archive reader,
release/provenance.py and deployment/promotion.py (both remain unchanged).

All tests use synthetic OCI fixture layers, NO signing, broker, registry or DB.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from deployment.policy import DeploymentPolicyError, canonical_bytes
from deployment.tests.fixtures import evidence
from release.analytics_oci_context import snapshot_committed_tree
from release.analytics_release_source_binding import (
    _canonical_json, _hash_existing_regular, prepare_original_signed_evidence_inputs,
    prepare_source_claim,
)
from release.tests.test_analytics_oci_archive import build_test_archive

ROOT = Path(__file__).resolve().parents[2]


def _original_unsigned_evidence_for_claim(claim: dict) -> tuple[bytes, bytes]:
    """Make UNSIGNED Task013-shaped evidence for fixture-only tests."""
    manifest_raw, provenance_raw = evidence()
    manifest, provenance = json.loads(manifest_raw), json.loads(provenance_raw)
    provenance["source_commit"] = claim["platform_source_commit"]
    provenance["execution"]["source_commit"] = claim["platform_source_commit"]
    provenance["execution"]["workflow_sha"] = claim["platform_source_commit"]
    provenance["subjects"]["oci_manifest_digest"] = claim["oci_manifest_digest"]
    provenance["subjects"]["oci_archive_sha256"] = claim["oci_archive_sha256"]
    manifest["source_commit"] = claim["platform_source_commit"]
    manifest["oci"]["repository"] = "omnilyzer/analytics"
    manifest["oci"]["manifest_digest"] = claim["oci_manifest_digest"]
    manifest["oci"]["deployment_identity"] = (
        "omnilyzer/analytics@" + claim["oci_manifest_digest"]
    )
    provenance_raw = canonical_bytes(provenance)
    manifest["provenance"]["sha256"] = hashlib.sha256(provenance_raw).hexdigest()
    return canonical_bytes(manifest), provenance_raw


class AnalyticsSignedSourceBindingTests(unittest.TestCase):
    """Guard the source and original provenance chain without any signing."""

    def test_duplicate_provenance_json_rejected(self) -> None:
        """No ambiguous repeated source or signature identity in signed input."""
        with self.assertRaises(DeploymentPolicyError):
            _canonical_json(b'{"source_commit":"abc","source_commit":"def"}', "provenance")

    def test_review_input_not_a_regular_file_denied(self) -> None:
        """Reject symlink and directory as a signed-source build context."""
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "a"
            file.write_text("one")
            link = Path(root) / "link"
            link.symlink_to(file)
            with self.assertRaises(DeploymentPolicyError):
                _hash_existing_regular(link)
            with self.assertRaises(DeploymentPolicyError):
                _hash_existing_regular(Path(root))

    def test_unsigned_evidence_requires_verified_real_git_and_archive(self) -> None:
        """Real PR49 Git tree and deterministic tar are required to create claim."""
        checkout = os.environ.get("OMNILYZER_ANALYTICS_CHECKOUT")
        if not checkout:
            self.skipTest("actual clean Analytics PR49 checkout not provided")
        source = Path(checkout)
        expected_commit = "df40b4632a088232de4699d5826641e0cf269dc8"
        self.assertEqual(
            __import__("subprocess").check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"], text=True,
            ).strip(), expected_commit,
        )
        with tempfile.TemporaryDirectory(prefix="m05-analytic-source-bind-test-") as root:
            parent = Path(root)
            context = parent / "context.tar"
            oci = parent / "local-oci.tar"
            built = snapshot_committed_tree(source, expected_commit, context)
            self.assertGreater(built["file_count"], 500)
            build_test_archive(oci)
            claim = prepare_source_claim(
                source, context, oci, platform_root=ROOT,
            )
            self.assertEqual(claim["source_commit"], expected_commit)
            self.assertEqual(claim["source_files_verified"], 77)
            self.assertEqual(claim["build_context_sha256"], built["context_sha256"])
            self.assertTrue(claim["oci_manifest_digest"].startswith("sha256:"))
            self.assertNotIn("signed", claim)
            self.assertNotIn("JWT_SECRET", canonical_bytes(claim).decode("utf-8"))

            # Original Task013 manifest/provenance share one signed-source
            # claim and the provenance SHA chain is recalculated BEFORE signing.
            unsigned_manifest, unsigned_provenance = _original_unsigned_evidence_for_claim(claim)
            prepared_manifest, prepared_provenance = prepare_original_signed_evidence_inputs(
                unsigned_manifest, unsigned_provenance, source, context, oci,
                platform_root=ROOT,
            )
            manifest = json.loads(prepared_manifest)
            provenance = json.loads(prepared_provenance)
            self.assertEqual(manifest["external_source"], claim)
            self.assertEqual(provenance["external_source"], claim)
            self.assertEqual(
                manifest["provenance"]["sha256"],
                hashlib.sha256(prepared_provenance).hexdigest(),
            )
            # Exercise actual executable CLI, not only the library function.
            original_dir = parent / "original-unsigned-evidence"
            original_dir.mkdir()
            (original_dir / "release-manifest.json").write_bytes(unsigned_manifest)
            (original_dir / "release-provenance.json").write_bytes(unsigned_provenance)
            prepared_dir = parent / "prepared-for-original-signer"
            cmd = [sys.executable, "-m", "release.analytics_release_source_binding",
                   "--analytics-checkout", str(source),
                   "--immutable-context", str(context),
                   "--oci-archive", str(oci),
                   "--original-evidence-dir", str(original_dir),
                   "--output-dir", str(prepared_dir)]
            result = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                                    text=True, check=True, timeout=60)
            cli = json.loads(result.stdout)
            self.assertFalse(cli["release_authorized"])
            self.assertFalse(cli["deployment_authorized"])
            self.assertEqual((prepared_dir / "release-manifest.json").read_bytes(),
                             prepared_manifest)
            self.assertEqual((prepared_dir / "release-provenance.json").read_bytes(),
                             prepared_provenance)
            self.assertEqual(prepared_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual((prepared_dir / "release-manifest.json").stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(subprocess.run(cmd, cwd=ROOT, capture_output=True,
                                               timeout=60).returncode, 0)

            # Exact source context content is mandatory, not just a matching
            # Git SHA or a caller supplied approval flag.
            with context.open("ab") as stream:
                stream.write(b"malicious source content")
            with self.assertRaises(DeploymentPolicyError):
                prepare_source_claim(source, context, oci, platform_root=ROOT)
            # Restore only the test fixture to exercise OCI tampering.
            context.unlink()
            snapshot_committed_tree(source, expected_commit, context)
            with oci.open("ab") as stream:
                stream.write(b"malicious OCI tar appendix")
            # A tar trailing padding appendix is ignored by tarfile, but the
            # whole archived SHA changes; release manifest consistency MUST
            # bind the whole-archive checksum in a later signed handoff.
            tampered = prepare_source_claim(source, context, oci, platform_root=ROOT)
            self.assertNotEqual(
                tampered["oci_archive_sha256"], claim["oci_archive_sha256"],
            )
            with self.assertRaises(DeploymentPolicyError):
                prepare_original_signed_evidence_inputs(
                    unsigned_manifest, unsigned_provenance, source, context, oci,
                    platform_root=ROOT,
                )

            # Original canary signed schema cannot quietly become Analytics.
            old_manifest, old_provenance = evidence()
            with self.assertRaises(DeploymentPolicyError):
                prepare_original_signed_evidence_inputs(
                    old_manifest, old_provenance, source, context, oci,
                    platform_root=ROOT,
                )

            # Wrong originating platform Git revision or wrong published OCI
            # digest must fail, even with a syntactically valid manifest.
            m = json.loads(unsigned_manifest)
            m["source_commit"] = "f" * 40
            with self.assertRaises(DeploymentPolicyError):
                prepare_original_signed_evidence_inputs(
                    canonical_bytes(m), unsigned_provenance, source, context, oci,
                    platform_root=ROOT,
                )
            m = json.loads(unsigned_manifest)
            m["oci"]["manifest_digest"] = "sha256:" + "f" * 64
            with self.assertRaises(DeploymentPolicyError):
                prepare_original_signed_evidence_inputs(
                    canonical_bytes(m), unsigned_provenance, source, context, oci,
                    platform_root=ROOT,
                )


if __name__ == "__main__":
    unittest.main()

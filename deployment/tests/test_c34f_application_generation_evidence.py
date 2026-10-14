"""File: deployment/tests/test_c34f_application_generation_evidence.py

Purpose: Verify C34F's exact 41-file Git source evidence and fail-closed
behavior for missing objects, extra changes and forged review receipts.
Related: deployment/c34f_application_generation_evidence.py,
deployment/application_manifest.py, deployment/application_source_set.py.

Tests never access installed source, root authority, tokens or live services.
"""

from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from deployment import c34f_application_generation_evidence as subject


class C34FGenerationTests(unittest.TestCase):
    """Test an immutable review snapshot, without deployment side effects."""

    def test_exact_frozen_git_generation(self) -> None:
        """Review complete Git-object manifests, not the mutable worktree."""
        result = subject.review_c34f_generation()
        self.assertEqual(result.path_count, 41)
        self.assertEqual(result.changed_paths, (
            "deployment/broker.py",
            "deployment/broker_https_ingress.py",
            "deployment/broker_integration.py",
        ))
        self.assertEqual(result.manifest_sha256, subject.MANIFESTS)

    def test_receipt_rejects_revision_and_path_drift(self) -> None:
        """The receipt cannot silently authorize a different target."""
        receipt = subject.C34FGenerationEvidence(
            subject.PREDECESSOR, subject.C34D_MAIN, subject.C34E_PROPOSAL,
            41, subject.CHANGED, subject.MANIFESTS,
        )
        for field, new in (
            ("proposal", "f" * 40),
            ("path_count", 42),
            ("changed_paths", ("deployment/broker.py",)),
            ("manifest_sha256", ("0" * 64,) * 3),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(receipt, **{field: new})

    def test_missing_git_object_fails_closed(self) -> None:
        """No source fallback when a pinned Git object cannot be read."""
        with patch.object(
            subject.git_source, "_git_blobs", side_effect=OSError("PRIVATE_OBJECT"),
        ):
            with self.assertRaises(subject.C34FGenerationEvidenceError) as error:
                subject.review_c34f_generation()
        self.assertEqual(str(error.exception), subject._ERROR)

    def test_extra_protected_file_change_fails_closed(self) -> None:
        """A synthetic change to any other protected path is prohibited."""
        original = subject.git_source._git_blobs

        def changed(commit, paths):
            """Return an extra change only for the C34E proposal."""
            records = original(commit, paths)
            if commit == subject.C34E_PROPOSAL:
                return tuple(
                    (name, raw + b"SYNTHETIC_DRIFT"
                     if name == "deployment/state.py" else raw)
                    for name, raw in records
                )
            return records

        with patch.object(subject.git_source, "_git_blobs", side_effect=changed):
            with self.assertRaises(subject.C34FGenerationEvidenceError):
                subject.review_c34f_generation()

    def test_public_surface_has_no_installer(self) -> None:
        """Only inert review models and a review function are exported."""
        self.assertEqual(subject.__all__, (
            "C34FGenerationEvidenceError",
            "C34FGenerationEvidence",
            "review_c34f_generation",
        ))


if __name__ == "__main__":
    unittest.main()

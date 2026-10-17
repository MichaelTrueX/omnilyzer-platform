"""File: deployment/tests/test_c34i_final_main_seal.py

Purpose: Prove a future merged-main manifest can bind the exact three approved
C34E blob changes without trusting a draft commit as deployment authority.
Related: deployment/c34i_final_main_seal.py,
deployment/c34f_application_generation_evidence.py,
deployment/tests/test_c34f_application_generation_evidence.py.

Tests use deterministic synthetic final SHAs and patched Git-object manifests.
They never access installed host files or authorize/perform deployment.
"""

from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from deployment import c34f_application_generation_evidence as reference
from deployment import c34i_final_main_seal as seal
from deployment.application_source_set import DevApplicationSourceSet
from deployment.application_manifest import DevApplicationManifest


TARGET = "abcdef0123456789abcdef0123456789abcdef01"


class C34IFinalMainSealTests(unittest.TestCase):
    """Require exact protected blob hashes, canonical manifests and no approval."""

    @classmethod
    def setUpClass(cls) -> None:
        """Build real known Git blob references only for deterministic tests."""
        cls.paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        cls.previous = reference._manifest(reference.PREDECESSOR, cls.paths)
        proposed = reference._manifest(reference.C34E_PROPOSAL, cls.paths)
        cls.candidate = DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", TARGET,
            proposed.entries,
        )

    def _seal_with(self, target: DevApplicationManifest):
        """Patch target Git-object lookup while using pinned true predecessor."""
        def select(commit, paths):
            """Return a known manifest for an exact SHA or refuse unknown source."""
            if paths != self.paths:
                raise ValueError
            if commit == reference.PREDECESSOR:
                return self.previous
            if commit == TARGET:
                return target
            raise OSError("unlisted synthetic source")

        with patch.object(seal.evidence, "_manifest", side_effect=select):
            return seal.prepare_c34i_final_main_source_seal(
                independently_reviewed_main_sha=TARGET,
            )

    def test_exact_post_merge_source_has_non_authorizing_seal(self):
        """Only reviewed three changed files yield a canonical 41-file seal."""
        receipt = self._seal_with(self.candidate)
        self.assertEqual(receipt.proposed_final_main_commit, TARGET)
        self.assertEqual(receipt.protected_file_count, 41)
        self.assertEqual(receipt.changed_paths, reference.CHANGED)
        self.assertEqual(
            receipt.source_manifest_sha256,
            reference._digest(self.candidate.canonical_bytes()),
        )
        self.assertIs(receipt.approval_granted, False)

    def test_draft_and_old_authority_never_count_as_merged_main(self):
        """A SHA only from old main or draft review cannot be used as final."""
        for candidate in (
            reference.PREDECESSOR, reference.C34D_MAIN,
            reference.C34E_PROPOSAL, "f" * 39, "A" * 40, None, True,
        ):
            with self.subTest(candidate=candidate), self.assertRaises(
                seal.C34IFinalMainSealError
            ):
                seal.prepare_c34i_final_main_source_seal(
                    independently_reviewed_main_sha=candidate,
                )

    def test_unapproved_protected_file_drift_is_rejected(self):
        """One unauthorized change in the other 38 files fails closed."""
        entries = list(self.candidate.entries)
        entry = entries[-1]
        entries[-1] = replace(entry, sha256="f" * 64)
        drifted = DevApplicationManifest(
            "canonical-relative-file-set-v1", "sha256", TARGET, tuple(entries),
        )
        with self.assertRaises(seal.C34IFinalMainSealError):
            self._seal_with(drifted)

    def test_missing_target_git_objects_are_not_accepted(self):
        """Never substitute working-tree content after Git provenance loss."""
        with patch.object(seal.evidence, "_manifest", side_effect=OSError(
            "SENSITIVE_GIT_PATH"
        )):
            with self.assertRaises(seal.C34IFinalMainSealError) as error:
                seal.prepare_c34i_final_main_source_seal(
                    independently_reviewed_main_sha=TARGET,
                )
        self.assertEqual(str(error.exception), seal._ERROR)
        self.assertNotIn("SENSITIVE_GIT_PATH", str(error.exception))

    def test_receipt_cannot_be_promoted_to_authority(self):
        """The seal is a read-only proposal even if caller forges fields."""
        receipt = self._seal_with(self.candidate)
        with self.assertRaises(ValueError):
            replace(receipt, approval_granted=True)
        with self.assertRaises(ValueError):
            replace(receipt, proposed_final_main_commit=reference.C34E_PROPOSAL)

    def test_no_writer_or_installer_exported(self):
        """The module intentionally contains no root file modification API."""
        self.assertEqual(seal.__all__, (
            "C34IFinalMainSealError",
            "C34IFinalMainSourceSeal",
            "prepare_c34i_final_main_source_seal",
        ))


if __name__ == "__main__":
    unittest.main()

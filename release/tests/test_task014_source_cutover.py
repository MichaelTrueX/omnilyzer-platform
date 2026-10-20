"""File: release/tests/test_task014_source_cutover.py

Purpose: Offline acceptance of a 43-file, root-owned DEV application
generation with an atomic directory exchange and rollback. Tests run ONLY
in disposable nonprivileged temporary directories and never contact live
DEV, registry, Docker, services or state.
Related: release/task014_source_cutover.py,
deployment/application_source_set.py, deployment/application_manifest.py.

Sections: baseline manifest identity; complete file admission;
atomic switch and rollback; failure rejection and recovery behavior.
"""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release import task014_source_cutover as cutover

ROOT = Path(__file__).resolve().parents[2]
HEAD = subprocess.check_output(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
    stderr=subprocess.DEVNULL, timeout=5,
).decode("ascii").strip()


class SourceCutoverTests(unittest.TestCase):
    """Full source generation and Linux atomic exchange in temp fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate the reviewed manifest once; preserve exact Git blob bytes."""
        cls.plan = cutover.reviewed_plan(ROOT, HEAD)
        cls.old_payloads = {
            path: cutover._git_blob(ROOT, cutover.PRIOR_SOURCE_SHA, path)
            for path, _ in cls.plan.prior_entries
        }

    def setUp(self) -> None:
        """Build a disposable complete old application, with no live paths."""
        self.workspace = tempfile.TemporaryDirectory(prefix="task014-offline-cutover-")
        self.addCleanup(self.workspace.cleanup)
        self.parent = Path(self.workspace.name) / "deployment"
        self.parent.mkdir(mode=0o755)
        self.parent.chmod(0o755)
        old = self.parent / "app"
        old.mkdir(mode=0o755)
        old.chmod(0o755)
        self.old = old
        for path, data in self.old_payloads.items():
            target = old / path
            target.parent.mkdir(parents=True, exist_ok=True)
            cursor = target.parent
            while cursor != old:
                cursor.chmod(0o755)
                cursor = cursor.parent
            target.write_bytes(data)
            target.chmod(0o644)
        # Nonprivileged fixtures substitute only the identity and fixed root;
        # the deployed function has no test-mode or bypass argument.
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(cutover, "APP_PARENT", self.parent))
        self.stack.enter_context(patch.object(
            cutover, "_required_ownership", return_value=(os.getuid(), os.getgid()),
        ))
        self.stack.enter_context(patch.object(cutover, "_require_root"))
        self.stack.enter_context(patch.object(cutover, "_require_quiesced"))

    def test_reviewed_source_selection_is_exact_eleven_deltas(self) -> None:
        """Pin the independent 40+3 manifest and nine replacements/two additions."""
        self.assertEqual(len(self.plan.target_entries), 43)
        self.assertEqual(len(self.plan.prior_entries), 41)
        self.assertEqual(len(self.plan.changed_paths), 11)
        self.assertIn("deployment/private_registry_fd.py", self.plan.changed_paths)
        self.assertIn("deployment/private_registry_pull.py", self.plan.changed_paths)
        self.assertEqual(
            len(set(dict(self.plan.target_entries)) & set(dict(self.plan.prior_entries))),
            41,
        )

    def test_complete_old_application_preflight_is_read_only(self) -> None:
        """The old complete tree is accepted without writing a staged file."""
        cutover.readonly_preflight(self.plan)
        self.assertEqual(set(path.name for path in self.parent.iterdir()), {"app"})

    def test_prepare_exchange_and_rollback_are_complete(self) -> None:
        """The old tree survives byte-identically in the stage backup."""
        stage = cutover.prepare_staging(self.plan, ROOT)
        self.assertEqual(stage.parent, self.parent)
        self.assertEqual(len(cutover._observed_tree(stage)), 43)
        self.assertEqual(len(cutover._observed_tree(self.old)), 41)
        cutover.activate_staging(self.plan, stage)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.target_entries)
        self.assertEqual(cutover._observed_tree(stage), self.plan.prior_entries)
        cutover.rollback_staging(self.plan, stage)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.prior_entries)
        self.assertEqual(cutover._observed_tree(stage), self.plan.target_entries)

    def test_unlisted_file_and_symlink_are_rejected(self) -> None:
        """No extra files, symlinks, or replacement with unapproved source."""
        extra = self.old / "deployment" / "backdoor.py"
        extra.write_bytes(b"not approved")
        extra.chmod(0o644)
        with self.assertRaises(cutover.CutoverHold):
            cutover.readonly_preflight(self.plan)
        extra.unlink()
        link = self.old / "deployment" / "external.py"
        link.symlink_to("/etc/passwd")
        with self.assertRaises(cutover.CutoverHold):
            cutover.readonly_preflight(self.plan)
        link.unlink()
        cutover.readonly_preflight(self.plan)

    def test_one_corrupted_installed_old_byte_blocks_preparation(self) -> None:
        """A stale host cannot be changed using the reviewed 41-file baseline."""
        path = self.old / "deployment/broker.py"
        path.write_bytes(b"tampered source")
        with self.assertRaises(cutover.CutoverHold):
            cutover.prepare_staging(self.plan, ROOT)
        self.assertEqual(set(x.name for x in self.parent.iterdir()), {"app"})

    def test_incomplete_staging_rejected_without_exchange(self) -> None:
        """Reject a tampered or missing stage while keeping the original live."""
        staged = cutover.prepare_staging(self.plan, ROOT)
        (staged / "deployment/private_registry_fd.py").unlink()
        with self.assertRaises(cutover.CutoverHold):
            cutover.activate_staging(self.plan, staged)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.prior_entries)

    def test_quiescence_failure_preserves_previous_generation(self) -> None:
        """No atomic exchange if the broker or socket is still active."""
        stage = cutover.prepare_staging(self.plan, ROOT)
        with patch.object(cutover, "_require_quiesced", side_effect=cutover.CutoverHold):
            with self.assertRaises(cutover.CutoverHold):
                cutover.activate_staging(self.plan, stage)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.prior_entries)
        self.assertEqual(cutover._observed_tree(stage), self.plan.target_entries)

    def test_post_exchange_verification_failure_automatically_rolls_back(self) -> None:
        """Undo the single atomic exchange after any post-check failure."""
        stage = cutover.prepare_staging(self.plan, ROOT)
        original = cutover._require_exact
        calls = [0]

        def fail_after_swap(path: Path, expected: tuple[tuple[str,str], ...]) -> None:
            """Fail the first verification of newly active source only."""
            calls[0] += 1
            if calls[0] == 3:
                raise cutover.CutoverHold("injected post-cutover verifier fault")
            return original(path, expected)

        with patch.object(cutover, "_require_exact", side_effect=fail_after_swap):
            with self.assertRaises(cutover.CutoverHold):
                cutover.activate_staging(self.plan, stage)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.prior_entries)
        self.assertEqual(cutover._observed_tree(stage), self.plan.target_entries)

    def test_directory_sync_failure_restores_original_generation(self) -> None:
        """A successful rename with failed durability cannot expose new source."""
        stage = cutover.prepare_staging(self.plan, ROOT)
        actual_sync = cutover.os.fsync
        attempts = [0]

        def fail_first_directory_sync(fd: int) -> None:
            """Simulate storage refusing durable acknowledgment once."""
            attempts[0] += 1
            if attempts[0] == 1:
                raise OSError("synthetic fsync I/O failure")
            actual_sync(fd)

        with patch.object(cutover.os, "fsync", side_effect=fail_first_directory_sync):
            with self.assertRaises(cutover.CutoverHold):
                cutover.activate_staging(self.plan, stage)
        self.assertEqual(cutover._observed_tree(self.old), self.plan.prior_entries)
        self.assertEqual(cutover._observed_tree(stage), self.plan.target_entries)

    def test_rollback_refuses_modified_current_files(self) -> None:
        """Never exchange an unknown, post-activation modified source tree."""
        stage = cutover.prepare_staging(self.plan, ROOT)
        cutover.activate_staging(self.plan, stage)
        changed = self.old / "deployment/broker.py"
        changed.write_text("unrecognized")
        with self.assertRaises(cutover.CutoverHold):
            cutover.rollback_staging(self.plan, stage)
        self.assertEqual(len(cutover._observed_tree(stage)), 41)

    def test_parent_and_live_directory_permissions_are_enforced(self) -> None:
        """Untrusted parent or current root permissions are denied."""
        self.parent.chmod(0o777)
        with self.assertRaises(cutover.CutoverHold):
            cutover.readonly_preflight(self.plan)
        self.parent.chmod(0o755)
        self.old.chmod(0o777)
        with self.assertRaises(cutover.CutoverHold):
            cutover.readonly_preflight(self.plan)

    def test_source_generation_function_may_not_accept_unknown_revision(self) -> None:
        """No mutable branch HEAD is accepted as a reviewed target."""
        with self.assertRaises(cutover.CutoverHold):
            cutover.reviewed_plan(ROOT, "not-an-exact-hash")


if __name__ == "__main__":
    unittest.main()

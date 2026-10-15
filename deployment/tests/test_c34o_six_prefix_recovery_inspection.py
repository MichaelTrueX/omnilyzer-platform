"""File: deployment/tests/test_c34o_six_prefix_recovery_inspection.py

Purpose: Exercise complete six-prefix read-only recovery inspection using
real 41-file predecessor Git blobs, canonical typed configs, five private
backups and C34J atomic one-file operations in a disposable nonroot tree.
Related: deployment/c34o_six_prefix_recovery_inspection.py,
deployment/tests/test_c34l_one_prefix_coordinator.py,
deployment/c34m_descriptor_source_observation.py,
deployment/c34j_atomic_file_mechanics.py.

No production /opt, /etc, root, systemd, Docker, network, token or deployment.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34o_six_prefix_recovery_inspection as subject
from deployment import c34j_atomic_file_mechanics as atomic
from deployment import c34k_five_file_backup_barrier as backup
from deployment.tests.test_c34l_one_prefix_coordinator import C34LOnePrefixTests


class C34OSixPrefixRecoveryTests(unittest.TestCase):
    """Use a closed, synthetic-root layout and a separately sealed final SHA."""

    @classmethod
    def setUpClass(cls):
        """Load immutable original/future test objects from reviewed Git history."""
        C34LOnePrefixTests.setUpClass()

    def setUp(self):
        """Build a root-like path tree and sealed private original backups."""
        self.previous = C34LOnePrefixTests(
            "test_no_plan_can_claim_live_authorization",
        )
        self.previous.setUp()
        self.addCleanup(self.previous.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix="c34o-isolated-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.app = self.root / "opt/omnilyzer/deployment/app"
        self.module = self.app / "deployment"
        self.executor = self.root / "etc/omnilyzer/deployment/dev"
        self.broker = self.root / "etc/omnilyzer/deployment/broker"
        self.backup = self.root / "sealed-originals"

        for path, mode in (
            (self.app, 0o755), (self.executor, 0o750),
            (self.broker, 0o750), (self.backup, 0o700),
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        for name in self.previous.paths:
            destination = self.app / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            parent = destination.parent
            while parent != self.root:
                if parent not in (self.executor, self.broker, self.backup):
                    parent.chmod(0o755)
                parent = parent.parent
            destination.write_bytes(self.previous.old[name])
            destination.chmod(0o644)
        # Explicit modes also enforce portability to strict umask=077.
        self.executor.chmod(0o750)
        self.broker.chmod(0o750)
        self.backup.chmod(0o700)
        (self.executor / "executor.json").write_bytes(
            self.previous.executor.canonical_bytes()
        )
        (self.broker / "dev.json").write_bytes(
            self.previous.broker.canonical_bytes()
        )
        (self.executor / "executor.json").chmod(0o640)
        (self.broker / "dev.json").chmod(0o640)
        self.payloads = subject.C34OSealedFivePayloads(
            originals=tuple(x.original for x in self.previous.sources),
            targets=self.previous.targets,
        )
        for name, raw in zip(
            backup._BACKUPS, self.payloads.originals, strict=True,
        ):
            dest = self.backup / name
            dest.write_bytes(raw)
            dest.chmod(0o600)
        self.rootfd = self._fd(self.root)
        self.backupfd = self._fd(self.backup)
        self.authority = self.previous.authority

    def _fd(self, path: Path):
        """Open only one disposable sandbox directory, retained until cleanup."""
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return fd

    def _inspect(self, **changes):
        """Perform two source/config/backups reads through retained descriptors."""
        args = dict(
            anchor_fd=self.rootfd, authority=self.authority,
            payloads=self.payloads, backup_dir_fd=self.backupfd,
            owner_uid=self.uid, application_gid=self.gid,
            executor_gid=self.gid, broker_gid=self.gid,
            backup_uid=self.uid, backup_gid=self.gid,
        )
        args.update(changes)
        return subject.inspect_c34o_six_prefix_candidate(**args)

    def _advance(self, step: int):
        """Publish only one approved file inside our disposable filesystem."""
        name = backup._ORDER[step]
        if step < 3:
            directory = self.module
        elif step == 3:
            directory = self.executor
        else:
            directory = self.broker
        ident = replace(
            self.previous.sources[step].identity,
            uid=self.uid, gid=self.gid,
        )
        return atomic.publish_exact_file(
            parent_fd=self._fd(directory), backup_dir_fd=self.backupfd,
            backup_uid=self.uid, backup_gid=self.gid,
            backup_name=backup._BACKUPS[step],
            identity=ident, original=self.payloads.originals[step],
            target=self.payloads.targets[step],
            stage_name=".omnilyzer-c34j-" + name + ".stage",
        )

    def _stage(self, step: int, raw: bytes, mode: int = 0o600):
        """Create one synthetic interrupted next-step stage by exact basename."""
        if step < 3:
            folder = self.module
        elif step == 3:
            folder = self.executor
        else:
            folder = self.broker
        name = backup._ORDER[step]
        path = folder / (".omnilyzer-c34j-" + name + ".stage")
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def test_every_forward_prefix_and_final_workflow_pin(self):
        """Classify 0..5 with all five original backups verified every time."""
        for step in range(6):
            with self.subTest(step=step):
                receipt = self._inspect()
                self.assertEqual(receipt.completed_steps, step)
                self.assertTrue(receipt.complete_backups)
                self.assertFalse(receipt.recovery_authorized)
                self.assertEqual(receipt.protected_file_count, 41)
                self.assertFalse(receipt.pending_stage)
                if step < 5:
                    self.assertTrue(self._advance(step).target_published)
        self.assertEqual(
            (self.broker / "dev.json").read_bytes(),
            self.previous.target_broker.canonical_bytes(),
        )
        self.assertEqual(
            self.previous.target_broker.expected_workflow_sha,
            self.previous.seal.proposed_final_main_commit,
        )

    def test_empty_and_partial_stage_recovery_all_five_steps(self):
        """A valid stage must belong to the classified next phase."""
        for step in range(5):
            with self.subTest(step=step):
                target = self.payloads.targets[step]
                stage = self._stage(step, target[:min(17, len(target))])
                observed = self._inspect()
                self.assertEqual(observed.completed_steps, step)
                self.assertTrue(observed.pending_stage)
                self.assertFalse(observed.recovery_authorized)
                self._advance(step)
                self.assertFalse(stage.exists())
        self.assertEqual(self._inspect().completed_steps, 5)

    def test_zero_length_stage_can_be_attested(self):
        """C34J interruption just after O_EXCL is a valid target prefix."""
        self._stage(0, b"")
        self.assertTrue(self._inspect().pending_stage)

    def test_wrong_phase_and_corrupt_stage_fail_closed(self):
        """Wrong next operation and arbitrary stage content are both HOLD."""
        stage = self._stage(1, b"")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()
        stage.unlink()
        self._stage(0, b"NOT-APPROVED-CONTENT")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_two_stages_and_leftover_final_stage_fail(self):
        """No concurrent publication or sixth incomplete operation is allowed."""
        stage0 = self._stage(0, b"")
        stage1 = self._stage(1, b"")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()
        stage0.unlink()
        stage1.unlink()
        for step in range(5):
            self._advance(step)
        self._stage(4, b"")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_missing_backup_and_unknown_backup_entry_fail(self):
        """All five immutable predecessor backups remain mandatory."""
        (self.backup / backup._BACKUPS[-1]).unlink()
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()
        (self.backup / backup._BACKUPS[-1]).write_bytes(
            self.payloads.originals[-1]
        )
        (self.backup / backup._BACKUPS[-1]).chmod(0o600)
        extra = self.backup / "unexpected"
        extra.write_bytes(b"untrusted")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_unlisted_source_change_and_symlink_fail(self):
        """Never accept unknown files or substituted module path targets."""
        file = self.module / "unexpected.py"
        file.write_bytes(b"new")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()
        file.unlink()
        original = self.module / "broker.py"
        original.unlink()
        original.symlink_to(self.module / "audit.py")
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_mixed_source_and_noncanonical_config_fail(self):
        """Disallow unreviewed bytes and duplicate JSON config members."""
        self._advance(0)
        (self.executor / "executor.json").write_bytes(
            b'{"stage":"dev","stage":"dev"}\n',
        )
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_untrusted_payloads_and_corrupt_config_group_fail(self):
        """Sealed-target claims must match all independent C34I digest pins."""
        altered = replace(
            self.payloads,
            targets=(b"unreviewed", *self.payloads.targets[1:]),
        )
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect(payloads=altered)
        self.executor.chmod(0o700)
        with self.assertRaises(subject.C34ORecoveryInspectionError):
            self._inspect()

    def test_unstable_two_pass_snapshot_cannot_pass(self):
        """An altered backup or source between readings must force HOLD."""
        actual = subject._inspect_once
        count = [0]

        def intervention(**kw):
            """Change backup contents only after the first approved snapshot."""
            result = actual(**kw)
            count[0] += 1
            if count[0] == 1:
                (self.backup / backup._BACKUPS[0]).write_bytes(b"corrupt")
            return result

        with patch.object(subject, "_inspect_once", side_effect=intervention):
            with self.assertRaises(subject.C34ORecoveryInspectionError):
                self._inspect()
        self.assertEqual(count[0], 1)

    def test_untrusted_receipt_cannot_authorize_recovery(self):
        """Readiness evidence cannot be recast as a live mutation capability."""
        receipt = self._inspect()
        with self.assertRaises(ValueError):
            replace(receipt, recovery_authorized=True)
        with self.assertRaises(ValueError):
            replace(receipt, completed_steps=6)
        with self.assertRaises(ValueError):
            replace(receipt, next_operation="write-arbitrary-file")
        self.assertEqual(subject.__all__, (
            "C34ORecoveryInspectionError", "C34OSealedFivePayloads",
            "C34ORecoveryObservation", "inspect_c34o_six_prefix_candidate",
        ))


if __name__ == "__main__":
    unittest.main()

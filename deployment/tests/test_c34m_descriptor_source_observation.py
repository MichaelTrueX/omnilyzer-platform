"""File: deployment/tests/test_c34m_descriptor_source_observation.py

Purpose: Validate C34M descriptor-based 41-file observation, exact directory
allowlist and tightly constrained incomplete C34J stage recovery.
Related: deployment/c34m_descriptor_source_observation.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/c34l_one_prefix_coordinator.py.

Only synthetic file bytes inside a disposable unprivileged temp directory.
No host paths, protected service config, sudo, network, registry, Docker,
root lock or live deployment are accessed.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from deployment.application_source_set import DevApplicationSourceSet
from deployment import c34m_descriptor_source_observation as scan


class C34MClosedSourceTests(unittest.TestCase):
    """Require 41 exact path digests and at most one approved next-step stage."""

    def setUp(self) -> None:
        """Create closed application and two configuration directory fixtures."""
        self.temp = tempfile.TemporaryDirectory(prefix="omnilyzer-c34m-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = root / "app"
        self.app.mkdir()
        self.app.chmod(0o755)
        self.executor_dir = root / "executor"
        self.broker_dir = root / "broker"
        for path in (self.executor_dir, self.broker_dir):
            path.mkdir()
            path.chmod(0o750)
        self.module_dir = self.app / "deployment"
        self.paths = tuple(
            entry.repository_path for entry in DevApplicationSourceSet().files
        )
        self.raw = {}
        for path in self.paths:
            location = self.app / path
            location.parent.mkdir(parents=True, exist_ok=True)
            location.parent.chmod(0o755)
            data = ("closed test blob: " + path + "\n").encode("ascii")
            location.write_bytes(data)
            location.chmod(0o644)
            self.raw[path] = data
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.app_fd = self._open(self.app)
        self.module_fd = self._open(self.module_dir)
        self.executor_fd = self._open(self.executor_dir)
        self.broker_fd = self._open(self.broker_dir)

    def _open(self, path: Path) -> int:
        """Retain only synthetic sandbox directory descriptors."""
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return fd

    def _scan(self) -> scan.C34MSourceObservation:
        """Inspect complete sandbox file set and both stage directories."""
        return scan.observe_c34m_closed_generation(
            application_fd=self.app_fd,
            executor_configuration_fd=self.executor_fd,
            broker_configuration_fd=self.broker_fd,
            application_uid=self.uid,
            application_gid=self.gid,
            configuration_uid=self.uid,
            executor_gid=self.gid,
            broker_gid=self.gid,
        )

    def _stage(self, phase: int, raw: bytes, mode: int = 0o600) -> Path:
        """Create only the exact permitted staged file for a chosen operation."""
        basename = scan._STAGE_LABELS[phase].rsplit("/", 1)[1]
        if phase < 3:
            directory = self.module_dir
        elif phase == 3:
            directory = self.executor_dir
        else:
            directory = self.broker_dir
        path = directory / basename
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def _attest(self, state: scan.C34MSourceObservation,
                phase: int, target: bytes | None) -> bool:
        """Verify pending bytes against the presumed sealed next target."""
        return scan.attest_c34m_next_stage(
            observation=state,
            completed_steps=phase,
            approved_target_bytes=target,
            application_module_fd=self.module_fd,
            executor_configuration_fd=self.executor_fd,
            broker_configuration_fd=self.broker_fd,
            owner_uid=self.uid, application_gid=self.gid,
            executor_gid=self.gid, broker_gid=self.gid,
        )

    def test_complete_41_file_scan_is_canonical(self):
        """Each digest comes from an actual no-follow 0644 regular file."""
        receipt = self._scan()
        expected = tuple(
            (name, hashlib.sha256(self.raw[name]).hexdigest())
            for name in self.paths
        )
        self.assertEqual(receipt.source_digests, expected)
        self.assertEqual(receipt.pending_stages, ())
        self.assertTrue(self._attest(receipt, 0, None))

    def test_extra_file_directory_and_symlink_rejected(self):
        """Unknown app entries never become part of the source generation."""
        other = self.module_dir / "unknown-file.py"
        other.write_bytes(b"extra")
        with self.assertRaises(scan.C34MObservationError):
            self._scan()
        other.unlink()
        other.mkdir()
        with self.assertRaises(scan.C34MObservationError):
            self._scan()
        other.rmdir()
        (self.module_dir / "broker.py").unlink()
        (self.module_dir / "broker.py").symlink_to("audit.py")
        with self.assertRaises(scan.C34MObservationError):
            self._scan()

    def test_hardlinked_and_wrong_mode_original_rejected(self):
        """Source modules must have exactly one link and expected mode."""
        original = self.module_dir / "broker.py"
        extra = self.temp.name + "/outside-link"
        os.link(original, extra)
        with self.assertRaises(scan.C34MObservationError):
            self._scan()
        os.unlink(extra)
        original.chmod(0o600)
        with self.assertRaises(scan.C34MObservationError):
            self._scan()

    def test_missing_one_of_41_rejected(self):
        """Omission is not allowed even when the other 40 files are valid."""
        (self.module_dir / "audit.py").unlink()
        with self.assertRaises(scan.C34MObservationError):
            self._scan()

    def test_all_five_half_written_stages_verified(self):
        """Only the current step's exact byte prefix may be pending."""
        for phase in range(5):
            with self.subTest(phase=phase):
                target = ("PROTECTED-TARGET-" + str(phase)).encode("ascii")
                path = self._stage(phase, target[:7])
                try:
                    observed = self._scan()
                    self.assertEqual(
                        observed.pending_stages, (scan._STAGE_LABELS[phase],)
                    )
                    self.assertTrue(self._attest(observed, phase, target))
                    if phase != 4:
                        with self.assertRaises(scan.C34MObservationError):
                            self._attest(observed, phase + 1, target)
                finally:
                    path.unlink()

    def test_zero_length_stage_is_valid_interruption_prefix(self):
        """An interruption immediately after O_EXCL creates an empty stage."""
        target = b"APPROVED-BROKER-CONTENT"
        path = self._stage(0, b"")
        self.assertTrue(self._attest(self._scan(), 0, target))
        path.unlink()

    def test_fully_written_source_stage_recovery(self):
        """Full stage must have final mode and complete approved bytes."""
        target = b"APPROVED-INTEGRATION-MODULE"
        path = self._stage(2, target, 0o644)
        self.assertTrue(self._attest(self._scan(), 2, target))
        path.unlink()

    def test_full_mode_requires_complete_target(self):
        """A 0644 stage with only a prefix is not ready for atomic replace."""
        target = b"COMPLETE-INTEGRATION"
        path = self._stage(2, target[:5], 0o644)
        with self.assertRaises(scan.C34MObservationError):
            self._attest(self._scan(), 2, target)
        path.unlink()

    def test_corrupt_stage_and_wrong_next_phase_rejected(self):
        """Unknown or mismatched partial contents never count as valid."""
        path = self._stage(0, b"UNAPPROVED")
        with self.assertRaises(scan.C34MObservationError):
            self._attest(self._scan(), 0, b"APPROVED")
        with self.assertRaises(scan.C34MObservationError):
            self._attest(self._scan(), 5, b"UNAPPROVED")
        path.unlink()

    def test_two_simultaneous_stages_rejected(self):
        """Only one unfinished operation may exist across app/config dirs."""
        a = self._stage(0, b"")
        b = self._stage(3, b"")
        with self.assertRaises(scan.C34MObservationError):
            self._scan()
        a.unlink()
        b.unlink()

    def test_unknown_config_stage_and_symlink_rejected(self):
        """No caller may introduce another C34J or legacy migration stage."""
        stray = self.executor_dir / ".omnilyzer-c34j-unknown.json.stage"
        stray.write_bytes(b"")
        with self.assertRaises(scan.C34MObservationError):
            self._scan()
        stray.unlink()
        target = self._stage(3, b"")
        target.unlink()
        target.symlink_to(self.module_dir / "audit.py")
        with self.assertRaises(scan.C34MObservationError):
            self._scan()

    def test_bad_config_directory_mode_rejected(self):
        """A strict sandbox must distinguish 0750 config from 0700."""
        self.executor_dir.chmod(0o700)
        with self.assertRaises(scan.C34MObservationError):
            self._scan()

    def test_config_stage_mode_and_corruption(self):
        """Completed canonical JSON stages have mode 0640, not 0644."""
        target = b'{"reviewed_commit":"final"}\n'
        stage = self._stage(4, target, 0o640)
        self.assertTrue(self._attest(self._scan(), 4, target))
        stage.chmod(0o644)
        with self.assertRaises(scan.C34MObservationError):
            self._attest(self._scan(), 4, target)
        stage.unlink()

    def test_finished_generation_rejects_leftover_stage(self):
        """Phase 5 can never report an unfinished sixth publication."""
        stage = self._stage(4, b"")
        with self.assertRaises(scan.C34MObservationError):
            self._attest(self._scan(), 5, None)
        stage.unlink()

    def test_forged_observation_cannot_claim_multiple_stages(self):
        """A fabricated receipt with simultaneous stages is rejected."""
        state = self._scan()
        with self.assertRaises(ValueError):
            replace(state, pending_stages=(
                scan._STAGE_LABELS[0], scan._STAGE_LABELS[1],
            ))

    def test_forged_path_order_and_digest_shape_refused(self):
        """A synthetic receipt cannot silently reorder the 41-file source set."""
        observation = self._scan()
        swapped = (
            observation.source_digests[1],
            observation.source_digests[0],
            *observation.source_digests[2:],
        )
        with self.assertRaises(ValueError):
            replace(observation, source_digests=swapped)
        altered = (
            ("unlisted.py", observation.source_digests[0][1]),
            *observation.source_digests[1:],
        )
        with self.assertRaises(ValueError):
            replace(observation, source_digests=altered)

    def test_no_mutating_or_live_host_public_api(self):
        """Only the two read-only operations are exported."""
        self.assertEqual(scan.__all__, (
            "C34MObservationError", "C34MSourceObservation",
            "observe_c34m_closed_generation", "attest_c34m_next_stage",
        ))


if __name__ == "__main__":
    unittest.main()

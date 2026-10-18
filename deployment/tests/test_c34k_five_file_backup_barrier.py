"""File: deployment/tests/test_c34k_five_file_backup_barrier.py

Purpose: Qualify complete five-backup-before-publication requirement and
reject missing, substituted, corrupt, linked, or unknown recovery artifacts.
Related: deployment/c34k_five_file_backup_barrier.py,
deployment/c34j_atomic_file_mechanics.py,
deployment/tests/test_c34j_atomic_file_mechanics.py.

Every fixture is an unprivileged disposable private filesystem. No root
service access, installed application/config, GitHub/registry, or deployment.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deployment import c34k_five_file_backup_barrier as barrier
from deployment import c34j_atomic_file_mechanics as mechanics


class C34KOriginalBackupTests(unittest.TestCase):
    """Exercise exact backup-cohort creation and fail-closed requalification."""

    def setUp(self) -> None:
        """Create five synthetic installed files and a private backup directory."""
        self.temporary = tempfile.TemporaryDirectory(prefix="omnilyzer-c34k-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "app"
        self.config = self.root / "config"
        self.backup = self.root / "private-backups"
        for path, mode in (
            (self.app, 0o755), (self.config, 0o750), (self.backup, 0o700),
        ):
            path.mkdir()
            path.chmod(mode)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.app_fd = self._open(self.app)
        self.config_fd = self._open(self.config)
        self.backup_fd = self._open(self.backup)
        self.originals = (
            b"# protected broker original\nVALUE = 0\n",
            b"# protected ingress original\nVALUE = 1\n",
            b"# protected composition original\nVALUE = 2\n",
            b'{"reviewed_commit":"predecessor"}\n',
            b'{"expected_workflow_sha":"old"}\n',
        )
        self.sources = []
        self.paths = []
        for idx, name in enumerate(barrier._ORDER):
            mode = 0o640 if name.endswith(".json") else 0o644
            directory = self.config if mode == 0o640 else self.app
            p = directory / name
            p.write_bytes(self.originals[idx])
            p.chmod(mode)
            self.paths.append(p)
            self.sources.append(
                barrier.C34KOriginalSource(
                    identity=mechanics.C34JFileIdentity(
                        name=name, uid=self.uid, gid=self.gid, mode=mode,
                        original_sha256=hashlib.sha256(
                            self.originals[idx]
                        ).hexdigest(),
                        target_sha256=hashlib.sha256(
                            self.originals[idx] + b"target"
                        ).hexdigest(),
                    ),
                    source_dir_fd=(
                        self.config_fd if mode == 0o640 else self.app_fd
                    ),
                    original=self.originals[idx],
                ),
            )
        self.sources = tuple(self.sources)

    def _open(self, path: Path) -> int:
        """Retain a verified sandbox-only directory descriptor for each test."""
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                     | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return fd

    def _seal(self):
        """Invoke backup-only operation with the complete ordered source set."""
        return barrier.seal_all_five_original_backups(
            sources=self.sources,
            backup_dir_fd=self.backup_fd,
            backup_uid=self.uid,
            backup_gid=self.gid,
        )

    def _verify(self):
        """Check all backups without creating any missing files."""
        return barrier.require_complete_original_backups(
            sources=self.sources,
            backup_dir_fd=self.backup_fd,
            backup_uid=self.uid,
            backup_gid=self.gid,
        )

    def test_complete_five_backups_preserve_all_sources(self):
        """All five sealed originals exist before returning a success receipt."""
        receipt = self._seal()
        self.assertTrue(receipt.all_five_sealed)
        self.assertEqual(len(receipt.original_sha256), 5)
        self.assertEqual(
            set(os.listdir(self.backup_fd)), set(barrier._BACKUPS),
        )
        for expected, name, installed in zip(
            self.originals, barrier._BACKUPS, self.paths, strict=True,
        ):
            self.assertEqual((self.backup / name).read_bytes(), expected)
            self.assertEqual(installed.read_bytes(), expected)
        self.assertEqual(self._verify(), receipt)

    def test_second_seal_keeps_stable_original_inodes(self):
        """Requalification never creates an alternate backup generation."""
        self._seal()
        before = tuple(
            (self.backup / name).stat().st_ino for name in barrier._BACKUPS
        )
        self.assertEqual(self._seal(), self._verify())
        self.assertEqual(
            tuple((self.backup / name).stat().st_ino
                  for name in barrier._BACKUPS), before,
        )

    def test_missing_fifth_source_blocks_all_backup_mutation(self):
        """Inspect all five installed sources before writing any backup."""
        self.paths[4].unlink()
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertEqual(os.listdir(self.backup_fd), [])

    def test_changed_fifth_source_blocks_all_backup_mutation(self):
        """A correct first four files cannot mask a changed final config."""
        self.paths[4].write_bytes(b"tampered")
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertEqual(os.listdir(self.backup_fd), [])

    def test_partial_backup_resumes_only_exact_bytes(self):
        """Interrupted backup writes resume, without replacing a different file."""
        first = self.backup / barrier._BACKUPS[0]
        first.write_bytes(self.originals[0][:7])
        first.chmod(0o600)
        self._seal()
        self.assertEqual(first.read_bytes(), self.originals[0])
        first.write_bytes(b"unreviewed")
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertEqual(first.read_bytes(), b"unreviewed")

    def test_missing_or_corrupt_backup_blocks_requalification(self):
        """A later one-step installer cannot advance without every backup."""
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._verify()
        self._seal()
        (self.backup / barrier._BACKUPS[3]).write_bytes(b"corrupt")
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._verify()

    def test_unknown_backup_directory_member_blocks_seal(self):
        """Unexpected filenames/directories are never silently discarded."""
        unknown = self.backup / "unreviewed-secret"
        unknown.write_bytes(b"unexpected")
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertEqual(unknown.read_bytes(), b"unexpected")
        self.assertEqual(len(os.listdir(self.backup_fd)), 1)

    def test_symlink_backup_is_rejected(self):
        """A forged backup symlink cannot be followed or overwritten."""
        (self.backup / barrier._BACKUPS[0]).symlink_to(self.paths[0])
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertTrue((self.backup / barrier._BACKUPS[0]).is_symlink())
        self.assertEqual(self.paths[0].read_bytes(), self.originals[0])

    def test_swapped_roles_or_duplicate_source_blocked(self):
        """The order and all five file names are part of the authority."""
        with self.assertRaises(barrier.C34KBackupBarrierError):
            barrier.seal_all_five_original_backups(
                sources=self.sources[:-1] + (self.sources[0],),
                backup_dir_fd=self.backup_fd,
                backup_uid=self.uid,
                backup_gid=self.gid,
            )
        self.assertEqual(os.listdir(self.backup_fd), [])

    def test_wrong_backup_directory_mode_blocked(self):
        """A mode-0755 backup directory is not acceptable for private data."""
        self.backup.chmod(0o755)
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()
        self.assertEqual(os.listdir(self.backup_fd), [])

    def test_mid_cohort_backup_failure_never_returns_pass(self):
        """A failed third seal must not return a partial success receipt."""
        original = mechanics.seal_original_backup
        calls = []

        def fail_at_third(**kw):
            """Stop at the third reviewed backup without changing app bytes."""
            calls.append(kw["backup_name"])
            if len(calls) == 3:
                raise OSError("private synthetic failure")
            return original(**kw)

        with patch.object(barrier.files, "seal_original_backup",
                          side_effect=fail_at_third):
            with self.assertRaises(barrier.C34KBackupBarrierError):
                self._seal()
        self.assertEqual(
            set(os.listdir(self.backup_fd)), set(barrier._BACKUPS[:2]),
        )
        for p, old in zip(self.paths, self.originals, strict=True):
            self.assertEqual(p.read_bytes(), old)
        self._seal()
        self.assertEqual(self._verify().all_five_sealed, True)

    def test_existing_backup_can_be_rechecked_after_installed_source_change(self):
        """Rollback evidence survives subsequent legitimate source replacement."""
        self._seal()
        self.paths[0].write_bytes(b"approved-target-synthetic")
        self.assertTrue(self._verify().all_five_sealed)
        with self.assertRaises(barrier.C34KBackupBarrierError):
            self._seal()

    def test_fixed_public_api_never_issues_source_publication(self):
        """The backup barrier has no write-to-installed-file operation."""
        self.assertEqual(barrier.__all__, (
            "C34KBackupBarrierError",
            "C34KOriginalSource",
            "C34KBackupReceipt",
            "seal_all_five_original_backups",
            "require_complete_original_backups",
        ))


if __name__ == "__main__":
    unittest.main()

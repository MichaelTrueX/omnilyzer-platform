"""File: deployment/tests/test_c34j_atomic_file_mechanics.py

Purpose: Qualify descriptor-based, private-backup, prefix-resumable file
publication with negative security and crash-stage acceptance tests.
Related: deployment/c34j_atomic_file_mechanics.py,
deployment/c34h_transition_rehearsal.py,
deployment/tests/test_c34h_transition_rehearsal.py.

All operations occur exclusively within each test's TemporaryDirectory
under the unprivileged GitHub runner. No installed files, root, services,
network, replay, registry credentials or protected config are accessed.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest

from deployment import c34j_atomic_file_mechanics as subject


class C34JAtomicDescriptorTests(unittest.TestCase):
    """Prove exact single-file backup and atomic publish contracts."""

    def setUp(self):
        """Build a private directory hierarchy and synthetic original bytes."""
        self.temporary = tempfile.TemporaryDirectory(prefix="c34j-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "app"
        self.config = self.root / "config"
        self.backup = self.root / "backup"
        for path, mode in ((self.app, 0o755),
                           (self.config, 0o750), (self.backup, 0o700)):
            path.mkdir()
            path.chmod(mode)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.original = b"# Old trusted broker\nACTION = 'old'\n"
        self.target = b"# New trusted broker\nACTION = 'diagnostic'\n"
        self.source = self.app / "broker.py"
        self.source.write_bytes(self.original)
        self.source.chmod(0o644)
        self.identity = subject.C34JFileIdentity(
            name="broker.py",
            original_sha256=hashlib.sha256(self.original).hexdigest(),
            target_sha256=hashlib.sha256(self.target).hexdigest(),
            uid=self.uid, gid=self.gid, mode=0o644,
        )
        self.stage = self.app / ".omnilyzer-c34j-broker.py.stage"

    def _open_directory(self, path):
        """Open only a newly created private test dir, no link traversal."""
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, descriptor)
        return descriptor

    def _seal(self):
        """Create/revalidate exactly one synthetic private root-equivalent copy."""
        fd = self._open_directory(self.backup)
        digest = subject.seal_original_backup(
            backup_dir_fd=fd, backup_name="00-broker.py",
            original=self.original, uid=self.uid, gid=self.gid,
        )
        self.assertEqual(digest, self.identity.original_sha256)
        return fd

    def _publish(self, *, backup_fd=None):
        """Publish a synthetic broker file using only retained dir descriptors."""
        if backup_fd is None:
            backup_fd = self._open_directory(self.backup)
        return subject.publish_exact_file(
            parent_fd=self._open_directory(self.app),
            backup_dir_fd=backup_fd, backup_uid=self.uid,
            backup_gid=self.gid, backup_name="00-broker.py",
            identity=self.identity, original=self.original,
            target=self.target,
            stage_name=".omnilyzer-c34j-broker.py.stage",
        )

    def test_backup_is_durable_private_and_idempotent(self):
        """A repeated seal must preserve original bytes and mode 0600."""
        fd = self._seal()
        target = self.backup / "00-broker.py"
        before = target.stat()
        self.assertEqual(target.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        subject.seal_original_backup(
            backup_dir_fd=fd, backup_name="00-broker.py",
            original=self.original, uid=self.uid, gid=self.gid,
        )
        self.assertEqual(target.stat().st_ino, before.st_ino)

    def test_backup_can_resume_only_an_exact_partial_prefix(self):
        """A partial backup can resume; a corrupt one is never replaced."""
        path = self.backup / "00-broker.py"
        path.write_bytes(self.original[:8])
        path.chmod(0o600)
        self._seal()
        self.assertEqual(path.read_bytes(), self.original)
        path.write_bytes(b"UNAUTHORIZED_BACKUP")
        with self.assertRaises(subject.C34JAtomicFileError):
            self._seal()
        self.assertEqual(path.read_bytes(), b"UNAUTHORIZED_BACKUP")

    def test_one_exact_atomic_publication_and_idempotent_failure(self):
        """Only an original-byte destination can be replaced."""
        backup_fd = self._seal()
        receipt = self._publish(backup_fd=backup_fd)
        self.assertTrue(receipt.backup_sealed)
        self.assertTrue(receipt.target_published)
        self.assertEqual(self.source.read_bytes(), self.target)
        self.assertFalse(self.stage.exists())
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o644)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.assertEqual(self.source.read_bytes(), self.target)

    def test_resume_partial_stage(self):
        """An interrupted exact target prefix is written then renamed."""
        backup_fd = self._seal()
        self.stage.write_bytes(self.target[:11])
        self.stage.chmod(0o600)
        self._publish(backup_fd=backup_fd)
        self.assertEqual(self.source.read_bytes(), self.target)
        self.assertFalse(self.stage.exists())

    def test_full_stage_resumes_without_appending_duplicate_bytes(self):
        """An already complete, properly staged payload may publish once."""
        backup_fd = self._seal()
        self.stage.write_bytes(self.target)
        self.stage.chmod(0o644)
        self._publish(backup_fd=backup_fd)
        self.assertEqual(self.source.read_bytes(), self.target)

    def test_missing_and_corrupted_backup_block_publication(self):
        """No destination replacement when sealed original evidence is absent."""
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish()
        self.assertEqual(self.source.read_bytes(), self.original)
        self._seal()
        (self.backup / "00-broker.py").write_bytes(b"FAKE")
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_corrupted_stage_and_symlink_fail_without_destination_mutation(self):
        """No overwritten stage and no link-following fallback."""
        backup_fd = self._seal()
        self.stage.write_bytes(b"CORRUPT")
        self.stage.chmod(0o600)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.assertEqual(self.stage.read_bytes(), b"CORRUPT")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.stage.unlink()
        self.stage.symlink_to(self.source)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_target_symlink_and_hardlink_fail_closed(self):
        """A linked original cannot be trusted as the sole installed file."""
        backup_fd = self._seal()
        other = self.root / "other.py"
        other.write_bytes(self.original)
        self.source.unlink()
        self.source.symlink_to(other)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.source.unlink()
        os.link(other, self.source)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.assertEqual(other.read_bytes(), self.original)

    def test_wrong_source_digests_or_modes_block_publication(self):
        """A file changed after backup must not be silently overwritten."""
        backup_fd = self._seal()
        self.source.write_bytes(b"TAMPERED")
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.source.write_bytes(self.original)
        self.source.chmod(0o600)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)

    def test_invalid_directory_permissions_block_publication(self):
        """A writable or wrong-mode parent is outside the protected contract."""
        backup_fd = self._seal()
        self.app.chmod(0o777)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)
        self.app.chmod(0o755)
        self.backup.chmod(0o755)
        with self.assertRaises(subject.C34JAtomicFileError):
            self._publish(backup_fd=backup_fd)

    def test_executor_style_config_uses_separate_backup_and_mode(self):
        """Config mode 0640 and 0750 directory differ from app modules."""
        original = b'{"reviewed_commit":"old"}\n'
        target = b'{"reviewed_commit":"new"}\n'
        file = self.config / "dev.json"
        file.write_bytes(original)
        file.chmod(0o640)
        ident = subject.C34JFileIdentity(
            name="dev.json", original_sha256=hashlib.sha256(original).hexdigest(),
            target_sha256=hashlib.sha256(target).hexdigest(),
            uid=self.uid, gid=self.gid, mode=0o640,
        )
        backup_fd = self._open_directory(self.backup)
        subject.seal_original_backup(
            backup_dir_fd=backup_fd, backup_name="04-broker.json",
            original=original, uid=self.uid, gid=self.gid,
        )
        receipt = subject.publish_exact_file(
            parent_fd=self._open_directory(self.config),
            backup_dir_fd=backup_fd, backup_uid=self.uid, backup_gid=self.gid,
            backup_name="04-broker.json", identity=ident,
            original=original, target=target,
            stage_name=".omnilyzer-c34j-dev.json.stage",
        )
        self.assertTrue(receipt.target_published)
        self.assertEqual(file.read_bytes(), target)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o640)

    def test_cross_file_backup_reuse_is_rejected(self):
        """A broker source may never point to a different step's backup."""
        self._seal()
        wrong = self.backup / "01-broker_https_ingress.py"
        wrong.write_bytes(self.original)
        wrong.chmod(0o600)
        with self.assertRaises(subject.C34JAtomicFileError):
            subject.publish_exact_file(
                parent_fd=self._open_directory(self.app),
                backup_dir_fd=self._open_directory(self.backup),
                backup_uid=self.uid, backup_gid=self.gid,
                backup_name="01-broker_https_ingress.py",
                identity=self.identity,
                original=self.original, target=self.target,
                stage_name=".omnilyzer-c34j-broker.py.stage",
            )
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_arbitrary_names_and_modes_rejected(self):
        """Caller cannot request a path traversal or a sixth target."""
        with self.assertRaises(ValueError):
            subject.C34JFileIdentity(
                name="../../etc/passwd", original_sha256="a" * 64,
                target_sha256="b" * 64, uid=self.uid, gid=self.gid,
                mode=0o644,
            )
        with self.assertRaises(ValueError):
            subject.C34JFileIdentity(
                name="broker.py", original_sha256="a" * 64,
                target_sha256="b" * 64, uid=self.uid, gid=self.gid,
                mode=0o777,
            )
        backup_fd = self._seal()
        with self.assertRaises(subject.C34JAtomicFileError):
            subject.publish_exact_file(
                parent_fd=self._open_directory(self.app),
                backup_dir_fd=backup_fd, backup_uid=self.uid,
                backup_gid=self.gid, backup_name="00-broker.py",
                identity=self.identity, original=self.original,
                target=self.target, stage_name="../wrong.stage",
            )
        self.assertEqual(self.source.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()

"""Fresh restore and mandatory corruption-rejection tests."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


SPIKE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SPIKE))

from durability.backup import BackupError, create_backup  # noqa: E402
from durability.restore import restore_backup  # noqa: E402
from durability.zot_process import (  # noqa: E402
    EXPECTED_BINARY_SHA256,
    EXPECTED_VERSION,
    VerifiedBinary,
)
from validate_zot_recovery import _corruption_matrix  # noqa: E402


BINARY = VerifiedBinary(Path("/usr/local/bin/zot"), EXPECTED_VERSION, EXPECTED_BINARY_SHA256, "test")


class RestorePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "nested").mkdir()
        (self.source / "nested" / "one").write_bytes(b"one")
        (self.source / "two").write_bytes(b"two")
        self.backup = self.root / "backup"
        create_backup(self.source, self.backup, BINARY)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_fresh_restore_is_exact(self) -> None:
        destination = self.root / "restore"
        destination.mkdir(mode=0o700)
        result = restore_backup(self.backup, destination, BINARY)
        self.assertTrue(result["restored"])
        self.assertEqual((destination / "nested" / "one").read_bytes(), b"one")
        self.assertEqual((destination / "two").read_bytes(), b"two")

    def test_destination_must_exist_and_be_empty(self) -> None:
        missing = self.root / "missing"
        with self.assertRaisesRegex(BackupError, "new empty"):
            restore_backup(self.backup, missing, BINARY)
        nonempty = self.root / "nonempty"
        nonempty.mkdir()
        (nonempty / "existing").write_bytes(b"preserve")
        with self.assertRaisesRegex(BackupError, "not empty"):
            restore_backup(self.backup, nonempty, BINARY)
        self.assertEqual((nonempty / "existing").read_bytes(), b"preserve")

    def test_all_mandatory_corruptions_fail_closed_without_partial_restore(self) -> None:
        results = _corruption_matrix(self.root, self.backup, BINARY)
        self.assertEqual(results, {
            "modified_payload_byte_rejected": True,
            "missing_required_file_rejected": True,
            "unexpected_file_rejected": True,
            "truncated_archive_rejected": True,
            "nonempty_destination_rejected": True,
            "path_traversal_rejected": True,
            "absolute_path_rejected": True,
            "duplicate_path_rejected": True,
            "symlink_rejected": True,
        })


if __name__ == "__main__":
    unittest.main()

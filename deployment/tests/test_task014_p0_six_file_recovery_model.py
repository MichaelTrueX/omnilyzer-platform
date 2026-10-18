"""Task 014 four-source/six-file recovery acceptance MODEL (test-only).

No production migration/recovery implementation or root execution is authorized.
Only synthetic TemporaryDirectory files and deterministic bytes are used.
Historic C34K five-backup and C34O six-prefix classes remain unchanged.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from deployment import c34k_five_file_backup_barrier as historic_backup
from deployment import c34o_six_prefix_recovery_inspection as historic_recovery


# A prospective 4 protected Python + 2 canonical authority config migration.
# These are synthetic basenames, not production paths or root execution targets.
_ORDER = (
    "broker.py",
    "broker_https_ingress.py",
    "broker_integration.py",
    "broker_loopback_listener.py",
    "executor.json",
    "dev.json",
)
_SOURCE_NAMES = _ORDER[:4]
_CONFIG_NAMES = _ORDER[4:]
_PREFIXES = tuple(range(7))


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _SyntheticSixFileCohort:
    """Test helper, deliberately unable to access a production application path."""

    def __init__(self, root: Path):
        self.installed = root / "synthetic-installed"
        self.backups = root / "synthetic-backups"
        self.installed.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        self.original = {name: ("ORIGINAL:" + name).encode("ascii") for name in _ORDER}
        self.target = {name: ("TARGET:" + name).encode("ascii") for name in _ORDER}
        for name in _ORDER:
            (self.installed / name).write_bytes(self.original[name])

    def seal_all_originals(self) -> None:
        """Simulate a complete protected backup barrier, never real host authority."""
        if any(self.backups.iterdir()):
            raise ValueError("synthetic backups must start empty")
        for name in _ORDER:
            current = (self.installed / name).read_bytes()
            if _hash(current) != _hash(self.original[name]):
                raise ValueError("synthetic predecessor changed")
            (self.backups / name).write_bytes(current)
        self.verify_backups()

    def verify_backups(self) -> None:
        observed = {p.name for p in self.backups.iterdir()}
        if observed != set(_ORDER):
            raise ValueError("synthetic original backup set incomplete or unexpected")
        for name in _ORDER:
            item = self.backups / name
            if item.is_symlink() or not item.is_file():
                raise ValueError("synthetic backup path is not a file")
            if _hash(item.read_bytes()) != _hash(self.original[name]):
                raise ValueError("synthetic original backup checksum failure")

    def forward(self, prefix: int) -> None:
        if type(prefix) is not int or prefix not in _PREFIXES:
            raise ValueError("invalid synthetic prefix")
        self.verify_backups()
        for name in _ORDER[:prefix]:
            (self.installed / name).write_bytes(self.target[name])
        self.classify(prefix)

    def classify(self, prefix: int) -> None:
        """All six bytes must match the one selected publication prefix."""
        if type(prefix) is not int or prefix not in _PREFIXES:
            raise ValueError("invalid synthetic prefix")
        self.verify_backups()
        for n, name in enumerate(_ORDER):
            expected = self.target[name] if n < prefix else self.original[name]
            if _hash((self.installed / name).read_bytes()) != _hash(expected):
                raise ValueError("synthetic installation does not match prefix")

    def rollback(self, prefix: int) -> None:
        """Simulate reverse-prefix restoration from verified originals only."""
        self.classify(prefix)
        for name in reversed(_ORDER[:prefix]):
            self.verify_backups()
            (self.installed / name).write_bytes(self.original[name])
        self.classify(0)


class TestTask014P0SixFileRecoveryModel(unittest.TestCase):
    def test_exact_four_source_two_config_cardinality(self):
        self.assertEqual(len(_SOURCE_NAMES), 4)
        self.assertEqual(len(_CONFIG_NAMES), 2)
        self.assertEqual(len(_ORDER), 6)
        self.assertEqual(_PREFIXES, (0, 1, 2, 3, 4, 5, 6))
        self.assertEqual(len(set(_ORDER)), 6)

    def test_historical_five_file_and_six_prefix_are_not_reauthorized(self):
        self.assertEqual(len(historic_backup._ORDER), 5)
        self.assertEqual(tuple(historic_backup._ORDER[:3]), _SOURCE_NAMES[:3])
        self.assertNotIn("broker_loopback_listener.py", historic_backup._ORDER)
        self.assertTrue(callable(historic_recovery.inspect_c34o_six_prefix_candidate))

    def test_all_seven_forward_and_reverse_interruption_states(self):
        for prefix in _PREFIXES:
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory(
                prefix="task014-six-file-review-"
            ) as path:
                subject = _SyntheticSixFileCohort(Path(path))
                subject.seal_all_originals()
                subject.forward(prefix)
                subject.classify(prefix)
                subject.rollback(prefix)
                subject.classify(0)

    def test_no_publication_before_complete_original_backup(self):
        with tempfile.TemporaryDirectory(prefix="task014-six-file-review-") as path:
            subject = _SyntheticSixFileCohort(Path(path))
            with self.assertRaises(ValueError):
                subject.forward(1)
            self.assertEqual(
                {name: (subject.installed / name).read_bytes() for name in _ORDER},
                subject.original,
            )

    def test_missing_or_corrupted_backup_fails_before_publication(self):
        for failure in ("delete", "alter", "symlink"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(
                prefix="task014-six-file-review-"
            ) as path:
                subject = _SyntheticSixFileCohort(Path(path))
                subject.seal_all_originals()
                target = subject.backups / "broker_loopback_listener.py"
                if failure == "delete":
                    target.unlink()
                elif failure == "alter":
                    target.write_bytes(b"SYNTHETIC_INVALID_HASH")
                else:
                    target.unlink()
                    target.symlink_to(subject.installed / target.name)
                with self.assertRaises(ValueError):
                    subject.forward(1)
                self.assertEqual(
                    (subject.installed / "broker.py").read_bytes(),
                    subject.original["broker.py"],
                )

    def test_interrupted_prefix_or_unexpected_change_rejected(self):
        with tempfile.TemporaryDirectory(prefix="task014-six-file-review-") as path:
            subject = _SyntheticSixFileCohort(Path(path))
            subject.seal_all_originals()
            subject.forward(3)
            (subject.installed / "dev.json").write_bytes(b"UNEXPECTED_SYNTHETIC")
            with self.assertRaises(ValueError):
                subject.classify(3)
            with self.assertRaises(ValueError):
                subject.rollback(3)

    def test_incomplete_or_noncanonical_prefix_rejected(self):
        with tempfile.TemporaryDirectory(prefix="task014-six-file-review-") as path:
            subject = _SyntheticSixFileCohort(Path(path))
            subject.seal_all_originals()
            for bad in (-1, 7, 1.0, True, "2", None):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    subject.forward(bad)
            self.assertEqual(
                {name: (subject.installed / name).read_bytes() for name in _ORDER},
                subject.original,
            )


if __name__ == "__main__":
    unittest.main()

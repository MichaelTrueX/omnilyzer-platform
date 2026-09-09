from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest

from deployment.audit import FilesystemAuditSink
from deployment.policy import DeploymentPolicyError
from deployment.tests.test_audit import value
from deployment.audit import AuditEvent


class FilesystemAuditTests(unittest.TestCase):
    def event(self, event_id: str, timestamp: str = "2026-09-08T12:00:00Z") -> AuditEvent:
        raw = value("promotion_started")
        raw["event_id"] = event_id
        raw["timestamp"] = timestamp
        return AuditEvent.from_dict(raw)

    def test_canonical_append_modes_and_hash_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private/events.jsonl"
            sink = FilesystemAuditSink(path)
            sink.append(self.event("one"))
            sink.append(self.event("two"))
            lines = path.read_bytes().splitlines(keepends=True)
            first, second = map(json.loads, lines)
            import hashlib
            self.assertIsNone(first["previous_event_sha256"])
            self.assertEqual(second["previous_event_sha256"], hashlib.sha256(lines[0]).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_duplicate_and_malformed_history_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = FilesystemAuditSink(path)
            sink.append(self.event("one"))
            with self.assertRaisesRegex(DeploymentPolicyError, "duplicate"):
                sink.append(self.event("one"))
            path.write_bytes(b'{"broken":true}\n')
            with self.assertRaises(DeploymentPolicyError):
                sink.append(self.event("two"))

    def test_rotation_renames_without_copytruncate_and_preserves_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = FilesystemAuditSink(path, rotate_bytes=1024)
            sink.append(self.event("day-one", "2026-09-08T23:59:59Z"))
            old_inode = path.stat().st_ino
            sink.append(self.event("day-two", "2026-09-09T00:00:00Z"))
            rotations = [item for item in path.parent.iterdir() if item.name.startswith("events.jsonl.")]
            self.assertEqual(len(rotations), 1)
            self.assertNotEqual(path.stat().st_ino, old_inode)
            previous_line = rotations[0].read_bytes()
            current = json.loads(path.read_bytes())
            import hashlib
            self.assertEqual(current["previous_event_sha256"], hashlib.sha256(previous_line).hexdigest())
            sink.append(self.event("day-three", "2026-09-10T00:00:00Z"))
            self.assertTrue(any(item.suffix == ".gz" for item in path.parent.iterdir()))
            self.assertNotIn("copytruncate", Path(__file__).resolve().parents[1].joinpath("audit.py").read_text())

    def test_oversized_event_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = FilesystemAuditSink(path)
            raw = value("promotion_started")
            raw["migration_identity"] = "a" * 20000
            with self.assertRaises(DeploymentPolicyError):
                AuditEvent.from_dict(raw)

    def test_rotation_retains_exactly_fourteen_and_uses_retained_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            sink = FilesystemAuditSink(path, rotate_bytes=1024)
            for day in range(1, 17):
                sink.append(self.event(f"event-{day}", f"2026-09-{day:02d}T00:00:00Z"))
            rotations = [
                item for item in path.parent.iterdir()
                if item.name.startswith("events.jsonl.")
            ]
            self.assertEqual(len(rotations), 14)
            sink.append(self.event("event-17", "2026-09-17T00:00:00Z"))


if __name__ == "__main__":
    unittest.main()

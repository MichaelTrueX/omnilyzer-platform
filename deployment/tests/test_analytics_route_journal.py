"""File: deployment/tests/test_analytics_route_journal.py

Purpose: Prove the Task14B Analytics route journal is durable, bounded,
         owner-scoped, strictly canonical and fail-closed across restarts.
Related: deployment/analytics_route_journal.py,
         deployment/analytics_loopback_guard.py,
         deployment/tests/test_analytics_loopback_guard.py,
         deployment/replay_sqlite.py (independent JTI replay).
Sections: exact phase transitions; corrupt/stale file protection; real fsync
          publication/rename; negative transition and restart simulations.
No production path, Docker, RootlessKit, systemd, registry or PostgreSQL touched.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_route_journal import (
    AnalyticsRouteJournal, AnalyticsRouteJournalUnavailable,
)
from deployment.policy import canonical_bytes

IMG = "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
OLD = IMG + "6dbdc6319218b19257311d2885e9f697a75fc6066b4eef34068cc8ae6a51c1f1"
NEXT = IMG + "a" * 64
LATER = IMG + "b" * 64


def approval(**overrides):
    """Synthetic pre-reviewed identity values, never real signatures."""
    return {
        **{
            "request_sha256": "c" * 64,
            "previous_slot": "blue",
            "previous_image": OLD,
            "previous_container_id": "d" * 64,
            "previous_ip": "172.20.0.3",
            "next_slot": "green",
            "next_image": NEXT,
            "next_container_id": "e" * 64,
            "next_ip": "172.20.0.4",
        },
        **overrides,
    }


class AnalyticsRouteJournalTests(unittest.TestCase):
    """Use real kernel file permissions, fsync, rename and readback."""

    def setUp(self):
        """Create owner-controlled isolated directory with a strict 0700 mode."""
        self.temp = tempfile.TemporaryDirectory(prefix="omnilyzer-journal-")
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        directory.chmod(0o700)
        self.directory = directory
        self.path = directory / "transaction.json"
        self.journal = AnalyticsRouteJournal(
            str(directory),
            expected_uid=os.getuid(), expected_gid=os.getgid(),
        )

    def denied(self, operation):
        """Assert a generic journal HOLD with no path or identity leakage."""
        with self.assertRaises(AnalyticsRouteJournalUnavailable) as raised:
            operation()
        self.assertNotIn(str(self.directory), str(raised.exception))

    def test_begin_switched_reopen_reuse_previous_signed_image(self):
        """Both durable phases survive a fresh process object's first read."""
        self.assertIsNone(self.journal.read())
        prepared = self.journal.begin(**approval())
        self.assertEqual(prepared["phase"], "prepared")
        self.assertEqual(prepared["generation"], 1)
        self.assertEqual(self.path.read_bytes(), canonical_bytes(prepared))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        reopened = AnalyticsRouteJournal(
            str(self.directory), expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertEqual(reopened.read(), prepared)
        switched = reopened.finish(prepared, phase="switched")
        self.assertEqual(reopened.read(), switched)
        later = approval(
            request_sha256="f" * 64, previous_slot="green",
            previous_image=NEXT, previous_container_id="e" * 64,
            previous_ip="172.20.0.4", next_slot="blue",
            next_image=LATER, next_container_id="d" * 64,
            next_ip="172.20.0.3",
        )
        second = self.journal.begin(**later)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["phase"], "prepared")
        self.assertEqual(self.journal.finish(second, phase="switched")["phase"],
                         "switched")

    def test_restored_route_may_retry_with_original_signed_identity(self):
        """Rollback is a recoverable state, not a reused prior JTI."""
        pending = self.journal.begin(**approval())
        self.journal.finish(pending, phase="restored")
        again = self.journal.begin(**approval(request_sha256="f" * 64))
        self.assertEqual(again["generation"], 2)
        self.assertEqual(again["phase"], "prepared")

    def test_unresolved_prepared_blocks_any_further_mutation_even_after_restart(self):
        """A simulated hard process crash cannot silently begin a new upgrade."""
        first = self.journal.begin(**approval())
        new_instance = AnalyticsRouteJournal(
            str(self.directory), expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertEqual(new_instance.read(), first)
        self.denied(lambda: new_instance.begin(**approval(request_sha256="b" * 64)))
        self.assertEqual(self.path.read_bytes(), canonical_bytes(first))

    def test_kernel_exclusive_lock_prevents_concurrent_prepare_and_recovery(self):
        """No second process can overwrite an in-progress route transaction."""
        competitor = AnalyticsRouteJournal(
            str(self.directory), expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        with self.journal.exclusive() as transaction:
            self.assertTrue(transaction.exclusive_active())
            self.denied(lambda: competitor.begin(**approval()))
            self.denied(lambda: competitor.finish(
                {**approval(), "schema_version": 1, "phase": "prepared",
                 "generation": 1}, phase="switched",
            ))
            def competing_lock():
                with competitor.exclusive():
                    pass
            self.denied(competing_lock)
            record = transaction.begin(**approval())
            self.assertEqual(transaction.read(), record)
            transaction.finish(record, phase="restored")
        self.assertFalse(self.journal.exclusive_active())
        self.assertEqual(competitor.read()["phase"], "restored")
        restarted = competitor.begin(**approval(request_sha256="f" * 64))
        self.assertEqual(restarted["generation"], 2)

    def test_other_thread_cannot_use_same_journal_object_as_lock_owner(self):
        """A shared journal object cannot bypass the exclusive process gate."""
        import threading
        failures = []
        with self.journal.exclusive():
            def intruder():
                try:
                    self.journal.begin(**approval())
                except AnalyticsRouteJournalUnavailable:
                    failures.append("denied")
                else:
                    failures.append("unexpected-write")
            worker = threading.Thread(target=intruder, daemon=True)
            worker.start()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, ["denied"])
            self.assertIsNone(self.journal.read())
            prepared = self.journal.begin(**approval())
            self.assertEqual(prepared["phase"], "prepared")
        self.assertEqual(self.journal.read(), prepared)

    def test_wrong_finish_phase_caller_or_replay_does_not_change_journal(self):
        """No swap replay, fabricated success or foreign commit."""
        record = self.journal.begin(**approval())
        for phase in ("prepared", "interrupted", None, 3):
            with self.subTest(phase=phase):
                self.denied(lambda: self.journal.finish(record, phase=phase))
        for mutation in (
            {"generation": 20}, {"previous_image": NEXT},
            {"request_sha256": "f" * 64}, {"phase": "switched"},
        ):
            with self.subTest(mutation=mutation):
                self.denied(lambda: self.journal.finish(
                    {**record, **mutation}, phase="switched",
                ))
        self.assertEqual(self.journal.read(), record)
        done = self.journal.finish(record, phase="restored")
        self.denied(lambda: self.journal.finish(record, phase="switched"))
        self.assertEqual(self.journal.read(), done)

    def test_wrong_owned_directory_symlink_and_unexpected_residue_fail_closed(self):
        """Refuse symlinked file/dir, wrong ownership or stale temp residue."""
        self.directory.chmod(0o777)
        self.denied(self.journal.read)
        self.directory.chmod(0o700)
        self.path.symlink_to("other.json")
        self.denied(self.journal.read)
        self.path.unlink()
        (self.directory / "unknown.txt").write_bytes(b"unknown")
        self.denied(lambda: self.journal.begin(**approval()))
        (self.directory / "unknown.txt").unlink()
        (self.directory / ".transaction.json.next").write_bytes(b"stale")
        self.denied(lambda: self.journal.begin(**approval()))

    def test_corrupt_duplicate_noncanonical_oversize_and_unsafe_file_fail_closed(self):
        """File content never grants new trusted OCI or route authority."""
        valid = self.journal.begin(**approval())
        variants = (
            b"not-json",
            canonical_bytes({**valid, "schema_version": 2}),
            canonical_bytes({**valid, "phase": "other"}),
            canonical_bytes({**valid, "previous_ip": "127.0.0.1"}),
            canonical_bytes({**valid, "next_image": "analytics:latest"}),
            canonical_bytes({**valid, "next_slot": "blue"}),
            canonical_bytes({**valid, "generation": True}),
            canonical_bytes({**valid, "request_sha256": "0" * 64}),
            canonical_bytes({**valid, "extra": True}),
            canonical_bytes(valid) + b" ",
            b" " * 2049,
            canonical_bytes(valid).replace(
                b'"phase":"prepared"',
                b'"phase":"prepared","phase":"switched"',
            ),
        )
        for payload in variants:
            with self.subTest(payload=payload[:45]):
                self.path.write_bytes(payload)
                self.denied(self.journal.read)
        self.path.write_bytes(canonical_bytes(valid))
        self.path.chmod(0o644)
        self.denied(self.journal.read)
        self.path.chmod(0o600)
        self.assertEqual(self.journal.read(), valid)

    def test_failed_file_fsync_prevents_publishing_a_new_prepared_intent(self):
        """No 3141 mutation can begin if a durable prepare is unavailable."""
        real = os.fsync
        def fail_file(handle):
            mode = os.fstat(handle).st_mode
            if stat.S_ISREG(mode):
                raise OSError("synthetic file fsync failure")
            return real(handle)
        with patch("deployment.analytics_route_journal.os.fsync", side_effect=fail_file):
            self.denied(lambda: self.journal.begin(**approval()))
        self.assertFalse(self.path.exists())
        self.assertTrue((self.directory / ".transaction.json.next").exists())
        self.denied(lambda: self.journal.begin(**approval()))

    def test_atomic_replacement_failure_preserves_previous_switched_image(self):
        """A write that did not replace journal must not mutate its prior state."""
        first = self.journal.begin(**approval())
        ready = self.journal.finish(first, phase="switched")
        before = self.path.read_bytes()
        with patch(
            "deployment.analytics_route_journal.os.replace",
            side_effect=OSError("synthetic rename failure"),
        ):
            self.denied(lambda: self.journal.begin(**approval(
                request_sha256="f" * 64, previous_slot="green",
                previous_image=NEXT, previous_container_id="e" * 64,
                previous_ip="172.20.0.4", next_slot="blue",
                next_image=LATER, next_container_id="d" * 64,
                next_ip="172.20.0.3",
            )))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.path.read_bytes(), canonical_bytes(ready))


if __name__ == "__main__":
    unittest.main()

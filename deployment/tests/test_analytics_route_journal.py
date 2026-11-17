"""File: deployment/tests/test_analytics_route_journal.py

Purpose: Prove the Task14B Analytics route journal is durable, bounded,
         owner-scoped, strictly canonical and fail-closed across restarts.
Related: deployment/analytics_route_journal.py,
         deployment/analytics_loopback_guard.py,
         deployment/tests/test_analytics_loopback_guard.py,
         deployment/replay_sqlite.py (independent JTI replay).
Sections: prepared/candidate_ready/switched/restored phase transitions;
          corrupt/stale file protection; real fsync
          publication/rename; negative transition and restart simulations;
          immutable dormant-slot retirement intent and interrupted fsync HOLD.
No production path, Docker, RootlessKit, systemd, registry or PostgreSQL touched.
"""
from __future__ import annotations

import json
import base64
import hashlib
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

    def execution_request(self):
        raw = canonical_bytes({'schema_version': 3, 'product_id': 'analytics',
            'stage': 'dev', 'manifest_digest': 'sha256:' + 'a' * 64,
            'exact_image_reference': NEXT})
        request_hash = hashlib.sha256(raw).hexdigest()
        intent = self.journal.begin(**approval(request_sha256=request_hash))
        ready = self.journal.finish(intent, phase='candidate_ready')
        self.journal.finish(ready, phase='switched')
        return raw, request_hash

    # Section: no historical rollback slot may be retired without an
    # immutable fsynced pre-retirement record. No Docker operation here.
    def test_durable_retirement_intent_blocks_original_route_transitions(self):
        """Crash/restart reads exact intent but cannot accidentally proceed."""
        previous = self.journal.begin(**approval())
        switched = self.journal.finish(
            self.journal.finish(previous, phase="candidate_ready"),
            phase="switched",
        )
        intent = self.journal.prepare_slot_retirement(
            request_sha256="f" * 64,
            active_slot="green", active_image=NEXT,
            active_container_id="e" * 64,
            dormant_slot="blue", dormant_image=OLD,
            dormant_container_id="d" * 64,
            next_image=LATER,
        )
        self.assertEqual(intent["prior_generation"], switched["generation"])
        pending = self.directory / "slot-retirement.json"
        self.assertEqual(pending.read_bytes(), canonical_bytes(intent))
        self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o600)
        restart = AnalyticsRouteJournal(
            str(self.directory), expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertEqual(restart.read_slot_retirement(), intent)
        self.denied(restart.read)
        self.denied(lambda: restart.begin(**approval(
            request_sha256="b" * 64, previous_slot="green",
            previous_image=NEXT, previous_container_id="e" * 64,
            previous_ip="172.20.0.4", next_slot="blue",
            next_image=LATER, next_container_id="d" * 64,
            next_ip="172.20.0.3",
        )))
        self.denied(lambda: restart.finish(switched, phase="rollback_pending"))
        self.denied(lambda: restart.prepare_slot_retirement(
            request_sha256="b" * 64,
            active_slot="green", active_image=NEXT,
            active_container_id="e" * 64,
            dormant_slot="blue", dormant_image=OLD,
            dormant_container_id="d" * 64, next_image=LATER,
        ))

    def test_retirement_unmatched_or_unsigned_source_is_never_recorded(self):
        """Wrong old image, active ID or noncanonical OCI leaves zero residue."""
        self.journal.begin(**approval())
        ready = self.journal.finish(self.journal.read(), phase="candidate_ready")
        self.journal.finish(ready, phase="switched")
        baseline = dict(request_sha256="f" * 64,
            active_slot="green", active_image=NEXT,
            active_container_id="e" * 64,
            dormant_slot="blue", dormant_image=OLD,
            dormant_container_id="d" * 64, next_image=LATER)
        for field, value in (
            ("request_sha256", "0" * 64),
            ("dormant_slot", "green"),
            ("dormant_image", LATER),
            ("active_image", OLD),
            ("active_container_id", "c" * 64),
            ("dormant_container_id", "0" * 64),
            ("next_image", "omnilyzer:latest"),
            ("next_image", NEXT),
        ):
            with self.subTest(field=field, value=value):
                self.denied(lambda: self.journal.prepare_slot_retirement(
                    **{**baseline, field: value},
                ))
                self.assertFalse((self.directory / "slot-retirement.json").exists())
        # A normal first-successor prepared or restored state is not a
        # committed source of the active old/new slot identities.
        self.denied(lambda: self.journal.prepare_slot_retirement(
            **{**baseline, "active_slot": "blue"},
        ))

    def test_retirement_file_permission_and_corruption_preserve_hold(self):
        """A forged symlink, changed mode or partial fsync blocks recovery."""
        self.journal.begin(**approval())
        ready = self.journal.finish(self.journal.read(), phase="candidate_ready")
        self.journal.finish(ready, phase="switched")
        kwargs = dict(request_sha256="f" * 64,
            active_slot="green", active_image=NEXT,
            active_container_id="e" * 64,
            dormant_slot="blue", dormant_image=OLD,
            dormant_container_id="d" * 64, next_image=LATER)
        intent = self.journal.prepare_slot_retirement(**kwargs)
        file = self.directory / "slot-retirement.json"
        original = file.read_bytes()
        file.chmod(0o644)
        self.denied(self.journal.read_slot_retirement)
        file.chmod(0o600)
        file.write_bytes(b"{")
        self.denied(self.journal.read_slot_retirement)
        file.write_bytes(original)
        self.assertEqual(self.journal.read_slot_retirement(), intent)
        file.rename(self.directory / "saved")
        file.symlink_to(self.directory / "saved")
        self.denied(self.journal.read_slot_retirement)
        self.denied(self.journal.read)

    def test_retirement_restart_rejects_altered_original_route_identity(self):
        """A valid pending intent cannot be paired with a forged older route."""
        self.journal.begin(**approval())
        ready = self.journal.finish(self.journal.read(), phase="candidate_ready")
        self.journal.finish(ready, phase="switched")
        self.journal.prepare_slot_retirement(
            request_sha256="f" * 64, active_slot="green", active_image=NEXT,
            active_container_id="e" * 64,
            dormant_slot="blue", dormant_image=OLD,
            dormant_container_id="d" * 64, next_image=LATER,
        )
        prior_bytes = self.path.read_bytes()
        prior = json.loads(prior_bytes)
        for key, altered in (
            ("phase", "restored"),
            ("generation", 2),
            ("next_image", LATER),
            ("next_container_id", "c" * 64),
            ("previous_container_id", "c" * 64),
        ):
            with self.subTest(key=key):
                self.path.write_bytes(canonical_bytes({**prior, key: altered}))
                self.denied(self.journal.read_slot_retirement)
                self.path.write_bytes(prior_bytes)
        self.assertEqual(self.journal.read_slot_retirement()["active_image"], NEXT)

    def slot_retirement_fixture(self):
        """Construct exact switched green, historical dormant blue and intent."""
        from dataclasses import replace
        from deployment.tests.test_analytics_active_state_review import observed, _active_state
        prior = self.journal.begin(**approval())
        ready = self.journal.finish(prior, phase="candidate_ready")
        self.journal.finish(ready, phase="switched")
        pending = self.journal.prepare_slot_retirement(
            request_sha256="f" * 64, active_slot="green", active_image=NEXT,
            active_container_id="e" * 64, dormant_slot="blue",
            dormant_image=OLD, dormant_container_id="d" * 64,
            next_image=LATER,
        )
        measured = replace(
            _active_state(**observed(active_slot="green")),
            active_image=NEXT, active_digest="sha256:" + "a" * 64,
            active_container_id="e" * 64,
        )
        return pending, measured

    def test_confirm_retirement_only_after_verified_empty_slot_and_active_writer(self):
        """Persist slot_empty only after two stable live reads and one absence."""
        pending, live = self.slot_retirement_fixture()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ) as inspector, patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
            return_value=None,
        ) as absent:
            done = self.journal.confirm_slot_retired(pending=pending)
        self.assertEqual(done["phase"], "slot_empty")
        self.assertEqual(inspector.call_count, 2)
        absent.assert_called_once_with("blue")
        self.assertEqual(self.journal.read_slot_retirement(), done)
        self.denied(self.journal.read)
        self.denied(lambda: self.journal.confirm_slot_retired(pending=pending))
        self.assertEqual(self.journal.read_slot_retirement(), done)

    def test_confirm_retirement_wrong_principal_or_active_route_stays_pending(self):
        """Foreign UID or changed active route cannot mark a slot empty."""
        from dataclasses import replace
        pending, live = self.slot_retirement_fixture()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=1005), self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.confirm_slot_retired(pending=pending)
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=replace(live, active_container_id="c" * 64),
        ), patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
        ) as absent, self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.confirm_slot_retired(pending=pending)
        absent.assert_not_called()
        self.assertEqual(self.journal.read_slot_retirement(), pending)

    def test_confirm_retirement_requires_absence_and_stable_second_snapshot(self):
        """A stale Docker container or reconfigured route keeps retirement HOLD."""
        from dataclasses import replace
        from deployment.analytics_active_state_review import AnalyticsActiveStateDenied
        pending, live = self.slot_retirement_fixture()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ), patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
            side_effect=AnalyticsActiveStateDenied("stopped slot remains"),
        ), self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.confirm_slot_retired(pending=pending)
        self.assertEqual(self.journal.read_slot_retirement(), pending)
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            side_effect=[live, replace(live, active_child_ip="172.20.0.7")],
        ), patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
            return_value=None,
        ), self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.confirm_slot_retired(pending=pending)
        self.assertEqual(self.journal.read_slot_retirement(), pending)

    def test_retirement_confirmation_interrupted_fsync_never_grants_go(self):
        """Partial replace cannot be interpreted as permission to stage."""
        pending, live = self.slot_retirement_fixture()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ), patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
        ), patch(
            "deployment.analytics_route_journal.os.fsync", side_effect=OSError,
        ), self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.confirm_slot_retired(pending=pending)
        self.denied(self.journal.read_slot_retirement)
        self.denied(self.journal.read)

    def confirmed_slot_retirement(self):
        """Persist a synthetic, exact and source-bound slot vacancy first."""
        pending, live = self.slot_retirement_fixture()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=live,
        ), patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
        ):
            done = self.journal.confirm_slot_retired(pending=pending)
        return done

    def test_prepared_second_release_starts_only_from_confirmed_empty_slot(self):
        """Convert durable vacancy into a normal generation2 route journal."""
        confirmed = self.confirmed_slot_retirement()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991):
            next_record = self.journal.begin_after_retirement(
                request_sha256="f" * 64,
                next_container_id="c" * 64, next_ip="172.20.0.3",
            )
        self.assertEqual(next_record["phase"], "prepared")
        self.assertEqual(next_record["generation"], confirmed["prior_generation"] + 1)
        self.assertEqual(next_record["previous_slot"], "green")
        self.assertEqual(next_record["next_slot"], "blue")
        self.assertEqual(next_record["next_image"], LATER)
        self.assertFalse((self.directory / "slot-retirement.json").exists())
        self.assertEqual(self.journal.read(), next_record)
        # Existing protected phases now apply, without creating a parallel
        # route, journal framework or second release-state machine.
        ready = self.journal.finish(next_record, phase="candidate_ready")
        switched = self.journal.finish(ready, phase="switched")
        self.assertEqual(switched["phase"], "switched")
        self.assertEqual(self.journal.read(), switched)

    def test_unconfirmed_wrong_signed_image_and_wrong_principal_never_stage(self):
        """Wrong prior request hash and duplicate IDs leave journal blocked."""
        pending, _live = self.slot_retirement_fixture()
        self.denied(lambda: self.journal.begin_after_retirement(
            request_sha256="f" * 64,
            next_container_id="c" * 64, next_ip="172.20.0.3",
        ))
        self.assertEqual(self.journal.read_slot_retirement(), pending)

    def test_confirmed_retirement_refuses_wrong_id_hash_and_uid(self):
        """Even after safe vacancy, only its one signed next request may begin."""
        confirmed = self.confirmed_slot_retirement()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=1005):
            self.denied(lambda: self.journal.begin_after_retirement(
                request_sha256="f" * 64,
                next_container_id="c" * 64, next_ip="172.20.0.3",
            ))
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991):
            for values in (
                {"request_sha256": "b" * 64},
                {"next_container_id": "e" * 64},
                {"next_ip": "172.20.0.4"},
                {"next_container_id": "not-a-container-id"},
            ):
                with self.subTest(values=values):
                    kwargs = dict(request_sha256="f" * 64,
                        next_container_id="c" * 64, next_ip="172.20.0.3")
                    kwargs.update(values)
                    self.denied(lambda: self.journal.begin_after_retirement(**kwargs))
            self.assertEqual(self.journal.read_slot_retirement(), confirmed)

    def test_interrupted_post_retirement_begin_never_forges_success(self):
        """An interrupted unlink leaves both intent and route HOLD."""
        self.confirmed_slot_retirement()
        with patch("deployment.analytics_route_journal.os.geteuid", return_value=991), patch(
            "deployment.analytics_route_journal.os.unlink", side_effect=OSError,
        ), self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.begin_after_retirement(
                request_sha256="f" * 64,
                next_container_id="c" * 64, next_ip="172.20.0.3",
            )
        self.assertTrue((self.directory / "slot-retirement.json").exists())
        self.denied(self.journal.read)
        self.denied(self.journal.read_slot_retirement)

    def test_retirement_intent_partial_write_fails_closed(self):
        """A crash at fsync cannot create a false durable retirement success."""
        self.journal.begin(**approval())
        ready = self.journal.finish(self.journal.read(), phase="candidate_ready")
        self.journal.finish(ready, phase="switched")
        with patch("deployment.analytics_route_journal.os.fsync", side_effect=OSError):
            self.denied(lambda: self.journal.prepare_slot_retirement(
                request_sha256="f" * 64,
                active_slot="green", active_image=NEXT,
                active_container_id="e" * 64,
                dormant_slot="blue", dormant_image=OLD,
                dormant_container_id="d" * 64, next_image=LATER,
            ))
        self.assertTrue((self.directory / "slot-retirement.json").exists())
        self.denied(self.journal.read)
        self.denied(lambda: self.journal.begin(**approval()))

    def test_execution_proof_persists_independent_request_and_container(self):
        raw, request_hash = self.execution_request()
        before = self.path.read_bytes()
        self.journal.record_execution(raw, 'e' * 64)
        proof = self.journal.read_execution(request_hash)
        self.assertEqual(proof, {'canonical_request': raw,
            'container_id': 'e' * 64, 'image': NEXT})
        file = self.directory / 'executions' / ('execution-' + request_hash + '.json')
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertEqual(self.path.read_bytes(), before)
        # Read through the real directory inventory after publishing proof.
        # A mocked journal reader misses proof/journal namespace coupling.
        self.assertEqual(canonical_bytes(self.journal.read()), before)
        self.denied(lambda: self.journal.record_execution(raw, 'e' * 64))
        # A forged journal cannot change the independently recorded expectation.
        changed = json.loads(self.path.read_bytes())
        changed['next_image'] = LATER
        self.path.write_bytes(canonical_bytes(changed))
        self.assertEqual(self.journal.read_execution(request_hash)['image'], NEXT)

    def test_execution_proof_rejects_changed_request_wrong_hash_or_identity(self):
        raw, request_hash = self.execution_request()
        self.denied(lambda: self.journal.record_execution(raw, 'f' * 64))
        self.journal.record_execution(raw, 'e' * 64)
        file = self.directory / 'executions' / ('execution-' + request_hash + '.json')
        saved = file.read_bytes()
        altered = json.loads(saved)
        altered['request_base64'] = base64.b64encode(raw.replace(b'"dev"', b'"prod"')).decode()
        file.write_bytes(canonical_bytes(altered))
        self.denied(lambda: self.journal.read_execution(request_hash))
        file.write_bytes(saved)
        file.chmod(0o644)
        self.denied(lambda: self.journal.read_execution(request_hash))
        file.chmod(0o600)
        file.unlink()
        file.symlink_to(self.path)
        self.denied(lambda: self.journal.read_execution(request_hash))

    def test_missing_partial_or_noncanonical_execution_proof_is_hold(self):
        _, request_hash = self.execution_request()
        self.denied(lambda: self.journal.read_execution(request_hash))
        file = self.directory / 'executions' / ('execution-' + request_hash + '.json')
        file.parent.mkdir(mode=0o700)
        file.write_bytes(b'{')
        file.chmod(0o600)
        self.denied(lambda: self.journal.read_execution(request_hash))
        self.denied(lambda: self.journal.read_execution('../untrusted'))

    def test_failed_proof_fsync_preserves_failure_evidence(self):
        raw, request_hash = self.execution_request()
        before = self.path.read_bytes()
        with patch('deployment.analytics_route_journal.os.fsync', side_effect=OSError):
            self.denied(lambda: self.journal.record_execution(raw, 'e' * 64))
        self.assertTrue((self.directory / 'executions' / ('execution-' + request_hash + '.json')).exists())
        self.assertEqual(self.path.read_bytes(), before)
        switched = self.journal.read()
        pending = self.journal.finish(switched, phase='rollback_pending')
        self.assertEqual(self.journal.finish(pending, phase='restored')['phase'], 'restored')

    def test_proof_survives_next_opposite_slot_journal_and_keeps_prior_evidence(self):
        raw, request_hash = self.execution_request()
        self.journal.record_execution(raw, 'e' * 64)
        proof = self.journal.read_execution(request_hash)
        next_intent = self.journal.begin(**approval(
            request_sha256='f' * 64, previous_slot='green',
            previous_image=NEXT, previous_container_id='e' * 64,
            previous_ip='172.20.0.4', next_slot='blue', next_image=LATER,
            next_container_id='d' * 64, next_ip='172.20.0.3'))
        self.assertEqual(next_intent['generation'], 2)
        self.assertEqual(self.journal.read_execution(request_hash), proof)
        self.assertEqual(self.journal.read(), next_intent)

    def test_proof_directory_custody_and_unknown_journal_residue_fail_closed(self):
        raw, request_hash = self.execution_request()
        self.journal.record_execution(raw, 'e' * 64)
        proofs = self.directory / 'executions'
        self.assertEqual(stat.S_IMODE(proofs.stat().st_mode), 0o700)
        proofs.chmod(0o750)
        self.denied(self.journal.read)
        self.denied(lambda: self.journal.read_execution(request_hash))
        proofs.chmod(0o700)
        proofs.rename(self.directory / 'saved-executions')
        proofs.symlink_to(self.directory / 'saved-executions', target_is_directory=True)
        self.denied(self.journal.read)
        self.denied(lambda: self.journal.read_execution(request_hash))
        proofs.unlink()
        (self.directory / 'saved-executions').rename(proofs)
        (self.directory / 'unknown').write_bytes(b'')
        self.denied(self.journal.read)

    def test_proof_directory_alone_never_looks_like_an_empty_first_install(self):
        (self.directory / 'executions').mkdir(mode=0o700)
        self.denied(self.journal.read)

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
        ready = reopened.finish(prepared, phase="candidate_ready")
        switched = reopened.finish(ready, phase="switched")
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
        ready_second = self.journal.finish(second, phase="candidate_ready")
        self.assertEqual(self.journal.finish(ready_second, phase="switched")["phase"],
                         "switched")

    def test_durable_candidate_ready_phase_requires_exact_prepared_identity(self):
        """Only verified staging can progress to cutover; no new JTI while ready."""
        prepared = self.journal.begin(**approval())
        ready = self.journal.finish(prepared, phase="candidate_ready")
        self.assertEqual(ready["phase"], "candidate_ready")
        self.assertEqual(self.journal.read(), ready)
        with self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.begin(**approval(request_sha256="f" * 64))
        with self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.finish(prepared, phase="switched")
        with self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.finish(ready, phase="candidate_ready")
        switched = self.journal.finish(ready, phase="switched")
        self.assertEqual(switched["phase"], "switched")

    def test_candidate_ready_may_be_restored_but_not_skipped_to_prepared(self):
        """Interrupted candidate can recover without permitting a new release."""
        prepared = self.journal.begin(**approval())
        ready = self.journal.finish(prepared, phase="candidate_ready")
        restored = self.journal.finish(ready, phase="restored")
        self.assertEqual(restored["phase"], "restored")
        with self.assertRaises(AnalyticsRouteJournalUnavailable):
            self.journal.finish(restored, phase="switched")

    def test_committed_rollback_intent_must_be_durable_before_restoration(self):
        """Switched can only transition through rollback_pending to restored.

        Never allow an arbitrary changed owner, process or request to clear
        an unfinished rollback after the 3141 writer has already switched.
        """
        prepared = self.journal.begin(**approval())
        ready = self.journal.finish(prepared, phase="candidate_ready")
        switched = self.journal.finish(ready, phase="switched")
        self.denied(lambda: self.journal.finish(switched, phase="restored"))
        pending = self.journal.finish(switched, phase="rollback_pending")
        self.assertEqual(pending["phase"], "rollback_pending")
        self.assertEqual(self.path.read_bytes(), canonical_bytes(pending))
        reopened = AnalyticsRouteJournal(
            str(self.directory),
            expected_uid=os.getuid(), expected_gid=os.getgid(),
        )
        self.assertEqual(reopened.read(), pending)
        self.denied(lambda: reopened.begin(**approval(request_sha256="f" * 64)))
        self.denied(lambda: reopened.finish(
            switched, phase="rollback_pending",
        ))
        self.denied(lambda: reopened.finish(
            pending, phase="switched",
        ))
        restored = reopened.finish(pending, phase="restored")
        self.assertEqual(restored["phase"], "restored")
        self.assertEqual(self.path.read_bytes(), canonical_bytes(restored))
        self.denied(lambda: reopened.finish(pending, phase="restored"))
        self.denied(lambda: reopened.finish(restored, phase="switched"))
        # A new signed release may subsequently begin, but the original
        # replay database still independently rejects reuse of the old JTI.
        second = reopened.begin(**approval(request_sha256="f" * 64))
        self.assertEqual(second["generation"], 2)

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
        candidate = self.journal.finish(first, phase="candidate_ready")
        ready = self.journal.finish(candidate, phase="switched")
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

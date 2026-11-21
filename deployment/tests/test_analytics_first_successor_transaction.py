"""File: deployment/tests/test_analytics_first_successor_transaction.py

Purpose: Verify complete *source-only* Task14B first-successor transaction,
         including signed review, original SQLite replay boundaries, private
         3142 stage, durable 3141 cutover, post-commit rollback and crash HOLD.
Related: deployment/analytics_executor.py (exact future coordinator),
         deployment/analytics_first_install.py (candidate),
         deployment/analytics_loopback_guard.py (real route primitives),
         deployment/analytics_route_journal.py (durable recovery),
         deployment/tests/test_analytics_executor_composition.py (live DENY).

Sections: isolated Analytics collaborators, sequence assertions, fail-closed
          deny scenarios and recovery after all substantive failure phases;
          ordinary signed predecessor green->blue using same replay/route.

Docker, sockets, JWTs, signing and live routes are simulated. Storage tests
use real isolated journal files, fsync and SQLite replay transitions with the
test process's own custody. Production UID/configuration is simulated only
at the startup entry boundary. Nothing installs,
starts, publishes, signs, deploys, or opens a public Analytics service.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from io import StringIO
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from deployment.analytics_execution import parse_analytics_successor_request
from deployment.tests.test_replay_sqlite import ReplayTestCase, HASH_A, NOW
from deployment.replay_sqlite import DATABASE_MODE
from deployment.analytics_executor import _read_analytics_execution_status
from deployment.analytics_executor import (
    AnalyticsPrivilegedExecutor, _execute_reviewed_first_successor_transaction,
)
from deployment.analytics_first_install import (
    AnalyticsFirstInstallOperation, AnalyticsSuccessorCandidateOperation,
)
from deployment.analytics_private_registry import AnalyticsPrivateZotPullAdapter
from deployment.analytics_route_journal import AnalyticsRouteJournal
from deployment.executor import (
    ExecutorRejectedError, ExecutorUnavailableError, parse_canonical_response,
)
from deployment.identity import ReplayError
from deployment.tests.test_analytics_execution import (
    AnalyticsSuccessorRequestTests, EXPECTED,
)
from deployment.tests.test_analytics_private_registry import (
    first_successor_empty_active_state,
)
from deployment.tests.test_analytics_successor_candidate_operation import (
    SyntheticGreenRunner,
)
from deployment.tests.test_identity import NOW, WORKFLOW_SHA
from deployment.policy import canonical_bytes

GREEN_ID = "b" * 64
BLUE_ID = "a" * 64


class ConsumedReplay:
    """Test-only broker-consumed JTI with native begin/finish method grammar."""

    def __init__(self):
        """Record order and optionally fail the exact replay phase."""
        self.events = []
        self.failure = None

    def begin_execution(self, jti, *, request_hash, run_id, run_attempt):
        """Require the same nonzero canonical SHA and retain a replay begin."""
        assert type(jti) is str and type(run_id) is int
        assert type(run_attempt) is int and len(request_hash) == 64
        self.events.append("begin")
        if self.failure == "begin":
            raise ReplayError("synthetic already consumed")
        return None

    def finish_execution(self, jti, *, request_hash, run_id, run_attempt):
        """Report the end only after the synthetic committed route."""
        assert type(jti) is str and len(request_hash) == 64
        self.events.append("finish")
        if self.failure == "finish":
            raise RuntimeError("synthetic disk fsync loss")
        return None


class FirstSuccessorTransactionTests(unittest.TestCase):
    """Prove the exact future release coordinator remains closed and fail-safe."""

    def setUp(self):
        """Build genuine product typed objects, replace all external operations."""
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        data, context = AnalyticsSuccessorRequestTests().candidate()
        self.request = parse_analytics_successor_request(
            canonical_bytes(data), **context,
        )
        self.raw = self.request.canonical_bytes()
        self.hash = hashlib.sha256(self.raw).hexdigest()
        self.original = first_successor_empty_active_state()
        self.green = replace(
            self.original, active_slot="green",
            active_image=self.request.exact_image_reference,
            active_digest=self.request.manifest_digest,
            active_container_id=GREEN_ID,
            candidate_slot="blue", candidate_probe_present=False,
        )
        self.events = []
        self.phase = None
        self.failure = None
        self.replay = ConsumedReplay()
        self.temp = tempfile.TemporaryDirectory(
            prefix="m05-task14b-combined-source-",
        )
        self.addCleanup(self.temp.cleanup)
        self.runner = SyntheticGreenRunner(self.request.exact_image_reference)
        self.registry = AnalyticsPrivateZotPullAdapter(
            self.runner, reviewed_installed_source=EXPECTED,
        )
        self.blue = AnalyticsFirstInstallOperation(
            runner=self.runner, private_registry=self.registry,
            reviewed_installed_source=EXPECTED,
        )
        self.executor = AnalyticsPrivilegedExecutor(
            replay_guard=self.replay, private_registry_preflight=self.registry,
            operation=self.blue, reviewed_installed_source=EXPECTED,
        )
        self.candidate = AnalyticsSuccessorCandidateOperation(
            runner=self.runner, private_registry=self.registry,
            reviewed_installed_source=EXPECTED,
        )
        self.journal = AnalyticsRouteJournal(
            self.temp.name, expected_uid=991, expected_gid=991,
        )
        self.stack.enter_context(patch(
            "deployment.analytics_route_journal.ROUTE_JOURNAL_DIRECTORY",
            self.temp.name,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.os.getuid", return_value=991,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.os.geteuid", return_value=991,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.os.getgid", return_value=991,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.os.getegid", return_value=991,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.time.time", return_value=NOW,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor_service_config."
            "load_analytics_executor_service_config",
            return_value=(EXPECTED, {
                "expected_workflow_sha": WORKFLOW_SHA,
                "expected_executor_uid": 991,
                "expected_executor_gid": 991,
                "owner_authorized_first_successor": True,
            }),
        ))
        self.reviewer = self.stack.enter_context(patch(
            "deployment.analytics_executor._review_executor_successor_signed_release",
            side_effect=self.review,
        ))
        self.inspector = self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=self.original,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_active_state_review."
            "verify_empty_analytics_successor_slot",
            return_value=None,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.read_sealed_credential",
            return_value=SimpleNamespace(expires_at=NOW + 270),
        ))
        # Save the actual helper before substituting the synthetic callback.
        # One negative test exercises genuine nested helper propagation.
        self.real_preflight = (
            AnalyticsPrivilegedExecutor.preflight_first_successor_without_deployment
        )
        self.preflight = self.stack.enter_context(patch.object(
            AnalyticsPrivilegedExecutor,
            "preflight_first_successor_without_deployment",
            side_effect=self.preflight_check,
        ))
        self.stage = self.stack.enter_context(patch.object(
            AnalyticsSuccessorCandidateOperation,
            "stage_first_successor_green",
            side_effect=self.candidate_start,
        ))
        self.stop = self.stack.enter_context(patch.object(
            AnalyticsSuccessorCandidateOperation,
            "rollback_staged_successor",
            side_effect=self.candidate_stop,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard."
            "_stage_reviewed_private_candidate_probe",
            side_effect=self.stage_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard."
            "_switch_reviewed_private_route",
            side_effect=self.switch_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard."
            "_recover_reviewed_private_route",
            side_effect=self.recover_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard."
            "_rollback_committed_private_successor",
            side_effect=self.rollback_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_active_state_review."
            "inspect_committed_analytics_route",
            side_effect=self.verify_committed,
        ))
        self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "read", side_effect=self.journal_read,
        ))
        self.receipt = self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "record_execution",
        ))

    def review(self, canonical_request, credential_fd, **kwargs):
        """Simulate a prior real independent three-JWT + Cosign verified review."""
        self.events.append("signed_review")
        if self.failure == "signed_review":
            raise ExecutorUnavailableError("synthetic signature denial")
        self.assertEqual(canonical_request, self.raw)
        self.assertEqual(kwargs["expected_workflow_sha"], WORKFLOW_SHA)
        self.assertEqual(kwargs["reviewed_installed_source"], EXPECTED)
        return self.request

    def preflight_check(self, canonical_request, *, credential_fd,
                        candidate_ready, trace_generation3=False):
        """Check original preflight and explicit generation3 trace opt-in."""
        self.assertIs(trace_generation3, True)
        self.events.append("preflight_candidate" if candidate_ready else "preflight_original")
        if self.failure == ("preflight_candidate" if candidate_ready else "preflight_original"):
            raise ExecutorUnavailableError("synthetic manifest denial")
        return None

    def candidate_start(self, request):
        """Expose a synthetic pre-3142 candidate only after durable replay."""
        self.assertEqual(request, self.request)
        self.assertIn("begin", self.replay.events)
        self.events.append("candidate_start")
        if self.failure == "candidate_start":
            raise RuntimeError("no start")
        return GREEN_ID

    def stage_route(self, **kw):
        """Journal a probed 3142 only for reviewed exact container and JTI."""
        self.events.append("3142_stage")
        self._route(kw)
        self.phase = "prepared" if self.failure == "3142_stage" else "candidate_ready"
        if self.failure == "3142_stage":
            raise RuntimeError("lost 3142 response")
        return None

    def switch_route(self, **kw):
        """Durably switch only the exact prepared 3142 -> stable 3141."""
        self.events.append("3141_switch")
        self._route(kw)
        self.assertEqual(self.phase, "candidate_ready")
        if self.failure == "3141_switch":
            raise RuntimeError("RootlessKit error")
        self.phase = "switched"
        return None

    def recover_route(self, **kw):
        """Recover interrupted candidate or cutover only to the old blue."""
        self.events.append("recover_previous")
        self._route(kw)
        if self.failure == "recovery":
            raise RuntimeError("cannot confirm Canary or old route")
        self.phase = "restored"
        return None

    def rollback_route(self, **kw):
        """Durably undo a committed green 3141 before stopping green."""
        self.events.append("rollback_committed")
        self._route(kw)
        if self.failure == "rollback":
            raise RuntimeError("blue route no longer healthy")
        self.phase = "restored"
        return None

    def candidate_stop(self, request, identifier):
        """Stop ONLY green by its immutable confirmed container ID."""
        self.events.append("stop_exact_green")
        self.assertEqual(request, self.request)
        self.assertEqual(identifier, GREEN_ID)
        self.assertNotEqual(self.phase, "switched")
        if self.failure == "candidate_stop":
            raise RuntimeError("cannot stop exact image")
        return None

    def verify_committed(self, *, journal, reviewed_image, reviewed_slot,
                         reviewed_container_id, reviewed_request_sha256):
        """Prove route and last journal phase before replay finish."""
        self.events.append("verify_" + reviewed_slot)
        self.assertIs(journal, self.journal)
        self.assertEqual(reviewed_request_sha256, self.hash)
        self.assertEqual(
            (reviewed_image, reviewed_container_id),
            (self.request.exact_image_reference, GREEN_ID) if reviewed_slot == "green"
            else (self.original.active_image, self.original.active_container_id),
        )
        if reviewed_slot == "green":
            self.assertEqual(self.phase, "switched")
            if self.failure == "committed_review":
                raise RuntimeError("wrong final writer")
            return self.green
        self.assertEqual(self.phase, "restored")
        return self.original

    def journal_read(self):
        """Return a synthetic exact journal; real fsync is tested elsewhere."""
        if self.phase is None:
            return None
        return {
            "phase": self.phase,
            "request_sha256": self.hash,
            "previous_container_id": self.original.active_container_id,
            "next_container_id": GREEN_ID,
            "previous_image": self.original.active_image,
            "next_image": self.request.exact_image_reference,
        }

    def _route(self, kw):
        """Prove no unrelated product, image, public port, or replay JTI."""
        self.assertEqual(kw["previous_slot"], "blue")
        self.assertEqual(kw["previous_image"], self.original.active_image)
        self.assertEqual(kw["previous_id"], self.original.active_container_id)
        self.assertEqual(kw["next_slot"], "green")
        self.assertEqual(kw["next_image"], self.request.exact_image_reference)
        self.assertEqual(kw["next_id"], GREEN_ID)
        self.assertEqual(kw["request_sha256"], self.hash)
        self.assertIs(kw["journal"], self.journal)

    def execute(self, **changes):
        """Exercise only the uninstalled future transaction with fake fd."""
        return _execute_reviewed_first_successor_transaction(
            self.raw, credential_fd=10,
            expected_workflow_sha=WORKFLOW_SHA, executor=self.executor,
            candidate_operation=self.candidate, journal=self.journal,
            **changes,
        )

    # Section: generation3-only local redacted hold markers, no network.
    def test_issued_phase_installed_authority_is_static_and_pre_replay(self):
        """A protected workflow mismatch emits one constant and denies."""
        with patch(
            "deployment.analytics_executor_service_config."
            "load_analytics_executor_service_config",
            return_value=(EXPECTED, {
                "expected_workflow_sha": "a" * 40,
                "expected_executor_uid": 991,
                "expected_executor_gid": 991,
            }),
        ):
            with patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr:
                with self.assertRaises(ExecutorUnavailableError):
                    self.execute()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=installed_authority\n",
        )
        self.assertEqual(self.events, [])
        self.assertEqual(self.replay.events, [])
        self.assertIsNone(self.phase)

    def test_issued_phase_private_preflight_keeps_existing_denial(self):
        """Outer-only state rejection logs exactly once, without touching JTI."""
        with (
            patch(
                "deployment.analytics_active_state_review."
                "verify_empty_analytics_successor_slot",
                side_effect=ValueError("synthetic-secret-outside-helper"),
            ),
            patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=private_preflight\n",
        )
        self.assertEqual(self.events, ["signed_review"])
        self.assertEqual(self.preflight.call_count, 0)
        self.assertEqual(self.replay.events, [])
        self.assertIsNone(self.phase)

    def test_actual_nested_helper_denial_emits_one_static_marker(self):
        """Real traced helper plus outer transaction logs only inner refusal."""
        self.preflight.side_effect = (
            lambda raw, **kwargs: self.real_preflight(
                self.executor, raw, **kwargs,
            )
        )
        with (
            patch(
                "deployment.analytics_executor._verify_executor_owner_source",
                return_value=None,
            ),
            patch(
                "deployment.analytics_executor.read_sealed_credential",
                side_effect=ValueError("synthetic-jwt-must-not-log"),
            ),
            patch(
                "deployment.analytics_executor.sys.stderr", new=StringIO(),
            ) as stderr,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=private_credential\n",
        )
        self.assertEqual(self.events, ["signed_review"])
        self.assertEqual(self.preflight.call_count, 1)
        self.assertEqual(self.replay.events, [])
        self.assertIsNone(self.phase)
        self.assertEqual(self.stage.call_count, 0)
        self.assertEqual(self.stop.call_count, 0)
        self.assertNotIn("synthetic-jwt", stderr.getvalue())

    def test_issued_phase_replay_begin_preserves_rejection_no_candidate(self):
        """One rejected SQLite begin has no candidate or 3142/3141 switch."""
        self.replay.failure = "begin"
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            with self.assertRaises(ExecutorRejectedError):
                self.execute()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=replay_begin\n",
        )
        self.assertEqual(self.replay.events, ["begin"])
        self.assertEqual(self.events, ["signed_review", "preflight_original"])
        self.assertIsNone(self.phase)

    def test_no_phase_on_success_or_untrusted_uid(self):
        """No success breadcrumbs; a non-UID991 failure stays silent."""
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            self.execute()
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.replay.events, ["begin", "finish"])
        self.replay.events.clear()
        self.events.clear()
        with (
            patch("deployment.analytics_executor.os.getuid", return_value=1005),
            patch("deployment.analytics_executor.sys.stderr", new=StringIO()) as stderr,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.replay.events, [])
        self.assertEqual(self.events, [])

    def test_failed_local_journal_write_does_not_change_denial(self):
        """A broken systemd stderr must not transform HOLD into acceptance."""
        self.failure = "preflight_original"
        with patch("deployment.analytics_executor.sys.stderr") as stderr:
            stderr.write.side_effect = OSError("synthetic output failure")
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(self.replay.events, [])
        self.assertIsNone(self.phase)

    def test_static_phase_filter_and_identity_read_failure_stay_silent(self):
        """Invalid IDs and failed UID probes cannot create leaked diagnostics."""
        from deployment.analytics_executor import (
            _emit_uid991_successor_failure_phase,
        )
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            _emit_uid991_successor_failure_phase("secret-dynamic-request")
            with patch(
                "deployment.analytics_executor.os.getuid",
                side_effect=OSError("synthetic-uid-lookup-secret"),
            ):
                _emit_uid991_successor_failure_phase("replay_begin")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.replay.events, [])

    def test_complete_signed_release_preflight_replay_private_cutover_finish(self):
        """Only verified 3141 committed state permits a success response."""
        response = parse_canonical_response(self.execute())
        self.assertEqual(response.executor_request_sha256, self.hash)
        self.assertEqual(self.phase, "switched")
        self.assertEqual(self.replay.events, ["begin", "finish"])
        self.assertEqual(self.events, [
            "signed_review", "preflight_original", "candidate_start",
            "3142_stage", "preflight_candidate", "3141_switch",
            "verify_green",
        ])
        self.assertEqual(self.stop.call_count, 0)
        self.receipt.assert_called_once_with(self.raw, GREEN_ID)

    def test_receipt_write_failure_rolls_back_before_replay_finish(self):
        self.receipt.side_effect = RuntimeError('synthetic proof fsync failure')
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.replay.events, ['begin'])
        self.assertEqual(self.phase, 'restored')
        self.assertEqual(self.events[-3:], [
            'rollback_committed', 'verify_blue', 'stop_exact_green'])
        self.assertEqual(self.stop.call_count, 1)

    def test_unverified_signature_blocks_replay_and_all_runtime(self):
        """No replay, private route or candidate after failed original signature."""
        self.failure = "signed_review"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.events, ["signed_review"])
        self.assertEqual(self.replay.events, [])
        self.assertIsNone(self.phase)

    def test_source_root_workflow_mismatch_fails_before_signed_review(self):
        """Workflow SHA selected by a requester cannot become root authority."""
        with patch(
            "deployment.analytics_executor_service_config."
            "load_analytics_executor_service_config",
            return_value=(EXPECTED, {
                "expected_workflow_sha": "a" * 40,
                "expected_executor_uid": 991,
                "expected_executor_gid": 991,
            }),
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(self.events, [])
        self.assertEqual(self.replay.events, [])

    def test_wrong_uid_does_not_even_start_signatures_or_replay(self):
        """Untrusted principal cannot use product source-only coordinator."""
        with patch("deployment.analytics_executor.os.getuid", return_value=1005):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(self.events, [])
        self.assertEqual(self.replay.events, [])

    def test_unconsumed_jti_denies_before_container(self):
        """Only original broker-consumed SQLite JTI may begin execution."""
        self.replay.failure = "begin"
        with self.assertRaises(ExecutorRejectedError):
            self.execute()
        self.assertEqual(self.replay.events, ["begin"])
        self.assertNotIn("candidate_start", self.events)

    def test_original_manifest_denial_prevents_any_replay(self):
        """No deployment against unverified original rootless/Zot manifest."""
        self.failure = "preflight_original"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertNotIn("candidate_start", self.events)
        self.assertEqual(self.replay.events, [])

    def test_candidate_failure_consumes_jti_but_never_routes(self):
        """Existing candidate implementation must stop its own partial start."""
        self.failure = "candidate_start"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.replay.events, ["begin"])
        self.assertIsNone(self.phase)
        self.assertNotIn("3142_stage", self.events)

    def test_3142_failure_recovers_prior_route_before_candidate_stop(self):
        """Incomplete PREPARED journal never counts as healthy first successor."""
        self.failure = "3142_stage"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(self.events[-3:], [
            "recover_previous", "verify_blue", "stop_exact_green",
        ])
        self.assertEqual(self.replay.events, ["begin"])

    def test_candidate_manifest_failure_recovers_before_stop(self):
        """3142-preflight denial cannot leave a routable green candidate."""
        self.failure = "preflight_candidate"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(self.events[-3:], [
            "recover_previous", "verify_blue", "stop_exact_green",
        ])
        self.assertEqual(self.replay.events, ["begin"])

    def test_failed_3141_switch_is_recovered_to_original_before_stop(self):
        """A RootlessKit failure cannot strand the old signed 0.15.0 route."""
        self.failure = "3141_switch"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(self.events[-3:], [
            "recover_previous", "verify_blue", "stop_exact_green",
        ])

    def test_replay_finalization_failure_rolls_back_committed_route_first(self):
        """Durable replay finish is the final condition for release success."""
        self.replay.failure = "finish"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(self.replay.events, ["begin", "finish"])
        self.assertEqual(self.events[-3:], [
            "rollback_committed", "verify_blue", "stop_exact_green",
        ])

    def test_committed_route_review_failure_rolls_back_without_finishing(self):
        """A wrong active writer after cutover never counts as signed success."""
        self.failure = "committed_review"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(self.replay.events, ["begin"])
        self.assertEqual(self.events[-3:], [
            "rollback_committed", "verify_blue", "stop_exact_green",
        ])

    def test_unconfirmed_route_rollback_never_stops_possible_active_green(self):
        """Crash/HOLD preserves green if signed blue cannot be restored."""
        self.replay.failure = "finish"
        self.failure = "rollback"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.phase, "switched")
        self.assertIn("rollback_committed", self.events)
        self.assertNotIn("stop_exact_green", self.events)

    def test_unconfirmed_candidate_recovery_never_stops_possible_route(self):
        """Failed recovery leaves protected phase and JTI consumed for audit."""
        self.failure = "recovery"
        with patch(
            "deployment.analytics_loopback_guard._switch_reviewed_private_route",
            side_effect=RuntimeError("lost 3141 update acknowledgement"),
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.execute()
        self.assertEqual(self.phase, "candidate_ready")
        self.assertNotIn("stop_exact_green", self.events)
        self.assertEqual(self.replay.events, ["begin"])

    def test_original_unix_composition_remains_deny_only(self):
        """Adding source-only coordinator never registers positive Unix route."""
        from deployment.analytics_executor_composition import (
            AnalyticsExecutorComposition,
        )
        from deployment.tests.test_analytics_executor_composition import (
            composition,
        )
        import socket
        original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(original.close)
        v2 = composition(original, workflow_sha=WORKFLOW_SHA)
        listener = object.__getattribute__(v2, "_serve_once").__self__
        handler = object.__getattribute__(
            listener, "_configuration",
        )[1].__self__
        operation = object.__getattribute__(
            handler, "_configuration",
        )[0]
        self.assertEqual(operation.__name__, "review_full_signed_and_reject")
        self.assertNotEqual(operation.__name__, "_execute_reviewed_first_successor_transaction")


# Section: separately root-selected generation3 *startup*, not synthetic
# replay execution. The product must reconcile one proven incomplete route
# before it can possibly accept another SCM_RIGHTS Unix request.
# Section: ordinary signed green->blue coordinator. These source-only tests
# exercise original owner/replay/port boundaries with synthetic collaborators.
class OrdinarySuccessorTransactionTests(unittest.TestCase):
    """The second release must not require an operator to delete old blue."""

    def setUp(self):
        """Reuse real typed executor/registry/replay objects and mocked I/O."""
        import hashlib
        from contextlib import nullcontext
        from deployment.analytics_active_state_review import AnalyticsActiveState
        from deployment.analytics_loopback_guard import _SUCCESSOR_SCOPE
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE
        from deployment.tests.test_analytics_successor_candidate_operation import (
            OrdinaryBlueCandidateStageTests,
        )
        self.fixture = OrdinaryBlueCandidateStageTests(
            "test_active_green_stages_private_healthy_blue_and_rollback_is_exact"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.request = self.fixture.request
        self.raw = self.request.canonical_bytes()
        self.hash = hashlib.sha256(self.raw).hexdigest()
        self.old = self.fixture.inspector.return_value
        self.new_id = GREEN_ID
        self.new_ip = "172.20.0.3"
        self.replay = ConsumedReplay()
        self.original_operation = AnalyticsFirstInstallOperation(
            runner=self.fixture.runner, private_registry=self.fixture.registry,
            reviewed_installed_source=EXPECTED,
        )
        self.executor = AnalyticsPrivilegedExecutor(
            replay_guard=self.replay,
            private_registry_preflight=self.fixture.registry,
            operation=self.original_operation,
            reviewed_installed_source=EXPECTED,
        )
        self.candidate = self.fixture.operation
        self.journal = AnalyticsRouteJournal(
            "/var/lib/omnilyzer/deployment/analytics-route",
            expected_uid=991, expected_gid=991,
        )
        self.current = {
            "phase": "switched", "request_sha256": "1" * 64,
            "next_slot": "green", "next_image": self.old.active_image,
            "next_container_id": self.old.active_container_id,
            "next_ip": self.old.active_child_ip,
            "previous_slot": "blue", "previous_image": PINNED_IMAGE,
            "previous_container_id": "a" * 64,
            "previous_ip": "172.20.0.3", "generation": 1,
        }
        self.phase = "historical"
        self.failure = None
        self.events = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {_SUCCESSOR_SCOPE: "1"}))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.time.time", return_value=NOW,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor_service_config.load_analytics_executor_service_config",
            return_value=(EXPECTED, {
                "expected_workflow_sha": WORKFLOW_SHA,
                "expected_executor_uid": 991, "expected_executor_gid": 991,
                "owner_authorized_ordinary_successor": True,
            }),
        ))
        self.signed = self.stack.enter_context(patch(
            "deployment.analytics_executor._review_executor_ordinary_signed_release",
            return_value=self.request,
        ))
        self.inspector = self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            side_effect=self.observe,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor.read_sealed_credential",
            return_value=SimpleNamespace(expires_at=NOW + 270),
        ))
        self.probe = self.stack.enter_context(patch.object(
            AnalyticsPrivateZotPullAdapter, "_run_private", return_value=None,
        ))
        self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "exclusive",
            side_effect=lambda: nullcontext(self.journal),
        ))
        self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "exclusive_active", return_value=True,
        ))
        self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "read", side_effect=self.journal_read,
        ))
        self.retire_intent = self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "prepare_slot_retirement",
            side_effect=self.prepare_retirement,
        ))
        self.retire = self.stack.enter_context(patch.object(
            AnalyticsSuccessorCandidateOperation, "retire_dormant_rollback_container",
            side_effect=self.remove_dormant,
        ))
        self.stage = self.stack.enter_context(patch.object(
            AnalyticsSuccessorCandidateOperation, "stage_ordinary_successor",
            side_effect=self.stage_candidate,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._verified_slot",
            return_value=self.new_ip,
        ))
        self.begin_next = self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "begin_after_retirement",
            side_effect=self.begin_prepared,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._stage_reviewed_private_candidate_probe",
            side_effect=self.stage_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._switch_reviewed_private_route",
            side_effect=self.switch_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._recover_reviewed_private_route",
            side_effect=self.restore_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._rollback_committed_private_successor",
            side_effect=self.restore_route,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.inspect_committed_analytics_route",
            side_effect=self.committed,
        ))
        self.execution = self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "record_execution",
            side_effect=self.record_execution,
        ))
        self.completion = self.stack.enter_context(patch.object(
            AnalyticsRouteJournal, "record_completed_release",
            side_effect=self.record_completed_release,
        ))
        self.stop = self.stack.enter_context(patch.object(
            AnalyticsSuccessorCandidateOperation, "rollback_staged_successor",
            side_effect=self.stop_candidate,
        ))

    def observe(self):
        """Only a verified green, staged-blue or committed-blue may be read."""
        if self.phase in ("historical", "retirement_pending", "slot_empty", "prepared"):
            return self.old
        if self.phase == "candidate_ready":
            return replace(
                self.old, candidate_probe_present=True,
                candidate_digest=self.request.manifest_digest,
                candidate_container_id=self.new_id,
            )
        if self.phase == "switched":
            return replace(
                self.old, active_slot="blue",
                active_image=self.request.exact_image_reference,
                active_digest=self.request.manifest_digest,
                active_container_id=self.new_id,
                active_child_ip=self.new_ip, candidate_slot="green",
                candidate_probe_present=False,
            )
        if self.phase == "restored":
            return self.old
        raise AssertionError("unsupported synthetic route phase")

    def journal_read(self):
        """Return exact expected journal metadata for each transaction phase."""
        if self.phase == "historical":
            return dict(self.current)
        if self.phase in ("retirement_pending", "slot_empty"):
            raise AssertionError("original journal MUST hard HOLD during retirement")
        if self.phase in ("prepared", "candidate_ready", "switched", "restored"):
            return {
                **self.current, "phase": self.phase,
                "request_sha256": self.hash,
                "previous_slot": "green", "previous_image": self.old.active_image,
                "previous_container_id": self.old.active_container_id,
                "next_slot": "blue", "next_image": self.request.exact_image_reference,
                "next_container_id": self.new_id,
            }
        raise AssertionError("unsupported journal phase")

    def prepare_retirement(self, **kw):
        """Must fsync signed old active/old dormant before any container removal."""
        self.assertEqual(self.phase, "historical")
        self.assertEqual(kw["next_image"], self.request.exact_image_reference)
        self.assertEqual(kw["dormant_image"], self.current["previous_image"])
        self.assertEqual(kw["active_container_id"], self.old.active_container_id)
        self.events.append("fsync_retirement")
        self.phase = "retirement_pending"
        return None

    def remove_dormant(self, *, request, journal):
        """Only exact historical blue removal after its durable intent."""
        self.assertEqual(self.phase, "retirement_pending")
        self.assertIs(request, self.request)
        self.assertIs(journal, self.journal)
        self.events.append("remove_exact_stopped_blue")
        self.phase = "slot_empty"
        if self.failure == "retire":
            raise RuntimeError("synthetic removed but journal uncertain")
        return None

    def stage_candidate(self, request, *, journal):
        """Candidate can start only after signed retirement and replay begin."""
        self.assertEqual(self.phase, "slot_empty")
        self.assertIs(request, self.request)
        self.assertIs(journal, self.journal)
        self.assertEqual(self.replay.events, ["begin"])
        self.events.append("stage_signed_blue")
        if self.failure == "stage":
            raise RuntimeError("synthetic private image unavailable")
        return self.new_id

    def begin_prepared(self, *, request_sha256, next_container_id, next_ip):
        """Rejoin the existing route journal only after reviewed next Docker IP."""
        self.assertEqual(self.phase, "slot_empty")
        self.assertEqual(request_sha256, self.hash)
        self.assertEqual(next_container_id, self.new_id)
        self.assertEqual(next_ip, self.new_ip)
        self.events.append("fsync_prepared")
        self.phase = "prepared"
        return self.journal_read()

    def stage_route(self, **route):
        """Route only fixed 3142 after durable prepared signed intent."""
        self.assertEqual(self.phase, "prepared")
        self.assertEqual(route["previous_slot"], "green")
        self.assertEqual(route["next_slot"], "blue")
        self.assertEqual(route["next_id"], self.new_id)
        self.events.append("3142_ready")
        self.phase = "candidate_ready"
        return None

    def switch_route(self, **route):
        """Preserve Canary and actual writer until signed 3142 is healthy."""
        self.assertEqual(self.phase, "candidate_ready")
        self.events.append("3141_switch")
        if self.failure == "cutover":
            raise RuntimeError("synthetic route switch refused")
        self.phase = "switched"
        return None

    def restore_route(self, **route):
        """Recover only to exact original signed active green."""
        self.events.append("restore_green")
        self.phase = "restored"
        return None

    def committed(self, *, journal, reviewed_image, reviewed_slot,
                  reviewed_container_id, reviewed_request_sha256):
        """The verified exact signed writer must match its route journal."""
        self.assertIs(journal, self.journal)
        self.assertEqual(reviewed_request_sha256, self.hash)
        self.events.append("verify_committed")
        if reviewed_slot == "blue":
            self.assertEqual(self.phase, "switched")
            self.assertEqual(reviewed_image, self.request.exact_image_reference)
            self.assertEqual(reviewed_container_id, self.new_id)
            return self.observe()
        self.assertEqual(self.phase, "restored")
        self.assertEqual(reviewed_image, self.old.active_image)
        return self.old

    def record_execution(self, raw, container_id):
        """No success response before a source-bound durable request proof."""
        self.assertEqual(raw, self.raw)
        self.assertEqual(container_id, self.new_id)
        self.assertEqual(self.phase, "switched")
        self.events.append("fsync_execution")
        if self.failure == "receipt":
            raise RuntimeError("synthetic journal disk loss")
        return None

    def record_completed_release(self, raw, container_id, *, replay_guard):
        self.assertEqual(raw, self.raw)
        self.assertEqual(container_id, self.new_id)
        self.assertIs(replay_guard, self.replay)
        self.assertEqual(self.phase, "switched")
        self.events.append("fsync_completion")
        return None

    def stop_candidate(self, request, identifier):
        """Stop only the exact verified next ID AFTER old green restored."""
        self.assertEqual(self.phase, "restored")
        self.assertIs(request, self.request)
        self.assertEqual(identifier, self.new_id)
        self.events.append("stop_exact_blue")
        return None

    def execute(self):
        """Call only uninstalled, owner-review-pending ordinary executor source."""
        from deployment.analytics_executor import (
            _execute_reviewed_ordinary_successor_transaction,
        )
        return _execute_reviewed_ordinary_successor_transaction(
            self.raw, credential_fd=21,
            expected_workflow_sha=WORKFLOW_SHA, executor=self.executor,
            candidate_operation=self.candidate, journal=self.journal,
        )

    def test_signed_ordinary_second_upgrade_replays_once_and_switches(self):
        """No new release component, sign bypass or extra host publication."""
        reply = self.execute()
        self.assertEqual(
            parse_canonical_response(reply).executor_request_sha256, self.hash,
        )
        self.assertEqual(self.replay.events, ["begin", "finish"])
        self.assertEqual(self.events, [
            "fsync_retirement", "remove_exact_stopped_blue",
            "stage_signed_blue", "fsync_prepared", "3142_ready",
            "3141_switch", "verify_committed", "fsync_execution",
            "fsync_completion",
        ])
        self.signed.assert_called_once()
        self.execution.assert_called_once()
        self.stop.assert_not_called()

    def test_failed_retirement_never_stages_or_switches(self):
        """A pending intent remains visible but never grants new deployment."""
        self.failure = "retire"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.replay.events, ["begin"])
        self.assertEqual(self.events, [
            "fsync_retirement", "remove_exact_stopped_blue",
        ])
        self.stage.assert_not_called()
        self.execution.assert_not_called()

    def test_failed_3141_switch_recovers_green_then_stops_only_blue(self):
        """A candidate may never be stopped until private green is restored."""
        self.failure = "cutover"
        with self.assertRaises(ExecutorUnavailableError):
            self.execute()
        self.assertEqual(self.replay.events, ["begin"])
        self.assertEqual(self.events[-3:], [
            "restore_green", "verify_committed", "stop_exact_blue",
        ])
        self.execution.assert_not_called()

class ProtectedSuccessorRestartTests(unittest.TestCase):
    """No crash-state adoption, false success or silent public route change."""

    def setUp(self):
        """Provide fixed root-owned provenance and fake private route readers."""
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE
        self.image = PINNED_IMAGE
        self.next = (
            "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:" + "a" * 64
        )
        self.record = {
            "phase": "candidate_ready",
            "request_sha256": "c" * 64,
            "previous_slot": "blue",
            "previous_image": self.image,
            "previous_container_id": BLUE_ID,
            "next_slot": "green",
            "next_image": self.next,
            "next_container_id": GREEN_ID,
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(
            os.environ, {"ANALYTICS_REVIEWED_SUPERVISOR_V2": "1"},
        ))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            self.stack.enter_context(patch(
                "deployment.analytics_executor.os." + name, return_value=991,
            ))
        self.loader = self.stack.enter_context(patch(
            "deployment.analytics_executor_service_config."
            "load_analytics_executor_service_config",
            return_value=(EXPECTED, {
                "expected_executor_uid": 991,
                "expected_executor_gid": 991,
                "owner_authorized_first_successor": True,
            }),
        ))
        self.reader = self.stack.enter_context(patch(
            "deployment.analytics_route_journal.AnalyticsRouteJournal.read",
            return_value=None,
        ))
        self.recover = self.stack.enter_context(patch(
            "deployment.analytics_loopback_guard._recover_reviewed_private_route",
        ))
        self.observed = self.stack.enter_context(patch(
            "deployment.analytics_active_state_review."
            "inspect_committed_analytics_route",
            return_value=SimpleNamespace(
                active_slot="blue", active_image=self.image,
            ),
        ))

    def attempt(self):
        """Invoke ONLY source-only protected startup reconciliation."""
        from deployment.analytics_executor import (
            _reconcile_interrupted_first_successor_before_receive,
        )
        return _reconcile_interrupted_first_successor_before_receive()

    def test_empty_root_verified_journal_permits_initial_receive(self):
        """No previous release must not mutate Docker, route or durable replay."""
        self.assertIsNone(self.attempt())
        self.loader.assert_called_once_with(require_successor=True)
        self.recover.assert_not_called()
        self.observed.assert_not_called()

    def test_all_three_incomplete_phases_restore_blue_then_hard_hold(self):
        """Never serve a new signed request after an interrupted old one."""
        from deployment.executor import ExecutorUnavailableError
        for phase in ("prepared", "candidate_ready", "rollback_pending"):
            with self.subTest(phase=phase):
                self.reader.return_value = {**self.record, "phase": phase}
                with self.assertRaises(ExecutorUnavailableError):
                    self.attempt()
                self.recover.assert_called_with(
                    journal=unittest.mock.ANY,
                    request_sha256="c" * 64,
                    previous_slot="blue",
                    previous_image=self.image,
                    previous_id=BLUE_ID,
                    next_slot="green",
                    next_image=self.next,
                    next_id=GREEN_ID,
                )
                self.assertEqual(
                    self.observed.call_args.kwargs["reviewed_slot"], "blue",
                )

    def test_committed_or_restored_record_is_hold_not_implicit_rollforward(self):
        """A SWITCHED journal might have a FINISHED replay; never guess."""
        from deployment.executor import ExecutorUnavailableError
        for phase in ("switched", "restored"):
            with self.subTest(phase=phase):
                self.reader.return_value = {**self.record, "phase": phase}
                with self.assertRaises(ExecutorUnavailableError):
                    self.attempt()
                self.recover.assert_not_called()
                self.observed.assert_not_called()

    def test_foreign_image_and_modified_trust_source_reject_before_route(self):
        """Neither arbitrary OCI nor root V2 review-only source can recover."""
        from deployment.executor import ExecutorUnavailableError
        self.reader.return_value = {
            **self.record, "previous_image": self.next,
        }
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.recover.assert_not_called()
        self.reader.return_value = self.record
        self.loader.return_value = (EXPECTED, {
            "expected_executor_uid": 991, "expected_executor_gid": 991,
        })
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.recover.assert_not_called()

    def completed_context(self):
        self.loader.return_value[1].update({
            'expected_replay_directory_uid': 0,
            'expected_replay_directory_gid': 992,
            'expected_broker_uid': 990,
        })
        self.reader.return_value = {**self.record, 'phase': 'switched'}
        self.proof_reader = self.stack.enter_context(patch(
            'deployment.analytics_route_journal.AnalyticsRouteJournal.read_execution',
            return_value={'image': self.next, 'container_id': GREEN_ID,
                          'canonical_request': b'simulated accepted request'},
        ))
        self.observed.return_value = SimpleNamespace(
            active_slot='green', active_image=self.next,
            active_container_id=GREEN_ID,
        )
        return self.stack.enter_context(patch(
            'deployment.analytics_executor._read_analytics_execution_status',
            return_value='finished',
        ))

    def test_completed_release_restarts_readonly_without_replaying_request(self):
        status = self.completed_context()
        self.assertIsNone(self.attempt())
        self.assertEqual(status.call_count, 2)
        status.assert_called_with(unittest.mock.ANY, 'c' * 64)
        self.recover.assert_not_called()
        self.observed.assert_called_once_with(
            journal=unittest.mock.ANY, reviewed_image=self.next,
            reviewed_slot='green', reviewed_container_id=GREEN_ID,
            reviewed_request_sha256='c' * 64,
        )

    def test_unknown_incomplete_or_unavailable_replay_never_adopts_green(self):
        from deployment.executor import ExecutorUnavailableError
        from deployment.identity import ReplayUnavailableError
        status = self.completed_context()
        for state in (None, 'consumed', 'executing'):
            with self.subTest(state=state):
                status.return_value = state
                with self.assertRaises(ExecutorUnavailableError):
                    self.attempt()
                self.observed.assert_not_called()
                self.recover.assert_not_called()
        status.side_effect = ReplayUnavailableError('private-storage-marker')
        with self.assertRaises(ExecutorUnavailableError) as caught:
            self.attempt()
        self.assertNotIn('private-storage-marker', str(caught.exception))

    def test_committed_route_or_journal_drift_holds_without_route_mutation(self):
        from deployment.executor import ExecutorUnavailableError
        self.completed_context()
        self.observed.return_value.active_container_id = 'f' * 64
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.observed.return_value.active_container_id = GREEN_ID
        intent = self.reader.return_value
        self.reader.side_effect = [intent, {**intent, 'request_sha256': 'd' * 64}]
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.recover.assert_not_called()

    def test_finished_hash_does_not_authenticate_forged_journal_image(self):
        self.completed_context()
        self.reader.return_value = {**self.reader.return_value,
            'next_image': 'oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:' + 'f' * 64}
        from deployment.executor import ExecutorUnavailableError
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.observed.assert_not_called()
        self.recover.assert_not_called()

    def test_legacy_missing_execution_proof_is_hold_without_mutation(self):
        self.completed_context()
        self.proof_reader.side_effect = ValueError('missing independent proof')
        from deployment.executor import ExecutorUnavailableError
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.observed.assert_not_called()
        self.recover.assert_not_called()

    def test_missing_root_scope_or_uid_does_not_even_read_journal(self):
        """Neither public env nor UID1005 may initiate protected recovery."""
        from deployment.executor import ExecutorUnavailableError
        with patch.dict(
            os.environ, {"ANALYTICS_REVIEWED_SUPERVISOR_V2": "0"},
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.attempt()
        with patch(
            "deployment.analytics_executor.os.geteuid", return_value=1005,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.attempt()
        self.loader.assert_not_called()
        self.reader.assert_not_called()
        self.recover.assert_not_called()

    def test_uncertain_old_writer_keeps_hold_without_false_success(self):
        """A failed actual recovery never reopens root-owned Unix admission."""
        from deployment.executor import ExecutorUnavailableError
        self.reader.return_value = self.record
        self.observed.return_value = SimpleNamespace(
            active_slot="green", active_image=self.next,
        )
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.recover.assert_called_once()






class DurableCompletedRestartTests(ReplayTestCase):
    """Exercise journal + proof + actual replay together across startup.

    The real host UID/config and Docker observation are substituted; neither
    journal reads, proof reads nor SQLite operations are mocked. This catches
    cross-component failures that separate state-machine mocks cannot prove.
    """

    def setUp(self):
        super().setUp()
        data, context = AnalyticsSuccessorRequestTests().candidate()
        request = parse_analytics_successor_request(canonical_bytes(data), **context)
        self.raw = request.canonical_bytes()
        self.request_hash = hashlib.sha256(self.raw).hexdigest()
        self.initialize()
        self.binding = dict(request_hash=self.request_hash, run_id=7, run_attempt=1)
        self.consume(**self.binding)
        self.guard.begin_execution('jti-1', **self.binding)
        temp = tempfile.TemporaryDirectory(prefix='m05-completed-route-')
        self.addCleanup(temp.cleanup)
        Path(temp.name).chmod(0o700)
        self.journal = AnalyticsRouteJournal(temp.name,
            expected_uid=os.getuid(), expected_gid=os.getgid())
        from deployment.tests.test_analytics_route_journal import approval
        intent = self.journal.begin(**approval(request_sha256=self.request_hash,
            next_image=request.exact_image_reference))
        ready = self.journal.finish(intent, phase='candidate_ready')
        self.switched = self.journal.finish(ready, phase='switched')

    def complete(self):
        self.journal.record_execution(self.raw, 'e' * 64)
        self.guard.finish_execution('jti-1', **self.binding)

    def attempt(self):
        from deployment.analytics_executor import (
            _reconcile_interrupted_first_successor_before_receive,
        )
        identities = {
            'expected_executor_uid': 991, 'expected_executor_gid': 991,
            'expected_replay_directory_uid': os.getuid(),
            'expected_replay_directory_gid': os.getgid(),
            'expected_broker_uid': 990,
            'owner_authorized_first_successor': True,
        }
        def observe(**kwargs):
            # Hardware response is synthetic; the underlying journal is real.
            self.assertIs(kwargs['journal'], self.journal)
            self.assertEqual(self.journal.read(), self.switched)
            return SimpleNamespace(active_slot='green',
                active_image=self.switched['next_image'], active_container_id='e' * 64)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,
                {'ANALYTICS_REVIEWED_SUPERVISOR_V2': '1'}))
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch('deployment.analytics_executor.os.' + name,
                    return_value=991))
            stack.enter_context(patch(
                'deployment.analytics_executor_service_config.load_analytics_executor_service_config',
                return_value=(EXPECTED, identities)))
            stack.enter_context(patch('deployment.analytics_route_journal.AnalyticsRouteJournal',
                return_value=self.journal))
            stack.enter_context(patch('deployment.replay_sqlite.PRODUCTION_REPLAY_DATABASE', self.path))
            recovery = stack.enter_context(patch(
                'deployment.analytics_loopback_guard._recover_reviewed_private_route'))
            stack.enter_context(patch(
                'deployment.analytics_active_state_review.inspect_committed_analytics_route',
                side_effect=observe))
            try:
                return _reconcile_interrupted_first_successor_before_receive()
            finally:
                recovery.assert_not_called()

    def test_finished_restart_and_second_restart_preserve_all_storage_bytes(self):
        self.complete()
        def storage():
            return {str(path): path.read_bytes() for root in (
                self.directory, Path(self.journal._directory))
                for path in root.rglob('*') if path.is_file()}
        before = storage()
        self.assertIsNone(self.attempt())
        self.assertIsNone(self.attempt())
        self.assertEqual(storage(), before)

    def test_proof_without_finished_replay_is_hold_with_original_evidence(self):
        self.journal.record_execution(self.raw, 'e' * 64)
        before = self.path.read_bytes()
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.journal.read(), self.switched)

    def test_finished_replay_without_proof_is_hold_without_synthesis(self):
        self.guard.finish_execution('jti-1', **self.binding)
        before = self.path.read_bytes()
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(set(Path(self.journal._directory).iterdir()),
            {Path(self.journal._directory) / 'transaction.json'})


# Section: accepted ordinary blue restart reuses durable signed execution
# receipts and the ORIGINAL SQLite replay without trying a new deployment.
class OrdinaryCommittedRestartTests(ReplayTestCase):
    """A completed second signed release survives restart without new OIDC."""

    def setUp(self):
        """Persist two real journal generations and one finished replay."""
        super().setUp()
        from deployment.tests.test_analytics_route_journal import approval, NEXT
        from deployment.tests.test_analytics_promotion_broker import (
            OrdinarySignedPredecessorTests,
        )
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE
        from release.analytics_owner_source_selection import expected_owner_approval_bytes
        data, context = AnalyticsSuccessorRequestTests().candidate()
        self.previous_image = NEXT
        self.previous_digest = NEXT.rsplit("@", 1)[-1]
        self.next_image = context["signed_release"].image
        data["owner_source_proof"] = "synthetic-owner-approved-next-release"
        data["ingress_reference"] = {
            **data["ingress_reference"], "active_slot": "green", "slot": "blue",
        }
        data["rollback_reference"] = {
            **data["rollback_reference"],
            "previous_digest": self.previous_digest,
            "previous_slot": "green",
        }
        selected, owner, signed, identity = (
            context["selected"], context["owner_approval"],
            context["signed_release"], context["identity"],
        )
        promotion = canonical_bytes({
            "product_id": "analytics", "release_version": selected.release_version,
            "source_sha": selected.platform_workflow_commit, "image": signed.image,
            "run_id": identity.run_id, "run_attempt": identity.run_attempt,
            "release_manifest_sha256": signed.manifest_sha256,
            "provenance_sha256": signed.provenance_sha256,
            "source_claim_sha256": signed.source.claim_sha256,
            "owner_approval_sha256": owner.approval_sha256,
            "previous_digest": self.previous_digest,
        })
        data["promotion_request_sha256"] = hashlib.sha256(promotion).hexdigest()
        self.raw = canonical_bytes(data)
        self.request_hash = hashlib.sha256(self.raw).hexdigest()
        self.prior_owner, self.next_owner = OrdinarySignedPredecessorTests.pair()
        self.initialize()
        self.binding = dict(request_hash=self.request_hash, run_id=7, run_attempt=1)
        self.consume(**self.binding)
        self.guard.begin_execution("jti-1", **self.binding)
        self.temp = tempfile.TemporaryDirectory(prefix="m05-ordinary-restart-")
        self.addCleanup(self.temp.cleanup)
        Path(self.temp.name).chmod(0o700)
        self.journal = AnalyticsRouteJournal(
            self.temp.name, expected_uid=os.getuid(), expected_gid=os.getgid(),
        )
        first = self.journal.begin(**approval(
            request_sha256="a" * 64,
            previous_image=PINNED_IMAGE,
            next_image=self.previous_image,
        ))
        self.journal.finish(
            self.journal.finish(first, phase="candidate_ready"),
            phase="switched",
        )
        ordinary = self.journal.begin(**approval(
            request_sha256=self.request_hash,
            previous_slot="green", previous_image=self.previous_image,
            previous_container_id="e" * 64, previous_ip="172.20.0.4",
            next_slot="blue", next_image=self.next_image,
            next_container_id="b" * 64, next_ip="172.20.0.3",
        ))
        self.switched = self.journal.finish(
            self.journal.finish(ordinary, phase="candidate_ready"),
            phase="switched",
        )

    def finish(self):
        """Durable success is replay FINISHED plus fsynced completion."""
        self.journal.record_execution(self.raw, "b" * 64)
        self.guard.finish_execution("jti-1", **self.binding)
        self.journal.record_completed_release(
            self.raw, "b" * 64, replay_guard=self.guard,
        )

    def attempt(self, *, signed_owner=None, active_image=None):
        """Review a prior and next root signature and live route without writes."""
        from deployment.analytics_executor import (
            _reconcile_interrupted_first_successor_before_receive,
        )
        former = self.prior_owner[1:]
        signed = self.next_owner[1:] if signed_owner is None else signed_owner
        identities = {
            "expected_executor_uid": 991, "expected_executor_gid": 991,
            "expected_replay_directory_uid": os.getuid(),
            "expected_replay_directory_gid": os.getgid(),
            "expected_broker_uid": 990,
            "owner_authorized_ordinary_successor": True,
        }
        with ExitStack() as stack:
            stack.enter_context(patch.dict(
                os.environ, {"ANALYTICS_REVIEWED_SUPERVISOR_V2": "1"},
            ))
            stack.enter_context(patch(
                "deployment.analytics_executor_service_config.load_analytics_executor_service_config",
                return_value=(EXPECTED, identities),
            ))
            # The *real* journal class remains the exact UID991 type. Only
            # its synthetic test-time constructor binds the already fsynced
            # isolated directory, avoiding a MagicMock as source authority.
            stack.enter_context(patch(
                "deployment.analytics_route_journal.ROUTE_JOURNAL_DIRECTORY",
                self.temp.name,
            ))
            def bind_existing_directory(target, *args, **kwargs):
                """Retain original class with the disposable exact journal FDs."""
                for key in ("_directory", "_uid", "_gid", "_locked_fd", "_locked_thread"):
                    object.__setattr__(target, key,
                        object.__getattribute__(self.journal, key))
            stack.enter_context(patch.object(
                AnalyticsRouteJournal, "__init__", bind_existing_directory,
            ))
            stack.enter_context(patch(
                "deployment.replay_sqlite.PRODUCTION_REPLAY_DATABASE", self.path,
            ))
            stack.enter_context(patch(
                "release.analytics_owner_source_selection.load_and_verify_owner_signed_source",
                return_value=former,
            ))
            stack.enter_context(patch(
                "release.analytics_owner_source_selection.verify_owner_signed_source_proof",
                return_value=signed,
            ))
            route = stack.enter_context(patch(
                "deployment.analytics_active_state_review.inspect_committed_analytics_route",
                return_value=SimpleNamespace(
                    active_slot="blue",
                    active_image=self.next_image if active_image is None else active_image,
                    active_container_id="b" * 64,
                ),
            ))
            recovery = stack.enter_context(patch(
                "deployment.analytics_loopback_guard._recover_reviewed_private_route",
            ))
            for field in ("getuid", "geteuid", "getgid", "getegid"):
                stack.enter_context(patch(
                    "deployment.analytics_executor.os." + field, return_value=991,
                ))
            try:
                return _reconcile_interrupted_first_successor_before_receive()
            finally:
                recovery.assert_not_called()

    def test_signed_finished_ordinary_restarts_without_writing_storage(self):
        """Second release remains bound to its real UID991 route after boot."""
        self.finish()
        def storage():
            """Hash all existing SQLite and journal source-of-truth bytes."""
            return {str(path): path.read_bytes() for root in (
                self.directory, Path(self.journal._directory),
            ) for path in root.rglob("*") if path.is_file()}
        before = storage()
        self.assertIsNone(self.attempt())
        self.assertIsNone(self.attempt())
        self.assertEqual(storage(), before)

    def test_completed_certificate_survives_legitimate_replay_expiry(self):
        """Fresh signed GitHub JTI may prune an old success without breaking boot."""
        self.finish()
        completed = self.journal.read_completed_release(self.request_hash)
        self.assertEqual(completed["request_sha256"], self.request_hash)
        self.assertIsNone(self.attempt())
        self.now = NOW + 1000
        self.guard.consume(
            "new-unrelated-github-jti", expires_at=self.now + 100,
            request_hash="d" * 64, run_id=8, run_attempt=1,
        )
        self.assertIsNone(_read_analytics_execution_status(self.guard, self.request_hash))
        before = (self.path.read_bytes(), self.journal.read())
        self.assertIsNone(self.attempt())
        self.assertIsNone(self.attempt())
        self.assertEqual((self.path.read_bytes(), self.journal.read()), before)

    def test_missing_certificate_with_pruned_replay_is_hold(self):
        """A crashed post-FINISHED pre-certificate path is always HOLD."""
        self.journal.record_execution(self.raw, "b" * 64)
        self.guard.finish_execution("jti-1", **self.binding)
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.now = NOW + 1000
        self.guard.consume(
            "next-unique-jti", expires_at=self.now + 100,
            request_hash="d" * 64, run_id=8, run_attempt=1,
        )
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()

    def test_unfinished_replay_cannot_write_completed_certificate(self):
        """No forged FINISHED record when SQLite is only CONSUMED/EXECUTING."""
        self.journal.record_execution(self.raw, "b" * 64)
        with self.assertRaises(Exception):
            self.journal.record_completed_release(
                self.raw, "b" * 64, replay_guard=self.guard,
            )
        self.assertIsNone(self.journal.read_completed_release(self.request_hash))

    def test_completion_certificate_tamper_and_symlink_are_hold(self):
        self.finish()
        certificate = (Path(self.journal._directory) / "executions"
                       / ("completion-" + self.request_hash + ".json"))
        original = certificate.read_bytes()
        before = self.path.read_bytes()
        with self.assertRaises(Exception):
            self.journal.record_completed_release(
                self.raw, "b" * 64, replay_guard=self.guard,
            )
        self.assertEqual(certificate.read_bytes(), original)
        self.assertEqual(self.path.read_bytes(), before)
        certificate.write_bytes(original.replace(b"finished", b"unknown_"))
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        certificate.unlink()
        certificate.symlink_to("execution-" + self.request_hash + ".json")
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()

    def test_ordinary_restart_requires_both_owner_and_finished_replay(self):
        """Forged source and uncommitted replay can never signal healthy GO."""
        from dataclasses import replace
        self.journal.record_execution(self.raw, "b" * 64)
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt()
        self.guard.finish_execution("jti-1", **self.binding)
        self.journal.record_completed_release(
            self.raw, "b" * 64, replay_guard=self.guard,
        )
        invalid = (
            replace(self.next_owner[2], owner_signature_verified=False),
            replace(self.next_owner[2], approval_sha256="f" * 64),
        )
        for signed in invalid:
            with self.subTest(signed=signed), self.assertRaises(ExecutorUnavailableError):
                self.attempt(signed_owner=(self.next_owner[1], signed))
        with self.assertRaises(ExecutorUnavailableError):
            self.attempt(active_image=self.previous_image)

class AnalyticsExecutionStatusReadOnlyTests(ReplayTestCase):
    def test_observes_each_state_without_changing_bytes_clock_or_rows(self):
        self.initialize()
        binding = dict(request_hash=HASH_A, run_id=1, run_attempt=1)
        self.consume()
        for expected in ('consumed', 'executing', 'finished'):
            if expected == 'executing':
                self.guard.begin_execution('jti-1', **binding)
            elif expected == 'finished':
                self.guard.finish_execution('jti-1', **binding)
            before = self.path.read_bytes()
            entries = set(self.directory.iterdir())
            self.now = NOW + 1000
            self.assertEqual(_read_analytics_execution_status(self.guard, HASH_A), expected)
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(set(self.directory.iterdir()), entries)
            self.now = NOW

    def test_missing_hash_is_unknown_without_initializing_or_mutating(self):
        self.initialize()
        before = self.path.read_bytes()
        self.assertIsNone(_read_analytics_execution_status(self.guard, HASH_A))
        self.assertEqual(self.path.read_bytes(), before)
        self.path.unlink()
        self.unavailable(lambda: _read_analytics_execution_status(self.guard, HASH_A))
        self.assertFalse(self.path.exists())

    def test_ambiguous_hash_never_selects_an_arbitrary_finished_row(self):
        self.initialize()
        self.consume()
        self.consume('jti-2', run_id=2)
        before = self.path.read_bytes()
        self.unavailable(lambda: _read_analytics_execution_status(self.guard, HASH_A))
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_hash_fails_before_opening_the_store(self):
        with patch.object(self.guard, '_open_directory') as opened:
            for value in (None, True, '', 'A' * 64, 'a' * 63, '0' * 64):
                with self.subTest(value=value):
                    self.unavailable(lambda: _read_analytics_execution_status(self.guard, value))
            opened.assert_not_called()

    def test_invalid_store_and_symlink_do_not_become_authority(self):
        self.initialize()
        self.consume()
        before = self.path.read_bytes()
        self.path.chmod(0o666)
        self.unavailable(lambda: _read_analytics_execution_status(self.guard, HASH_A))
        self.assertEqual(self.path.read_bytes(), before)
        self.path.chmod(DATABASE_MODE)
        renamed = self.directory / 'foreign.sqlite3'
        self.path.rename(renamed)
        self.path.symlink_to(renamed)
        self.unavailable(lambda: _read_analytics_execution_status(self.guard, HASH_A))
        self.assertEqual(renamed.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

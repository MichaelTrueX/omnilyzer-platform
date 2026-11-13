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
          deny scenarios and recovery after all substantive failure phases.

All Docker, sockets, JWTs, signing, permissions, SQLite mutations and routes
are simulated only in this file. Existing independent real-source security
and replay/socket tests continue to cover those components. Nothing installs,
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


if __name__ == "__main__":
    unittest.main()

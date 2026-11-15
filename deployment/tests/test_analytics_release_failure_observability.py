"""File: deployment/tests/test_analytics_release_failure_observability.py

Purpose: Negative-first tests for fixed, nonsecret Analytics Task014 failure
         classification across signed evidence, UID990 broker, private ingress,
         Unix sender, and existing UID991 post-replay recovery.
Related: deployment/analytics_registry_review_composition.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/analytics_promotion_broker.py,
         deployment/analytics_broker_router.py,
         deployment/broker_https_ingress.py,
         deployment/analytics_unix_boundary.py,
         deployment/analytics_executor.py,
         deployment/tests/test_analytics_promotion_broker.py.

All requests are synthetic and local. No real JWT, root, registry, Docker,
protected replay, Task014 workflow, service restart or private HTTP exposure.
"""
from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from deployment.analytics_registry_review_composition import (
    _emit_analytics_release_boundary,
)
from deployment.analytics_signed_release_consumer import (
    _emit_signed_successor_failure,
)
from deployment.analytics_unix_boundary import _emit_analytics_unix_phase
from deployment.broker_https_ingress import (
    PROMOTION_PATH,
    dispatch_inert_dev_promotion_ingress,
    _emit_broker_unavailable_boundary,
)
from deployment.tests.test_broker_https_ingress import BODY, headers
from deployment.tests.test_analytics_promotion_broker import (
    AnalyticsFirstSuccessorBrokerReviewTests,
    SyntheticPositiveSuccessorTransport,
    evidence,
    make_broker,
)
from deployment.broker import BrokerUnavailableError


class FixedPrivateReleaseLogTests(unittest.TestCase):
    """Assert only compile-time failure phases can leave a protected process."""

    def test_safe_broker_phase_allowlist_is_closed_and_ascii(self):
        """One exact fixed record, not any user-selected phase or category."""
        with patch("deployment.analytics_registry_review_composition.os.write") as write:
            _emit_analytics_release_boundary("broker_unix_send", "unavailable")
            _emit_analytics_release_boundary("broker_unix_send\nBearer user-secret", "unavailable")
            _emit_analytics_release_boundary("broker_unix_send", "invalid-outcome")
            _emit_analytics_release_boundary(42, "unavailable")
            _emit_analytics_release_boundary("broker_unix_send", {"secret": "x"})
        write.assert_called_once_with(
            2,
            b"TASK014_ANALYTICS_BROKER_BOUNDARY phase=broker_unix_send outcome=unavailable\n",
        )

    def test_safe_signed_evidence_phase_allowlist_is_closed(self):
        """A source-controlled phase is printed, dynamic exception text never."""
        with patch("deployment.analytics_signed_release_consumer.os.write") as write:
            _emit_signed_successor_failure("zot_manifest_read")
            _emit_signed_successor_failure("zot_manifest_read\nsecret=x")
            _emit_signed_successor_failure("")
        write.assert_called_once_with(
            2, b"TASK014_ANALYTICS_SIGNED_HOLD phase=zot_manifest_read\n",
        )

    def test_unix_phase_allowlist_is_closed(self):
        """No token, FD, peer path or arbitrary socket error appears in output."""
        with patch("deployment.analytics_unix_boundary.os.write") as write:
            _emit_analytics_unix_phase("socket_transport")
            _emit_analytics_unix_phase("../path?authorization=secret")
        write.assert_called_once_with(
            2, b"TASK014_ANALYTICS_UNIX_HOLD phase=socket_transport\n",
        )

    def test_broken_journald_cannot_change_original_release_decision(self):
        """All best-effort writers swallow ordinary I/O errors."""
        with patch("os.write", side_effect=OSError("secret=never-print")):
            self.assertIsNone(_emit_analytics_release_boundary("owner_signature", "unavailable"))
            self.assertIsNone(_emit_signed_successor_failure("sigstore_blobs"))
            self.assertIsNone(_emit_analytics_unix_phase("socket_transport"))
            self.assertIsNone(_emit_broker_unavailable_boundary())

    def test_http_503_is_unchanged_and_secret_free(self):
        """An actual handler failure is still the same fixed 503 on the wire."""
        secret = "Bearer.private_synthetic_sensitive_token"

        class BrokenHandler:
            def handle(self, **kwargs):
                raise RuntimeError("private failure: " + secret)

        with patch("deployment.broker_https_ingress.os.write") as write:
            result = dispatch_inert_dev_promotion_ingress(
                BrokenHandler(), method="POST", path=PROMOTION_PATH,
                headers=headers(), body=BODY, received_at=123,
            )
        self.assertEqual(result.status, 503)
        self.assertEqual(result.body, b'{"status":"unavailable"}\n')
        write.assert_called_once_with(
            2, b"TASK014_PRIVATE_BROKER_INGRESS_HOLD phase=handler_unavailable\n",
        )
        self.assertNotIn(secret.encode(), write.call_args.args[1])
        self.assertNotIn(secret.encode(), result.body)

    def test_no_sender_is_classified_before_signed_review_or_replay(self):
        """A missing secure transport must not consume any JTI or open an FD."""
        raw, _context, _ = AnalyticsFirstSuccessorBrokerReviewTests.candidate()
        kwargs = AnalyticsFirstSuccessorBrokerReviewTests.kwargs(raw)
        broker, replay, transport = make_broker()
        with (
            patch("deployment.analytics_promotion_broker._emit_analytics_release_boundary") as emit,
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.authorize_and_forward_first_successor(**kwargs)
        emit.assert_called_once_with("broker_sender", "unavailable")
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_absent_root_owner_is_classified_before_successor_dispatch(self):
        """The independent signed source gate is still mandatory and no replay occurs."""
        raw, _context, _ = AnalyticsFirstSuccessorBrokerReviewTests.candidate()
        broker, replay, transport = make_broker(
            transport=SyntheticPositiveSuccessorTransport(),
            owner_files=None,
        )
        with (
            patch(
                "deployment.analytics_registry_review_composition."
                "acquire_and_review_analytics_release",
                return_value=evidence(),
            ),
            patch("deployment.analytics_registry_review_composition.os.write") as write,
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.authorize_and_forward_first_successor(
                **AnalyticsFirstSuccessorBrokerReviewTests.kwargs(raw),
            )
        logged = [call.args[1] for call in write.call_args_list]
        self.assertIn(
            b"TASK014_ANALYTICS_BROKER_BOUNDARY phase=owner_signature outcome=unavailable\n",
            logged,
        )
        self.assertIn(
            b"TASK014_ANALYTICS_BROKER_BOUNDARY phase=broker_successor_evidence outcome=unavailable\n",
            logged,
        )
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.checked, [])

    def test_new_uid991_candidate_phases_are_strict_closed_constants(self):
        """Original UID991 logger can label every new post-replay failure safely."""
        from deployment.analytics_executor import _UID991_FAILURE_PHASES
        required = {
            "candidate_stage", "candidate_identity", "candidate_probe",
            "candidate_ready_preflight", "private_route_switch",
            "private_route_verify", "replay_finish", "signed_success_reply",
        }
        self.assertTrue(required.issubset(_UID991_FAILURE_PHASES))
        self.assertTrue(all(phase.isascii() and phase.replace("_", "").isalpha()
                            for phase in _UID991_FAILURE_PHASES))


if __name__ == "__main__":
    unittest.main()

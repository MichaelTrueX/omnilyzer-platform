"""File: deployment/tests/test_analytics_signed_binding_diagnostics.py

Purpose: Prove generation3 Task014 local, redacted diagnostics distinguish a
         rejected signed request binding from subsequent active-host drift.
Related: deployment/analytics_executor.py (UID991 stage boundary),
         deployment/analytics_execution.py (unchanged strict parser),
         deployment/tests/test_analytics_execution.py (closed signed fixture).

Sections: synthetic authorized setup; binding denial; live drift denial;
          silent legacy/foreign principal and successful read-only review;
          ordinary signed predecessor/next and opposite-slot executor checks.
No real OIDC credentials, registry calls, Docker, replay writes or routing.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from io import StringIO
import unittest
from unittest.mock import patch

from deployment.analytics_executor import (
    _review_executor_successor_signed_release,
)
from deployment.analytics_execution import parse_analytics_successor_request
from deployment.executor import ExecutorUnavailableError
from deployment.policy import canonical_bytes
from deployment.tests.test_analytics_execution import (
    AnalyticsSuccessorRequestTests, EXPECTED,
)
from deployment.tests.test_analytics_private_registry import (
    first_successor_empty_active_state,
)
from deployment.tests.test_identity import NOW, WORKFLOW_SHA


class SignedBindingDiagnosticTests(unittest.TestCase):
    """Exercise actual reviewed stage control flow, with all I/O simulated."""

    def setUp(self):
        """Reuse genuine typed fixtures without authorizing a deployment."""
        data, self.context = AnalyticsSuccessorRequestTests().candidate()
        self.raw = canonical_bytes(data)
        self.parsed = parse_analytics_successor_request(
            self.raw, **self.context,
        )
        self.original = first_successor_empty_active_state()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for field in ("getuid", "geteuid", "getgid", "getegid"):
            self.stack.enter_context(patch(
                "deployment.analytics_executor.os." + field,
                return_value=991,
            ))
        self.stack.enter_context(patch(
            "deployment.analytics_unix_boundary._root_reviewed_source",
            return_value=EXPECTED,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor._verify_executor_owner_source",
            return_value=None,
        ))
        self.inspector = self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=self.original,
        ))
        self.credentials = self.stack.enter_context(patch(
            "deployment.analytics_executor."
            "_verified_executor_successor_identity_and_credentials",
            return_value=(self.context["identity"], object()),
        ))
        provenance = self.stack.enter_context(patch(
            "deployment.sigstore_authority_provenance."
            "DevSigstoreVerificationProvenance",
        ))
        provenance.return_value.broker_service_configuration_kwargs.return_value = {
            "cosign_version": "synthetic",
            "cosign_binary_sha256": "a" * 64,
            "sigstore_trusted_root_sha256": "b" * 64,
        }
        self.blob = self.stack.enter_context(patch(
            "deployment.blob_verifier.CosignReleaseBlobVerifier",
        ))
        self.oci = self.stack.enter_context(patch(
            "deployment.oci_verifier.CosignOCISignatureVerifier",
        ))
        self.signed = self.stack.enter_context(patch(
            "deployment.analytics_signed_release_consumer."
            "acquire_and_review_owner_approved_analytics_release",
            return_value=self.context["signed_release"],
        ))
        self.stack.enter_context(patch(
            "release.analytics_owner_source_selection."
            "load_and_verify_owner_signed_source",
            return_value=(
                self.context["selected"], self.context["owner_approval"],
            ),
        ))
        self.parser = self.stack.enter_context(patch(
            "deployment.analytics_execution.parse_analytics_successor_request",
            return_value=self.parsed,
        ))

    def review(self, *, trace=True):
        """Run the original UID991 signed-review helper, without live I/O."""
        return _review_executor_successor_signed_release(
            self.raw, credential_fd=21,
            expected_workflow_sha=WORKFLOW_SHA,
            reviewed_installed_source=EXPECTED,
            received_at=NOW, trace_generation3=trace,
        )

    # Section 1: no new permissive return route or success-stage noise.
    def test_success_does_not_log_or_change_the_request(self):
        """Successful strict parse and stable second snapshot stay silent."""
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            self.assertEqual(self.review(), self.parsed)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.parser.call_count, 1)
        self.assertEqual(self.inspector.call_count, 2)
        self.credentials.assert_called_once()
        self.signed.assert_called_once()
        self.blob.assert_called_once()
        self.oci.assert_called_once()

    # Section 2: a rejected binding remains a generic external denial.
    def test_parser_denial_keeps_original_fixed_phase(self):
        """A signed request mismatch cannot be mislabeled as host drift."""
        self.parser.side_effect = ValueError("synthetic-token-must-not-log")
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            with self.assertRaises(ExecutorUnavailableError) as caught:
                self.review()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=signed_release_binding\n",
        )
        self.assertEqual(self.inspector.call_count, 1)
        self.assertNotIn("synthetic-token", str(caught.exception))
        self.assertNotIn("synthetic-token", stderr.getvalue())

    def test_invalid_parsed_image_stays_in_binding_stage(self):
        """Type and signed-image equality remain enforced before recheck."""
        for bad in (
            object(),
            replace(
                self.parsed,
                exact_image_reference=(
                    "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
                    + "0" * 64
                ),
            ),
        ):
            with self.subTest(parsed_type=type(bad).__name__):
                self.parser.return_value = bad
                with patch(
                    "deployment.analytics_executor.sys.stderr", new=StringIO(),
                ) as stderr:
                    with self.assertRaises(ExecutorUnavailableError):
                        self.review()
                self.assertEqual(
                    stderr.getvalue(),
                    "TASK014_ANALYTICS_UID991_HOLD phase=signed_release_binding\n",
                )
                self.inspector.assert_called_once()
                self.inspector.reset_mock()

    # Section 3: only a passed parse may enter live-active recheck.
    def test_second_snapshot_changed_emits_new_static_stage(self):
        """Two different signed-blue snapshots are never accepted."""
        later = replace(
            self.original, active_container_id="f" * 64,
        )
        self.inspector.side_effect = [self.original, later]
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            with self.assertRaises(ExecutorUnavailableError):
                self.review()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=signed_live_recheck\n",
        )
        self.parser.assert_called_once()
        self.assertEqual(self.inspector.call_count, 2)

    def test_second_snapshot_exception_is_closed_and_redacted(self):
        """A failed host read is also a deny, not a successful recheck."""
        self.inspector.side_effect = [
            self.original, RuntimeError("synthetic-host-secret"),
        ]
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            with self.assertRaises(ExecutorUnavailableError) as caught:
                self.review()
        self.assertEqual(
            stderr.getvalue(),
            "TASK014_ANALYTICS_UID991_HOLD phase=signed_live_recheck\n",
        )
        self.assertNotIn("synthetic-host-secret", stderr.getvalue())
        self.assertNotIn("synthetic-host-secret", str(caught.exception))

    # Section 4: preserve generation2 silence and UID991-only logging.
    def test_default_silent_on_identical_binding_failure(self):
        """No stage is emitted absent explicit generation3 trace opt-in."""
        self.parser.side_effect = ValueError("synthetic-token")
        with patch(
            "deployment.analytics_executor.sys.stderr", new=StringIO(),
        ) as stderr:
            with self.assertRaises(ExecutorUnavailableError):
                self.review(trace=False)
        self.assertEqual(stderr.getvalue(), "")

    def test_foreign_uid_stays_silent_and_never_reads_registry(self):
        """Unprivileged caller cannot enable local stage diagnostics."""
        with (
            patch("deployment.analytics_executor.os.getuid", return_value=1005),
            patch("deployment.analytics_executor.sys.stderr", new=StringIO()) as stderr,
        ):
            with self.assertRaises(ExecutorUnavailableError):
                self.review()
        self.assertEqual(stderr.getvalue(), "")
        self.signed.assert_not_called()
        self.parser.assert_not_called()


# Section 5: independently signed ordinary predecessor and real opposite slot.
class OrdinaryExecutorSignedPredecessorTests(unittest.TestCase):
    """Exercise source-only UID991 predecessor/next review with synthetic I/O."""

    def setUp(self):
        """Use the genuine request parser and two synthetic signed versions."""
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE, PINNED_DIGEST
        from deployment.tests.test_analytics_promotion_broker import (
            OrdinarySignedPredecessorTests,
        )
        data, self.context = AnalyticsSuccessorRequestTests().candidate()
        data["owner_source_proof"] = "synthetic-public-proof"
        self.raw = canonical_bytes(data)
        predecessor, next_release = OrdinarySignedPredecessorTests.pair()
        self.predecessor = (
            replace(predecessor[0], image=PINNED_IMAGE,
                source=replace(predecessor[0].source,
                    oci_manifest_digest=PINNED_DIGEST)),
            predecessor[1], predecessor[2],
        )
        self.next_release = next_release
        self.live = first_successor_empty_active_state()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            self.stack.enter_context(patch(
                "deployment.analytics_executor.os." + name, return_value=991,
            ))
        self.stack.enter_context(patch(
            "deployment.analytics_unix_boundary._root_reviewed_source",
            return_value=EXPECTED,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_executor._verify_executor_owner_source",
            return_value=None,
        ))
        self.inspector = self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.inspect_analytics_active_state",
            return_value=self.live,
        ))
        self.stack.enter_context(patch(
            "deployment.analytics_active_state_review.verify_empty_analytics_candidate_slot",
            return_value=None,
        ))
        self.identity = self.stack.enter_context(patch(
            "deployment.analytics_executor._verified_executor_successor_identity_and_credentials",
            return_value=(self.context["identity"], object()),
        ))
        provenance = self.stack.enter_context(patch(
            "deployment.sigstore_authority_provenance.DevSigstoreVerificationProvenance",
        ))
        provenance.return_value.broker_service_configuration_kwargs.return_value = {
            "cosign_version": "synthetic",
            "cosign_binary_sha256": "a" * 64,
            "sigstore_trusted_root_sha256": "b" * 64,
        }
        self.stack.enter_context(patch("deployment.blob_verifier.CosignReleaseBlobVerifier"))
        self.stack.enter_context(patch("deployment.oci_verifier.CosignOCISignatureVerifier"))
        self.signed = self.stack.enter_context(patch(
            "deployment.analytics_signed_release_consumer.acquire_and_review_owner_approved_analytics_release",
            side_effect=[self.predecessor[0], self.next_release[0]],
        ))
        self.stack.enter_context(patch(
            "release.analytics_owner_source_selection.load_and_verify_owner_signed_source",
            return_value=self.predecessor[1:],
        ))
        self.stack.enter_context(patch(
            "release.analytics_owner_source_selection.verify_owner_signed_source_proof",
            return_value=self.next_release[1:],
        ))

    def review(self):
        """Invoke the new read-only ordinary executor boundary."""
        from deployment.analytics_executor import _review_executor_ordinary_signed_release
        return _review_executor_ordinary_signed_release(
            self.raw, 21, expected_workflow_sha=WORKFLOW_SHA,
            reviewed_installed_source=EXPECTED, received_at=NOW,
        )

    def test_read_only_signed_predecessor_and_opposite_slot(self):
        """Bind actual observed OCI, both signatures and exact request parser."""
        checked = self.review()
        self.assertEqual(checked.canonical_bytes(), self.raw)
        self.assertEqual(checked.rollback_reference["previous_digest"],
                         self.live.active_digest)
        self.assertEqual(self.signed.call_count, 2)
        self.identity.assert_called_once()
        self.assertGreaterEqual(self.inspector.call_count, 3)

    def test_wrong_prior_signer_or_live_oci_cannot_become_authority(self):
        """Never accept a previous release that does not match the real route."""
        from deployment.analytics_signed_release_consumer import PINNED_IMAGE
        bad = replace(self.predecessor[0], image=PINNED_IMAGE.replace("sha256:", "sha256:0"))
        self.signed.side_effect = [bad, self.next_release[0]]
        with self.assertRaises(ExecutorUnavailableError):
            self.review()
        self.assertEqual(self.signed.call_count, 2)

    def test_changed_route_after_signed_review_is_denied(self):
        """No stale measured writer may survive a four-read identity check."""
        self.inspector.side_effect = [
            self.live, self.live, self.live,
            replace(self.live, active_container_id="d" * 64),
        ]
        with self.assertRaises(ExecutorUnavailableError):
            self.review()
        self.assertEqual(self.signed.call_count, 2)
        self.assertEqual(self.inspector.call_count, 4)

    def test_signed_active_green_to_candidate_blue_is_supported(self):
        """The ordinary request binds the actual signed green, not old blue."""
        import hashlib
        from deployment.policy import canonical_bytes
        from deployment.tests.test_analytics_execution import AnalyticsSuccessorRequestTests
        data, _ = AnalyticsSuccessorRequestTests().candidate()
        data["owner_source_proof"] = "synthetic-public-proof"
        prior_digest = "sha256:" + "a" * 64
        prior_image = "oci-dev.omnilyzer.ai/omnilyzer/analytics@" + prior_digest
        old = replace(self.predecessor[0], image=prior_image,
                      source=replace(self.predecessor[0].source,
                                     oci_manifest_digest=prior_digest))
        self.signed.side_effect = [old, self.next_release[0]]
        self.live = replace(
            self.live, active_slot="green", active_digest=prior_digest,
            active_image=prior_image, candidate_slot="blue",
            active_child_ip="172.20.0.4", active_container_id="b" * 64,
        )
        self.inspector.return_value = self.live
        data["ingress_reference"] = {
            **data["ingress_reference"], "slot": "blue", "active_slot": "green",
        }
        data["rollback_reference"] = {
            **data["rollback_reference"], "previous_digest": prior_digest,
            "previous_slot": "green",
        }
        signed, selected, owner = self.next_release
        identity = self.context["identity"]
        intent = canonical_bytes({
            "product_id": "analytics", "release_version": selected.release_version,
            "source_sha": selected.platform_workflow_commit, "image": signed.image,
            "run_id": identity.run_id, "run_attempt": identity.run_attempt,
            "release_manifest_sha256": signed.manifest_sha256,
            "provenance_sha256": signed.provenance_sha256,
            "source_claim_sha256": signed.source.claim_sha256,
            "owner_approval_sha256": owner.approval_sha256,
            "previous_digest": prior_digest,
        })
        data["promotion_request_sha256"] = hashlib.sha256(intent).hexdigest()
        self.raw = canonical_bytes(data)
        checked = self.review()
        self.assertEqual(checked.ingress_reference["slot"], "blue")
        self.assertEqual(checked.rollback_reference["previous_slot"], "green")
        self.assertEqual(checked.rollback_reference["previous_digest"], prior_digest)

    def test_foreign_uid_blocks_before_signed_proof_and_docker(self):
        """A non-executor caller cannot cause even a registry read."""
        with patch("deployment.analytics_executor.os.getuid", return_value=1005):
            with self.assertRaises(ExecutorUnavailableError):
                self.review()
        self.signed.assert_not_called()
        self.identity.assert_not_called()
        self.inspector.assert_not_called()

    def test_occupied_or_unstable_route_fails_before_authorization(self):
        """No upgrade when a private candidate already exists or route drifts."""
        self.inspector.return_value = replace(self.live, candidate_probe_present=True)
        with self.assertRaises(ExecutorUnavailableError):
            self.review()
        self.identity.assert_not_called()
        self.signed.assert_not_called()

if __name__ == "__main__":
    unittest.main()

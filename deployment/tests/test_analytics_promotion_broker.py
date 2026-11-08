"""File: deployment/tests/test_analytics_promotion_broker.py

Purpose: Negative-first isolated Task014 Analytics signed-release -> original
         OIDC/registry audience -> exact sealed Zot FD -> replay -> explicit
         product-only private transport orchestration. Synthetic signers are
         NOT evidence of actual 0.15.0 cryptographic acceptance or installation.

Related: deployment/analytics_promotion_broker.py,
         deployment/private_registry_fd.py,
         deployment/analytics_signed_release_consumer.py,
         deployment/analytics_registry_review_composition.py,
         deployment/tests/test_analytics_execution.py,
         deployment/tests/test_analytics_review_composition.py.

Sections: exact original private one-pass positive pipe; mandatory
          signer, OIDC, registry and replay failures, token/FD redaction,
          canary isolation; read-only root broker first-successor review
          using signed old/new releases and measured active image.

No actual Docker, network, real keys, secrets or installed executor.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from deployment.analytics_promotion_broker import AnalyticsPrivatePromotionBroker
from deployment.analytics_signed_release_consumer import (
    AnalyticsSignedEvidenceReview, PINNED_IMAGE, PINNED_RUN_ID, PINNED_VERSION,
)
from deployment.analytics_signed_source_pin import (
    AnalyticsSourceReviewReceipt, SOURCE_COMMIT, SOURCE_TREE,
)
from deployment.broker import BrokerRejectedError, BrokerUnavailableError
from deployment.private_registry_fd import (
    read_sealed_credential, read_sealed_successor_review_credentials,
)
from deployment.registry_oidc_credentials import VerifiedRegistryCredentials
from deployment.tests.test_analytics_execution import (
    EXPECTED, PRODUCT_SHA, RUNTIME_SHA, fixture,
)
from deployment.tests.test_analytics_review_composition import handler
from deployment.tests.test_broker import Replay, Verifier
from deployment.tests.test_broker_integration import (
    FORGEJO_TOKEN, KEY, TOKEN, ZOT_TOKEN,
)
from deployment.tests.test_identity import NOW, WORKFLOW_SHA
from deployment.tests.test_registry_oidc_credentials import StaticCache
from deployment.policy import canonical_bytes


def evidence() -> AnalyticsSignedEvidenceReview:
    """Return synthetic hash-compatible test evidence only, not real signatures."""
    return AnalyticsSignedEvidenceReview(
        release_version=PINNED_VERSION, image=PINNED_IMAGE,
        release_run_id=PINNED_RUN_ID, manifest_sha256="a" * 64,
        provenance_sha256="b" * 64,
        source=AnalyticsSourceReviewReceipt(
            source_commit=SOURCE_COMMIT, source_tree=SOURCE_TREE,
            oci_manifest_digest=PINNED_IMAGE.rsplit("@", 1)[-1],
            claim_sha256="e" * 64, product_profile_sha256=PRODUCT_SHA,
            runtime_profile_sha256=RUNTIME_SHA,
        ),
    )


class PrivateAnalyticsTransport:
    """Test-only product-specific receiver that inspects real sealed FDs."""

    def __init__(self, *, error: bool = False, response: bytes = b'{"accepted":true}\n'):
        self.requests: list[bytes] = []
        self.seen_credentials: list[str] = []
        self.received_fds: list[int] = []
        self.error = error
        self.response = response

    def _send_analytics_private(self, request: bytes, *, credential_fd: int) -> bytes:
        """Never display secret; require real sealed exact Analytics FD."""
        value = read_sealed_credential(
            credential_fd, canonical_request=request,
            image=PINNED_IMAGE, now=NOW, product_id="analytics",
        )
        self.requests.append(request)
        self.seen_credentials.append(hashlib.sha256(value.token.encode()).hexdigest())
        self.received_fds.append(credential_fd)
        if self.error:
            raise OSError("synthetic no transport listener")
        return self.response


def make_broker(
    *, replay: Replay | None = None,
    verifier: Verifier | None = None,
    transport: PrivateAnalyticsTransport | None = None,
    expected: dict[str, str] | None = None,
    owner_files: tuple[Path, Path] | None = None,
):
    """Create fully original OIDC+JWT verifiers with synthetic signed blob result."""
    chosen_replay = Replay() if replay is None else replay
    chosen_transport = PrivateAnalyticsTransport() if transport is None else transport
    broker = AnalyticsPrivatePromotionBroker(
        expected_workflow_sha=WORKFLOW_SHA,
        verifier=Verifier() if verifier is None else verifier,
        signed_review_handler=handler(owner_files=owner_files),
        replay_guard=chosen_replay,
        analytics_transport=chosen_transport,
        reviewed_installed_source=EXPECTED if expected is None else expected,
        jwks_cache=StaticCache(KEY.public_key()),
    )
    return broker, chosen_replay, chosen_transport


def call(broker, **overrides):
    """Use the one exact canonical request and three separate JWT channels."""
    args = dict(
        compact_token=TOKEN, zot_token=ZOT_TOKEN,
        forgejo_token=FORGEJO_TOKEN,
        canonical_request=canonical_bytes(fixture()),
        received_at=NOW,
    )
    return broker.authorize_and_forward(**(args | overrides))


class AnalyticsSignedBrokerTests(unittest.TestCase):
    """Prove fail-closed ordering without a live executor/installation."""

    def setUp(self):
        self.verified = patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
            return_value=evidence(),
        )
        self.mocked = self.verified.start()
        self.clock = patch("deployment.analytics_promotion_broker.time.time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.verified.stop)
        self.addCleanup(self.clock.stop)

    def test_real_original_jwt_and_sealed_credential_then_replay_and_private_send(self):
        """Signed review must occur internally; no public dataclass input."""
        broker, replay, transport = make_broker()
        request = canonical_bytes(fixture())
        before = set(os.listdir("/proc/self/fd"))
        result = call(broker)
        after = set(os.listdir("/proc/self/fd"))
        self.assertEqual(before, after)
        self.assertEqual(result, transport.response)
        self.assertEqual(transport.requests, [request])
        self.assertEqual(len(transport.received_fds), 1)
        self.assertEqual(len(transport.seen_credentials), 1)
        self.assertEqual(replay.calls[0]["request_hash"], hashlib.sha256(request).hexdigest())
        self.assertEqual(len(replay.calls), 1)
        self.mocked.assert_called_once()
        self.assertNotIn(ZOT_TOKEN.encode(), request)
        self.assertNotIn(FORGEJO_TOKEN.encode(), request)
        self.assertNotIn(TOKEN.encode(), request)

    def test_unsigned_or_mismatched_evidence_does_not_consume_replay(self):
        """Even a matching supplied request requires FULL internal signed proof."""
        for result in (
            replace(evidence(), manifest_sha256="0" * 64),
            replace(evidence(), provenance_sha256="0" * 64),
            replace(evidence(), deployment_authorized=True),
            replace(evidence(), source=replace(
                evidence().source, source_commit="f" * 40,
            )),
        ):
            with self.subTest(result=result), self.assertRaises(BrokerUnavailableError):
                self.mocked.return_value = result
                broker, replay, transport = make_broker()
                call(broker)
                self.assertEqual(replay.calls, [])
                self.assertEqual(transport.requests, [])
        self.mocked.side_effect = RuntimeError("synthetic signer invalid")
        with self.assertRaises(BrokerUnavailableError):
            broker, replay, transport = make_broker()
            call(broker)
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_wrong_source_or_broken_canonical_request_stops_before_signer(self):
        """Malformed client request never drives network/signature work."""
        for raw in (
            canonical_bytes({**fixture(), "stage": "prod"}),
            canonical_bytes({**fixture(), "oci_repository": "omnilyzer/task013-release-canary"}),
            b"{}",
            canonical_bytes(fixture()) + b" ",
            b"x" * 16385,
        ):
            self.mocked.reset_mock()
            broker, replay, transport = make_broker()
            with self.subTest(raw=raw[:35]), self.assertRaises(BrokerRejectedError):
                call(broker, canonical_request=raw)
            self.mocked.assert_not_called()
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.requests, [])

    def test_explicit_oidc_rejection_is_not_signer_or_replay_acceptance(self):
        """Original OIDC denies before review, credential or replay."""
        from deployment.jwks import OIDCVerificationError
        broker, replay, transport = make_broker(verifier=Verifier(error=OIDCVerificationError("deny")))
        with self.assertRaises(BrokerRejectedError):
            call(broker)
        self.mocked.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_registry_credentials_wrong_audience_fail_before_replay(self):
        """Original independent Zot and Forgejo signed audience contracts."""
        for changes in (
            {"zot_token": FORGEJO_TOKEN},
            {"forgejo_token": ZOT_TOKEN},
            {"zot_token": "synthetic.invalid.jwt"},
            {"forgejo_token": "synthetic.invalid.jwt"},
        ):
            self.mocked.reset_mock()
            broker, replay, transport = make_broker()
            with self.subTest(changes=changes), self.assertRaises(
                (BrokerRejectedError, BrokerUnavailableError)
            ):
                call(broker, **changes)
            self.mocked.assert_not_called()
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.requests, [])

    def test_short_post_review_zot_ttl_never_consumes_replay(self):
        """Require a fresh full 180s pull budget plus 45s safety margin."""
        broker, replay, transport = make_broker()
        with patch("deployment.analytics_promotion_broker.time.time", return_value=NOW + 100):
            with self.assertRaises(BrokerUnavailableError):
                call(broker)
        self.mocked.assert_called_once()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_replay_refusal_consumes_no_transport_and_closes_fd(self):
        """A duplicate release attempt cannot reach product-specific executor."""
        from deployment.identity import ReplayError
        transport = PrivateAnalyticsTransport()
        broker, replay, _ = make_broker(
            replay=Replay(error=ReplayError("duplicate")), transport=transport,
        )
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(BrokerRejectedError):
            call(broker)
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(transport.requests, [])

    def test_failed_private_transport_is_unavailable_and_fd_closes(self):
        """No positive response or leaked FD after failed private receiver."""
        transport = PrivateAnalyticsTransport(error=True)
        broker, replay, _ = make_broker(transport=transport)
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(BrokerUnavailableError):
            call(broker)
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.requests), 1)

    def test_wrong_transport_or_unreviewed_source_constructor_fails_closed(self):
        """Canary-only sender cannot be mistaken for Analytics transport."""
        from deployment.tests.test_broker import Transport
        with self.assertRaises(TypeError):
            AnalyticsPrivatePromotionBroker(
                expected_workflow_sha=WORKFLOW_SHA,
                verifier=Verifier(),
                signed_review_handler=handler(),
                replay_guard=Replay(),
                analytics_transport=Transport(),
                reviewed_installed_source=EXPECTED,
                jwks_cache=StaticCache(KEY.public_key()),
            )
        for bad in (
            {**EXPECTED, "reviewed_compose_sha256": "bad"},
            {**EXPECTED, "extra": "unreviewed"},
        ):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                make_broker(expected=bad)

    def test_mutable_collaborator_swap_does_not_redirect_signed_review(self):
        """Operations captured at construction cannot be changed afterwards."""
        verifier = Verifier()
        broker, replay, transport = make_broker(verifier=verifier)
        verifier.verify = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("late verifier replacement")
        )
        self.assertEqual(call(broker), transport.response)
        with self.assertRaises(AttributeError):
            broker._transport = lambda *args: None

    def test_original_sqlite_replay_is_durable_across_broker_instances(self):
        """Reuse original SQLite durable JTI guard; never forward twice."""
        import tempfile
        from pathlib import Path
        from deployment.replay_sqlite import SQLiteReplayGuard

        with tempfile.TemporaryDirectory(prefix="m05-14-real-replay-") as folder:
            os.chmod(folder, 0o2770)
            path = Path(folder) / "replay.sqlite3"

            def guard():
                """Build the original Task014 durable replay implementation."""
                return SQLiteReplayGuard(
                    path, expected_directory_uid=os.getuid(),
                    expected_directory_gid=os.getgid(), current_time=lambda: NOW,
                )

            first = guard()
            first.initialize()
            transport = PrivateAnalyticsTransport()
            broker, _, _ = make_broker(replay=first, transport=transport)
            self.assertEqual(call(broker), transport.response)
            second_transport = PrivateAnalyticsTransport()
            second_broker, _, _ = make_broker(
                replay=guard(), transport=second_transport,
            )
            with self.assertRaises(BrokerRejectedError):
                call(second_broker)
            self.assertEqual(len(transport.requests), 1)
            self.assertEqual(second_transport.requests, [])

    def test_kernel_scm_rights_transfers_only_one_analytics_scoped_fd(self):
        """Actual Linux socketpair handoff tests token-free request framing."""
        import socket
        from deployment.private_registry_fd import (
            receive_sealed_header, send_sealed_header,
        )

        class KernelTransport:
            """Disposable exact one-FD receiver, not an installed executor."""

            received = 0

            def _send_analytics_private(self, request: bytes, *, credential_fd: int) -> bytes:
                parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                receiving = None
                try:
                    send_sealed_header(
                        parent, len(request).to_bytes(4, "big"), credential_fd,
                    )
                    parent.sendall(request)
                    header, receiving = receive_sealed_header(peer)
                    assert int.from_bytes(header, "big") == len(request)
                    received_request = peer.recv(len(request))
                    assert received_request == request
                    credential = read_sealed_credential(
                        receiving, canonical_request=received_request,
                        image=PINNED_IMAGE, now=NOW, product_id="analytics",
                    )
                    assert credential.token == ZOT_TOKEN
                    self.received += 1
                    return b'{"accepted":true}\n'
                finally:
                    if receiving is not None:
                        os.close(receiving)
                    parent.close()
                    peer.close()

        transport = KernelTransport()
        broker, replay, _ = make_broker(transport=transport)
        before = set(os.listdir("/proc/self/fd"))
        self.assertEqual(call(broker), b'{"accepted":true}\n')
        self.assertEqual(transport.received, 1)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_explicit_no_public_review_receipt_or_mock_parameter(self):
        """Caller cannot inject review_result or skip signed-verification call."""
        broker, replay, transport = make_broker()
        with self.assertRaises(TypeError):
            call(broker, review_result=evidence())
        self.mocked.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])


# Section: a full original OIDC/owner/signed-release-reviewed successor can
# reach only the already hard-rejecting UID991 manifest/OCI test probe.
class ReadOnlySuccessorProbeTransport(PrivateAnalyticsTransport):
    """Inspect the real Linux sealed successor FD; never claim promotion."""

    def __init__(self, *, positive_response: bool = False):
        super().__init__()
        self.checked: list[tuple[bytes, str]] = []
        self.positive_response = positive_response

    def _send_analytics_successor_private(
        self, request: bytes, *, credential_fd: int,
    ) -> bytes:
        """Read scoped memfd, simulate hard executor rejection afterward."""
        from deployment.private_registry_fd import _successor_request_image
        image = _successor_request_image(request)
        scoped = read_sealed_credential(
            credential_fd, canonical_request=request,
            image=image, product_id="analytics-successor", now=NOW,
        )
        assert scoped.token == ZOT_TOKEN
        # This new sealed schema-2 contains raw proofs that UID991 must
        # authenticate *itself*. No caller-created receipt grants a release.
        review = read_sealed_successor_review_credentials(
            credential_fd, canonical_request=request,
            image=image, now=NOW,
        )
        assert review.zot.token == ZOT_TOKEN
        assert review.github_oidc_token == TOKEN
        assert review.forgejo_token == FORGEJO_TOKEN
        assert image != PINNED_IMAGE
        self.checked.append((request, image))
        if self.positive_response:
            return b'{"accepted":true}\n'
        raise OSError("test-only UID991 read-only receiver denied")


# Section: positive reply fake proves original FD/replay parser gate only,
# NEVER a signed or installed release. Original HTTPS router remains read-only.
class SyntheticPositiveSuccessorTransport(ReadOnlySuccessorProbeTransport):
    """Validate the authentic test FD then project a canonical signed-reply shape."""

    def __init__(self):
        """Retain full sealed JWT verification from existing test receiver."""
        super().__init__(positive_response=True)

    def _send_analytics_successor_private(
        self, request: bytes, *, credential_fd: int,
    ) -> bytes:
        """Return an original response only after the real test FD is opened."""
        from deployment.executor import _build_success_response
        super()._send_analytics_successor_private(
            request, credential_fd=credential_fd,
        )
        return _build_success_response(hashlib.sha256(request).hexdigest())


# Section: first successor is a read-only ROOT broker review, not dispatch.
class AnalyticsFirstSuccessorBrokerReviewTests(unittest.TestCase):
    """Prove actual original OIDC+two signed reviews+live image integration."""

    @staticmethod
    def candidate():
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.tests.test_analytics_active_state_review import (
            observed, _active_state,
        )
        data, context = AnalyticsSuccessorRequestTests().candidate()
        live = _active_state(**observed(active_slot="blue"))
        return canonical_bytes(data), context, live

    @staticmethod
    def kwargs(raw: bytes):
        return {
            "compact_token": TOKEN, "zot_token": ZOT_TOKEN,
            "forgejo_token": FORGEJO_TOKEN, "canonical_request": raw,
            "received_at": NOW,
        }

    def test_root_broker_checks_original_and_successor_without_side_effects(self):
        from deployment.analytics_execution import AnalyticsSuccessorRequest
        raw, context, live = self.candidate()
        paths = (Path("/root/owner.json"), Path("/root/owner.json.sig"))
        broker, replay, transport = make_broker(owner_files=paths)
        before = set(os.listdir("/proc/self/fd"))
        with (
            patch("deployment.analytics_promotion_broker.time.time",
                  return_value=NOW),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()) as previous,
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])) as owner,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]) as successor,
            patch("deployment.analytics_active_state_review.inspect_analytics_active_state",
                  return_value=live) as inspector,
            patch("deployment.analytics_promotion_broker.create_sealed_credential") as seal,
        ):
            result = broker.review_first_successor_without_forwarding(
                **self.kwargs(raw),
            )
            self.assertIs(type(result), AnalyticsSuccessorRequest)
            self.assertEqual(result.canonical_bytes(), raw)
            self.assertEqual(result.rollback_reference["previous_digest"],
                             live.active_digest)
            previous.assert_called_once()
            owner.assert_called_once_with(*paths)
            successor.assert_called_once()
            inspector.assert_not_called()
            seal.assert_not_called()
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_wrong_oidc_request_owner_old_release_and_live_state_fail_closed(self):
        from deployment.jwks import OIDCVerificationError
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.analytics_active_state_review import AnalyticsActiveState
        raw, context, live = self.candidate()
        paths = (Path("/root/owner.json"), Path("/root/owner.json.sig"))
        broker, replay, transport = make_broker(owner_files=paths)

        with (
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release") as previous,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release") as successor,
        ):
            for bad in (
                b"{}", b"notjson",
                raw + b" ",
                raw.replace(
                    b'"product_id":"analytics"',
                    b'"product_id":"analytics","product_id":"analytics"',
                ),
                canonical_bytes({**AnalyticsSuccessorRequestTests().candidate()[0],
                                 "schema_version": 2}),
            ):
                with self.subTest(raw=bad[:25]), self.assertRaises(
                    BrokerRejectedError
                ):
                    broker.review_first_successor_without_forwarding(
                        **self.kwargs(bad),
                    )
            previous.assert_not_called()
            successor.assert_not_called()

        denied, _replay, _transport = make_broker(
            verifier=Verifier(error=OIDCVerificationError("synthetic denied")),
            owner_files=paths,
        )
        with patch(
            "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
        ) as previous, self.assertRaises(BrokerRejectedError):
            denied.review_first_successor_without_forwarding(**self.kwargs(raw))
            previous.assert_not_called()

        for previous_receipt in (
            replace(evidence(), image="oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:" + "f" * 64),
            replace(evidence(), deployment_authorized=True),
        ):
            with self.subTest(previous=previous_receipt), patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                return_value=previous_receipt,
            ), patch(
                "deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                return_value=(context["selected"], context["owner_approval"]),
            ), patch(
                "deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                return_value=context["signed_release"],
            ), patch(
                "deployment.analytics_active_state_review.inspect_analytics_active_state",
                return_value=live,
            ), self.assertRaises(BrokerUnavailableError):
                broker.review_first_successor_without_forwarding(**self.kwargs(raw))

        # Broker can cryptographically verify a first successor, but cannot
        # inspect Docker sockets. A caller-supplied previous-image hint other
        # than the original accepted 0.15.0 is rejected without invoking
        # an unprivileged Docker workaround.
        import json
        bad_request = json.loads(raw)
        bad_request["rollback_reference"]["previous_digest"] = "sha256:" + "a" * 64
        with (
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()),
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]),
            patch("deployment.analytics_active_state_review.inspect_analytics_active_state") as inspector,
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.review_first_successor_without_forwarding(
                **self.kwargs(canonical_bytes(bad_request)),
            )
        inspector.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_verified_owner_oidc_and_signed_successor_fd_probes_but_never_go(self):
        """Broker securely seals exact next image; UID991 denial cannot GO."""
        raw, context, _live = self.candidate()
        paths = (Path("/root/owner.json"), Path("/root/owner.json.sig"))
        transport = ReadOnlySuccessorProbeTransport()
        broker, replay, _ = make_broker(owner_files=paths, transport=transport)
        before = set(os.listdir("/proc/self/fd"))
        with (
            patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()) as original,
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])) as owner,
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]) as signed,
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.forward_verified_first_successor_probe_without_deployment(
                **self.kwargs(raw),
            )
        self.assertEqual(len(transport.checked), 1)
        self.assertEqual(transport.checked[0], (
            raw, context["signed_release"].image,
        ))
        self.assertNotIn(ZOT_TOKEN.encode(), raw)
        self.assertEqual(len(owner.call_args_list), 1)
        original.assert_called_once()
        signed.assert_called_once()
        self.assertEqual(replay.calls, [])
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

        # Even a forged 'accepted' reply is not returned as promotion GO.
        positive = ReadOnlySuccessorProbeTransport(positive_response=True)
        positive_broker, replay2, _ = make_broker(owner_files=paths, transport=positive)
        with (
            patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()),
            patch("deployment.analytics_registry_review_composition.load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]),
            self.assertRaises(BrokerUnavailableError),
        ):
            positive_broker.forward_verified_first_successor_probe_without_deployment(
                **self.kwargs(raw),
            )
        self.assertEqual(len(positive.checked), 1)
        self.assertEqual(replay2.calls, [])
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_successor_probe_missing_sender_or_owner_never_opens_fd(self):
        """Neither a missing trusted owner nor missing exact sender falls back."""
        raw, context, _ = self.candidate()
        broker, replay, legacy = make_broker()
        with patch(
            "deployment.analytics_promotion_broker.create_sealed_credential"
        ) as sealed, self.assertRaises(BrokerUnavailableError):
            broker.forward_verified_first_successor_probe_without_deployment(
                **self.kwargs(raw),
            )
        sealed.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(legacy.requests, [])
        transport = ReadOnlySuccessorProbeTransport()
        denied, replay2, _ = make_broker(transport=transport)
        with (
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release") as signed,
            patch("deployment.analytics_promotion_broker.create_sealed_credential") as sealed,
            self.assertRaises(BrokerUnavailableError),
        ):
            denied.forward_verified_first_successor_probe_without_deployment(
                **self.kwargs(raw),
            )
        signed.assert_not_called()
        sealed.assert_not_called()
        self.assertEqual(transport.checked, [])
        self.assertEqual(replay2.calls, [])

    def test_source_only_first_successor_consumes_original_jti_and_checks_reply(self):
        """Original full signatures -> 3 signed JWTs -> replay -> canonical reply."""
        from deployment.executor import parse_canonical_response
        raw, context, _ = self.candidate()
        transport = SyntheticPositiveSuccessorTransport()
        broker, replay, _ = make_broker(
            transport=transport,
            owner_files=(Path("/root/owner.json"), Path("/root/owner.json.sig")),
        )
        before = set(os.listdir("/proc/self/fd"))
        with (
            patch("deployment.analytics_promotion_broker.time.time",
                  return_value=NOW),
            patch(
                "deployment.analytics_registry_review_composition."
                "acquire_and_review_analytics_release",
                return_value=evidence(),
            ) as old_signed,
            patch(
                "deployment.analytics_registry_review_composition."
                "load_and_verify_owner_signed_source",
                return_value=(context["selected"], context["owner_approval"]),
            ) as owner,
            patch(
                "deployment.analytics_registry_review_composition."
                "acquire_and_review_owner_approved_analytics_release",
                return_value=context["signed_release"],
            ) as new_signed,
        ):
            result = broker.authorize_and_forward_first_successor(
                **self.kwargs(raw),
            )
        self.assertEqual(
            parse_canonical_response(result).executor_request_sha256,
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(transport.checked[0][0], raw)
        self.assertEqual(len(transport.checked), 1)
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))
        old_signed.assert_called_once()
        owner.assert_called_once()
        new_signed.assert_called_once()

    def test_source_only_uninstalled_successor_cannot_accept_fake_reply(self):
        """Even a forged positive JSON response consumes JTI, never reports GO."""
        raw, context, _ = self.candidate()
        transport = ReadOnlySuccessorProbeTransport(positive_response=True)
        broker, replay, _ = make_broker(
            transport=transport,
            owner_files=(Path("/root/owner.json"), Path("/root/owner.json.sig")),
        )
        with (
            patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_analytics_release", return_value=evidence()),
            patch("deployment.analytics_registry_review_composition."
                  "load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])),
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]),
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.authorize_and_forward_first_successor(**self.kwargs(raw))
        self.assertEqual(len(transport.checked), 1)
        self.assertEqual(len(replay.calls), 1)

    def test_source_only_successor_signer_denial_never_consumes_or_sends(self):
        """No signature, owner selection or 0.15.0 proof means no original JTI."""
        raw, context, _ = self.candidate()
        transport = SyntheticPositiveSuccessorTransport()
        broker, replay, _ = make_broker(
            transport=transport, owner_files=None,
        )
        with (
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_analytics_release", return_value=evidence()),
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_owner_approved_analytics_release") as review,
            self.assertRaises(BrokerUnavailableError),
        ):
            broker.authorize_and_forward_first_successor(**self.kwargs(raw))
        review.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.checked, [])

    def test_source_only_successor_requires_unique_original_replay_record(self):
        """Replay refusal must close FD without entering future UID991 socket."""
        raw, context, _ = self.candidate()
        transport = SyntheticPositiveSuccessorTransport()

        class RejectDuplicateReplay(Replay):
            """Mirror the genuine SQLite guard's one-use JTI contract."""

            def consume(self, jti, *, expires_at, request_hash,
                        run_id, run_attempt):
                """Reject a previously consumed JTI, never send it twice."""
                from deployment.identity import ReplayError
                if self.calls:
                    raise ReplayError("synthetic original durable replay denial")
                return super().consume(
                    jti, expires_at=expires_at, request_hash=request_hash,
                    run_id=run_id, run_attempt=run_attempt,
                )

        replay = RejectDuplicateReplay()
        broker, replay, _ = make_broker(
            replay=replay, transport=transport,
            owner_files=(Path("/root/owner.json"), Path("/root/owner.json.sig")),
        )
        before = set(os.listdir("/proc/self/fd"))
        with (
            patch("deployment.analytics_promotion_broker.time.time", return_value=NOW),
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_analytics_release", return_value=evidence()),
            patch("deployment.analytics_registry_review_composition."
                  "load_and_verify_owner_signed_source",
                  return_value=(context["selected"], context["owner_approval"])),
            patch("deployment.analytics_registry_review_composition."
                  "acquire_and_review_owner_approved_analytics_release",
                  return_value=context["signed_release"]),
        ):
            broker.authorize_and_forward_first_successor(**self.kwargs(raw))
            with self.assertRaises(BrokerRejectedError):
                broker.authorize_and_forward_first_successor(**self.kwargs(raw))
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))
        self.assertEqual(len(transport.checked), 1)

    def test_no_future_transport_never_consumes_replay(self):
        """Original V1-only transport cannot be substituted as V2 listener."""
        raw, _, _ = self.candidate()
        broker, replay, transport = make_broker()
        with self.assertRaises(BrokerUnavailableError):
            broker.authorize_and_forward_first_successor(**self.kwargs(raw))
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])

    def test_missing_root_owner_key_has_no_registry_or_executor_side_effect(self):
        raw, _context, _live = self.candidate()
        broker, replay, transport = make_broker()
        with (
            patch("deployment.analytics_registry_review_composition.acquire_and_review_analytics_release",
                  return_value=evidence()),
            patch("deployment.analytics_registry_review_composition.acquire_and_review_owner_approved_analytics_release") as successor,
            patch("deployment.analytics_promotion_broker.create_sealed_credential") as sealed,
        ):
            with self.assertRaises(BrokerUnavailableError):
                broker.review_first_successor_without_forwarding(**self.kwargs(raw))
            successor.assert_not_called()
            sealed.assert_not_called()
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()

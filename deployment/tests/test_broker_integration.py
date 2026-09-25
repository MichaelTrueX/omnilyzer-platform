"""Deterministic C32C promotion-to-executor contract tests; no live I/O."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import unittest

from deployment.broker import BrokerRejectedError, BrokerUnavailableError, RestrictedDeploymentBroker
from deployment.broker_integration import InertDevPromotionHandler, MAX_PROMOTION_REQUEST_BYTES
from deployment.execution import ExecutorRequest, IngressReference, RuntimeConfigurationReference, parse_canonical_request
from deployment.identity import ReplayError, ReplayUnavailableError, authorize_verified_github_oidc
from deployment.jwks import OIDCVerificationError, OIDCVerificationUnavailable
from deployment.tests.test_broker import Replay, Transport, Verifier
from deployment.tests.test_execution import ingress_reference, runtime_reference
from deployment.tests.test_execution import valid_request
from deployment.tests.test_identity import NOW, valid_claims
from deployment.tests.test_release_consumer import Signatures, setup


ROOT = Path(__file__).resolve().parents[2]
TOKEN = "exact.compact.token"


def fixture(*, verifier=None, replay=None, transport=None, signatures=None, runtime=None, ingress=None):
    promotion, _, zot, forgejo, zot_factory, forgejo_factory = setup()
    selected_verifier = verifier or Verifier()
    selected_replay = replay or Replay()
    selected_transport = transport or Transport()
    handler = InertDevPromotionHandler(
        verifier=selected_verifier, replay_guard=selected_replay,
        transport=selected_transport, zot=zot, forgejo=forgejo,
        signatures=signatures or Signatures(),
        runtime=runtime or RuntimeConfigurationReference.from_dict(runtime_reference()),
        ingress=ingress or IngressReference.from_dict(ingress_reference()),
    )
    return handler, promotion, selected_verifier, selected_replay, selected_transport, zot_factory, forgejo_factory


def invoke(handler, promotion, *, token=TOKEN, raw=None):
    return handler.handle(
        compact_token=token,
        promotion_request=promotion.canonical_bytes() if raw is None else raw,
        received_at=NOW,
    )


class IntegrationTests(unittest.TestCase):
    def test_construction_is_inert(self):
        _, _, verifier, replay, transport, zot, forgejo = fixture()
        self.assertEqual(verifier.calls, [])
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])
        self.assertEqual(zot.calls, [])
        self.assertEqual(forgejo.calls, [])

    def test_exact_verified_flow_and_stable_bytes(self):
        handler, promotion, verifier, replay, transport, zot, forgejo = fixture()
        result = invoke(handler, promotion)
        self.assertEqual(result, transport.response)
        self.assertEqual(verifier.calls, [(TOKEN, NOW)])
        self.assertEqual(len(zot.calls), 2)
        self.assertEqual(len(forgejo.calls), 2)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(len(transport.calls), 1)
        raw = transport.calls[0]
        request = parse_canonical_request(raw)
        self.assertEqual(request.promotion_request_sha256, promotion.sha256())
        self.assertEqual(request.github_workflow_sha, authorize_verified_github_oidc(valid_claims(), received_at=NOW).workflow_sha)
        self.assertEqual(replay.calls[0]["request_hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(replay.calls[0]["jti"], request.oidc_jti)
        other, _, _, other_replay, other_transport, _, _ = fixture()
        invoke(other, promotion)
        self.assertEqual(other_transport.calls, [raw])
        self.assertEqual(other_replay.calls[0]["request_hash"], replay.calls[0]["request_hash"])

    def test_malformed_or_oversized_input_never_reaches_verifier(self):
        handler, promotion, verifier, replay, transport, _, _ = fixture()
        raw = promotion.canonical_bytes()
        cases = (
            b"", b"[]\n", raw[:-1], b" " + raw, raw.replace(b'"schema_version":1', b'"schema_version":true'),
            raw.replace(b'"schema_version":1', b'"unknown":0,"schema_version":1'),
            raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
            b"x" * (MAX_PROMOTION_REQUEST_BYTES + 1),
        )
        for value in cases:
            with self.subTest(value=value[:40]), self.assertRaises(BrokerRejectedError):
                invoke(handler, promotion, raw=value)
        for token in ("", "é", "x" * (16 * 1024 + 1)):
            with self.subTest(token=token[:10]), self.assertRaises(BrokerRejectedError):
                invoke(handler, promotion, token=token)
        self.assertEqual(verifier.calls, [])
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])

    def test_oidc_rejection_unavailability_and_altered_identity(self):
        for error, expected in ((OIDCVerificationError("token"), BrokerRejectedError),
                                (OIDCVerificationUnavailable("network"), BrokerUnavailableError)):
            handler, promotion, _, replay, transport, _, _ = fixture(verifier=Verifier(error=error))
            with self.assertRaises(expected):
                invoke(handler, promotion)
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])
        identity = authorize_verified_github_oidc(valid_claims(), received_at=NOW)
        for altered in (replace(identity, repository_id=1), replace(identity, workflow_ref="other")):
            handler, promotion, _, replay, transport, _, _ = fixture(verifier=Verifier(result=altered))
            with self.assertRaises(BrokerRejectedError):
                invoke(handler, promotion)
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])

    def test_release_checks_fail_before_replay(self):
        class BadSignature:
            def verify(self, *args):
                raise ValueError("secret-credential-text")

        handler, promotion, _, replay, transport, _, _ = fixture(signatures=BadSignature())
        with self.assertRaises(BrokerUnavailableError) as raised:
            invoke(handler, promotion)
        self.assertNotIn("secret-credential-text", str(raised.exception))
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])
        handler, promotion, _, replay, transport, _, _ = fixture()
        for name, value in (("target_stage", "prod"), ("oci_repository", "other/repository"),
                            ("manifest_digest", "sha256:" + "0" * 64),
                            ("release_manifest_sha256", "0" * 64),
                            ("originating_release_run_id", 1)):
            changed = replace(promotion, **{name: value})
            with self.subTest(name=name), self.assertRaises((BrokerRejectedError, BrokerUnavailableError)):
                invoke(handler, changed)
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])

    def test_altered_runtime_or_ingress_reference_fails_before_replay(self):
        runtime = RuntimeConfigurationReference.from_dict(runtime_reference())
        ingress = IngressReference.from_dict(ingress_reference())
        for options in (
            {"runtime": replace(runtime, reviewed_commit="f" * 40)},
            {"ingress": replace(ingress, reviewed_commit="f" * 40)},
        ):
            handler, promotion, _, replay, transport, _, _ = fixture(**options)
            with self.assertRaises(BrokerUnavailableError):
                invoke(handler, promotion)
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])

    def test_builder_cannot_substitute_request_identity_or_bytes(self):
        class SubstitutingBuilder:
            def build(self, promotion, identity, *, received_at):
                value = valid_request()
                value["github_run_id"] += 1
                return ExecutorRequest.from_dict(value)

        verifier, replay, transport = Verifier(), Replay(), Transport()
        broker = RestrictedDeploymentBroker(
            verifier=verifier, replay_guard=replay, transport=transport,
            request_builder=SubstitutingBuilder(),
        )
        with self.assertRaises(BrokerRejectedError):
            broker.authorize_promotion_and_forward(
                compact_token=TOKEN, promotion=object(), received_at=NOW,
            )
        self.assertEqual(verifier.calls, [(TOKEN, NOW)])
        self.assertEqual(replay.calls, [])
        self.assertEqual(transport.calls, [])

    def test_replay_and_transport_failures_never_retry_or_reset(self):
        for error, expected in ((ReplayError("duplicate"), BrokerRejectedError),
                                (ReplayUnavailableError("storage"), BrokerUnavailableError),
                                (RuntimeError("storage"), BrokerUnavailableError)):
            replay = Replay(error=error)
            handler, promotion, _, _, transport, _, _ = fixture(replay=replay)
            with self.assertRaises(expected):
                invoke(handler, promotion)
            self.assertEqual(len(replay.calls), 1)
            self.assertEqual(transport.calls, [])
        class InvalidReplay(Replay):
            def consume(self, jti, *, expires_at, request_hash, run_id, run_attempt):
                super().consume(
                    jti, expires_at=expires_at, request_hash=request_hash,
                    run_id=run_id, run_attempt=run_attempt,
                )
                return False

        replay = InvalidReplay()
        handler, promotion, _, _, transport, _, _ = fixture(replay=replay)
        with self.assertRaises(BrokerUnavailableError):
            invoke(handler, promotion)
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(transport.calls, [])
        for transport in (Transport(error=OSError("socket")), Transport(response="bad"),
                          Transport(response=b"x" * (64 * 1024 + 1))):
            handler, promotion, _, replay, _, _, _ = fixture(transport=transport)
            with self.assertRaises(BrokerUnavailableError):
                invoke(handler, promotion)
            self.assertEqual(len(replay.calls), 1)
            self.assertEqual(len(transport.calls), 1)
            self.assertFalse(hasattr(replay, "reset"))

    def test_inert_repository_contract(self):
        source = (ROOT / "deployment/broker_integration.py").read_text()
        broker_source = (ROOT / "deployment/broker.py").read_text()
        for forbidden in ("subprocess", "systemctl", "socket.socket", ".bind(", ".listen(",
                          ".start(", "docker.sock", "write_bytes", "write_text", "open("):
            self.assertNotIn(forbidden, source.lower())
            self.assertNotIn(forbidden, broker_source.lower())
        workflow = (ROOT / ".github/workflows/platform-promote.yml").read_text()
        for forbidden in ("id-token: write", "environment: task014-dev", "deploy-dev.omnilyzer.ai",
                          "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            self.assertNotIn(forbidden, workflow)
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9_-]*):$", workflow.split("\njobs:\n", 1)[1], re.MULTILINE), ["gate"])
        self.assertEqual(set(json.loads((ROOT / "deployment/environments/dev.json").read_text())["activation"]),
                         {"deployment_enabled", "verified_at"})
        self.assertIs(json.loads((ROOT / "deployment/environments/dev.json").read_text())["activation"]["deployment_enabled"], False)
        self.assertIn("deployment/broker_integration.py", [item.repository_path for item in __import__(
            "deployment.application_source_set", fromlist=["DevApplicationSourceSet"]
        ).DevApplicationSourceSet().files])


if __name__ == "__main__":
    unittest.main()

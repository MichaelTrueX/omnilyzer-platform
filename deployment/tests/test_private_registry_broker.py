"""File: deployment/tests/test_private_registry_broker.py

Purpose: Verify the opt-in broker forwards exactly one previously validated,
request-bound, ephemeral Zot-read FD without putting a JWT in the canonical
request, replay record, or transport arguments. Related: deployment/broker.py,
deployment/private_registry_fd.py, deployment/unix_transport.py, and
deployment/tests/test_request_scoped_registry_integration.py.

Sections: synthetic verified context; pre-replay rejection; success/failure
credential cleanup. Nothing contacts live GitHub, Zot or the executor.
"""

from __future__ import annotations

import os
import time
import unittest

from deployment.broker import (
    BrokerUnavailableError, RestrictedDeploymentBroker,
)
from deployment.execution import ExecutorRequest
from deployment.private_registry_fd import read_sealed_credential
from deployment.tests.test_broker import Replay, Verifier, identity
from deployment.tests.test_execution import valid_request
from deployment.tests.test_identity import NOW, WORKFLOW_SHA

JWT = "synthetic.issue-specific.read-only.Zot.JWT"
REQUEST = ExecutorRequest.from_dict(valid_request())


class VerifiedZot:
    """Immutable-like test result representing already-verified broker authority."""

    def __init__(self, token: str, expires_at: int) -> None:
        self.token = token
        self.expires_at = expires_at


class VerifiedContext:
    """Test credential provider; not a substitute for a real JWT verifier."""

    def __init__(self, token: str, expires_at: int) -> None:
        self.value = VerifiedZot(token, expires_at)

    def zot_read_credential(self) -> VerifiedZot:
        """Expose a synthetic short-lived Zot credential."""
        return self.value


class ContextVerifier:
    """Pretend the real verifier succeeded, for isolated broker sequencing."""

    def __init__(self, context: VerifiedContext) -> None:
        self.context = context

    def verify(self, deployment_identity: object, promotion_context: object,
               *, received_at: int) -> VerifiedContext:
        """Return a private provider with no socket or registry I/O."""
        assert deployment_identity == identity()
        assert received_at == NOW
        return self.context


class RequestBuilder:
    """Construct the existing exact token-free canonical request."""

    def build(self, promotion: object, deployment_identity: object,
              verified_context: object, *, received_at: int) -> ExecutorRequest:
        """Only a dummy verified context can build the synthetic request."""
        assert type(verified_context) is VerifiedContext
        assert received_at == NOW
        return REQUEST


class PrivateTransport:
    """Consume and check sealed FD before returning a bounded response."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[bytes] = []
        self.received_fd: int | None = None

    def send(self, canonical_request: bytes) -> bytes:
        """The legacy transport must not be invoked for private credentials."""
        raise AssertionError("private transport incorrectly used legacy send")

    def _send_private(self, canonical_request: bytes, *, credential_fd: int) -> bytes:
        """Validate request association but do not receive actual socket bytes."""
        self.received_fd = credential_fd
        self.calls.append(canonical_request)
        credential = read_sealed_credential(
            credential_fd,
            canonical_request=canonical_request,
            image=REQUEST.exact_image_reference,
        )
        assert credential.token == JWT
        assert JWT.encode() not in canonical_request
        if self.fail:
            raise OSError("synthetic transport unavailable")
        return b"synthetic-executor-response"


class PrivateRegistryBrokerTests(unittest.TestCase):
    """A registry rejection must happen before replay or any socket send."""

    def compose(self, *, token: str = JWT, expires_at: int | None = None,
                fail: bool = False) -> tuple[RestrictedDeploymentBroker, Replay, PrivateTransport]:
        """Create one isolated synthetic credential-aware broker graph."""
        context = VerifiedContext(
            token, int(time.time()) + 100 if expires_at is None else expires_at,
        )
        replay = Replay()
        transport = PrivateTransport(fail=fail)
        broker = RestrictedDeploymentBroker(
            expected_workflow_sha=WORKFLOW_SHA,
            verifier=Verifier(),
            replay_guard=replay,
            transport=transport,
            request_builder=RequestBuilder(),
            promotion_context_verifier=ContextVerifier(context),
            private_registry_transport=True,
        )
        return broker, replay, transport

    def send(self, broker: RestrictedDeploymentBroker) -> bytes:
        """Call the existing broker method with synthetic promotion authority."""
        return broker.authorize_promotion_and_forward(
            compact_token="synthetic-authenticated-oidc",
            promotion=object(), promotion_context=object(),
            received_at=NOW,
        )

    def test_valid_private_send_preserves_request_and_closes_fd(self) -> None:
        """Broker seals the token, consumes replay once, and closes local fd."""
        broker, replay, transport = self.compose()
        self.assertEqual(self.send(broker), b"synthetic-executor-response")
        self.assertEqual(len(replay.calls), 1)
        self.assertEqual(transport.calls, [REQUEST.canonical_bytes()])
        self.assertIsNotNone(transport.received_fd)
        with self.assertRaises(OSError):
            os.fstat(transport.received_fd)
        self.assertNotIn(JWT.encode(), transport.calls[0])
        self.assertNotIn(JWT, repr(replay.calls))

    def test_invalid_token_expires_before_replay(self) -> None:
        """Rejected authority cannot consume a GitHub replay ID."""
        for expiry in (int(time.time()) - 1, int(time.time()) + 301):
            broker, replay, transport = self.compose(expires_at=expiry)
            with self.assertRaises(BrokerUnavailableError):
                self.send(broker)
            self.assertEqual(replay.calls, [])
            self.assertEqual(transport.calls, [])

    def test_private_transport_failure_closes_fd_without_replay_reset(self) -> None:
        """A network failure consumes replay at most once and never leaks JWT."""
        broker, replay, transport = self.compose(fail=True)
        with self.assertRaises(BrokerUnavailableError) as error:
            self.send(broker)
        self.assertEqual(len(replay.calls), 1)
        self.assertNotIn(JWT, str(error.exception))
        self.assertIsNotNone(transport.received_fd)
        with self.assertRaises(OSError):
            os.fstat(transport.received_fd)

    def test_private_mode_requires_verified_builder(self) -> None:
        """The opt-in private mode cannot bypass credential verification."""
        with self.assertRaises(TypeError):
            RestrictedDeploymentBroker(
                expected_workflow_sha=WORKFLOW_SHA, verifier=Verifier(),
                replay_guard=Replay(), transport=PrivateTransport(),
                private_registry_transport=True,
            )


if __name__ == "__main__":
    unittest.main()

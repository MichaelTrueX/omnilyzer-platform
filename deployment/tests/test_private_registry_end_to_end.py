"""File: deployment/tests/test_private_registry_end_to_end.py

Purpose: Run a complete synthetic broker -> Unix SCM_RIGHTS -> executor
preflight -> replay -> deployment exchange with real local kernel sockets.
Related: deployment/broker.py, deployment/unix_transport.py,
deployment/executor_server.py, deployment/executor.py,
deployment/private_registry_fd.py and deployment/private_registry_pull.py.

Sections: complete local protocol fixture; exact request/credential assertions.
Never contacts live registry, Docker, GitHub, or a privileged host.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from deployment.broker import RestrictedDeploymentBroker
from deployment.executor import RestrictedPrivilegedExecutor, parse_canonical_response
from deployment.executor_server import UnixExecutorConnectionHandler
from deployment.private_registry_fd import read_sealed_credential
from deployment.private_registry_pull import current_private_zot_request
from deployment.tests.test_broker import Replay as BrokerReplay, Verifier
from deployment.tests.test_executor import Replay as ExecutorReplay
from deployment.tests.test_identity import NOW, WORKFLOW_SHA
from deployment.tests.test_private_registry_broker import (
    JWT, REQUEST, ContextVerifier, RequestBuilder, VerifiedContext,
)
from deployment.tests.test_unix_transport import constructed


class ManifestPreflight:
    """A synthetic successful verified registry lookup with no network I/O."""

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def preflight_private_registry(self, canonical_request: bytes,
                                   credential_fd: int) -> None:
        """Validate the original signed broker-bound sealed read capability."""
        self.events.append("registry-manifest-authorized")
        assert canonical_request == REQUEST.canonical_bytes()
        credential = read_sealed_credential(
            credential_fd,
            canonical_request=canonical_request,
            image=REQUEST.exact_image_reference,
        )
        assert credential.token == JWT


class BoundDeployment:
    """One synthetic deployment verifying the context is still request-local."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0

    def deploy(self, request: object) -> None:
        """Act only after replay begins with the exact token-free request."""
        self.events.append("deploy")
        self.calls += 1
        assert request == REQUEST
        scoped = current_private_zot_request()
        assert scoped is not None
        fd, request_bytes = scoped
        assert request_bytes == REQUEST.canonical_bytes()
        authority = read_sealed_credential(
            fd, canonical_request=request_bytes,
            image=REQUEST.exact_image_reference,
        )
        assert authority.token == JWT
        assert JWT.encode() not in request_bytes


class CompletePrivateTransportTests(unittest.TestCase):
    """Use real peer identities and kernel ancillary descriptor passing."""

    def test_full_private_registry_promotion_is_bound_and_nonpersistent(self) -> None:
        """Credential check precedes replay and request stays canonical."""
        with tempfile.TemporaryDirectory(prefix="task014-private-e2e-") as root:
            path = str(Path(root) / "executor.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            os.chmod(path, 0o660)
            listener.listen(1)
            listener.settimeout(4)

            events: list[str] = []
            executor_replay = ExecutorReplay(events)
            operation = BoundDeployment(events)
            privileged = RestrictedPrivilegedExecutor(
                replay_guard=executor_replay, operation=operation,
                private_registry_preflight=ManifestPreflight(events),
            )
            receiver = UnixExecutorConnectionHandler(
                executor=privileged,
                expected_broker_uid=os.getuid(),
                expected_broker_gid=os.getgid(),
                private_registry_transfer=True,
            )
            errors: list[BaseException] = []

            def serve() -> None:
                """Serve exactly one socket connection in a synthetic thread."""
                try:
                    client, _ = listener.accept()
                    receiver.handle(client)
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            broker_replay = BrokerReplay()
            broker = RestrictedDeploymentBroker(
                expected_workflow_sha=WORKFLOW_SHA,
                verifier=Verifier(),
                replay_guard=broker_replay,
                transport=constructed(path),
                request_builder=RequestBuilder(),
                promotion_context_verifier=ContextVerifier(
                    VerifiedContext(JWT, int(time.time()) + 120)
                ),
                private_registry_transport=True,
            )
            try:
                response = broker.authorize_promotion_and_forward(
                    compact_token="synthetic-deployment-identity",
                    promotion=object(), promotion_context=object(),
                    received_at=NOW,
                )
                parsed = parse_canonical_response(response)
                self.assertEqual(
                    parsed.executor_request_sha256,
                    __import__("hashlib").sha256(REQUEST.canonical_bytes()).hexdigest(),
                )
            finally:
                worker.join(5)
                listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(
                events, [
                    "registry-manifest-authorized",
                    "begin_execution", "deploy", "finish_execution",
                ],
            )
            self.assertEqual(operation.calls, 1)
            self.assertEqual(len(broker_replay.calls), 1)
            self.assertEqual(len(executor_replay.begin_calls), 1)
            self.assertEqual(len(executor_replay.finish_calls), 1)
            self.assertIsNone(current_private_zot_request())


if __name__ == "__main__":
    unittest.main()

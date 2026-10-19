"""File: deployment/tests/test_private_executor_receiver.py

Purpose: Test optional Linux SCM_RIGHTS receiver in the pre-existing
peer-authenticated executor connection handler. This file never uses live
Docker, registry, GitHub or replay records.
Related: deployment/executor_server.py, deployment/private_registry_fd.py,
deployment/tests/test_executor_server.py, deployment/executor.py.

Sections: valid one-FD exchange; missing, expired, wrong-request and multiple
FD rejection before any executor invocation; source FD leak protections.
"""

from __future__ import annotations

from array import array
import hashlib
import os
import socket
import struct
import time
import unittest

from deployment.execution import ExecutorRequest
from deployment.executor import ExecutorResponse
from deployment.executor_server import (
    ExecutorConnectionUnavailableError, UnixExecutorConnectionHandler,
)
from deployment.private_registry_fd import (
    create_sealed_credential, send_sealed_header,
)
from deployment.tests.test_execution import valid_request

REQUEST = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
IMAGE = ExecutorRequest.from_dict(valid_request()).exact_image_reference
TOKEN = "synthetic.only-privileged-executor-test-credential"
RESPONSE = ExecutorResponse(
    hashlib.sha256(REQUEST).hexdigest()
).canonical_bytes()


class PrivateExecutor:
    """Synthetic, carefully shaped executor verifying the in-band FD."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []
        self.received_fd: int | None = None

    def execute_private(self, canonical_request: bytes, *,
                        credential_fd: int) -> bytes:
        """The receiver has already validated the sealed FD before this call."""
        self.calls.append(canonical_request)
        self.received_fd = credential_fd
        return RESPONSE


class PrivateExecutorReceiverTests(unittest.TestCase):
    """Use real AF_UNIX connected socketpairs with kernel peer credentials."""

    def make_pair(self) -> tuple[socket.socket, socket.socket]:
        """Create an isolated local stream pair without a filesystem socket."""
        return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    def handler(self, executor: PrivateExecutor) -> UnixExecutorConnectionHandler:
        """Enable only the reviewed private receiver under local UID/GID."""
        return UnixExecutorConnectionHandler(
            executor=executor,
            expected_broker_uid=os.getuid(),
            expected_broker_gid=os.getgid(),
            private_registry_transfer=True,
        )

    def make_fd(self, *, request: bytes = REQUEST, expires_at: int | None = None) -> int:
        """Create one synthetic sealed credential for a specific request."""
        now = int(time.time())
        return create_sealed_credential(
            TOKEN, expires_at=now + 90 if expires_at is None else expires_at,
            image=IMAGE, canonical_request=request, now=now,
        )

    def test_exact_fd_and_canonical_request_reaches_private_executor(self) -> None:
        """A valid sealed FD passes peer checks; executor invocation is exact."""
        client, connection = self.make_pair()
        fd = self.make_fd()
        executor = PrivateExecutor()
        try:
            send_sealed_header(client, len(REQUEST).to_bytes(4, "big"), fd)
            client.sendall(REQUEST)
            client.shutdown(socket.SHUT_WR)
            self.assertIsNone(self.handler(executor).handle(connection))
            self.assertEqual(executor.calls, [REQUEST])
            self.assertEqual(client.recv(4), len(RESPONSE).to_bytes(4, "big"))
            self.assertEqual(client.recv(len(RESPONSE)), RESPONSE)
            self.assertEqual(client.recv(1), b"")
            self.assertIsNotNone(executor.received_fd)
            with self.assertRaises(OSError):
                os.fstat(executor.received_fd)
        finally:
            os.close(fd)
            client.close()
            connection.close()

    def test_missing_fd_rejected_before_executor(self) -> None:
        """Legacy request framing cannot bypass credential-required mode."""
        client, connection = self.make_pair()
        executor = PrivateExecutor()
        try:
            client.sendall(len(REQUEST).to_bytes(4, "big") + REQUEST)
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(ExecutorConnectionUnavailableError):
                self.handler(executor).handle(connection)
            self.assertEqual(executor.calls, [])
        finally:
            client.close()
            connection.close()

    def test_wrong_request_binding_rejected_before_executor(self) -> None:
        """A valid FD for one request cannot authorize different canonical bytes."""
        client, connection = self.make_pair()
        fd = self.make_fd()
        executor = PrivateExecutor()
        bad = REQUEST + b" "
        try:
            send_sealed_header(client, len(bad).to_bytes(4, "big"), fd)
            client.sendall(bad)
            client.shutdown(socket.SHUT_WR)
            with self.assertRaises(ExecutorConnectionUnavailableError):
                self.handler(executor).handle(connection)
            self.assertEqual(executor.calls, [])
        finally:
            os.close(fd)
            client.close()
            connection.close()

    def test_expired_credential_rejected_before_executor(self) -> None:
        """A recipient does not accept a short-lived FD after its expiry."""
        client, connection = self.make_pair()
        fd = self.make_fd(expires_at=int(time.time()) + 1)
        executor = PrivateExecutor()
        try:
            send_sealed_header(client, len(REQUEST).to_bytes(4, "big"), fd)
            client.sendall(REQUEST)
            client.shutdown(socket.SHUT_WR)
            time.sleep(1.2)
            with self.assertRaises(ExecutorConnectionUnavailableError):
                self.handler(executor).handle(connection)
            self.assertEqual(executor.calls, [])
        finally:
            os.close(fd)
            client.close()
            connection.close()

    def test_multiple_fd_rejected_before_executor_and_not_leaked(self) -> None:
        """Refuse injected ancillary descriptors even with a valid request."""
        client, connection = self.make_pair()
        fd = self.make_fd()
        extra = os.dup(fd)
        executor = PrivateExecutor()
        try:
            rights = array("i", (fd, extra))
            client.sendmsg(
                [len(REQUEST).to_bytes(4, "big")],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())],
            )
            client.sendall(REQUEST)
            client.shutdown(socket.SHUT_WR)
            before = len(os.listdir("/proc/self/fd"))
            with self.assertRaises(ExecutorConnectionUnavailableError):
                self.handler(executor).handle(connection)
            after = len(os.listdir("/proc/self/fd"))
            self.assertEqual(before - 1, after)  # Handler closes connection.
            self.assertEqual(executor.calls, [])
        finally:
            os.close(extra)
            os.close(fd)
            client.close()
            connection.close()

    def test_private_mode_rejects_executor_missing_explicit_private_method(self) -> None:
        """Cannot accidentally invoke the old, replay-consuming execute() path."""
        from deployment.tests.test_executor_server import Executor
        with self.assertRaises(TypeError):
            self.handler(Executor())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

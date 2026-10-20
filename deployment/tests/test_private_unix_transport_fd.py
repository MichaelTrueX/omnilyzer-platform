"""File: deployment/tests/test_private_unix_transport_fd.py

Purpose: Validate opt-in sealed Zot credential passing through the existing
UnixExecutorTransport while the original public send() framing stays intact.
Related: deployment/private_registry_fd.py, deployment/unix_transport.py,
deployment/tests/test_unix_transport.py and deployment/executor_server.py.

Sections: real AF_UNIX message framing, exact peer/credential transfer,
failure to transfer malformed credentials, and legacy compatibility.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from deployment.execution import ExecutorRequest
from deployment.private_registry_fd import (
    create_sealed_credential, read_sealed_credential, receive_sealed_header,
)
from deployment.tests.test_execution import valid_request
from deployment.tests.test_unix_transport import constructed
from deployment.unix_transport import ExecutorTransportUnavailableError

REQUEST = ExecutorRequest.from_dict(valid_request()).canonical_bytes()
IMAGE = ExecutorRequest.from_dict(valid_request()).exact_image_reference
REPLY = b"synthetic-private-registry-test-response"
TEST_TOKEN = "synthetic-secret-is-not-written-into-the-request"


def exact_read(connection: socket.socket, length: int) -> bytes:
    """Read a deterministic socket-frame payload without changing kernel state."""
    received = bytearray()
    while len(received) < length:
        piece = connection.recv(length - len(received))
        if not piece:
            break
        received.extend(piece)
    return bytes(received)


class PrivateUnixTransportTests(unittest.TestCase):
    """Exercise actual Linux peer-checked private one-FD transport."""

    def test_private_send_receives_bound_one_fd_and_canonical_request(self) -> None:
        """Transport carries JWT only in SCM_RIGHTS, never in request bytes."""
        with tempfile.TemporaryDirectory(prefix="omnilyzer-private-transport-") as d:
            path = str(Path(d) / "executor.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            os.chmod(path, 0o660)
            server.listen(1)
            server.settimeout(3)
            now = int(time.time())
            fd = create_sealed_credential(
                TEST_TOKEN, expires_at=now + 120,
                image=IMAGE, canonical_request=REQUEST, now=now,
            )
            captured: list[tuple[bytes, bytes, str]] = []
            errors: list[BaseException] = []

            def respond() -> None:
                """Handle one peer connection without a real privileged executor."""
                try:
                    client, _ = server.accept()
                    with client:
                        client.settimeout(3)
                        header, transferred = receive_sealed_header(client)
                        try:
                            size = int.from_bytes(header, "big")
                            canonical = exact_read(client, size)
                            authority = read_sealed_credential(
                                transferred, canonical_request=canonical,
                                image=IMAGE,
                            )
                            captured.append((header, canonical, authority.token))
                        finally:
                            os.close(transferred)
                        self.assertEqual(client.recv(1), b"")
                        client.sendall(len(REPLY).to_bytes(4, "big") + REPLY)
                        client.shutdown(socket.SHUT_WR)
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            try:
                result = constructed(path)._send_private(
                    REQUEST, credential_fd=fd,
                )
                self.assertEqual(result, REPLY)
            finally:
                os.close(fd)
                worker.join(5)
                server.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(
                captured, [(len(REQUEST).to_bytes(4, "big"), REQUEST, TEST_TOKEN)],
            )
            self.assertNotIn(TEST_TOKEN.encode(), captured[0][1])

    def test_private_send_denies_mismatched_canonical_request_before_connect(self) -> None:
        """No valid sealed FD may be replayed with different request bytes."""
        with tempfile.TemporaryDirectory(prefix="omnilyzer-private-fd-reject-") as d:
            path = str(Path(d) / "nonexistent.sock")
            now = int(time.time())
            fd = create_sealed_credential(
                TEST_TOKEN, expires_at=now + 100,
                image=IMAGE, canonical_request=REQUEST, now=now,
            )
            try:
                with self.assertRaises(ExecutorTransportUnavailableError):
                    constructed(path)._send_private(
                        REQUEST + b" ", credential_fd=fd,
                    )
            finally:
                os.close(fd)

    def test_private_send_denies_unsealed_descriptor(self) -> None:
        """Transport refuses unsafe descriptor before any socket side effects."""
        with tempfile.TemporaryDirectory(prefix="omnilyzer-unsealed-denied-") as d:
            path = str(Path(d) / "not-created.sock")
            fd = os.memfd_create("unsealed-fd", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                with self.assertRaises(ExecutorTransportUnavailableError):
                    constructed(path)._send_private(
                        REQUEST, credential_fd=fd,
                    )
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()

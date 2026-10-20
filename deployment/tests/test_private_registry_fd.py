"""File: deployment/tests/test_private_registry_fd.py

Purpose: negative-first, Linux socketpair acceptance of sealed, short-lived
private Zot-read credential handoff. No real registry, Docker, service or
replay I/O. Related: deployment/private_registry_fd.py, deployment/unix_transport.py,
deployment/executor_server.py and deployment/tests/test_docker_runtime.py.

Sections: sealed credential integrity, request/expiry binding, ancillary
SCM_RIGHTS frame validation and descriptor cleanup.
"""

from __future__ import annotations

from array import array
import fcntl
import hashlib
import json
import os
import socket
import struct
import time
import unittest
from unittest.mock import patch

from deployment.private_registry_fd import (
    PrivateRegistryTransferError, ScopedReadCredential,
    create_sealed_credential, read_sealed_credential,
    receive_sealed_header, send_sealed_header,
)

REQUEST = b'{"operation":"promotion","stage":"dev"}\n'
IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/task013-release-canary@sha256:"
    + "2f9db44a1cb475bec5a82ad7f81508e2b6ecd327f32b358ec1f1deca95e5385e"
)
NOW = 1_800_000_000
SECRET = "header.payload.signature-only-for-offline-unit-tests"


class SealedCredentialTests(unittest.TestCase):
    """Verify a closed, memory-only read credential cannot cross requests."""

    def new_fd(self, **replacements: object) -> int:
        """Create one synthetic credential under a deterministic test clock."""
        params: dict[str, object] = dict(
            token=SECRET, expires_at=NOW + 60, image=IMAGE,
            canonical_request=REQUEST, now=NOW,
        )
        params.update(replacements)
        return create_sealed_credential(**params)

    def test_creation_is_sealed_bound_and_redacted(self) -> None:
        """Sealed input validates exactly the original request and image."""
        fd = self.new_fd()
        try:
            value = read_sealed_credential(fd, canonical_request=REQUEST,
                                           image=IMAGE, now=NOW)
            self.assertIs(type(value), ScopedReadCredential)
            self.assertEqual(value.token, SECRET)
            self.assertNotIn(SECRET, repr(value))
            self.assertEqual(value.request_sha256, hashlib.sha256(REQUEST).hexdigest())
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(os.fstat(fd).st_nlink, 0)
            with self.assertRaises(OSError):
                os.write(fd, b"payload-modification")
            with self.assertRaises(AttributeError):
                value.image = "elsewhere"  # type: ignore[misc]
            import pickle
            with self.assertRaises(TypeError):
                pickle.dumps(value)
        finally:
            os.close(fd)

    def test_mismatched_request_image_and_stale_clock_fail_closed(self) -> None:
        """No wrong digest, wrong canonical request or expired credential."""
        fd = self.new_fd()
        try:
            for params in (
                dict(canonical_request=b'{"different":true}', image=IMAGE, now=NOW),
                dict(canonical_request=REQUEST, image=IMAGE[:-1] + "0", now=NOW),
                dict(canonical_request=REQUEST, image=IMAGE, now=NOW + 60),
                dict(canonical_request=REQUEST, image=IMAGE, now=NOW - 241),
            ):
                with self.subTest(**params), self.assertRaises(PrivateRegistryTransferError):
                    read_sealed_credential(fd, **params)
        finally:
            os.close(fd)

    def test_missing_invalid_expired_or_overlong_authority_rejected(self) -> None:
        """Before creating an FD reject tokens, wrong image and wrong TTL."""
        variants = (
            dict(token=""),
            dict(token="a" * 8193),
            dict(token="has a space"),
            dict(token="contains\x00null"),
            dict(image="other.example/repo@sha256:" + "a" * 64),
            dict(image=IMAGE[:-1] + "G"),
            dict(canonical_request=b""),
            dict(canonical_request="not bytes"),
            dict(expires_at=NOW),
            dict(expires_at=NOW + 301),
            dict(expires_at=True),
            dict(now=True),
        )
        for params in variants:
            with self.subTest(params=params), self.assertRaises(PrivateRegistryTransferError):
                self.new_fd(**params)

    def test_plain_and_unsealed_fd_rejected(self) -> None:
        """Executor refuses ordinary files, including unsealed memfds."""
        fd = os.memfd_create("invalid-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, b'{"token":"fake"}\n')
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_credential(fd, canonical_request=REQUEST, image=IMAGE, now=NOW)
        finally:
            os.close(fd)

    def test_duplicate_keys_and_noncanonical_bytes_rejected(self) -> None:
        """A sealed malicious descriptor cannot smuggle duplicate JSON keys."""
        fields = {
            "expires_at": NOW + 60, "host": "oci-dev.omnilyzer.ai",
            "image": IMAGE,
            "request_sha256": hashlib.sha256(REQUEST).hexdigest(),
            "schema_version": 1, "token": SECRET,
        }
        base = json.dumps(fields, separators=(",", ":"), sort_keys=True)
        variants = (
            base[:-1] + ',"token":"attacker"}\n',
            json.dumps(fields, indent=2) + "\n",
            base[:-1] + ',"unexpected":0}\n',
        )
        for raw in variants:
            fd = os.memfd_create("adversarial-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(fd, raw.encode("ascii"))
                seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                         fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
                with self.assertRaises(PrivateRegistryTransferError):
                    read_sealed_credential(fd, canonical_request=REQUEST, image=IMAGE, now=NOW)
            finally:
                os.close(fd)


class AncillarySocketTests(unittest.TestCase):
    """Exercise actual Linux SCM_RIGHTS and fd leak defenses."""

    def test_roundtrip_one_sealed_fd_and_four_byte_header(self) -> None:
        """Transfer a sealed descriptor without disclosing the token as bytes."""
        fd = create_sealed_credential(SECRET, expires_at=NOW + 60,
                                      image=IMAGE, canonical_request=REQUEST, now=NOW)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        peerfd = None
        try:
            header = len(REQUEST).to_bytes(4, "big")
            send_sealed_header(a, header, fd)
            a.sendall(REQUEST)
            got_header, peerfd = receive_sealed_header(b)
            self.assertEqual(header, got_header)
            self.assertFalse(os.get_inheritable(peerfd))
            self.assertNotEqual(fd, peerfd)
            self.assertEqual(b.recv(len(REQUEST)), REQUEST)
            actual = read_sealed_credential(peerfd, canonical_request=REQUEST,
                                             image=IMAGE, now=NOW)
            self.assertEqual(actual.token, SECRET)
        finally:
            if peerfd is not None:
                os.close(peerfd)
            os.close(fd)
            a.close()
            b.close()

    def test_missing_fd_rejected(self) -> None:
        """No legacy unauthenticated frame may enter credential-required mode."""
        a, b = socket.socketpair()
        try:
            a.sendall(b"\x00\x00\x00\x05")
            with self.assertRaises(PrivateRegistryTransferError):
                receive_sealed_header(b)
        finally:
            a.close()
            b.close()

    def test_multiple_fds_rejected_and_closed(self) -> None:
        """Ancillary fd injection must not leak descriptor copies."""
        a, b = socket.socketpair()
        fd = os.memfd_create("test-fd", os.MFD_CLOEXEC)
        originals = []
        try:
            originals = [os.dup(fd), os.dup(fd)]
            rights = array("i", originals)
            a.sendmsg([b"\x00\x00\x00\x05"],
                      [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
            before = len(os.listdir("/proc/self/fd"))
            with self.assertRaises(PrivateRegistryTransferError):
                receive_sealed_header(b)
            after = len(os.listdir("/proc/self/fd"))
            self.assertEqual(before, after)
        finally:
            for x in originals:
                os.close(x)
            os.close(fd)
            a.close()
            b.close()

    def test_invalid_header_and_fd_rejected(self) -> None:
        """Never send absent descriptors or non-four-byte lengths."""
        a, b = socket.socketpair()
        try:
            for header, fd in ((b"", 1), (b"123", 1), (b"12345", 1), (b"1234", -1)):
                with self.subTest(header=header, fd=fd):
                    with self.assertRaises(PrivateRegistryTransferError):
                        send_sealed_header(a, header, fd)
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()

"""File: deployment/tests/test_private_registry_fd.py

Purpose: negative-first, Linux socketpair acceptance of sealed, short-lived
private Zot-read credential handoff. No real registry, Docker, service or
replay I/O. Related: deployment/private_registry_fd.py, deployment/unix_transport.py,
deployment/executor_server.py, deployment/analytics_promotion_broker.py and
deployment/tests/test_docker_runtime.py.

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
    ANALYTICS_IMAGE, PrivateRegistryTransferError, ScopedReadCredential,
    ScopedSuccessorReviewCredentials,
    create_sealed_credential, read_sealed_credential,
    create_sealed_successor_review_credentials,
    read_sealed_successor_review_credentials,
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


class AnalyticsSealedCredentialScopeTests(unittest.TestCase):
    """Prove distinct exact Analytics release scope cannot mutate canary FD."""

    def test_exact_signed_analytics_fd_roundtrip_with_explicit_scope(self) -> None:
        """One immutable reviewed OCI digest, existing FD seals and request hash."""
        request = b'{"analytics":true,"schema_version":2}\n'
        descriptor = create_sealed_credential(
            SECRET, expires_at=NOW + 240, image=ANALYTICS_IMAGE,
            canonical_request=request, now=NOW, product_id="analytics",
        )
        try:
            received = read_sealed_credential(
                descriptor, canonical_request=request,
                image=ANALYTICS_IMAGE, now=NOW, product_id="analytics",
            )
            self.assertIs(type(received), ScopedReadCredential)
            self.assertEqual(received.image, ANALYTICS_IMAGE)
            self.assertEqual(received.token, SECRET)
            self.assertEqual(received.request_sha256, hashlib.sha256(request).hexdigest())
            self.assertNotIn(SECRET, repr(received))
            self.assertFalse(os.get_inheritable(descriptor))
            with self.assertRaises(OSError):
                os.write(descriptor, b"tamper")
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_credential(
                    descriptor, canonical_request=request,
                    image=ANALYTICS_IMAGE, now=NOW,
                )
        finally:
            os.close(descriptor)

    def test_cross_product_tag_wrong_digest_request_and_expiry_denied(self) -> None:
        """Canary default remains canary-only; no Analytics tags or wildcards."""
        request = b'{"analytics":true,"schema_version":2}\n'
        kwargs = dict(token=SECRET, expires_at=NOW + 240,
                      image=ANALYTICS_IMAGE, canonical_request=request, now=NOW)
        for overrides in (
            {},
            {"product_id": "canary"},
            {"product_id": "Analytics"},
            {"product_id": "other"},
            {"product_id": True},
            {"product_id": None},
            {"product_id": "analytics", "image": ANALYTICS_IMAGE[:-1] + "0"},
            {"product_id": "analytics", "image": ANALYTICS_IMAGE.split("@")[0] + ":0.15.0"},
            {"product_id": "analytics", "image": IMAGE},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(PrivateRegistryTransferError):
                create_sealed_credential(**(kwargs | overrides))
        descriptor = create_sealed_credential(**(kwargs | {"product_id": "analytics"}))
        try:
            for overrides in (
                {"product_id": "canary"},
                {"product_id": "other"},
                {"image": IMAGE},
                {"image": ANALYTICS_IMAGE[:-1] + "0"},
                {"canonical_request": b'{"different":true}'},
                {"now": NOW + 240},
                {"now": NOW - 61},
            ):
                with self.subTest(overrides=overrides), self.assertRaises(PrivateRegistryTransferError):
                    read_sealed_credential(descriptor, **(dict(
                        canonical_request=request, image=ANALYTICS_IMAGE,
                        now=NOW, product_id="analytics",
                    ) | overrides))
        finally:
            os.close(descriptor)

    def test_analytics_scope_can_never_consume_canary_fd(self) -> None:
        """An original canary credential cannot silently become an Analytics grant."""
        descriptor = create_sealed_credential(
            SECRET, expires_at=NOW + 240,
            image=IMAGE, canonical_request=REQUEST, now=NOW,
        )
        try:
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_credential(
                    descriptor, canonical_request=REQUEST,
                    image=IMAGE, now=NOW, product_id="analytics",
                )
            self.assertEqual(
                read_sealed_credential(
                    descriptor, canonical_request=REQUEST,
                    image=IMAGE, now=NOW,
                ).image, IMAGE,
            )
        finally:
            os.close(descriptor)


# Section 4: future exact owner-reviewed Analytics schema-3 sealed FD.
# This is only structural request/image scope, NOT actual signature authority.
class AnalyticsSuccessorSealedCredentialTests(unittest.TestCase):
    """Use original Linux memfd seals for the exact future signed-image claim."""

    @staticmethod
    def candidate():
        from deployment.tests.test_analytics_execution import (
            AnalyticsSuccessorRequestTests,
        )
        from deployment.policy import canonical_bytes
        request, _context = AnalyticsSuccessorRequestTests().candidate()
        return canonical_bytes(request), request["exact_image_reference"], request

    def test_next_signed_image_exact_scoped_fd_and_actual_kernel_rights(self):
        """One future digest, precise request SHA and same real SCM_RIGHTS."""
        raw, image, _ = self.candidate()
        before = set(os.listdir("/proc/self/fd"))
        fd = create_sealed_credential(
            SECRET, expires_at=NOW + 240, image=image,
            canonical_request=raw, now=NOW, product_id="analytics-successor",
        )
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        peer = None
        try:
            credential = read_sealed_credential(
                fd, canonical_request=raw, image=image,
                now=NOW, product_id="analytics-successor",
            )
            self.assertIs(type(credential), ScopedReadCredential)
            self.assertEqual(credential.image, image)
            self.assertEqual(credential.request_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(credential.token, SECRET)
            self.assertFalse(os.get_inheritable(fd))
            self.assertNotIn(SECRET, repr(credential))
            with self.assertRaises(OSError):
                os.write(fd, b"edit unsealed")
            send_sealed_header(a, len(raw).to_bytes(4, "big"), fd)
            a.sendall(raw)
            header, peer = receive_sealed_header(b)
            self.assertEqual(int.from_bytes(header, "big"), len(raw))
            self.assertEqual(b.recv(len(raw)), raw)
            received = read_sealed_credential(
                peer, canonical_request=raw, image=image,
                now=NOW, product_id="analytics-successor",
            )
            self.assertEqual(received.token, SECRET)
            for different in (
                {"product_id": "canary"},
                {"product_id": "analytics"},
                {"product_id": "other"},
                {"image": ANALYTICS_IMAGE},
                {"image": image[:-1] + ("0" if image[-1] != "0" else "f")},
                {"canonical_request": raw + b" "},
                {"now": NOW + 240},
            ):
                with self.subTest(different=different), self.assertRaises(
                    PrivateRegistryTransferError
                ):
                    read_sealed_credential(
                        peer, **{
                            **{"canonical_request": raw, "image": image,
                               "now": NOW, "product_id": "analytics-successor"},
                            **different,
                        }
                    )
        finally:
            if peer is not None:
                os.close(peer)
            os.close(fd)
            a.close()
            b.close()
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_next_release_cannot_borrow_original_or_canary_scope(self):
        raw, image, data = self.candidate()
        for altered in (
            ("image", ANALYTICS_IMAGE),
            ("image", IMAGE),
            ("product_id", "analytics"),
            ("product_id", "canary"),
            ("product_id", "analytics-successors"),
            ("product_id", None),
        ):
            name, value = altered
            with self.subTest(name=name, value=value), self.assertRaises(
                PrivateRegistryTransferError
            ):
                create_sealed_credential(
                    SECRET, expires_at=NOW + 240, now=NOW,
                    **{
                        **{"image": image, "canonical_request": raw,
                           "product_id": "analytics-successor"},
                        name: value,
                    },
                )
        old = create_sealed_credential(
            SECRET, expires_at=NOW + 240, now=NOW, image=ANALYTICS_IMAGE,
            canonical_request=b'{"analytics":true,"schema_version":2}\n',
            product_id="analytics",
        )
        try:
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_credential(
                    old, image=image, canonical_request=raw,
                    now=NOW, product_id="analytics-successor",
                )
        finally:
            os.close(old)

    def test_malformed_new_request_rejected_before_any_fd_creation(self):
        from deployment.policy import canonical_bytes
        raw, image, data = self.candidate()
        variants = (
            raw + b" ",
            raw + b"\n",
            raw.replace(
                b'"product_id":"analytics"',
                b'"product_id":"analytics","product_id":"analytics"',
            ),
            raw.replace(
                b'"owner_approval_sha256":',
                b'"owner_approval_sha256":"bad","owner_approval_sha256":',
            ),
            canonical_bytes({**data, "schema_version": 2}),
            canonical_bytes({**data, "product_id": "canary"}),
            canonical_bytes({**data, "operation": "delete"}),
            canonical_bytes({**data, "stage": "prod"}),
            canonical_bytes({**data, "oci_repository": "omnilyzer/task013-release-canary"}),
            canonical_bytes({**data, "owner_approval_sha256": "0" * 64}),
            canonical_bytes({**data, "source_claim_sha256": "bad"}),
            canonical_bytes({**data, "manifest_digest": "sha256:" + "0" * 64}),
            canonical_bytes({**data, "exact_image_reference": ANALYTICS_IMAGE}),
            canonical_bytes({**data, "ingress_reference": {
                **data["ingress_reference"], "loopback_port": 3141,
            }}),
            canonical_bytes({**data, "rollback_reference": {
                **data["rollback_reference"], "preserve_database_writes": False,
            }}),
            b"x" * 16385,
            b"not-json",
        )
        with patch("deployment.private_registry_fd.os.memfd_create") as create:
            for broken in variants:
                with self.subTest(broken=broken[:40]), self.assertRaises(
                    PrivateRegistryTransferError
                ):
                    create_sealed_credential(
                        SECRET, expires_at=NOW + 240, now=NOW, image=image,
                        canonical_request=broken, product_id="analytics-successor",
                    )
            create.assert_not_called()

    def test_independent_review_bundle_is_kernel_sealed_and_does_not_grant_deploy(self):
        """Three JWTs transfer through one sealed FD, without JSON or log leakage."""
        raw, image, _ = self.candidate()
        before = set(os.listdir("/proc/self/fd"))
        params = {
            "zot_token": SECRET,
            "forgejo_token": "forgejo.payload.signature",
            "github_oidc_token": "deployment.payload.signature",
            "expires_at": NOW + 240,
            "image": image,
            "canonical_request": raw,
            "now": NOW,
        }
        fd = create_sealed_successor_review_credentials(**params)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        peer = None
        try:
            view = read_sealed_successor_review_credentials(
                fd, canonical_request=raw, image=image, now=NOW,
            )
            self.assertIs(type(view), ScopedSuccessorReviewCredentials)
            self.assertEqual(view.zot.token, SECRET)
            self.assertEqual(view.forgejo_token, params["forgejo_token"])
            self.assertEqual(view.github_oidc_token, params["github_oidc_token"])
            self.assertEqual(
                read_sealed_credential(
                    fd, canonical_request=raw, image=image,
                    product_id="analytics-successor", now=NOW,
                ).token,
                SECRET,
            )
            self.assertFalse(os.get_inheritable(fd))
            for secret in (SECRET, params["forgejo_token"], params["github_oidc_token"]):
                self.assertNotIn(secret, repr(view))
                self.assertNotIn(secret.encode(), raw)
            with self.assertRaises(OSError):
                os.write(fd, b"alter")
            with self.assertRaises(AttributeError):
                view.forgejo_token = "changed"
            import pickle
            with self.assertRaises(TypeError):
                pickle.dumps(view)
            send_sealed_header(a, len(raw).to_bytes(4, "big"), fd)
            a.sendall(raw)
            header, peer = receive_sealed_header(b)
            self.assertEqual(int.from_bytes(header, "big"), len(raw))
            self.assertEqual(b.recv(len(raw)), raw)
            received = read_sealed_successor_review_credentials(
                peer, canonical_request=raw, image=image, now=NOW,
            )
            self.assertEqual(received.github_oidc_token, params["github_oidc_token"])
            self.assertEqual(received.zot.request_sha256, hashlib.sha256(raw).hexdigest())
            for wrong in (
                {"image": ANALYTICS_IMAGE},
                {"canonical_request": raw + b" "},
                {"now": NOW + 241},
            ):
                with self.subTest(wrong=wrong), self.assertRaises(
                    PrivateRegistryTransferError
                ):
                    read_sealed_successor_review_credentials(
                        peer, **{
                            "canonical_request": raw, "image": image,
                            "now": NOW, **wrong,
                        },
                    )
            for product in ("analytics", "canary", "unknown"):
                with self.subTest(product=product), self.assertRaises(
                    PrivateRegistryTransferError
                ):
                    read_sealed_credential(
                        peer, canonical_request=raw, image=image,
                        now=NOW, product_id=product,
                    )
        finally:
            if peer is not None:
                os.close(peer)
            os.close(fd)
            a.close()
            b.close()
        self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_original_one_token_successor_cannot_claim_full_oidc_evidence(self):
        """Schema-1 remains read-only, but never supplies a three-JWT approval."""
        raw, image, _ = self.candidate()
        fd = create_sealed_credential(
            SECRET, expires_at=NOW + 240, image=image,
            canonical_request=raw, now=NOW, product_id="analytics-successor",
        )
        try:
            self.assertEqual(
                read_sealed_credential(
                    fd, canonical_request=raw, image=image,
                    now=NOW, product_id="analytics-successor",
                ).token,
                SECRET,
            )
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_successor_review_credentials(
                    fd, canonical_request=raw, image=image, now=NOW,
                )
        finally:
            os.close(fd)

    def test_review_envelope_rejects_invalid_jwts_scope_and_unsealed_copy(self):
        """Malformed JWT or altered request must fail before any reviewer use."""
        raw, image, _ = self.candidate()
        valid = {
            "zot_token": SECRET, "forgejo_token": "forgejo.payload.signature",
            "github_oidc_token": "deployment.payload.signature",
            "expires_at": NOW + 240, "image": image,
            "canonical_request": raw, "now": NOW,
        }
        for mutation in (
            {"forgejo_token": "invalid"},
            {"github_oidc_token": "invalid"},
            {"forgejo_token": "a.b."},
            {"github_oidc_token": "a.b.\n"},
            {"forgejo_token": "a" * 8193},
            {"expires_at": NOW + 301},
            {"image": ANALYTICS_IMAGE},
            {"canonical_request": raw + b" "},
        ):
            with self.subTest(mutation=list(mutation)), self.assertRaises(
                PrivateRegistryTransferError
            ):
                create_sealed_successor_review_credentials(**(valid | mutation))
        fd = os.memfd_create("test-unsealed-review", os.MFD_ALLOW_SEALING)
        try:
            legitimate = create_sealed_successor_review_credentials(**valid)
            try:
                os.write(fd, os.pread(legitimate, os.fstat(legitimate).st_size, 0))
            finally:
                os.close(legitimate)
            with self.assertRaises(PrivateRegistryTransferError):
                read_sealed_successor_review_credentials(
                    fd, canonical_request=raw, image=image, now=NOW,
                )
        finally:
            os.close(fd)



if __name__ == "__main__":
    unittest.main()

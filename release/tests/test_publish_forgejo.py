from __future__ import annotations

import hashlib
import io
import re
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from release.publish_forgejo import NoRedirect, _pypi_multipart, _request


def _field(body: bytes, name: str) -> str:
    pattern = re.compile(
        rb'Content-Disposition: form-data; name="' + re.escape(name.encode()) + rb'"\r\n\r\n([^\r]*)\r\n'
    )
    values = pattern.findall(body)
    if len(values) != 1:
        raise AssertionError(f"expected exactly one {name} field, found {len(values)}")
    return values[0].decode("ascii")


class PublishForgejoTests(unittest.TestCase):
    def test_pypi_digest_is_exactly_one_hash_of_uploaded_content(self) -> None:
        content = b"synthetic wheel bytes\x00\xff"
        body, content_type = _pypi_multipart("canary.whl", content, "canary", "1.2.3")
        self.assertEqual(body.count(b'name="sha256_digest"'), 1)
        digest = _field(body, "sha256_digest")
        self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())
        self.assertIn(content, body)
        self.assertEqual(content_type, "multipart/form-data; boundary=omnilyzer-task013-fixed-boundary")

    def test_altered_content_produces_a_different_pypi_digest(self) -> None:
        first, _ = _pypi_multipart("canary.whl", b"baseline", "canary", "1.2.3")
        second, _ = _pypi_multipart("canary.whl", b"replacement", "canary", "1.2.3")
        self.assertNotEqual(_field(first, "sha256_digest"), _field(second, "sha256_digest"))

    def test_http_error_is_bounded_contextual_and_redacts_token(self) -> None:
        token = "header.payload.signature"
        error_body = b"hash mismatch: " + token.encode() + b" " + (b"x" * 1000)

        class RejectingOpener:
            def open(self, request, timeout):  # noqa: ANN001, ARG002
                raise HTTPError(request.full_url, 400, "Bad Request", {}, io.BytesIO(error_body))

        with patch("release.publish_forgejo.urllib.request.build_opener", return_value=RejectingOpener()):
            with self.assertRaises(RuntimeError) as caught:
                _request(
                    "https://registry-dev.omnilyzer.ai", token, "POST",
                    "/api/packages/omnilyzer/pypi", b"payload", "multipart/form-data",
                )
        message = str(caught.exception)
        self.assertIn("Forgejo POST /api/packages/omnilyzer/pypi returned HTTP 400", message)
        self.assertIn("hash mismatch", message)
        self.assertIn("[REDACTED]", message)
        self.assertNotIn(token, message)
        self.assertNotIn("x" * 513, message)

    def test_origin_and_redirect_protections_remain_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "escaped the reviewed origin"):
            _request(
                "https://registry-dev.omnilyzer.ai", "header.payload.signature", "GET",
                "https://attacker.invalid/api/packages/omnilyzer/pypi",
            )
        with self.assertRaisesRegex(RuntimeError, "redirect refused"):
            NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://attacker.invalid")


if __name__ == "__main__":
    unittest.main()

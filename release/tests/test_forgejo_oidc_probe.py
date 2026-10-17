# File: release/tests/test_forgejo_oidc_probe.py
# Purpose: Test the read-only Forgejo OIDC diagnostic, including negative paths.
# Related: release/forgejo_oidc_probe.py, release/request_oidc.py,
#          .github/workflows/platform-release.yml.
# Authority: Completely offline, mocked network; no JWTs or deployments.

"""Regression tests for a fixed-target and non-publishing OIDC diagnostic."""

from __future__ import annotations

import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from release.forgejo_oidc_probe import (
    MAX_RESPONSE, PROBE_URL, NoRedirect, ProbeError, read_token, verify_read_only,
)

# Section 1: A fake JWT proves validation and redaction without real credentials.
TOKEN = ".".join(("eyJhbGciOiJSUzI1NiJ9", "eyJhdWQiOiJ0ZXN0In0", "SGVsbG8"))


class _Response:
    """A bounded, fake API reply supporting urllib's response context manager."""

    def __init__(self, payload: bytes = b"[]", status: int = 200,
                 content_type: str = "application/json"):
        self.status = status
        self.headers = {"Content-Type": content_type}
        self.payload = io.BytesIO(payload)

    def read(self, size: int = -1) -> bytes:
        """Return the fake package listing without network access."""
        return self.payload.read(size)

    def __enter__(self):
        """Support the urllib response context used by the implementation."""
        return self

    def __exit__(self, *args):
        """Close the fake response."""
        self.payload.close()


class ForgejoOidcProbeTests(unittest.TestCase):
    """Check the fixed target, JWT privacy and strictly read-only behavior."""

    def test_token_file_requires_regular_private_file(self) -> None:
        """Only a regular file with mode 0600 may hold the ephemeral bearer."""
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "token"
            p.write_text(TOKEN)
            p.chmod(0o600)
            self.assertEqual(read_token(p), TOKEN)
            p.chmod(0o644)
            with self.assertRaisesRegex(ProbeError, "NOT_PRIVATE"):
                read_token(p)
            p.chmod(0o600)
            link = Path(temp) / "link"
            link.symlink_to(p)
            with self.assertRaisesRegex(ProbeError, "UNREADABLE"):
                read_token(link)

    def test_empty_malformed_oversized_and_missing_token_rejected(self) -> None:
        """Do not send malformed token files to the registry."""
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "token"
            for value in ("", "invalid jwt", TOKEN + "\n", "x" * 16385):
                p.write_text(value)
                p.chmod(0o600)
                with self.subTest(size=len(value)), self.assertRaises(ProbeError):
                    read_token(p)
            p.unlink()
            with self.assertRaisesRegex(ProbeError, "UNREADABLE"):
                read_token(p)

    def test_only_one_get_to_fixed_origin_with_ephemeral_bearer(self) -> None:
        """Make no HTTP writes, no redirected call and no variable destination."""
        response = _Response()
        class Opener:
            def open(self, request, timeout):
                """Inspect the sole outgoing request before returning a fake 200."""
                self.test_case.assertEqual(request.full_url, PROBE_URL)
                self.test_case.assertEqual(request.get_method(), "GET")
                self.test_case.assertEqual(request.get_header("Authorization"),
                                            f"Bearer {TOKEN}")
                self.test_case.assertEqual(timeout, 15)
                self.test_case.assertIsNone(request.data)
                return response
        opener = Opener()
        opener.test_case = self
        with patch("release.forgejo_oidc_probe.urllib.request.build_opener",
                   return_value=opener) as build:
            verify_read_only(TOKEN)
        self.assertEqual(build.call_count, 1)
        self.assertIs(build.call_args.args[0], NoRedirect)

    def test_empty_package_list_is_a_valid_authenticated_read(self) -> None:
        """A 200 with an empty list still proves package API authorization."""
        with patch("release.forgejo_oidc_probe.urllib.request.build_opener") as build:
            build.return_value.open.return_value = _Response()
            verify_read_only(TOKEN)

    def test_http_401_is_denied_without_leaking_token_or_error_body(self) -> None:
        """Never surface a JWT if Forgejo returns an authorization failure."""
        error = urllib.error.HTTPError(
            PROBE_URL, 401, f"contains fake token {TOKEN}",
            {}, io.BytesIO(f"private token {TOKEN}".encode()),
        )
        with patch("release.forgejo_oidc_probe.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = error
            with self.assertRaises(ProbeError) as raised:
                verify_read_only(TOKEN)
        self.assertEqual(str(raised.exception), "FORGEJO_OIDC_PROBE_HTTP_401")
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_redirects_are_explicitly_denied(self) -> None:
        """A redirect cannot copy a bearer credential to another origin."""
        with self.assertRaisesRegex(ProbeError, "REDIRECT_DENIED"):
            NoRedirect().redirect_request(
                None, None, 302, "Found", {}, "https://attacker.invalid",
            )

    def test_non_json_unexpected_shape_or_non_200_fail_closed(self) -> None:
        """Require a normal JSON package list rather than any arbitrary 2xx."""
        cases = (
            (_Response(status=204), "UNEXPECTED_STATUS"),
            (_Response(content_type="text/html"), "UNEXPECTED_CONTENT_TYPE"),
            (_Response(payload=b"{}"), "NOT_A_PACKAGE_LIST"),
            (_Response(payload=b"not json"), "INVALID_JSON"),
            (_Response(payload=b"[]" + b" " * MAX_RESPONSE), "RESPONSE_TOO_LARGE"),
        )
        for response, error in cases:
            with self.subTest(error=error):
                with patch("release.forgejo_oidc_probe.urllib.request.build_opener") as build:
                    build.return_value.open.return_value = response
                    with self.assertRaisesRegex(ProbeError, error):
                        verify_read_only(TOKEN)

    def test_network_errors_and_bad_inline_tokens_fail_closed(self) -> None:
        """Do not expose internal network exceptions or make malformed JWT calls."""
        with self.assertRaisesRegex(ProbeError, "TOKEN_FORMAT"):
            verify_read_only("not.a token")
        with patch("release.forgejo_oidc_probe.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = urllib.error.URLError(
                "contains fake credential " + TOKEN
            )
            with self.assertRaises(ProbeError) as raised:
                verify_read_only(TOKEN)
        self.assertEqual(str(raised.exception), "FORGEJO_OIDC_PROBE_NETWORK_ERROR")
        self.assertNotIn(TOKEN, str(raised.exception))


if __name__ == "__main__":
    unittest.main()

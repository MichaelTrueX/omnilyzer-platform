# File: release/tests/test_publish_forgejo.py
# Purpose: Validate immutable Forgejo package publication and one-use,
#          explicitly typed credential input without live registry mutation.
# Related: release/publish_forgejo.py, .github/workflows/platform-release.yml.
# Sections: existing package integrity and readback; token-kind negative tests.

from __future__ import annotations

import hashlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from release.publish_forgejo import (
    NoRedirect,
    _pypi_multipart,
    _request,
    _validated_pypi_download_url,
    publish,
    _token,
)


ORIGIN = "https://registry-dev.omnilyzer.ai"
OWNER = "omnilyzer"
PACKAGE = "omnilyzer-release-canary"
VERSION = "0.13.3"
WHEEL = "omnilyzer_release_canary-0.13.3-py3-none-any.whl"
SHA256 = "7016188deee3d4522087facd082974b4de2ffd397304e81d6768b574082573a9"
WHEEL_PATH = f"/api/packages/{OWNER}/pypi/files/{PACKAGE}/{VERSION}/{WHEEL}"
WHEEL_URL = f"{ORIGIN}{WHEEL_PATH}#sha256={SHA256}"


def _field(body: bytes, name: str) -> str:
    pattern = re.compile(
        rb'Content-Disposition: form-data; name="' + re.escape(name.encode()) + rb'"\r\n\r\n([^\r]*)\r\n'
    )
    values = pattern.findall(body)
    if len(values) != 1:
        raise AssertionError(f"expected exactly one {name} field, found {len(values)}")
    return values[0].decode("ascii")


class PublishForgejoTests(unittest.TestCase):
    def test_valid_pypi_link_returns_exact_fragment_free_request_url(self) -> None:
        self.assertEqual(
            _validated_pypi_download_url(
                ORIGIN, WHEEL_URL, OWNER, PACKAGE, VERSION, WHEEL, SHA256,
            ),
            ORIGIN + WHEEL_PATH,
        )

    def test_publish_strips_validated_fragment_before_wheel_request(self) -> None:
        wheel_bytes = b"synthetic wheel"
        wheel_sha256 = hashlib.sha256(wheel_bytes).hexdigest()
        advertised_url = f"{ORIGIN}{WHEEL_PATH}#sha256={wheel_sha256}"
        npm_bytes = b"synthetic npm tarball"
        npm_url = f"{ORIGIN}/api/packages/{OWNER}/npm/package/-/package-0.13.3.tgz"
        responses = [
            (201, b""),
            (200, f'<a href="{advertised_url}">{WHEEL}</a>'.encode()),
            (200, wheel_bytes),
            (201, b""),
            (200, json.dumps({"versions": {VERSION: {"dist": {"tarball": npm_url}}}}).encode()),
            (200, npm_bytes),
            (201, b""),
            (200, b"evidence"),
        ]
        plan = {
            "registries": {"forgejo_origin": ORIGIN},
            "packages": {
                "python": {"owner": OWNER, "name": PACKAGE},
                "npm": {"name": "package"},
                "evidence": {"name": "evidence"},
            },
            "artifacts": {"python_wheel": WHEEL, "npm_tarball": "package-0.13.3.tgz"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / WHEEL).write_bytes(wheel_bytes)
            (root / "package-0.13.3.tgz").write_bytes(npm_bytes)
            token_file = root / "token"
            token_file.write_text("header.payload.signature", encoding="ascii")
            token_file.chmod(0o600)
            with (
                patch("release.publish_forgejo.verify", return_value={"plan": plan}),
                patch("release.publish_forgejo._evidence_archive", return_value=b"evidence"),
                patch("release.publish_forgejo._request", side_effect=responses) as request,
            ):
                publish(root, root, token_file, root, VERSION, "a" * 40)
        self.assertEqual(request.call_args_list[2].args[3], ORIGIN + WHEEL_PATH)
        self.assertNotIn("#", request.call_args_list[2].args[3])

    def test_missing_pypi_hash_fragment_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid SHA-256 fragment"):
            _validated_pypi_download_url(
                ORIGIN, ORIGIN + WHEEL_PATH, OWNER, PACKAGE, VERSION, WHEEL, SHA256,
            )

    def test_wrong_pypi_hash_fragment_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid SHA-256 fragment"):
            _validated_pypi_download_url(
                ORIGIN, f"{ORIGIN}{WHEEL_PATH}#sha256={'0' * 64}",
                OWNER, PACKAGE, VERSION, WHEEL, SHA256,
            )

    def test_malformed_pypi_hash_fragments_are_rejected(self) -> None:
        fragments = (
            f"sha512={SHA256}",
            "sha256=not-hex",
            "sha256=*",
            f"sha256={SHA256.upper()}",
            f"sha256%3D{SHA256}",
        )
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                with self.assertRaisesRegex(ValueError, "invalid SHA-256 fragment"):
                    _validated_pypi_download_url(
                        ORIGIN, f"{ORIGIN}{WHEEL_PATH}#{fragment}",
                        OWNER, PACKAGE, VERSION, WHEEL, SHA256,
                    )

    def test_additional_pypi_fragment_data_is_rejected(self) -> None:
        for fragment in (f"sha256={SHA256}&extra=value", f"sha256={SHA256},sha256={SHA256}"):
            with self.subTest(fragment=fragment):
                with self.assertRaisesRegex(ValueError, "invalid SHA-256 fragment"):
                    _validated_pypi_download_url(
                        ORIGIN, f"{ORIGIN}{WHEEL_PATH}#{fragment}",
                        OWNER, PACKAGE, VERSION, WHEEL, SHA256,
                    )

    def test_foreign_or_insecure_pypi_origin_is_rejected(self) -> None:
        urls = (
            f"https://attacker.invalid{WHEEL_PATH}#sha256={SHA256}",
            f"http://registry-dev.omnilyzer.ai{WHEEL_PATH}#sha256={SHA256}",
            f"https://registry-dev.omnilyzer.ai:444{WHEEL_PATH}#sha256={SHA256}",
            f"https://user:password@registry-dev.omnilyzer.ai{WHEEL_PATH}#sha256={SHA256}",
        )
        for url in urls:
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "expected Forgejo route"):
                    _validated_pypi_download_url(
                        ORIGIN, url, OWNER, PACKAGE, VERSION, WHEEL, SHA256,
                    )

    def test_wrong_pypi_file_route_is_rejected(self) -> None:
        paths = (
            WHEEL_PATH.replace(f"/{OWNER}/", "/wrong-owner/"),
            WHEEL_PATH.replace(f"/{PACKAGE}/", "/wrong-package/"),
            WHEEL_PATH.replace(f"/{VERSION}/", "/0.13.4/"),
            WHEEL_PATH.replace(WHEEL, "wrong.whl"),
            WHEEL_PATH + "?download=1",
            WHEEL_PATH.replace("/api/", "/api%2f"),
        )
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "expected Forgejo route"):
                    _validated_pypi_download_url(
                        ORIGIN, f"{ORIGIN}{path}#sha256={SHA256}",
                        OWNER, PACKAGE, VERSION, WHEEL, SHA256,
                    )

    def test_pypi_path_ambiguity_is_rejected(self) -> None:
        for path in (WHEEL_PATH.replace("/pypi/", "/pypi\\/"), WHEEL_PATH + "%00"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "expected Forgejo route"):
                    _validated_pypi_download_url(
                        ORIGIN, f"{ORIGIN}{path}#sha256={SHA256}",
                        OWNER, PACKAGE, VERSION, WHEEL, SHA256,
                    )

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

    def test_request_still_rejects_fragment_bearing_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "escaped the reviewed origin"):
            _request(ORIGIN, "header.payload.signature", "GET", WHEEL_URL)


class CredentialBoundaryTests(unittest.TestCase):
    """Keep protected Forgejo bearer tokens private and explicitly typed."""

    def test_scoped_package_token_one_use_and_strict_type(self) -> None:
        """Accept only an opaque PAT and unlink its file after consumption."""
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "pat"
            value = "gitea_example_BEARER_token_123456789"
            p.write_text(value, encoding="ascii")
            p.chmod(0o600)
            self.assertEqual(_token(p, "pat"), value)
            self.assertFalse(p.exists())

    def test_legacy_oidc_input_kept_explicit(self) -> None:
        """Original OIDC parser remains valid only under the legacy mode."""
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "jwt"
            p.write_text("header.payload.signature", encoding="ascii")
            p.chmod(0o600)
            self.assertEqual(_token(p, "oidc"), "header.payload.signature")
            self.assertFalse(p.exists())

    def test_cross_type_and_malformed_values_rejected(self) -> None:
        """Reject ambiguous token types, whitespace and directory traversal."""
        for kind, value in (
            ("pat", "header.payload.signature"),
            ("oidc", "gitea_opaque_example_1234567890"),
            ("pat", "bad\nvalue"),
            ("pat", "short"),
            ("pat", "a" * 4100),
        ):
            with self.subTest(kind=kind, length=len(value)), tempfile.TemporaryDirectory() as directory:
                p = Path(directory) / "token"
                p.write_text(value, encoding="ascii")
                p.chmod(0o600)
                with self.assertRaises(ValueError):
                    _token(p, kind)
                self.assertFalse(p.exists())

    def test_symlink_and_excessive_permissions_rejected(self) -> None:
        """Never follow a symlink or accept a readable credential file."""
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "real"
            token.write_text("gitea_safe_dummy_long_value_123456789")
            token.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(token)
            with self.assertRaises(ValueError):
                _token(link, "pat")
            self.assertTrue(token.exists())
            token.chmod(0o644)
            with self.assertRaises(ValueError):
                _token(token, "pat")
            self.assertFalse(token.exists())

    def test_unknown_token_kind_fails_without_reading_file(self) -> None:
        """A caller cannot silently switch to an unreviewed credential scheme."""
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "token"
            p.write_text("gitea_long_example_test_token_123456")
            p.chmod(0o600)
            with self.assertRaises(ValueError):
                _token(p, "auto")
            self.assertTrue(p.exists())


if __name__ == "__main__":
    unittest.main()

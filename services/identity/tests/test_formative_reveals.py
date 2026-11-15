"""File: services/identity/tests/test_formative_reveals.py
Purpose: Focused security and transport tests for the BFF's signed-stage,
    stage-help, source-gated media index/asset and Read-first POST routes.
Related: services/identity/identity_bff/formative.py,
    services/identity/config/{urls,settings}.py, Sumlaude Native PR #366.
These tests use only synthetic identities and mock Native transport.
"""
import hashlib
import json
import os
import time
import unittest
from unittest import mock

from cryptography.fernet import Fernet

# Section: Isolated Django settings identical to existing formative tests.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_SECRET_KEY", "testonly_" + "x" * 60)
os.environ.setdefault("TOKEN_FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("PRODUCT_ORIGIN", "https://app.sumlaude.com")
os.environ.setdefault("OIDC_ISSUER", "https://login.omnilyzer.ai/realms/main")
os.environ.setdefault("OIDC_CLIENT_ID", "sumlaude-confidential")
os.environ.setdefault("OIDC_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("SUMLAUDE_ISSUER_DSN", "postgresql://unreachable")
os.environ.setdefault("IDENTITY_PG_DATABASE", "identity_disposable")
os.environ.setdefault("IDENTITY_PG_USER", "identity_qa")
os.environ.setdefault("IDENTITY_PG_PASSWORD", "test-password")
os.environ.setdefault("IDENTITY_PG_HOST", "127.0.0.1")

import django
django.setup()

from django.test import Client, SimpleTestCase, override_settings
from identity_bff import formative

COURSE = "11111111-1111-4111-8111-111111111111"
LESSON = "square-root-function"
BASE = "/api/valoria/learning/courses/" + COURSE + "/formative/" + LESSON
INDEX = BASE + "/reveals"
ASSET = INDEX + "/axes_png"
PROGRESS = BASE + "/progress"
HELP = BASE + "/help/first_step"
COOKIE = "c" * 64
DIGEST = hashlib.sha256(COOKIE.encode("ascii")).hexdigest()
PNG = b"\x89PNG\r\n\x1a\n" + b"verified test image bytes"
WEBP = b"RIFF\x18\x00\x00\x00WEBP" + b"verified test image bytes"


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    REQUIRE_GTM_ADULT_CHOICE=True,
)
class FormativeMediaTests(SimpleTestCase):
    """Exercise the genuine Django middleware, cookies and URL dispatcher."""

    def setUp(self):
        # Section: Synthetic server-side signed-principal state, never a live
        # Keycloak account, product session, or real learner data.
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        self.index_bridge = mock.patch.object(
            formative, "_forward_native_get",
            return_value=(200, {"lessonId": LESSON, "media": []}, "application/json"),
        )
        self.get_native = self.index_bridge.start()
        self.addCleanup(self.index_bridge.stop)
        self.post_bridge = mock.patch.object(
            formative, "_forward_native",
            return_value=(200, {"saved": True}),
        )
        self.post_native = self.post_bridge.start()
        self.addCleanup(self.post_bridge.stop)

    def _authenticate(self):
        """Create only mock Django session data with correct S03 cookie digest."""
        now = int(time.time())
        session = self.client.session
        session.update({
            "principal": {"issuer": "https://login.omnilyzer.ai/realms/main",
                          "sub": "synthetic-valid-subject"},
            "sealed_tokens": "synthetic-sealed",
            "absolute_deadline": now + 300,
            "last_seen": now,
            "age_choice": "adult",
            "s03_digest": DIGEST,
        })
        session.save()
        self.client.cookies["__Host-sumlaude_session"] = COOKIE

    def _get(self, path=INDEX):
        return self.client.get(path, secure=True)

    def test_anonymous_unknown_or_unpaired_identity_never_reaches_native(self):
        """Unknown/stale sessions, swapped cookies and wrong lessons fail closed."""
        self.assertEqual(self._get().status_code, 401)
        self._authenticate()
        self.client.cookies["__Host-sumlaude_session"] = "a" * 64
        self.assertEqual(self._get().status_code, 401)
        self.client.cookies["__Host-sumlaude_session"] = COOKIE
        self.assertEqual(
            self._get(INDEX.replace(LESSON, "unapproved-lesson")).status_code, 404)
        self.assertEqual(self._get(INDEX + "?next=https://other.example").status_code, 400)
        self.assertEqual(self._get(INDEX + "/not.approved").status_code, 404)
        self.assertEqual(self._get(INDEX + "/9invalid").status_code, 404)
        self.get_native.assert_not_called()

    def test_authenticated_reveals_metadata_index_is_private(self):
        """The Native index may return only source-approved neutral items."""
        self._authenticate()
        response = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"lessonId": LESSON, "media": []})
        self.assertEqual(
            self.get_native.call_args.args,
            (INDEX, COOKIE),
        )
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("private", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Cookie")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Cross-Origin-Resource-Policy"], "same-origin")

    def test_server_restricted_asset_delivers_only_passive_bytes(self):
        """An approved private image is never turned into a public/static URL."""
        self._authenticate()
        self.get_native.return_value = (200, PNG, "image/png")
        response = self._get(ASSET)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, PNG)
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Content-Security-Policy"],
                         "default-src 'none'; sandbox")
        self.get_native.assert_called_once_with(ASSET, COOKIE, asset=True)

    def test_native_gate_denial_preserved_and_not_cached(self):
        """A first-answer/Read-first lock is a Native denial, not a fallback."""
        self._authenticate()
        self.get_native.return_value = (
            403, {"message": "Formative access unavailable"}, "application/json")
        response = self._get(ASSET)
        self.assertEqual(response.status_code, 403)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn("image", response["Content-Type"])
        self.assertNotIn("set-cookie", {k.lower() for k in response.headers})

    def test_read_first_write_requires_real_session_csrf(self):
        """BFF must not accept only a forged Native X-CSRF-Token presence header."""
        self._authenticate()
        body = json.dumps({
            "action": "read-first", "stageId": "intro",
            "revision": 0, "operationId": "synthetic-operation",
        })
        denied = self.client.post(
            PROGRESS, data=body, content_type="application/json",
            secure=True, HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRF_TOKEN="any-value",
        )
        self.assertEqual(denied.status_code, 403)
        self.post_native.assert_not_called()
        token = self.client.get("/auth/csrf", secure=True).json()["csrf_token"]
        accepted = self.client.post(
            PROGRESS, data=body, content_type="application/json",
            secure=True, HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(accepted.status_code, 200)
        self.post_native.assert_called_once()
        self.assertEqual(json.loads(self.post_native.call_args.args[1])["action"],
                         "read-first")

    def test_get_does_not_permit_head(self):
        """Do not expose media size via an unreviewed HEAD route."""
        self._authenticate()
        response = self.client.head(ASSET, secure=True)
        self.assertEqual(response.status_code, 405)
        self.get_native.assert_not_called()

    def test_learner_stage_get_requires_signed_paired_session(self):
        """Current stage is private, authorized and read-only, never public."""
        self.assertEqual(self._get(BASE).status_code, 401)
        self.get_native.assert_not_called()
        self._authenticate()
        expected = {"lessonId": LESSON, "progress": {"attemptStatus": "in_progress"}}
        self.get_native.return_value = (200, expected, "application/json")
        response = self._get(BASE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        self.get_native.assert_called_once_with(BASE, COOKIE)
        self.assertIn("private", response["Cache-Control"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Cookie")
        self.assertEqual(response["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertNotIn("set-cookie", {k.lower() for k in response.headers})

    def test_stage_help_denial_and_authorized_readback(self):
        """Native persists Read-first/first answer; BFF preserves Native gate."""
        self._authenticate()
        self.get_native.return_value = (
            403, {"message": "Help locked until your first response"},
            "application/json",
        )
        before = self._get(HELP)
        self.assertEqual(before.status_code, 403)
        self.assertIn("private", before["Cache-Control"])
        self.assertIn("no-store", before["Cache-Control"])
        self.get_native.assert_called_once_with(HELP, COOKIE)
        self.get_native.reset_mock()
        self.get_native.return_value = (
            200, {"stageId": "first_step", "help": "Authorized learning cue"},
            "application/json",
        )
        after = self._get(HELP)
        self.assertEqual(after.status_code, 200)
        self.assertEqual(after.json()["stageId"], "first_step")
        self.get_native.assert_called_once_with(HELP, COOKIE)
        self.assertEqual(after["X-Content-Type-Options"], "nosniff")

    def test_stage_and_help_reject_foreign_cookie_logout_and_stale_session(self):
        """Product cookie alone cannot read without matching Django session."""
        self._authenticate()
        self.client.cookies["__Host-sumlaude_session"] = "f" * 64
        self.assertEqual(self._get(BASE).status_code, 401)
        self.assertEqual(self._get(HELP).status_code, 401)
        self.client.cookies["__Host-sumlaude_session"] = COOKIE
        other = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        other.cookies["__Host-sumlaude_session"] = COOKIE
        self.assertEqual(other.get(BASE, secure=True).status_code, 401)
        self.assertEqual(other.get(HELP, secure=True).status_code, 401)
        session = self.client.session
        session["s03_digest"] = "a" * 64
        session.save()
        self.assertEqual(self._get(BASE).status_code, 401)
        session.flush()
        self.assertEqual(self._get(HELP).status_code, 401)
        self.get_native.assert_not_called()

    def test_stage_help_id_query_method_and_lesson_bounds(self):
        """No arbitrary stage, query, unsupported source or unreviewed HEAD."""
        self._authenticate()
        for path in (
            HELP.replace("first_step", "9invalid"),
            HELP.replace("first_step", "unknown.stage"),
            HELP.replace(LESSON, "not-approved-lesson"),
            HELP + "?stageId=next",
            BASE + "?download=1",
            BASE.replace(COURSE, "not-a-uuid"),
        ):
            self.assertIn(self._get(path).status_code, (400, 404))
        self.assertEqual(self.client.head(BASE, secure=True).status_code, 405)
        self.assertEqual(self.client.head(HELP, secure=True).status_code, 405)
        # The actual CSRF middleware correctly rejects this POST even before
        # the GET-only view decorator. Either bounded denial is acceptable;
        # neither is permitted to call Native or mutate saved progression.
        self.assertIn(self.client.post(
            HELP, data="{}", content_type="application/json", secure=True,
        ).status_code, (403, 405))
        self.get_native.assert_not_called()



class MediaTransportTests(SimpleTestCase):
    """Check fixed loopback, response bounds and no active-content passthrough."""

    def _native(self, status=200, body=PNG, content_type="image/png"):
        """Construct only a synthetic http.client response and connection."""
        response = mock.Mock()
        response.status = status
        response.read.return_value = body
        response.getheader.return_value = content_type
        connection = mock.Mock()
        connection.getresponse.return_value = response
        return connection, response

    def test_binary_png_and_webp_and_fixed_request_headers(self):
        """Native alone authorizes image bytes; browser headers are never forwarded."""
        for body, mime in ((PNG, "image/png"), (WEBP, "image/webp")):
            connection, response = self._native(body=body, content_type=mime)
            with mock.patch.object(formative.http.client, "HTTPConnection",
                                   return_value=connection) as make:
                result = formative._forward_native_get(ASSET, COOKIE, asset=True)
            self.assertEqual(result, (200, body, mime))
            make.assert_called_once_with("127.0.0.1", 18741, timeout=6)
            method, path = connection.request.call_args.args[:2]
            self.assertEqual((method, path), ("GET", ASSET))
            headers = connection.request.call_args.kwargs["headers"]
            self.assertEqual(headers["Cookie"], "__Host-sumlaude_session=" + COOKIE)
            self.assertEqual(headers["Host"], "app.sumlaude.com")
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("X-CSRF-Token", headers)
            self.assertNotIn("X-Forwarded-For", headers)
            self.assertNotIn("__Host-omnilyzer_identity", str(headers))
            connection.close.assert_called_once()

    def test_index_json_and_native_denial_are_bounded(self):
        """Index and denial bodies must remain JSON and preserve Native status."""
        for status in (200, 403):
            content = {"media": []} if status == 200 else {"message": "denied"}
            connection, response = self._native(
                status=status, body=json.dumps(content).encode(),
                content_type="application/json")
            with mock.patch.object(formative.http.client, "HTTPConnection",
                                   return_value=connection):
                self.assertEqual(formative._forward_native_get(INDEX, COOKIE),
                                 (status, content, "application/json"))

    def test_s03_approved_private_binary_exact_sql_boundary(self):
        """Allow exact S03 migration108 BYTEA 2,500,000 and deny 2,500,001.

        The response is synthetic; the source-pinned Native image SHA,
        enrollment and Read-first decision remain authoritative in S03.
        """
        self.assertEqual(formative._MEDIA_LIMIT, 2_500_000)
        for size, permitted in ((2_500_000, True), (2_500_001, False)):
            body = b"\x89PNG\r\n\x1a\n" + b"x" * (size - 8)
            connection, native = self._native(
                status=200, body=body, content_type="image/png")
            with mock.patch.object(
                formative.http.client, "HTTPConnection",
                return_value=connection,
            ):
                result = formative._forward_native_get(
                    ASSET, COOKIE, asset=True)
            self.assertEqual(result == (200, body, "image/png"), permitted)
            native.read.assert_called_once_with(2_500_001)
            connection.close.assert_called_once()

    def test_html_svg_redirect_and_oversized_response_never_pass(self):
        """Reject execution-capable MIME, redirects, and oversized image buffers."""
        for status, mime, body in (
            (200, "text/html", b"<html>unsafe</html>"),
            (200, "image/svg+xml", b"<svg/>"),
            (302, "image/png", PNG),
            (200, "image/png", b"not-a-png"),
            (200, "image/png", b"x" * (formative._MEDIA_LIMIT + 1)),
            (200, "text/plain", b"\xff"),
        ):
            connection, response = self._native(
                status=status, content_type=mime, body=body)
            with mock.patch.object(formative.http.client, "HTTPConnection",
                                   return_value=connection):
                self.assertIsNone(formative._forward_native_get(
                    ASSET, COOKIE, asset=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)

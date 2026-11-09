"""File: services/identity/tests/test_formative_csrf.py
Purpose: Focused signed-session, CSRF, cookie-pairing and Native forwarding
    tests for the existing shared Keycloak Django browser BFF.
Related: services/identity/identity_bff/formative.py,
    services/identity/config/{settings,urls}.py,
    services/identity/tests/test_identity.py, Sumlaude PR #366.
No production secrets, DB writes, browser bearer tokens or new test framework.
"""
import hashlib
import json
import os
import unittest
from unittest import mock

from cryptography.fernet import Fernet

# Section: Identical isolated source-test configuration used by test_identity.
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

from django.conf import settings
from django.test import Client, SimpleTestCase, override_settings
from identity_bff import formative, issuer, oidc


COURSE = "11111111-1111-4111-8111-111111111111"
ROUTE = ("/api/valoria/learning/courses/" + COURSE +
         "/formative/square-root-function/progress")
COOKIE = "b" * 64
DIGEST = hashlib.sha256(COOKIE.encode("ascii")).hexdigest()


def _tokens():
    """Fixture values remain solely in memory and never access Keycloak."""
    return {"access_token": "fake-access", "refresh_token": "fake-refresh",
            "id_token": "fake-signed-id", "expires_in": 120}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    REQUIRE_GTM_ADULT_CHOICE=False,
)
class FormativeSessionCsrfTests(SimpleTestCase):
    """Use real Django middleware, including CSRF_USE_SESSIONS and cookies."""

    def setUp(self):
        self.assertTrue(settings.CSRF_USE_SESSIONS)
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        self.patches = [
            mock.patch.object(oidc, "authorize", return_value="https://login.omnilyzer.ai/auth"),
            mock.patch.object(oidc, "exchange", return_value=_tokens()),
            mock.patch.object(oidc, "verify_id", return_value={
                "issuer": settings.OIDC_ISSUER, "sub": "signed-known-subject"}),
            mock.patch.object(issuer, "issue", return_value=(COOKIE, DIGEST)),
            mock.patch.object(issuer, "revoke", return_value=True),
            mock.patch.object(oidc, "revoke_provider", return_value=True),
        ]
        self.mocks = [p.start() for p in self.patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])
        self.bridge = mock.patch.object(
            formative, "_forward_native", return_value=(200, {"saved": True}))
        self.forward = self.bridge.start()
        self.addCleanup(self.bridge.stop)

    def _login(self, client=None):
        """Complete the existing confidential callback with mocked provider."""
        c = client or self.client
        self.assertEqual(c.get("/auth/login", secure=True).status_code, 302)
        state = c.session["transaction"]["state"]
        response = c.get("/auth/callback?state=" + state + "&code=fixture", secure=True)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(c.get("/auth/session", secure=True).json()["authenticated"], True)

    def _csrf(self, client=None):
        c = client or self.client
        response = c.get("/auth/csrf", secure=True)
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def _post(self, token=None, client=None, path=ROUTE, origin="https://app.sumlaude.com", extra=None):
        c = client or self.client
        headers = {"HTTP_ORIGIN": origin}
        if token is not None:
            headers["HTTP_X_CSRFTOKEN"] = token
        if extra:
            headers.update(extra)
        return c.post(path, data=json.dumps({"operationId": "fixture"}),
                      content_type="application/json", secure=True, **headers)

    def test_signed_session_valid_token_and_native_cookie_only(self):
        """Positive OIDC session, matching session CSRF and SHA-paired S03 cookie."""
        self._login()
        csrf = self._csrf()
        # The secret exists only in Django's server-held session, not a
        # browser-readable independent double-submit CSRF cookie.
        self.assertIn("_csrftoken", self.client.session)
        self.assertNotIn("csrftoken", self.client.cookies)
        response = self._post(csrf)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"saved": True})
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.forward.assert_called_once()
        upstream, body, cookie, token = self.forward.call_args.args
        self.assertEqual(upstream, ROUTE)
        self.assertEqual(json.loads(body), {"operationId": "fixture"})
        self.assertEqual(cookie, COOKIE)
        self.assertEqual(token, csrf)
        self.assertNotIn("access_token", response.content.decode())

    def test_missing_wrong_and_arbitrary_native_header_denied(self):
        """A mere X-CSRF-Token or a random X-CSRFToken cannot pass Django."""
        self._login()
        self.assertEqual(self._post().status_code, 403)
        self.assertEqual(self._post("X" * 64).status_code, 403)
        self.assertEqual(self._post(extra={"HTTP_X_CSRF_TOKEN": "not-verified"}).status_code, 403)
        self.forward.assert_not_called()

    def test_other_account_csrf_denied_even_with_matching_product_cookie(self):
        """Django's server-held CSRF secret is bound to each OIDC session."""
        self._login()
        other = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        self._login(other)
        other_token = self._csrf(other)
        self.assertEqual(self._post(other_token).status_code, 403)
        self.assertEqual(self._post(self._csrf()).status_code, 200)
        self.assertEqual(self.forward.call_count, 1)

    def test_revoked_or_unpaired_product_session_cannot_forward(self):
        """Expired/login-lost identity and a swapped S03 cookie fail closed."""
        self._login()
        token = self._csrf()
        self.client.cookies["__Host-sumlaude_session"] = "a" * 64
        self.assertEqual(self._post(token).status_code, 401)
        self.client.cookies["__Host-sumlaude_session"] = COOKIE
        self.assertEqual(self._post(token).status_code, 200)
        logout_token = self._csrf()
        self.assertEqual(self.client.post("/auth/logout", secure=True,
            HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRFTOKEN=logout_token).status_code, 200)
        self.assertNotEqual(self._post(token).status_code, 200)
        self.assertEqual(self.forward.call_count, 1)

    def test_cross_origin_and_unapproved_lesson_denied(self):
        """Foreign Origin is rejected before proxy; no arbitrary lesson proxy."""
        self._login()
        token = self._csrf()
        self.assertEqual(self._post(token, origin="https://evil.example").status_code, 403)
        wrong = ROUTE.replace("square-root-function", "not-approved-lesson")
        self.assertEqual(self._post(token, path=wrong).status_code, 404)
        self.forward.assert_not_called()

    def test_anonymous_with_valid_session_csrf_still_cannot_mutate(self):
        """Obtaining a prelogin CSRF token does not confer a learner session."""
        token = self._csrf()
        self.assertEqual(self._post(token).status_code, 401)
        self.forward.assert_not_called()


class FormativeForwardingTests(unittest.TestCase):
    """Bound exact internal Native transport, no upstream redirects or cookies."""

    def test_only_fixed_loopback_uri_and_product_cookie_forwarded(self):
        response = mock.Mock()
        response.status = 200
        response.getheader.return_value = "application/json"
        response.read.return_value = b'{"saved":true}'
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(formative.http.client, "HTTPConnection",
                               return_value=connection) as maker:
            result = formative._forward_native(ROUTE, b"{}", COOKIE, "session-csrf")
        self.assertEqual(result, (200, {"saved": True}))
        maker.assert_called_once_with("127.0.0.1", 18741, timeout=6)
        method, path = connection.request.call_args.args[:2]
        self.assertEqual((method, path), ("POST", ROUTE))
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Cookie"], "__Host-sumlaude_session=" + COOKIE)
        self.assertEqual(headers["X-CSRF-Token"], "session-csrf")
        self.assertEqual(headers["Origin"], "https://app.sumlaude.com")
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("__Host-omnilyzer_identity", str(headers))
        connection.close.assert_called_once()

    def test_native_redirect_and_oversized_response_fail_closed(self):
        response = mock.Mock()
        response.status = 302
        response.getheader.return_value = "text/html"
        response.read.return_value = b"redirect"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(formative.http.client, "HTTPConnection",
                               return_value=connection):
            self.assertIsNone(formative._forward_native(ROUTE, b"{}", COOKIE, "token"))
        response.status = 200
        response.getheader.return_value = "application/json"
        response.read.return_value = b"X" * (formative._RESPONSE_LIMIT + 1)
        with mock.patch.object(formative.http.client, "HTTPConnection",
                               return_value=connection):
            self.assertIsNone(formative._forward_native(ROUTE, b"{}", COOKIE, "token"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""File: services/identity/tests/test_canonical_public_host.py

Purpose: Validate the explicit second HTTPS hostname for canonical public
    lessons without widening existing app cookies, Keycloak redirects, Django
    CSRF, session origin or the downstream Native student authorization.
Related: config/{settings,urls}.py, identity_bff/{views,oidc,formative}.py,
    tests/{test_identity,test_formative_csrf,test_adult_age_choice}.py,
    Sumlaude S01 PR364 and S05 public NGINX/CSP release contract.

All credentials/learners are synthetic; no live identity or database is read.
"""
import hashlib
import json
import os
import unittest
from urllib.parse import parse_qs, urlparse
from unittest import mock

from cryptography.fernet import Fernet

# Section: Keep the existing accepted private app BFF configuration as baseline.
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
from identity_bff import formative, oidc, issuer
from identity_bff.oidc import authorize as real_authorize, exchange as real_exchange

PUBLIC = "https://sumlaude.com"
APP = "https://app.sumlaude.com"
MATH = "/learn/math/square-root-function/"
SCIENCE = "/learn/science/why-earth-supports-life/"
COOKIE = "b" * 64
DIGEST = hashlib.sha256(COOKIE.encode()).hexdigest()
COURSE = "11111111-1111-4111-8111-111111111111"
PROGRESS = ("/api/valoria/learning/courses/" + COURSE
            + "/formative/square-root-function/progress")


def _tokens():
    """Use OIDC-like fields with no actual provider token or user."""
    return {"access_token": "synthetic-access", "id_token": "synthetic-id",
            "refresh_token": "synthetic-refresh", "expires_in": 300}


def _principal():
    """Synthetic verified principal for isolated issuance only."""
    return {"issuer": settings.OIDC_ISSUER, "sub": "synthetic-adult-user"}


# Section: Enable only the second host in these tests; the real release flag
# defaults to OFF and must remain OFF in production without release approval.
@override_settings(
    CANONICAL_AUTH_ENABLED=True,
    ALLOWED_HOSTS=["app.sumlaude.com", "sumlaude.com"],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    REQUIRE_GTM_ADULT_CHOICE=True,
)
class CanonicalPublicHostTests(SimpleTestCase):
    """Check both OIDC origin binding and learner API preservation."""

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="sumlaude.com")
        patchers = [
            mock.patch.object(oidc, "authorize", return_value="https://login.omnilyzer.ai/realms/main/auth"),
            mock.patch.object(oidc, "exchange", return_value=_tokens()),
            mock.patch.object(oidc, "verify_id", return_value=_principal()),
            mock.patch.object(oidc, "refresh", return_value=_tokens()),
            mock.patch.object(issuer, "issue", return_value=(COOKIE, DIGEST)),
            mock.patch.object(issuer, "revoke", return_value=True),
            mock.patch.object(oidc, "revoke_provider", return_value=True),
        ]
        self.patched = [p.start() for p in patchers]
        for patcher in reversed(patchers):
            self.addCleanup(patcher.stop)

    def get(self, path, **headers):
        return self.client.get(path, secure=True, **headers)

    def csrf(self):
        response = self.get("/auth/csrf")
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def login_pending(self, *, path=MATH):
        """Cross a synthetic state-bound callback, still without S03 cookie."""
        self.assertEqual(self.get("/auth/login?next=" + path).status_code, 302)
        txn = self.client.session["transaction"]
        self.assertEqual(txn["origin"], PUBLIC)
        self.assertEqual(txn["return_path"], path)
        self.assertEqual(self.patched[0].call_args.kwargs["redirect_uri"],
                         PUBLIC + "/auth/callback")
        callback = self.get("/auth/callback?state=" + txn["state"] + "&code=fake")
        self.assertEqual(callback.status_code, 302)
        self.assertEqual(callback["Location"], path)
        self.assertEqual(self.patched[1].call_args.kwargs["redirect_uri"],
                         PUBLIC + "/auth/callback")
        self.assertEqual(self.client.session["session_origin"], PUBLIC)
        self.assertNotIn("s03_digest", self.client.session)
        self.assertEqual(callback.cookies["__Host-sumlaude_session"]["max-age"], 0)
        return callback

    def adult(self):
        """Require a second CSRF-checked step and new signed S03 pair."""
        self.login_pending()
        pending_csrf = self.csrf()
        result = self.client.post(
            "/auth/age-choice", secure=True, content_type="application/json",
            data=json.dumps({"ageBand": "adult"}),
            HTTP_ORIGIN=PUBLIC, HTTP_X_CSRFTOKEN=pending_csrf,
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["productAuthorized"], "check-S03")
        self.assertEqual(result.cookies["__Host-sumlaude_session"]["domain"], "")
        self.assertTrue(result.cookies["__Host-sumlaude_session"]["httponly"])
        self.assertTrue(result.cookies["__Host-sumlaude_session"]["secure"])
        self.assertEqual(self.get("/auth/session").json()["authenticated"], True)
        return pending_csrf

    def test_anonymous_static_host_get_cannot_claim_product_authority(self):
        """No product session is created merely by hosting a public lesson."""
        self.assertEqual(self.get("/auth/session").json(), {"authenticated": False})
        self.assertEqual(self.get("/api/valoria/context").status_code, 401)

    def test_host_port_and_forwarded_host_spoof_rejected(self):
        """No dynamic browser-controlled callback host or alternate port."""
        self.assertEqual(self.get("/auth/session", HTTP_HOST="sumlaude.com:8443").status_code, 400)
        self.assertEqual(self.get("/auth/login", HTTP_HOST="attacker.example").status_code, 400)
        self.assertEqual(self.get("/auth/login", HTTP_X_FORWARDED_HOST="attacker.example").status_code, 302)
        self.assertEqual(self.client.session["transaction"]["origin"], PUBLIC)

    def test_login_callback_exact_host_and_return_path(self):
        """Private session never becomes public merely by changing Host."""
        self.login_pending(path=SCIENCE)
        self.assertEqual(self.get("/auth/session").json()["productAuthorized"],
                         "adult-choice-required")

    def test_cross_host_callback_denied_before_code_exchange(self):
        """Do not exchange Keycloak code on the wrong sibling hostname."""
        self.assertEqual(self.get("/auth/login?next=" + MATH).status_code, 302)
        state = self.client.session["transaction"]["state"]
        response = self.get("/auth/callback?state=" + state + "&code=fake",
                            HTTP_HOST="app.sumlaude.com")
        self.assertEqual(response.status_code, 400)
        self.patched[1].assert_not_called()

    def test_open_redirect_in_next_query_denied(self):
        """No external URL, protocol-relative path or arbitrary private route."""
        for value in ("https://attacker.example/", "//attacker.example",
                      "/auth/logout", "/learn/math/other/"):
            response = self.get("/auth/login?next=" + value)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(self.client.session["transaction"]["return_path"],
                             "/learn/")

    def test_session_cookie_copied_to_other_host_denied(self):
        """Even a synthetically replayed cookie cannot cross product origins."""
        self.adult()
        self.assertEqual(self.get(
            "/auth/session", HTTP_HOST="app.sumlaude.com").json(),
            {"authenticated": False})
        self.assertEqual(self.get(
            "/auth/session", HTTP_HOST="sumlaude.com").json()["authenticated"],
            True)

    def test_public_under18_declines_native_issuance(self):
        """A self-declared minor receives no native student authorization."""
        self.login_pending()
        pending = self.csrf()
        response = self.client.post(
            "/auth/age-choice", secure=True, content_type="application/json",
            data=json.dumps({"ageBand": "under18"}),
            HTTP_ORIGIN=PUBLIC, HTTP_X_CSRFTOKEN=pending)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["productAuthorized"], "adult-pilot-denied")
        self.assertNotIn("s03_digest", self.client.session)
        self.patched[4].assert_not_called()

    def test_actual_provider_redirect_and_code_exchange_use_same_exact_uri(self):
        """Verify actual OAuth parameters, not only mocked Django call arguments."""
        endpoint = settings.OIDC_ISSUER + "/protocol/openid-connect/auth"
        with mock.patch.object(oidc, "metadata",
                               return_value={"authorization_endpoint": endpoint}):
            uri = real_authorize("state", "nonce", "challenge",
                                 redirect_uri=PUBLIC + "/auth/callback")
            self.assertEqual(parse_qs(urlparse(uri).query)["redirect_uri"],
                             [PUBLIC + "/auth/callback"])
        with (mock.patch.object(oidc, "metadata", return_value={
                "token_endpoint": settings.OIDC_ISSUER + "/protocol/openid-connect/token"}),
              mock.patch.object(oidc, "_provider", return_value=_tokens()) as provider):
            real_exchange("code", "verifier",
                          redirect_uri=PUBLIC + "/auth/callback")
        self.assertEqual(provider.call_args.kwargs["form"]["redirect_uri"],
                         PUBLIC + "/auth/callback")
        with self.assertRaises(oidc.IdentityError):
            real_exchange("code", "verifier",
                          redirect_uri="https://attacker.example/auth/callback")
        with override_settings(CANONICAL_AUTH_ENABLED=False):
            with self.assertRaises(oidc.IdentityError):
                real_authorize("state", "nonce", "challenge",
                               redirect_uri=PUBLIC + "/auth/callback")

    def test_public_origin_csrf_must_match_host_and_rotates_after_choice(self):
        """Django CSRF plus exact public origin, not app trusted-origin bypass."""
        old = self.adult()
        self.assertEqual(self.client.post(
            "/auth/logout", secure=True, HTTP_ORIGIN=PUBLIC,
            HTTP_X_CSRFTOKEN=old).status_code, 403)
        new = self.csrf()
        self.assertEqual(self.client.post(
            "/auth/logout", secure=True, HTTP_ORIGIN=APP,
            HTTP_X_CSRFTOKEN=new).status_code, 403)
        self.assertEqual(self.client.post(
            "/auth/logout", secure=True, HTTP_ORIGIN=PUBLIC,
            HTTP_X_CSRFTOKEN=new).status_code, 200)

    def test_public_context_uses_only_paired_cookie_fixed_native(self):
        """One Native context is forwarded without auth/browser headers."""
        self.adult()
        with mock.patch.object(formative, "_forward_native_get", return_value=(
                200, {"active": {"courses": []}}, "application/json")) as forwarded:
            result = self.get("/api/valoria/context")
        self.assertEqual(result.status_code, 200)
        self.assertIn("no-store", result["Cache-Control"])
        self.assertIn("Cookie", result["Vary"])
        forwarded.assert_called_once_with("/api/valoria/context", COOKIE)

    def test_public_context_wrong_cookie_or_query_or_head_denied(self):
        """A stolen foreign Native cookie cannot read another learner context."""
        self.adult()
        self.client.cookies["__Host-sumlaude_session"] = "d" * 64
        with mock.patch.object(formative, "_forward_native_get") as forwarded:
            self.assertEqual(self.get("/api/valoria/context").status_code, 401)
            self.assertEqual(self.get("/api/valoria/context?other=1").status_code, 400)
            self.assertEqual(self.client.head("/api/valoria/context", secure=True).status_code, 405)
        forwarded.assert_not_called()

    def test_public_formative_progress_is_django_csrf_validated(self):
        """Server-checked POST uses only S03 cookie, no frontend bearer token."""
        old_csrf = self.adult()
        with mock.patch.object(formative, "_forward_native",
                               return_value=(200, {"saved": True})) as forward:
            self.assertEqual(self.client.post(
                PROGRESS, secure=True, content_type="application/json",
                data=json.dumps({"operationId": "synthetic"}),
                HTTP_ORIGIN=PUBLIC, HTTP_X_CSRFTOKEN=old_csrf).status_code, 403)
            new = self.csrf()
            self.assertEqual(self.client.post(
                PROGRESS, secure=True, content_type="application/json",
                data=json.dumps({"operationId": "synthetic"}),
                HTTP_ORIGIN=APP, HTTP_X_CSRFTOKEN=new).status_code, 403)
            result = self.client.post(
                PROGRESS, secure=True, content_type="application/json",
                data=json.dumps({"operationId": "synthetic"}),
                HTTP_ORIGIN=PUBLIC, HTTP_X_CSRFTOKEN=new)
            self.assertEqual(result.status_code, 200)
            self.assertTrue(result.json()["saved"])
            forward.assert_called_once()
            self.assertEqual(forward.call_args.args[2], COOKIE)

    @override_settings(CANONICAL_AUTH_ENABLED=False, ALLOWED_HOSTS=["app.sumlaude.com"])
    def test_public_feature_off_is_denied_without_host_override(self):
        """Default disabled host cannot activate by a crafted request header."""
        self.assertEqual(self.get("/auth/session").status_code, 400)
        self.assertEqual(self.get("/auth/login").status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)

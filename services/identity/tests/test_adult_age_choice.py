"""File: services/identity/tests/test_adult_age_choice.py
Purpose: Genuine server-side age-band choice transaction and persistence
    failure scenarios using isolated mocks only, including session-bound CSRF.
Related: services/identity/identity_bff/views.py,
    services/identity/config/settings.py, test_formative_csrf.py.
No fake age document, real admission, or automatic learner enrolment.
"""
import json
import os
import time
import unittest
from unittest import mock

from cryptography.fernet import Fernet

os.environ.update({
    "DJANGO_SETTINGS_MODULE": "config.settings",
    "DJANGO_SECRET_KEY": "testonly_" + ("a" * 60),
    "TOKEN_FERNET_KEY": Fernet.generate_key().decode(),
    "PRODUCT_ORIGIN": "https://app.sumlaude.com",
    "OIDC_ISSUER": "https://login.omnilyzer.ai/realms/main",
    "OIDC_CLIENT_ID": "sumlaude-confidential",
    "OIDC_CLIENT_SECRET": "test-client-secret",
    "SUMLAUDE_ISSUER_DSN": "postgresql://unreachable",
    "IDENTITY_PG_DATABASE": "identity_disposable",
    "IDENTITY_PG_USER": "identity_qa",
    "IDENTITY_PG_PASSWORD": "test-password",
    "IDENTITY_PG_HOST": "127.0.0.1",
})
import django
django.setup()
from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.backends.cache import SessionStore
from django.test import Client, SimpleTestCase, override_settings
from identity_bff import oidc, issuer


def values():
    return {"access_token": "opaque-access", "id_token": "signed-id",
            "refresh_token": "opaque-refresh", "expires_in": 300}


def trusted():
    return {"issuer": settings.OIDC_ISSUER, "sub": "known-verified-subject"}


@override_settings(
    REQUIRE_GTM_ADULT_CHOICE=True,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AdultChoiceGatewayTests(SimpleTestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        self.patches = [
            mock.patch.object(oidc, "authorize", return_value="https://login.omnilyzer.ai/auth?state=test"),
            mock.patch.object(oidc, "exchange", return_value=values()),
            mock.patch.object(oidc, "verify_id", return_value=trusted()),
            mock.patch.object(oidc, "refresh", return_value=values()),
            mock.patch.object(oidc, "revoke_provider", return_value=True),
            mock.patch.object(issuer, "issue", return_value=("b" * 64, "c" * 64)),
            mock.patch.object(issuer, "revoke", return_value=True),
        ]
        self.mocks = [patch.start() for patch in self.patches]
        for patch in reversed(self.patches):
            self.addCleanup(patch.stop)

    def get(self, target):
        return self.client.get(target, secure=True)

    def csrf(self):
        result = self.get("/auth/csrf")
        self.assertEqual(result.status_code, 200)
        return result.json()["csrf_token"]

    def post(self, choice="adult", *, csrf=True, origin="https://app.sumlaude.com",
             body=None, content_type="application/json", csrf_token=None):
        args = {"HTTP_ORIGIN": origin}
        if csrf:
            args["HTTP_X_CSRFTOKEN"] = csrf_token if csrf_token is not None else self.csrf()
        return self.client.post(
            "/auth/age-choice",
            data=json.dumps({"ageBand": choice}) if body is None else body,
            content_type=content_type, secure=True, **args,
        )

    def login_identity_only(self):
        self.assertEqual(self.get("/auth/login").status_code, 302)
        state = self.client.session["transaction"]["state"]
        result = self.get("/auth/callback?state=" + state + "&code=one-time-code")
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result["Location"], "/professional/gtm-001")
        return result

    def test_no_s03_cookie_or_session_before_any_age_declaration(self):
        result = self.login_identity_only()
        # Callback explicitly expires any pre-existing private product cookie.
        self.assertEqual(result.cookies["__Host-sumlaude_session"]["max-age"], 0)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.get("/auth/session").json(), {
            "authenticated": True, "productAuthorized": "adult-choice-required"})
        self.assertNotIn("sub", self.get("/auth/session").content.decode())
        self.assertNotIn("opaque-refresh", str(dict(self.client.session)))
        self.assertNotIn("s03_digest", self.client.session)
        self.assertEqual(self.get("/auth/refresh").status_code, 405)

    def test_age_post_without_real_identity_denied(self):
        self.assertEqual(self.post().status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.get("/auth/session").json(), {"authenticated": False})

    def test_csrf_and_origin_protect_age_post(self):
        self.login_identity_only()
        self.assertEqual(self.post(csrf=False).status_code, 403)
        self.assertEqual(self.post(origin="https://attacker.example").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_under18_blocks_private_pilot_and_cannot_be_upgraded_in_same_session(self):
        self.login_identity_only()
        result = self.post("under18")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["productAuthorized"], "adult-pilot-denied")
        self.assertNotIn("__Host-sumlaude_session", result.cookies)
        self.assertEqual(self.get("/auth/session").json(), {
            "authenticated": True, "productAuthorized": "adult-pilot-denied"})
        self.assertEqual(self.post("adult").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.post("under18").status_code, 403)

    def test_adult_choice_rotates_csrf_before_product_authorized_writes(self):
        """The pending identity token cannot authorize a post-admission logout."""
        self.login_identity_only()
        pending_token = self.csrf()
        before_secret = self.client.session["_csrftoken"]
        result = self.post("adult", csrf_token=pending_token)
        self.assertEqual(result.status_code, 200)
        self.assertNotEqual(self.client.session["_csrftoken"], before_secret)
        self.assertEqual(self.client.post(
            "/auth/logout", secure=True,
            HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRFTOKEN=pending_token,
        ).status_code, 403)
        self.assertEqual(self.client.post(
            "/auth/logout", secure=True,
            HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRFTOKEN=self.csrf(),
        ).status_code, 200)

    def test_under18_choice_rotates_identity_csrf_secret(self):
        """The adult-pilot denial also invalidates previous pending CSRF."""
        self.login_identity_only()
        pending_token = self.csrf()
        before_secret = self.client.session["_csrftoken"]
        self.assertEqual(
            self.post("under18", csrf_token=pending_token).status_code, 200)
        self.assertNotEqual(self.client.session["_csrftoken"], before_secret)
        self.assertEqual(self.post("adult", csrf_token=pending_token).status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_normal_adult_only_issues_product_cookie_after_s03_guard(self):
        self.login_identity_only()
        result = self.post("adult")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {
            "authenticated": True, "productAuthorized": "check-S03",
            "adultDeclared": True, "csrfResetRequired": True})
        cookie = result.cookies["__Host-sumlaude_session"]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.mocks[5].assert_called_once_with(trusted())
        self.assertEqual(self.get("/auth/session").json(), {
            "authenticated": True, "productAuthorized": "check-S03"})
        self.assertEqual(self.client.session["age_choice"], "adult")
        self.assertEqual(self.post("adult").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 1)

    def test_invalid_or_extra_fields_and_oversized_request_denied(self):
        self.login_identity_only()
        for body in [
            "{}", '{"ageBand":"true"}', '{"ageBand":"adult","sub":"forged"}',
            '{"ageBand":"adult","email":"admin@example.invalid"}',
            '{"ageBand":"adult","publisher":true}',
            '{"ageBand":"adult"' ,
            json.dumps({"ageBand": "adult", "extra": "x" * 200}),
        ]:
            with self.subTest(body=body[:30]):
                self.assertEqual(self.post(body=body).status_code, 400)
        self.assertEqual(self.post(body="ageBand=adult",
                                   content_type="application/x-www-form-urlencoded").status_code, 400)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_absent_adult_or_course_admission_stays_identity_only(self):
        self.login_identity_only()
        self.mocks[5].side_effect = issuer.AdmissionError("S03 denies missing admission")
        result = self.post("adult")
        self.assertEqual(result.status_code, 403)
        self.assertNotIn("__Host-sumlaude_session", result.cookies)
        self.assertEqual(self.client.session["age_choice"], "pending")
        self.assertEqual(self.get("/auth/session").json()["productAuthorized"],
                         "adult-choice-required")

    def test_changed_signed_subject_or_provider_outage_denied(self):
        self.login_identity_only()
        self.mocks[2].return_value = {"issuer": settings.OIDC_ISSUER,
                                      "sub": "different-person-sub"}
        self.assertEqual(self.post("adult").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertNotIn("s03_digest", self.client.session)

    def test_persist_failure_revokes_exact_issued_s03_digest(self):
        self.login_identity_only()
        original = SessionStore.save

        def fail_update(store, must_create=False):
            if must_create:
                return original(store, must_create=True)
            raise UpdateError("synthetic session storage outage")

        # Session-bound CSRF must be persisted BEFORE deliberately failing
        # all session updates. Otherwise this test only checks token issuance.
        csrf_token = self.csrf()
        with mock.patch.object(SessionStore, "save", fail_update):
            result = self.post("adult", csrf_token=csrf_token)
        self.assertEqual(result.status_code, 503)
        self.mocks[6].assert_called_once_with("c" * 64)
        self.assertEqual(result.cookies["__Host-sumlaude_session"]["max-age"], 0)
        self.assertEqual(result.cookies["__Host-omnilyzer_identity"]["max-age"], 0)

    def test_expired_or_missing_session_cannot_issue_native(self):
        self.login_identity_only()
        session = self.client.session
        session["absolute_deadline"] = int(time.time()) - 1
        session.save()
        self.assertEqual(self.post("adult").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.get("/auth/session").json(), {"authenticated": False})

    def test_after_login_logout_revokes_bff_and_native(self):
        self.login_identity_only()
        self.assertEqual(self.post("adult").status_code, 200)
        csrf = self.csrf()
        result = self.client.post("/auth/logout", secure=True,
            HTTP_ORIGIN="https://app.sumlaude.com",
            HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(result.status_code, 200)
        self.mocks[6].assert_called_once_with("c" * 64)
        self.assertEqual(self.get("/auth/session").json(), {"authenticated": False})

    def test_identity_routes_no_store_in_pending_and_adult(self):
        self.login_identity_only()
        results=[self.get("/auth/session"),self.get("/auth/csrf"),
                 self.post("adult")]
        for result in results:
            self.assertIn("no-store", result.headers.get("Cache-Control",""))
            self.assertIn("private",result.headers.get("Cache-Control",""))

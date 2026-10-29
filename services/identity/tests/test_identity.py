"""Self-contained authentication lifecycle tests, no production DB/Keycloak."""
import os
import time
import unittest
from unittest import mock

from cryptography.fernet import Fernet

os.environ.update({
    "DJANGO_SETTINGS_MODULE": "config.settings",
    "DJANGO_SECRET_KEY": "testonly_" + ("x" * 60),
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
from django.test import Client, SimpleTestCase, override_settings
from identity_bff import oidc, issuer


def tokens():
    return {"access_token": "opaque-access", "id_token": "signed-id",
            "refresh_token": "opaque-refresh", "expires_in": 300}


def principal():
    return {"issuer": settings.OIDC_ISSUER, "sub": "known-verified-subject"}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class IdentityRouteTests(SimpleTestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True, HTTP_HOST="app.sumlaude.com")
        self.patches = [
            mock.patch.object(oidc, "authorize", return_value="https://login.omnilyzer.ai/auth?state=test"),
            mock.patch.object(oidc, "exchange", return_value=tokens()),
            mock.patch.object(oidc, "verify_id", return_value=principal()),
            mock.patch.object(oidc, "refresh", return_value=tokens()),
            mock.patch.object(oidc, "revoke_provider", return_value=True),
            mock.patch.object(issuer, "issue", return_value=("b" * 64, "c" * 64)),
            mock.patch.object(issuer, "revoke", return_value=True),
        ]
        self.mocks = [patch.start() for patch in self.patches]

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def get(self, route):
        return self.client.get(route, secure=True)

    def csrf(self):
        result = self.get("/auth/csrf")
        self.assertEqual(result.status_code, 200)
        return result.json()["csrf_token"]

    def post(self, route, *, csrf=True):
        headers = {"HTTP_ORIGIN": "https://app.sumlaude.com"}
        if csrf:
            headers["HTTP_X_CSRFTOKEN"] = self.csrf()
        return self.client.post(route, secure=True, **headers)

    def login(self):
        self.assertEqual(self.get("/auth/login").status_code, 302)
        state = self.client.session["transaction"]["state"]
        result = self.get("/auth/callback?state=" + state + "&code=one-time-code")
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result["Location"], "/start")
        self.assertTrue(result.cookies["__Host-sumlaude_session"]["secure"])
        self.assertTrue(result.cookies["__Host-sumlaude_session"]["httponly"])
        self.assertEqual(result.cookies["__Host-sumlaude_session"]["samesite"], "Lax")

    def test_one_use_state_pkce_and_verified_issuance(self):
        self.assertEqual(self.get("/auth/login").status_code, 302)
        self.assertEqual(self.get("/auth/callback?state=wrong&code=abc").status_code, 400)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.login()
        self.assertEqual(self.get("/auth/session").json()["authenticated"], True)
        self.assertNotIn("subject", self.get("/auth/session").json())
        self.assertNotIn("refresh_token", self.get("/auth/session").content.decode())
        self.assertNotIn("access_token", self.get("/auth/session").content.decode())
        self.assertNotIn("id_token", self.get("/auth/session").content.decode())
        session = self.client.session
        self.assertIn("sealed_tokens", session)
        self.assertNotIn("opaque-refresh", str(dict(session)))
        self.assertEqual(self.get("/auth/callback?state=wrong&code=abc").status_code, 400)

    def test_reject_unapproved_s03_learner(self):
        self.mocks[5].side_effect = issuer.AdmissionError("unapproved")
        self.assertEqual(self.get("/auth/login").status_code, 302)
        state = self.client.session["transaction"]["state"]
        result = self.get("/auth/callback?state=" + state + "&code=abc")
        self.assertEqual(result.status_code, 403)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)
        self.assertNotIn("__Host-sumlaude_session", result.cookies)

    def test_refresh_csrf_old_digest_revocation_and_product_rotation(self):
        self.login()
        self.assertEqual(self.post("/auth/refresh", csrf=False).status_code, 403)
        self.assertEqual(self.post("/auth/refresh").status_code, 200)
        self.assertGreaterEqual(self.mocks[6].call_count, 1)
        self.assertEqual(self.mocks[5].call_count, 2)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], True)

    def test_failed_refresh_revokes_session_and_rejects_user(self):
        self.login()
        self.mocks[3].side_effect = oidc.IdentityError("refused")
        self.assertEqual(self.post("/auth/refresh").status_code, 401)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)

    def test_logout_revokes_product_and_session(self):
        self.login()
        self.assertEqual(self.post("/auth/logout", csrf=False).status_code, 403)
        self.assertEqual(self.post("/auth/logout").status_code, 200)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)
        self.assertEqual(self.mocks[6].call_count, 1)
        self.assertEqual(self.mocks[4].call_count, 1)

    def test_revoke_unavailable_never_says_logout_success(self):
        self.login()
        self.mocks[6].side_effect = issuer.AdmissionError("network down")
        self.assertEqual(self.post("/auth/logout").status_code, 503)

    def test_expired_idle_or_absolute_session_not_authenticated(self):
        self.login()
        session = self.client.session
        session["absolute_deadline"] = int(time.time()) - 1
        session.save()
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)

    def test_refresh_subject_changed_does_not_issue(self):
        self.login()
        self.mocks[2].side_effect = oidc.IdentityError("subject switched")
        self.assertEqual(self.post("/auth/refresh").status_code, 401)
        self.assertEqual(self.mocks[5].call_count, 1)

    def test_expired_refresh_revokes_product_and_clears_cookie(self):
        self.login()
        session = self.client.session
        session["absolute_deadline"] = int(time.time()) - 1
        session.save()
        result = self.post("/auth/refresh")
        self.assertEqual(result.status_code, 401)
        self.assertEqual(self.mocks[6].call_count, 1)
        self.assertEqual(result.cookies["__Host-sumlaude_session"]["max-age"], 0)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)

    def test_expired_refresh_revoke_failure_fails_closed_for_retry(self):
        self.login()
        session = self.client.session
        session["absolute_deadline"] = int(time.time()) - 1
        session.save()
        self.mocks[6].side_effect = issuer.AdmissionError("DB unavailable")
        result = self.post("/auth/refresh")
        self.assertEqual(result.status_code, 503)
        self.assertIn("s03_digest", self.client.session)
        self.assertEqual(self.mocks[5].call_count, 1)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], False)

    def test_cross_origin_csrf_refused_even_with_known_token(self):
        self.login()
        token = self.csrf()
        for route in ("/auth/refresh", "/auth/logout"):
            result = self.client.post(route, secure=True,
                HTTP_ORIGIN="https://malicious.example", HTTP_X_CSRFTOKEN=token)
            self.assertEqual(result.status_code, 403)
        self.assertEqual(self.mocks[6].call_count, 0)
        self.assertEqual(self.get("/auth/session").json()["authenticated"], True)

    def test_callback_expired_state_and_provider_errors_do_not_issue(self):
        self.assertEqual(self.get("/auth/login").status_code, 302)
        session = self.client.session
        state = session["transaction"]["state"]
        session["transaction"]["deadline"] = int(time.time()) - 1
        session.save()
        self.assertEqual(self.get("/auth/callback?state=" + state + "&code=abc").status_code, 400)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.get("/auth/login").status_code, 302)
        state = self.client.session["transaction"]["state"]
        self.assertEqual(self.get("/auth/callback?state=" + state +
                                   "&code=abc&iss=https://untrusted.example").status_code, 400)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_invalid_signed_identity_never_reaches_issuer(self):
        self.mocks[2].side_effect = oidc.IdentityError("bad nonce or audience")
        self.assertEqual(self.get("/auth/login").status_code, 302)
        state = self.client.session["transaction"]["state"]
        result = self.get("/auth/callback?state=" + state + "&code=abc")
        self.assertEqual(result.status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_unsealable_provider_response_does_not_issue(self):
        with mock.patch.object(oidc, "seal",
                               side_effect=oidc.IdentityError("invalid data")):
            self.assertEqual(self.get("/auth/login").status_code, 302)
            state = self.client.session["transaction"]["state"]
            result = self.get("/auth/callback?state=" + state + "&code=abc")
        self.assertEqual(result.status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.mocks[6].call_count, 0)

    def test_invalid_provider_expiry_does_not_issue(self):
        with mock.patch.object(oidc, "deadline",
                               side_effect=oidc.IdentityError("invalid expiry")):
            self.assertEqual(self.get("/auth/login").status_code, 302)
            state = self.client.session["transaction"]["state"]
            result = self.get("/auth/callback?state=" + state + "&code=abc")
        self.assertEqual(result.status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.assertEqual(self.mocks[6].call_count, 0)


class ContractTests(unittest.TestCase):
    def test_issuer_disallows_qa_function_in_prod(self):
        with self.assertRaises(issuer.AdmissionError):
            issuer._function("sumlaude_auth.qa_issue_admitted_oidc_session")
        with self.assertRaises(issuer.AdmissionError):
            issuer._function("sumlaude_auth.issue_session;DROP TABLE students")

    def test_issuer_never_uses_claimed_email(self):
        with self.assertRaises(issuer.AdmissionError):
            issuer.issue({"issuer": settings.OIDC_ISSUER, "sub": ""})

    def test_token_sealed_and_bad_key_rejected(self):
        value = oidc.seal(tokens())
        self.assertNotIn("opaque-refresh", value)
        self.assertEqual(oidc.unseal(value)["refresh_token"], "opaque-refresh")
        with self.assertRaises(oidc.IdentityError):
            oidc.unseal(value[:-3] + "bad")

    def test_pkce_is_s256(self):
        verifier, challenge = oidc.pkce()
        import hashlib, base64
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(challenge, expected)

    def test_real_rsa_signature_issuer_audience_nonce_and_jwks_rollover(self):
        from authlib.jose import JsonWebKey, JsonWebToken
        signing_key = JsonWebKey.generate_key("RSA", 2048, is_private=True,
                                             options={"kid": "rotation-k1"})
        claims = {"iss": settings.OIDC_ISSUER, "sub": "stable-verified-subject",
                  "aud": settings.OIDC_CLIENT_ID, "exp": int(time.time()) + 120,
                  "iat": int(time.time()), "nonce": "expected-nonce"}
        jwt = JsonWebToken(["RS256"])
        good = jwt.encode({"alg": "RS256", "kid": "rotation-k1"},
                          claims, signing_key).decode()
        with mock.patch.object(oidc, "jwks", return_value={"keys": [
                signing_key.as_dict(is_private=False)]}) as jwks_mock:
            value = oidc.verify_id(good, "opaque-access", nonce="expected-nonce")
            self.assertEqual(value["sub"], claims["sub"])
            with self.assertRaises(oidc.IdentityError):
                oidc.verify_id(good, "opaque-access", nonce="wrong-nonce")
            with self.assertRaises(oidc.IdentityError):
                oidc.verify_id(good, "opaque-access", previous_sub="other-subject")
        self.assertIn(mock.call(True), jwks_mock.mock_calls)

    def test_reject_wrong_issuer_even_with_valid_rsa_signature(self):
        from authlib.jose import JsonWebKey, JsonWebToken
        signing_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        claims = {"iss": "https://attacker.example/realms/main",
                  "sub": "valid-length-subject", "aud": settings.OIDC_CLIENT_ID,
                  "exp": int(time.time()) + 120, "iat": int(time.time()),
                  "nonce": "intended-nonce"}
        token = JsonWebToken(["RS256"]).encode(
            {"alg": "RS256"}, claims, signing_key).decode()
        with mock.patch.object(oidc, "jwks", return_value={"keys": [
                signing_key.as_dict(is_private=False)]}):
            with self.assertRaises(oidc.IdentityError):
                oidc.verify_id(token, "opaque-access", nonce="intended-nonce")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class RedirectTransportTests(unittest.TestCase):
    def test_refuse_all_oidc_endpoint_redirects(self):
        from urllib.request import Request
        for code in (301, 302, 303, 307, 308):
            with self.assertRaises(oidc.IdentityError):
                oidc._NoProviderRedirect().redirect_request(
                    Request('https://issuer.example/token'), None,
                    code, 'Moved', {}, 'https://other.example')

    def test_confidential_provider_uses_no_redirect_handler(self):
        with mock.patch.object(oidc.request, 'build_opener') as build:
            build.return_value.open.side_effect = oidc.IdentityError('blocked')
            with self.assertRaises(oidc.IdentityError):
                oidc._provider('https://issuer.example/token',
                               form={'grant_type':'authorization_code'},
                               authenticated=True)
            self.assertIsInstance(build.call_args.args[0],
                                  oidc._NoProviderRedirect)

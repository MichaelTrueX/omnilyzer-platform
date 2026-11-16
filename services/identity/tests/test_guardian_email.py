"""Focused consent capability, real session/CSRF and SMTP failure checks."""
import json
from unittest import mock

from django.test import SimpleTestCase, override_settings

import test_adult_age_choice as age
from identity_bff import guardian, issuer


@override_settings(
    GUARDIAN_EMAIL_ENABLED=True,
    REQUIRE_GTM_ADULT_CHOICE=True,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class GuardianEmailTests(SimpleTestCase):
    setUp = age.AdultChoiceGatewayTests.setUp
    get = age.AdultChoiceGatewayTests.get
    csrf = age.AdultChoiceGatewayTests.csrf
    post = age.AdultChoiceGatewayTests.post
    login_identity_only = age.AdultChoiceGatewayTests.login_identity_only

    def setUp(self):
        age.AdultChoiceGatewayTests.setUp(self)
        self.state = mock.patch.object(guardian, "state", return_value="unknown")
        self.state_mock = self.state.start()
        self.addCleanup(self.state.stop)

    def send(self, path, payload, *, csrf=True):
        headers = {"HTTP_ORIGIN": "https://app.sumlaude.com"}
        if csrf:
            headers["HTTP_X_CSRFTOKEN"] = self.csrf()
        return self.client.post(path, json.dumps(payload), content_type="application/json",
                                secure=True, **headers)

    def minor(self):
        self.login_identity_only()
        with mock.patch.object(guardian, "declare_minor", return_value=True):
            response = self.post("under18")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["productAuthorized"], "guardian-required")

    def test_minor_remains_identity_only_and_cannot_choose_adult(self):
        self.minor()
        self.assertNotIn("s03_digest", self.client.session)
        self.assertEqual(self.post("adult").status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)

    def test_adult_declares_inside_product_after_fresh_signed_identity(self):
        self.login_identity_only()
        with mock.patch.object(guardian, "declare_adult", return_value=True) as declare:
            response = self.post(body=json.dumps({"ageBand":"adult","country":"DK"}))
        self.assertEqual(response.status_code, 200)
        declare.assert_called_once_with(age.trusted(), "DK")
        self.assertEqual(self.client.session["age_choice"], "adult")

    def test_failed_fresh_identity_never_records_adult_admission(self):
        self.login_identity_only()
        with mock.patch.object(guardian, "declare_adult") as declare, \
             mock.patch.object(age.oidc, "verify_id", side_effect=age.oidc.IdentityError):
            response = self.post(body=json.dumps({"ageBand":"adult","country":"DK"}))
        self.assertEqual(response.status_code, 403)
        declare.assert_not_called()

    def test_adult_needs_own_country_and_cannot_replace_known_minor(self):
        self.login_identity_only()
        with mock.patch.object(guardian, "declare_adult") as declare:
            self.assertEqual(self.post(body=json.dumps({"ageBand":"adult","country":"bad"})).status_code, 400)
            self.state_mock.return_value = "required"
            self.assertEqual(self.post(body=json.dumps({"ageBand":"adult","country":"DK"})).status_code, 403)
            declare.assert_not_called()

    def test_minor_declaration_failure_does_not_report_success(self):
        self.login_identity_only()
        with mock.patch.object(guardian, "declare_minor", side_effect=issuer.AdmissionError):
            self.assertEqual(self.post("under18").status_code, 503)
        self.assertEqual(self.client.session["age_choice"], "pending")

    def test_new_login_remembers_minor_without_new_age_choice(self):
        self.state_mock.return_value = "pending"
        self.login_identity_only()
        self.assertEqual(self.client.session["age_choice"], "under18")
        self.assertEqual(self.get("/auth/session").json()["productAuthorized"], "guardian-pending")
        self.assertEqual(self.post("adult").status_code, 403)

    def test_send_requires_signed_minor_and_csrf(self):
        with mock.patch.object(guardian, "request_confirmation") as send:
            self.assertEqual(self.send("/auth/guardian-request", {"guardianEmail":"parent@example.org"}).status_code, 403)
            self.minor()
            self.assertEqual(self.send("/auth/guardian-request", {"guardianEmail":"parent@example.org"}, csrf=False).status_code, 403)
            self.assertEqual(self.send("/auth/guardian-request", {"guardianEmail":"parent@example.org"}).status_code, 200)
            send.assert_called_once_with(age.trusted(), "parent@example.org")

    def test_delivery_failure_does_not_claim_sent(self):
        self.minor()
        with mock.patch.object(guardian, "request_confirmation", side_effect=issuer.AdmissionError):
            response = self.send("/auth/guardian-request", {"guardianEmail":"parent@example.org"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("sent", response.json())

    def test_confirmation_is_csrf_protected_without_learner_login(self):
        payload = {"token":"a"*43,"guardianConsent":True,"country":"DK"}
        with mock.patch.object(guardian, "confirm") as confirm:
            self.assertEqual(self.send("/auth/guardian-confirm", payload, csrf=False).status_code, 403)
            self.assertEqual(self.send("/auth/guardian-confirm", payload).status_code, 200)
            confirm.assert_called_once_with("a"*43, True, "DK")
        self.assertNotIn("s03_digest", self.client.session)

    def test_confirmation_requires_explicit_consent_valid_token_country(self):
        with mock.patch.object(guardian, "_call") as db:
            for token, consent, country in [("a"*43,False,"DK"),("wrong",True,"DK"),("a"*43,True,"")]:
                with self.assertRaises(ValueError):
                    guardian.confirm(token,consent,country)
            db.assert_not_called()

    def test_continue_requires_this_learners_confirmed_admission(self):
        self.minor()
        for state in ("required", "pending", "unknown"):
            self.state_mock.return_value = state
            self.assertEqual(self.send("/auth/guardian-continue", {}).status_code, 403)
        self.assertEqual(self.mocks[5].call_count, 0)
        self.state_mock.return_value = "confirmed"
        response = self.send("/auth/guardian-continue", {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.session["age_choice"], "guardian")
        self.assertEqual(self.get("/auth/session").json()["productAuthorized"], "check-S03")
        self.assertEqual(response.cookies["__Host-sumlaude_session"]["secure"], True)

    def test_landing_get_cannot_confirm_or_expose_a_token(self):
        with mock.patch.object(guardian, "_call") as db:
            response = self.get("/auth/guardian")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Referrer-Policy"], "no-referrer")
            self.assertIn("no-store", response["Cache-Control"])
            db.assert_not_called()
        self.assertEqual(self.get("/auth/guardian?token=secret").status_code, 404)

    def test_header_injection_rejected_before_database_or_smtp(self):
        with mock.patch.object(guardian, "_call") as db:
            for address in ("parent@example.org\r\nBcc:other@example.org", "not-an-email"):
                with self.assertRaises(ValueError):
                    guardian.request_confirmation(age.trusted(), address)
            db.assert_not_called()

    def test_email_contains_fragment_token_but_db_receives_only_digest(self):
        with mock.patch.object(guardian, "_call", return_value=True) as db, \
                mock.patch.object(guardian.smtplib, "SMTP_SSL") as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {}
            guardian.request_confirmation(age.trusted(), "Parent@example.org")
            args = db.call_args.args[1]
            self.assertEqual(len(args[-1]), 32)
            self.assertNotEqual(args[-2], "parent@example.org")
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
            self.assertIn("https://sumlaude.com/auth/guardian#", message.get_content())
            self.assertNotIn(age.trusted()["sub"], message.get_content())

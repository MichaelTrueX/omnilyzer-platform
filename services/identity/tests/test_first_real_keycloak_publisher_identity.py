"""Focused first-real-user Keycloak-only invitation contract; NO live admin."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, call

SRC = (Path(__file__).resolve().parents[1] / "ops" /
       "first_real_keycloak_publisher_identity.py")
spec = importlib.util.spec_from_file_location("first_real_keycloak", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

U_ID = "11111111-1111-4111-8111-111111111111"
EMAIL = "publisher@company.org"
REALM = {"realm": "omnilyzer", "enabled": True,
         "registrationAllowed": False,
         "smtpServer": {"host": "smtp.example.net", "from": "sender@example.net"}}
CLIENTS = [{"clientId": "sumlaude-bff", "enabled": True, "publicClient": False,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "redirectUris": [m.CALLBACK],
            "attributes": {"pkce.code.challenge.method": "S256"}}]
PENDING = {"id": U_ID, "email": EMAIL, "enabled": True,
           "emailVerified": False, "requiredActions": m.ACTIONS}
VERIFIED = {**PENDING, "emailVerified": True, "requiredActions": []}
REAL_TMP = tempfile.TemporaryDirectory


class FirstPublisherTests(unittest.TestCase):
    def test_email_canonicalization(self):
        self.assertEqual(m.canonical_email("  Publisher@COMPANY.org  "), EMAIL)

    def test_synthetic_and_malformed_email_refused(self):
        for email in ("", "not-email", "test@company.org", "publisher@foo.invalid",
                      "fake@company.org", "qa@company.org", "publisher@foo.test",
                      "publisher@localhost", "foo@example", "publisher@some.test"):
            with self.subTest(email=email), self.assertRaises(m.Stop):
                m.canonical_email(email)

    def test_invite_has_never_verified_flag_or_privileged_roles(self):
        payload = m.invite_payload(EMAIL)
        self.assertEqual(payload["email"], EMAIL)
        self.assertIs(payload["emailVerified"], False)
        self.assertEqual(payload["requiredActions"],
                         ["VERIFY_EMAIL", "UPDATE_PASSWORD"])
        self.assertNotIn("roles", payload)
        self.assertNotIn("credentials", payload)
        self.assertNotIn("password", payload)

    def test_exact_email_selection(self):
        result = m.select_account([{"id": U_ID, "email": "other@company.org"},
                                   PENDING], EMAIL)
        self.assertEqual(result, PENDING)

    def test_duplicate_real_email_fails_closed(self):
        with self.assertRaisesRegex(m.Stop, "DUPLICATE"):
            m.select_account([PENDING, PENDING], EMAIL)

    def test_disabled_identity_fails_closed(self):
        with self.assertRaisesRegex(m.Stop, "DISABLED"):
            m.select_account([{**PENDING, "enabled": False}], EMAIL)

    def test_invalid_issuer_subject_fails_closed(self):
        with self.assertRaisesRegex(m.Stop, "SUB_INVALID"):
            m.select_account([{**PENDING, "id": "NOT_A_SUB"}], EMAIL)

    def test_verified_status_requires_true_flag_and_completed_actions(self):
        self.assertEqual(m.verification_status(None), "ABSENT")
        self.assertEqual(m.verification_status(PENDING),
                         "PENDING_EMAIL_VERIFICATION")
        self.assertEqual(m.verification_status({
            **VERIFIED, "requiredActions": ["UPDATE_PASSWORD"]}),
            "PENDING_REQUIRED_ACTION")
        self.assertEqual(m.verification_status(VERIFIED), "VERIFIED")

    def test_realm_exact_confidential_client_pass(self):
        self.assertEqual(m.verify_realm(REALM, CLIENTS), REALM["smtpServer"])

    def test_registration_enabled_or_redirect_drift_fails(self):
        with self.assertRaisesRegex(m.Stop, "POLICY_MISMATCH"):
            m.verify_realm({**REALM, "registrationAllowed": True}, CLIENTS)
        with self.assertRaisesRegex(m.Stop, "CLIENT_DRIFT"):
            m.verify_realm(REALM, [{**CLIENTS[0], "redirectUris": ["*"]}])

    def test_missing_smtp_refuses_invite(self):
        for smtp in (None, {}, {"host": "127.0.0.1"}, {"from": "x@example.net"}):
            with self.subTest(smtp=smtp), self.assertRaisesRegex(m.Stop, "SMTP"):
                m.require_smtp(smtp)

    def exercise(self, action, responses):
        fake_result = []
        def cli(args, env, cfg, payload=None):
            fake_result.append((tuple(args), payload))
            return ""
        def fake_temp(*args, **kwargs):
            return REAL_TMP(prefix="m01-dev-test-", dir="/tmp")
        with patch.dict(m.os.environ, {"PUBLISHER_EMAIL": EMAIL}), \
             patch.object(m, "root_admin_env",
                          return_value={"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
                                        "KC_BOOTSTRAP_ADMIN_PASSWORD": "injected-only"}), \
             patch.object(m, "json_result", side_effect=responses), \
             patch.object(m, "kcadm", side_effect=cli), \
             patch.object(m.tempfile, "TemporaryDirectory", side_effect=fake_temp):
            m.operate(action)
        return fake_result

    def test_readonly_preflight_does_not_create_or_email(self):
        sent = self.exercise("preflight", [REALM, CLIENTS, []])
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0][0:2], ("config", "credentials"))

    def test_invite_once_unverified_no_password_and_verify_email(self):
        sent = self.exercise("invite", [REALM, CLIENTS, [], [PENDING]])
        self.assertEqual(len(sent), 3)
        self.assertEqual(sent[1][0][:2], ("create", "users"))
        self.assertFalse(sent[1][1]["emailVerified"])
        self.assertEqual(sent[2][0][0], "update")
        self.assertEqual(sent[2][1], ["VERIFY_EMAIL", "UPDATE_PASSWORD"])

    def test_existing_user_invite_is_denied_without_mutation(self):
        with self.assertRaisesRegex(m.Stop, "ALREADY_EXISTS"):
            self.exercise("invite", [REALM, CLIENTS, [PENDING]])

    def test_verified_user_status_is_read_only(self):
        sent = self.exercise("verify", [REALM, CLIENTS, [VERIFIED]])
        self.assertEqual(len(sent), 1)

    def test_unverified_user_never_passes_verify(self):
        with self.assertRaisesRegex(m.Stop, "ACTIONS_INCOMPLETE"):
            self.exercise("verify", [REALM, CLIENTS, [PENDING]])


if __name__ == "__main__":
    unittest.main()

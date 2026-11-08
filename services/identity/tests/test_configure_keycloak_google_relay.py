"""Source-only mock of first REAL Keycloak SMTP realm write guard."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
REAL_TEMP_DIR = tempfile.TemporaryDirectory

SRC = (Path(__file__).resolve().parents[1] / "ops" /
       "configure_keycloak_google_relay.py")
spec = importlib.util.spec_from_file_location("m01_relay", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

REALM = {"realm": "omnilyzer", "enabled": True, "registrationAllowed": False}
CLIENTS = [{"clientId": "sumlaude-bff", "enabled": True,
            "publicClient": False, "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "redirectUris": [m.CALLBACK],
            "attributes": {"pkce.code.challenge.method": "S256"}}]


class KeycloakSMTPTests(unittest.TestCase):
    def test_valid_tls_only_implicit_465_no_password(self):
        self.assertEqual(m.SMTP["host"], "smtp-relay.gmail.com")
        self.assertEqual(m.SMTP["port"], "465")
        self.assertEqual(m.SMTP["ssl"], "true")
        self.assertEqual(m.SMTP["starttls"], "false")
        self.assertEqual(m.SMTP["auth"], "false")
        self.assertEqual(m.SMTP["from"], "no-reply@sumlaude.com")
        self.assertNotIn("password", m.SMTP)
        self.assertNotIn("user", m.SMTP)

    def test_smtp_state_missing_exact_unexpected(self):
        self.assertEqual(m.smtp_state({}), "MISSING")
        self.assertEqual(m.smtp_state(None), "MISSING")
        self.assertEqual(m.smtp_state(m.SMTP), "EXACT_EXPECTED")
        self.assertEqual(m.smtp_state({**m.SMTP, "auth": "true"}), "UNEXPECTED")
        self.assertEqual(m.smtp_state({**m.SMTP, "port": "587"}), "UNEXPECTED")
        self.assertEqual(m.smtp_state({"host": "unknown"}), "UNEXPECTED")

    def test_exact_confidential_client_guard(self):
        m.verify_contract(REALM, CLIENTS)
        for realm,client in [
            ({**REALM, "registrationAllowed": True}, CLIENTS),
            (REALM, [{**CLIENTS[0], "publicClient": True}]),
            (REALM, [{**CLIENTS[0], "redirectUris": ["*"]}]),
            (REALM, [{**CLIENTS[0], "directAccessGrantsEnabled": True}])
        ]:
            with self.subTest(realm=realm, client=client), self.assertRaises(m.Hold):
                m.verify_contract(realm, client)

    def exercise(self, action, replies):
        calls = []
        def fake_admin(args,env,config):
            calls.append(args)
            return ""
        def local_tmp(*args, **kwargs):
            return REAL_TEMP_DIR(prefix="m01-stub-", dir="/tmp")
        with patch.object(m, "protected_admin_credentials",
                          return_value={"KC_BOOTSTRAP_ADMIN_USERNAME": "existing-admin",
                                        "KC_BOOTSTRAP_ADMIN_PASSWORD": "fake-only"}), \
             patch.object(m, "admin_cli", side_effect=fake_admin), \
             patch.object(m, "read_json", side_effect=replies), \
             patch.object(m, "tls_connectivity", return_value="MOCK_TLS_OK"), \
             patch.object(m.tempfile, "TemporaryDirectory", side_effect=local_tmp):
            m.operate(action)
        return calls

    def test_preflight_never_writes(self):
        calls = self.exercise("preflight", [REALM, CLIENTS])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["config", "credentials"])

    def test_exact_single_realm_smtp_write_and_readback(self):
        calls = self.exercise("configure",
                              [REALM, CLIENTS, {**REALM, "smtpServer": m.SMTP}, CLIENTS])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0:2], ["update", "realms/omnilyzer"])
        self.assertEqual(calls[1][-1], "--merge")
        self.assertEqual(calls[1][2], "-s")
        self.assertTrue(calls[1][3].startswith("smtpServer={"))

    def test_refuse_existing_smtp_and_never_overwrite(self):
        with self.assertRaisesRegex(m.Hold, "ALREADY_CONFIGURED"):
            self.exercise("configure", [{**REALM, "smtpServer": m.SMTP}, CLIENTS])
        with self.assertRaisesRegex(m.Hold, "UNEXPECTED_EXISTING"):
            self.exercise("configure",
                          [{**REALM, "smtpServer": {"host": "external"}}, CLIENTS])

    def test_hard_fail_if_smtp_write_does_not_match(self):
        with self.assertRaisesRegex(m.Hold, "READBACK_MISMATCH"):
            self.exercise("configure",
                          [REALM, CLIENTS, {**REALM, "smtpServer": {}}, CLIENTS])

    def test_rollback_requires_exact_current_configuration(self):
        with self.assertRaisesRegex(m.Hold, "ROLLBACK_REQUIRES"):
            self.exercise("rollback", [REALM, CLIENTS])
        calls = self.exercise("rollback",
                              [{**REALM, "smtpServer": m.SMTP}, CLIENTS,
                               {**REALM, "smtpServer": {}}])
        self.assertEqual(calls[-1][2:4], ["-s", "smtpServer={}"])

    def test_rollback_readback_mismatch_is_hard_failure(self):
        with self.assertRaisesRegex(m.Hold, "ROLLBACK_READBACK"):
            self.exercise("rollback",
                          [{**REALM, "smtpServer": m.SMTP}, CLIENTS,
                           {**REALM, "smtpServer": m.SMTP}])

if __name__ == "__main__":
    unittest.main()

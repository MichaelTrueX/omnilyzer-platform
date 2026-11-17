"""File: services/identity/tests/test_keycloak_provision_realm.py
Purpose: Offline tests for protected, single-realm Keycloak production
    provisioning and an exact confidential Sumlaude OIDC client contract.
Related: services/identity/ops/keycloak_provision_realm.py and ADR-0003.
"""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "ops" / "keycloak_provision_realm.py"
SPEC = importlib.util.spec_from_file_location("keycloak_provision_realm", SOURCE)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ProductionRealmTests(unittest.TestCase):
    """Check protected realm behavior without using live admin credentials."""

    def test_exact_issuer_client_and_callback(self):
        self.assertEqual(MOD.REALM, "omnilyzer")
        self.assertEqual(MOD.ISSUER, "https://login.omnilyzer.ai/realms/omnilyzer")
        self.assertEqual(MOD.CLIENT, "sumlaude-bff")
        self.assertEqual(MOD.CALLBACK, "https://app.sumlaude.com/auth/callback")

    def test_one_confidential_client_and_required_s256(self):
        doc = MOD.realm_document("synthetic-not-a-real-secret")
        self.assertEqual(doc["realm"], "omnilyzer")
        self.assertTrue(doc["enabled"])
        self.assertEqual(len(doc["clients"]), 1)
        c = doc["clients"][0]
        self.assertEqual(c["clientId"], "sumlaude-bff")
        self.assertFalse(c["publicClient"])
        self.assertFalse(c["directAccessGrantsEnabled"])
        self.assertFalse(c["implicitFlowEnabled"])
        self.assertFalse(c["serviceAccountsEnabled"])
        self.assertTrue(c["standardFlowEnabled"])
        self.assertEqual(c["clientAuthenticatorType"], "client-secret")
        self.assertEqual(c["redirectUris"], [MOD.CALLBACK])
        self.assertEqual(c["webOrigins"], ["https://app.sumlaude.com"])
        self.assertEqual(c["attributes"]["pkce.code.challenge.method"], "S256")

    def test_no_open_registration_or_unverified_email_identity(self):
        doc = MOD.realm_document("synthetic")
        self.assertFalse(doc["registrationAllowed"])
        self.assertFalse(doc["resetPasswordAllowed"])
        self.assertFalse(doc["loginWithEmailAllowed"])
        self.assertFalse(doc["verifyEmail"])
        self.assertTrue(doc["bruteForceProtected"])
        self.assertEqual(doc["sslRequired"], "external")
        self.assertNotIn("users", doc)
        self.assertNotIn("identityProviders", doc)

    def test_unauthorized_preflight_does_not_create_or_authenticate(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD.socket, "gethostname", return_value="wrong-host"), \
             mock.patch.object(MOD, "load_root_env") as env, \
             mock.patch.object(MOD.subprocess, "run") as command, \
             mock.patch.object(MOD, "http_status") as http:
            findings = MOD.preflight()
            self.assertIn("root required on truexmainserver", findings)
            env.assert_not_called()
            self.assertTrue(findings)

    def test_provision_aborts_before_secret_creation_on_preflight_failure(self):
        with mock.patch.object(MOD, "preflight", return_value=["unexpected realm"]), \
             mock.patch.object(MOD, "load_root_env") as env, \
             mock.patch.object(MOD.secrets, "token_urlsafe") as secret, \
             mock.patch.object(MOD.os, "open") as file_open:
            with self.assertRaisesRegex(RuntimeError, "unexpected realm"):
                MOD.provision()
            env.assert_not_called()
            secret.assert_not_called()
            file_open.assert_not_called()

    def test_root_only_provisioning_script_does_not_touch_other_products(self):
        src = SOURCE.read_text()
        for forbidden in (
            "tailscale serve", "certbot", "cloudflare.request",
            "systemctl restart nginx", "docker compose",
            "CREATE ROLE", "CREATE DATABASE", "analytics_dev", "legacy_users",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=", "kc.sh start-dev",
        ):
            self.assertNotIn(forbidden, src)
        self.assertIn('env["KC_CLI_PASSWORD"]', src)
        self.assertIn('TemporaryDirectory(prefix="m01-keycloak-admin-", dir="/run")', src)
        self.assertIn('os.O_EXCL', src)


if __name__ == "__main__":
    unittest.main()

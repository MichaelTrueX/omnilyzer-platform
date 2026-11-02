"""File: services/identity/tests/test_keycloak_public_ingress.py
Purpose: Offline security review of isolated ACME preflight and later HTTPS
    ingress for real Keycloak on truexmainserver without using root or DNS.
Related: services/identity/ops/keycloak_public_ingress.py; ADR-0003.
"""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / "ops/keycloak_public_ingress.py"
SPEC = importlib.util.spec_from_file_location("keycloak_public_ingress", SRC)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class KeycloakIngressTests(unittest.TestCase):
    """Verify vhosts, expected fail-close paths and no production side effects."""

    def test_http_only_acme_and_no_premature_identity_proxy(self):
        config = MOD.http_vhost()
        self.assertIn("server_name login.omnilyzer.ai;", config)
        self.assertIn("location ^~ /.well-known/acme-challenge/", config)
        self.assertIn("root /var/www/omnilyzer-login-acme;", config)
        self.assertIn("return 404;", config)
        self.assertNotIn("listen 443", config)
        self.assertNotIn("proxy_pass", config)

    def test_https_only_expected_realm_and_static_resources(self):
        conf = MOD.https_vhost()
        self.assertIn("location ^~ /realms/omnilyzer/", conf)
        self.assertIn("location ^~ /resources/", conf)
        self.assertIn("proxy_pass http://127.0.0.1:18742;", conf)
        self.assertNotIn("location ^~ /realms/master/", conf)
        self.assertNotIn("location ^~ /admin/", conf)
        self.assertIn('location / {\n        return 404;\n    }', conf)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/login.omnilyzer.ai/fullchain.pem;", conf)
        self.assertIn("ssl_certificate_key /etc/letsencrypt/live/login.omnilyzer.ai/privkey.pem;", conf)

    def test_cloudflare_only_and_no_unsafe_proxy_trust(self):
        conf = MOD.https_vhost()
        self.assertEqual(conf.count("proxy_pass http://127.0.0.1:18742;"), 2)
        self.assertIn("    deny all;", conf)
        self.assertEqual(conf.count("    allow "), len(MOD.CLOUDFLARE_IPS))
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", conf)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", conf)
        self.assertNotIn("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;", conf)
        self.assertIn('add_header Cache-Control "no-store" always;', conf)

    def test_preflight_fails_for_wrong_host_without_mutation(self):
        with mock.patch.object(MOD.os, "geteuid", return_value=1000), \
             mock.patch.object(MOD.socket, "gethostname", return_value="false-prod"), \
             mock.patch.object(MOD, "run", side_effect=OSError("not root")), \
             mock.patch.object(MOD, "identity_check", side_effect=OSError("unavailable")):
            issues = MOD.base_check()
            self.assertIn("root required on truexmainserver", issues)
            self.assertIn("Nginx or exact local identity source not verified", issues)

    def test_acme_install_aborts_if_existing_vhost(self):
        with mock.patch.object(MOD, "acme_preflight", return_value=["already configured"]), \
             mock.patch.object(MOD, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "already configured"):
                MOD.install_acme()
            run.assert_not_called()

    def test_https_install_aborts_if_untrusted_cert(self):
        with mock.patch.object(MOD, "tls_preflight", return_value=["no trusted certificate"]), \
             mock.patch.object(MOD, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "no trusted certificate"):
                MOD.install_https()
            run.assert_not_called()

    def test_identity_and_other_websites_are_never_touched(self):
        source = SRC.read_text()
        for forbidden in ("systemctl restart nginx", "systemctl stop nginx",
                          "certbot certonly", "cloudflare.request",
                          "CREATE DATABASE", "drop database", "tailscale serve",
                          "kc.sh start", "systemctl restart omnilyzer-keycloak"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"reload", "nginx"', source)
        self.assertIn('CERT = Path("/etc/letsencrypt/live/login.omnilyzer.ai/fullchain.pem")', source)


if __name__ == "__main__":
    unittest.main()

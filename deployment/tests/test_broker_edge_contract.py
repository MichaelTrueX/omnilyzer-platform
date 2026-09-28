"""C32Z's pinned, uninstalled DEV HTTPS edge candidate and live prerequisites."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import hashlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

from deployment.application_source_set import DevApplicationSourceSet
from deployment.broker_edge_contract import (
    DevBrokerEdgeContract, DevBrokerEdgeQualificationPlan,
)
from deployment.broker_https_ingress import (
    BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, PROMOTION_PATH, PUBLIC_ORIGIN,
)
from deployment import blob_verifier, jwks, release_consumer, unix_transport
from deployment.final_application_generation import TARGET_REVIEWED_COMMIT


ROOT = Path(__file__).resolve().parents[2]
ASSET = ROOT / "deployment/ingress/dev-broker-https.nginx.conf"
BASE = "ca0021482f14d1d8c7ce9535e938276018d19b61"
C32Z_BASE = "e80cb2dffbdc05d195a74398dbbc702346d4524a"


class DevBrokerEdgeContractTests(unittest.TestCase):
    def test_closed_pure_authority(self):
        self.assertEqual(tuple(inspect.signature(DevBrokerEdgeContract).parameters), ())
        with patch("builtins.open", side_effect=AssertionError("host I/O")), patch(
            "subprocess.run", side_effect=AssertionError("host I/O")
        ), patch("socket.socket", side_effect=AssertionError("host I/O")):
            edge = DevBrokerEdgeContract()
            plan = edge.qualification_plan()
        self.assertEqual(edge.public_origin, PUBLIC_ORIGIN)
        self.assertEqual(edge.host, "deploy-dev.omnilyzer.ai")
        self.assertEqual(edge.https_port, 443)
        self.assertEqual((edge.method, edge.endpoint), ("POST", PROMOTION_PATH))
        self.assertEqual((edge.upstream_host, edge.upstream_port),
                         (BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT))
        self.assertEqual((edge.upstream_connect_timeout_seconds,
                          edge.upstream_send_timeout_seconds,
                          edge.upstream_response_timeout_seconds), (3, 30, 900))
        self.assertEqual(edge.certificate_path,
                         "/etc/letsencrypt/live/deploy-dev.omnilyzer.ai/fullchain.pem")
        self.assertEqual(edge.private_key_path,
                         "/etc/letsencrypt/live/deploy-dev.omnilyzer.ai/privkey.pem")
        self.assertIsNone(edge.nginx_include_destination)
        self.assertEqual(plan.status, "pending-live-qualification")
        self.assertEqual(type(plan.checks), tuple)
        self.assertFalse(hasattr(edge, "__dict__"))
        self.assertFalse(hasattr(plan, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            edge.host = "other.example"
        with self.assertRaises(TypeError):
            DevBrokerEdgeContract(host="other.example")
        with self.assertRaises(TypeError):
            DevBrokerEdgeContract(upstream_response_timeout_seconds=30)
        for name, value in (("https_port", True), ("host", "other.example"),
                            ("upstream_response_timeout_seconds", 30),
                            ("nginx_include_destination", "/etc/nginx/conf.d/broker.conf")):
            forged = object.__new__(DevBrokerEdgeContract)
            for item in fields(edge):
                object.__setattr__(forged, item.name,
                                   value if item.name == name else getattr(edge, item.name))
            with self.subTest(name=name), self.assertRaises(ValueError):
                forged.qualification_plan()

    def test_final_asset_digest_and_tls_authority(self):
        edge = DevBrokerEdgeContract()
        payload = ASSET.read_bytes()
        asset = payload.decode("ascii")
        self.assertEqual(edge.nginx_source_path,
                         "deployment/ingress/dev-broker-https.nginx.conf")
        self.assertEqual(edge.nginx_source_sha256,
                         "0e0b966454fc4e0b9a00d7817e532ab5efa5d9c39a17c5856c6aea0fead5e9c6")
        self.assertEqual(hashlib.sha256(payload).hexdigest(), edge.nginx_source_sha256)
        for directive in (
            "listen 443 ssl;", "server_name deploy-dev.omnilyzer.ai;",
            f"ssl_certificate {edge.certificate_path};",
            f"ssl_certificate_key {edge.private_key_path};",
            "ssl_protocols TLSv1.2 TLSv1.3;",
        ):
            self.assertIn(directive, asset)
        self.assertEqual(len(re.findall(r"^\s*listen\s+", asset, re.M)), 1)
        self.assertNotIn("listen 80", asset)
        self.assertNotIn("return 301", asset)
        self.assertNotIn("return 302", asset)
        self.assertNotIn("ssl_verify_client off", asset)
        self.assertNotIn("-----BEGIN", asset)
        self.assertNotIn("-----END", asset)

    def test_exact_route_headers_bounds_and_nonlogging(self):
        asset = ASSET.read_text(encoding="ascii")
        self.assertIn("location = /task014/dev/promote {", asset)
        self.assertIn("location / { return 404; }", asset)
        self.assertEqual(re.findall(r"^\s*proxy_pass\s+([^;]+);", asset, re.M),
                         ["http://127.0.0.1:3031"])
        for directive in (
            "if ($request_method != POST) { return 405; }",
            'if ($request_uri != "/task014/dev/promote") { return 400; }',
            'if ($content_type != "application/json") { return 415; }',
            'if ($content_length = "") { return 411; }',
            'if ($http_transfer_encoding != "") { return 400; }',
            'if ($http_content_encoding != "") { return 415; }',
            'if ($http_cookie != "") { return 400; }',
            'if ($http_authorization ~ ",") { return 400; }',
            'if ($http_x_omnilyzer_zot_oidc ~ ",") { return 400; }',
            'if ($http_x_omnilyzer_forgejo_oidc ~ ",") { return 400; }',
            "client_max_body_size 4096;", "proxy_http_version 1.0;",
            "proxy_set_header Connection close;", "proxy_pass_request_headers off;",
            "proxy_request_buffering off;", "proxy_buffering off;",
            "proxy_max_temp_file_size 0;", "proxy_cache off;",
            "access_log off;", 'add_header Cache-Control "no-store" always;',
            "proxy_hide_header Set-Cookie;", "proxy_hide_header Location;",
            "proxy_hide_header Access-Control-Allow-Origin;",
            "proxy_connect_timeout 3s;", "proxy_read_timeout 900s;",
            "proxy_send_timeout 30s;",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, asset)
        forwarded = re.findall(r"^\s*proxy_set_header\s+([^;]+);", asset, re.M)
        self.assertEqual(re.findall(r"^\s*proxy_read_timeout\s+([^;]+);", asset, re.M),
                         ["900s"])
        original = subprocess.check_output(
            ["git", "show", f"{C32Z_BASE}:deployment/ingress/dev-broker-https.nginx.conf"],
            cwd=ROOT).decode("ascii")
        self.assertEqual(original.count("proxy_read_timeout 30s;"), 1)
        self.assertEqual(asset, original.replace("proxy_read_timeout 30s;",
                                                 "proxy_read_timeout 900s;"))
        self.assertEqual(forwarded, [
            "Host deploy-dev.omnilyzer.ai",
            "Authorization $http_authorization",
            "X-Omnilyzer-Zot-OIDC $http_x_omnilyzer_zot_oidc",
            "X-Omnilyzer-Forgejo-OIDC $http_x_omnilyzer_forgejo_oidc",
            "Content-Type application/json",
            "Content-Length $content_length",
            "Connection close",
        ])
        for forbidden in ("X-Forwarded", "Access-Control-Allow-Credentials",
                          "add_header Set-Cookie", "add_header Location", "access_log on",
                          "proxy_redirect", "proxy_cookie", "http://$", "localhost"):
            self.assertNotIn(forbidden, asset)

    def test_live_qualification_is_pending_and_explicit(self):
        checks = DevBrokerEdgeQualificationPlan().checks
        self.assertEqual(len(checks), 16)
        for marker in ("host-nginx-include-layout-proven", "nginx-configuration-test-passed",
                       "loaded-upstream-timeouts-match-pinned-contract",
                       "dns-resolves-to-intended-dev-ingress-host",
                       "certificate-hostname-current-validity-and-public-trust-proven",
                       "private-key-not-group-or-world-readable",
                       "public-origin-https-negotiation-proven",
                       "plaintext-deployment-endpoint-unavailable-without-redirect",
                       "authorization-zot-and-forgejo-duplicate-headers-each-rejected-at-edge",
                       "oversized-chunked-and-cookie-requests-rejected",
                       "deployment-access-logging-secret-free"):
            self.assertIn(marker, checks)
        docs = " ".join((ROOT / "deployment/README.md").read_text().split())
        for marker in ("nginx -t", "version string alone is insufficient",
                       "intended DEV ingress host",
                       "include destination unset", "port 80", "No public IP",
                       "timeout values match the pinned contract",
                       "disable automatic retry", "response deadline greater than 900 seconds",
                       "workflow job with a still longer timeout"):
            self.assertTrue(marker in docs, marker)
        self.assertTrue("rejected **before** reaching the broker" in docs)

    def test_response_timeout_exceeds_independent_runtime_budget(self):
        oidc_cold_seconds = 2 * (
            jwks.CONNECT_TIMEOUT_SECONDS + jwks.READ_TIMEOUT_SECONDS)
        release_reads_seconds = 2 * (
            release_consumer.CONNECT_TIMEOUT + release_consumer.READ_TIMEOUT)
        cosign_seconds = 3 * blob_verifier.EXECUTION_TIMEOUT
        executor_seconds = (unix_transport.MAX_TIMEOUT_MS
                            + unix_transport.RESPONSE_TIMEOUT_MS) / 1000
        known_ceiling = (oidc_cold_seconds + release_reads_seconds
                         + cosign_seconds + executor_seconds)
        self.assertEqual(known_ceiling, 717.0)
        edge = DevBrokerEdgeContract()
        self.assertGreaterEqual(edge.upstream_response_timeout_seconds,
                                known_ceiling + 60)
        self.assertEqual(edge.upstream_response_timeout_seconds - known_ceiling, 183.0)
        asset = ASSET.read_text(encoding="ascii")
        for directive in (
            f"proxy_connect_timeout {edge.upstream_connect_timeout_seconds}s;",
            f"proxy_send_timeout {edge.upstream_send_timeout_seconds}s;",
            f"proxy_read_timeout {edge.upstream_response_timeout_seconds}s;",
        ):
            self.assertIn(directive, asset)

    def test_historical_and_nonlive_boundaries(self):
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        self.assertNotIn("deployment/broker_edge_contract.py", selected)
        self.assertNotIn("deployment/ingress/dev-broker-https.nginx.conf", selected)
        self.assertEqual(subprocess.run(
            ["git", "diff", "--quiet", TARGET_REVIEWED_COMMIT, "--", *selected],
            cwd=ROOT, check=False).returncode, 0)
        protected = [
            "deployment/application_source_set.py",
            "deployment/application_manifest.py",
            "deployment/final_application_generation.py",
            "deployment/dev_final_application_update.py",
            "deployment/final_configuration_authority.py",
            "deployment/dev_final_broker_resources.py",
            "deployment/dev_post_c31_application_update.py",
            "deployment/ingress/dev-broker-https.nginx.review.conf",
        ]
        self.assertEqual(subprocess.run(["git", "diff", "--quiet", BASE, "--", *protected],
                                        cwd=ROOT, check=False).returncode, 0)
        environment = json.loads((ROOT / "deployment/environments/dev.json").read_text())
        self.assertIs(environment["activation"]["deployment_enabled"], False)
        source = (ROOT / "deployment/broker_edge_contract.py").read_text()
        for forbidden in ("systemctl", "certbot", "nginx -s", "socket.", "subprocess.",
                          "os.system", "http.client", "urllib", "import requests", "__main__"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()

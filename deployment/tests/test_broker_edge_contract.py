"""C32ZC's pure Tailscale-private edge, Nginx and pending live checks."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import hashlib
import inspect
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

from deployment.application_source_set import DevApplicationSourceSet
from deployment import blob_verifier, jwks, release_consumer, unix_transport
from deployment.broker_edge_contract import DevBrokerEdgeContract, DevBrokerEdgeQualificationPlan
from deployment.broker_https_ingress import BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT, PROMOTION_PATH, PUBLIC_HOST
from deployment.broker_integration import MAX_PROMOTION_REQUEST_BYTES
from deployment.final_application_generation import (
    TARGET_REVIEWED_COMMIT, TARGET_MANIFEST_SHA256, TARGET_RUNTIME_SHA256,
    TARGET_INGRESS_SHA256,
)

ROOT = Path(__file__).resolve().parents[2]
ASSET = ROOT / "deployment/ingress/dev-broker-tailscale-origin.nginx.conf"
BASE = "41095ac83c53b05cc3a1e7a350a4a5c848041c26"


class DevBrokerEdgeContractTests(unittest.TestCase):
    def test_closed_pure_transport_authority(self):
        self.assertEqual(tuple(inspect.signature(DevBrokerEdgeContract).parameters), ())
        with patch("builtins.open", side_effect=AssertionError("host I/O")), patch(
            "subprocess.run", side_effect=AssertionError("host I/O")
        ), patch("socket.socket", side_effect=AssertionError("host I/O")):
            edge = DevBrokerEdgeContract()
            plan = edge.qualification_plan()
        self.assertEqual(edge.transport, "tailscale-private-serve")
        self.assertEqual(edge.tailscale_https_host, "omnilyzerdev.tail52e570.ts.net")
        self.assertEqual(edge.tailscale_https_port, 443)
        self.assertEqual(edge.transport_endpoint,
                         "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote")
        self.assertEqual(edge.serve_origin_target, "http://127.0.0.1:3032")
        self.assertEqual((edge.nginx_listen_host, edge.nginx_listen_port), ("127.0.0.1", 3032))
        self.assertEqual(edge.logical_broker_host, PUBLIC_HOST)
        self.assertEqual((edge.method, edge.endpoint), ("POST", PROMOTION_PATH))
        self.assertEqual(edge.promotion_request_max_bytes, MAX_PROMOTION_REQUEST_BYTES)
        self.assertIs(edge.automatic_retry_allowed, False)
        self.assertEqual((edge.upstream_host, edge.upstream_port),
                         (BROKER_LOOPBACK_HOST, BROKER_LOOPBACK_PORT))
        self.assertEqual((edge.upstream_connect_timeout_seconds,
                          edge.upstream_send_timeout_seconds,
                          edge.upstream_response_timeout_seconds), (3, 30, 900))
        self.assertEqual(edge.expected_tailscale_version, "1.102.4")
        self.assertEqual(edge.github_action_sha, "d1b6cd204f8dceda5b3eaad7f1f767be390056cd")
        self.assertEqual(edge.tailscale_static_tarball_sha256,
                         "50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9")
        self.assertEqual(edge.github_action_connection_timeout, "2m")
        self.assertEqual(edge.github_action_connection_attempts, 1)
        self.assertEqual(edge.github_action_args,
                         "--accept-routes=false --accept-dns=true --shields-up=true")
        self.assertEqual(edge.ci_tag, "tag:omnilyzer-task014-ci")
        self.assertEqual(edge.wif_issuer, "https://token.actions.githubusercontent.com")
        self.assertEqual(edge.wif_subject,
                         "repo:MichaelTrueX@130741173/omnilyzer-platform@1350104356:environment:task014-dev")
        self.assertEqual(edge.wif_scopes, ("auth_keys",))
        self.assertEqual(edge.wif_permitted_tags, ("tag:omnilyzer-task014-ci",))
        self.assertEqual(edge.wif_custom_claims, (
            ("repository", "MichaelTrueX/omnilyzer-platform"),
            ("repository_id", "1350104356"),
            ("workflow_ref", "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-promote.yml@refs/heads/main"),
            ("ref", "refs/heads/main"),
            ("environment", "task014-dev"),
            ("event_name", "workflow_dispatch"),
            ("runner_environment", "github-hosted"),
        ))
        self.assertFalse(any("workflow_sha" in key for key, _ in edge.wif_custom_claims))
        self.assertIsNone(edge.nginx_include_destination)
        for forbidden in ("waf_action", "waf_block_expression", "certificate_path",
                          "private_key_path", "tunnel_origin_service"):
            self.assertFalse(hasattr(edge, forbidden))
        self.assertEqual(plan.status, "pending-live-qualification")
        self.assertFalse(hasattr(edge, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            edge.transport = "public"
        with self.assertRaises(TypeError):
            DevBrokerEdgeContract(transport="public")
        for name, value in (("transport", "funnel"), ("tailscale_https_host", "other"),
                            ("nginx_listen_port", 443), ("logical_broker_host", "other"),
                            ("upstream_response_timeout_seconds", 30)):
            forged = object.__new__(DevBrokerEdgeContract)
            for item in fields(edge):
                object.__setattr__(forged, item.name,
                                   value if item.name == name else getattr(edge, item.name))
            with self.subTest(name=name), self.assertRaises(ValueError):
                forged.qualification_plan()

    def test_exact_local_nginx_asset_and_header_boundary(self):
        edge = DevBrokerEdgeContract()
        payload = ASSET.read_bytes()
        asset = payload.decode("ascii")
        self.assertEqual(edge.nginx_source_path,
                         "deployment/ingress/dev-broker-tailscale-origin.nginx.conf")
        self.assertEqual(edge.nginx_source_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(re.findall(r"^\s*listen\s+([^;]+);", asset, re.M),
                         ["127.0.0.1:3032"])
        self.assertIn("server_name omnilyzerdev.tail52e570.ts.net;", asset)
        self.assertIn('if ($http_host != "omnilyzerdev.tail52e570.ts.net") { return 400; }', asset)
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
            "client_max_body_size 4096;", "client_body_buffer_size 8k;",
            "client_body_in_file_only off;", "proxy_http_version 1.0;",
            "proxy_pass_request_headers off;", "proxy_request_buffering off;",
            "proxy_buffering off;", "proxy_max_temp_file_size 0;", "proxy_cache off;",
            "access_log off;", 'add_header Cache-Control "no-store" always;',
            "proxy_hide_header Set-Cookie;", "proxy_hide_header Location;",
            "proxy_hide_header Access-Control-Allow-Origin;",
            "proxy_connect_timeout 3s;", "proxy_send_timeout 30s;",
            "proxy_read_timeout 900s;",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, asset)
        self.assertEqual(re.findall(r"^\s*proxy_set_header\s+([^;]+);", asset, re.M), [
            "Host deploy-dev.omnilyzer.ai",
            "Authorization $http_authorization",
            "X-Omnilyzer-Zot-OIDC $http_x_omnilyzer_zot_oidc",
            "X-Omnilyzer-Forgejo-OIDC $http_x_omnilyzer_forgejo_oidc",
            "Content-Type application/json",
            "Content-Length $content_length",
            "Connection close",
        ])
        for forbidden in ("listen 80", "listen 443", "0.0.0.0", "[::]",
                          "ssl_certificate", "ssl_certificate_key", "X-Forwarded",
                          "Tailscale-", "CF-Connecting-IP", "return 301", "return 302",
                          "add_header Set-Cookie", "add_header Location"):
            self.assertNotIn(forbidden, asset)

    def test_independent_synchronous_budget_from_frozen_runtime_constants(self):
        # Two OIDC metadata fetches, two release-registry reads, three Cosign
        # executions, then the bounded executor connection and response.
        oidc_cold_path = 2 * (jwks.CONNECT_TIMEOUT_SECONDS + jwks.READ_TIMEOUT_SECONDS)
        release_reads = 2 * (release_consumer.CONNECT_TIMEOUT + release_consumer.READ_TIMEOUT)
        cosign_executions = 3 * blob_verifier.EXECUTION_TIMEOUT
        executor = (unix_transport.MAX_TIMEOUT_MS + unix_transport.RESPONSE_TIMEOUT_MS) / 1000
        derived_ceiling = oidc_cold_path + release_reads + cosign_executions + executor
        self.assertEqual(derived_ceiling, 717.0)
        edge = DevBrokerEdgeContract()
        self.assertGreaterEqual(edge.upstream_response_timeout_seconds, derived_ceiling + 60)
        self.assertEqual(edge.upstream_response_timeout_seconds - derived_ceiling, 183.0)
        asset = ASSET.read_text(encoding="ascii")
        for directive in ("proxy_connect_timeout 3s;", "proxy_send_timeout 30s;",
                          "proxy_read_timeout 900s;"):
            self.assertIn(directive, asset)

    def test_pending_tailscale_plan_has_no_cloudflare_authority(self):
        checks = DevBrokerEdgeQualificationPlan().checks
        self.assertEqual(len(checks), 38)
        self.assertEqual(len(checks), len(set(checks)))
        for marker in (
            "tailscale-package-version-1.102.4-proven", "tailscaled-enabled-and-active",
            "host-online-in-intended-tailnet", "host-magicdns-fqdn-exact",
            "no-funnel-configuration", "serve-private-tailnet-only",
            "github-workload-identity-federation-configured",
            "wif-issuer-exact-github-actions", "wif-subject-exact-task014-dev-environment",
            "wif-scope-auth-keys-only", "wif-permitted-tag-task014-ci-only",
            "wif-supported-custom-claims-exact-github-workload-no-workflow-sha-binding",
            "ephemeral-ci-node-tag-exact",
            "tailnet-policy-ci-tag-only-omnilyzerdev-tcp-443",
            "tailnet-policy-no-ssh-unrelated-ports-or-subnet-route-authority",
            "local-nginx-exact-tailscale-host-only",
            "exact-valid-shaped-private-request-reaches-broker",
            "alternate-path-method-and-query-rejected",
            "local-nginx-rewrites-logical-broker-host-exactly",
            "serve-added-and-arbitrary-headers-cannot-reach-broker",
            "nginx-duplicate-header-combination-proven-by-live-probes",
            "workflow-exact-tailscale-https-endpoint",
            "workflow-no-automatic-promotion-retry",
            "broker-workflow-sha-rotated-to-final-merge-before-activation",
            "frozen-c32w-application-authority-unchanged",
            "c32y-static-resource-authority-otherwise-unchanged",
        ):
            self.assertIn(marker, checks)
        self.assertFalse(any("cloudflare" in item for item in checks))
        docs = (ROOT / "deployment/README.md").read_text()
        section = docs.split("All live checks remain pending.", 1)[1].split(
            "## C32P request-scoped registry", 1)[0]
        self.assertEqual(tuple(re.findall(r"^\d+\. `([^`]+)`", section, re.M)), checks)

    def test_frozen_application_and_historical_tls_asset(self):
        selected = tuple(item.repository_path for item in DevApplicationSourceSet().files)
        self.assertEqual(len(selected), 41)
        for new in ("deployment/broker_edge_contract.py",
                    "deployment/dev_final_broker_resources.py",
                    "deployment/ingress/dev-broker-tailscale-origin.nginx.conf"):
            self.assertNotIn(new, selected)
        successor_deltas = tuple(subprocess.check_output(
            ["git", "diff", "--name-only", TARGET_REVIEWED_COMMIT, "--", *selected],
            cwd=ROOT, text=True,
        ).splitlines())
        self.assertEqual(successor_deltas, ("deployment/docker_runtime.py", "deployment/state_store.py"))
        self.assertEqual(TARGET_MANIFEST_SHA256,
                         "774391d16235855222aa4dedb617112cccc9a862d1599d2546c08b5f8b17c8f9")
        self.assertEqual(TARGET_RUNTIME_SHA256,
                         "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f")
        self.assertEqual(TARGET_INGRESS_SHA256, (
            "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
            "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
            "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
        ))
        historical = ROOT / "deployment/ingress/dev-broker-https.nginx.historical.conf"
        self.assertEqual(hashlib.sha256(historical.read_bytes()).hexdigest(),
                         "0e0b966454fc4e0b9a00d7817e532ab5efa5d9c39a17c5856c6aea0fead5e9c6")
        self.assertEqual(historical.read_bytes(), subprocess.check_output([
            "git", "show", f"{BASE}:deployment/ingress/dev-broker-https.nginx.conf"
        ], cwd=ROOT))
        self.assertFalse((ROOT / "deployment/ingress/dev-broker-https.nginx.conf").exists())
        self.assertFalse((ROOT / "deployment/ingress/dev-broker-tunnel-origin.nginx.conf").exists())


if __name__ == "__main__":
    unittest.main()

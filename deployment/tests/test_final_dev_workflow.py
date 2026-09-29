"""Offline contract and transport tests for the final DEV promotion caller."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import parse, request

import yaml

from deployment.broker_integration import MAX_PROMOTION_REQUEST_BYTES


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-promote.yml"
INPUTS = {
    "target_stage", "release_version", "source_sha", "manifest_digest",
    "release_manifest_sha256", "provenance_sha256", "originating_release_run_id",
}
AUDIENCES = (
    "https://deploy-dev.omnilyzer.ai/task014-dev",
    "https://oci-dev.omnilyzer.ai",
    "u:2:316bec9a-53e4-4807-9557-7febdc979d0a",
)
ENDPOINT = "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote"


class Response:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size: int) -> bytes:
        return self.body[:size]


class FinalDevWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text()
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        cls.gate = cls.workflow["jobs"]["gate"]
        cls.dev = cls.workflow["jobs"]["deploy_dev"]
        cls.script = cls.dev["steps"][-1]["run"].split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        compile(cls.script, "platform-promote.yml:DEV", "exec")

    def test_manual_inputs_and_exact_job_authority(self):
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), INPUTS)
        self.assertTrue(all(value["required"] == "true" for value in inputs.values()))
        self.assertEqual(inputs["target_stage"]["options"], ["dev", "staging", "prod"])
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(set(self.workflow["jobs"]), {"gate", "deploy_dev"})
        self.assertEqual(self.gate["permissions"], {"contents": "read"})
        self.assertNotIn("environment", self.gate)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST", str(self.gate))
        self.assertEqual(self.dev["if"], "${{ inputs.target_stage == 'dev' }}")
        self.assertEqual(self.dev["needs"], "gate")
        self.assertEqual(self.dev["runs-on"], "ubuntu-24.04")
        self.assertEqual(self.dev["environment"], "task014-dev")
        self.assertEqual(self.dev["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(self.dev["timeout-minutes"], "25")
        self.assertEqual([step.get("uses") for step in self.gate["steps"] if "tailscale" in str(step).lower()], [])
        self.assertEqual([step.get("uses") for step in self.dev["steps"] if "tailscale" in str(step).lower()],
                         ["tailscale/github-action@d1b6cd204f8dceda5b3eaad7f1f767be390056cd"])
        tailscale = self.dev["steps"][2]
        self.assertEqual(tailscale["with"], {
            "oauth-client-id": "${{ secrets.TS_OAUTH_CLIENT_ID }}",
            "audience": "${{ secrets.TS_AUDIENCE }}",
            "tags": "tag:omnilyzer-task014-ci",
            "version": "1.102.4",
            "sha256sum": "50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9",
            "retry": "1",
            "timeout": "2m",
            "use-cache": "false",
            "args": "--accept-routes=false --accept-dns=true --shields-up=true",
        })
        self.assertNotIn("authkey", str(tailscale).lower())
        self.assertNotIn("oauth-secret", str(tailscale).lower())
        self.assertNotIn("funnel", str(tailscale).lower())

    def test_request_generation_and_checkout_are_exact(self):
        for job in (self.gate, self.dev):
            checkout = job["steps"][0]
            self.assertEqual(checkout["uses"],
                             "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
            self.assertEqual(checkout["with"],
                             {"ref": "${{ github.sha }}", "persist-credentials": "false"})
        create = self.dev["steps"][1]
        self.assertEqual(set(create["env"]), {
            "TARGET_STAGE", "RELEASE_VERSION", "SOURCE_SHA", "MANIFEST_DIGEST",
            "RELEASE_MANIFEST_SHA256", "PROVENANCE_SHA256", "ORIGINATING_RELEASE_RUN_ID",
            "REQUESTED_BY",
        })
        self.assertEqual(create["env"]["REQUESTED_BY"], "github:${{ github.actor }}")
        self.assertEqual(create["env"]["TARGET_STAGE"], "${{ inputs.target_stage }}")
        for name in INPUTS - {"target_stage"}:
            self.assertEqual(create["env"][name.upper()], "${{ inputs." + name + " }}")
        self.assertIn("umask 077", create["run"])
        self.assertIn("test \"$TARGET_STAGE\" = dev", create["run"])
        self.assertIn("python3 -m deployment.promotion", create["run"])
        self.assertIn('--output "$RUNNER_TEMP/task014-dev-promotion-request.json"', create["run"])
        self.assertNotIn("deployment.controller", create["run"])
        self.assertNotIn("deployment.promotion", self.dev["steps"][-1]["run"])
        self.assertNotIn("upload-artifact", self.raw)
        self.assertEqual(self.raw.count("secrets."), 2)
        self.assertNotIn("set -x", self.raw)
        self.assertNotIn("docker ", self.raw.lower())
        self.assertNotIn("http://", self.raw)
        self.assertNotIn("retry", self.script.lower())
        self.assertIn('ENDPOINT = "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote"', self.script)
        self.assertEqual(self.dev["steps"][3]["name"], "Submit DEV promotion once")

    def run_client(self, *, broker_status=202, broker_body=b'{"status":"accepted"}\n',
                   oidc_body=None, request_body=None):
        with tempfile.TemporaryDirectory() as directory:
            body = (b'{ "canonical": "preserve exact bytes" }\n'
                    if request_body is None else request_body)
            path = Path(directory) / "task014-dev-promotion-request.json"
            path.write_bytes(body)
            path.chmod(0o600)
            calls = []
            options = []

            class Opener:
                def open(self, req, timeout):
                    calls.append((req, timeout))
                    if req.full_url == ENDPOINT:
                        return Response(broker_status, broker_body)
                    audience = parse.parse_qs(parse.urlsplit(req.full_url).query)["audience"][0]
                    if audience not in AUDIENCES:
                        raise AssertionError("unexpected audience")
                    index = AUDIENCES.index(audience)
                    payload = oidc_body if oidc_body is not None else json.dumps(
                        {"value": f"a.b.{index}"}).encode()
                    return Response(200, payload)

            def build_opener(*handlers):
                options.extend(handlers)
                return Opener()

            env = {
                "RUNNER_TEMP": directory,
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.actions.githubusercontent.com/token?x=1",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret",
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                request, "build_opener", side_effect=build_opener
            ):
                exec(compile(self.script, "platform-promote.yml:DEV", "exec"), {})
        return body, calls, options

    def test_three_encoded_audiences_and_exact_broker_submission(self):
        body, calls, handlers = self.run_client()
        self.assertEqual(len(calls), 4)
        self.assertEqual(handlers[0].proxies, {})
        self.assertTrue(issubclass(handlers[1], request.HTTPRedirectHandler))
        with self.assertRaises(ValueError):
            handlers[1]().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.example")
        self.assertEqual([req.full_url for req, _ in calls[:3]], [
            "https://oidc.actions.githubusercontent.com/token?x=1&audience=" + parse.quote(audience, safe="")
            for audience in AUDIENCES
        ])
        self.assertEqual([parse.parse_qs(parse.urlsplit(req.full_url).query)["audience"][0]
                          for req, _ in calls[:3]], list(AUDIENCES))
        self.assertEqual([timeout for _, timeout in calls], [30, 30, 30, 930])
        for req, _ in calls[:3]:
            self.assertEqual(req.get_header("Authorization"), "Bearer runner-secret")
            self.assertNotIn("runner-secret", req.full_url)
        req = calls[-1][0]
        self.assertEqual(req.full_url, ENDPOINT)
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.data, body)
        self.assertEqual(dict(req.header_items()), {
            "Authorization": "Bearer a.b.0",
            "X-omnilyzer-zot-oidc": "a.b.1",
            "X-omnilyzer-forgejo-oidc": "a.b.2",
            "Content-type": "application/json",
        })

    def test_non_exact_response_and_bad_oidc_fail_without_retry(self):
        for status, body in ((200, b'{"status":"accepted"}\n'),
                             (202, b'{"status":"accepted"}'),
                             (302, b'{"status":"accepted"}\n')):
            with self.subTest(status=status, body=body), self.assertRaises(ValueError):
                self.run_client(broker_status=status, broker_body=body)
        for payload in (b'{}', b'{"value":2}', b'{"value":"bad"}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.run_client(oidc_body=payload)

    def test_request_size_matches_reviewed_broker_bound(self):
        self.assertEqual(MAX_PROMOTION_REQUEST_BYTES, 4096)
        self.assertIn("if not 1 <= len(body) <= 4096:", self.script)
        self.assertNotIn("65536", self.script)
        for size in (1, MAX_PROMOTION_REQUEST_BYTES):
            with self.subTest(size=size):
                body, calls, _ = self.run_client(request_body=b"x" * size)
                self.assertEqual(calls[-1][0].data, body)
        for size in (0, MAX_PROMOTION_REQUEST_BYTES + 1):
            with self.subTest(size=size), self.assertRaisesRegex(
                ValueError, "invalid canonical promotion request size"
            ):
                self.run_client(request_body=b"x" * size)

    def test_duplicate_oidc_json_member_is_rejected(self):
        self.assertIn("object_pairs_hook=unique_members", self.script)
        with self.assertRaisesRegex(ValueError, "duplicate GitHub OIDC response member"):
            self.run_client(oidc_body=b'{"value":"a.b.0","value":"a.b.1"}')


if __name__ == "__main__":
    unittest.main()

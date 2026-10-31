"""File: deployment/tests/test_final_dev_workflow.py

Purpose: Preserve the original Task014 canary promotion, private Tailscale,
         three OIDC audiences, HTTP framing and closed response contracts.
Related: .github/workflows/platform-promote.yml,
         deployment/analytics_ci_request.py (separate schema-v2 route),
         deployment/tests/test_analytics_ci_request.py.
Sections: exact manual inputs, original canary request/transport, independent
          product routing, negative OIDC/HTTP failures and diagnostic redaction.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import error, parse, request

import yaml

from deployment.broker_integration import MAX_PROMOTION_REQUEST_BYTES


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-promote.yml"
PROMOTION_INPUTS = {
    "target_stage", "release_version", "source_sha", "manifest_digest",
    "release_manifest_sha256", "provenance_sha256", "originating_release_run_id",
}
INPUTS = PROMOTION_INPUTS | {
    "auth_probe", "product_id", "analytics_installed_commit",
    "analytics_source_claim_sha256",
}
AUDIENCES = (
    "https://deploy-dev.omnilyzer.ai/task014-dev",
    "https://oci-dev.omnilyzer.ai",
    "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb",
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
        cls.steps = {step["name"]: step for step in cls.dev["steps"]}
        cls.join = cls.steps[
            "Join private Task 014 tailnet with direct federated identity"
        ]
        cls.submit = cls.steps["Submit DEV promotion once"]
        cls.cleanup = cls.steps["Leave private Task 014 tailnet"]
        cls.script = cls.submit["run"].split(
            "python3 - <<'PY'\n", 1
        )[1].rsplit("\nPY", 1)[0]
        compile(cls.script, "platform-promote.yml:DEV", "exec")
        cls.join_python = re.findall(
            r"python3 - <<'PY'\n(.*?)\nPY",
            cls.join["run"],
            re.S,
        )
        if len(cls.join_python) != 3:
            raise AssertionError("expected three direct Tailscale Python blocks")
        for index, script in enumerate(cls.join_python, 1):
            compile(script, f"platform-promote.yml:Tailscale:{index}", "exec")

    def test_manual_inputs_and_exact_job_authority(self):
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), INPUTS)
        self.assertEqual(inputs["product_id"], {
            "description": "Exact Task014 product (original canary is default)",
            "required": "true", "type": "choice",
            "options": ["canary", "analytics"], "default": "canary",
        })
        for key in ("analytics_installed_commit", "analytics_source_claim_sha256"):
            self.assertEqual(inputs[key]["required"], "false")
            self.assertEqual(inputs[key]["type"], "string")
            self.assertEqual(inputs[key]["default"], "")
        self.assertEqual(inputs["target_stage"]["required"], "true")
        self.assertEqual(inputs["auth_probe"]["required"], "false")
        self.assertEqual(inputs["auth_probe"]["type"], "boolean")
        self.assertEqual(inputs["auth_probe"]["default"], "false")
        for key in PROMOTION_INPUTS - {"target_stage"}:
            self.assertEqual(inputs[key]["required"], "false")
            self.assertEqual(inputs[key]["default"], "")
        self.assertEqual(inputs["target_stage"]["options"], ["dev", "staging", "prod"])
        self.assertEqual(inputs["target_stage"]["default"], "dev")
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(set(self.workflow["jobs"]), {
            "gate", "deploy_dev", "private_zot_readonly_probe",
        })
        diagnostic = self.workflow["jobs"]["private_zot_readonly_probe"]
        self.assertEqual(diagnostic["if"], "${{ inputs.auth_probe == true }}")
        self.assertEqual(diagnostic["environment"], "task014-dev")
        self.assertEqual(diagnostic["permissions"], {
            "contents": "read", "id-token": "write",
        })
        self.assertEqual(len(diagnostic["steps"]), 3)
        self.assertEqual(diagnostic["steps"][1]["if"], "${{ inputs.product_id == 'analytics' }}")
        self.assertEqual(diagnostic["steps"][1]["uses"], "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6")
        self.assertEqual(diagnostic["steps"][1]["with"], {"cosign-release": "v3.1.2"})
        self.assertIn("release.private_zot_auth_probe", diagnostic["steps"][2]["run"])
        self.assertEqual(
            diagnostic["steps"][2]["env"],
            {"DIAGNOSTIC_TARGET_STAGE": "${{ inputs.target_stage }}",
             "DIAGNOSTIC_PRODUCT_ID": "${{ inputs.product_id }}"},
        )
        self.assertIn('test "$DIAGNOSTIC_TARGET_STAGE" = dev',
                      diagnostic["steps"][2]["run"])
        self.assertNotIn("deployment.promotion", str(diagnostic))
        self.assertNotIn("deployment.controller", str(diagnostic))
        self.assertNotIn("secrets.", str(diagnostic))
        self.assertNotIn("tailscale", str(diagnostic).lower())
        self.assertEqual(self.gate["if"], "${{ inputs.auth_probe != true }}")
        self.assertEqual(self.gate["permissions"], {"contents": "read"})
        self.assertNotIn("environment", self.gate)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST", str(self.gate))
        self.assertEqual(
            self.dev["if"],
            "${{ inputs.auth_probe != true && inputs.target_stage == 'dev' }}",
        )
        self.assertEqual(self.dev["needs"], "gate")
        self.assertEqual(self.dev["runs-on"], "ubuntu-24.04")
        self.assertEqual(self.dev["environment"], "task014-dev")
        self.assertEqual(self.dev["permissions"], {"contents": "read", "id-token": "write"})
        self.assertEqual(self.dev["timeout-minutes"], "25")
        self.assertEqual([step.get("uses") for step in self.gate["steps"] if "tailscale" in str(step).lower()], [])
        self.assertEqual(
            [
                step.get("uses")
                for step in self.dev["steps"]
                if "tailscale" in str(step).lower() and "uses" in step
            ],
            [],
        )
        self.assertNotIn("uses", self.join)
        self.assertEqual(
            self.join["env"],
            {
                "TS_OAUTH_CLIENT_ID": "${{ secrets.TS_OAUTH_CLIENT_ID }}",
                "TS_AUDIENCE": "${{ secrets.TS_AUDIENCE }}",
            },
        )
        join = self.join["run"]
        self.assertIn('TS_VERSION="1.102.4"', join)
        self.assertIn(
            'TS_SHA256="50748df1045e60b5b695f19f4c56b0da36c019948b440fb456b6584a50f0d8b9"',
            join,
        )
        self.assertIn(
            '"https://pkgs.tailscale.com/stable/"',
            join,
        )
        self.assertEqual(
            re.findall(r"--accept-routes(?:=[^\s\\]+)?", join),
            ["--accept-routes=false"],
        )
        for argument in (
            "--accept-dns=true",
            "--shields-up=true",
            "--advertise-tags=tag:omnilyzer-task014-ci",
            "--timeout=2m",
            "--client-id=",
            '--id-token="file:$TS_ROOT/id-token"',
        ):
            with self.subTest(argument=argument):
                self.assertEqual(join.count(argument), 1)
        self.assertEqual(join.count('sudo -n "$TS_DIR/tailscale" up'), 1)
        self.assertIn('chown "$SUDO_UID:$SUDO_GID" "$1"', join)
        self.assertIn('chmod 0600 "$1"', join)
        self.assertNotIn("retry", join.lower())
        self.assertNotIn("authkey", join.lower())
        self.assertNotIn("oauth-secret", join.lower())
        self.assertNotIn("funnel", join.lower())
        self.assertNotIn("sudo -E", join)
        self.assertNotIn('ID_TOKEN="$(cat', join)
        self.assertIn(
            'request_host.endswith(".actions.githubusercontent.com")',
            join,
        )
        self.assertIn('parsed.scheme != "https"', join)
        self.assertIn('request_port not in (None, 443)', join)
        self.assertIn(
            'any(key == "audience" for key, _value in query)',
            join,
        )
        self.assertEqual(self.cleanup["if"], "${{ always() }}")
        self.assertIn('sudo -n "$TS_DIR/tailscale" logout', self.cleanup["run"])
        self.assertIn('read -r daemon_pid <"$TS_ROOT/tailscaled.pid"', self.cleanup["run"])
        self.assertIn('readlink -f "/proc/$daemon_pid/exe"', self.cleanup["run"])
        self.assertIn('sudo -n kill -TERM "$daemon_pid"', self.cleanup["run"])
        self.assertNotIn("pkill", self.cleanup["run"])
        self.assertNotIn("secrets.", self.cleanup["run"])

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
            "REQUESTED_BY", "TASK014_PRODUCT", "ANALYTICS_INSTALLED_COMMIT",
            "ANALYTICS_SOURCE_CLAIM_SHA256",
        })
        self.assertEqual(create["env"]["TASK014_PRODUCT"], "${{ inputs.product_id }}")
        self.assertEqual(create["env"]["ANALYTICS_INSTALLED_COMMIT"],
                         "${{ inputs.analytics_installed_commit }}")
        self.assertEqual(create["env"]["ANALYTICS_SOURCE_CLAIM_SHA256"],
                         "${{ inputs.analytics_source_claim_sha256 }}")
        self.assertIn("python3 -m deployment.analytics_ci_request --preflight",
                      create["run"])
        self.assertIn('if [ "$TASK014_PRODUCT" = analytics ]; then',
                      create["run"])
        self.assertEqual(create["env"]["REQUESTED_BY"], "github:${{ github.actor }}")
        self.assertEqual(create["env"]["TARGET_STAGE"], "${{ inputs.target_stage }}")
        for name in PROMOTION_INPUTS - {"target_stage"}:
            self.assertEqual(create["env"][name.upper()], "${{ inputs." + name + " }}")
        self.assertIn("umask 077", create["run"])
        self.assertIn("test \"$TARGET_STAGE\" = dev", create["run"])
        self.assertIn("python3 -m deployment.promotion", create["run"])
        self.assertIn('--output "$RUNNER_TEMP/task014-dev-promotion-request.json"', create["run"])
        self.assertNotIn("deployment.controller", create["run"])
        self.assertNotIn("deployment.promotion", self.submit["run"])
        self.assertIn("build_analytics_ci_request(", self.submit["run"])
        self.assertIn('elif os.environ.get("TASK014_PRODUCT") in ("canary", None):',
                      self.submit["run"])
        self.assertEqual(self.submit["env"]["TASK014_PRODUCT"],
                         "${{ inputs.product_id }}")
        self.assertIn("python3 -m deployment.analytics_ci_request --preflight",
                      self.gate["steps"][1]["run"])
        self.assertNotIn("upload-artifact", self.raw)
        self.assertEqual(self.raw.count("secrets."), 2)
        self.assertNotIn("set -x", self.raw)
        self.assertNotIn("docker ", str((self.gate, self.dev)).lower())
        self.assertNotIn("http://", self.raw)
        self.assertNotIn("retry", self.script.lower())
        self.assertNotIn("tailscale/github-action", self.raw)
        self.assertIn('ENDPOINT = "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote"', self.script)
        self.assertEqual(self.dev["steps"][3]["name"], "Submit DEV promotion once")
        self.assertEqual(self.dev["steps"][4]["name"], "Leave private Task 014 tailnet")

    def run_client(self, *, broker_status=202, broker_body=b'{"status":"accepted"}\n',
                   oidc_body=None, request_body=None, raise_broker_http_error=False):
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
                        if raise_broker_http_error:
                            raise error.HTTPError(
                                req.full_url, broker_status, "synthetic", {},
                                io.BytesIO(broker_body),
                            )
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

    def test_c34d_response_shape_diagnostics_are_secret_free(self):
        """The workflow reports only a status and fixed rejection shape."""
        cases = (
            (403, b'{"status":"rejected"}\n', "fixed_broker_rejection_shape"),
            (403, b"<html>synthetic secret</html>", "other_response_shape"),
            (503, b'{"status":"unavailable"}\n', "other_response_shape"),
        )
        for status, body, shape in cases:
            with self.subTest(status=status, shape=shape):
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(error.HTTPError):
                    self.run_client(
                        broker_status=status, broker_body=body,
                        raise_broker_http_error=True,
                    )
                result = output.getvalue()
                self.assertEqual(
                    result, f"task014_diag http_status={status} response_shape={shape}\n"
                )
                self.assertNotIn("synthetic secret", result)
                self.assertNotIn("a.b.0", result)

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

"""File: deployment/tests/test_analytics_ci_request.py

Purpose: Validate exact Analytics 0.15.0 schema-v2 request generation inside
         the original Task014 GitHub promotion workflow, preserving canary.
Related: deployment/analytics_ci_request.py,
         deployment/analytics_execution.py (canonical request parser),
         .github/workflows/platform-promote.yml (original OIDC transport),
         deployment/tests/test_final_dev_workflow.py.

Sections: exact approved dispatch/identity shape; negative unverified OIDC and
          release-input tests; actual workflow inline Python with synthetic
          GitHub JWT audience responses and captured (not sent) broker POST.

No real JWT signature, network, root permission, broker, Docker, database,
secrets or deployment. The root broker must authenticate every actual claim.
"""
from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib import parse, request

import yaml

from deployment.analytics_ci_request import (
    AnalyticsCIDispatchError, build_analytics_ci_request,
    validate_analytics_ci_inputs, resolve_analytics_ci_release_inputs,
)
from deployment.analytics_execution import parse_analytics_request
from deployment.analytics_signed_release_consumer import (
    PINNED_DIGEST, PINNED_PLATFORM_COMMIT, PINNED_RUN_ID, PINNED_VERSION,
)
from deployment.identity import DEV_AUDIENCE, DEV_REPOSITORY
from deployment.policy import canonical_bytes
from deployment.tests.test_analytics_signed_release_consumer import fixture, archive
from deployment.tests.test_analytics_execution import EXPECTED
from deployment.tests.test_identity import valid_claims, WORKFLOW_SHA, NOW

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/platform-promote.yml"
AUDIENCES = (
    DEV_AUDIENCE, "https://oci-dev.omnilyzer.ai",
    "u:3:d4f50b90-f001-4b9f-ad1e-487080ec44fb",
)


def dispatch() -> dict[str, str]:
    """Mock exact GitHub manual Analytics input and identity metadata."""
    claims = valid_claims()
    return {
        "TASK014_PRODUCT": "analytics",
        "TARGET_STAGE": "dev",
        "GITHUB_REPOSITORY": DEV_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": WORKFLOW_SHA,
        "GITHUB_RUN_ID": claims["run_id"],
        "GITHUB_RUN_ATTEMPT": claims["run_attempt"],
        "GITHUB_ACTOR_ID": claims["actor_id"],
        "RELEASE_VERSION": PINNED_VERSION,
        "SOURCE_SHA": PINNED_PLATFORM_COMMIT,
        "MANIFEST_DIGEST": PINNED_DIGEST,
        "RELEASE_MANIFEST_SHA256": "a" * 64,
        "PROVENANCE_SHA256": "b" * 64,
        "ORIGINATING_RELEASE_RUN_ID": str(PINNED_RUN_ID),
        "ANALYTICS_INSTALLED_COMMIT": EXPECTED["reviewed_installed_commit"],
        "ANALYTICS_SOURCE_CLAIM_SHA256": "e" * 64,
    }


def token(claims=None, audience=DEV_AUDIENCE) -> str:
    """Encode *UNSIGNED SYNTHETIC* JWT-shaped data for runner-side tests."""
    value = {**valid_claims(), "aud": audience, **(claims or {})}
    def encoded(data):
        return base64.urlsafe_b64encode(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode(),
        ).rstrip(b"=").decode("ascii")
    return ".".join((encoded({"alg": "RS256", "typ": "JWT"}),
                     encoded(value), encoded({"test": "NOT-A-SIGNATURE"})))


class AnalyticsCIRequestTests(unittest.TestCase):
    """The client never authenticates or authorizes its own request bytes."""

    def test_exact_signed_release_and_untrusted_identity_request(self):
        """Only the original broker can authenticate the generated schema v2."""
        result = build_analytics_ci_request(
            deployment_oidc_token=token(), environment=dispatch(),
        )
        self.assertLessEqual(len(result), 4096)
        parsed = parse_analytics_request(result, **EXPECTED)
        self.assertEqual(parsed.schema_version, 2)
        self.assertEqual(parsed.product_id, "analytics")
        self.assertEqual(parsed.requested_by_actor_id, int(valid_claims()["actor_id"]))
        self.assertEqual(parsed.github_workflow_sha, WORKFLOW_SHA)
        self.assertEqual(parsed.oidc_jti, valid_claims()["jti"])
        self.assertEqual(parsed.source_claim_sha256, "e" * 64)
        self.assertTrue(parsed.secrets_reference["rootless_required"])
        self.assertIsNone(parsed.ingress_reference["public_origin"])
        self.assertEqual(result, parsed.canonical_bytes())
        self.assertEqual(result, build_analytics_ci_request(
            deployment_oidc_token=token(), environment=dispatch(),
        ))

    def test_invalid_dispatch_denies_before_oidc_or_broker(self):
        """Wrong product, stage, signed release or unsigned user digest denies."""
        original = dispatch()
        for key, replacement in (
            ("TASK014_PRODUCT", "canary"),
            ("TASK014_PRODUCT", "unknown"),
            ("TARGET_STAGE", "prod"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_EVENT_NAME", "push"),
            ("RELEASE_VERSION", "0.15.1"),
            ("SOURCE_SHA", "f" * 40),
            ("MANIFEST_DIGEST", "sha256:" + "0" * 64),
            ("RELEASE_MANIFEST_SHA256", "0" * 64),
            ("PROVENANCE_SHA256", "z" * 64),
            ("ORIGINATING_RELEASE_RUN_ID", "1"),
            ("ANALYTICS_INSTALLED_COMMIT", "f" * 39),
            ("ANALYTICS_SOURCE_CLAIM_SHA256", "0" * 64),
            ("ANALYTICS_SOURCE_CLAIM_SHA256", "f" * 63),
        ):
            with self.subTest(key=key, value=replacement):
                candidate = {**original, key: replacement}
                with self.assertRaises(AnalyticsCIDispatchError):
                    validate_analytics_ci_inputs(candidate)

    def test_unverified_oidc_shape_and_run_metadata_mismatch_rejected(self):
        """Missing, cross-run or cross-audience token fields never reach POST."""
        for field, altered in (
            ("aud", "https://oci-dev.omnilyzer.ai"),
            ("iss", "https://example.invalid"),
            ("repository_id", "123"),
            ("workflow_sha", "0" * 40),
            ("workflow_ref", "evil"),
            ("ref", "refs/heads/evil"),
            ("run_id", "42"),
            ("run_attempt", "3"),
            ("actor_id", "45"),
            ("jti", "../evil"),
            ("exp", valid_claims()["iat"]),
        ):
            with self.subTest(field=field), self.assertRaises(
                AnalyticsCIDispatchError,
            ):
                build_analytics_ci_request(
                    deployment_oidc_token=token({field: altered}),
                    environment=dispatch(),
                )
        for field, bad in (
            ("GITHUB_SHA", "c" * 40),
            ("GITHUB_RUN_ID", "100"),
            ("GITHUB_RUN_ATTEMPT", "0"),
            ("GITHUB_ACTOR_ID", "100"),
        ):
            with self.subTest(field=field), self.assertRaises(
                AnalyticsCIDispatchError,
            ):
                build_analytics_ci_request(
                    deployment_oidc_token=token(),
                    environment={**dispatch(), field: bad},
                )
        with self.assertRaises(AnalyticsCIDispatchError):
            build_analytics_ci_request(
                deployment_oidc_token="not.a.valid.jwt",
                environment=dispatch(),
            )

    def test_cli_preflight_requires_exact_analytics_workflow(self):
        """Read-only CLI prints only one fixed status, never token or hashes."""
        from deployment.analytics_ci_request import main
        import contextlib
        with tempfile.TemporaryFile(mode="w+") as output, patch.dict(
            os.environ, dispatch(), clear=True,
        ), patch("sys.argv", ["analytics_ci_request", "--preflight"]), \
             contextlib.redirect_stdout(output):
            self.assertEqual(main(), 0)
            output.seek(0)
            self.assertEqual(output.read(), "analytics_task014_preflight_ok\n")

    def test_all_empty_hash_gate_only_allows_deferred_resolution(self):
        """A read-only gate may defer three hashes; request creation may not."""
        env = {**dispatch(), "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
               "ANALYTICS_SOURCE_CLAIM_SHA256": ""}
        self.assertEqual(validate_analytics_ci_inputs(
            env, allow_metadata_resolution=True,
        )["PROVENANCE_SHA256"], "")
        with self.assertRaises(AnalyticsCIDispatchError):
            build_analytics_ci_request(deployment_oidc_token=token(), environment=env)
        for key in ("RELEASE_MANIFEST_SHA256", "PROVENANCE_SHA256", "ANALYTICS_SOURCE_CLAIM_SHA256"):
            with self.subTest(key=key), self.assertRaises(AnalyticsCIDispatchError):
                validate_analytics_ci_inputs({**env, key: "a" * 64}, allow_metadata_resolution=True)

    def test_authenticated_metadata_uses_exact_archive_bytes_without_authorizing(self):
        """Resolve request inputs from the actual closed-schema synthetic archive."""
        evidence, _ = fixture()
        env = {**dispatch(), "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
               "ANALYTICS_SOURCE_CLAIM_SHA256": ""}
        jwt = token(audience=AUDIENCES[2])
        with patch("deployment.release_consumer._get", return_value=(archive(evidence), {})) as get:
            result = resolve_analytics_ci_release_inputs(environment=env, forgejo_oidc_token=jwt)
        get.assert_called_once()
        self.assertEqual(get.call_args.args[:3], ("forgejo", PINNED_VERSION, jwt))
        self.assertEqual(get.call_args.kwargs, {"product": "analytics"})
        self.assertEqual(result["RELEASE_MANIFEST_SHA256"], hashlib.sha256(evidence["release-manifest.json"]).hexdigest())
        self.assertEqual(result["PROVENANCE_SHA256"], hashlib.sha256(evidence["release-provenance.json"]).hexdigest())
        claim = json.loads(evidence["release-manifest.json"])["external_source"]
        self.assertEqual(result["ANALYTICS_SOURCE_CLAIM_SHA256"], hashlib.sha256(canonical_bytes(claim)).hexdigest())
        self.assertEqual(env["PROVENANCE_SHA256"], "")
        self.assertNotIn(jwt, json.dumps(result))
        body = build_analytics_ci_request(deployment_oidc_token=token(), environment=result)
        self.assertEqual(parse_analytics_request(body, **EXPECTED).product_id, "analytics")

    def test_explicit_hash_mode_keeps_existing_no_network_path(self):
        """Existing complete manual inputs retain their original behavior."""
        env = dispatch()
        with patch("deployment.release_consumer._get") as get:
            self.assertEqual(resolve_analytics_ci_release_inputs(
                environment=env, forgejo_oidc_token="unused",
            ), env)
        get.assert_not_called()

    def test_wrong_token_or_dispatch_fails_before_metadata_get(self):
        """No canary credential, wrong stage or malformed input reaches Forgejo."""
        env = {**dispatch(), "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
               "ANALYTICS_SOURCE_CLAIM_SHA256": ""}
        for candidate, jwt in (
            (env, token()), (env, "not-a-jwt"), (env, "secret with whitespace"),
            ({**env, "TARGET_STAGE": "prod"}, token(audience=AUDIENCES[2])),
            ({**env, "PROVENANCE_SHA256": "a" * 64}, token(audience=AUDIENCES[2])),
        ):
            with self.subTest(candidate=candidate["TARGET_STAGE"]), patch("deployment.release_consumer._get") as get:
                with self.assertRaises(AnalyticsCIDispatchError):
                    resolve_analytics_ci_release_inputs(environment=candidate, forgejo_oidc_token=jwt)
                get.assert_not_called()

    def test_wrong_private_metadata_is_rejected_without_leaking_details(self):
        """Fail closed on missing/scanner-mismatched/wrong-release archive data."""
        evidence, _ = fixture()
        env = {**dispatch(), "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
               "ANALYTICS_SOURCE_CLAIM_SHA256": ""}
        wrong = dict(evidence)
        manifest = json.loads(wrong["release-manifest.json"])
        manifest["version"] = "99.0.0"
        wrong["release-manifest.json"] = canonical_bytes(manifest)
        scanner_wrong = {**evidence, "oci-grype.json": b"PRIVATE_DYNAMIC_DATA"}
        for payload in (b"PRIVATE_DYNAMIC_DATA", archive(wrong), archive(scanner_wrong),
                        archive(evidence, omit_name="release-provenance.json")):
            with self.subTest(size=len(payload)), patch("deployment.release_consumer._get", return_value=(payload, {})):
                with self.assertRaises(AnalyticsCIDispatchError) as caught:
                    resolve_analytics_ci_release_inputs(environment=env, forgejo_oidc_token=token(audience=AUDIENCES[2]))
                self.assertEqual(str(caught.exception), "Task014 Analytics CI request rejected")

    def test_real_bash_workflow_gate_routes_only_exact_analytics_dev(self):
        """Execute the actual existing Task014 gate offline without any OIDC.

        Rootless/Sigstore authorization is NOT tested here; the runner gate
        only prevents invalid product/stage/release inputs before obtaining
        private credentials or entering the real broker.
        """
        import subprocess
        value = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        gate = value["jobs"]["gate"]["steps"][1]["run"]
        env = {**dispatch(), "PATH": "/usr/bin:/bin",
               "PYTHONPATH": str(ROOT)}
        result = subprocess.run(
            ("/bin/bash", "-c", gate), env=env, cwd=str(ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("analytics_task014_preflight_ok", result.stdout)
        self.assertNotIn("Bearer ", result.stdout + result.stderr)

        auto = subprocess.run(
            ("/bin/bash", "-c", gate),
            env={**env, "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
                 "ANALYTICS_SOURCE_CLAIM_SHA256": ""}, cwd=str(ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=15, check=False,
        )
        self.assertEqual(auto.returncode, 0, auto.stderr)
        self.assertIn("analytics_task014_preflight_ok", auto.stdout)

        for key, new in (
            ("TARGET_STAGE", "prod"),
            ("TASK014_PRODUCT", "unknown"),
            ("MANIFEST_DIGEST", "sha256:" + "0" * 64),
            ("ANALYTICS_SOURCE_CLAIM_SHA256", ""),
        ):
            with self.subTest(key=key):
                denied = subprocess.run(
                    ("/bin/bash", "-c", gate),
                    env={**env, key: new}, cwd=str(ROOT),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=15, check=False,
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertNotIn("Bearer ", denied.stdout + denied.stderr)

    def test_existing_workflow_submits_only_canonical_analytics_schema_v2(self):
        """Real embedded Task014 HTTP client, synthetic OIDC and no network."""
        value = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        steps = value["jobs"]["deploy_dev"]["steps"]
        submit = next(step for step in steps if step["name"] == "Submit DEV promotion once")
        script = submit["run"].split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        captured = []

        class Response:
            """Closed synthetic GitHub OIDC or original broker HTTP response."""
            status = 200
            def __init__(self, body: bytes, status=200):
                self.body = body
                self.status = status
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, count=-1):
                return self.body[:count] if count != -1 else self.body

        class Opener:
            """Capture all three OIDC JWT audiences and one exact body."""
            def open(self, req, timeout):
                parsed = parse.urlsplit(req.full_url)
                if (
                    parsed.scheme == "https"
                    and parsed.hostname == "oidc.actions.githubusercontent.com"
                    and parsed.port in (None, 443)
                    and parsed.path == "/token"
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.fragment
                ):
                    audience = parse.parse_qs(
                        parsed.query,
                    )["audience"][0]
                    self.assert_audience(audience)
                    body = json.dumps({"value": token(audience=audience)}).encode()
                    captured.append(("oidc", audience))
                    return Response(body)
                self.assert_url(req.full_url)
                captured.append(("post", req, timeout))
                return Response(b'{"status":"accepted"}\n', 202)
            def assert_audience(self, audience):
                if audience not in AUDIENCES:
                    raise AssertionError("unrecognized OIDC audience")
            def assert_url(self, url):
                if url != "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote":
                    raise AssertionError("wrong endpoint")
        env = {
            **dispatch(),
            "ACTIONS_ID_TOKEN_REQUEST_URL":
                "https://oidc.actions.githubusercontent.com/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-only-token",
        }
        with tempfile.TemporaryDirectory() as directory:
            env["RUNNER_TEMP"] = directory
            with patch.dict(os.environ, env, clear=True), patch.object(
                request, "build_opener", return_value=Opener(),
            ), patch("time.time", return_value=NOW):
                exec(compile(script, "platform-promote.yml:DEV", "exec"), {})
        self.assertEqual([v[0] for v in captured], [
            "oidc", "oidc", "oidc", "post",
        ])
        self.assertEqual([v[1] for v in captured[:3]], list(AUDIENCES))
        request_obj = captured[-1][1]
        self.assertEqual(captured[-1][2], 930)
        self.assertEqual(request_obj.get_method(), "POST")
        data = request_obj.data
        self.assertEqual(data, build_analytics_ci_request(
            deployment_oidc_token=token(), environment=dispatch(),
        ))
        self.assertEqual(parse_analytics_request(data, **EXPECTED).product_id, "analytics")
        self.assertNotIn(b"test-only-token", data)

    def test_real_workflow_automatic_hashes_and_metadata_failure_before_post(self):
        """Run actual client code: three OIDC tokens, one metadata GET, one POST."""
        value = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        submit = next(step for step in value["jobs"]["deploy_dev"]["steps"]
                      if step["name"] == "Submit DEV promotion once")
        script = submit["run"].split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        evidence, _ = fixture()
        env = {**dispatch(), "RELEASE_MANIFEST_SHA256": "", "PROVENANCE_SHA256": "",
               "ANALYTICS_SOURCE_CLAIM_SHA256": "",
               "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.actions.githubusercontent.com/token",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-only-runner-token"}

        class Response:
            def __init__(self, body, status=200):
                self.body, self.status = body, status
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, count=-1):
                return self.body[:count] if count >= 0 else self.body

        for payload in (archive(evidence), b"PRIVATE_BAD_ARCHIVE", RuntimeError("PRIVATE_NETWORK_ERROR")):
            with self.subTest(success=isinstance(payload, bytes) and payload.startswith(b"\x1f\x8b")):
                events = []
                posted = []
                class Opener:
                    def open(self, req, timeout):
                        parsed = parse.urlsplit(req.full_url)
                        if (
                            parsed.scheme == "https"
                            and parsed.hostname == "oidc.actions.githubusercontent.com"
                            and parsed.port in (None, 443)
                            and parsed.path == "/token"
                            and parsed.username is None
                            and parsed.password is None
                            and not parsed.fragment
                        ):
                            audience = parse.parse_qs(parsed.query)["audience"][0]
                            if audience not in AUDIENCES:
                                raise AssertionError("unexpected audience")
                            events.append("oidc")
                            return Response(json.dumps({"value": token(audience=audience)}).encode())
                        if req.full_url != "https://omnilyzerdev.tail52e570.ts.net/task014/dev/promote" or req.get_method() != "POST":
                            raise AssertionError("unexpected URL or method")
                        events.append("post")
                        posted.append(req.data)
                        return Response(b'{"status":"accepted"}\n', 202)
                def metadata(*args, **kwargs):
                    events.append("metadata")
                    self.assertEqual(args[:3], ("forgejo", PINNED_VERSION, token(audience=AUDIENCES[2])))
                    self.assertEqual(kwargs, {"product": "analytics"})
                    if isinstance(payload, Exception):
                        raise payload
                    return payload, {}
                with patch.dict(os.environ, env, clear=True), patch.object(
                    request, "build_opener", return_value=Opener(),
                ), patch("time.time", return_value=NOW), patch("deployment.release_consumer._get", side_effect=metadata):
                    if isinstance(payload, bytes) and payload.startswith(b"\x1f\x8b"):
                        exec(compile(script, "platform-promote.yml:auto", "exec"), {})
                        self.assertEqual(events, ["oidc", "oidc", "oidc", "metadata", "post"])
                        parsed = parse_analytics_request(posted[0], **EXPECTED)
                        self.assertEqual(parsed.release_manifest_sha256, hashlib.sha256(evidence["release-manifest.json"]).hexdigest())
                    else:
                        with self.assertRaises(AnalyticsCIDispatchError) as error:
                            exec(compile(script, "platform-promote.yml:auto", "exec"), {})
                        self.assertEqual(str(error.exception), "Task014 Analytics CI request rejected")
                        self.assertEqual(events, ["oidc", "oidc", "oidc", "metadata"])
                        self.assertEqual(posted, [])


if __name__ == "__main__":
    unittest.main()

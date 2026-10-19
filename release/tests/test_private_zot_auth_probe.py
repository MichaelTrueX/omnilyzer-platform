"""File: release/tests/test_private_zot_auth_probe.py

Purpose: Offline acceptance of the Task014 read-only protected-main Zot
diagnostic. No GitHub token request, registry connection, Docker operation,
broker request or deployment is made by these tests.
Links: release/private_zot_auth_probe.py,
.github/workflows/platform-promote.yml,
deployment/tests/test_final_dev_workflow.py.

Sections: exact workflow context, bounded JWT claims and OIDC endpoint
verification, confidential Docker config and failure/cleanup behavior.
"""

from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from release import private_zot_auth_probe as probe

NOW = 1_800_000_000
SHA = "a" * 40
OIDC_URL = "https://pipelines.actions.githubusercontent.com/aaaaaaaa/oidc"
RUNNER_TOKEN = "synthetic-github-runner-token"
ENVIRONMENT = {
    "GITHUB_REPOSITORY": probe.REPOSITORY,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_WORKFLOW_REF": probe.WORKFLOW_REF,
    "GITHUB_SHA": SHA,
    "RUNNER_ENVIRONMENT": "github-hosted",
    "ACTIONS_ID_TOKEN_REQUEST_URL": OIDC_URL,
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": RUNNER_TOKEN,
}


def synthetic_jwt(**claims_override: object) -> str:
    """Generate a non-signed, strictly test-only GitHub-shaped claim set."""
    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": probe.AUDIENCE,
        "repository": probe.REPOSITORY,
        "repository_id": "1350104356",
        "repository_owner_id": "130741173",
        "ref": "refs/heads/main",
        "workflow_ref": probe.WORKFLOW_REF,
        "workflow_sha": SHA,
        "event_name": "workflow_dispatch",
        "environment": probe.ENVIRONMENT,
        "runner_environment": "github-hosted",
        "iat": NOW - 5,
        "nbf": NOW - 5,
        "exp": NOW + 200,
    }
    claims.update(claims_override)

    def encode(value: dict[str, object]) -> str:
        """Return URL-safe base64 without padding for fake JWT segments."""
        return base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
        ).rstrip(b"=").decode("ascii")

    return encode({"alg": "RS256"}) + "." + encode(claims) + ".synthetic_signature"


class StubResponse:
    """One bounded in-memory GitHub OIDC HTTP 200 response."""

    status = 200

    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def __enter__(self) -> "StubResponse":
        """Use existing context-manager ownership semantics."""
        return self

    def __exit__(self, *args: object) -> None:
        """Allow deterministic response closure without external I/O."""
        return None

    def read(self, size: int) -> bytes:
        """Return at most the declared HTTP bound."""
        return self.raw[:size]


class OIDCProbeSecurityTests(unittest.TestCase):
    """Verify fail-closed context, claims, Docker cleanup and stdout redaction."""

    def test_exact_main_context_and_valid_claims_pass(self) -> None:
        """The right workflow revision and short expiry permit a read-only call."""
        self.assertEqual(probe._workflow_context_preflight(ENVIRONMENT), SHA)
        probe._claims_preflight(synthetic_jwt(), ENVIRONMENT, NOW)

    def test_wrong_workflow_environment_or_source_denied(self) -> None:
        """Cross-branch and nonapproved workflow claims never authorize a probe."""
        for name, invalid in (
            ("GITHUB_REF", "refs/heads/task014/private-branch"),
            ("GITHUB_REPOSITORY", "another/repo"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_WORKFLOW_REF", "another/workflow@refs/heads/main"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_SHA", "b" * 39),
        ):
            with self.subTest(name=name):
                changed = dict(ENVIRONMENT, **{name: invalid})
                with self.assertRaises(probe.ProbeUnavailableError):
                    probe._workflow_context_preflight(changed)

    def test_invalid_claims_expiry_and_repository_denied(self) -> None:
        """Never accept expired, far-future or changed GitHub OIDC claims."""
        cases = (
            {"environment": "other"},
            {"repository_id": "0"},
            {"workflow_ref": "unreviewed@refs/heads/main"},
            {"workflow_sha": "c" * 40},
            {"aud": "https://deploy-dev.omnilyzer.ai/task014-dev"},
            {"exp": NOW + 360},
            {"exp": NOW + 1},
            {"iat": NOW - 200},
            {"nbf": NOW + 60},
            {"exp": True},
        )
        for variant in cases:
            with self.subTest(variant=variant):
                with self.assertRaises(probe.ProbeUnavailableError):
                    probe._claims_preflight(
                        synthetic_jwt(**variant), ENVIRONMENT, NOW
                    )

    def test_oidc_request_uses_exact_audience_without_redirect(self) -> None:
        """Runner token stays in Authorization and issued JWT stays in memory."""
        fake = synthetic_jwt()
        response = StubResponse(json.dumps({"value": fake}).encode())
        seen: list[tuple[str, str]] = []

        class StubOpener:
            """Record only synthetic request URL and header."""

            def open(self, req: object, *, timeout: int) -> StubResponse:
                """Simulate exactly one GitHub Actions OIDC GET."""
                seen.append((req.full_url, req.get_header("Authorization")))
                self_timeout = timeout
                assert self_timeout == 20
                return response

        with patch.object(probe.request, "build_opener", return_value=StubOpener()):
            token = probe._oidc_token(ENVIRONMENT)
        self.assertEqual(token, fake)
        self.assertEqual(len(seen), 1)
        self.assertEqual(
            seen[0][0],
            OIDC_URL + "?audience=https%3A%2F%2Foci-dev.omnilyzer.ai",
        )
        self.assertEqual(seen[0][1], "Bearer " + RUNNER_TOKEN)

    def test_invalid_oidc_request_url_rejected_without_network(self) -> None:
        """No redirect host, query audience injection or HTTP endpoint is valid."""
        for value in (
            "http://pipelines.actions.githubusercontent.com/a",
            "https://attacker.invalid/oidc",
            OIDC_URL + "?audience=attacker",
            "https://evil.example/pipelines.actions.githubusercontent.com",
        ):
            with self.subTest(value=value):
                with patch.object(probe.request, "build_opener") as opener:
                    altered = dict(ENVIRONMENT,
                                   ACTIONS_ID_TOKEN_REQUEST_URL=value)
                    with self.assertRaises(probe.ProbeUnavailableError):
                        probe._oidc_token(altered)
                    opener.assert_not_called()

    def test_docker_exact_digest_temporary_basic_credential_and_cleanup(self) -> None:
        """Real runner boundary passes no token in argv/env, only private 0600 config."""
        token = synthetic_jwt()
        observed: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            """Inspect private, single-host Docker auth config during fake process."""
            self.assertEqual(argv[0], probe.DOCKER_CLI)
            self.assertEqual(argv[1], "--config")
            self.assertEqual(argv[3:], ["manifest", "inspect", probe.CANARY_IMAGE])
            self.assertNotIn(token, repr(argv))
            self.assertNotIn(token, repr(kwargs["env"]))
            directory = Path(argv[2])
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            config = directory / "config.json"
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            value = json.loads(config.read_text())
            self.assertEqual(set(value), {"auths"})
            self.assertEqual(set(value["auths"]), {probe.OCI_HOST})
            encoded = value["auths"][probe.OCI_HOST]["auth"]
            self.assertEqual(
                base64.b64decode(encoded).decode("ascii"), "oidc:" + token
            )
            observed.append((tuple(argv), kwargs["env"]))
            answer = json.dumps({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
            }).encode()
            return subprocess.CompletedProcess(argv, 0, answer, b"")

        with patch.object(probe.subprocess, "run", side_effect=fake_run):
            probe._docker_manifest_probe(token)
        self.assertEqual(len(observed), 1)
        self.assertFalse(Path(observed[0][0][2]).exists())

    def test_failed_manifest_cleanup_and_no_raw_output(self) -> None:
        """A denied registry lookup must remove temporary credentials."""
        paths: list[Path] = []

        def deny(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            """Simulate exactly one denied manifest without any real Docker call."""
            paths.append(Path(argv[2]))
            return subprocess.CompletedProcess(argv, 1, b"", b"unauthorized")

        with patch.object(probe.subprocess, "run", side_effect=deny):
            with self.assertRaises(probe.ProbeUnavailableError):
                probe._docker_manifest_probe(synthetic_jwt())
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0].exists())

    def test_timeout_removes_private_docker_config(self) -> None:
        """A hung registry lookup cannot leave a reusable GitHub credential."""
        temporary_paths: list[Path] = []

        def timeout(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            """Simulate the exactly bounded daemonless manifest subprocess."""
            temporary_paths.append(Path(argv[2]))
            raise subprocess.TimeoutExpired(argv, 35)

        with patch.object(probe.subprocess, "run", side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe._docker_manifest_probe(synthetic_jwt())
        self.assertEqual(len(temporary_paths), 1)
        self.assertFalse(temporary_paths[0].exists())

    def test_main_never_requests_token_when_workflow_context_wrong(self) -> None:
        """Do not even mint GitHub OIDC token outside approved main job."""
        import contextlib

        output = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/unreviewed"},
                        clear=True), patch.object(
                            probe, "_oidc_token"
                        ) as request_token, contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 2)
        request_token.assert_not_called()
        self.assertEqual(output.getvalue().strip(),
                         "TASK014_PRIVATE_ZOT_AUTH_PROBE_HOLD")


if __name__ == "__main__":
    unittest.main()

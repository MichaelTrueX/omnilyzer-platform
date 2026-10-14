"""File: deployment/tests/test_ci_oidc_diagnostics.py

Purpose: Regression-test the workflow-only, non-authoritative claim diagnostic.
Related: deployment/ci_oidc_diagnostics.py,
.github/workflows/platform-promote.yml, deployment/identity.py.
Tests use only synthetic JWT-shaped text, never real credentials.
"""

from __future__ import annotations

import base64
import json
import unittest

from deployment import identity
from deployment.ci_oidc_diagnostics import diagnose_oidc_claims


_SHA = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"
_NOW = 1800000050
_AUDIENCES = (
    identity.DEV_AUDIENCE,
    identity.DEV_ZOT_READ_AUDIENCE,
    identity.DEV_FORGEJO_READ_AUDIENCE,
)


def _encode(value: dict[str, object]) -> str:
    """Create an intentionally unsigned, synthetic JWT-shaped fixture."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    segment = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return "c3ludGhldGlj." + segment + ".c3ludGhldGlj"


def _claims(audience: str, jti: str) -> dict[str, object]:
    """Return claims matching the existing Task 014 broker allowlist."""
    return {
        "iss": identity.DEV_ISSUER,
        "aud": audience,
        "repository": identity.DEV_REPOSITORY,
        "repository_id": str(identity.DEV_REPOSITORY_ID),
        "repository_owner_id": str(identity.DEV_REPOSITORY_OWNER_ID),
        "workflow_ref": identity.DEV_WORKFLOW_REF,
        "workflow_sha": _SHA,
        "ref": identity.DEV_REF,
        "environment": identity.DEV_ENVIRONMENT,
        "event_name": identity.DEV_EVENT_NAME,
        "runner_environment": identity.DEV_RUNNER_ENVIRONMENT,
        "run_id": "38382512194",
        "run_attempt": "1",
        "actor_id": "130741173",
        "iat": _NOW - 5,
        "nbf": _NOW - 5,
        "exp": _NOW + 250,
        "jti": jti,
    }


def _tokens() -> tuple[str, str, str]:
    """Create three separately issued synthetic JWT-shaped credentials."""
    return tuple(_encode(_claims(aud, "synthetic-" + str(i)))
                 for i, aud in enumerate(_AUDIENCES))


def _diagnose(tokens: tuple[str, str, str]) -> tuple[str, ...]:
    """Supply deterministic nonsecret runner metadata to the diagnostic."""
    return diagnose_oidc_claims(
        tokens, expected_workflow_sha=_SHA,
        run_id="38382512194", run_attempt="1", actor_id="130741173",
        received_at=_NOW,
    )


class CIOIDCDiagnosticTests(unittest.TestCase):
    """Check static mismatch outputs, no secret disclosure and no side effects."""

    def test_matching_three_audience_claim_shapes(self) -> None:
        """Valid-looking synthetic claim data has no mismatches."""
        self.assertEqual(_diagnose(_tokens()), ("ok",))

    def test_workflow_sha_mismatch_reports_role_not_value(self) -> None:
        """A different revision produces bounded codes without leaking tokens."""
        tokens = list(_tokens())
        token = _claims(_AUDIENCES[0], "synthetic-0")
        token["workflow_sha"] = "f" * 40
        tokens[0] = _encode(token)
        result = _diagnose(tuple(tokens))
        self.assertIn("deployment_workflow_sha_mismatch", result)
        self.assertIn("cross_workflow_sha_mismatch", result)
        self.assertNotIn("f" * 40, repr(result))

    def test_expired_or_old_token(self) -> None:
        """A token outside the sixty-second reception window is classified."""
        tokens = list(_tokens())
        stale = _claims(_AUDIENCES[1], "synthetic-1")
        stale["iat"] = _NOW - 90
        stale["nbf"] = _NOW - 90
        stale["exp"] = _NOW + 120
        tokens[1] = _encode(stale)
        self.assertIn("zot_time_mismatch", _diagnose(tuple(tokens)))

    def test_wrong_registry_audience(self) -> None:
        """Zot token with the wrong audience is rejected in diagnostics."""
        tokens = list(_tokens())
        wrong = _claims(_AUDIENCES[1], "synthetic-1")
        wrong["aud"] = identity.DEV_AUDIENCE
        tokens[1] = _encode(wrong)
        self.assertIn("zot_aud_mismatch", _diagnose(tuple(tokens)))

    def test_invalid_structure_and_metadata(self) -> None:
        """Malformed JWT and missing runner authority yield fixed codes only."""
        tokens = list(_tokens())
        tokens[2] = "not.a.valid.token"
        self.assertIn("forgejo_payload_invalid", _diagnose(tuple(tokens)))
        self.assertEqual(diagnose_oidc_claims(
            _tokens(), expected_workflow_sha=_SHA,
            run_id="", run_attempt="1", actor_id="130741173", received_at=_NOW,
        ), ("runner_metadata_invalid",))

    def test_diagnostics_never_return_claim_values(self) -> None:
        """Diagnostic results are only known fixed field labels."""
        tokens = list(_tokens())
        altered = _claims(_AUDIENCES[2], "synthetic-2")
        altered["repository"] = "SECRET_REPOSITORY_NOT_FOR_LOGGING"
        tokens[2] = _encode(altered)
        output = repr(_diagnose(tuple(tokens)))
        self.assertIn("forgejo_repository_mismatch", output)
        self.assertNotIn("SECRET_REPOSITORY_NOT_FOR_LOGGING", output)


if __name__ == "__main__":
    unittest.main()

"""File: deployment/ci_oidc_diagnostics.py

Purpose: Compare ephemeral runner-side GitHub OIDC claim *shapes* to the
existing Task 014 policy before a single live DEV promotion attempt.

Related: .github/workflows/platform-promote.yml, deployment/identity.py,
deployment/oidc_verifier.py, deployment/tests/test_ci_oidc_diagnostics.py.

Security: The JWT payload is NOT signature verified here; this is diagnostics
only, never a source of authorization. No network, token persistence, secrets,
raw claim values, or stage mutations. Only fixed classification codes leave
this module. Production signature verification remains exclusively server-side.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

from . import identity


# Section 1: Fixed policy labels and output vocabulary.
_ROLES = ("deployment", "zot", "forgejo")
_AUDIENCES = (
    identity.DEV_AUDIENCE,
    identity.DEV_ZOT_READ_AUDIENCE,
    identity.DEV_FORGEJO_READ_AUDIENCE,
)
_EXPECTED = {
    "iss": identity.DEV_ISSUER,
    "repository": identity.DEV_REPOSITORY,
    "repository_id": str(identity.DEV_REPOSITORY_ID),
    "repository_owner_id": str(identity.DEV_REPOSITORY_OWNER_ID),
    "workflow_ref": identity.DEV_WORKFLOW_REF,
    "ref": identity.DEV_REF,
    "environment": identity.DEV_ENVIRONMENT,
    "event_name": identity.DEV_EVENT_NAME,
    "runner_environment": identity.DEV_RUNNER_ENVIRONMENT,
}
_CROSS_FIELDS = (
    "iss", "repository", "repository_id", "repository_owner_id",
    "workflow_ref", "workflow_sha", "ref", "environment", "event_name",
    "runner_environment", "run_id", "run_attempt", "actor_id",
)
_TOKEN_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z")
_JTI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON member names without reflecting their values."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate claim member")
        result[key] = value
    return result


def _decode_untrusted(compact_token: str) -> dict[str, object]:
    """Decode only a bounded JWT payload, never authenticate or persist it."""
    if type(compact_token) is not str or not 1 <= len(compact_token) <= 16384:
        raise ValueError("invalid token length")
    parts = compact_token.split(".")
    if len(parts) != 3 or any(
        not part or _TOKEN_SEGMENT.fullmatch(part) is None for part in parts
    ):
        raise ValueError("invalid token structure")
    segment = parts[1]
    if len(segment) > 16384 or len(segment) % 4 == 1:
        raise ValueError("invalid claim encoding")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        if (
            not 0 < len(raw) <= 12288
            or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            != segment
        ):
            raise ValueError("noncanonical claim encoding")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise ValueError("invalid untrusted claim payload") from None
    if type(value) is not dict or len(value) > 64:
        raise ValueError("invalid claim object")
    return value


def diagnose_oidc_claims(
    tokens: tuple[str, str, str],
    *,
    expected_workflow_sha: str,
    run_id: str,
    run_attempt: str,
    actor_id: str,
    received_at: int,
) -> tuple[str, ...]:
    """Return static codes for one three-audience OIDC claim observation.

    These classifications compare *unverified* JWT payloads with the closed
    broker claim policy. Callers must not use an "ok" result to authorize any
    request: only the existing broker can cryptographically authenticate JWTs.
    """
    if (
        type(tokens) is not tuple
        or len(tokens) != len(_ROLES)
        or any(type(token) is not str for token in tokens)
        or type(expected_workflow_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", expected_workflow_sha) is None
        or any(type(value) is not str or not value.isascii()
               or not value.isdecimal() or not value
               for value in (run_id, run_attempt, actor_id))
        or type(received_at) is not int
        or received_at < 0
    ):
        return ("runner_metadata_invalid",)

    issues: set[str] = set()
    payloads: list[dict[str, object]] = []
    for role, audience, token in zip(_ROLES, _AUDIENCES, tokens, strict=True):
        try:
            claims = _decode_untrusted(token)
        except ValueError:
            issues.add(role + "_payload_invalid")
            continue
        payloads.append(claims)

        # Section 2: Compare only fixed identifiers, never print their values.
        expected = {
            **_EXPECTED,
            "aud": audience,
            "workflow_sha": expected_workflow_sha,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "actor_id": actor_id,
        }
        for name, value in expected.items():
            if type(claims.get(name)) is not str or claims[name] != value:
                issues.add(role + "_" + name + "_mismatch")

        # Section 3: Apply the broker's explicit issuance/expiry constraints.
        iat, nbf, exp = (claims.get(name) for name in ("iat", "nbf", "exp"))
        if any(type(value) is not int or value < 0 for value in (iat, nbf, exp)):
            issues.add(role + "_time_invalid")
        elif (
            not iat < exp
            or nbf > exp
            or exp - iat > identity.MAX_TOKEN_LIFETIME_SECONDS
            or iat > received_at + identity.MAX_CLOCK_SKEW_SECONDS
            or nbf > received_at + identity.MAX_CLOCK_SKEW_SECONDS
            or received_at > exp + identity.MAX_CLOCK_SKEW_SECONDS
            or received_at - iat > identity.MAX_RECEIVED_AGE_SECONDS
        ):
            issues.add(role + "_time_mismatch")

        jti = claims.get("jti")
        if (
            type(jti) is not str or len(jti) > identity.MAX_JTI_LENGTH
            or _JTI.fullmatch(jti) is None or ".." in jti
        ):
            issues.add(role + "_jti_invalid")

    # Section 4: Compare only identity-binding fields across audiences.
    if len(payloads) == 3:
        for name in _CROSS_FIELDS:
            if any(payload.get(name) != payloads[0].get(name)
                   for payload in payloads[1:]):
                issues.add("cross_" + name + "_mismatch")

    return tuple(sorted(issues)) if issues else ("ok",)


__all__ = ("diagnose_oidc_claims",)

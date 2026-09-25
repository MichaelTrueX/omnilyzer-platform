"""Strict non-live GitHub OIDC JWT verification boundary."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping

import jwt

from .identity import (
    DEV_AUDIENCE,
    DEV_ISSUER,
    REQUIRED_AUTHORIZATION_CLAIMS,
    AuthorizedGitHubIdentity,
    OIDCAuthorizationError,
    authorize_verified_github_oidc,
    validate_expected_workflow_sha,
)
from .jwks import (
    GitHubJWKSCache,
    OIDCVerificationError,
    OIDCVerificationUnavailable,
    parse_bounded_json,
    validate_kid,
)


MAX_COMPACT_TOKEN_BYTES = 16 * 1024
MAX_HEADER_BYTES = 2 * 1024
MAX_CLAIMS_BYTES = 12 * 1024
MAX_SIGNATURE_BYTES = 512
MAX_HEADER_MEMBERS = 8
MAX_CLAIMS_MEMBERS = 64
MAX_JSON_DEPTH = 4
MAX_JSON_ARRAY = 32
MAX_JSON_STRING = 4096
MAX_JSON_NODES = 512

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_HEADER_FIELDS = frozenset({"alg", "kid", "typ"})


def _segment(value: str, *, maximum_decoded: int) -> bytes:
    if (
        not value or "=" in value or _BASE64URL.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        raise OIDCVerificationError("OIDC token structure is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise OIDCVerificationError("OIDC token structure is invalid") from None
    if (
        not decoded or len(decoded) > maximum_decoded
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise OIDCVerificationError("OIDC token structure is invalid")
    return decoded


def _parse_compact_token(compact_token: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(compact_token, str):
        raise OIDCVerificationError("OIDC token structure is invalid")
    try:
        encoded = compact_token.encode("ascii", "strict")
    except UnicodeError:
        raise OIDCVerificationError("OIDC token structure is invalid") from None
    if not encoded or len(encoded) > MAX_COMPACT_TOKEN_BYTES:
        raise OIDCVerificationError("OIDC token structure is invalid")
    segments = compact_token.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise OIDCVerificationError("OIDC token structure is invalid")
    header_raw = _segment(segments[0], maximum_decoded=MAX_HEADER_BYTES)
    claims_raw = _segment(segments[1], maximum_decoded=MAX_CLAIMS_BYTES)
    _segment(segments[2], maximum_decoded=MAX_SIGNATURE_BYTES)
    header = parse_bounded_json(
        header_raw, maximum_bytes=MAX_HEADER_BYTES,
        maximum_root_members=MAX_HEADER_MEMBERS, maximum_depth=MAX_JSON_DEPTH,
        maximum_nodes=MAX_JSON_NODES, maximum_array=MAX_JSON_ARRAY,
        maximum_string=MAX_JSON_STRING,
    )
    claims = parse_bounded_json(
        claims_raw, maximum_bytes=MAX_CLAIMS_BYTES,
        maximum_root_members=MAX_CLAIMS_MEMBERS, maximum_depth=MAX_JSON_DEPTH,
        maximum_nodes=MAX_JSON_NODES, maximum_array=MAX_JSON_ARRAY,
        maximum_string=MAX_JSON_STRING,
    )
    if set(header) not in ({"alg", "kid"}, {"alg", "kid", "typ"}):
        raise OIDCVerificationError("OIDC token header is invalid")
    if not set(header) <= _HEADER_FIELDS or header.get("alg") != "RS256":
        raise OIDCVerificationError("OIDC token header is invalid")
    if "typ" in header and header["typ"] != "JWT":
        raise OIDCVerificationError("OIDC token header is invalid")
    validate_kid(header.get("kid"))
    return header, claims


class GitHubOIDCVerifier:
    """Verify and authorize one fixed GitHub Actions deployment identity."""

    __slots__ = ("_jwks_cache", "_expected_workflow_sha")

    def __init__(self, *, expected_workflow_sha: str,
                 jwks_cache: GitHubJWKSCache | None = None) -> None:
        object.__setattr__(self, "_expected_workflow_sha",
                           validate_expected_workflow_sha(expected_workflow_sha))
        object.__setattr__(self, "_jwks_cache",
                           GitHubJWKSCache() if jwks_cache is None else jwks_cache)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("OIDC verifier authority is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("OIDC verifier authority is immutable")

    def verify(
        self, compact_token: str, *, received_at: int,
    ) -> AuthorizedGitHubIdentity:
        """Return the authorized identity; C1 deliberately does not consume replay."""

        if isinstance(received_at, bool) or not isinstance(received_at, int) or received_at < 0:
            raise OIDCVerificationError("OIDC receipt time is invalid")
        header, bounded_claims = _parse_compact_token(compact_token)
        key = self._jwks_cache.get_key(header["kid"])
        try:
            verified_claims = jwt.decode(
                compact_token,
                key=key,
                algorithms=["RS256"],
                issuer=DEV_ISSUER,
                audience=DEV_AUDIENCE,
                options={
                    "verify_signature": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "strict_aud": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "require": sorted(REQUIRED_AUTHORIZATION_CLAIMS),
                },
            )
        except jwt.PyJWTError:
            raise OIDCVerificationError("OIDC token verification failed") from None
        except Exception:
            raise OIDCVerificationError("OIDC token verification failed") from None
        if not isinstance(verified_claims, Mapping) or dict(verified_claims) != bounded_claims:
            raise OIDCVerificationError("OIDC verified claims are inconsistent")
        try:
            return authorize_verified_github_oidc(
                bounded_claims, received_at=received_at,
                expected_workflow_sha=object.__getattribute__(self, "_expected_workflow_sha"),
            )
        except OIDCAuthorizationError:
            raise OIDCVerificationError("OIDC identity is not authorized") from None


__all__ = [
    "GitHubOIDCVerifier",
    "OIDCVerificationError",
    "OIDCVerificationUnavailable",
]

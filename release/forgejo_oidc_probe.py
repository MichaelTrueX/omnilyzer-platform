#!/usr/bin/env python3
# File: release/forgejo_oidc_probe.py
# Purpose: Compare token claim names with exact reviewed Forgejo trust rules
#          without exposing values, then make one bounded authenticated GET.
#          No registry mutation is allowed.
# Related: release/request_oidc.py, release/publish_forgejo.py,
#          .github/workflows/platform-release.yml,
#          release/tests/test_forgejo_oidc_probe.py.
# Authority: Diagnostic-only; never publishes, signs, or modifies credentials.

"""Fail-closed, non-publishing Forgejo OIDC Authorized Integration diagnostic."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
import urllib.error
import urllib.request
from pathlib import Path

# Section 1: Fix the approved Forgejo origin and package-only GET route.
# The operator cannot supply a URL, HTTP method, owner, path, or redirect target.
PROBE_URL = "https://registry-dev.omnilyzer.ai/api/v1/packages/omnilyzer?type=pypi&limit=1"
MAX_RESPONSE = 32 * 1024
JWT_RE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")


# Section 2: Exact, source-reviewed Github OIDC claims for this Forgejo
# Authorized Integration. This is a *diagnostic* unverified decode, not JWT
# signature verification or an alternative authorization scheme.
EXPECTED_STRING_CLAIMS = {
    "iss": "https://token.actions.githubusercontent.com",
    "repository": "MichaelTrueX/omnilyzer-platform",
    "repository_owner": "MichaelTrueX",
    "repository_visibility": "public",
    "ref": "refs/heads/main",
    "workflow_ref": "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml@refs/heads/main",
    "event_name": "workflow_dispatch",
}
EXPECTED_AUDIENCE = "u:2:316bec9a-53e4-4807-9557-7febdc979d0a"


def _decode_jwt_json(segment: str) -> dict:
    """Decode one bounded JWT JSON segment without ever including content in errors."""
    if len(segment) > 8192:
        raise ProbeError("FORGEJO_OIDC_PROBE_CLAIMS_INVALID")
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error):
        raise ProbeError("FORGEJO_OIDC_PROBE_CLAIMS_INVALID") from None
    if not isinstance(document, dict):
        raise ProbeError("FORGEJO_OIDC_PROBE_CLAIMS_INVALID")
    return document


def compare_expected_claims(token: str) -> tuple[str, ...]:
    """Return only fixed claim names that do not match the reviewed trust contract."""
    if JWT_RE.fullmatch(token) is None:
        raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FORMAT_INVALID")
    header_raw, payload_raw, _signature = token.split(".")
    header = _decode_jwt_json(header_raw)
    claims = _decode_jwt_json(payload_raw)
    mismatches: list[str] = []
    if header.get("alg") != "RS256":
        mismatches.append("jwt_header_alg")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        mismatches.append("jwt_header_kid")
    for key, expected in EXPECTED_STRING_CLAIMS.items():
        if claims.get(key) != expected:
            mismatches.append(key)
    actual_audience = claims.get("aud")
    if isinstance(actual_audience, str):
        actual_audience = [actual_audience]
    if actual_audience != [EXPECTED_AUDIENCE]:
        mismatches.append("aud")
    return tuple(mismatches)


class ProbeError(ValueError):
    """Report a sanitized diagnostic rejection without exposing the JWT."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects to protect the bearer token and fixed destination."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        """Deny every redirect instead of forwarding the Authorization header."""
        raise ProbeError("FORGEJO_OIDC_PROBE_REDIRECT_DENIED")


def read_token(path: Path) -> str:
    """Read exactly one pre-created private regular JWT file; never log its data."""
    try:
        # Linux O_NOFOLLOW closes the lstat/open symlink-replacement window.
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="ascii") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FILE_NOT_PRIVATE")
            if metadata.st_size < 20 or metadata.st_size > 16_384:
                raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FILE_BAD_SIZE")
            token = source.read(16_385)
    except (OSError, UnicodeError):
        raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FILE_UNREADABLE") from None
    if JWT_RE.fullmatch(token) is None:
        raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FORMAT_INVALID")
    return token


def verify_read_only(token: str) -> None:
    """Issue one fixed GET, reject redirects/non-200s, and validate bounded JSON."""
    if JWT_RE.fullmatch(token) is None:
        raise ProbeError("FORGEJO_OIDC_PROBE_TOKEN_FORMAT_INVALID")
    request = urllib.request.Request(
        PROBE_URL,
        method="GET",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise ProbeError("FORGEJO_OIDC_PROBE_UNEXPECTED_STATUS")
            media_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
            if media_type != "application/json":
                raise ProbeError("FORGEJO_OIDC_PROBE_UNEXPECTED_CONTENT_TYPE")
            payload = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        # Release the response without printing its body or its sensitive reason.
        status = error.code
        error.close()
        raise ProbeError(f"FORGEJO_OIDC_PROBE_HTTP_{status}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProbeError("FORGEJO_OIDC_PROBE_NETWORK_ERROR") from None
    if len(payload) > MAX_RESPONSE:
        raise ProbeError("FORGEJO_OIDC_PROBE_RESPONSE_TOO_LARGE")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ProbeError("FORGEJO_OIDC_PROBE_INVALID_JSON") from None
    if not isinstance(parsed, list):
        raise ProbeError("FORGEJO_OIDC_PROBE_NOT_A_PACKAGE_LIST")


def main() -> int:
    """Validate a file supplied by GitHub Actions; print only a fixed PASS code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        token = read_token(args.token_file)
        # Only static claim names and boolean outcomes may reach Actions logs.
        mismatches = compare_expected_claims(token)
        for name in ("jwt_header_alg", "jwt_header_kid",
                     *EXPECTED_STRING_CLAIMS.keys(), "aud"):
            status = "MISMATCH" if name in mismatches else "MATCH"
            print(f"FORGEJO_OIDC_CLAIM_{name}={status}", flush=True)
        if mismatches:
            raise ProbeError("FORGEJO_OIDC_PROBE_CLAIMS_MISMATCH")
        verify_read_only(token)
    except ProbeError as error:
        raise SystemExit(str(error)) from None
    print("FORGEJO_OIDC_READ_ONLY_AUTHENTICATION_ACCEPTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

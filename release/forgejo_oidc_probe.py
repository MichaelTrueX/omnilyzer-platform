#!/usr/bin/env python3
# File: release/forgejo_oidc_probe.py
# Purpose: Validate the exact Forgejo package publishing OIDC identity with one
#          bounded authenticated GET and no registry mutation.
# Related: release/request_oidc.py, release/publish_forgejo.py,
#          .github/workflows/platform-release.yml,
#          release/tests/test_forgejo_oidc_probe.py.
# Authority: Diagnostic-only; never publishes, signs, or modifies credentials.

"""Fail-closed, non-publishing Forgejo OIDC Authorized Integration diagnostic."""

from __future__ import annotations

import argparse
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
        verify_read_only(read_token(args.token_file))
    except ProbeError as error:
        raise SystemExit(str(error)) from None
    print("FORGEJO_OIDC_READ_ONLY_AUTHENTICATION_ACCEPTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

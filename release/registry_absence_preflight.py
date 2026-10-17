#!/usr/bin/env python3
# File: release/registry_absence_preflight.py
# Purpose: Check that a single exact release version is absent at every
#          externally published Task 013 destination before any registry write.
# Related: release/release_plan.py, release/request_oidc.py,
#          release/forgejo_oidc_probe.py, release/publish_zot.py,
#          release/publish_forgejo.py, .github/workflows/platform-release.yml,
#          release/tests/test_registry_absence_preflight.py.
# Security: Read-only GET/HEAD with two short-lived, audience-specific OIDC JWTs;
#           fixed TLS origins and package identities; no redirects or bodies logged.
"""Authenticated, nonpublishing, fail-closed package version absence preflight."""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .forgejo_oidc_probe import read_token
from .release_plan import validate_semver

# Section 1: Immutable Task 013 destination identities. No caller-supplied URL.
FORGEJO = "https://registry-dev.omnilyzer.ai"
ZOT = "https://oci-dev.omnilyzer.ai"
OWNER = "omnilyzer"
OCI_REPO = "omnilyzer/task013-release-canary"
PACKAGE_NAMES = {
    "pypi": "omnilyzer-release-canary",
    "npm": "@omnilyzer/release-canary",
    "generic": "task013-release-evidence",
}
MAX_JSON = 128 * 1024
MAX_PAGES = 25


class PreflightError(ValueError):
    """Return a fixed sanitized failure marker without exposing JWT data."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects rather than forwarding bearer tokens across origins."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        """Deny 3xx responses unconditionally, including same-origin redirects."""
        raise PreflightError("REGISTRY_PREFLIGHT_REDIRECT_DENIED")


def _status(opener, origin: str, path: str, token: str, *, method: str = "GET") -> tuple[int, bytes]:
    """Make one bounded, read-only authenticated request to an exact trusted origin."""
    if origin not in {FORGEJO, ZOT} or not path.startswith("/") or "//" in path:
        raise PreflightError("REGISTRY_PREFLIGHT_UNTRUSTED_DESTINATION")
    if method not in {"GET", "HEAD"}:
        raise PreflightError("REGISTRY_PREFLIGHT_READ_ONLY_METHOD_REQUIRED")
    # Do not accept any URL contributed by response content or external input.
    request = urllib.request.Request(
        origin + path,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": ("application/vnd.oci.image.index.v1+json,"
                       "application/vnd.oci.image.manifest.v1+json,"
                       "application/vnd.docker.distribution.manifest.v2+json")
                      if origin == ZOT else "application/json",
        },
    )
    try:
        with opener.open(request, timeout=15) as reply:
            status, body = reply.status, reply.read(MAX_JSON + 1) if method == "GET" else b""
    except urllib.error.HTTPError as err:
        status = err.code
        err.close()
        body = b""
    except (urllib.error.URLError, TimeoutError, OSError):
        raise PreflightError("REGISTRY_PREFLIGHT_NETWORK_OR_TLS_FAILURE") from None
    if len(body) > MAX_JSON:
        raise PreflightError("REGISTRY_PREFLIGHT_RESPONSE_TOO_LARGE")
    return status, body


def _checked_package_list(raw: bytes) -> list[dict]:
    """Require a canonical JSON package listing and relevant typed fields."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise PreflightError("REGISTRY_PREFLIGHT_INVALID_PACKAGE_LIST") from None
    if not isinstance(payload, list) or any(not isinstance(x, dict) for x in payload):
        raise PreflightError("REGISTRY_PREFLIGHT_INVALID_PACKAGE_LIST")
    for package in payload:
        if not all(isinstance(package.get(k), str) for k in ("name", "version", "type")):
            raise PreflightError("REGISTRY_PREFLIGHT_INVALID_PACKAGE_LIST")
    return payload


def check_absence(version: str, forgejo_jwt: str, zot_jwt: str) -> None:
    """Prove authenticated registry access and absence of all exact version identities."""
    validate_semver(version)
    jwt_pattern = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
    if jwt_pattern.fullmatch(forgejo_jwt) is None or jwt_pattern.fullmatch(zot_jwt) is None:
        raise PreflightError("REGISTRY_PREFLIGHT_JWT_FORMAT_INVALID")
    opener = urllib.request.build_opener(NoRedirect)

    # Section 2: Prove Forgejo authenticated access before treating any 404
    # as a genuine absence. The original OIDC probe already uses this route.
    status, raw = _status(opener, FORGEJO, "/api/v1/packages/omnilyzer?type=pypi&limit=1", forgejo_jwt)
    if status != 200:
        raise PreflightError(f"REGISTRY_PREFLIGHT_FORGEJO_AUTH_HTTP_{status}")
    _checked_package_list(raw)

    # Section 3: Check precise package-version records and independently scan
    # bounded paginated listings, catching URL-escaped npm name ambiguities.
    for kind, name in PACKAGE_NAMES.items():
        encoded_name = urllib.parse.quote(name, safe="")
        path = f"/api/v1/packages/{OWNER}/{kind}/{encoded_name}/{version}"
        status, _ = _status(opener, FORGEJO, path, forgejo_jwt)
        if status == 200:
            raise PreflightError(f"REGISTRY_PREFLIGHT_{kind.upper()}_VERSION_OCCUPIED")
        if status != 404:
            raise PreflightError(f"REGISTRY_PREFLIGHT_{kind.upper()}_EXACT_HTTP_{status}")
        for page in range(1, MAX_PAGES + 1):
            url = f"/api/v1/packages/{OWNER}?type={kind}&limit=50&page={page}"
            status, raw = _status(opener, FORGEJO, url, forgejo_jwt)
            if status != 200:
                raise PreflightError(f"REGISTRY_PREFLIGHT_{kind.upper()}_LIST_HTTP_{status}")
            packages = _checked_package_list(raw)
            for package in packages:
                if package["type"] == kind and package["name"].lower().replace("_", "-") == name.lower().replace("_", "-") and package["version"] == version:
                    raise PreflightError(f"REGISTRY_PREFLIGHT_{kind.upper()}_VERSION_OCCUPIED")
            if len(packages) < 50:
                break
        else:
            raise PreflightError(f"REGISTRY_PREFLIGHT_{kind.upper()}_PAGINATION_LIMIT")
        print(f"REGISTRY_PREFLIGHT_{kind.upper()}_VERSION_ABSENT", flush=True)

    # Section 4: Authenticate to the OCI registry before interpreting a
    # missing tag. HEAD 404 is the OCI Distribution specification's absence.
    status, _ = _status(opener, ZOT, "/v2/", zot_jwt)
    if status != 200:
        raise PreflightError(f"REGISTRY_PREFLIGHT_ZOT_AUTH_HTTP_{status}")
    status, _ = _status(opener, ZOT, f"/v2/{OCI_REPO}/manifests/{version}", zot_jwt, method="HEAD")
    if status == 200:
        raise PreflightError("REGISTRY_PREFLIGHT_OCI_TAG_OCCUPIED")
    if status != 404:
        raise PreflightError(f"REGISTRY_PREFLIGHT_OCI_HEAD_HTTP_{status}")
    print("REGISTRY_PREFLIGHT_OCI_TAG_ABSENT", flush=True)
    print("REGISTRY_PREFLIGHT_ALL_FOUR_DESTINATIONS_ABSENT", flush=True)


def main() -> int:
    """Run the exact trusted preflight from an already validated GitHub release."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--forgejo-token-file", required=True, type=Path)
    parser.add_argument("--zot-token-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        check_absence(
            args.version,
            read_token(args.forgejo_token_file),
            read_token(args.zot_token_file),
        )
    except (PreflightError, ValueError) as err:
        # Only predefined markers may be printed; exception strings from
        # urllib or JWT fields are not propagated.
        message = str(err)
        if not message.startswith("REGISTRY_PREFLIGHT_"):
            message = "REGISTRY_PREFLIGHT_INVALID_ARGUMENTS"
        raise SystemExit(message) from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

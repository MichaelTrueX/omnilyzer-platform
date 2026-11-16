#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_add_public_callback_once.py
Purpose: Add ONLY one exact public Sumlaude callback URI to the existing
    confidential Keycloak client, after read-only checks and explicit owner GO.
Related: services/identity/ops/keycloak_provision_realm.py,
    services/identity/config/settings.py,
    services/identity/tests/test_keycloak_add_public_callback_once.py,
    docs/operations/p0-shared-keycloak-sumlaude-identity-20261029.md.

The legacy app callback, client secret, web origins, PKCE and existing users
are preserved. Never creates a realm/client, rotates credentials, changes
public DNS/NGINX, enables BFF, or admits learners. This is NOT an automatic
production deployment. The first root mutation requires separate owner
approval of an exact reviewed Git SHA, installed operator SHA256 and scope.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler

# Section: Exact existing-production immutable Keycloak runtime and client.
HOST = "truexmainserver"
ROOT = Path("/etc/omnilyzer/keycloak")
ENV = ROOT / "keycloak.env"
KCADM = Path("/opt/omnilyzer/keycloak/current/bin/kcadm.sh")
CLIENT = "sumlaude-bff"
REALM = "omnilyzer"
SERVER = "http://127.0.0.1:18742"
ISSUER = "https://login.omnilyzer.ai/realms/omnilyzer"
APP = "https://app.sumlaude.com/auth/callback"
PUBLIC = "https://sumlaude.com/auth/callback"
OLD_REDIRECTS = [APP]
NEW_REDIRECTS = [APP, PUBLIC]
EXPECTED_ORIGINS = ["https://app.sumlaude.com"]
GO_SCOPE = "M01_CANONICAL_KEYCLOAK_EXACT_CALLBACK_ONCE_GO"
RECEIPTS = ROOT / "canonical-public-callback-receipts"
ATTEMPT = RECEIPTS / "attempt.json"
SUCCESS = RECEIPTS / "success.json"


def refuse(reason: str) -> None:
    """Fail closed with one stable marker, never leaking admin credentials."""
    raise RuntimeError("M01_CALLBACK_HOLD_" + reason)


class NoRedirect(HTTPRedirectHandler):
    """Never follow an OIDC redirect toward a real identity provider."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def authorization_code_status(callback: str) -> int:
    """Anonymous loopback Keycloak authorization probe: no cookies or code."""
    parameters = urlencode({
        "client_id": CLIENT,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": callback,
        "state": "readonly-source-probe",
        "nonce": "readonly-source-probe",
        "code_challenge_method": "S256",
        "code_challenge": "YXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXYXY",
    })
    from urllib.request import Request
    req = Request(SERVER + "/realms/" + REALM +
                  "/protocol/openid-connect/auth?" + parameters)
    # Block any environment HTTP proxy or unexpected public redirects.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=6) as response:
            response.read(8192)
            return response.status
    except HTTPError as exc:
        exc.read(8192)
        return exc.code
    except (OSError, URLError):
        refuse("KEYCLOAK_LOCAL_AUTH_UNAVAILABLE")


def public_preflight() -> tuple[int, int]:
    """Read-only existing and proposed Keycloak browser callback comparison.

    The previous callback may return login HTML (200) or browser redirect
    (302) depending on installed login theme. An unregistered new URI must
    fail, normally with 400; no account or user session is created.
    """
    if socket.gethostname().split(".")[0] != HOST:
        refuse("WRONG_HOST")
    app_code = authorization_code_status(APP)
    public_code = authorization_code_status(PUBLIC)
    if app_code not in (200, 302):
        refuse("EXISTING_APP_CALLBACK_BROKEN")
    if public_code not in (200, 302, 400):
        refuse("UNEXPECTED_PUBLIC_CALLBACK_STATUS")
    return app_code, public_code


def root_admin_env() -> dict[str, str]:
    """Read existing root-only admin credentials without printing values."""
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        refuse("ROOT_OR_HOST_REQUIRED")
    if ROOT.is_symlink() or not ROOT.is_dir():
        refuse("UNSAFE_ROOT_CONFIG")
    rd = ROOT.stat()
    if rd.st_uid != 0 or stat.S_IMODE(rd.st_mode) != 0o700:
        refuse("ROOT_CONFIG_PERMISSIONS")
    if ENV.is_symlink() or not ENV.is_file():
        refuse("NO_EXACT_ROOT_ENV")
    meta = ENV.stat()
    if (meta.st_uid != 0 or meta.st_nlink != 1
            or stat.S_IMODE(meta.st_mode) != 0o600):
        refuse("ADMIN_ENV_PERMISSIONS")
    if not KCADM.is_file() or KCADM.is_symlink():
        refuse("EXISTING_KEYCLOAK_CLIENT_NOT_INSTALLED")
    entries = {}
    for line in ENV.read_text(encoding="ascii").splitlines():
        key, sep, value = line.partition("=")
        if not sep or not key.isidentifier() or key in entries:
            refuse("ADMIN_ENV_FORMAT")
        entries[key] = value
    if not entries.get("KC_BOOTSTRAP_ADMIN_USERNAME") or not entries.get(
            "KC_BOOTSTRAP_ADMIN_PASSWORD"):
        refuse("ADMIN_CREDENTIALS_MISSING")
    return entries


def command(args: list[str], *, env: dict, timeout=40) -> str:
    """Execute a fixed kcadm argument vector, never a shell string."""
    try:
        result = subprocess.run(args, env=env, check=False,
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        refuse("KEYCLOAK_COMMAND_UNAVAILABLE")
    if result.returncode:
        # Do NOT surface stderr: Keycloak error details can include secrets.
        refuse("KEYCLOAK_COMMAND_FAILED")
    return result.stdout


def admin_client(config: Path, env: dict) -> dict:
    """Fetch exactly one existing confidential BFF client (no secret output)."""
    response = command([
        str(KCADM), "get", "clients", "-r", REALM, "-q",
        "clientId=" + CLIENT, "--config", str(config),
    ], env=env)
    try:
        clients = json.loads(response)
    except ValueError:
        refuse("CLIENT_JSON_INVALID")
    if not isinstance(clients, list) or len(clients) != 1:
        refuse("EXACT_CLIENT_NOT_FOUND")
    client = clients[0]
    if not isinstance(client, dict):
        refuse("CLIENT_JSON_INVALID")
    return client


def verify_security_contract(client: dict, *, after: bool) -> None:
    """Forbid modification of existing confidential PKCE and browser origins."""
    redirects = NEW_REDIRECTS if after else OLD_REDIRECTS
    if (client.get("clientId") != CLIENT
            or not isinstance(client.get("id"), str)
            or not re.fullmatch(r"[a-zA-Z0-9-]{16,80}", client["id"])
            or client.get("protocol") != "openid-connect"
            or client.get("publicClient") is not False
            or client.get("enabled") is not True
            or client.get("standardFlowEnabled") is not True
            or client.get("implicitFlowEnabled") is not False
            or client.get("directAccessGrantsEnabled") is not False
            or client.get("serviceAccountsEnabled") is not False
            or client.get("redirectUris") != redirects
            or client.get("webOrigins") != EXPECTED_ORIGINS
            or client.get("attributes", {}).get(
                "pkce.code.challenge.method") != "S256"):
        refuse("CONFIDENTIAL_CLIENT_CONTRACT_CHANGED")


def new_document(client: dict) -> dict:
    """Make exactly one extra callback change in the existing client JSON."""
    verify_security_contract(client, after=False)
    clone = dict(client)
    clone["redirectUris"] = NEW_REDIRECTS.copy()
    if {k for k in clone if clone[k] != client.get(k)} != {"redirectUris"}:
        refuse("UNEXPECTED_UPDATE_DELTA")
    return clone


def create_attempt_receipt() -> None:
    """Protect against replay before any potential Keycloak mutation."""
    if RECEIPTS.exists() or RECEIPTS.is_symlink():
        refuse("ATTEMPT_OR_RECEIPT_ALREADY_EXISTS")
    RECEIPTS.mkdir(mode=0o700)
    if (RECEIPTS.stat().st_uid != 0
            or stat.S_IMODE(RECEIPTS.stat().st_mode) != 0o700):
        refuse("UNSAFE_RECEIPT_DIRECTORY")
    fd = os.open(ATTEMPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as dest:
        dest.write(json.dumps({
            "client": CLIENT, "realm": REALM, "old": OLD_REDIRECTS,
            "requested": NEW_REDIRECTS, "outcome": "ATTEMPT_STARTED_HOLD_ON_ERROR",
        }, sort_keys=True) + "\n")
        dest.flush()
        os.fsync(dest.fileno())


def apply_once() -> None:
    """Modify one existing client's redirectUris only after exact owner GO.

    The root-private attempt receipt is written BEFORE the API call. On an
    interrupted/ambiguous response there is no automatic retry or guesswork.
    No Keycloak secret, bearer token or complete client document is logged.
    """
    if os.environ.get("M01_CANONICAL_KEYCLOAK_OWNER_GO") != GO_SCOPE:
        refuse("EXACT_OWNER_GO_ABSENT")
    app_code, new_code = public_preflight()
    if new_code != 400:
        refuse("NEW_CALLBACK_NOT_ABSENT")
    admin = root_admin_env()
    if RECEIPTS.exists() or RECEIPTS.is_symlink():
        refuse("PRIOR_ATTEMPT_REVIEW_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="m01-keycloak-callback-",
                                     dir="/run") as scratch:
        temp = Path(scratch)
        temp.chmod(0o700)
        config = temp / "kcadm.config"
        env = dict(os.environ)
        env["HOME"] = str(temp)
        env["KC_CLI_PASSWORD"] = admin["KC_BOOTSTRAP_ADMIN_PASSWORD"]
        command([
            str(KCADM), "config", "credentials", "--config", str(config),
            "--server", SERVER, "--realm", "master",
            "--user", admin["KC_BOOTSTRAP_ADMIN_USERNAME"],
        ], env=env)
        before = admin_client(config, env)
        next_document = new_document(before)
        # Root-private file only; preserve all existing Keycloak fields.
        payload = temp / "same-client-exact-callback-only.json"
        fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(next_document, output, sort_keys=True)
            output.write("\n")
        create_attempt_receipt()
        command([
            str(KCADM), "update", "clients/" + before["id"],
            "-r", REALM, "-f", str(payload), "--config", str(config),
        ], env=env)
        after = admin_client(config, env)
        verify_security_contract(after, after=True)
        for name in ("id", "clientId", "protocol", "publicClient",
                     "standardFlowEnabled", "implicitFlowEnabled",
                     "directAccessGrantsEnabled", "serviceAccountsEnabled",
                     "webOrigins", "attributes", "secret"):
            if before.get(name) != after.get(name):
                refuse("SIBLING_CLIENT_FIELDS_CHANGED")
        _, public_status = public_preflight()
        if public_status not in (200, 302):
            refuse("PUBLIC_CALLBACK_LIVE_READBACK_FAILED")
        fd = os.open(SUCCESS, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(json.dumps({
                "outcome": "M01_KEYCLOAK_CANONICAL_CALLBACK_ONLY_PASS",
                "client": CLIENT, "realm": REALM,
                "redirectUris": NEW_REDIRECTS,
                "retained_app_callback": True,
            }, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
    print("M01_KEYCLOAK_CANONICAL_CALLBACK_ONLY_PASS "
          "one_existing_confidential_client=true two_exact_redirects=true "
          "no_new_realm_user_secret_or_oauth_grant=true")


def main() -> int:
    """Expose only safe public inspection or separately authorized root apply."""
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["status", "apply"])
    args = parser.parse_args()
    if args.action == "status":
        app, public = public_preflight()
        print("M01_KEYCLOAK_CALLBACK_READONLY "
              "app_status=" + str(app) + " public_status=" + str(public))
    else:
        apply_once()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc) if str(exc).startswith("M01_CALLBACK_HOLD_")
              else "M01_CALLBACK_HOLD_RUNTIME_ERROR", file=sys.stderr)
        sys.exit(2)

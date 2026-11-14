#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_provision_realm.py
Purpose: One-time, local-only production realm + confidential Sumlaude client
    provisioning using the ALREADY running Omnilyzer Keycloak 26.8.1.
Related: services/identity/ops/keycloak_public_prod.py,
    services/identity/tests/test_keycloak_provision_realm.py,
    services/identity/config/settings.py, docs/adr/0003-keycloak-bff-and-native-authentication.md.

Scope: exactly one realm 'omnilyzer' and one Code+PKCE S256 browser BFF client.
Never imports/creates a user, connects to legacy authentication, changes DNS,
Nginx, TLS, systemd, PostgreSQL, Analytics, or enables public registration.
The master realm and temporary admin bootstrap are not published.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

HOST = "truexmainserver"
ROOT = Path("/etc/omnilyzer/keycloak")
ENV = ROOT / "keycloak.env"
CLIENT_ENV = ROOT / "sumlaude-bff-client.env"
CURRENT = Path("/opt/omnilyzer/keycloak/current")
KCADM = CURRENT / "bin" / "kcadm.sh"
BASE_URL = "http://127.0.0.1:18742"
REALM = "omnilyzer"
ISSUER = "https://login.omnilyzer.ai/realms/omnilyzer"
CLIENT = "sumlaude-bff"
CALLBACK = "https://app.sumlaude.com/auth/callback"


# Section: Strict local and secret-file preflight, no state-changing calls.
def http_status(url):
    """Read one localhost URL with redirects disabled and a bounded response."""
    from urllib.request import build_opener, HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        """Keep diagnostic HTTP checks on the verified loopback socket."""
        def redirect_request(self, request, fp, code, message, headers, newurl):
            return None
    try:
        with build_opener(NoRedirect).open(url, timeout=5) as response:
            return response.status, response.read(1048576)
    except HTTPError as exc:
        return exc.code, exc.read(4096)


def load_root_env():
    """Read only the previously installed root-owned 0600 file; never log values."""
    directory = ROOT.stat()
    metadata = ENV.lstat()
    if (directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700 or
            metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode) or
            metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise RuntimeError("root-owned identity credential boundary changed")
    entries = {}
    for line in ENV.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key.isidentifier() or key in entries:
            raise RuntimeError("unexpected local credential file format")
        entries[key] = value
    if not entries.get("KC_BOOTSTRAP_ADMIN_PASSWORD") or not entries.get("KC_BOOTSTRAP_ADMIN_USERNAME"):
        raise RuntimeError("missing existing bootstrap admin, do not reset")
    return entries


def preflight():
    """Collect missing conditions before creating ANY realm or file."""
    problems = []
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        problems.append("root required on truexmainserver")
    try:
        if not CURRENT.is_symlink() or not KCADM.is_file():
            problems.append("installed Keycloak runtime not found")
        if CLIENT_ENV.exists() or CLIENT_ENV.is_symlink():
            problems.append("client credential file exists, never overwrite")
        if ROOT.is_symlink():
            problems.append("config directory is symlinked")
        if os.geteuid() == 0:
            load_root_env()
    except (OSError, RuntimeError, UnicodeError) as exc:
        problems.append("Keycloak root config unavailable: " + type(exc).__name__)
    try:
        status = subprocess.run(
            ["/usr/bin/systemctl", "show", "omnilyzer-keycloak.service",
             "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState", "--no-pager"],
            check=True, capture_output=True, text=True, timeout=8).stdout.splitlines()
        if not all(x in status for x in
                   ("ActiveState=active", "SubState=running", "UnitFileState=disabled")):
            problems.append("Keycloak is not running+disabled as reviewed")
    except (OSError, subprocess.SubprocessError):
        problems.append("unable to inspect Keycloak service")
    try:
        status, response = http_status(BASE_URL + "/realms/master/.well-known/openid-configuration")
        if status != 200 or json.loads(response).get("issuer") != (
                "https://login.omnilyzer.ai/realms/master"):
            problems.append("existing master realm issuer mismatch")
        status, response = http_status(BASE_URL + "/realms/" + REALM +
                                       "/.well-known/openid-configuration")
        if status != 404:
            problems.append("production realm already exists or unexpected response")
    except (OSError, ValueError, URLError, UnicodeError):
        problems.append("local OIDC discovery not available")
    return problems


# Section: One limited realm with a confidential, fixed-redirect product client.
def realm_document(client_secret):
    """Generate one known realm; login never creates real accounts or admits pupils."""
    return {
        "realm": REALM,
        "displayName": "Omnilyzer",
        "enabled": True,
        "sslRequired": "external",
        "registrationAllowed": False,
        "registrationEmailAsUsername": False,
        "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False,
        "verifyEmail": False,
        "rememberMe": False,
        "bruteForceProtected": True,
        "permanentLockout": False,
        "passwordPolicy": "length(12) and upperCase(1) and lowerCase(1) and digits(1)",
        "clients": [{
            "clientId": CLIENT,
            "name": "Sumlaude confidential browser BFF",
            "enabled": True,
            "protocol": "openid-connect",
            "clientAuthenticatorType": "client-secret",
            "secret": client_secret,
            "publicClient": False,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "authorizationServicesEnabled": False,
            "redirectUris": [CALLBACK],
            "webOrigins": ["https://app.sumlaude.com"],
            "attributes": {"pkce.code.challenge.method": "S256"},
        }],
    }


def provision():
    """Authenticate existing bootstrap admin first; then create one realm.

    Never modify a real user, reset an admin credential or run twice.
    The confidential client secret is preserved root-only for recovery.
    """
    issues = preflight()
    if issues:
        raise RuntimeError("PROVISION_HOLD: " + "; ".join(issues))
    root_env = load_root_env()
    with tempfile.TemporaryDirectory(prefix="m01-keycloak-admin-", dir="/run") as temp:
        # Both CLI token and one-time realm JSON stay in root-owned 0700 /run.
        tempdir = Path(temp)
        config = str(tempdir / "kcadm.config")
        env = dict(os.environ)
        env["KC_CLI_PASSWORD"] = root_env["KC_BOOTSTRAP_ADMIN_PASSWORD"]
        env["HOME"] = temp
        if not root_env["KC_BOOTSTRAP_ADMIN_USERNAME"].isascii():
            raise RuntimeError("unexpected bootstrap username")
        login = subprocess.run(
            [str(KCADM), "config", "credentials", "--config", config,
             "--server", BASE_URL, "--realm", "master",
             "--user", root_env["KC_BOOTSTRAP_ADMIN_USERNAME"]],
            env=env, capture_output=True, text=True, timeout=45)
        if login.returncode:
            raise RuntimeError("existing admin CLI authentication failed; no reset performed")

        # Generate after admin login succeeds. Store a durable recovery copy
        # BEFORE the API call: a partial realm is never silently re-created.
        secret = secrets.token_urlsafe(48)
        descriptor = os.open(str(CLIENT_ENV), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write("OIDC_ISSUER=" + ISSUER + "\n")
            output.write("OIDC_CLIENT_ID=" + CLIENT + "\n")
            output.write("OIDC_CLIENT_SECRET=" + secret + "\n")
            output.flush()
            os.fsync(output.fileno())
        document = tempdir / "realm.json"
        document.write_text(json.dumps(realm_document(secret)) + "\n", encoding="utf-8")
        document.chmod(0o600)
        result = subprocess.run(
            [str(KCADM), "create", "realms", "--config", config, "-f", str(document)],
            env=env, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise RuntimeError("Keycloak realm create failed; inspect existing root-only secret file")
        status, response = http_status(BASE_URL + "/realms/" + REALM +
                                       "/.well-known/openid-configuration")
        if status != 200 or json.loads(response).get("issuer") != ISSUER:
            raise RuntimeError("realm created but canonical issuer not verified; public HOLD")

        # Admin-only readback. Do not display client JSON or OAuth credentials.
        verified = subprocess.run(
            [str(KCADM), "get", "clients", "-r", REALM, "-q",
             "clientId=" + CLIENT, "--config", config],
            env=env, capture_output=True, text=True, timeout=30)
        if verified.returncode:
            raise RuntimeError("realm created but client readback unavailable")
        clients = json.loads(verified.stdout)
        if (not isinstance(clients, list) or len(clients) != 1 or
                clients[0].get("clientId") != CLIENT or
                clients[0].get("publicClient") is not False or
                clients[0].get("standardFlowEnabled") is not True or
                clients[0].get("directAccessGrantsEnabled") is not False or
                clients[0].get("redirectUris") != [CALLBACK] or
                clients[0].get("attributes", {}).get("pkce.code.challenge.method") != "S256"):
            raise RuntimeError("realm created but confidential client contract mismatch")
    print("M01_PRODUCTION_REALM_PROVISION_PASS issuer=" + ISSUER +
          " confidential_client=verified strict_PKCE_S256=true " +
          "public_registration=false credential_file=root0600 " +
          "real_users_created=0 public_ingress=false")

def main(argv=None):
    """Only two operator actions: inspect state or provision the single realm."""
    parser = argparse.ArgumentParser(description="Existing Keycloak realm one-time setup")
    parser.add_argument("action", choices=("preflight", "provision"))
    args = parser.parse_args(argv)
    if args.action == "preflight":
        issues = preflight()
        print("M01_PRODUCTION_REALM_" + ("HOLD: " + "; ".join(issues)
              if issues else "PREFLIGHT_PASS"))
        if issues:
            return 2
    else:
        provision()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print("M01_PRODUCTION_REALM_HOLD " +
              (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)

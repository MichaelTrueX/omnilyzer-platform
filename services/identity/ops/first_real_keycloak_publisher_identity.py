#!/usr/bin/env python3
"""First REAL publisher identity invitation, existing Keycloak only.

This creates at most one unverified Keycloak user and emails required actions.
It NEVER sets emailVerified, inserts Sumlaude DB users/links, creates publisher
roles or admission, starts BFF, or activates a product release. Human mailbox
verification is mandatory and is confirmed only in a later read-only action.

Source scope: existing Omnilyzer platform identity PR #243, no new realm.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from uuid import UUID

HOST = "truexmainserver"
ROOT = Path("/etc/omnilyzer/keycloak")
ENV = ROOT / "keycloak.env"
CURRENT = Path("/opt/omnilyzer/keycloak/current")
KCADM = CURRENT / "bin" / "kcadm.sh"
BASE = "http://127.0.0.1:18742"
ISSUER = "https://login.omnilyzer.ai/realms/omnilyzer"
REALM = "omnilyzer"
CLIENT = "sumlaude-bff"
CALLBACK = "https://app.sumlaude.com/auth/callback"
ACTIONS = ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}$")


class Stop(RuntimeError):
    pass


def require(test, code):
    if not test:
        raise Stop(code)


def canonical_email(value):
    require(isinstance(value, str), "EMAIL_MISSING")
    value = value.strip().lower()
    require(len(value) <= 254 and EMAIL_RE.fullmatch(value), "EMAIL_INVALID")
    require(not value.endswith((".invalid", ".example", ".test", ".localhost")),
            "SYNTHETIC_EMAIL_NOT_ALLOWED")
    require(not value.startswith(("test@", "qa@", "fake@", "noreply@")),
            "TEST_IDENTITY_NOT_ALLOWED")
    return value


def root_admin_env():
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(socket.gethostname().split(".")[0] == HOST, "WRONG_HOST")
    require(CURRENT.is_symlink() and KCADM.is_file(), "KEYCLOAK_RUNTIME_MISSING")
    root = ROOT.lstat()
    config = ENV.lstat()
    require(stat.S_ISDIR(root.st_mode) and root.st_uid == 0
            and stat.S_IMODE(root.st_mode) == 0o700 and not ROOT.is_symlink(),
            "KEYCLOAK_ROOT_DIR_UNTRUSTED")
    require(stat.S_ISREG(config.st_mode) and config.st_uid == 0
            and config.st_nlink == 1 and stat.S_IMODE(config.st_mode) == 0o600,
            "KEYCLOAK_ENV_UNTRUSTED")
    props = {}
    for line in ENV.read_text("ascii").splitlines():
        name, sep, value = line.partition("=")
        require(sep and name.isidentifier() and name not in props,
                "KEYCLOAK_ENV_INVALID")
        props[name] = value
    require(props.get("KC_BOOTSTRAP_ADMIN_USERNAME")
            and props.get("KC_BOOTSTRAP_ADMIN_PASSWORD"), "NO_EXISTING_LOCAL_ADMIN")
    return props


def kcadm(args, env, config, *, payload=None):
    cmd = [str(KCADM), *args, "--config", str(config)]
    if payload is not None:
        file = config.parent / ("payload-%d.json" % len(list(config.parent.glob("payload-*.json"))))
        fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(payload, f, ensure_ascii=True, separators=(",", ":"))
            f.write("\n")
        cmd.extend(["-f", str(file)])
    result = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=40)
    require(result.returncode == 0, "KEYCLOAK_LOCAL_ADMIN_API_FAILED")
    return result.stdout


def json_result(args, env, config):
    try:
        return json.loads(kcadm(args, env, config))
    except (TypeError, ValueError):
        raise Stop("KEYCLOAK_ADMIN_JSON_INVALID") from None


def verify_realm(realm, clients):
    require(isinstance(realm, dict) and realm.get("realm") == REALM
            and realm.get("enabled") is True
            and realm.get("registrationAllowed") is False,
            "SHARED_REALM_POLICY_MISMATCH")
    require(isinstance(clients, list) and len(clients) == 1,
            "SUM_LAUDE_CLIENT_NOT_UNIQUE")
    client = clients[0]
    require(client.get("clientId") == CLIENT
            and client.get("enabled") is True
            and client.get("publicClient") is False
            and client.get("standardFlowEnabled") is True
            and client.get("directAccessGrantsEnabled") is False
            and client.get("redirectUris") == [CALLBACK]
            and client.get("attributes", {}).get("pkce.code.challenge.method") == "S256",
            "CONFIDENTIAL_BFF_CLIENT_DRIFT")
    return realm.get("smtpServer")


def select_account(users, email):
    require(isinstance(users, list), "KEYCLOAK_USERS_INVALID")
    exact = [u for u in users
             if isinstance(u, dict) and str(u.get("email", "")).lower() == email]
    require(len(exact) <= 1, "DUPLICATE_REAL_EMAIL_USERS")
    if not exact:
        return None
    user = exact[0]
    try:
        UUID(user.get("id", ""))
    except (ValueError, TypeError, AttributeError):
        raise Stop("KEYCLOAK_SUB_INVALID") from None
    require(user.get("enabled") is True, "EXISTING_USER_DISABLED")
    return user


def verification_status(user):
    if user is None:
        return "ABSENT"
    if user.get("emailVerified") is not True:
        return "PENDING_EMAIL_VERIFICATION"
    if any(action in (user.get("requiredActions") or []) for action in ACTIONS):
        return "PENDING_REQUIRED_ACTION"
    return "VERIFIED"


def require_smtp(smtp):
    require(isinstance(smtp, dict) and smtp.get("host") and smtp.get("from"),
            "NO_VERIFIED_SMTP_CONFIG_DO_NOT_INVITE")


def invite_payload(email):
    # NO password, NEVER emailVerified:true, NO Keycloak/Sumlaude admin roles.
    return {"username": email, "email": email, "enabled": True,
            "emailVerified": False, "requiredActions": ACTIONS}


def operate(action):
    email = canonical_email(os.environ.get("PUBLISHER_EMAIL"))
    props = root_admin_env()
    with tempfile.TemporaryDirectory(prefix="m01-real-user-", dir="/run") as tmp:
        os.chmod(tmp, 0o700)
        cfg = Path(tmp) / "kcadm.config"
        admin = os.environ.copy()
        admin["HOME"] = tmp
        admin["KC_CLI_PASSWORD"] = props["KC_BOOTSTRAP_ADMIN_PASSWORD"]
        # Local-only legacy master admin, held exclusively in root-protected env.
        kcadm(["config", "credentials", "--server", BASE, "--realm", "master",
               "--user", props["KC_BOOTSTRAP_ADMIN_USERNAME"]], admin, cfg)
        realm = json_result(["get", "realms/" + REALM], admin, cfg)
        clients = json_result(["get", "clients", "-r", REALM,
                               "-q", "clientId=" + CLIENT], admin, cfg)
        smtp = verify_realm(realm, clients)
        users = json_result(["get", "users", "-r", REALM,
                             "-q", "email=" + email, "-q", "exact=true",
                             "-q", "max=10"], admin, cfg)
        user = select_account(users, email)
        status = verification_status(user)
        identity_digest = (hashlib.sha256(user["id"].encode()).hexdigest()[:12]
                           if user else "NONE")
        if action == "preflight":
            print("M01_KEYCLOAK_REALM_CONFIDENTIAL_CLIENT_READONLY_PASS")
            print("M01_KEYCLOAK_PUBLISHER_ACCOUNT_STATUS=" + status)
            print("M01_KEYCLOAK_SELECTED_SUB_SHA12=" + identity_digest)
            print("M01_KEYCLOAK_SMTP_CONFIG=" +
                  ("PRESENT" if isinstance(smtp, dict)
                   and smtp.get("host") and smtp.get("from") else "MISSING"))
            print("M01_KEYCLOAK_NO_ACCOUNT_OR_ROLE_WRITE_PASS")
            return
        if action == "verify":
            require(status == "VERIFIED", "REAL_HUMAN_EMAIL_ACTIONS_INCOMPLETE")
            print("M01_KEYCLOAK_EMAIL_VERIFIED_AND_ACTIONS_CLEARED_PASS sub_sha12=" +
                  identity_digest)
            print("M01_REAL_SIGNED_OIDC_LOGIN_AND_S03_LINK_STILL_REQUIRED")
            print("M01_SUM_LAUDE_DATABASE_USER_LINK_PUBLISHER_ROLE_NOT_CREATED")
            return
        require(action == "invite", "INVALID_ACTION")
        require(status == "ABSENT", "REAL_ACCOUNT_ALREADY_EXISTS_NO_OVERWRITE")
        require_smtp(smtp)
        # Create one identity that cannot authenticate before real mailbox action.
        kcadm(["create", "users", "-r", REALM],
              admin, cfg, payload=invite_payload(email))
        created = select_account(json_result(
            ["get", "users", "-r", REALM, "-q", "email=" + email,
             "-q", "exact=true", "-q", "max=10"], admin, cfg), email)
        require(created and verification_status(created)
                == "PENDING_EMAIL_VERIFICATION" and
                set(ACTIONS).issubset(set(created.get("requiredActions") or [])),
                "NEW_USER_NEEDS_MANUAL_OPERATOR_RECOVERY")
        kcadm(["update", "users/" + created["id"] + "/execute-actions-email",
               "-r", REALM],
              admin, cfg, payload=ACTIONS)
        print("M01_KEYCLOAK_ONE_REAL_MAILBOX_INVITATION_SENT")
        print("M01_KEYCLOAK_EMAIL_VERIFICATION_AND_PASSWORD_SETUP_REQUIRED")
        print("M01_SUM_LAUDE_DATABASE_USER_LINK_PUBLISHER_ROLE_NOT_CREATED")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "invite", "verify"))
    arg = parser.parse_args()
    try:
        operate(arg.action)
    except (Stop, OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        if isinstance(exc, Stop):
            reason = str(exc)
        else:
            reason = "LOCAL_PROTECTED_OPERATION_UNAVAILABLE"
        print("M01_FIRST_REAL_IDENTITY_HOLD=" + reason, file=sys.stderr)
        return 73
    return 0


if __name__ == "__main__":
    sys.exit(main())

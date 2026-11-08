#!/usr/bin/env python3
"""Bounded root-only Google Workspace SMTP configuration for existing Keycloak.

Requires an existing root-owned local bootstrap admin, unchanged realm client,
no existing SMTP config, and TLS 1.2+ to Google's implicit TLS port 465.
Does not create users, send mail, open public registration, or alter services.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tempfile

HOST = "truexmainserver"
ROOT = Path("/etc/omnilyzer/keycloak")
ENV = ROOT / "keycloak.env"
KCADM = Path("/opt/omnilyzer/keycloak/current/bin/kcadm.sh")
CURRENT = Path("/opt/omnilyzer/keycloak/current")
LOCAL_ADMIN = "http://127.0.0.1:18742"
REALM = "omnilyzer"
ISSUER = "https://login.omnilyzer.ai/realms/omnilyzer"
CLIENT = "sumlaude-bff"
CALLBACK = "https://app.sumlaude.com/auth/callback"
SMTP = {
    "host": "smtp-relay.gmail.com",
    "port": "465",
    "from": "no-reply@sumlaude.com",
    "envelopeFrom": "no-reply@sumlaude.com",
    "fromDisplayName": "Sumlaude",
    "ssl": "true",
    "starttls": "false",
    "auth": "false",
}

class Hold(RuntimeError):
    pass

def require(condition, code):
    if not condition:
        raise Hold(code)

def protected_admin_credentials():
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(socket.gethostname().split(".")[0] == HOST, "WRONG_HOST")
    require(CURRENT.is_symlink() and KCADM.is_file(), "KEYCLOAK_RUNTIME_MISSING")
    root = ROOT.lstat()
    config = ENV.lstat()
    require(stat.S_ISDIR(root.st_mode) and root.st_uid == 0
            and stat.S_IMODE(root.st_mode) == 0o700
            and not ROOT.is_symlink(), "ROOT_CONFIG_DIR_UNTRUSTED")
    require(stat.S_ISREG(config.st_mode) and config.st_uid == 0
            and config.st_nlink == 1 and stat.S_IMODE(config.st_mode) == 0o600,
            "ROOT_ADMIN_CREDENTIAL_FILE_UNTRUSTED")
    props = {}
    for line in ENV.read_text("ascii").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key.isidentifier() and key not in props,
                "ROOT_ADMIN_CREDENTIAL_FILE_INVALID")
        props[key] = value
    require(props.get("KC_BOOTSTRAP_ADMIN_USERNAME")
            and props.get("KC_BOOTSTRAP_ADMIN_PASSWORD"), "ROOT_ADMIN_CREDENTIAL_MISSING")
    return props

def admin_cli(args, env, config):
    cmd = [str(KCADM), *args, "--config", str(config)]
    result = subprocess.run(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=45)
    require(result.returncode == 0, "KEYCLOAK_ADMIN_LOCAL_CALL_FAILED")
    return result.stdout

def read_json(args, env, config):
    try:
        return json.loads(admin_cli(args, env, config))
    except (TypeError, ValueError):
        raise Hold("ADMIN_RESPONSE_NOT_VALID_JSON") from None

def verify_contract(realm, clients):
    require(isinstance(realm, dict) and realm.get("realm") == REALM
            and realm.get("enabled") is True
            and realm.get("registrationAllowed") is False,
            "KEYCLOAK_REALM_POLICY_DRIFT")
    require(isinstance(clients, list) and len(clients) == 1,
            "CONFIDENTIAL_CLIENT_NOT_UNIQUE")
    client = clients[0]
    require(client.get("clientId") == CLIENT and client.get("enabled") is True
            and client.get("publicClient") is False
            and client.get("standardFlowEnabled") is True
            and client.get("directAccessGrantsEnabled") is False
            and client.get("redirectUris") == [CALLBACK]
            and client.get("attributes", {}).get("pkce.code.challenge.method") == "S256",
            "CONFIDENTIAL_CLIENT_POLICY_DRIFT")

def smtp_state(obj):
    if obj in (None, {}):
        return "MISSING"
    if isinstance(obj, dict) and all(obj.get(k) == v for k, v in SMTP.items()) \
            and set(obj).issubset(set(SMTP)):
        return "EXACT_EXPECTED"
    return "UNEXPECTED"

def tls_connectivity():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((SMTP["host"], int(SMTP["port"])), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=SMTP["host"]) as sock:
                require(sock.version() in ("TLSv1.2", "TLSv1.3"), "GOOGLE_TLS_PROTOCOL_WEAK")
                greeting = sock.recv(128)
                require(greeting.startswith(b"220"), "GOOGLE_SMTP_TLS_GREETING_INVALID")
    except (OSError, ssl.SSLError):
        raise Hold("GOOGLE_IMPLICIT_TLS_CONNECT_FAILED") from None
    return "M01_KEYCLOAK_GOOGLE_IMPLICIT_TLS465_CERT_VALIDATED_PASS"

def operate(action):
    props = protected_admin_credentials()
    with tempfile.TemporaryDirectory(prefix="m01-keycloak-smtp-", dir="/run") as tmp:
        os.chmod(tmp, 0o700)
        config = Path(tmp) / "kcadm.config"
        env = os.environ.copy()
        env["HOME"] = tmp
        env["KC_CLI_PASSWORD"] = props["KC_BOOTSTRAP_ADMIN_PASSWORD"]
        admin_cli(["config", "credentials", "--server", LOCAL_ADMIN,
                   "--realm", "master", "--user",
                   props["KC_BOOTSTRAP_ADMIN_USERNAME"]], env, config)
        realm = read_json(["get", "realms/" + REALM], env, config)
        clients = read_json(["get", "clients", "-r", REALM,
                             "-q", "clientId=" + CLIENT], env, config)
        verify_contract(realm, clients)
        state = smtp_state(realm.get("smtpServer"))
        print("M01_KEYCLOAK_CONFIDENTIAL_REALM_READONLY_PASS")
        print("M01_KEYCLOAK_SMTP_CURRENT=" + state)
        require(state != "UNEXPECTED", "UNEXPECTED_EXISTING_SMTP_CONFIG_HOLD")
        if action == "preflight":
            print(tls_connectivity())
            print("M01_KEYCLOAK_SMTP_PREFLIGHT_NO_WRITES_PASS")
            return
        if action == "configure":
            require(state == "MISSING", "SMTP_ALREADY_CONFIGURED_NO_OVERWRITE")
            print(tls_connectivity())
            # kcadm --merge fetches realm and modifies *only* smtpServer.
            # SMTP is a Map<String,String>; never insert JSON booleans.
            admin_cli(["update", "realms/" + REALM, "-s",
                       "smtpServer=" + json.dumps(SMTP, separators=(",", ":")),
                       "--merge"], env, config)
            new_realm = read_json(["get", "realms/" + REALM], env, config)
            verify_contract(new_realm, read_json(
                ["get", "clients", "-r", REALM,
                 "-q", "clientId=" + CLIENT], env, config))
            require(smtp_state(new_realm.get("smtpServer")) == "EXACT_EXPECTED",
                    "SMTP_WRITE_READBACK_MISMATCH_STOP")
            print("M01_KEYCLOAK_SMTP_EXACT_TLS465_NO_AUTH_CONFIGURED_PASS")
            print("M01_KEYCLOAK_NO_USER_NO_ROLE_NO_SERVICE_CHANGE")
            print("M01_KEYCLOAK_SMTP_REAL_EMAIL_DELIVERY_NOT_YET_TESTED")
            return
        require(action == "rollback", "INVALID_ACTION")
        require(state == "EXACT_EXPECTED", "ROLLBACK_REQUIRES_EXACT_CURRENT_SMTP")
        admin_cli(["update", "realms/" + REALM,
                   "-s", "smtpServer={}", "--merge"], env, config)
        new_realm = read_json(["get", "realms/" + REALM], env, config)
        require(smtp_state(new_realm.get("smtpServer")) == "MISSING",
                "SMTP_ROLLBACK_READBACK_FAILED_STOP")
        print("M01_KEYCLOAK_SMTP_ROLLBACK_DISABLED_PASS")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "configure", "rollback"))
    args = parser.parse_args()
    try:
        operate(args.action)
    except (Hold, OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        reason = str(exc) if isinstance(exc, Hold) else "PROTECTED_OPERATION_UNAVAILABLE"
        print("M01_KEYCLOAK_SMTP_HOLD=" + reason, file=sys.stderr)
        return 73
    return 0

if __name__ == "__main__":
    sys.exit(main())

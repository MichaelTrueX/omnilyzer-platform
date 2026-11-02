#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_private_dev.py
Purpose: Prepare and operate one isolated, tailnet-only Keycloak DEV instance
    backed by persistent PostgreSQL without affecting Analytics Task014.
Related: services/identity/config/settings.py, services/identity/identity_bff/oidc.py,
    services/identity/tests/test_keycloak_private_dev.py and ADR-0003.

This is not a production IdP installer. Never use its synthetic realm as
an authority for real Omnilyzer or Sumlaude users.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import secrets
import socket
import subprocess
import sys
import time
from urllib.request import Request, urlopen

PROJECT = "omnilyzer-keycloak-private-dev"
BASE = Path.home() / ".local" / "share" / PROJECT
TAILNET_NAME = "truexdevelopment.tail52e570.ts.net"
ORIGIN = "https://" + TAILNET_NAME
ISSUER = ORIGIN + "/realms/omnilyzer-dev"
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.2"
POSTGRES_IMAGE = "postgres:16.15-alpine"
# Local, previously inspected Docker image IDs, not remote manifest digests.
IMAGE_IDS = {
    KEYCLOAK_IMAGE: "sha256:710025e15517f004db1166fea5f9d74a6624ed89eb4196aa48f401c75a52c7ce",
    POSTGRES_IMAGE: "sha256:75f5a96988cdf694a215073c3e9c001b706b371e2f94df3967f2efdec2787f6b",
}
PORT = 18080

# Section: Rendering. Only Docker Compose's built-in interpolation is used.
# Credentials exist solely in a 0600 runtime file outside source control.
COMPOSE = '''name: omnilyzer-keycloak-private-dev
services:
  keycloak-db:
    image: postgres:16.15-alpine
    pull_policy: never
    restart: unless-stopped
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${KEYCLOAK_DB_PASSWORD:?}
    volumes:
      - keycloak_data:/var/lib/postgresql/data
    networks:
      - private-db
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 10s
      timeout: 5s
      retries: 10
    mem_limit: 512m
    pids_limit: 128
    security_opt: ["no-new-privileges:true"]
  keycloak:
    image: quay.io/keycloak/keycloak:26.7.2
    pull_policy: never
    restart: unless-stopped
    command: ["start", "--import-realm"]
    depends_on:
      keycloak-db:
        condition: service_healthy
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KEYCLOAK_DB_PASSWORD:?}
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME: https://truexdevelopment.tail52e570.ts.net
      KC_HOSTNAME_STRICT: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HEALTH_ENABLED: "true"
      KC_BOOTSTRAP_ADMIN_USERNAME: ${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:?}
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD:?}
    ports:
      - "127.0.0.1:18080:8080"
    volumes:
      - ./realm.json:/opt/keycloak/data/import/omnilyzer-dev.json:ro
    networks:
      - private-db
      - frontend
    mem_limit: 2g
    pids_limit: 256
    security_opt: ["no-new-privileges:true"]
volumes:
  keycloak_data:
networks:
  private-db:
    internal: true
  frontend:
    driver: bridge
'''


# Section: Deny accidental mutations of an occupied or unexpectedly changed host.
def run(*args, timeout=20, capture=True):
    """Invoke fixed commands with no shell expansion or secret-bearing arguments."""
    return subprocess.run(args, check=True, text=True, timeout=timeout,
                          capture_output=capture)


def plan():
    """Read-only preflight for image identity, localhost port and tailnet name."""
    if os.geteuid() == 0:
        raise RuntimeError("run as the normal dedicated DEV operator, not root")
    if shutil.disk_usage(Path.home()).free < 12 * 1024**3:
        raise RuntimeError("insufficient free disk for protected DEV deployment")
    run("docker", "compose", "version")
    for image, expected in IMAGE_IDS.items():
        actual = run("docker", "image", "inspect", image, "--format", "{{.Id}}").stdout.strip()
        if actual != expected:
            raise RuntimeError("local Docker image differs from reviewed image ID: " + image)
    if BASE.exists():
        raise RuntimeError("private DEV install path already exists; do not overwrite")
    if run("docker", "ps", "-a", "--filter", "label=com.docker.compose.project=" + PROJECT,
           "--format", "{{.ID}}").stdout.strip():
        raise RuntimeError("existing Docker project must be inventoried before install")
    with socket.socket() as s:
        s.bind(("127.0.0.1", PORT))
    status = json.loads(run("tailscale", "status", "--json").stdout)
    own = status.get("Self") or {}
    if not own.get("Online") or own.get("DNSName", "").rstrip(".") != TAILNET_NAME:
        raise RuntimeError("unexpected Tailscale identity; do not bind wrong issuer")
    serve = json.loads(run("tailscale", "serve", "status", "--json").stdout) or {}
    if (serve.get("Web") or serve.get("TCP")):
        raise RuntimeError("existing Tailscale Serve configuration needs independent review")
    return {"source": "cached Docker images verified", "issuer": ISSUER,
            "bind": "127.0.0.1:18080", "db": "isolated Docker volume/no host port",
            "existing_services": "not touched"}


def realm(client_secret):
    """Create a synthetic-only DEV realm and strictly scoped confidential BFF client."""
    return {
        "realm": "omnilyzer-dev", "enabled": True,
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False,
        "clients": [{
            "clientId": "sumlaude-bff-dev", "name": "Sumlaude disposable BFF QA",
            "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret",
            "secret": client_secret, "standardFlowEnabled": True,
            "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": ["https://app.sumlaude.com/auth/callback"],
            "webOrigins": ["https://app.sumlaude.com"],
            "attributes": {"pkce.code.challenge.method": "S256"},
        }],
    }


def write_new(path, data):
    """Create secret-bearing runtime files exactly once without following symlinks."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def prepare():
    """Create isolated private runtime configuration with random 48-byte secrets."""
    plan()
    BASE.mkdir(parents=True, mode=0o700)
    os.chmod(BASE, 0o700)
    db_secret = secrets.token_urlsafe(48)
    bootstrap = secrets.token_urlsafe(48)
    client_secret = secrets.token_urlsafe(48)
    write_new(BASE / ".env", "KEYCLOAK_DB_PASSWORD=" + db_secret + "\n"
              "KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=dev-operator\n"
              "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=" + bootstrap + "\n")
    write_new(BASE / "realm.json", json.dumps(realm(client_secret), indent=2) + "\n")
    write_new(BASE / "compose.yaml", COMPOSE)
    # The runtime never writes these values to logs, GitHub, or chat.
    return {"runtime_dir": str(BASE), "credentials": "private 0600 files created",
            "db": "persistent compose volume (backup not yet verified)"}


def activate():
    """Start only the named isolated Compose project; never modify existing stacks."""
    if not BASE.is_dir() or BASE.is_symlink():
        raise RuntimeError("missing or invalid prepared runtime directory")
    if os.stat(BASE).st_mode & 0o077:
        raise RuntimeError("runtime directory permits other users")
    for name in (".env", "realm.json", "compose.yaml"):
        p = BASE / name
        if not p.is_file() or p.is_symlink() or os.stat(p).st_mode & 0o077:
            raise RuntimeError("insecure or missing runtime file: " + name)
    if (BASE / "compose.yaml").read_text() != COMPOSE:
        raise RuntimeError("compose bytes do not match reviewed source")
    run("docker", "compose", "--project-directory", str(BASE),
        "--file", str(BASE / "compose.yaml"), "up", "--detach", "--no-build", "--pull", "never",
        timeout=120)
    url = "http://127.0.0.1:18080/realms/omnilyzer-dev/.well-known/openid-configuration"
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        try:
            with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=2) as r:
                if r.status == 200:
                    body = json.loads(r.read(1048577))
                    if body.get("issuer") == ISSUER:
                        return {"status": "local OIDC discovery PASS", "issuer": ISSUER,
                                "note": "Tailscale HTTPS exposure not enabled by this operation"}
                    raise RuntimeError("OIDC issuer mismatch")
        except (OSError, ValueError):
            time.sleep(2)
    raise RuntimeError("Keycloak did not become ready; preserve data for diagnosis")


def main(argv=None):
    """Expose separate non-mutating plan, configuration preparation, activation."""
    parser = argparse.ArgumentParser(description="Isolated Keycloak DEV installer")
    parser.add_argument("action", choices=["plan", "prepare", "activate"])
    args = parser.parse_args(argv)
    if args.action == "plan":
        result = plan()
    elif args.action == "prepare":
        result = prepare()
    else:
        result = activate()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as exc:
        print("KEYCLOAK_PRIVATE_DEV_HOLD: " + str(exc), file=sys.stderr)
        sys.exit(2)

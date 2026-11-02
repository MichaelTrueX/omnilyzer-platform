#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_public_ingress.py
Purpose: Install a dedicated HTTP-01-only Nginx vhost and later activate
    Cloudflare-only HTTPS proxying to an already working production Keycloak.
Linked: services/identity/ops/{keycloak_public_prod,keycloak_provision_realm}.py,
    services/identity/tests/test_keycloak_public_ingress.py,
    docs/adr/0003-keycloak-bff-and-native-authentication.md.

Two separate explicit root actions:
1. prepare-acme: only a public HTTP ACME challenge path, all else HTTP404.
2. activate-https: only after an exact public trusted TLS certificate, enable
   the production-realm/public-resources proxy. Master/admin remain inaccessible.
This tool never creates DNS or certificates, restarts Keycloak, changes product
auth, or edits existing Nginx virtual hosts. No uncontrolled retries.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
from urllib.request import urlopen

HOST = "truexmainserver"
DOMAIN = "login.omnilyzer.ai"
ORIGIN = "https://" + DOMAIN
ISSUER = ORIGIN + "/realms/omnilyzer"
BACKEND = "127.0.0.1:18742"
AVAILABLE = Path("/etc/nginx/sites-available/login.omnilyzer.ai.conf")
ENABLED = Path("/etc/nginx/sites-enabled/login.omnilyzer.ai.conf")
WEBROOT = Path("/var/www/omnilyzer-login-acme")
CERT = Path("/etc/letsencrypt/live/login.omnilyzer.ai/fullchain.pem")
KEY = Path("/etc/letsencrypt/live/login.omnilyzer.ai/privkey.pem")

CLOUDFLARE_IPS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
)


# Section: Render one isolated vhost; never alter an existing site's config.
def http_vhost():
    """Limit public port 80 to ACME HTTP-01 and return 404 otherwise."""
    return """# File: /etc/nginx/sites-available/login.omnilyzer.ai.conf
# Purpose: Single Keycloak issuer; phase 1 ACME-only, NOT public login yet.
# Links: services/identity/ops/keycloak_public_ingress.py and Keycloak 18742.
server {
    listen 80;
    listen [::]:80;
    server_name login.omnilyzer.ai;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/omnilyzer-login-acme;
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        try_files $uri =404;
    }
    location / {
        return 404;
    }
}
"""


def https_vhost():
    """Expose only the product realm and its static resources via Cloudflare."""
    ip_rules = "".join("    allow " + ip + ";\n" for ip in CLOUDFLARE_IPS)
    return (http_vhost() +
            """
# Phase 2: Cloudflare Full (strict) upstream HTTPS; never expose /admin
# or /realms/master, and no direct-origin bypass of Cloudflare protection.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name login.omnilyzer.ai;
    ssl_certificate /etc/letsencrypt/live/login.omnilyzer.ai/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/login.omnilyzer.ai/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    ssl_session_tickets off;
""" + ip_rules + """    deny all;
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Cache-Control "no-store" always;
    access_log off;
    location = / {
        return 404;
    }
    location / {
        return 404;
    }
    # Only identity users' realm is public. No bootstrap/master/admin API.
    location ^~ /realms/omnilyzer/ {
        proxy_pass http://127.0.0.1:18742;
        proxy_http_version 1.1;
        proxy_set_header Host login.omnilyzer.ai;
        proxy_set_header X-Forwarded-Host login.omnilyzer.ai;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_connect_timeout 4s;
        proxy_send_timeout 45s;
        proxy_read_timeout 45s;
        proxy_buffering off;
    }
    # Needed by the Keycloak browser login page. Static files carry no
    # OAuth account or administrator permission.
    location ^~ /resources/ {
        proxy_pass http://127.0.0.1:18742;
        proxy_http_version 1.1;
        proxy_set_header Host login.omnilyzer.ai;
        proxy_set_header X-Forwarded-Host login.omnilyzer.ai;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_connect_timeout 4s;
        proxy_read_timeout 45s;
    }
}
""")


# Section: Run bounded, fixed host commands; enforce exact-state transitions.
def run(argv, *, timeout=15):
    """Execute a command without shell expansion or secret-bearing arguments."""
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          timeout=timeout)


def identity_check():
    """Require live local product issuer before exposing any login endpoint."""
    with urlopen("http://" + BACKEND +
                 "/realms/omnilyzer/.well-known/openid-configuration",
                 timeout=5) as response:
        data = json.loads(response.read(1048577))
    if data.get("issuer") != ISSUER or not data.get("jwks_uri", "").startswith(ORIGIN):
        raise RuntimeError("actual local realm issuer mismatch")


def base_check():
    """Verify exact root authority, host and untouched Nginx service."""
    problems = []
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        problems.append("root required on truexmainserver")
    try:
        if run(["/usr/bin/systemctl", "is-active", "nginx"]).stdout.strip() != "active":
            problems.append("Nginx not active")
        run(["/usr/sbin/nginx", "-t"])
        identity_check()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        problems.append("Nginx or exact local identity source not verified")
    if ENABLED.is_symlink() and ENABLED.resolve() != AVAILABLE:
        problems.append("existing Nginx symlink points to another configuration")
    return problems


def acme_preflight():
    """Fail closed if this dedicated vhost or webroot already exists."""
    problems = base_check()
    if AVAILABLE.exists() or AVAILABLE.is_symlink() or ENABLED.exists() or ENABLED.is_symlink():
        problems.append("login vhost already exists; do not replace")
    if WEBROOT.exists():
        problems.append("ACME webroot already exists; inspect before mutation")
    return problems


def install_acme():
    """Install only an HTTP-01 challenge endpoint; restore on failed Nginx test."""
    problems = acme_preflight()
    if problems:
        raise RuntimeError("ACME_HOLD: " + "; ".join(problems))
    WEBROOT.mkdir(parents=True, mode=0o755)
    (WEBROOT / ".well-known" / "acme-challenge").mkdir(
        parents=True, mode=0o755)
    # Root's 0077 umask would otherwise make the ACME challenge unreadable
    # by Nginx's unprivileged worker. Only this brand-new webroot is adjusted.
    for directory in (WEBROOT, WEBROOT / ".well-known",
                      WEBROOT / ".well-known" / "acme-challenge"):
        if directory.is_symlink():
            raise RuntimeError("new ACME webroot unexpectedly symlinked")
        directory.chmod(0o755)
    file_created = False
    link_created = False
    try:
        fd = os.open(AVAILABLE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(http_vhost())
            output.flush()
            os.fsync(output.fileno())
        file_created = True
        ENABLED.symlink_to(AVAILABLE)
        link_created = True
        run(["/usr/sbin/nginx", "-t"])
        run(["/usr/bin/systemctl", "reload", "nginx"])
    except Exception:
        if link_created:
            ENABLED.unlink()
        if file_created:
            AVAILABLE.unlink()
        # Retain the innocuous webroot for administrator inspection.
        run(["/usr/sbin/nginx", "-t"])
        run(["/usr/bin/systemctl", "reload", "nginx"])
        raise
    print("M01_LOGIN_ACME_ONLY_PASS http_80_challenge=true login_http=404 " +
          "https_unmodified=true keycloak_private=true other_vhosts_untouched=true")


def tls_preflight():
    """Only permit upgrade of the exact previously accepted ACME-only vhost."""
    problems = base_check()
    try:
        if not AVAILABLE.is_file() or AVAILABLE.is_symlink():
            problems.append("dedicated vhost missing or symlinked")
        elif AVAILABLE.read_text() != http_vhost():
            problems.append("dedicated vhost does not match approved ACME-only phase")
        if not ENABLED.is_symlink() or ENABLED.resolve() != AVAILABLE:
            problems.append("dedicated vhost activation symlink unexpected")
        if not (WEBROOT / ".well-known" / "acme-challenge").is_dir():
            problems.append("ACME webroot absent")
        if not CERT.is_file() or not KEY.is_file():
            problems.append("publicly trusted certificate and private key not yet installed")
        else:
            data = run(["/usr/bin/openssl", "x509", "-in", str(CERT),
                        "-noout", "-ext", "subjectAltName"]).stdout
            if "DNS:" + DOMAIN not in data:
                problems.append("certificate SAN does not match login host")
            run(["/usr/bin/openssl", "x509", "-checkend", "1209600", "-noout",
                 "-in", str(CERT)])
    except (OSError, subprocess.SubprocessError):
        problems.append("certificate or ACME config unreadable")
    return problems


def diagnose_https():
    """Read-only Nginx parser test against the exact proposed and existing sites.

    Build a temporary alternative Nginx master config in root-only /run;
    substitute only the login virtual-host include and never change the
    live Nginx config, service, certificates, DNS, or Keycloak.
    """
    import re
    import tempfile
    problems = tls_preflight()
    if problems:
        raise RuntimeError("DIAG_HOLD " + "; ".join(problems))
    master = Path("/etc/nginx/nginx.conf").read_text(encoding="utf-8")
    needle = "include /etc/nginx/sites-enabled/*;"
    if master.count(needle) != 1:
        raise RuntimeError("NGINX_INCLUDE_LAYOUT_HOLD")
    current_sites = sorted(Path("/etc/nginx/sites-enabled").iterdir())
    if not current_sites or len(current_sites) > 64:
        raise RuntimeError("NGINX_SITE_COUNT_HOLD")
    if ENABLED not in current_sites:
        raise RuntimeError("NGINX_LOGIN_SITE_NOT_ENABLED")
    for site in current_sites:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", site.name) or not site.is_file():
            raise RuntimeError("NGINX_UNEXPECTED_SITE_NAME_OR_FILE")
    with tempfile.TemporaryDirectory(prefix="m01-nginx-diagnostic-", dir="/run") as directory:
        scratch = Path(directory)
        proposed = scratch / "login-proposed.conf"
        proposed.write_text(https_vhost(), encoding="utf-8")
        proposed.chmod(0o600)
        all_includes = "".join(
            "    include " + str(proposed if site == ENABLED else site) + ";\n"
            for site in current_sites
        )
        alternate = scratch / "nginx.conf"
        alternate.write_text(master.replace(needle, all_includes), encoding="utf-8")
        alternate.chmod(0o600)
        result = subprocess.run(
            ["/usr/sbin/nginx", "-t", "-c", str(alternate),
             "-p", "/etc/nginx/"],
            capture_output=True, text=True, timeout=20)
        # This output contains only Nginx diagnostics, not config or secrets.
        # Limit its length so no large privileged log is copied into the chat.
        output = "\n".join((result.stderr or "").splitlines()[-14:])
        print("M01_NGINX_CANDIDATE_EXIT=" + str(result.returncode))
        print("M01_NGINX_CANDIDATE_DIAGNOSTIC_BEGIN\n" +
              output[:2400] + "\nM01_NGINX_CANDIDATE_DIAGNOSTIC_END")
        if result.returncode:
            raise RuntimeError("isolated Nginx candidate validation failed; existing config untouched")
        print("M01_NGINX_CANDIDATE_PASS live_nginx_unchanged=true")


def install_https():
    """Atomically upgrade only the dedicated identity vhost after cert checks."""
    problems = tls_preflight()
    if problems:
        raise RuntimeError("TLS_HOLD: " + "; ".join(problems))
    fd, stage = None, None
    from tempfile import mkstemp
    fd, stage = mkstemp(prefix=".m01-login-", dir=str(AVAILABLE.parent))
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(https_vhost())
            output.flush()
            os.fsync(output.fileno())
        os.replace(stage, AVAILABLE)
        stage = None
        try:
            run(["/usr/sbin/nginx", "-t"])
            run(["/usr/bin/systemctl", "reload", "nginx"])
        except Exception:
            AVAILABLE.write_text(http_vhost(), encoding="utf-8")
            AVAILABLE.chmod(0o644)
            run(["/usr/sbin/nginx", "-t"])
            run(["/usr/bin/systemctl", "reload", "nginx"])
            raise
    finally:
        if stage and os.path.exists(stage):
            os.unlink(stage)
    print("M01_LOGIN_HTTPS_ORIGIN_PASS host=" + DOMAIN +
          " allowed_paths=realms/omnilyzer,resources " +
          "admin_master_denied=true cloudflare_only=true " +
          "http_acme_only=true other_vhosts_untouched=true")


def main(argv=None):
    """One explicit phase per root command; no automatic public activation."""
    parser = argparse.ArgumentParser(description="Isolated Keycloak HTTPS ingress")
    parser.add_argument("action", choices=("acme-preflight", "prepare-acme",
                                           "tls-preflight", "diagnose-https",
                                           "activate-https"))
    name = parser.parse_args(argv).action
    if name == "acme-preflight":
        errors = acme_preflight()
    elif name == "tls-preflight":
        errors = tls_preflight()
    else:
        errors = None
    if errors is not None:
        print("M01_LOGIN_INGRESS_" + ("HOLD " + "; ".join(errors) if errors
              else "PREFLIGHT_PASS phase=" + name))
        return 2 if errors else 0
    if name == "prepare-acme":
        install_acme()
    elif name == "diagnose-https":
        diagnose_https()
    else:
        install_https()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("M01_LOGIN_INGRESS_HOLD " +
              (str(error) if isinstance(error, RuntimeError)
               else type(error).__name__), file=sys.stderr)
        sys.exit(2)

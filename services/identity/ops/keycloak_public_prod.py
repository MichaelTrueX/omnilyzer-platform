#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_public_prod.py
Purpose: Owner-controlled, fail-closed install of one native Keycloak 26.8.1
    on truexmainserver with an isolated PostgreSQL database and loopback service.
Related: services/identity/ops/keycloak_private_dev.py,
    services/identity/identity_bff/{oidc,views}.py,
    docs/adr/0003-keycloak-bff-and-native-authentication.md,
    services/identity/tests/test_keycloak_public_prod.py.

The installer NEVER creates a DNS record, changes Nginx, publishes a port,
starts another product or migrates a legacy user. An installed local IdP does
NOT authorize public authentication, learner access, or production BFF.
"""
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen
import json

VERSION = "26.8.1"
ARTIFACT_SHA256 = "4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8"
ARCHIVE = Path("/home/trusthansen/.cache/omnilyzer-identity-production-preflight/keycloak-26.8.1.tar.gz")
RELEASE = Path("/opt/omnilyzer/keycloak/releases/26.8.1")
CURRENT = Path("/opt/omnilyzer/keycloak/current")
ENV = Path("/etc/omnilyzer/keycloak/keycloak.env")
UNIT = Path("/etc/systemd/system/omnilyzer-keycloak.service")
DB = "omnilyzer_keycloak"
ROLE = "omnilyzer_keycloak"
SERVICE_USER = "omnilyzer-keycloak"
PUBLIC_HOST = "login.omnilyzer.ai"
PORT = 18742


# Section: Execute fixed host commands, never a shell or secret-bearing argv.
def call(args, *, input_text=None, environ=None, timeout=120):
    """Run one explicit command and raise on failure without printing secrets."""
    return subprocess.run(args, input=input_text, text=True, check=True,
                          capture_output=True, env=environ, timeout=timeout)


def archive_bytes():
    """Read a single regular, owner-controlled archive with O_NOFOLLOW and SHA check."""
    fd = os.open(str(ARCHIVE), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        expected_owner = pwd.getpwnam("trusthansen").pw_uid
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_size > 200 * 1024 * 1024):
            raise RuntimeError("archive ownership, size or mode unexpected")
        with os.fdopen(fd, "rb", closefd=False) as fp:
            raw = fp.read(200 * 1024 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != ARTIFACT_SHA256:
            raise RuntimeError("official Keycloak release digest mismatch")
        return raw
    finally:
        os.close(fd)


def archive_layout(raw):
    """Reject traversal, special files, links and unexpected archive members."""
    import io
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if not 300 <= len(members) <= 2000:
            raise RuntimeError("unexpected archive member count")
        for member in members:
            parts = Path(member.name).parts
            if (not parts or parts[0] != "keycloak-" + VERSION or
                    ".." in parts or member.name.startswith("/") or
                    not (member.isfile() or member.isdir())):
                raise RuntimeError("unsafe Keycloak distribution member")
        return len(members)


# Section: Inspect the exact public host and report all relevant holds together.
def preflight():
    """Require host, free resources, reserved ports, source and isolation."""
    problems = []
    if socket.gethostname().split(".")[0] != "truexmainserver":
        problems.append("wrong host")
    if os.path.exists(UNIT) or RELEASE.exists() or os.path.lexists(CURRENT) or ENV.exists():
        problems.append("production identity already installed or partially staged")
    if os.path.exists("/etc/omnilyzer/keycloak"):
        problems.append("existing protected Keycloak configuration directory")
    try:
        pwd.getpwnam(SERVICE_USER)
        problems.append("Keycloak service user already exists; inspect before installation")
    except KeyError:
        pass
    if shutil.disk_usage("/").free < 10 * 1024**3:
        problems.append("less than 10GiB free root filesystem")
    with open("/proc/meminfo", encoding="ascii") as f:
        info = {k.rstrip(":"): int(v.split()[0]) for k, v in
                (line.split(":", 1) for line in f if ":" in line)}
    if info.get("MemAvailable", 0) < 1800 * 1024:
        problems.append("less than 1.8GiB currently available memory")
    for port in (PORT, 18740, 18741):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                problems.append("identity or Sumlaude port already occupied: " + str(port))
    try:
        raw = archive_bytes()
        archive_layout(raw)
    except (OSError, RuntimeError, tarfile.TarError, ValueError) as exc:
        problems.append("Keycloak archive invalid: " + str(exc))
    try:
        if call(["systemctl", "is-active", "postgresql.service"]).stdout.strip() != "active":
            problems.append("local PostgreSQL not active")
    except subprocess.SubprocessError:
        problems.append("PostgreSQL status unavailable")
    if os.geteuid() == 0:
        for kind, name in (("pg_roles", ROLE), ("pg_database", DB)):
            sql = "SELECT 1 FROM " + kind + " WHERE " + (
                "rolname" if kind == "pg_roles" else "datname") + "='" + name + "'"
            try:
                value = call(["/usr/sbin/runuser", "-u", "postgres", "--",
                              "/usr/bin/psql", "-XAtq", "-d", "postgres", "-c", sql]).stdout.strip()
                if value:
                    problems.append("database or role already exists: " + name)
            except subprocess.SubprocessError:
                problems.append("cannot inspect PostgreSQL catalog: " + kind)
    return problems


# Section: Create one root-controlled installation, without public exposure.
def install():
    """Install Java and isolated identity objects only after strict root preflight."""
    if os.geteuid() != 0:
        raise RuntimeError("owner-root approval required for local install")
    issues = preflight()
    if issues:
        raise RuntimeError("INSTALL_HOLD: " + "; ".join(issues))
    # Archive bytes remain pinned in memory, independent of user-path changes.
    raw = archive_bytes()
    archive_layout(raw)
    if not Path("/usr/sbin/useradd").exists() or not Path("/usr/bin/apt-get").exists():
        raise RuntimeError("expected Ubuntu operator tools missing")
    # Java 21 is supported by official Keycloak. Do not upgrade other packages.
    call(["/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
          "openjdk-21-jre-headless"], timeout=300)
    java = call(["/usr/bin/java", "-version"]).stderr
    if '21.' not in java:
        raise RuntimeError("OpenJDK 21 verification failed")
    call(["/usr/sbin/useradd", "--system", "--user-group",
          "--home-dir", "/var/lib/omnilyzer-keycloak",
          "--shell", "/usr/sbin/nologin", SERVICE_USER])
    account = pwd.getpwnam(SERVICE_USER)
    RELEASE.parent.mkdir(parents=True, exist_ok=True)
    RELEASE.parent.chmod(0o755)
    # Unpack vetted archive into a root-owned temporary directory; rename once.
    import io
    temp = Path(tempfile.mkdtemp(prefix=".keycloak-install-", dir=RELEASE.parent))
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as f:
            f.extractall(temp, filter="data")
        extracted = temp / ("keycloak-" + VERSION)
        if not (extracted / "bin" / "kc.sh").is_file():
            raise RuntimeError("Keycloak distribution missing executable")
        extracted.rename(RELEASE)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
    data = RELEASE / "data"
    data.mkdir(mode=0o700, exist_ok=True)
    os.chown(data, account.pw_uid, account.pw_gid)
    data.chmod(0o700)
    CURRENT.symlink_to(RELEASE, target_is_directory=True)
    # Independent production database; never use Analytics or Sumlaude roles.
    password = secrets.token_urlsafe(48)
    admin_password = secrets.token_urlsafe(48)
    sql_role = ("CREATE ROLE " + ROLE +
                " LOGIN PASSWORD '" + password +
                "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;")
    call(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql",
          "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], input_text=sql_role)
    call(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql",
          "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", "postgres"],
         input_text="CREATE DATABASE " + DB + " OWNER " + ROLE + ";")
    # The root-only environment file is consumed by systemd, not served over HTTP.
    ENV.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    environment = {
        "KC_DB": "postgres",
        "KC_DB_URL": "jdbc:postgresql://127.0.0.1:5432/" + DB,
        "KC_DB_USERNAME": ROLE,
        "KC_DB_PASSWORD": password,
        "KC_HTTP_ENABLED": "true",
        "KC_HTTP_HOST": "127.0.0.1",
        "KC_HTTP_PORT": str(PORT),
        "KC_HOSTNAME": "https://" + PUBLIC_HOST,
        "KC_HOSTNAME_STRICT": "true",
        "KC_PROXY_HEADERS": "xforwarded",
        "KC_PROXY_TRUSTED_ADDRESSES": "127.0.0.1",
        "KC_HEALTH_ENABLED": "true",
        "KC_METRICS_ENABLED": "false",
        "KC_DB_POOL_MAX_SIZE": "10",
        "KC_BOOTSTRAP_ADMIN_USERNAME": "identity-owner-bootstrap",
        "KC_BOOTSTRAP_ADMIN_PASSWORD": admin_password,
        "JAVA_OPTS_KC_HEAP": "-Xms128m -Xmx768m",
    }
    # All values use controlled alphanumeric / base64url syntax.
    if any(not re.fullmatch(r"[A-Za-z0-9_.:/=+ -]+", x) for x in environment.values()):
        raise RuntimeError("generated environment contains unsafe delimiter")
    file_descriptor = os.open(ENV, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
        file.write("".join(k + "=" + v + "\n" for k, v in environment.items()))
    # Build the optimized server before launching a least-privilege service.
    build_env = dict(os.environ)
    build_env.update({"KC_DB": "postgres", "KC_HTTP_ENABLED": "true",
                      "KC_HEALTH_ENABLED": "true"})
    call([str(RELEASE / "bin/kc.sh"), "build"], environ=build_env, timeout=240)
    unit_text = service_unit()
    unit_fd = os.open(UNIT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(unit_fd, "w", encoding="utf-8") as f:
        f.write(unit_text)
    call(["/usr/bin/systemctl", "daemon-reload"])
    # Installed, deliberately disabled: public ingress and admin recovery need
    # their own independent acceptance. --start-local starts local backend only.
    print("M01_KEYCLOAK_PRODUCTION_NATIVE_INSTALLED_DISABLED; " +
          "secrets_saved_root_only=true public_ingress=false legacy_accounts_untouched=true")


def service_unit():
    """Return the only root-owned systemd service, bound to localhost."""
    return """# File: /etc/systemd/system/omnilyzer-keycloak.service
# Purpose: Dedicated Keycloak 26.8.1 production issuer backend, local-only.
# Related: /etc/omnilyzer/keycloak/keycloak.env, /opt/omnilyzer/keycloak/current
[Unit]
Description=Omnilyzer native Keycloak OIDC issuer (production localhost)
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service
[Service]
Type=simple
User=omnilyzer-keycloak
Group=omnilyzer-keycloak
WorkingDirectory=/opt/omnilyzer/keycloak/current
EnvironmentFile=/etc/omnilyzer/keycloak/keycloak.env
ExecStart=/opt/omnilyzer/keycloak/current/bin/kc.sh start --optimized
Restart=on-failure
RestartSec=15
TimeoutStartSec=180
LimitNOFILE=10240
MemoryMax=1536M
TasksMax=512
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/omnilyzer/keycloak/releases/26.8.1/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
[Install]
WantedBy=multi-user.target
"""


# Section: Repair only the observed optimized-build mismatch, never reinstall.
def metrics_repair_plan():
    """Verify one installed/stopped provider and its exact root-owned boundaries.

    Do not read, print, or alter any password values as a part of diagnosis.
    Report all independently detected mismatches before permitting a repair.
    """
    import zipfile
    problems = []
    if os.geteuid() != 0:
        problems.append("owner-root authorization required")
    if socket.gethostname().split(".")[0] != "truexmainserver":
        problems.append("unexpected hostname")
    try:
        status = call(["/usr/bin/systemctl", "show", "omnilyzer-keycloak.service",
                       "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
                       "--no-pager"]).stdout
        for required in ("ActiveState=inactive", "SubState=dead",
                         "UnitFileState=disabled"):
            if required not in status.splitlines():
                problems.append("service must remain stopped and disabled: " + required)
    except subprocess.SubprocessError:
        problems.append("cannot verify service state")
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", PORT))
        except OSError:
            problems.append("Keycloak private port is already occupied")
    if not CURRENT.is_symlink() or CURRENT.resolve() != RELEASE or not RELEASE.is_dir():
        problems.append("Keycloak release layout differs from approved installation")
    try:
        user = pwd.getpwnam(SERVICE_USER)
        directory = ENV.parent.stat()
        if (directory.st_uid != 0 or
                stat.S_IMODE(directory.st_mode) != 0o700):
            problems.append("secret directory ownership or permissions changed")
        metadata = ENV.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
                metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            problems.append("secret file must be regular root-owned 0600")
        if user.pw_uid == 0:
            problems.append("Keycloak must not run as root")
        raw = ENV.read_bytes() if "secret file must be regular root-owned 0600" not in problems else b""
        if raw.count(b"KC_METRICS_ENABLED=false\\n") != 1:
            problems.append("metrics line not the single expected false value")
        installed_unit = UNIT.read_text(encoding="utf-8")
        if installed_unit != service_unit():
            problems.append("installed unit differs from reviewed exact original")
        jar = RELEASE / "lib" / "quarkus" / "generated-bytecode.jar"
        with zipfile.ZipFile(jar) as archive:
            persisted = archive.read("META-INF/keycloak-persisted.properties")
        keys = persisted.splitlines()
        for required in (b"kc.db=postgres", b"kc.health-enabled=true"):
            if required not in keys:
                problems.append("approved optimized build is missing " + required.decode())
        if any(line.startswith(b"kc.metrics-enabled=") for line in keys):
            problems.append("optimized build already defines a metrics value")
        if any((ENV.parent / name).exists() for name in
               ("keycloak.env.m01-pre-metrics-repair",
                "omnilyzer-keycloak.service.m01-pre-metrics-repair")):
            problems.append("prior repair backup exists; do not repeat")
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        problems.append("cannot verify installed identity content: " +
                        type(exc).__name__)
    return problems


def prepare_metrics_repair():
    """Read-only root preflight: list every issue without starting services."""
    problems = metrics_repair_plan()
    print("M01_KEYCLOAK_METRICS_REPAIR_" +
          ("HOLD " + "; ".join(problems) if problems else
           "PREFLIGHT_PASS installed_unit_exact=true persisted_metrics_absent=true"))
    if problems:
        raise RuntimeError("metrics repair preflight failed")


def write_file_exclusive(path, payload, mode):
    """Write one root-owned backup without replacing an existing pathname."""
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def replace_file_atomic(path, payload, mode):
    """Replace one already-validated root file by same-filesystem atomic rename."""
    descriptor, temporary = tempfile.mkstemp(prefix=".m01-metrics-", dir=str(path.parent))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def repair_metrics_only():
    """Remove one runtime-only build mismatch and disable restart loops.

    Preserve existing production database, hostname, administrator and all
    other secrets. Keep root-only backups and do NOT start Keycloak or publish
    DNS/TLS. The owner separately reviews and starts the corrected service.
    """
    prepare_metrics_repair()
    before = ENV.read_bytes()
    original_unit = UNIT.read_bytes()
    updated = before.replace(b"KC_METRICS_ENABLED=false\\n", b"")
    if len(updated) >= len(before):
        raise RuntimeError("metrics value did not match exact expected line")
    restricted_unit = original_unit.replace(
        b"Restart=on-failure\\n", b"Restart=no\\n")
    if restricted_unit == original_unit:
        raise RuntimeError("existing restart policy differs from approved original")
    write_file_exclusive(ENV.parent / "keycloak.env.m01-pre-metrics-repair",
                         before, 0o600)
    write_file_exclusive(ENV.parent / "omnilyzer-keycloak.service.m01-pre-metrics-repair",
                         original_unit, 0o600)
    replace_file_atomic(ENV, updated, 0o600)
    replace_file_atomic(UNIT, restricted_unit, 0o644)
    call(["/usr/bin/systemctl", "daemon-reload"])
    print("M01_KEYCLOAK_METRICS_REPAIR_PASS " +
          "one_build_setting_removed=true service_restart_disabled=true " +
          "secrets_preserved=true backups_root_only=true no_service_start=true")


# Section: Explicit, separate activation of *only* the local Keycloak service.
def start_local():
    """Start only the preinstalled unit; never touch Nginx/DNS or other services."""
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != "truexmainserver":
        raise RuntimeError("owner-root on exact public host required")
    if not (UNIT.is_file() and ENV.is_file() and RELEASE.is_dir() and CURRENT.is_symlink()):
        raise RuntimeError("missing reviewed production installation")
    if CURRENT.resolve() != RELEASE or stat.S_IMODE(ENV.stat().st_mode) != 0o600:
        raise RuntimeError("identity source or secret permissions unexpected")
    call(["/usr/bin/systemctl", "start", "omnilyzer-keycloak.service"], timeout=170)
    url = "http://127.0.0.1:" + str(PORT) + "/realms/master/.well-known/openid-configuration"
    import time
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=3) as response:
                data = json.loads(response.read(1048576))
                if response.status == 200 and data.get("issuer") == "https://" + PUBLIC_HOST + "/realms/master":
                    print("M01_KEYCLOAK_PUBLIC_HOST_BACKEND_LOCAL_PASS " +
                          "issuer=https://" + PUBLIC_HOST + "/realms/master external_ingress=false")
                    return
        except (OSError, ValueError):
            time.sleep(2)
    raise RuntimeError("Keycloak local OIDC not verified; inspect service before public DNS")


def main(argv=None):
    """Choose read-only preflight, privileged offline installation or local start."""
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "install", "start-local", "repair-preflight", "repair-metrics"))
    args = parser.parse_args(argv)
    if args.action == "preflight":
        problems = preflight()
        print("M01_KEYCLOAK_PRODUCTION_PREFLIGHT_" + ("HOLD: " + "; ".join(problems)
              if problems else "PASS"))
        if problems:
            sys.exit(2)
    elif args.action == "install":
        install()
    elif args.action == "repair-preflight":
        prepare_metrics_repair()
    elif args.action == "repair-metrics":
        repair_metrics_only()
    else:
        start_local()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        # Never put raw subprocess stderr or env secrets in the operator log.
        print("M01_KEYCLOAK_PRODUCTION_HOLD " + type(exc).__name__ + ": " +
              (str(exc) if isinstance(exc, RuntimeError) else "operation did not complete"),
              file=sys.stderr)
        sys.exit(2)

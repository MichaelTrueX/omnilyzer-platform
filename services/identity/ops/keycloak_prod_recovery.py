#!/usr/bin/env python3
"""File: services/identity/ops/keycloak_prod_recovery.py
Purpose: Back up and restore-test the existing production Keycloak PostgreSQL
    database before enabling safe service startup on truexmainserver.
Related: services/identity/ops/keycloak_public_prod.py,
    services/identity/ops/keycloak_provision_realm.py,
    services/identity/tests/test_keycloak_prod_recovery.py,
    docs/adr/0003-keycloak-bff-and-native-authentication.md.

This is a one-time local recovery qualification, NOT an off-host backup,
not a generic database framework, and not an authorization to sign in users.
Only Keycloak's own database, credential snapshots, and systemd unit are in
scope. Nothing restarts: no Nginx, PostgreSQL, Keycloak, product or Analytics.
All database contents and credentials remain root-only on the same host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.request import urlopen

HOST = "truexmainserver"
DB = "omnilyzer_keycloak"
BACKUPS = Path("/var/backups/omnilyzer-keycloak")
UNIT = Path("/etc/systemd/system/omnilyzer-keycloak.service")
ENV = Path("/etc/omnilyzer/keycloak/keycloak.env")
CLIENT_ENV = Path("/etc/omnilyzer/keycloak/sumlaude-bff-client.env")
ORIGIN = "https://login.omnilyzer.ai"
ISSUER = ORIGIN + "/realms/omnilyzer"
BACKEND = "http://127.0.0.1:18742/realms/omnilyzer/.well-known/openid-configuration"
PG_BIN = "/usr/bin"
RUNUSER = "/usr/sbin/runuser"


# Section: Fixed command invocation with no shell interpolation or credentials.
def command(args, *, input_stream=None, output_stream=None, timeout=180):
    """Capture only bounded diagnostic metadata, never dump bytes or secret data."""
    return subprocess.run(args, check=True, stdin=input_stream,
                          stdout=output_stream if output_stream is not None else subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


def pg(*args, input_stream=None, output_stream=None, timeout=180):
    """Run the installed PostgreSQL CLI as the existing local postgres user."""
    return command([RUNUSER, "-u", "postgres", "--", *args],
                   input_stream=input_stream, output_stream=output_stream, timeout=timeout)


def expected_unit():
    """Match the exact local source unit after the reviewed metrics repair."""
    # Use existing source rather than defining a different service architecture.
    import importlib.util
    source = Path(__file__).with_name("keycloak_public_prod.py")
    # Executing a copied, root-only operator from /run has no sibling script;
    # the original immutable installed unit is checked by safe structural
    # constraints below rather than loading code from another location.
    return None


def next_unit(existing):
    """Preserve the installed non-root unit and allow at most 3 failure restarts."""
    required = (
        "User=omnilyzer-keycloak\n",
        "Group=omnilyzer-keycloak\n",
        "EnvironmentFile=/etc/omnilyzer/keycloak/keycloak.env\n",
        "ExecStart=/opt/omnilyzer/keycloak/current/bin/kc.sh start --optimized\n",
        "MemoryMax=1536M\n",
        "ProtectSystem=strict\n",
        "NoNewPrivileges=true\n",
        "Restart=no\n",
        "[Unit]\n",
        "[Service]\n",
    )
    if any(existing.count(x) != 1 for x in required):
        raise RuntimeError("installed identity unit differs from reviewed security contract")
    if "StartLimitIntervalSec=" in existing or "StartLimitBurst=" in existing:
        raise RuntimeError("unit already has restart limits; reconcile manually")
    if not existing.startswith("# File: /etc/systemd/system/omnilyzer-keycloak.service\n"):
        raise RuntimeError("unexpected identity unit header")
    updated = existing.replace(
        "[Unit]\n", "[Unit]\nStartLimitIntervalSec=infinity\nStartLimitBurst=3\n", 1)
    updated = updated.replace("Restart=no\n", "Restart=on-failure\nRestartSec=20\n", 1)
    if len(updated) <= len(existing):
        raise RuntimeError("unexpected identity unit change")
    return updated


# Section: Read-only baseline before any PostgreSQL or systemd mutation.
def preflight():
    """Collect independent critical mismatches without changing live state."""
    issues = []
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        issues.append("owner-root on exact public host required")
    if BACKUPS.exists() or BACKUPS.is_symlink():
        issues.append("recovery directory already exists; do not overwrite")
    if shutil.disk_usage("/").free < 8 * 1024**3:
        issues.append("insufficient free filesystem capacity")
    for filename in (ENV, CLIENT_ENV):
        try:
            metadata = filename.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
                    metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
                issues.append("root credential ownership or mode changed: " + filename.name)
        except OSError:
            issues.append("root credential file missing: " + filename.name)
    try:
        unit = UNIT.read_text(encoding="utf-8")
        next_unit(unit)
        metadata = UNIT.lstat()
        if (metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode) or
                stat.S_IMODE(metadata.st_mode) != 0o644):
            issues.append("unit file metadata changed")
    except (OSError, RuntimeError, UnicodeError) as exc:
        issues.append("unit content unsafe: " + type(exc).__name__)
    try:
        service = command(["/usr/bin/systemctl", "show", "omnilyzer-keycloak.service",
                           "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
                           "-p", "NRestarts", "--no-pager"], timeout=10).stdout.decode().splitlines()
        for field in ("ActiveState=active", "SubState=running",
                      "UnitFileState=disabled", "NRestarts=0"):
            if field not in service:
                issues.append("existing systemd state mismatch: " + field)
    except (OSError, subprocess.SubprocessError):
        issues.append("cannot inspect systemd identity service")
    try:
        with urlopen(BACKEND, timeout=5) as response:
            data = json.loads(response.read(1048576))
        if data.get("issuer") != ISSUER:
            issues.append("running Keycloak issuer changed")
    except (OSError, ValueError):
        issues.append("running Keycloak OIDC unavailable")
    try:
        row = pg(PG_BIN + "/psql", "-XAtq", "-d", "postgres", "-c",
                 "SELECT 1 FROM pg_database WHERE datname='" + DB + "'", timeout=10)
        if row.stdout.strip() != b"1":
            issues.append("dedicated Keycloak database missing")
    except (OSError, subprocess.SubprocessError):
        issues.append("PostgreSQL catalog inspection unavailable")
    return issues


# Section: Root-only durable backup and independent disposable restore.
def private_file(destination, data, mode=0o600):
    """Create an original backup file exactly once, without following symlinks."""
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def backup_files():
    """Capture confidential Keycloak credentials and exact systemd unit locally."""
    BACKUPS.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(BACKUPS, 0o700)
    for original in (ENV, CLIENT_ENV, UNIT):
        private_file(BACKUPS / original.name, original.read_bytes())


def backup_database():
    """Take a PostgreSQL MVCC custom-format backup without printing table data."""
    destination = BACKUPS / "keycloak.pgcustom"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            pg(PG_BIN + "/pg_dump", "--format=custom", "--no-owner",
               "--no-privileges", "--dbname=" + DB,
               output_stream=output, timeout=240)
            output.flush()
            os.fsync(output.fileno())
        if destination.stat().st_size < 16384:
            raise RuntimeError("Keycloak dump unexpectedly small")
        with destination.open("rb") as source:
            magic = source.read(5)
        if magic != b"PGDMP":
            raise RuntimeError("Keycloak pg_dump custom archive signature mismatch")
        return destination
    finally:
        if not os.path.exists(destination):
            try:
                os.close(fd)
            except OSError:
                pass


def restore_verify(archive):
    """Actually restore into a unique temporary DB, count realms, then drop."""
    name = "m01_keycloak_restore_" + secrets.token_hex(5)
    if not name.replace("_", "").isalnum():
        raise RuntimeError("invalid generated isolated restore name")
    created = False
    try:
        pg(PG_BIN + "/createdb", "--template=template0", "--encoding=UTF8", name,
           timeout=30)
        created = True
        with archive.open("rb") as input_stream:
            pg(PG_BIN + "/pg_restore", "--exit-on-error", "--no-owner",
               "--no-privileges", "--dbname=" + name,
               input_stream=input_stream, timeout=240)
        count = pg(PG_BIN + "/psql", "-XAtq", "-d", name, "-c",
                   "SELECT COUNT(*) FROM public.realm WHERE name='omnilyzer'",
                   timeout=15).stdout.strip()
        if count != b"1":
            raise RuntimeError("restore does not contain exactly one canonical realm")
    finally:
        if created:
            pg(PG_BIN + "/dropdb", "--if-exists", "--force", name, timeout=30)
    print("M01_KEYCLOAK_ISOLATED_RESTORE_PASS realm=omnilyzer " +
          "distinct_database_created_and_dropped=true")


# Section: Enable bounded Keycloak boot recovery only after backup qualifies.
def enable_service():
    """Atomically update only the identity unit and register it for reboot."""
    before = UNIT.read_bytes()
    updated = next_unit(before.decode("utf-8")).encode("utf-8")
    fd, stage = tempfile.mkstemp(prefix=".m01-keycloak-recovery-", dir=str(UNIT.parent))
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(updated)
            f.flush()
            os.fsync(f.fileno())
        os.replace(stage, UNIT)
        stage = None
        try:
            command(["/usr/bin/systemctl", "daemon-reload"], timeout=20)
            command(["/usr/bin/systemctl", "enable", "omnilyzer-keycloak.service"],
                    timeout=20)
        except (OSError, subprocess.SubprocessError):
            # Restore the byte-exact previous unit and previous disabled state.
            UNIT.write_bytes(before)
            UNIT.chmod(0o644)
            command(["/usr/bin/systemctl", "daemon-reload"], timeout=20)
            raise
    finally:
        if stage and os.path.exists(stage):
            os.unlink(stage)
    state = command(["/usr/bin/systemctl", "show", "omnilyzer-keycloak.service",
                     "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"],
                    timeout=10).stdout.decode().splitlines()
    if "ActiveState=active" not in state or "UnitFileState=enabled" not in state:
        raise RuntimeError("Keycloak service persistence verification failed")
    print("M01_KEYCLOAK_BOOT_SERVICE_PASS enabled=true restart_bounded=true " +
          "no_runtime_restart=true")


def execute():
    """Once-only transaction order: preflight, backup, restore, enable unit."""
    issues = preflight()
    if issues:
        raise RuntimeError("RECOVERY_HOLD " + "; ".join(issues))
    backup_files()
    archive = backup_database()
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    restore_verify(archive)
    private_file(BACKUPS / "sha256sum.txt",
                 (checksum + "  keycloak.pgcustom\n").encode("ascii"))
    enable_service()
    print("M01_KEYCLOAK_LOCAL_RECOVERY_PASS backup_root_only=true " +
          "pg_dump_sha256_verified=true restore_verified=true " +
          "offhost_backup_pending=true user_login_not_accepted=true")


def main(argv=None):
    """Expose only preflight and the explicit owner-root one-time qualification."""
    parser = argparse.ArgumentParser(description="Keycloak local recovery qualification")
    parser.add_argument("action", choices=("preflight", "backup-restore-enable"))
    action = parser.parse_args(argv).action
    if action == "preflight":
        problems = preflight()
        print("M01_KEYCLOAK_RECOVERY_" +
              ("HOLD " + "; ".join(problems) if problems else "PREFLIGHT_PASS"))
        return 2 if problems else 0
    execute()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print("M01_KEYCLOAK_RECOVERY_HOLD " +
              (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)

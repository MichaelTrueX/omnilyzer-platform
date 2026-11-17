#!/usr/bin/env python3
"""File: deployment/analytics_prod_db_install.py

Purpose: One-shot, explicitly reviewed first-install of the NEW isolated
         Analytics PostgreSQL16 database on existing truexmainserver.
Related: deployment/analytics_prod_sql_admission.py,
         deployment/analytics_dev_bootstrap.py,
         deployment/runtime/prod/analytics.compose.private.yaml,
         docs/operations/analytics-prod-first-install.md.

Sections: exact source/context preflight, protected one-shot marker, new DB,
          reviewed SQL migration sequence, restricted credentials, narrow
          HBA SCRAM admission, RLS verification and metadata-only inspection.
No Docker, Nginx, PM2, Keycloak, existing-DB or public-route operations.
Do not execute --apply before source review and separately recorded PROD GO.
An interrupted install is HOLD: never rerun --apply or auto-drop the DB.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import secrets
import socket
import stat
import subprocess
import sys
from urllib.parse import quote

HOST = "truexmainserver"
ROOTLESS_USER = "omnilyzer-analytics"
ROOTLESS_UID = 990
ROOTLESS_GID = 982
MAPPED_UID = 241072
MAPPED_GID = 241072
DB = "omnilyzer_analytics_prod"
PRIVATE = Path("/var/lib/omnilyzer/analytics/prod")
SQL_DIR = PRIVATE / "sql"
SECRETS = PRIVATE / "secrets"
STATE = PRIVATE / "database-install-started-v1.json"
HBA = Path("/etc/postgresql/16/main/pg_hba.conf")
HBA_ORIGINAL = PRIVATE / "pg-hba-original-v1"
HBA_EXPECTED = "0709ada1b9a61908ceb70255346b83da131f37a5758b39820ced1f2b23b8f01c"
GATE = Path(__file__).with_name("analytics_prod_sql_admission.py")
# SHA must be updated to exactly the independently reviewed, installed
# admission source at the final release boundary, not an editable file.
GATE_SHA256 = "883b8a7eb029abe2c7ca6f768ff0ef6955633c3ee88e2a487e1e368f5a2d5504"
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/var/lib/postgresql",
    "LC_ALL": "C",
    "PGCONNECT_TIMEOUT": "3",
    "PGAPPNAME": "omnilyzer-analytics-prod-db-install",
}
PSQL = (
    "/usr/sbin/runuser", "-u", "postgres", "--",
    "/usr/bin/psql", "-X", "-w", "-q", "-A", "-t",
    "-P", "pager=off", "-h", "/var/run/postgresql",
    "-v", "ON_ERROR_STOP=1",
)
SQL_NAMES = (
    "analytics-pr52-base-schema-20261030.sql",
    "multiwebsite-expand-backfill.sql",
    "rls--m01-runtime.install.sql",
    "rls--analytics-app-workspace.install.sql",
    "rls--analytics-app-events.install.sql",
)
SECRET_NAMES = ("DATABASE_URL", "COLLECTOR_DATABASE_URL", "JWT_SECRET", "JWT_REFRESH_SECRET")
HBA_INSERT = (
    b"local   omnilyzer_analytics_prod omni_runtime scram-sha-256\n"
    b"local   omnilyzer_analytics_prod collector_runtime scram-sha-256\n"
)
HBA_NEEDLE = b"local   all             all                                     peer\n"


class InstallHold(RuntimeError):
    """Stop on changed identity, source, partial state or database gate."""


def assert_file(path: Path, *, uid: int, gid: int, mode: int) -> bytes:
    """Accept only an owned single-link regular file, with no symlinks."""
    try:
        item = os.lstat(path)
        if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                or item.st_uid != uid or item.st_gid != gid
                or stat.S_IMODE(item.st_mode) != mode):
            raise InstallHold("installed source/file metadata differs")
        return path.read_bytes()
    except OSError:
        raise InstallHold("required immutable file unavailable") from None


def gate_module():
    """Load only the root-owned reviewed gate from the exact fixed path."""
    if not GATE_SHA256:
        raise InstallHold("missing reviewed gate source digest")
    data = assert_file(GATE, uid=0, gid=0, mode=0o500)
    if hashlib.sha256(data).hexdigest() != GATE_SHA256:
        raise InstallHold("installed source gate digest differs")
    spec = importlib.util.spec_from_file_location("analytics_prod_sql_admission", GATE)
    if spec is None or spec.loader is None:
        raise InstallHold("source gate unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv: tuple[str, ...], *, input_data: bytes | None = None, timeout: int = 60) -> bytes:
    """Use fixed argv and sanitized env; never reveal SQL credentials or secrets."""
    try:
        result = subprocess.run(
            argv, input=input_data, capture_output=True, stdin=subprocess.DEVNULL
            if input_data is None else None, env=ENV, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise InstallHold("fixed PostgreSQL action unavailable") from None
    if result.returncode:
        raise InstallHold("fixed PostgreSQL action rejected; do not retry") 
    return result.stdout


def psql(database: str, sql: bytes, *, timeout: int = 90) -> bytes:
    """Run exact SQL bytes through stdin, never as a command-line secret."""
    return run((*PSQL, "-d", database), input_data=sql, timeout=timeout)


def check_context() -> None:
    """Refuse installation outside the one actual PROD host and OS identity."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split(".")[0] != HOST
            or platform.machine() != "x86_64"):
        raise InstallHold("root on exact PROD host required")
    try:
        rootless = pwd.getpwnam(ROOTLESS_USER)
        if rootless.pw_uid != ROOTLESS_UID or rootless.pw_gid != ROOTLESS_GID:
            raise InstallHold("dedicated rootless service identity changed")
    except KeyError:
        raise InstallHold("rootless service identity absent") from None


def directory(path: Path, uid: int, gid: int, mode: int) -> None:
    """Require an existing trusted private directory before any mutation."""
    try:
        item = os.lstat(path)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != uid
                or item.st_gid != gid or stat.S_IMODE(item.st_mode) != mode):
            raise InstallHold("protected directory differs")
    except OSError:
        raise InstallHold("protected directory unavailable") from None


def preflight() -> object:
    """Prove complete accepted SQL, HBA, absent target DB/roles and empty targets."""
    check_context()
    directory(PRIVATE, 0, ROOTLESS_GID, 0o710)
    if any(os.path.lexists(p) for p in (STATE, HBA_ORIGINAL, SECRETS)):
        raise InstallHold("prior DB installation attempt or secret custody exists")
    gate = gate_module()
    gate.prod_preflight()
    if tuple(name for name, _ in gate.SQL) != SQL_NAMES:
        raise InstallHold("SQL sequence differs from reviewed DEV install")
    if not isinstance(gate.HBA_SHA256, str) or gate.HBA_SHA256 != HBA_EXPECTED:
        raise InstallHold("production HBA baseline differs")
    print("ANALYTICS_PROD_DB_READONLY_PREFLIGHT_PASS no_changes=true", flush=True)
    return gate


def new_file(path: Path, content: bytes, *, uid: int, gid: int, mode: int) -> None:
    """Publish one new inode only, protect ownership and persist bytes."""
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def start_marker() -> None:
    """Write the durable no-retry marker BEFORE the first PostgreSQL change."""
    data = json.dumps({
        "scope": "analytics-prod-new-db-first-install",
        "target_db": DB,
        "phase": "started-no-automatic-retry",
        "source_gate_sha256": GATE_SHA256,
    }, sort_keys=True).encode("ascii") + b"\n"
    new_file(STATE, data, uid=0, gid=0, mode=0o600)


def execute_sql(gate: object) -> None:
    """Create only the target DB and apply all five previously accepted SQL files."""
    run(("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/createdb",
         "-h", "/var/run/postgresql", "-O", "postgres", "-E", "UTF8",
         "-T", "template0", DB), timeout=40)
    for name in SQL_NAMES:
        source = gate.exact_file(SQL_DIR / name, uid=0, mode=0o400, max_bytes=65536)
        psql(DB, source, timeout=120)
        print(f"ANALYTICS_PROD_DB_SQL_APPLIED {name}", flush=True)


def generate_credentials() -> dict[str, bytes]:
    """Generate new production-only secrets in memory, never from DEV."""
    passwords = {name: secrets.token_urlsafe(48) for name in
                 ("omni_runtime", "collector_runtime", "JWT_SECRET", "JWT_REFRESH_SECRET")}
    for name in ("omni_runtime", "collector_runtime"):
        token = passwords[name]
        if not token.replace("-", "").replace("_", "").isalnum():
            raise InstallHold("unexpected generated secret")
        psql(DB, f"ALTER ROLE {name} LOGIN PASSWORD '{token}';\n".encode("ascii"))
    host = "localhost:5432"
    def url(role: str) -> str:
        return (f"postgresql://{role}:{quote(passwords[role], safe='')}@{host}/{DB}"
                "?host=/var/run/postgresql&schema=public")
    return {
        "DATABASE_URL": f"DATABASE_URL={url('omni_runtime')}\n".encode("ascii"),
        "COLLECTOR_DATABASE_URL": f"COLLECTOR_DATABASE_URL={url('collector_runtime')}\n".encode("ascii"),
        "JWT_SECRET": f"JWT_SECRET={passwords['JWT_SECRET']}\n".encode("ascii"),
        "JWT_REFRESH_SECRET": f"JWT_REFRESH_SECRET={passwords['JWT_REFRESH_SECRET']}\n".encode("ascii"),
    }


def seal_secrets(contents: dict[str, bytes]) -> None:
    """Create only four mapped-UID private Compose secret files."""
    if set(contents) != set(SECRET_NAMES):
        raise InstallHold("incomplete production secret set")
    os.mkdir(SECRETS, mode=0o710)
    os.chown(SECRETS, 0, ROOTLESS_GID)
    os.chmod(SECRETS, 0o710)
    for name in SECRET_NAMES:
        data = contents[name]
        if not data.startswith((name + "=").encode()) or len(data) > 8192:
            raise InstallHold("unexpected protected secret format")
        new_file(SECRETS / name, data, uid=MAPPED_UID, gid=MAPPED_GID, mode=0o600)


def install_hba() -> None:
    """Insert only two named DB SCRAM rules ahead of broad local peer rule."""
    postgres = pwd.getpwnam("postgres")
    original = assert_file(HBA, uid=postgres.pw_uid, gid=postgres.pw_gid, mode=0o640)
    if hashlib.sha256(original).hexdigest() != HBA_EXPECTED:
        raise InstallHold("HBA changed since preflight")
    if original.count(HBA_NEEDLE) != 1 or HBA_INSERT in original:
        raise InstallHold("HBA insertion point differs")
    new_file(HBA_ORIGINAL, original, uid=0, gid=0, mode=0o600)
    updated = original.replace(HBA_NEEDLE, HBA_INSERT + HBA_NEEDLE, 1)
    next_file = HBA.with_name(".pg_hba.omnilyzer-analytics-prod-next")
    new_file(next_file, updated, uid=postgres.pw_uid, gid=postgres.pw_gid, mode=0o640)
    os.replace(next_file, HBA)
    run(("/usr/bin/pg_ctlcluster", "16", "main", "reload"), timeout=20)
    evidence = psql("postgres", b"""BEGIN TRANSACTION READ ONLY;
SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL;
COMMIT;
""")
    if evidence.strip() != b"0":
        raise InstallHold("HBA parse-error after reload, preserve state for manual recovery")


def verify_installed() -> None:
    """Require FORCE RLS on five critical tables and all four isolated roles."""
    output = psql(DB, b"""BEGIN TRANSACTION READ ONLY;
SELECT 'RLS|'||count(*) FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public'
AND c.relname IN ('Workspace','Website','WorkspaceMembership',
                  'WorkspaceAnalyticsEvent','WebsiteAnalyticsDaily')
AND c.relrowsecurity AND c.relforcerowsecurity;
SELECT 'ROLES|'||count(*) FROM pg_catalog.pg_roles
WHERE rolname IN ('omni_runtime','collector_runtime','archive_runtime','collector_lock_definer')
AND NOT rolsuper AND NOT rolbypassrls;
COMMIT;
""")
    if output.strip().splitlines() != [b"RLS|5", b"ROLES|4"]:
        raise InstallHold("post-install tenant RLS or role validation failed")


def apply() -> None:
    """Perform one authorized initial installation; on failure preserve partial state."""
    gate = preflight()
    os.umask(0o077)
    start_marker()
    print("ANALYTICS_PROD_DB_FIRST_INSTALL_MARKER_SET no_retry=true", flush=True)
    execute_sql(gate)
    secrets_data = generate_credentials()
    seal_secrets(secrets_data)
    install_hba()
    verify_installed()
    print("ANALYTICS_PROD_DB_PRIVATE_INSTALL_PASS public_routes=unchanged app=not_started",
          flush=True)


def inspect() -> None:
    """Report only fixed metadata, never role passwords or SQL/secret content."""
    check_context()
    print("ANALYTICS_PROD_DB_INSTALL_MARKER=" +
          ("present" if STATE.is_file() else "absent"))
    print("ANALYTICS_PROD_DB_ORIGINAL_HBA=" +
          ("present" if HBA_ORIGINAL.is_file() else "absent"))
    print("ANALYTICS_PROD_DB_SECRETS=" +
          ("present" if SECRETS.is_dir() else "absent"))
    print("ANALYTICS_PROD_DB_INSPECT_READONLY no_changes=true")


def main() -> int:
    """Only fixed command modes, no arbitrary SQL or dynamic destinations."""
    if len(sys.argv) != 2 or sys.argv[1] not in ("--preflight", "--apply", "--inspect"):
        print("ANALYTICS_PROD_DB_INSTALL_HOLD invalid mode", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "--preflight":
            preflight()
        elif sys.argv[1] == "--apply":
            apply()
        else:
            inspect()
    except (InstallHold, OSError, ValueError) as exc:
        print(f"ANALYTICS_PROD_DB_INSTALL_HOLD {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

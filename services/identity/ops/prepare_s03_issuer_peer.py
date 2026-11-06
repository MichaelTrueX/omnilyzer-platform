#!/usr/bin/env python3
"""File: services/identity/ops/prepare_s03_issuer_peer.py
Purpose: Provision ONE PostgreSQL 16 local peer authentication mapping from
  the existing Omnilyzer BFF OS identity to the existing restricted S03
  session-issuer DB role, without passwords, new accounts or broad grants.
Related:
  services/identity/identity_bff/issuer.py,
  services/identity/config/settings.py,
  services/identity/tests/test_prepare_s03_issuer_peer.py,
  SHSLearningStudio/scripts/production/s03-fresh-db-cluster-bootstrap.sql,
  SHSLearningStudio/scripts/production/s03-verified-oidc-session-issuer.sql.candidate.

Actions: preflight (no writes, root for full checks), prepare (root only,
  trusted SHA-pinned copy under /run). No app/Keycloak/login service starts,
  no SQL changes, no credentials, no user admission or public DNS changes.
The operator maintains root-only backups of the two prior PostgreSQL files
and restores them if any config reload or authorization assertion fails.
"""
import argparse
import hashlib
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile


# Section 1: Exact existing host, service, database, role and file boundaries.
HOST = "truexmainserver"
BFF_OS = "omnilyzer-identity"
BFF_OLD = Path(
    "/opt/omnilyzer/identity/releases/d65d14b69d3e5c899ab9291741b9029669244168"
)
BFF_NEW = Path(
    "/opt/omnilyzer/identity/releases/304b5acdc642ec4b26e08867af467e63c1b04c5e"
)
BFF_CURRENT = Path("/opt/omnilyzer/identity/current")
HBA = Path("/etc/postgresql/16/main/pg_hba.conf")
IDENT = Path("/etc/postgresql/16/main/pg_ident.conf")
BACKUP_DIR = Path("/etc/postgresql/16/main/.m01-issuer-peer-backup-20261106")
TRUST_DIR = Path("/run/m01-issuer-peer")
TRUST_FILE = TRUST_DIR / "prepare_s03_issuer_peer.py"
DB = "sumlaude_learning"
PG_ROLE = "sumlaude_identity_issuer"
PEER_MAP = "m01_sumlaude_bff"
HBA_ENTRY = (
    "local    sumlaude_learning    sumlaude_identity_issuer"
    "    peer map=m01_sumlaude_bff\n"
)
IDENT_ENTRY = "m01_sumlaude_bff    omnilyzer-identity    sumlaude_identity_issuer\n"
HBA_EXPECTED_LOCAL = [
    ["local", "all", "postgres", "peer"],
    ["local", "all", "all", "peer"],
    ["local", "replication", "all", "peer"],
]


def hold(message):
    """Fail closed with no file content, password or private SQL disclosed."""
    raise RuntimeError("M01_S03_ISSUER_PEER_HOLD " + message)


def run(argv, *, timeout=12):
    """Execute a bounded fixed binary; never interpolate shell commands."""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            check=False, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        hold("required host operation unavailable")
    return p


def pgsql(sql, *, database="postgres", os_user="postgres"):
    """Read-only SQL query via local OS postgres or restricted peer identity."""
    cmd = [
        "/usr/sbin/runuser", "-u", os_user, "--", "/usr/bin/psql",
        "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
        "-w", "-h", "/var/run/postgresql", "-d", database,
    ]
    if os_user != "postgres":
        cmd.extend(["-U", PG_ROLE])
    cmd.extend(["-c", sql])
    p = run(cmd)
    if p.returncode:
        hold("read-only PostgreSQL verification failed")
    return p.stdout.strip()


def check_service_and_runtime():
    """Verify old current, new inactive artifact and dedicated OS account."""
    if socket.gethostname().split(".")[0] != HOST:
        hold("wrong host")
    if os.geteuid() == 0 and not TRUST_FILE.is_file():
        hold("trusted root-only operator missing")
    if not BFF_CURRENT.is_symlink() or BFF_CURRENT.resolve() != BFF_OLD:
        hold("BFF original current symlink changed")
    if not BFF_NEW.is_dir() or BFF_NEW.is_symlink():
        hold("new inactively installed BFF source absent")
    try:
        os_account = pwd.getpwnam(BFF_OS)
    except KeyError:
        hold("BFF OS account unavailable")
    if os_account.pw_name != BFF_OS:
        hold("BFF OS identity mismatched")
    for service in ("omnilyzer-identity.service", "sumlaude-native.service"):
        state = run([
            "/usr/bin/systemctl", "show", service,
            "-p", "ActiveState", "-p", "UnitFileState", "--no-pager",
        ])
        if state.returncode or "ActiveState=inactive" not in state.stdout.splitlines():
            hold("product service active or unknown")
        if "UnitFileState=disabled" not in state.stdout.splitlines():
            hold("product service enabled or unknown")
    if run(["/usr/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432"]).returncode:
        hold("existing PostgreSQL16 cluster unavailable")


def parse_rules(content):
    """Normalize non-comment rules while preserving raw source bytes."""
    return [re.split(r"\s+", line.split("#", 1)[0].strip())
            for line in content.splitlines()
            if line.split("#", 1)[0].strip()]


def propose_auth_change(hba, ident):
    """Produce the only additive, precisely scoped peer mapping.

    The existing three default local rules must be EXACT. Keep all host rules,
    replication, trust boundaries and other ident mappings byte-for-byte.
    """
    if "\x00" in hba or "\x00" in ident or "\r" in hba or "\r" in ident:
        hold("unexpected PostgreSQL configuration encoding")
    if not hba.endswith("\n") or (ident and not ident.endswith("\n")):
        hold("missing final PostgreSQL config newline")
    local = [line for line in parse_rules(hba) if line[0] == "local"]
    if local != HBA_EXPECTED_LOCAL:
        hold("existing PostgreSQL local auth rules differ from approved peer-only baseline")
    ident_rules = parse_rules(ident)
    if any(line[0] == PEER_MAP or (len(line) >= 3 and line[2] == PG_ROLE)
           for line in ident_rules):
        hold("an issuer peer map already exists, do not overwrite")
    if any("m01_sumlaude_bff" in line for line in hba.splitlines()):
        hold("HBA mapping already exists, no duplicate insert")
    old_lines = hba.splitlines(keepends=True)
    idx = None
    for i, line in enumerate(old_lines):
        tokens = re.split(r"\s+", line.split("#", 1)[0].strip())
        if tokens == ["local", "all", "all", "peer"]:
            idx = i
            break
    if idx is None:
        hold("default peer rule insertion point absent")
    old_lines.insert(idx, HBA_ENTRY)
    new_hba = "".join(old_lines)
    new_ident = ident + IDENT_ENTRY
    if (new_hba.replace(HBA_ENTRY, "", 1) != hba or
            new_ident.removesuffix(IDENT_ENTRY) != ident):
        hold("file preservation assertion failed")
    return new_hba, new_ident


def approved_file(path):
    """Read one expected root-only-administrable postgres-owned config."""
    if path.is_symlink():
        hold("PostgreSQL configuration symlink denied")
    info = path.lstat()
    postgres = pwd.getpwnam("postgres")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != postgres.pw_uid
            or info.st_gid != postgres.pw_gid
            or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1):
        hold("PostgreSQL configuration file owner/mode changed")
    return path.read_bytes()


def check_role_authority():
    """Validate current role/function privileges without viewing any learners."""
    check = pgsql(
        "SELECT "
        "(SELECT current_setting('server_version_num')::int BETWEEN 160000 AND 169999)::int,"
        "(SELECT rolcanlogin::int FROM pg_roles WHERE rolname='" + PG_ROLE + "'),"
        "(SELECT rolpassword IS NULL FROM pg_authid WHERE rolname='" + PG_ROLE + "')::int,"
        "(SELECT rolinherit::int FROM pg_roles WHERE rolname='" + PG_ROLE + "'),"
        "(SELECT rolsuper::int FROM pg_roles WHERE rolname='" + PG_ROLE + "'),"
        "(SELECT count(*) FROM pg_roles WHERE rolname='" + PG_ROLE + "');"
    )
    if check != "1|1|1|0|0|1":
        hold("issuer role login/no-password/isolation mismatch")
    sql = (
        "SELECT "
        "has_database_privilege('" + PG_ROLE + "', current_database(), 'CONNECT')::int,"
        "has_function_privilege('" + PG_ROLE + "',"
        "'sumlaude_auth.issue_admitted_oidc_session(text,text,bytea,timestamptz)',"
        "'EXECUTE')::int,"
        "has_function_privilege('" + PG_ROLE + "',"
        "'sumlaude_auth.revoke_issued_oidc_session(bytea)',"
        "'EXECUTE')::int,"
        "has_table_privilege('" + PG_ROLE + "', 'public.users', 'SELECT')::int,"
        "has_table_privilege('" + PG_ROLE + "', 'sumlaude_private.learner_admission',"
        "'SELECT')::int;"
    )
    if pgsql(sql, database=DB) != "1|1|1|0|0":
        hold("restricted S03 issuer grant/denial assertions failed")


def protected_root_operator():
    """Only exact root-owned 0500 code under new private /run can modify."""
    if os.geteuid() != 0:
        hold("root privileges required")
    root_dir = TRUST_DIR.lstat()
    operator = TRUST_FILE.lstat()
    if (Path(__file__).absolute() != TRUST_FILE
            or not stat.S_ISDIR(root_dir.st_mode)
            or root_dir.st_uid != 0
            or stat.S_IMODE(root_dir.st_mode) != 0o700
            or not stat.S_ISREG(operator.st_mode)
            or operator.st_uid != 0
            or operator.st_nlink != 1
            or stat.S_IMODE(operator.st_mode) != 0o500):
        hold("root-owned /run operator custody invalid")


def snapshot_preflight():
    """Return checked original bytes and exact proposals before any writes."""
    check_service_and_runtime()
    protected_root_operator()
    if not run(["/usr/bin/pg_lsclusters", "-h"]).stdout.startswith("16 main 5432 online "):
        hold("unexpected PostgreSQL16 cluster configuration")
    original = (approved_file(HBA), approved_file(IDENT))
    try:
        candidate = propose_auth_change(*(x.decode("utf-8") for x in original))
    except UnicodeError:
        hold("PostgreSQL config is not UTF8")
    check_role_authority()
    for path in (HBA, IDENT):
        if (BACKUP_DIR / path.name).exists() or (BACKUP_DIR / path.name).is_symlink():
            hold("prior backup already exists")
    if BACKUP_DIR.exists() or BACKUP_DIR.is_symlink():
        hold("prior peer installation attempt exists")
    return original, [s.encode("utf-8") for s in candidate]


def make_file(path, content, mode, uid, gid):
    """Exclusively create an expected file, fsync, and set exact owner/mode."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def replace_config(path, content):
    """Prepare a same-directory mode0640 replacement and atomic rename."""
    pg = pwd.getpwnam("postgres")
    temp_fd, temp_name = tempfile.mkstemp(prefix=".m01-peer-", dir=path.parent)
    os.close(temp_fd)
    temp = Path(temp_name)
    try:
        temp.write_bytes(content)
        os.chown(temp, pg.pw_uid, pg.pw_gid)
        os.chmod(temp, 0o640)
        if temp.read_bytes() != content:
            hold("atomic candidate content verification failed")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def reload_postgresql():
    """Reload PostgreSQL configuration without stopping the shared cluster."""
    result = run(["/usr/bin/pg_ctlcluster", "16", "main", "reload"], timeout=20)
    if result.returncode:
        hold("PostgreSQL reload failed")


def verify_new_mapping():
    """Verify parsed HBA/ident, positive BFF peer login, negative OS identity."""
    hba = pgsql(
        "SELECT count(*) FROM pg_hba_file_rules WHERE type='local' "
        "AND database=ARRAY['" + DB + "'] AND "
        "user_name=ARRAY['" + PG_ROLE + "'] "
        "AND auth_method='peer' AND options=ARRAY['map=" + PEER_MAP + "'] "
        "AND error IS NULL;"
    )
    ident = pgsql(
        "SELECT count(*) FROM pg_ident_file_mappings "
        "WHERE map_name='" + PEER_MAP + "' AND sys_name='" + BFF_OS + "' "
        "AND pg_username='" + PG_ROLE + "' AND error IS NULL;"
    )
    if hba != "1" or ident != "1":
        hold("server parsed peer/ident rules differ from reviewed mapping")
    if pgsql(
        "SELECT current_user||'|'||session_user||'|'||current_database();",
        database=DB, os_user=BFF_OS,
    ) != PG_ROLE + "|" + PG_ROLE + "|" + DB:
        hold("actual dedicated BFF OS peer login mismatch")
    negative = run([
        "/usr/sbin/runuser", "-u", "trusthansen", "--",
        "/usr/bin/psql", "-X", "-A", "-t", "-w",
        "-h", "/var/run/postgresql", "-U", PG_ROLE,
        "-d", DB, "-c", "SELECT 1;",
    ])
    if negative.returncode == 0 or "Peer authentication failed" not in negative.stderr:
        hold("unauthorized OS user unexpectedly accepted or denial not verified")
    check_role_authority()


def prepare():
    """Write only two exact file changes, preserve rollback copies, test mapping."""
    previous, proposed = snapshot_preflight()
    pg = pwd.getpwnam("postgres")
    BACKUP_DIR.mkdir(mode=0o700)
    if stat.S_IMODE(BACKUP_DIR.stat().st_mode) != 0o700:
        hold("root-only backup directory protection failed")
    for path, data in zip((HBA, IDENT), previous):
        make_file(BACKUP_DIR / path.name, data, 0o600, 0, 0)
    try:
        # Fail if anything changes after preflight, before modifying live files.
        if (approved_file(HBA), approved_file(IDENT)) != tuple(previous):
            hold("concurrent PostgreSQL file change")
        for path, data in zip((HBA, IDENT), proposed):
            replace_config(path, data)
        reload_postgresql()
        verify_new_mapping()
    except Exception:
        # Restore only if current config is still OUR candidate or original.
        # Preserve owner-only backups even after automatic recovery.
        for path, old, new in zip((HBA, IDENT), previous, proposed):
            try:
                current = approved_file(path)
                if current in (old, new):
                    replace_config(path, old)
            except OSError:
                pass
        reload_postgresql()
        raise
    print("M01_S03_ISSUER_PEER_INSTALL_PASS "
          "local_db_only=true account_mapping_only=true no_password=true "
          "bff_os_user=omnilyzer-identity issuer_role=sumlaude_identity_issuer "
          "wrong_os_user_denied=true unchanged_role_grants=true "
          "postgres_cluster_reloaded=true BFF_and_Native_inactive=true")


def main(argv=None):
    """Choose a read-only root preflight or an explicit one-time installation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "prepare"))
    args = parser.parse_args(argv)
    if args.action == "preflight":
        snapshot_preflight()
        print("M01_S03_ISSUER_PEER_ROOT_PREFLIGHT_PASS "
              "pg_hba_peer_only=true ident_clean=true "
              "issuer_role_no_password=true "
              "restricted_execute_grants=true BFF_and_Native_inactive=true")
        return 0
    prepare()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, UnicodeError) as exc:
        text = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("M01_S03_ISSUER_PEER_HOLD " + text, file=sys.stderr)
        sys.exit(2)

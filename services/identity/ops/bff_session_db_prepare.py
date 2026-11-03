#!/usr/bin/env python3
"""File: services/identity/ops/bff_session_db_prepare.py
Purpose: One-time production preparation of the ALREADY APPROVED Django
    PostgreSQL server-side session store, without starting any login service.
Related: services/identity/config/settings.py,
    services/identity/omnilyzer-identity.service,
    services/identity/ops/keycloak_prod_recovery.py,
    services/identity/tests/test_bff_session_db_prepare.py,
    docs/adr/0003-keycloak-bff-and-native-authentication.md.

No new PostgreSQL cluster, website, S03 database, framework or Keycloak realm.
Existing PostgreSQL 16 is used. Only exact named NEW database and NEW runtime
role can be created; PostgreSQL schema migrations use the old, already-pinned
offline Django code with an independently matched migration footprint.
The runtime login role gets DML on django_session ONLY and no schema ownership,
CREATE, privilege inheritance or membership. Distinct DBA remains schema owner.

DO NOT run 'prepare' without separate owner-root approval. Privileged
execution requires this exact complete script copied by the owner into the
root-owned /run/omnilyzer-identity-db-prep/ directory (0700, script 0500)
and SHA256-pinned against the approved Git file BEFORE execution. Never
invoke root Python from the mutable /home/trusthansen source staging path.
Preparation does not constitute permission to serve login or enroll users.
It never starts a service or modifies Nginx/DNS/Keycloak or student data.
BFF secrets and the production restricted S03 issuer DSN are still missing.
"""
import argparse
import hashlib
import os
from pathlib import Path
import base64
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys

HOST = "truexmainserver"
DB = "omnilyzer_identity_sessions"
RUNTIME_ROLE = "omnilyzer_identity_runtime"
SOURCE = Path("/home/trusthansen/omnilyzer-identity-bff-candidate-f8fe41d056d8")
SOURCE_TAR_SHA256 = "584399803a6d94f52cf9950e8c39f4618aa9cde81036154f6527c4e40f364d59"
STAGED_SOURCE = SOURCE / "source/services/identity"
ORIGINAL_RELEASE = Path(
    "/opt/omnilyzer/identity/releases/d65d14b69d3e5c899ab9291741b9029669244168"
)
PRIV_DIR = Path("/etc/omnilyzer/identity")
PARTIAL_ENV = PRIV_DIR / "identity-session-db.env.partial"
LIVE_ENV = PRIV_DIR / "identity.env"
APPROVAL = PRIV_DIR / "owner-approved-go"
UNIT = "omnilyzer-identity.service"
DB_PORT = 5432
PG_SOCKET = "/var/run/postgresql"
ROOT_OPERATOR_DIR = Path("/run/omnilyzer-identity-db-prep")
ROOT_OPERATOR = ROOT_OPERATOR_DIR / "bff_session_db_prepare.py"

# Section 1: Independently guard the existing host, code and disabled service.
def digest(path):
    """Calculate SHA256 of the known public source archive, never secrets."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def call(argv, *, stdin=None, env=None, timeout=40):
    """Invoke fixed-path local tools without shell interpolation or logging SQL."""
    try:
        result = subprocess.run(
            argv, input=stdin, capture_output=True, text=True,
            env=env, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("bounded local operation unavailable") from exc
    if result.returncode:
        raise RuntimeError("bounded local operation failed: " + argv[0])
    return result.stdout.strip()


def local_preflight():
    """Return actionable reasons for HOLD without accessing protected secrets."""
    errors = []
    if socket.gethostname().split(".")[0] != HOST:
        errors.append("must be on truexmainserver")
    try:
        if digest(SOURCE / "source.tar") != SOURCE_TAR_SHA256:
            errors.append("current reviewed immutable source archive mismatch")
        metadata = SOURCE.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or
                stat.S_IMODE(metadata.st_mode) != 0o500 or
                metadata.st_uid != pwd.getpwnam("trusthansen").pw_uid):
            errors.append("source staging not sealed owner-only")
        if not (STAGED_SOURCE / "manage.py").is_file():
            errors.append("new source Django entrypoint missing")
        installed = ORIGINAL_RELEASE / "services/identity"
        for path in (
            "config/settings.py", "config/urls.py", "identity_bff/issuer.py",
            "manage.py", "requirements.txt",
        ):
            if not (installed / path).is_file() or not (STAGED_SOURCE / path).is_file():
                errors.append("missing original or reviewed Django source")
                break
        if (installed / "requirements.txt").read_bytes() != (
                STAGED_SOURCE / "requirements.txt").read_bytes():
            errors.append("original and reviewed BFF dependency versions changed")
        # These exact Django apps/migration files must match when migrated
        # using existing installed old release while new source is still held.
        for path in (
            "identity_bff/migrations/__init__.py",
            "config/wsgi.py",
        ):
            old, new = installed / path, STAGED_SOURCE / path
            if old.exists() != new.exists() or (
                    old.is_file() and old.read_bytes() != new.read_bytes()):
                errors.append("original/new Django migration or WSGI scope differs")
    except (OSError, ValueError, KeyError) as exc:
        errors.append("reviewed Django source unavailable: " + type(exc).__name__)

    # Only root may inspect children of the existing root0700 private
    # directory. An unprivileged preflight is necessarily PRELIMINARY.
    # Never relax directory access, follow symlinks or interpret EACCES
    # as proof that a sensitive file is absent.
    if os.geteuid() == 0:
        for path in (LIVE_ENV, APPROVAL, PARTIAL_ENV):
            if path.exists() or path.is_symlink():
                errors.append(path.name + " exists; do not overwrite or activate")
    try:
        meta = PRIV_DIR.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
                stat.S_IMODE(meta.st_mode) != 0o700):
            errors.append("protected BFF configuration directory not root0700")
    except OSError:
        errors.append("protected BFF directory missing")
    service = call(["/usr/bin/systemctl", "show", UNIT, "-p",
                    "ActiveState", "-p", "UnitFileState", "--no-pager"])
    if "ActiveState=inactive" not in service.splitlines() or (
            "UnitFileState=disabled" not in service.splitlines()):
        errors.append("identity BFF service must remain disabled and inactive")
    if not Path("/usr/sbin/runuser").is_file() or not Path("/usr/bin/psql").is_file():
        errors.append("existing local PostgreSQL administrative tools absent")
    if not (ORIGINAL_RELEASE / ".venv/bin/python").is_file():
        errors.append("existing pinned Django Python venv absent")
    if shutil.disk_usage("/").free < 8 * 1024**3:
        errors.append("less than 8GiB free disk")
    return errors


# Section 2: Privileged source custody and DBA peer access.
def trusted_root_operator():
    """Reject mutable home, symlink or unowned code before any root SQL.

    The future operator first installs the exact Git-reviewed source file
    into a dedicated root-owned /run directory and checks its SHA256 there.
    Preflight remains safe to run from the original unprivileged staging.
    """
    if Path(__file__).absolute() != ROOT_OPERATOR:
        raise RuntimeError("trusted root-owned operator path required")
    try:
        run = Path("/run").lstat()
        directory = ROOT_OPERATOR_DIR.lstat()
        script = ROOT_OPERATOR.lstat()
    except OSError as exc:
        raise RuntimeError("trusted root-owned operator staging missing") from exc
    if (not stat.S_ISDIR(run.st_mode) or run.st_uid != 0 or
            bool(run.st_mode & (stat.S_IWGRP | stat.S_IWOTH))):
        raise RuntimeError("trusted root-owned /run directory required")
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            stat.S_IMODE(directory.st_mode) != 0o700):
        raise RuntimeError("trusted root-owned operator directory required")
    if (not stat.S_ISREG(script.st_mode) or script.st_uid != 0 or
            script.st_nlink != 1 or stat.S_IMODE(script.st_mode) != 0o500):
        raise RuntimeError("trusted root-owned operator file required")


def pgsql(sql, *, database="postgres"):
    """Send SQL only via stdin to the OS postgres role, not shell or argv."""
    return call([
        "/usr/sbin/runuser", "-u", "postgres", "--",
        "/usr/bin/psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
        "-d", database,
    ], stdin=sql + "\n", timeout=45)


def root_guard():
    """Require a real operator-approved root action and an empty target scope."""
    if os.geteuid() != 0:
        raise RuntimeError("explicit owner-root privilege required")
    reasons = local_preflight()
    if reasons:
        raise RuntimeError("BFF_DB_PREP_HOLD: " + "; ".join(reasons))
    trusted_root_operator()
    # PostgreSQL 16 target, exact no-collision role/database names only.
    output = pgsql(
        "SELECT current_setting('server_version_num')::int>=160000 AND "
        "current_setting('server_version_num')::int<170000;")
    if output != "t":
        raise RuntimeError("requires existing PostgreSQL16")
    existing = pgsql(
        "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='" +
        RUNTIME_ROLE + "')::int, EXISTS(SELECT 1 FROM pg_database "
        "WHERE datname='" + DB + "')::int;")
    if existing != "0|0":
        raise RuntimeError("session DB or runtime role already exists")


# Section 3: Run ORIGINAL, pinned Django migrations as PostgreSQL DBA only.
def django_migrate():
    """Initialize Django tables, without reusing the BFF runtime database role."""
    old = ORIGINAL_RELEASE / "services/identity"
    config = {
        "DJANGO_SETTINGS_MODULE": "config.settings",
        "DJANGO_SECRET_KEY": "synthetic-migration-signing-" + secrets.token_urlsafe(48),
        "TOKEN_FERNET_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        "PRODUCT_ORIGIN": "https://app.sumlaude.com",
        "OIDC_ISSUER": "https://login.omnilyzer.ai/realms/omnilyzer",
        "OIDC_CLIENT_ID": "sumlaude-bff",
        "OIDC_CLIENT_SECRET": "synthetic-do-not-use-migration-only",
        "SUMLAUDE_ISSUER_DSN": "dbname=UNREACHABLE_migration_only",
        "IDENTITY_PG_DATABASE": DB,
        "IDENTITY_PG_USER": "postgres",
        "IDENTITY_PG_PASSWORD": "synthetic-unused-peer-password",
        "IDENTITY_PG_HOST": PG_SOCKET,
        "IDENTITY_PG_PORT": str(DB_PORT),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env = dict(os.environ)
    env.update(config)
    command = [
        "/usr/sbin/runuser", "-u", "postgres", "--",
        str(ORIGINAL_RELEASE / ".venv/bin/python"),
        str(old / "manage.py"), "migrate", "--noinput", "--verbosity", "0",
    ]
    call(command, env=env, timeout=100)


def restrict_runtime_role():
    """Grant existing session-table DML but no DDL or other Django tables."""
    # REVOKE/GRANT on the new DB needs a connection TO that database.
    pgsql("REVOKE ALL ON DATABASE " + DB + " FROM PUBLIC;\n" +
          "GRANT CONNECT ON DATABASE " + DB + " TO " + RUNTIME_ROLE + ";")
    pgsql(
        "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n" +
        "GRANT USAGE ON SCHEMA public TO " + RUNTIME_ROLE + ";\n" +
        "GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.django_session TO " +
        RUNTIME_ROLE + ";", database=DB)
    proof = pgsql(
        "SELECT "
        "has_database_privilege('" + RUNTIME_ROLE + "','" + DB + "','CONNECT')::int,"
        "has_database_privilege('" + RUNTIME_ROLE + "','" + DB + "','CREATE')::int,"
        "has_table_privilege('" + RUNTIME_ROLE +
        "','public.django_session','SELECT')::int,"
        "has_table_privilege('" + RUNTIME_ROLE +
        "','public.django_session','INSERT')::int,"
        "has_table_privilege('" + RUNTIME_ROLE +
        "','public.django_session','UPDATE')::int,"
        "has_table_privilege('" + RUNTIME_ROLE +
        "','public.django_session','DELETE')::int,"
        "has_table_privilege('" + RUNTIME_ROLE +
        "','public.django_migrations','SELECT')::int,"
        "has_schema_privilege('" + RUNTIME_ROLE + "','public','CREATE')::int;",
        database=DB)
    if proof != "1|0|1|1|1|1|0|0":
        raise RuntimeError("strict Django runtime grants not verified")
    print("M01_BFF_SESSION_DB_ROLE_ISOLATION_PASS table=django_session "
          "ddl_denied=true migration_history_denied=true")



def verify_runtime_connection(password):
    """Prove actual SCRAM login and session-table grants using runtime role.

    The credential exists only in the local child process environment;
    never pass it via argv, CLI, logs, a shell or browser JavaScript.
    """
    env = dict(os.environ)
    env["PGPASSWORD"] = password
    env["PGCONNECT_TIMEOUT"] = "5"
    env["PGSSLMODE"] = "disable"  # localhost-only, not Internet transport
    sql = (
        "SELECT current_user, "
        "has_database_privilege(current_user,current_database(),'CREATE')::int, "
        "has_schema_privilege(current_user,'public','CREATE')::int, "
        "has_table_privilege(current_user,'public.django_session','SELECT')::int, "
        "has_table_privilege(current_user,'public.django_migrations','SELECT')::int, "
        "(SELECT count(*) FROM public.django_session);"
    )
    result = call(
        ["/usr/bin/psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
         "-h", "127.0.0.1", "-p", str(DB_PORT),
         "-U", RUNTIME_ROLE, "-d", DB, "-c", sql],
        env=env, timeout=12)
    if result != RUNTIME_ROLE + "|0|0|1|0|0":
        raise RuntimeError("actual role-authenticated session isolation failed")
    # A successful TCP connection does NOT prove authentication happened:
    # pg_hba.conf can permit host trust, silently ignoring PGPASSWORD.
    # Ask the independent local DBA for only a boolean SCRAM verifier result,
    # never the role's stored password or hash.
    verifier = pgsql(
        "SELECT rolcanlogin::int,rolinherit::int,rolsuper::int,"
        "rolbypassrls::int,"
        "(rolpassword LIKE 'SCRAM-SHA-256$%')::int "
        "FROM pg_authid WHERE rolname='" + RUNTIME_ROLE + "';")
    if verifier != "1|0|0|0|1":
        raise RuntimeError("runtime role SCRAM verifier or role flags invalid")
    # Confirm the *same* localhost route refuses an intentionally different
    # password. LC_ALL makes the expected PostgreSQL diagnostic deterministic.
    # No secret, hash, or raw server diagnostic is printed or logged.
    bad_env = dict(env)
    bad_env["PGPASSWORD"] = secrets.token_urlsafe(48)
    bad_env["LC_ALL"] = "C"
    try:
        denied = subprocess.run(
            ["/usr/bin/psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
             "-h", "127.0.0.1", "-p", str(DB_PORT),
             "-U", RUNTIME_ROLE, "-d", DB, "-c", sql],
            env=bad_env, capture_output=True, text=True,
            check=False, timeout=12)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("negative password-authentication check unavailable") from exc
    if (denied.returncode == 0 or
            "password authentication failed for user" not in denied.stderr):
        raise RuntimeError("password authentication not positively enforced")
    print("M01_BFF_SESSION_DB_RUNTIME_LOGIN_PASS "
          "scram_verifier=true wrong_password_denied=true owner=false "
          "ddl_denied=true migration_read_denied=true session_table_empty=true")


# Section 4: Leave a root-only password fragment for a later approved release.
def prepare():
    """One-time new DB and role, no BFF runtime or product writes."""
    root_guard()
    password = secrets.token_urlsafe(48)
    if not re.fullmatch(r"[A-Za-z0-9_-]{48,96}", password):
        raise RuntimeError("generated password alphabet/length invalid")
    # There are NO secrets in command-line args or GitHub. Ensure SCRAM.
    pgsql(
        "SET password_encryption='scram-sha-256';\n" +
        "CREATE ROLE " + RUNTIME_ROLE +
        " WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE"
        " NOREPLICATION CONNECTION LIMIT 16 PASSWORD '" + password + "';")
    pgsql(
        "CREATE DATABASE " + DB +
        " WITH OWNER postgres ENCODING 'UTF8' TEMPLATE template0;")
    django_migrate()
    restrict_runtime_role()
    verify_runtime_connection(password)
    proof = pgsql(
        "SELECT count(*) FROM public.django_session;", database=DB)
    if proof != "0":
        raise RuntimeError("new Django session database is not empty")
    # The partial fragment is not consumed by the disabled systemd service.
    # Existing live identity.env is expressly untouched and remains absent.
    descriptor = os.open(PARTIAL_ENV, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as target:
        target.write(
            "IDENTITY_PG_DATABASE=" + DB + "\n"
            "IDENTITY_PG_USER=" + RUNTIME_ROLE + "\n"
            "IDENTITY_PG_PASSWORD=" + password + "\n"
            "IDENTITY_PG_HOST=127.0.0.1\n"
            "IDENTITY_PG_PORT=" + str(DB_PORT) + "\n")
        target.flush()
        os.fsync(target.fileno())
    if stat.S_IMODE(PARTIAL_ENV.stat().st_mode) != 0o600:
        raise RuntimeError("root-only database password fragment permissions failed")
    state = call(["/usr/bin/systemctl", "show", UNIT,
                  "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"])
    if "ActiveState=inactive" not in state.splitlines() or (
            "UnitFileState=disabled" not in state.splitlines()):
        raise RuntimeError("unexpected BFF runtime activation")
    print("M01_BFF_SESSION_DB_PREPARED_PASS PostgreSQL16=true "
          "separate_database=true runtime_schema_owner=false "
          "separate_runtime_role=true scram_password=true "
          "server_side_django_sessions=true root_only_password_fragment=true "
          "no_user_sessions_created=true BFF_still_disabled=true "
          "S03_database_untouched=true production_activation_pending=true")


def main(argv=None):
    """Run safe read-only preflight or owner-controlled one-time DB preparation."""
    parser = argparse.ArgumentParser(description="Isolated Django session DB preparation")
    parser.add_argument("action", choices=("preflight", "prepare"))
    action = parser.parse_args(argv).action
    if action == "preflight":
        problems = local_preflight()
        if problems:
            print("M01_BFF_SESSION_DB_HOLD " + "; ".join(problems))
            return 2
        if os.geteuid() != 0:
            print("M01_BFF_SESSION_DB_SOURCE_PREFLIGHT_PASS "
                  "root_only_secret_and_database_checks_pending=true "
                  "database_not_created=true service_not_started=true")
        else:
            print("M01_BFF_SESSION_DB_PREFLIGHT_PASS "
                  "root_only_file_checks_passed=true "
                  "database_collision_check_requires_prepare=true")
        return 0
    prepare()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        msg = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("M01_BFF_SESSION_DB_HOLD " + msg, file=sys.stderr)
        sys.exit(2)

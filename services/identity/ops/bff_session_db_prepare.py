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

DO NOT run 'prepare' without separate owner-root approval. Preparation does
not constitute permission to serve login or enroll users. It never enables
or starts a service, modifies Nginx/DNS/Keycloak, or creates real student data.
BFF secrets and the production restricted S03 issuer DSN are still missing.
"""
import argparse
import hashlib
import os
from pathlib import Path
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
EXISTING_REQUIREMENTS_SHA256 = "5d337039d4b1de28f929d0a0d4d19c18ba8dbb5fe5240fb4dcce6023ff67fd62"

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
                metadata.st_uid != __import__("pwd").getpwnam("trusthansen").pw_uid):
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


# Section 2: Root-only DBA peer access for the new isolated session store.
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
    from cryptography.fernet import Fernet  # pinned installed runtime library
    config = {
        "DJANGO_SETTINGS_MODULE": "config.settings",
        "DJANGO_SECRET_KEY": "synthetic-migration-signing-" + secrets.token_urlsafe(48),
        "TOKEN_FERNET_KEY": Fernet.generate_key().decode("ascii"),
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


def restrict_runtime_role(password):
    """Grant existing session-table DML but no DDL or other Django tables."""
    sql = (
        "REVOKE ALL ON DATABASE " + DB + " FROM PUBLIC;\n" +
        "GRANT CONNECT ON DATABASE " + DB + " TO " + RUNTIME_ROLE + ";\n" +
        "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n" +
        "GRANT USAGE ON SCHEMA public TO " + RUNTIME_ROLE + ";\n" +
        "GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.django_session TO " +
        RUNTIME_ROLE + ";\n"
    )
    # REVOKE/GRANT on the new DB needs a connection TO that database.
    pgsql("REVOKE ALL ON DATABASE " + DB + " FROM PUBLIC;\n" +
          "GRANT CONNECT ON DATABASE " + DB + " TO " + RUNTIME_ROLE + ";")
    pgsql(sql.split("REVOKE ALL ON SCHEMA public FROM PUBLIC;\n")[1]
          .join([]) if False else (
          "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n" +
          "GRANT USAGE ON SCHEMA public TO " + RUNTIME_ROLE + ";\n" +
          "GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.django_session TO " +
          RUNTIME_ROLE + ";"), database=DB)
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
    restrict_runtime_role(password)
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
        print("M01_BFF_SESSION_DB_" + (
            "HOLD " + "; ".join(problems) if problems else "PREFLIGHT_PASS"))
        return 2 if problems else 0
    prepare()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        msg = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("M01_BFF_SESSION_DB_HOLD " + msg, file=sys.stderr)
        sys.exit(2)

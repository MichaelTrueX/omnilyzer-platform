#!/usr/bin/env python3
"""File: services/identity/ops/prepare_identity_runtime_env.py
Purpose: Assemble ONE inactive Django BFF production EnvironmentFile from
  existing root-only Keycloak confidential-client and PostgreSQL session-DB
  fragments. Generate only the new Django signing and token-at-rest keys.
Linked files: config/settings.py, omnilyzer-identity.service,
  identity_bff/issuer.py, ops/bff_session_db_prepare.py,
  ops/prepare_s03_issuer_peer.py,
  tests/test_prepare_identity_runtime_env.py.

This one-time operator never changes PostgreSQL schema, Keycloak, S03 admission,
service state, systemd unit, existing client/DB credentials or public DNS.
Both PostgreSQL connections and Django production settings are validated
BEFORE writing an exclusive root:root 0600 /etc/omnilyzer/identity/identity.env.
Production activation, current release switch and owner-approved-go remain
separate GO decisions.
"""
import argparse
import base64
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import subprocess
import sys


# Section 1: Existing exact host resources and immutable release.
HOST = "truexmainserver"
OS_USER = "omnilyzer-identity"
RELEASE = Path("/opt/omnilyzer/identity/releases/"
               "304b5acdc642ec4b26e08867af467e63c1b04c5e")
OLD_RELEASE = Path("/opt/omnilyzer/identity/releases/"
                   "d65d14b69d3e5c899ab9291741b9029669244168")
CURRENT = Path("/opt/omnilyzer/identity/current")
PRIVATE_DIR = Path("/etc/omnilyzer/identity")
KEYCLOAK_DIR = Path("/etc/omnilyzer/keycloak")
CLIENT_FILE = KEYCLOAK_DIR / "sumlaude-bff-client.env"
DB_FILE = PRIVATE_DIR / "identity-session-db.env.partial"
DEST = PRIVATE_DIR / "identity.env"
APPROVAL = PRIVATE_DIR / "owner-approved-go"
TRUST_DIR = Path("/run/m01-bff-env")
TRUST_SCRIPT = TRUST_DIR / "prepare_identity_runtime_env.py"
PRODUCT_ORIGIN = "https://app.sumlaude.com"
OIDC_ISSUER = "https://login.omnilyzer.ai/realms/omnilyzer"
OIDC_CLIENT_ID = "sumlaude-bff"
ISSUER_DSN = ("dbname=sumlaude_learning user=sumlaude_identity_issuer "
              "host=/var/run/postgresql port=5432")
OIDC_KEYS = frozenset(("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"))
DB_KEYS = frozenset(("IDENTITY_PG_DATABASE", "IDENTITY_PG_USER",
                     "IDENTITY_PG_PASSWORD", "IDENTITY_PG_HOST",
                     "IDENTITY_PG_PORT"))


def fail(reason):
    """Exit fail-closed without ever printing credentials or environment."""
    raise RuntimeError("M01_BFF_ENV_HOLD " + reason)


def run(argv, *, env=None, cwd=None, timeout=25):
    """Execute bounded known binaries, capture diagnostics without echoing secrets."""
    try:
        proc = subprocess.run(
            argv, env=env, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail("required local runtime unavailable")
    return proc


def secure_regular_file(path):
    """Verify and read existing root:root 0600 fragment via O_NOFOLLOW."""
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or
            info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600):
        fail("root-only existing credential file has unexpected metadata")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_ino != info.st_ino or opened.st_dev != info.st_dev):
            fail("credential file changed during read")
        data = os.read(fd, 8193)
        if len(data) > 8192:
            fail("credential file unexpectedly large")
        return data
    finally:
        os.close(fd)


def exact_fragment(data, expected):
    """Parse strict ASCII KEY=value credentials, rejecting duplicates and extra keys."""
    try:
        text = data.decode("ascii")
    except UnicodeError:
        fail("credential fragment is not ASCII")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        fail("credential fragment line endings invalid")
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            fail("unexpected credential fragment line")
        key, sep, value = line.partition("=")
        if not sep or key not in expected or key in result:
            fail("unexpected or duplicate credential fragment key")
        if not value or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value):
            fail("credential value contains unsupported EnvironmentFile characters")
        result[key] = value
    if frozenset(result) != expected:
        fail("required credential fragment fields missing")
    return result


def root_operator_guard():
    """Require owner-installed root-owned 0500 source under 0700 private /run."""
    if os.geteuid() != 0 or Path(__file__).absolute() != TRUST_SCRIPT:
        fail("trusted root-only operator required")
    parent, source = TRUST_DIR.lstat(), TRUST_SCRIPT.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
            stat.S_IMODE(parent.st_mode) != 0o700 or
            not stat.S_ISREG(source.st_mode) or source.st_uid != 0 or
            source.st_gid != 0 or source.st_nlink != 1 or
            stat.S_IMODE(source.st_mode) != 0o500):
        fail("trusted root operator custody mismatch")


def host_guard():
    """Ensure original disabled systemd and immutable source/credential boundaries."""
    root_operator_guard()
    if socket.gethostname().split(".")[0] != HOST:
        fail("wrong production host")
    for parent in (PRIVATE_DIR, KEYCLOAK_DIR):
        m = parent.lstat()
        if (not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or
                m.st_gid != 0 or stat.S_IMODE(m.st_mode) != 0o700):
            fail("private root configuration directory changed")
    if DEST.exists() or DEST.is_symlink():
        fail("production identity.env already exists; never overwrite")
    if APPROVAL.exists() or APPROVAL.is_symlink():
        fail("production activation marker already exists")
    if not CURRENT.is_symlink() or CURRENT.resolve() != OLD_RELEASE:
        fail("selected BFF release changed")
    if not RELEASE.is_dir() or RELEASE.is_symlink():
        fail("approved new immutable BFF release missing")
    user = pwd.getpwnam(OS_USER)
    if user.pw_name != OS_USER:
        fail("unexpected Django service identity")
    for unit in ("omnilyzer-identity.service", "sumlaude-native.service"):
        state = run(["/usr/bin/systemctl", "show", unit,
                     "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"])
        if (state.returncode or "ActiveState=inactive" not in state.stdout.splitlines()
                or "UnitFileState=disabled" not in state.stdout.splitlines()):
            fail("product service must be disabled and inactive")
    pg = run(["/usr/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432"])
    if pg.returncode:
        fail("PostgreSQL16 not ready")


def credentials():
    """Assemble validated immutable source fragments in local root process memory."""
    client = exact_fragment(secure_regular_file(CLIENT_FILE), OIDC_KEYS)
    db = exact_fragment(secure_regular_file(DB_FILE), DB_KEYS)
    if (client["OIDC_ISSUER"] != OIDC_ISSUER or
            client["OIDC_CLIENT_ID"] != OIDC_CLIENT_ID or
            not re.fullmatch(r"[A-Za-z0-9_-]{60,128}",
                             client["OIDC_CLIENT_SECRET"])):
        fail("Keycloak source confidential-client contract mismatch")
    if (db["IDENTITY_PG_DATABASE"] != "omnilyzer_identity_sessions" or
            db["IDENTITY_PG_USER"] != "omnilyzer_identity_runtime" or
            db["IDENTITY_PG_HOST"] != "127.0.0.1" or
            db["IDENTITY_PG_PORT"] != "5432" or
            not re.fullmatch(r"[A-Za-z0-9_-]{60,128}",
                             db["IDENTITY_PG_PASSWORD"])):
        fail("session-DB runtime credential contract mismatch")
    return {**client, **db}


# Section 2: Actual role-isolated read-only checks under future OS service user.
DB_CHECK = r"""
import os
import psycopg

# Both roles are authenticated from the real future systemd OS principal.
with psycopg.connect(
    dbname=os.environ['IDENTITY_PG_DATABASE'],
    user=os.environ['IDENTITY_PG_USER'],
    password=os.environ['IDENTITY_PG_PASSWORD'],
    host=os.environ['IDENTITY_PG_HOST'],
    port=int(os.environ['IDENTITY_PG_PORT']),
    connect_timeout=5,
) as session_db:
    with session_db.cursor() as cur:
        cur.execute(
            "SELECT current_user, current_database(), "
            "has_table_privilege(current_user,'public.django_session','SELECT'), "
            "has_table_privilege(current_user,'public.django_session','INSERT'), "
            "has_table_privilege(current_user,'public.django_session','UPDATE'), "
            "has_table_privilege(current_user,'public.django_session','DELETE'), "
            "has_schema_privilege(current_user,'public','CREATE'), "
            "has_database_privilege(current_user,current_database(),'CREATE'), "
            "has_table_privilege(current_user,'public.django_migrations','SELECT'), "
            "(SELECT count(*) FROM public.django_session)"
        )
        if cur.fetchone() != (
            'omnilyzer_identity_runtime', 'omnilyzer_identity_sessions',
            True, True, True, True, False, False, False, 0
        ):
            raise RuntimeError('restricted Django session role verification failed')

with psycopg.connect(os.environ['SUMLAUDE_ISSUER_DSN'],
                     connect_timeout=5) as issuer_db:
    with issuer_db.cursor() as cur:
        cur.execute(
            "SELECT current_user, session_user, current_database(), "
            "has_function_privilege(current_user,"
            "'sumlaude_auth.issue_admitted_oidc_session(text,text,bytea,timestamptz)',"
            "'EXECUTE'), "
            "has_function_privilege(current_user,"
            "'sumlaude_auth.revoke_issued_oidc_session(bytea)','EXECUTE'), "
            "has_table_privilege(current_user,'public.users','SELECT'), "
            "has_table_privilege(current_user,"
            "'sumlaude_private.learner_admission','SELECT'), "
            "has_schema_privilege(current_user,'sumlaude_private','USAGE'), "
            "has_database_privilege(current_user,current_database(),'CREATE')"
        )
        if cur.fetchone() != (
            'sumlaude_identity_issuer', 'sumlaude_identity_issuer',
            'sumlaude_learning', True, True, False, False, False, False
        ):
            raise RuntimeError('restricted S03 issuer role verification failed')
"""


def assembled_variables(source, *, signing_key, fernet_key):
    """Build one exact runtime env and one quoted systemd EnvironmentFile."""
    out = {
        "DJANGO_SECRET_KEY": signing_key,
        "TOKEN_FERNET_KEY": fernet_key,
        "PRODUCT_ORIGIN": PRODUCT_ORIGIN,
        **source,
        "SUMLAUDE_ISSUER_DSN": ISSUER_DSN,
    }
    if frozenset(out) != frozenset((
            "DJANGO_SECRET_KEY", "TOKEN_FERNET_KEY", "PRODUCT_ORIGIN",
            "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
            "SUMLAUDE_ISSUER_DSN",
            "IDENTITY_PG_DATABASE", "IDENTITY_PG_USER",
            "IDENTITY_PG_PASSWORD", "IDENTITY_PG_HOST",
            "IDENTITY_PG_PORT")):
        fail("runtime environment key-set changed")
    lines = []
    for key, val in out.items():
        if not val or any(c in val for c in "\n\r\x00\"\\"):
            fail("unsafe systemd environment value")
        lines.append(key + "=" + ('"' + val + '"' if " " in val else val))
    return out, ("\n".join(lines) + "\n").encode("ascii")


# Section 2a: Django check --deploy intentionally reports two constrained
# HSTS warnings: Sumlaude cannot promise HTTPS across all sibling subdomains
# and does not request the browser HSTS preload list. These are the only
# accepted warnings. Other warnings or any errors remain release blockers.
KNOWN_DEPLOY_WARNINGS = frozenset(("security.W005", "security.W021"))


def django_deploy_check_passed(result):
    """Accept a successful Django CLI only with no issues or two known HSTS warnings.

    Django writes deployment warnings and summary to stderr, not stdout.
    Never mistake successful exit code 0 with arbitrary warnings for approval.
    The exact known exception is not a request to modify SSL/HSTS policy.
    """
    if result.returncode or "ERRORS:" in result.stderr:
        return False
    messages = re.findall(
        r"(?m)^[^:\n]+:\s+\(([a-zA-Z0-9_.]+)\)\s+",
        result.stderr,
    )
    stdout = result.stdout.strip()
    if stdout == "System check identified no issues (0 silenced).":
        return not messages and "System check identified some issues" not in result.stderr
    return (
        not stdout
        and len(messages) == len(KNOWN_DEPLOY_WARNINGS)
        and frozenset(messages) == KNOWN_DEPLOY_WARNINGS
        and result.stderr.count("WARNINGS:") == 1
        and result.stderr.count("System check identified 2 issues (0 silenced).") == 1
        and "System check identified some issues:" in result.stderr
    )


def verify_runtime(configuration):
    """Run real Django deployment checks and two real read-only PG connections."""
    django_root = RELEASE / "services/identity"
    py = RELEASE / ".venv/bin/python"
    if not py.is_file() or not (django_root / "manage.py").is_file():
        fail("installed pinned Django runtime unavailable")
    env = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
        "DJANGO_SETTINGS_MODULE": "config.settings", **configuration,
    }
    # Match the existing systemd ExecStartPre exactly: -I intentionally
    # removes Django's script directory from sys.path and would misdiagnose
    # this real, immutable Django manage.py runtime as unimportable.
    cmd = ["/usr/sbin/runuser", "-u", OS_USER, "--", str(py),
           "-B", "manage.py", "check", "--deploy"]
    p = run(cmd, cwd=django_root, env=env)
    if not django_deploy_check_passed(p):
        fail("real nonroot Django production settings check failed")
    check = run(["/usr/sbin/runuser", "-u", OS_USER, "--", str(py),
                 "-I", "-B", "-c", DB_CHECK], cwd=django_root, env=env)
    if check.returncode:
        fail("nonroot session DB or restricted issuer connection failed")


def preflight():
    """Only root reads existing secrets and performs read-only verification."""
    host_guard()
    sources = credentials()
    dummy = {
        "DJANGO_SECRET_KEY": "synthetic-preflight-only-" + "x" * 64,
        "TOKEN_FERNET_KEY": base64.urlsafe_b64encode(b"\x00" * 32).decode(),
    }
    env, _ = assembled_variables(sources, **dict(
        signing_key=dummy["DJANGO_SECRET_KEY"],
        fernet_key=dummy["TOKEN_FERNET_KEY"],
    ))
    verify_runtime(env)
    print("M01_BFF_ENV_ROOT_PREFLIGHT_PASS "
          "client_source=root0600 session_DB_source=root0600 "
          "django_check_deploy=pass "
          "actual_session_DB_login=pass actual_S03_peer_issuer=pass "
          "no_credentials_printed=true no_write=true "
          "BFF_and_Native_inactive=true")


# Section 3: Root-only one-time environment file preparation, no activation.
def prepare():
    """Check again, generate fresh keys, atomically make exclusive root0600 env."""
    preflight()
    source = credentials()
    keys = {
        "signing_key": secrets.token_urlsafe(64),
        "fernet_key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    }
    env, content = assembled_variables(source, **keys)
    verify_runtime(env)
    # Fail closed on changed current/marker or root credential sources.
    host_guard()
    if credentials() != source:
        fail("source credentials changed during preparation")
    fd = os.open(DEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as target:
            target.write(content)
            target.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    stat_result = DEST.lstat()
    if (not stat.S_ISREG(stat_result.st_mode) or
            stat_result.st_uid != 0 or stat_result.st_gid != 0 or
            stat.S_IMODE(stat_result.st_mode) != 0o600):
        fail("written environment file permissions invalid")
    print("M01_BFF_ENV_PREPARED_PASS "
          "root0600=true client_reused=true session_DB_reused=true "
          "new_signing_and_fernet_keys=true "
          "real_Django_and_two_PG_connections=pass "
          "no_secret_leakage=true no_service_start=true "
          "no_current_switch=true no_owner_go_marker=true")


def main(args=None):
    """Route explicitly selected root-only preflight or one-time preparation."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=("preflight", "prepare"))
    command = ap.parse_args(args).action
    if command == "preflight":
        preflight()
    else:
        prepare()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError, UnicodeError) as exc:
        print(str(exc) if isinstance(exc, RuntimeError) else
              "M01_BFF_ENV_HOLD " + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

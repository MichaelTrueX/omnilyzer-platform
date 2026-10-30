#!/usr/bin/env python3
"""File: deployment/analytics_dev_bootstrap.py

Purpose: Owner-operated, one-time isolated Analytics 0.15.0 DEV PostgreSQL
         bootstrap. Generate secrets ON THE SERVER, apply the exact reviewed
         PR52 schema and least-privilege/RLS installers, and leave signed
         Task014 activation to the EXISTING protected GitHub workflow.
Related: /opt/omnilyzer/deployment/.analytics-db-review/*.sql (five immutable
         PR52 SQL inputs); deployment/analytics_dev_release_review.py
         (four specific UID10001/mode0600 product secret files);
         deployment/analytics_first_install.py (subsequent signed Task014).

IMPORTANT: This unreviewed operator is NOT itself a signed release, an OCI
verifier, or permission to deploy. Independent security review and a genuine
owner-authorized root session are required before execution. No production
hosts, existing databases, or original Canary resources may be modified.

Sections: fixed release identity, root-only preflight, locally generated
          credentials, isolated PostgreSQL16 container, reviewed SQL install,
          restricted role credentials, protected four-file handoff, phase-aware
          failure and read-only partial-state inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import quote


HOST = "omnilyzerdev"
ROOTLESS_UID = 991
ROOTLESS_GID = 991
MAPPED_APP_UID = 503216
MAPPED_APP_GID = 503216
NETWORK = "omnilyzer-analytics-backend-dev"
VOLUME = "omnilyzer-analytics-pg16-dev"
CONTAINER = "omnilyzer-analytics-pg16-dev"
DB_NAME = "omnilyzer_analytics_dev"
DB_OWNER = "omnilyzer_owner"
IMAGE = (
    "docker.io/library/postgres@sha256:"
    "0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"
)
DOCKER = ("/usr/bin/docker", "--host", "unix:///run/user/991/docker.sock")
DB_DIR = Path("/opt/omnilyzer/deployment/.analytics-db-review")
PRIVATE_DIR = Path("/var/lib/omnilyzer/deployment/analytics/dev")
SECRET_DIR = PRIVATE_DIR / "secrets"
ADMIN_DIR = PRIVATE_DIR / "pg-admin"
ADMIN_SECRET = ADMIN_DIR / "POSTGRES_ADMIN_PASSWORD"
STAGES = (
    ("analytics-pr52-base-schema-20261030.sql", "03ab77f1b3776d1ecf71d3742912387216121635236ae8365c15b559c3040a11"),
    ("multiwebsite-expand-backfill.sql", "fd6393411cde318b15f1e9b0ac7bbb72da4a558f1c7f2c0ffeba1f97415e2dd1"),
    ("rls--m01-runtime.install.sql", "fd42f933217baa78c77ae706fc9597ab4b643cdbdfb8b21021ea892c508d73fd"),
    ("rls--analytics-app-workspace.install.sql", "c781167272664ab0928e3532bdea13415c51d706df6a27d055398f189777f276"),
    ("rls--analytics-app-events.install.sql", "7aab892cf3668fe74700e70577f6d4581397d652fe8d13a95d575cc1659cbf50"),
)
SECRET_NAMES = (
    "COLLECTOR_DATABASE_URL", "DATABASE_URL", "JWT_REFRESH_SECRET", "JWT_SECRET"
)
_PG_QUERY = (
    'SELECT count(*) FROM pg_class WHERE relname IN '
    '(\'Workspace\',\'Website\',\'WorkspaceMembership\',\'WorkspaceAnalyticsEvent\',\'WebsiteAnalyticsDaily\') '
    'AND relnamespace=\'public\'::regnamespace AND relrowsecurity AND relforcerowsecurity;'
)
_ROLE_QUERY = (
    'SELECT count(*) FROM pg_roles WHERE rolname IN '
    '(\'omni_runtime\',\'collector_runtime\',\'archive_runtime\') '
    'AND NOT rolsuper AND NOT rolbypassrls AND NOT rolinherit;'
)


class BootstrapDenied(RuntimeError):
    """An immutable host/release boundary or DB installation step failed."""


def run(argv: tuple[str, ...] | list[str], *, data: bytes | None = None,
        timeout: int = 90, secret_step: bool = False) -> bytes:
    """Run fixed executable argv, no shell, and never print credential SQL."""
    try:
        result = subprocess.run(
            list(argv), input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/root"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapDenied("required host operation failed") from exc
    if result.returncode != 0:
        # Do not emit dynamic subprocess logs for any operation that could
        # contain authentication material. This also avoids quoted SQL leaks.
        raise BootstrapDenied("secret operation denied" if secret_step
                              else "fixed host operation failed")
    return result.stdout


def _metadata(path: Path, *, owner: int, group: int, mode: int,
              directory: bool) -> None:
    """Reject path substitution, symlinks, unexpected owner or permissions."""
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != owner
            or info.st_gid != group or stat.S_IMODE(info.st_mode) != mode
            or (not directory and info.st_nlink != 1)):
        raise BootstrapDenied("unexpected protected path metadata")


def _sha256(path: Path) -> str:
    """Stream exact trusted SQL bytes without exposing their contents."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(131072):
            digest.update(block)
    return digest.hexdigest()


def preflight() -> None:
    """Prove root, DEV-only immutable SQL, empty new PG and no secret drift."""
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        raise BootstrapDenied("operator is not authorized for this host")
    _metadata(DB_DIR, owner=0, group=0, mode=0o700, directory=True)
    for name, digest in STAGES:
        file = DB_DIR / name
        _metadata(file, owner=0, group=0, mode=0o400, directory=False)
        if _sha256(file) != digest:
            raise BootstrapDenied("SQL source differs from reviewed PR52")
    for directory in (PRIVATE_DIR.parent, PRIVATE_DIR, SECRET_DIR):
        _metadata(directory, owner=0, group=ROOTLESS_GID,
                  mode=0o710, directory=True)
    if ADMIN_DIR.exists() or ADMIN_DIR.is_symlink():
        raise BootstrapDenied("admin credential generation already attempted")
    if list(SECRET_DIR.iterdir()):
        raise BootstrapDenied("product secret path is not empty")
    network = json.loads(run((*DOCKER, "network", "inspect", NETWORK)))[0]
    if (network.get("Name") != NETWORK
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not True
            or network.get("Containers") not in ({}, None)):
        raise BootstrapDenied("backend network is not isolated and empty")
    volume = json.loads(run((*DOCKER, "volume", "inspect", VOLUME)))[0]
    if (volume.get("Name") != VOLUME or volume.get("Driver") != "local"
            or volume.get("Labels", {}).get("ai.omnilyzer.product") != "analytics"):
        raise BootstrapDenied("unreviewed PostgreSQL volume")
    data_directory = Path(volume.get("Mountpoint", ""))
    if (not data_directory.is_absolute() or data_directory.is_symlink()
            or not data_directory.is_dir() or list(data_directory.iterdir())):
        raise BootstrapDenied("PostgreSQL data volume must be newly empty")
    image = json.loads(run((*DOCKER, "image", "inspect", IMAGE)))[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise BootstrapDenied("wrong immutable PostgreSQL architecture")
    # Avoid shell parsing and remote state changes: exact Docker inspect
    # must fail when the first-install name does not exist.
    presence = subprocess.run([*DOCKER, "container", "inspect", CONTAINER],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False, timeout=8)
    if presence.returncode == 0:
        raise BootstrapDenied("existing PostgreSQL container requires reconciliation")
    if run(("/usr/bin/systemctl", "is-active", "omnilyzer-deployment-broker.service")).strip() != b"active":
        raise BootstrapDenied("original Task014 broker is unhealthy")


def private_file(path: Path, data: bytes, *, uid: int, gid: int,
                 mode: int) -> None:
    """Atomically create a protected file, without replacing any prior inode."""
    if not data or len(data) > 8192 or b"\0" in data:
        raise BootstrapDenied("invalid protected secret")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise BootstrapDenied("short secret write")
        os.fsync(fd)
    finally:
        os.close(fd)
    _metadata(path, owner=uid, group=gid, mode=mode, directory=False)


def postgres_exec(sql: bytes, *, secret_step: bool = False) -> bytes:
    """Send SQL only on stdin; never place passwords in argv or shell history."""
    return run((*DOCKER, "exec", "-i", CONTAINER, "psql", "-X", "-q",
                "-v", "ON_ERROR_STOP=1", "-A", "-t", "-U", DB_OWNER, "-d", DB_NAME),
               data=sql, secret_step=secret_step)


def create_database(password: str) -> None:
    """Start only the first isolated PostgreSQL16 container on private Docker."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{50,100}", password):
        raise BootstrapDenied("invalid generated admin credential")
    os.mkdir(ADMIN_DIR, mode=0o710)
    os.chown(ADMIN_DIR, 0, ROOTLESS_GID)
    # The process has umask 0077, so mkdir's 0710 would become 0700.
    os.chmod(ADMIN_DIR, 0o710)
    _metadata(ADMIN_DIR, owner=0, group=ROOTLESS_GID,
              mode=0o710, directory=True)
    private_file(ADMIN_SECRET, (password + "\n").encode("ascii"),
                 uid=ROOTLESS_UID, gid=ROOTLESS_GID, mode=0o400)
    run((*DOCKER, "run", "--detach", "--name", CONTAINER,
         "--network", NETWORK, "--network-alias", CONTAINER,
         "--restart", "unless-stopped", "--pids-limit", "192",
         "--memory", "1024m", "--security-opt", "no-new-privileges:true",
         "--mount", f"type=volume,src={VOLUME},dst=/var/lib/postgresql/data",
         "--mount", f"type=bind,src={ADMIN_SECRET},dst=/run/secrets/pg-admin,readonly",
         "--env", f"POSTGRES_USER={DB_OWNER}",
         "--env", f"POSTGRES_DB={DB_NAME}",
         "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/pg-admin",
         "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
         IMAGE), timeout=40, secret_step=True)
    # Preserve the volume and credentials on failure; no data-destructive
    # automatic cleanup, docker rm, volume rm, or compose down is allowed.
    for _ in range(60):
        try:
            run((*DOCKER, "exec", CONTAINER, "pg_isready", "-q",
                 "-U", DB_OWNER, "-d", DB_NAME), timeout=4)
            break
        except BootstrapDenied:
            time.sleep(1)
    else:
        raise BootstrapDenied("isolated PostgreSQL did not become ready")


def install_reviewed_schema() -> None:
    """Execute precisely the five already-qualified SQL stages in order."""
    for name, digest in STAGES:
        sql = (DB_DIR / name).read_bytes()
        if hashlib.sha256(sql).hexdigest() != digest:
            raise BootstrapDenied("reviewed SQL changed during bootstrap")
        postgres_exec(sql)
        print("PASS", name, flush=True)
    if postgres_exec(_PG_QUERY.encode("ascii")).strip() != b"5":
        raise BootstrapDenied("FORCE RLS qualification rejected")
    if postgres_exec(_ROLE_QUERY.encode("ascii")).strip() != b"3":
        raise BootstrapDenied("least privilege role qualification rejected")


def install_runtime_credentials(app_password: str, collector_password: str,
                                jwt_secret: str, jwt_refresh_secret: str) -> None:
    """Bind DB credentials to non-bypass roles and write four UID-mapped files."""
    for token in (app_password, collector_password, jwt_secret,
                  jwt_refresh_secret):
        if not re.fullmatch(r"[A-Za-z0-9_-]{50,100}", token):
            raise BootstrapDenied("unexpected locally generated credential")
    # All values are generated locally using the operating system CSPRNG.
    # SQL goes only through docker exec STDIN, never shell/stdout/environment.
    role_sql = (
        f'REVOKE ALL ON DATABASE "{DB_NAME}" FROM PUBLIC;\n'
        f'GRANT CONNECT ON DATABASE "{DB_NAME}" TO omni_runtime, collector_runtime;\n'
        f"ALTER ROLE omni_runtime LOGIN PASSWORD '{app_password}';\n"
        f"ALTER ROLE collector_runtime LOGIN PASSWORD '{collector_password}';\n"
    ).encode("ascii")
    postgres_exec(role_sql, secret_step=True)
    host = CONTAINER
    app_url = f"postgresql://omni_runtime:{quote(app_password, safe='')}@{host}:5432/{DB_NAME}?schema=public"
    collector_url = f"postgresql://collector_runtime:{quote(collector_password, safe='')}@{host}:5432/{DB_NAME}?schema=public"
    contents = {
        "DATABASE_URL": f"DATABASE_URL={app_url}\n",
        "COLLECTOR_DATABASE_URL": f"COLLECTOR_DATABASE_URL={collector_url}\n",
        "JWT_SECRET": f"JWT_SECRET={jwt_secret}\n",
        "JWT_REFRESH_SECRET": f"JWT_REFRESH_SECRET={jwt_refresh_secret}\n",
    }
    if set(contents) != set(SECRET_NAMES):
        raise BootstrapDenied("incomplete product secret set")
    for name in SECRET_NAMES:
        private_file(SECRET_DIR / name, contents[name].encode("ascii"),
                     uid=MAPPED_APP_UID, gid=MAPPED_APP_GID, mode=0o600)
    print("PASS four mapped product secrets, all 0600; no contents emitted", flush=True)


def inspect_partial_install() -> dict[str, object]:
    """Read protected metadata only; identify any partial install for manual reconciliation.

    This is NOT a retry, repair, readiness or authorization proof. A crashed or
    interrupted install must be inspected before any operator changes the
    preserved container/volume/secret state. It never reads credential bytes.
    """
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        raise BootstrapDenied("operator is not authorized for this host")
    directory_state = {}
    for label, path in (("admin_dir", ADMIN_DIR), ("secrets_dir", SECRET_DIR)):
        if not path.exists() and not path.is_symlink():
            directory_state[label] = "absent"
            continue
        info = path.lstat()
        directory_state[label] = (
            "directory" if stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            else "untrusted_path"
        )
    secret_state = {}
    for name in SECRET_NAMES:
        path = SECRET_DIR / name
        if not path.exists() and not path.is_symlink():
            secret_state[name] = "absent"
            continue
        info = path.lstat()
        secret_state[name] = (
            "metadata_ok"
            if stat.S_ISREG(info.st_mode)
            and info.st_uid == MAPPED_APP_UID
            and info.st_gid == MAPPED_APP_GID
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            else "untrusted_metadata"
        )
    if not ADMIN_SECRET.exists() and not ADMIN_SECRET.is_symlink():
        admin_secret_state = "absent"
    else:
        info = ADMIN_SECRET.lstat()
        admin_secret_state = (
            "metadata_ok"
            if stat.S_ISREG(info.st_mode) and info.st_uid == ROOTLESS_UID
            and info.st_gid == ROOTLESS_GID
            and stat.S_IMODE(info.st_mode) == 0o400
            and info.st_nlink == 1
            else "untrusted_metadata"
        )
    # Docker inspect shows only state, never environment variables.
    result = subprocess.run(
        [*DOCKER, "container", "inspect", "--format",
         "{{.State.Status}}", CONTAINER],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=8, check=False,
    )
    status = (
        result.stdout.decode("ascii").strip()
        if result.returncode == 0 and len(result.stdout) < 40
        else "absent_or_unavailable"
    )
    if status not in ("created", "running", "restarting", "exited",
                      "paused", "dead", "removing"):
        status = "absent_or_unavailable"
    return {
        "host": HOST,
        "recovery_required": True,
        "operator_may_retry": False,
        "postgres_container": status,
        "admin_dir": directory_state["admin_dir"],
        "admin_secret": admin_secret_state,
        "secrets_dir": directory_state["secrets_dir"],
        "product_secrets": secret_state,
        "sql_state": "unverified_no_automatic_replay",
    }


def main() -> int:
    """Review preflight, inspect partial state or approved one-shot install."""
    parser = argparse.ArgumentParser(description="Analytics DEV-only one-time PostgreSQL bootstrap")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--inspect", action="store_true")
    action.add_argument("--install", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    phase = "preflight"
    try:
        if args.inspect:
            # A root operator can inspect the internal metadata in Python.
            # CLI output is deliberately a SMALL FIXED vocabulary. Do not
            # log a JSON dump of values derived from protected secret paths:
            # even file metadata may be treated as sensitive by CodeQL.
            evidence = inspect_partial_install()
            if evidence["postgres_container"] == "running":
                print("PARTIAL_DB_CONTAINER_RUNNING", flush=True)
            else:
                print("PARTIAL_DB_CONTAINER_ABSENT_STOPPED_OR_UNVERIFIED", flush=True)
            if evidence["admin_secret"] == "metadata_ok":
                print("PARTIAL_ADMIN_SECRET_METADATA_VALID", flush=True)
            elif evidence["admin_secret"] == "absent":
                print("PARTIAL_ADMIN_SECRET_ABSENT", flush=True)
            else:
                print("PARTIAL_ADMIN_SECRET_UNTRUSTED", flush=True)
            secrets_seen = tuple(evidence["product_secrets"].values())
            if all(value == "metadata_ok" for value in secrets_seen):
                print("PARTIAL_FOUR_SECRET_FILES_METADATA_VALID", flush=True)
            elif all(value == "absent" for value in secrets_seen):
                print("PARTIAL_PRODUCT_SECRETS_ABSENT", flush=True)
            else:
                print("PARTIAL_PRODUCT_SECRETS_INCOMPLETE_OR_UNTRUSTED", flush=True)
            print("PARTIAL_SQL_STATE_UNVERIFIED_MANUAL_RECONCILIATION_REQUIRED",
                  flush=True)
            return 0
        preflight()
        print("PASS protected PostgreSQL16 and reviewed-source preflight", flush=True)
        if args.preflight:
            return 0
        # Fixed, non-secret phase markers allow review after a partial failure.
        # No cleanup/retry is permitted; volume and any credentials stay intact.
        phase = "postgres_start"
        admin = secrets.token_urlsafe(48)
        app = secrets.token_urlsafe(48)
        collector = secrets.token_urlsafe(48)
        jwt = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        create_database(admin)
        phase = "reviewed_sql_stages"
        install_reviewed_schema()
        phase = "restricted_credentials"
        install_runtime_credentials(app, collector, jwt, refresh)
        print("DEV_POSTGRES_BOOTSTRAP_STAGED_NOT_SIGNED_TASK014_DEPLOYED", flush=True)
        return 0
    except (BootstrapDenied, OSError, ValueError) as exc:
        print("DEV_BOOTSTRAP_FAIL_CLOSED phase=" + phase
              + "; inspect existing resources before any retry",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

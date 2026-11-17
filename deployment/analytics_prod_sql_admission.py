#!/usr/bin/env python3
"""File: deployment/analytics_prod_sql_admission.py

Purpose: Validate the five accepted Analytics PostgreSQL16 migrations and
         the exact truexmainserver admission boundary before any PROD write.
Related: deployment/analytics_dev_bootstrap.py,
         deployment/analytics_prod_pg_readonly.py,
         deployment/runtime/prod/analytics.compose.private.yaml,
         docs/operations/analytics-prod-first-install.md.

Sections: immutable SQL inputs, file integrity, host identity, read-only PG
          catalog, HBA rule-order validation and CLI.
This file intentionally contains NO database installer or mutation mode.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import pwd
import re
import socket
import stat
import subprocess
import sys

HOST = "truexmainserver"
DB = "omnilyzer_analytics_prod"
PROD_SQL = Path("/var/lib/omnilyzer/analytics/prod/sql")
HBA = Path("/etc/postgresql/16/main/pg_hba.conf")
HBA_SHA256 = "0709ada1b9a61908ceb70255346b83da131f37a5758b39820ced1f2b23b8f01c"
SQL = (
    ("analytics-pr52-base-schema-20261030.sql", "03ab77f1b3776d1ecf71d3742912387216121635236ae8365c15b559c3040a11"),
    ("multiwebsite-expand-backfill.sql", "fd6393411cde318b15f1e9b0ac7bbb72da4a558f1c7f2c0ffeba1f97415e2dd1"),
    ("rls--m01-runtime.install.sql", "fd42f933217baa78c77ae706fc9597ab4b643cdbdfb8b21021ea892c508d73fd"),
    ("rls--analytics-app-workspace.install.sql", "c781167272664ab0928e3532bdea13415c51d706df6a27d055398f189777f276"),
    ("rls--analytics-app-events.install.sql", "7aab892cf3668fe74700e70577f6d4581397d652fe8d13a95d575cc1659cbf50"),
)
ROLE_NAMES = ("omni_runtime", "collector_runtime", "archive_runtime", "collector_lock_definer")
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/var/lib/postgresql",
    "LC_ALL": "C",
    "PGCONNECT_TIMEOUT": "3",
    "PGAPPNAME": "omnilyzer-analytics-prod-admission-readonly",
}
CATALOG = """BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT 'VERSION|' || current_setting('server_version_num');
SELECT 'DATABASE|' || count(*)::text FROM pg_catalog.pg_database WHERE datname='omnilyzer_analytics_prod';
SELECT 'ROLES|' || count(*)::text FROM pg_catalog.pg_roles WHERE rolname IN
  ('omni_runtime','collector_runtime','archive_runtime','collector_lock_definer');
SELECT 'HBA_ERRORS|' || count(*)::text FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL;
COMMIT;
"""


class AdmissionHold(RuntimeError):
    """Fail closed when source, permissions, host or PG boundary differs."""


def exact_file(path: Path, *, uid: int, mode: int, max_bytes: int) -> bytes:
    """Read only a single-link, exact-owner regular file without symlink traversal."""
    try:
        metadata = os.lstat(path)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != mode
                or metadata.st_size > max_bytes):
            raise AdmissionHold("file metadata differs")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            live = os.fstat(fd)
            if (live.st_ino != metadata.st_ino or live.st_dev != metadata.st_dev
                    or live.st_size > max_bytes):
                raise AdmissionHold("file changed during read")
            data = b""
            while len(data) <= max_bytes:
                part = os.read(fd, min(131072, max_bytes + 1 - len(data)))
                if not part:
                    break
                data += part
            if len(data) > max_bytes:
                raise AdmissionHold("oversized SQL input")
            return data
        finally:
            os.close(fd)
    except OSError:
        raise AdmissionHold("file unavailable or unsafe") from None


def verify_sql(directory: Path, *, uid: int, file_mode: int, directory_mode: int) -> None:
    """Require exactly five trusted SQL files, with byte-for-byte accepted digests."""
    try:
        info = os.lstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != directory_mode):
            raise AdmissionHold("SQL custody directory metadata differs")
        if sorted(item.name for item in directory.iterdir()) != sorted(x[0] for x in SQL):
            raise AdmissionHold("SQL custody file inventory differs")
    except OSError:
        raise AdmissionHold("SQL custody directory unavailable") from None
    for name, expected in SQL:
        data = exact_file(directory / name, uid=uid, mode=file_mode, max_bytes=65536)
        if hashlib.sha256(data).hexdigest() != expected:
            raise AdmissionHold(f"accepted SQL digest differs: {name}")


def verify_hba(text: str) -> None:
    """Require known local peer rule order and no existing Analytics exception."""
    entries = [(i, re.split(r"\s+", s.strip())) for i, s in enumerate(text.splitlines(), 1)
               if s.strip() and not s.lstrip().startswith("#")]
    if any(words[0] in {"include", "include_dir", "include_if_exists"}
           for _, words in entries):
        raise AdmissionHold("PG HBA include directives need separate review")
    local = [(i, words) for i, words in entries if words[0] == "local"]
    expected = [
        ("all", "postgres", "peer"),
        ("sumlaude_learning", "sumlaude_identity_issuer", "peer"),
        ("all", "all", "peer"),
        ("replication", "all", "peer"),
    ]
    if [(w[1], w[2], w[3]) for _, w in local] != expected:
        raise AdmissionHold("PROD local HBA rule order differs")
    if not local[1][1][-1] == "map=m01_sumlaude_bff":
        raise AdmissionHold("Sumlaude peer mapping differs")
    if any(DB in line for line in text.splitlines()):
        raise AdmissionHold("Analytics HBA rule already exists")


def postgres_catalog() -> None:
    """Confirm target database and global runtime roles are absent, using READ ONLY SQL."""
    argv = (
        "/usr/sbin/runuser", "-u", "postgres", "--",
        "/usr/bin/psql", "-X", "-w", "-q", "-A", "-t",
        "-P", "pager=off", "-h", "/var/run/postgresql",
        "-d", "postgres", "-v", "ON_ERROR_STOP=1",
    )
    try:
        result = subprocess.run(argv, input=CATALOG, text=True, capture_output=True,
                                env=ENV, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        raise AdmissionHold("read-only PostgreSQL catalog unavailable") from None
    expected = ["VERSION|160015", "DATABASE|0", "ROLES|0", "HBA_ERRORS|0"]
    if result.returncode != 0 or result.stdout.strip().splitlines() != expected:
        raise AdmissionHold("PostgreSQL catalog changed or unexpected")


def prod_preflight() -> None:
    """Check exact PROD prerequisites without creating DB, roles, HBA rules or files."""
    if (os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST
            or platform.machine() != "x86_64"):
        raise AdmissionHold("exact production root identity required")
    verify_sql(PROD_SQL, uid=0, file_mode=0o400, directory_mode=0o700)
    contents = exact_file(HBA, uid=pwd.getpwnam("postgres").pw_uid,
                          mode=0o640, max_bytes=65536)
    if hashlib.sha256(contents).hexdigest() != HBA_SHA256:
        raise AdmissionHold("PROD HBA exact source checksum differs")
    verify_hba(contents.decode("utf-8"))
    postgres_catalog()


def main() -> int:
    """Expose two read-only checks; no installation, deployment or HBA mutation."""
    parser = argparse.ArgumentParser(description="Bounded Analytics PROD SQL admission")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify-dev-sql", action="store_true")
    group.add_argument("--prod-preflight", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_dev_sql:
            if os.geteuid() == 0:
                raise AdmissionHold("DEV SQL verification must run unprivileged")
            directory = Path("/home/omnigpt/m05-analytics-sql-review")
            current = pwd.getpwuid(os.geteuid())
            if socket.gethostname().split(".")[0] != "omnilyzerdev" or current.pw_name != "omnigpt":
                raise AdmissionHold("restricted DEV verifier identity differs")
            verify_sql(directory, uid=os.geteuid(), file_mode=0o400, directory_mode=0o700)
            print("ANALYTICS_PROD_SQL_FIVE_ORIGINAL_DIGESTS_PASS no_changes=true")
        else:
            prod_preflight()
            print("ANALYTICS_PROD_SQL_READONLY_PREFLIGHT_PASS no_changes=true")
    except (AdmissionHold, UnicodeError) as exc:
        print(f"ANALYTICS_PROD_SQL_ADMISSION_HOLD {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

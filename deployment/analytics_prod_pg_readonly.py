#!/usr/bin/env python3
"""File: deployment/analytics_prod_pg_readonly.py

Purpose: One bounded, READ-ONLY inspection of truexmainserver PostgreSQL 16
         before the approved Analytics 0.16 PROD database admission.
Related: AGENTS.md, docs/adr/0002-workspace-tenancy-and-postgresql-rls.md,
         deployment/analytics_dev_bootstrap.py,
         deployment/runtime/prod/analytics.compose.private.yaml,
         docs/operations/analytics-prod-first-install.md.

Sections: fixed host/query contract, strict subprocess execution and reporting.
This command NEVER installs SQL, creates or changes roles, reads password
verifiers, changes HBA, restarts services, writes a file, or grants access.
There is no automatic fallback, retry or mutation option.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import socket
import subprocess
import sys

HOST = "truexmainserver"
MAX_OUTPUT = 16384
PSQL = (
    "/usr/sbin/runuser", "-u", "postgres", "--",
    "/usr/bin/psql", "-X", "-w", "-q", "-A", "-t", "-P", "pager=off",
    "-h", "/var/run/postgresql", "-d", "postgres",
    "-v", "ON_ERROR_STOP=1",
)
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/var/lib/postgresql",
    "LC_ALL": "C",
    "PGCONNECT_TIMEOUT": "3",
    "PGAPPNAME": "omnilyzer-analytics-prod-readonly",
}

# Exactly these catalog reads. No dynamic SQL, role creation or secret access.
# pg_hba_file_rules exposes authentication rule order, not passwords.
SQL = """BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT 'CLUSTER|' || current_setting('server_version_num') || '|' ||
       current_setting('port') || '|' ||
       current_setting('unix_socket_directories') || '|' ||
       current_setting('password_encryption');
SELECT 'TARGET_DB|' || count(*)::text
FROM pg_catalog.pg_database
WHERE datname = 'omnilyzer_analytics_prod';
SELECT 'ROLE|' || rolname || '|' || rolcanlogin::text || '|' ||
       rolsuper::text || '|' || rolbypassrls::text || '|' ||
       rolinherit::text || '|' || rolcreatedb::text || '|' ||
       rolcreaterole::text
FROM pg_catalog.pg_roles
WHERE rolname IN (
  'omni_runtime', 'collector_runtime', 'archive_runtime',
  'omnilyzer_owner', 'omnilyzer_analytics_prod_app',
  'omnilyzer_analytics_prod_collector'
)
ORDER BY rolname;
SELECT 'HBA_LOCAL|' || line_number::text || '|' ||
       array_to_string(database, ',') || '|' ||
       array_to_string(user_name, ',') || '|' || auth_method
FROM pg_catalog.pg_hba_file_rules
WHERE type = 'local' AND error IS NULL
ORDER BY line_number;
SELECT 'HBA_ERRORS|' || count(*)::text
FROM pg_catalog.pg_hba_file_rules
WHERE error IS NOT NULL;
SELECT 'DATABASE_COUNT|' || count(*)::text
FROM pg_catalog.pg_database
WHERE datallowconn AND NOT datistemplate;
COMMIT;
"""


class AuditHold(RuntimeError):
    """Cannot reliably prove the existing PROD catalog without changing it."""


def check_context() -> None:
    """Reject every host, identity and script path outside the owner scope."""
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOST:
        raise AuditHold("requires authorized root on the exact production host")
    if platform.machine() != "x86_64":
        raise AuditHold("unexpected production architecture")
    if not Path("/etc/postgresql/16/main/pg_hba.conf").is_file():
        raise AuditHold("expected PostgreSQL16 main configuration is absent")


def execute_readonly() -> str:
    """Run fixed catalog SQL as postgres using a read-only transaction."""
    try:
        result = subprocess.run(
            PSQL, input=SQL, text=True, capture_output=True,
            env=ENV, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise AuditHold("PostgreSQL read-only catalog command unavailable") from None
    if (result.returncode != 0 or not isinstance(result.stdout, str)
            or len(result.stdout.encode("utf-8")) > MAX_OUTPUT):
        # Do not print SQL error output; a future server might include
        # sensitive catalog fields in an unexpected diagnostic.
        raise AuditHold("PostgreSQL read-only catalog check rejected")
    return result.stdout


def verify_report(output: str) -> list[str]:
    """Require a complete scoped result before reporting any catalog facts."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    prefixes = ("CLUSTER|", "TARGET_DB|", "HBA_ERRORS|", "DATABASE_COUNT|")
    for prefix in prefixes:
        if sum(line.startswith(prefix) for line in lines) != 1:
            raise AuditHold("required catalog evidence incomplete")
    if not any(line.startswith("HBA_LOCAL|") for line in lines):
        raise AuditHold("no usable PostgreSQL Unix socket rules found")
    version = lines[0].split("|")[1]
    if not version.isdecimal() or not 160000 <= int(version) < 170000:
        raise AuditHold("PostgreSQL major release differs")
    if not any(line == "HBA_ERRORS|0" for line in lines):
        raise AuditHold("PostgreSQL authentication file contains errors")
    allowed = ("CLUSTER|", "TARGET_DB|", "ROLE|",
               "HBA_LOCAL|", "HBA_ERRORS|", "DATABASE_COUNT|")
    if any(not line.startswith(allowed) for line in lines):
        raise AuditHold("unexpected catalog output shape")
    return lines


def main() -> int:
    """Print nonsecret role and socket policy metadata, never make changes."""
    try:
        check_context()
        lines = verify_report(execute_readonly())
    except AuditHold as exc:
        print(f"ANALYTICS_PROD_PG_READONLY_HOLD {exc}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    print("ANALYTICS_PROD_PG_READONLY_PASS no_changes=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

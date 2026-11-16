#!/usr/bin/env python3
"""File: deployment/analytics_prod_scoped_ops.py

Purpose: A permanent root-owned, command-specific Omnilyzer Analytics PROD
         operations entrypoint for the existing authorized remote account.
Related: deployment/analytics_prod_pg_readonly.py,
         deployment/analytics_prod_ops_install.py,
         docs/operations/analytics-prod-first-install.md,
         docs/adr/0012-direct-dev-prod-delivery.md.

Sections: trusted host/runtime boundary, fixed command allowlist,
          read-only PostgreSQL audit and runtime status.
Security: NO shell, dynamic imports, arbitrary scripts, user paths,
          package management, SQL writes, Docker socket access,
          registry credentials or PROD public route changes.

Additional privileged operations require their OWN reviewed, root-owned
adapter and explicit authorization. This is not sudo ALL.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import pwd
import socket
import stat
import subprocess
import sys

HOST = "truexmainserver"
OWNER = "trusthansen"
OWNER_UID = 1000
ROOTLESS_USER = "omnilyzer-analytics"
ROOTLESS_UID = 990
ROOTLESS_GID = 982
AUDIT = Path("/usr/local/libexec/omnilyzer-analytics-prod-pg-readonly.py")
AUDIT_SHA256 = "d763480a212ac007ac12dfcd812cf7c0d0a48c0dd177d2867b1aefc60b3a74c8"
OPERATIONS = ("pg-audit", "runtime-status")
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
}


class AccessDenied(RuntimeError):
    """This invocation does not match its fixed, reviewed authority."""


def require_context() -> None:
    """Demand root on exactly PROD, the expected sudo caller, and static UIDs."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split(".")[0] != HOST
            or platform.machine() != "x86_64"):
        raise AccessDenied("root execution on the exact PROD host required")
    if (os.environ.get("SUDO_USER") != OWNER
            or os.environ.get("SUDO_UID") != str(OWNER_UID)
            or os.environ.get("SUDO_COMMAND") is None):
        raise AccessDenied("only the designated sudo caller is authorized")
    try:
        service = pwd.getpwnam(ROOTLESS_USER)
        if service.pw_uid != ROOTLESS_UID or service.pw_gid != ROOTLESS_GID:
            raise AccessDenied("dedicated Analytics runtime identity differs")
    except KeyError:
        raise AccessDenied("dedicated Analytics runtime identity missing") from None


def require_root_file(path: Path, digest: str) -> None:
    """Reject any noncanonical root-owned interpreter input, including symlinks."""
    try:
        record = os.lstat(path)
        if (not stat.S_ISREG(record.st_mode)
                or record.st_uid != 0 or record.st_gid != 0
                or stat.S_IMODE(record.st_mode) != 0o500
                or record.st_nlink != 1
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise AccessDenied("reviewed read-only audit source changed")
    except OSError:
        raise AccessDenied("root-owned read-only audit is unavailable") from None


def run_command(*args: str, timeout: int = 30) -> str:
    """Execute fixed absolute argv with no shell and bounded, sanitized output."""
    try:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, env=ENV, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise AccessDenied("fixed operational subprocess unavailable") from None
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 16384:
        raise AccessDenied("fixed operational subprocess rejected")
    return result.stdout


def postgres_audit() -> str:
    """Run only the reviewed, immutable PostgreSQL transaction-read-only probe."""
    require_root_file(AUDIT, AUDIT_SHA256)
    result = run_command("/usr/bin/python3", "-I", "-B", str(AUDIT))
    if not result.rstrip().endswith(
        "ANALYTICS_PROD_PG_READONLY_PASS no_changes=true"
    ):
        raise AccessDenied("PG audit did not complete its expected read-only result")
    return result


def runtime_status() -> str:
    """Expose only statuses of fixed rootless and existing PROD services."""
    names = (
        "nginx.service", "postgresql.service", "user@990.service",
        "docker.service", "docker.socket", "containerd.service",
    )
    lines = ["ANALYTICS_PROD_RUNTIME_READONLY"]
    for name in names:
        # Nonzero is normal for an inactive or masked unit. Never
        # accidentally convert this diagnostic into a service action.
        try:
            completed = subprocess.run(
                ("/usr/bin/systemctl", "is-active", name),
                stdin=subprocess.DEVNULL, capture_output=True,
                text=True, env=ENV, timeout=6, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise AccessDenied("service status query unavailable") from None
        status = completed.stdout.strip()
        if status not in {
            "active", "inactive", "failed", "activating",
            "deactivating", "unknown", "not-found",
        }:
            raise AccessDenied("unexpected service status")
        lines.append(f"{name}={status}")
    for port in (3141, 3142, 3451):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            occupied = connection.connect_ex(("127.0.0.1", port)) == 0
            lines.append(f"loopback_{port}={'listening' if occupied else 'closed'}")
    lines.append("ANALYTICS_PROD_RUNTIME_READONLY_PASS no_changes=true")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Permit only two reviewed operations, never arbitrary future code."""
    try:
        require_context()
        if len(sys.argv) != 2 or sys.argv[1] not in OPERATIONS:
            raise AccessDenied("operation not in the fixed audited allowlist")
        result = (
            postgres_audit() if sys.argv[1] == "pg-audit"
            else runtime_status()
        )
    except AccessDenied as exc:
        print(f"ANALYTICS_PROD_OPS_HOLD {exc}", file=sys.stderr)
        return 1
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

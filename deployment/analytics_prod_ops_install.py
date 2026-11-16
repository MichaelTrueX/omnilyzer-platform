#!/usr/bin/env python3
"""File: deployment/analytics_prod_ops_install.py

Purpose: One-time owner installation of fixed Analytics PROD read-only ops.
Related: deployment/analytics_prod_scoped_ops.py,
         deployment/analytics_prod_pg_readonly.py,
         docs/operations/analytics-prod-first-install.md.

Sections: exact reviewed SHA and host verification, sudo syntax preflight,
          exclusive root-owned installation.
No sudo ALL, arbitrary user scripts, PostgreSQL writes, container access,
privileged network route changes or future release approval is granted.
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
import tempfile

HOST = "truexmainserver"
OWNER = "trusthansen"
OWNER_UID = 1000
HOME = Path("/home/trusthansen")
INCOMING_OPS = HOME / "analytics-prod-scoped-ops-20261117.py"
INCOMING_PG = HOME / "analytics016-prod-pg-readonly-20261117.py"
INSTALLED_OPS = Path("/usr/local/libexec/omnilyzer-analytics-prod-ops.py")
INSTALLED_PG = Path("/usr/local/libexec/omnilyzer-analytics-prod-pg-readonly.py")
SUDOERS = Path("/etc/sudoers.d/94-omnilyzer-analytics-prod-ops")
OPS_SHA256 = "4042362e3cd9d61a510c1a335740d54316e1bac1f16e2977b39ed07d00d9e3cb"
PG_SHA256 = "d763480a212ac007ac12dfcd812cf7c0d0a48c0dd177d2867b1aefc60b3a74c8"
SUDOERS_TEXT = """# File: /etc/sudoers.d/94-omnilyzer-analytics-prod-ops
# Purpose: Persistent fixed Analytics PROD read-only operations.
# Related: /usr/local/libexec/omnilyzer-analytics-prod-ops.py.
# No wildcard arguments, arbitrary scripts, shell, Docker or DB writes.
trusthansen ALL=(root) NOPASSWD:NOSETENV: /usr/bin/python3 -I -B /usr/local/libexec/omnilyzer-analytics-prod-ops.py pg-audit, /usr/bin/python3 -I -B /usr/local/libexec/omnilyzer-analytics-prod-ops.py runtime-status
"""
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
       "LANG": "C", "LC_ALL": "C"}


class InstallHold(RuntimeError):
    """The root-owned privilege delegation cannot be safely established."""


def inspect_exact_file(path: Path, *, sha: str, uid: int, gid: int, mode: int) -> bytes:
    """Read one exact regular source file after no-follow metadata checks."""
    try:
        info = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != mode):
            raise InstallHold("source file metadata differs")
        content = path.read_bytes()
    except OSError:
        raise InstallHold("required source not readable") from None
    if hashlib.sha256(content).hexdigest() != sha:
        raise InstallHold("reviewed source digest differs")
    return content


def check_context() -> None:
    """Restrict installation to the approved owner and actual PROD host."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split(".")[0] != HOST
            or platform.machine() != "x86_64"):
        raise InstallHold("root on exact PROD host required")
    if os.environ.get("SUDO_USER") != OWNER or os.environ.get("SUDO_UID") != str(OWNER_UID):
        raise InstallHold("must be initiated by approved owner")
    try:
        account = pwd.getpwnam(OWNER)
        if account.pw_uid != OWNER_UID or account.pw_gid != OWNER_UID:
            raise InstallHold("approved owner identity differs")
    except KeyError:
        raise InstallHold("approved owner identity missing") from None

    for parent, modes in (
        (Path("/usr/local/libexec"), {0o755}),
        (Path("/etc/sudoers.d"), {0o750, 0o755}),
        (HOME, {0o700, 0o750, 0o755}),
    ):
        try:
            info = os.lstat(parent)
            expected_uid = OWNER_UID if parent == HOME else 0
            expected_gid = OWNER_UID if parent == HOME else 0
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != expected_uid or info.st_gid != expected_gid
                    or stat.S_IMODE(info.st_mode) not in modes):
                raise InstallHold("source parent ownership or permissions differ")
        except OSError:
            raise InstallHold("source parent missing") from None
    for destination in (INSTALLED_OPS, INSTALLED_PG, SUDOERS):
        if os.path.lexists(destination):
            raise InstallHold("existing privileged target requires manual inspection")


def run(*argv: str, timeout: int = 20) -> str:
    """Execute fixed verification argv without shell, password, or inherited env."""
    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True,
            check=False, text=True, timeout=timeout, env=ENV,
        )
    except (OSError, subprocess.SubprocessError):
        raise InstallHold("fixed verification command unavailable") from None
    if result.returncode:
        raise InstallHold("fixed verification command rejected")
    return result.stdout


def install_new(path: Path, data: bytes, mode: int) -> None:
    """Write new root-owned file exclusively and sync its contents."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as target:
        os.fchmod(target.fileno(), mode)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def publish_sudoers_atomically() -> None:
    """Make the fully fsynced reviewed policy visible in ONE atomic link."""
    # Dot-containing basename is ignored by sudo's @includedir parser.
    # The active rule must never be a partly written command prefix.
    fd, temporary = tempfile.mkstemp(
        prefix=".omnilyzer-analytics-ops-", dir=SUDOERS.parent,
    )
    try:
        with os.fdopen(fd, "wb") as candidate:
            os.fchmod(candidate.fileno(), 0o440)
            candidate.write(SUDOERS_TEXT.encode("utf-8"))
            candidate.flush()
            os.fsync(candidate.fileno())
        run("/usr/sbin/visudo", "-cf", temporary)
        # Unlike os.replace(), link() fails if a rule was installed in
        # the meantime. The active file is published fully written.
        os.link(temporary, SUDOERS)
        try:
            run("/usr/sbin/visudo", "-cf", "/etc/sudoers")
        except InstallHold:
            os.unlink(SUDOERS)
            raise
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def install() -> None:
    """Verify all code and syntax before installing the fixed sudo command."""
    check_context()
    ops = inspect_exact_file(
        INCOMING_OPS, sha=OPS_SHA256, uid=OWNER_UID, gid=OWNER_UID, mode=0o600,
    )
    pg = inspect_exact_file(
        INCOMING_PG, sha=PG_SHA256, uid=OWNER_UID, gid=OWNER_UID, mode=0o600,
    )
    for source in (INCOMING_OPS, INCOMING_PG):
        compile(source.read_bytes(), str(source), "exec")
    with tempfile.TemporaryDirectory(prefix="omni-analytics-ops.", dir="/var/tmp") as directory:
        candidate = Path(directory) / "sudoers"
        candidate.write_text(SUDOERS_TEXT, encoding="utf-8")
        candidate.chmod(0o440)
        run("/usr/sbin/visudo", "-cf", str(candidate))

    # Verify the original global configuration before any publication.
    run("/usr/sbin/visudo", "-cf", "/etc/sudoers")
    install_new(INSTALLED_PG, pg, 0o500)
    install_new(INSTALLED_OPS, ops, 0o500)
    publish_sudoers_atomically()
    print("ANALYTICS_PROD_SCOPED_OPS_INSTALLED_PASS")
    print("PERMITTED=pg-audit,runtime-status")
    print("FUTURE_ARBITRARY_ROOT_SCRIPTS=DENIED")
    print("APPLICATION_AND_PUBLIC_ROUTES=unchanged")


def main() -> int:
    """One root-only installation attempt; never retry after partial changes."""
    if sys.argv[1:] != ["--install"]:
        print("ANALYTICS_PROD_SCOPED_OPS_HOLD wrong arguments", file=sys.stderr)
        return 2
    try:
        install()
    except (InstallHold, OSError) as exc:
        print(f"ANALYTICS_PROD_SCOPED_OPS_HOLD {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

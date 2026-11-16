#!/usr/bin/env python3
"""File: deployment/enable_prod_omnigpt_m01_access.py

Purpose: Bootstrap a permanent, isolated AI account on truexmainserver with
    tightly allowlisted permissions for the two already approved M01 release
    operators. Install a SHA-verified Node binary for its unprivileged remote
    connector. This does NOT perform a release, alter production services,
    change Keycloak, or authorize arbitrary root scripts.
Related: AGENTS.md, SECURITY.md, deployment/enable_dev_root_audit.sh,
    services/identity/ops/{keycloak_add_public_callback_once.py,
    m01_active_bff_upgrade_once.py}, platform PR298.

An administrator installs this EXACT reviewed source as root:root 0500 at
/usr/local/sbin/omnilyzer-prod-omnigpt-access-bootstrap, then runs "install".
Never execute privileged source directly from a writable Git checkout.
"""
from __future__ import annotations

import grp
import hashlib
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import tempfile

# Fixed host, role and reviewed root-controlled release commands.
HOST = "truexmainserver"
ACCOUNT = "omnigpt"
HOME = Path("/home/omnigpt")
BOOTSTRAP = Path("/usr/local/sbin/omnilyzer-prod-omnigpt-access-bootstrap")
SUDOERS_DIR = Path("/etc/sudoers.d")
SUDOERS = SUDOERS_DIR / "91-omnilyzer-prod-omnigpt-m01"
KEYCLOAK = Path("/usr/local/sbin/m01-keycloak-public-callback-once")
BFF = Path("/usr/local/sbin/m01-active-bff-def92-upgrade-once")
KEYCLOAK_HASH = "6a43414a89a38514a3553bb92374d9f520e278d4bf8b4a3bc2a61e7015ff2d2d"
BFF_HASH = "83e8748ba898b339da1a4811682a934ab58a6e13e5700b4235b96af5e9dffe0e"
NODE_SOURCE = Path("/home/trusthansen/.nvm/versions/node/v24.22.0/bin/node")
NODE_TARGET = Path("/usr/local/bin/omnilyzer-ops-node24")
NODE_HASH = "67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c"
KC_GO = "M01_CANONICAL_KEYCLOAK_OWNER_GO=M01_CANONICAL_KEYCLOAK_EXACT_CALLBACK_ONCE_GO"
BFF_GO = (
    "M01_OWNER_GO_SCOPE=M01_CANONICAL_BFF_DEF92_DIRECT_UPGRADE_GO "
    "M01_OWNER_GO_SOURCE_SHA=def92cdb254beeb58e34dc08f9a5aeca2ae2e612 "
    "M01_OWNER_GO_ARCHIVE_SHA256=fd46713dd62b407c0d1ea8b4afb45e342fdc87dd9a3baf53a730b5d0447e0db9"
)


def hold(reason: str) -> None:
    """Fail closed without exposing credentials, tokens or client documents."""
    raise RuntimeError("M01_AI_ACCESS_HOLD_" + reason)


def sha256(path: Path) -> str:
    """Hash source bytes in bounded chunks."""
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def trusted_file(path: Path, *, uid: int, mode: int, expected: str) -> None:
    """Verify non-symlink single-link owner, permissions and complete digest."""
    m = path.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != uid or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != mode or sha256(path) != expected):
        hold("SOURCE_FILE_CHANGED")


def command(args: list[str], *, capture: bool = False) -> str:
    """Run only fixed local OS tools, no shell and no caller environment."""
    try:
        result = subprocess.run(
            args, check=False, timeout=30, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        hold("REQUIRED_OS_TOOL_UNAVAILABLE")
    if result.returncode:
        hold("REQUIRED_OS_TOOL_FAILED")
    return result.stdout.decode("ascii") if capture else ""


def rules() -> bytes:
    """Allow exactly five M01 operations, fixed flags and fixed GO values."""
    pre = "omnigpt ALL=(root) NOPASSWD:NOSETENV: "
    py = "/usr/bin/python3 -I "
    env = "/usr/bin/env "
    return ("\n".join((
        "# File: /etc/sudoers.d/91-omnilyzer-prod-omnigpt-m01",
        "# Purpose: Permanent reviewed M01 operator permissions only.",
        "# Related: deployment/enable_prod_omnigpt_m01_access.py, PR298.",
        "# No wildcard, shell, Docker, sudoedit, SETENV or arbitrary installer.",
        pre + py + str(KEYCLOAK) + " status",
        pre + env + KC_GO + " " + py + str(KEYCLOAK) + " apply",
        pre + env + BFF_GO + " " + py + str(BFF) + " stage",
        pre + env + BFF_GO + " " + py + str(BFF) + " apply",
        pre + py + str(BFF) + " verify",
    )) + "\n").encode("ascii")


def root_preflight() -> None:
    """Require root executing the fixed installed script on exact PROD host."""
    if (socket.gethostname().split(".")[0] != HOST
            or os.getuid() != 0 or os.geteuid() != 0):
        hold("ROOT_PRODUCTION_HOST_REQUIRED")
    if Path(__file__).absolute() != BOOTSTRAP:
        hold("ROOT_OWNED_FIXED_BOOTSTRAP_REQUIRED")
    m = BOOTSTRAP.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != 0o500):
        hold("BOOTSTRAP_PERMISSIONS_CHANGED")
    for directory, accepted in ((SUDOERS_DIR, (0o750, 0o755)),
                                (Path("/usr/local/sbin"), (0o755,)),
                                (Path("/usr/local/bin"), (0o755,))):
        state = directory.lstat()
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0
                or stat.S_IMODE(state.st_mode) not in accepted):
            hold("ROOT_PARENT_CHANGED")
    trusted_file(KEYCLOAK, uid=0, mode=0o500, expected=KEYCLOAK_HASH)
    trusted_file(BFF, uid=0, mode=0o500, expected=BFF_HASH)
    trust_uid = pwd.getpwnam("trusthansen").pw_uid
    trusted_file(NODE_SOURCE, uid=trust_uid, mode=0o750, expected=NODE_HASH)


def checked_account() -> pwd.struct_passwd | None:
    """Reject existing accounts with unsafe home, groups or passwords."""
    try:
        user = pwd.getpwnam(ACCOUNT)
    except KeyError:
        return None
    if (user.pw_uid == 0 or user.pw_gid == 0 or user.pw_dir != str(HOME)
            or user.pw_shell != "/bin/bash"
            or grp.getgrgid(user.pw_gid).gr_name != ACCOUNT):
        hold("ACCOUNT_IDENTITY_MISMATCH")
    groups = sorted({g.gr_name for g in grp.getgrall()
                     if ACCOUNT in g.gr_mem or g.gr_gid == user.pw_gid})
    if groups != [ACCOUNT]:
        hold("ACCOUNT_HAS_UNAPPROVED_GROUP")
    mode = HOME.lstat()
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != user.pw_uid
            or stat.S_IMODE(mode.st_mode) != 0o700):
        hold("ACCOUNT_HOME_UNSAFE")
    status = command(["/usr/bin/passwd", "-S", ACCOUNT], capture=True).split()
    if len(status) < 2 or status[1] != "L":
        hold("ACCOUNT_PASSWORD_NOT_LOCKED")
    return user


def create_account() -> pwd.struct_passwd:
    """Make one locked, non-sudo Linux identity only when absent."""
    user = checked_account()
    if user:
        return user
    if HOME.exists() or HOME.is_symlink():
        hold("HOME_ALREADY_OCCUPIED")
    command(["/usr/sbin/useradd", "--create-home", "--user-group",
             "--shell", "/bin/bash", "--home-dir", str(HOME), ACCOUNT])
    HOME.chmod(0o700)
    user = checked_account()
    if user is None:
        hold("ACCOUNT_CREATE_UNCONFIRMED")
    return user


def install_node() -> None:
    """Copy approved Node24 for unprivileged remote agent, not root execution."""
    if NODE_TARGET.exists() or NODE_TARGET.is_symlink():
        trusted_file(NODE_TARGET, uid=0, mode=0o755, expected=NODE_HASH)
        return
    # Use the existing root-owned /usr/local/bin, not an AI-writable home:
    # a directory replacement race must not redirect root's Node copy.
    parent = NODE_TARGET.parent
    m = parent.lstat()
    if (not stat.S_ISDIR(m.st_mode) or m.st_uid != 0
            or stat.S_IMODE(m.st_mode) != 0o755):
        hold("AGENT_NODE_PARENT_UNSAFE")
    fd, name = tempfile.mkstemp(prefix=".node24-", dir=parent)
    temp = Path(name)
    try:
        checksum = hashlib.sha256()
        with os.fdopen(fd, "wb") as target, NODE_SOURCE.open("rb") as source:
            for data in iter(lambda: source.read(1048576), b""):
                checksum.update(data)
                target.write(data)
            target.flush()
            os.fsync(target.fileno())
        if checksum.hexdigest() != NODE_HASH:
            hold("NODE_COPY_HASH_CHANGED")
        temp.chmod(0o755)
        os.replace(temp, NODE_TARGET)
    finally:
        temp.unlink(missing_ok=True)
    trusted_file(NODE_TARGET, uid=0, mode=0o755, expected=NODE_HASH)


def install_sudoers() -> None:
    """Validate sudoers and publish exact immutable rule without replacing any."""
    desired = rules()
    if SUDOERS.exists() or SUDOERS.is_symlink():
        m = SUDOERS.lstat()
        if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0
                or stat.S_IMODE(m.st_mode) != 0o440
                or SUDOERS.read_bytes() != desired):
            hold("SUDOERS_ALREADY_DIFFERENT")
        return
    fd, name = tempfile.mkstemp(prefix=".omnigpt-m01-", dir=SUDOERS_DIR)
    candidate = Path(name)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(desired)
            file.flush()
            os.fsync(file.fileno())
        command(["/usr/sbin/visudo", "-cf", str(candidate)])
        candidate.chmod(0o440)
        os.link(candidate, SUDOERS)
    finally:
        candidate.unlink(missing_ok=True)
    command(["/usr/sbin/visudo", "-cf", "/etc/sudoers"])


def main() -> None:
    """One fixed root bootstrap command, never a generic privileged CLI."""
    if sys.argv[1:] != ["install"]:
        hold("EXACT_INSTALL_ARGUMENT_REQUIRED")
    root_preflight()
    user = create_account()
    install_node()
    install_sudoers()
    print("M01_PROD_OMNIGPT_PERMANENT_EXACT_RELEASE_ROLE_INSTALLED_PASS")
    print("ACCOUNT=omnigpt UID=" + str(user.pw_uid))
    print("NEXT=Connect a separate Remote Desktop Commander as omnigpt")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(str(error) if str(error).startswith("M01_AI_ACCESS_HOLD_")
              else "M01_AI_ACCESS_HOLD_UNEXPECTED_ERROR", file=sys.stderr)
        raise SystemExit(2)

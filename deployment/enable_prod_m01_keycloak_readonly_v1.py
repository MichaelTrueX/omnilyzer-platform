#!/usr/bin/env python3
"""File: deployment/enable_prod_m01_keycloak_readonly_v1.py

Purpose: One fixed owner-run root bootstrap to install the SHA-verified
    Keycloak diagnostic as root 0500 and add EXACTLY ONE additional
    root-only, read-only client diagnostic to the existing omnigpt sudoers.
    No Keycloak administrator call or product deployment occurs here.
Related: services/identity/ops/m01_keycloak_client_readonly_v1.py,
    services/identity/tests/test_m01_keycloak_client_readonly_v1.py,
    deployment/enable_prod_omnigpt_m01_access.py and platform PR298/PR301.
Precondition: independently reviewed root-owned 0500 file at BOOTSTRAP.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import tempfile

# Section: Immutable source and the already installed five-command role.
HOST = "truexmainserver"
BOOTSTRAP = Path("/usr/local/sbin/m01-keycloak-readonly-access-bootstrap")
SOURCE = Path("/home/trusthansen/m01-kc-readonly-source-20261116/m01_keycloak_client_readonly_v1.py")
INSTALLED = Path("/usr/local/sbin/m01-keycloak-client-readonly-v1")
OPERATOR_SOURCE_SHA256 = "3fb909ef9f83d6b89f66de8b9944143d9ec382184bfaf1a05e8c89927f6bbca2"
PRIOR_REVIEWED = Path("/usr/local/sbin/m01-keycloak-public-callback-once")
PRIOR_REVIEWED_SHA256 = "6a43414a89a38514a3553bb92374d9f520e278d4bf8b4a3bc2a61e7015ff2d2d"
SUDOERS = Path("/etc/sudoers.d/91-omnilyzer-prod-omnigpt-m01")
SUDOERS_OLD_SHA256 = "dfb3420bd3ebbc1bc2bce62a4f66ff0ca2ca1443c9b19e5444919a909e6937e5"
ADD_LINE = (
    b"omnigpt ALL=(root) NOPASSWD:NOSETENV: "
    b"/usr/bin/python3 -I /usr/local/sbin/m01-keycloak-client-readonly-v1 inspect\n"
)


def hold(reason: str) -> None:
    """Fail closed with a fixed marker and no private Keycloak information."""
    raise RuntimeError("M01_KC_READONLY_ACCESS_HOLD_" + reason)


def digest(path: Path) -> str:
    """Hash only the bounded installed source and policy bytes."""
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def file_check(path: Path, *, uid: int, mode: int, sha: str) -> None:
    """Check a fixed regular inode, ownership, mode and reviewed full digest."""
    m = path.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_nlink != 1 or m.st_uid != uid
            or stat.S_IMODE(m.st_mode) != mode or digest(path) != sha):
        hold("SOURCE_METADATA_OR_BYTES_DRIFT")


def root_preflight() -> None:
    """Require a fixed reviewed root entrypoint and unchanged existing policy."""
    if (os.getuid() != 0 or os.geteuid() != 0
            or socket.gethostname().split(".")[0] != HOST
            or Path(__file__).absolute() != BOOTSTRAP):
        hold("FIXED_OWNER_ROOT_ENTRYPOINT_REQUIRED")
    m = BOOTSTRAP.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != 0o500):
        hold("BOOTSTRAP_ROOT_CUSTODY")
    owner = pwd.getpwnam("trusthansen")
    if owner.pw_uid != 1000:
        hold("OWNER_ID_DRIFT")
    operator = pwd.getpwnam("omnigpt")
    if operator.pw_uid != 1001 or operator.pw_gid != 1001:
        hold("DEDICATED_ACCOUNT_DRIFT")
    parents = (
        (Path("/usr/local/sbin"), (0o755,)),
        (Path("/etc/sudoers.d"), (0o750, 0o755)),
    )
    for parent, accepted in parents:
        state = parent.lstat()
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0
                or stat.S_IMODE(state.st_mode) not in accepted):
            hold("ROOT_PARENT_CHANGED")
    directory = SOURCE.parent.lstat()
    if (not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != owner.pw_uid
            or stat.S_IMODE(directory.st_mode) != 0o700):
        hold("SOURCE_PARENT_UNSAFE")
    file_check(SOURCE, uid=owner.pw_uid, mode=0o400,
               sha=OPERATOR_SOURCE_SHA256)
    file_check(PRIOR_REVIEWED, uid=0, mode=0o500,
               sha=PRIOR_REVIEWED_SHA256)


def proposed_rule() -> bytes:
    """Derive only one additional read-only command from the prior rule."""
    existing = SUDOERS.read_bytes()
    current = digest(SUDOERS)
    if current == SUDOERS_OLD_SHA256:
        if existing.count(b"omnigpt ALL=(root)") != 5 or ADD_LINE in existing:
            hold("BASE_POLICY_NOT_EXACT")
        return existing + ADD_LINE
    proposed = existing.removesuffix(ADD_LINE)
    if (existing.endswith(ADD_LINE)
            and hashlib.sha256(proposed).hexdigest() == SUDOERS_OLD_SHA256
            and existing.count(b"omnigpt ALL=(root)") == 6):
        return existing
    hold("PRIVILEGE_POLICY_CHANGED")


def install_readonly_binary() -> None:
    """Install only pinned source bytes into one root-owned fixed executable."""
    if INSTALLED.exists() or INSTALLED.is_symlink():
        file_check(INSTALLED, uid=0, mode=0o500,
                   sha=OPERATOR_SOURCE_SHA256)
        return
    # Verify a complete root-private copy before publishing its executable
    # pathname. An interrupted copy never leaves a partial operator selected.
    fd, name = tempfile.mkstemp(prefix=".m01-kc-readonly-operator-",
                                dir=INSTALLED.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as target, SOURCE.open("rb") as source:
            for chunk in iter(lambda: source.read(1048576), b""):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if digest(temporary) != OPERATOR_SOURCE_SHA256:
            hold("REVIEWED_SOURCE_COPY_CHANGED")
        temporary.chmod(0o500)
        os.link(temporary, INSTALLED)
    finally:
        temporary.unlink(missing_ok=True)
    file_check(INSTALLED, uid=0, mode=0o500, sha=OPERATOR_SOURCE_SHA256)


def visudo_check(path: Path) -> None:
    """Parse the fixed sudoers candidate without running a shell."""
    try:
        p = subprocess.run(
            ["/usr/sbin/visudo", "-cf", str(path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        hold("VISUDO_UNAVAILABLE")
    if p.returncode != 0:
        hold("VISUDO_REJECTED_POLICY")


def install_rule() -> None:
    """Atomically replace only the matching pre-reviewed five-command policy."""
    m = SUDOERS.lstat()
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != 0o440):
        hold("BASE_SUDOERS_UNSAFE")
    expected = proposed_rule()
    if SUDOERS.read_bytes() == expected:
        visudo_check(SUDOERS)
        return
    fd, name = tempfile.mkstemp(prefix=".m01-kc-readonly-", dir=SUDOERS.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(expected)
            writer.flush()
            os.fsync(writer.fileno())
        visudo_check(temp)
        temp.chmod(0o440)
        # Fail closed if another privileged actor edited this policy while
        # this isolated source and candidate were being validated.
        if digest(SUDOERS) != SUDOERS_OLD_SHA256:
            hold("POLICY_CHANGED_DURING_INSTALL")
        os.replace(temp, SUDOERS)
    finally:
        temp.unlink(missing_ok=True)
    visudo_check(SUDOERS)


def main() -> None:
    """Fixed one-argument owner installation, not a generic privileged CLI."""
    if sys.argv[1:] != ["install"]:
        hold("EXACT_INSTALL_ONLY")
    root_preflight()
    # A new policy is never installed unless both old and proposed policy
    # have already been validated and unchanged from the reviewed source.
    proposed_rule()
    install_readonly_binary()
    install_rule()
    print("M01_KC_READONLY_ROLE_EXACT_ONE_COMMAND_INSTALLED_PASS")
    print("M01_KC_READONLY_PRODUCT_AUTH_AND_RELEASE_UNCHANGED_PASS")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(str(error) if str(error).startswith("M01_KC_READONLY_ACCESS_HOLD_")
              else "M01_KC_READONLY_ACCESS_HOLD_REDACTED_FAILURE",
              file=sys.stderr)
        raise SystemExit(2)

#!/usr/bin/env python3
"""File: services/identity/ops/install_inactive_identity_release.py
Purpose: Install one exact, Git-archived Django BFF candidate INACTIVE beside
         the existing production release. Never touch current, systemd, DB,
         private credentials, Keycloak, Nginx, DNS or learner admission.
Related: services/identity/{requirements.txt,omnilyzer-identity.service},
         services/identity/prepare-identity-only.sh,
         docs/operations/p0-shared-keycloak-sumlaude-identity-20261029.md.

Run preflight as unprivileged trusthansen. Root execution is allowed ONLY from
the root-owned mode 0500 /run copy, after operator verifies the exact Git file
SHA256. This does not authorize live activation or a migration.
"""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile


# Section 1: Fixed original platform and host release boundaries.
HOST = "truexmainserver"
OLD_SHA = "d65d14b69d3e5c899ab9291741b9029669244168"
OLD = Path("/opt/omnilyzer/identity/releases") / OLD_SHA
RELEASES = OLD.parent
CURRENT = Path("/opt/omnilyzer/identity/current")
UNIT = "omnilyzer-identity.service"
APPROVAL = Path("/etc/omnilyzer/identity/owner-approved-go")
REPO = Path("/home/trusthansen/omnilyzer-identity-prep-20261029/repo")
INSTALLER = Path("/run/m01-identity-inactive-install.py")
OWNER = "trusthansen"


def fail(why):
    """Stop before writes on any mismatched source, ownership or runtime."""
    raise RuntimeError("M01_INACTIVE_RELEASE_HOLD: " + why)


def run(argv, *, timeout=20):
    """Execute a fixed read-only tool without shell interpolation or secrets."""
    try:
        result = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail("required read-only command unavailable")
    if result.returncode:
        fail("read-only command failed: " + argv[0])
    return result.stdout.strip()


def stage_for(sha):
    """Map an exact source SHA to one existing owner-sealed stage, no user path."""
    return Path("/home/trusthansen") / (
        "omnilyzer-identity-" + sha[:7] + "-source-stage-20261106"
    )


def trusted_staged_archive(sha, expected):
    """Compare sealed archive to exact Git object and expected operator digest."""
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        fail("source commit must be exact 40-hex SHA")
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        fail("archive digest must be exact 64-hex SHA256")
    stage = stage_for(sha)
    archive = stage / "source.tar"
    uid = pwd.getpwnam(OWNER).pw_uid
    for path, is_dir, permission in (
        (stage, True, 0o500),
        (archive, False, 0o400),
    ):
        try:
            meta = path.lstat()
        except OSError:
            fail("pinned source stage absent")
        if (meta.st_uid != uid or stat.S_IMODE(meta.st_mode) != permission
                or not (stat.S_ISDIR(meta.st_mode) if is_dir else
                        stat.S_ISREG(meta.st_mode))
                or (not is_dir and meta.st_nlink != 1)):
            fail("source stage owner, mode or file type mismatch")
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        fail("source archive digest mismatch")
    # Root must not disable Git's safe.directory ownership protection.
    # Execute Git as the existing nonprivileged checkout owner instead.
    git = ["/usr/bin/git"]
    if os.geteuid() == 0:
        git = ["/usr/sbin/runuser", "-u", OWNER, "--", "/usr/bin/git"]
    if run(git + ["-C", str(REPO), "cat-file", "-t", sha]) != "commit":
        fail("exact reviewed Git commit unavailable")
    expected_tar = subprocess.run(
        git + ["-C", str(REPO), "archive", "--format=tar", sha,
               "services/identity",
               "docs/operations/p0-shared-keycloak-sumlaude-identity-20261029.md"],
        capture_output=True, timeout=25, check=False,
    )
    if expected_tar.returncode or expected_tar.stdout != data:
        fail("source archive differs from canonical Git archive")
    return archive


def manifest_members(archive):
    """Reject tar links, devices and traversal even with exact Git provenance."""
    with tarfile.open(archive, mode="r:") as tf:
        members = tf.getmembers()
        if not members:
            fail("empty source archive")
        for member in members:
            p = PurePosixPath(member.name)
            if (p.is_absolute() or ".." in p.parts
                    or not (p.parts[:2] == ("services", "identity") or
                            p.parts[:2] == ("docs", "operations") or
                            member.name in ("services", "docs"))):
                fail("archive path not part of reviewed identity source")
            if not (member.isfile() or member.isdir()):
                fail("archive contains nonregular entry")
        return members


def installed_runtime_guard(sha, archive):
    """Prove existing BFF cannot be affected by an inactive install."""
    if socket.gethostname().split(".")[0] != HOST:
        fail("wrong host")
    if not CURRENT.is_symlink() or CURRENT.resolve() != OLD:
        fail("installed current release changed")
    new = RELEASES / sha
    if new.exists() or new.is_symlink():
        fail("target version already installed; do not overwrite")
    service = run(["/usr/bin/systemctl", "show", UNIT,
                   "-p", "ActiveState", "-p", "UnitFileState", "--no-pager"])
    if "ActiveState=inactive" not in service.splitlines():
        fail("BFF currently active")
    if "UnitFileState=disabled" not in service.splitlines():
        fail("BFF currently enabled")
    if APPROVAL.exists() or APPROVAL.is_symlink():
        fail("live BFF owner GO marker exists")
    # Use /proc socket view, never open a listener.
    ports = run(["/usr/bin/ss", "-lnt"])
    if re.search(r"127\.0\.0\.1:18740\s", ports):
        fail("private BFF port already occupied")
    if not (OLD / ".venv/bin/python").is_file():
        fail("original installed Python missing")
    if not (OLD / ".venv/bin/gunicorn").is_file():
        fail("original installed Gunicorn missing")
    with tarfile.open(archive, mode="r:") as tf:
        requirement = tf.extractfile("services/identity/requirements.txt")
        if not requirement or requirement.read() != (
                OLD / "services/identity/requirements.txt").read_bytes():
            fail("dependency versions changed; offline reuse not authorized")
    return new


def trusted_privileged_operator():
    """Do not execute mutable user-owned home source with root privileges."""
    if os.geteuid() != 0:
        fail("inactive install requires operator root authorization")
    try:
        here = Path(__file__).absolute()
        meta = here.lstat()
    except OSError:
        fail("root-owned temporary operator missing")
    if (here != INSTALLER or not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != 0 or meta.st_nlink != 1
            or stat.S_IMODE(meta.st_mode) != 0o500):
        fail("operator must be root-owned mode0500 in reviewed /run path")


def rewrite_console_scripts(venv, old_path, new_path):
    """Make copied console entrypoints self-contained in the new release."""
    old_interpreter = (str(old_path / ".venv/bin/python")).encode()
    new_interpreter = (str(new_path / ".venv/bin/python")).encode()
    for file in (venv / "bin").iterdir():
        if not file.is_file() or file.is_symlink():
            continue
        content = file.read_bytes()
        first, sep, rest = content.partition(b"\n")
        if first == b"#!" + old_interpreter:
            file.write_bytes(b"#!" + new_interpreter + sep + rest)
            file.chmod(file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    gunicorn = venv / "bin/gunicorn"
    if not gunicorn.read_bytes().startswith(b"#!" + new_interpreter + b"\n"):
        fail("new Gunicorn shebang not relocated")


def check_pinned_packages(python, requirements):
    """Verify copied installed distribution versions against exact source pins."""
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from importlib.metadata import version\n"
        "for line in Path(sys.argv[1]).read_text().splitlines():\n"
        "  if not line or line.startswith('#'): continue\n"
        "  name, pinned = line.split('==', 1)\n"
        "  if version(name.split('[',1)[0]) != pinned:\n"
        "    raise SystemExit('M01_RUNTIME_DEPENDENCY_PIN_MISMATCH')\n"
    )
    run([str(python), "-I", "-B", "-c", code, str(requirements)])


def install_inactive(sha, archive, new):
    """Atomically publish new root-owned source+venv, without selecting it."""
    trusted_privileged_operator()
    temporary = Path(tempfile.mkdtemp(prefix=".m01-inactive-", dir=RELEASES))
    try:
        with tarfile.open(archive, mode="r:") as tf:
            tf.extractall(path=temporary, filter="data")
        shutil.copytree(OLD / ".venv", temporary / ".venv",
                        symlinks=True)
        rewrite_console_scripts(temporary / ".venv", OLD, new)
        check_pinned_packages(
            temporary / ".venv/bin/python",
            temporary / "services/identity/requirements.txt",
        )
        if not (temporary / "services/identity/config/wsgi.py").is_file():
            fail("new WSGI entrypoint absent")
        # Only this release directory is created, no current or unit update.
        if new.exists() or new.is_symlink():
            fail("target appeared during installation")
        temporary.rename(new)
        # Retain both releases for safe rollback and verify service remains inert.
        if CURRENT.resolve() != OLD:
            fail("unexpected live current release change")
        print("M01_INACTIVE_RELEASE_INSTALLED=" + str(new))
        print("M01_NO_CURRENT_SWITCH_NO_SYSTEMD_NO_DB_NO_SECRETS_NO_DNS")
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main(argv=None):
    """Support one readonly preflight and one root-held install command only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "install"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--archive-sha256", required=True)
    args = parser.parse_args(argv)
    archive = trusted_staged_archive(args.sha, args.archive_sha256)
    manifest_members(archive)
    target = installed_runtime_guard(args.sha, archive)
    if args.action == "preflight":
        print("M01_INACTIVE_RELEASE_READONLY_PREFLIGHT_PASS="
              + args.sha + " no_production_write=true")
        return 0
    install_inactive(args.sha, archive, target)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        # No untrusted URL, SQL, password, raw archive or environment logged.
        print("M01_INACTIVE_RELEASE_HOLD " + type(exc).__name__
              + (": " + str(exc) if isinstance(exc, RuntimeError) else ""),
              file=sys.stderr)
        sys.exit(2)

#!/usr/bin/env python3
"""File: services/identity/ops/m01_active_bff_upgrade_once.py

Purpose: One direct, SHA-bound immutable BFF upgrade from the currently
    active private 3481cac version to M04 source-approved canonical
    def92cdb, with rollback to the old ACTIVE version on failed readiness.
    The public site feature flag remains separately governed and OFF by default.
    No Keycloak client, Native, NGINX, DB, DNS, session, or public site mutation.
    This is the old PR243 operator's reviewed lifecycle reused on PR298 with
    changed-only source pins. No staging or production apply without explicit GO.
Related: services/identity/{requirements.txt,omnilyzer-identity.service},
    services/identity/ops/install_inactive_identity_release.py,
    services/identity/identity_bff/{formative,views}.py,
    services/identity/tests/test_m01_active_upgrade_source.py,
    platform PR #243 and PR #298, Sumlaude PR #421, S01 PR #364.

The root-only operator must first be installed as an exact SHA-reviewed,
root-owned 0500 file at OPERATOR. Never run a writable user-home copy as
root. Actions are deliberately separate: preflight, stage, apply, verify.
No release action is permitted from a generic "continue" instruction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

# Section 1: Exact immutable approved sources, host, old live runtime.
OLD_SHA = "3481cacbef910a37d87a3c26341b1a8f16a6612f"
NEW_SHA = "def92cdb254beeb58e34dc08f9a5aeca2ae2e612"
OLD_UNIT_SHA256 = "9f49c797f8ca266b873ae7cebabcc110f35ae6f42b37d67a74e3f522e90c0586"
NEW_UNIT_SHA256 = "0198baceb956ef7d36ade346c49e953e365f36f53789f11aebcc2d4ff93d95b3"
REQUIREMENTS_SHA256 = "c864060dcac5945ef86cce56a0dedb9a368e190d74cb1f65ec3178ec0e117c9c"
SOURCE_ARCHIVE_SHA256 = "fd46713dd62b407c0d1ea8b4afb45e342fdc87dd9a3baf53a730b5d0447e0db9"
SOURCE_ARCHIVE_BYTES = 675840
ARCHIVE = Path("/home/trusthansen/m01-bff-def92-source-20261116/identity-source-def92.tar")
OPERATOR = Path("/usr/local/sbin/m01-active-bff-def92-upgrade-once")
RELEASES = Path("/opt/omnilyzer/identity/releases")
OLD = RELEASES / OLD_SHA
NEW = RELEASES / NEW_SHA
CURRENT = Path("/opt/omnilyzer/identity/current")
UNIT = Path("/etc/systemd/system/omnilyzer-identity.service")
GO_MARKER = Path("/etc/omnilyzer/identity/owner-approved-go")
RECEIPTS = Path("/etc/omnilyzer/identity/m01-bff-def92-once")
SERVICE = "omnilyzer-identity.service"
NATIVE = "sumlaude-native.service"
VHOST = Path("/etc/nginx/sites-enabled/app.sumlaude.com.conf")
OLD_VHOST_SHA256 = "49753649cac70dceaf893ea03c5b74fd475bb8500166c7a8ced00b8612710769"
NATIVE_CURRENT = Path("/opt/sumlaude/native/current")
NATIVE_APPROVED = Path("/opt/sumlaude/native/releases/ca5b54ccf3e179cc5706bd129cf4f9350f41e026")
GO_SCOPE = "M01_CANONICAL_BFF_DEF92_DIRECT_UPGRADE_GO"


class UpgradeHold(RuntimeError):
    """Fail closed with a non-secret, stable operator failure reason."""


def hold(reason):
    """Reject unsafe or ambiguous state; never attempt a second upgrade."""
    raise UpgradeHold("M01_ACTIVE_BFF_HOLD " + reason)


def sha256(path):
    """Hash a regular file in bounded chunks without logging its contents."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command(args, *, timeout=15, check=True):
    """Run one fixed argv program, never interpolate a shell or credentials."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        hold("REQUIRED_LOCAL_COMMAND_UNAVAILABLE")
    if check and result.returncode:
        hold("LOCAL_CHECK_FAILED_" + Path(args[0]).name.upper().replace("-", "_"))
    return result.stdout.strip() if check else result


def systemd(property_name, service=SERVICE):
    """Read only a single exact systemd property, without showing secrets."""
    return command(["/usr/bin/systemctl", "show", service,
                    "-p", property_name, "--value"])


def service_active(service):
    """Read actual active state, including stale failed/stopped distinction."""
    return command(["/usr/bin/systemctl", "is-active", service], check=False).stdout.strip()


def valid_regular(path, *, uid, mode):
    """Require exact regular, single-link, expected-owner protected file."""
    try:
        m = path.lstat()
    except OSError:
        hold("SOURCE_FILE_MISSING")
    if (not stat.S_ISREG(m.st_mode) or m.st_uid != uid or m.st_nlink != 1
            or stat.S_IMODE(m.st_mode) != mode):
        hold("SOURCE_FILE_TYPE_OWNER_MODE_MISMATCH")


def validate_archive():
    """Check complete exact Git archive bytes, ownership and traversal safety.

    The immutable BFF source commit is PR298 parent def92cdb, independently
    M04 SOURCE accepted. The final current PR commit adds only its operator/
    tests and MUST NOT be silently substituted for the pinned BFF archive.
    """
    try:
        user = pwd.getpwnam("trusthansen").pw_uid
        directory = ARCHIVE.parent.lstat()
    except (OSError, KeyError):
        hold("SOURCE_STAGING_MISSING")
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != user
            or stat.S_IMODE(directory.st_mode) != 0o700):
        hold("SOURCE_STAGING_OWNERSHIP")
    valid_regular(ARCHIVE, uid=user, mode=0o400)
    if ARCHIVE.stat().st_size != SOURCE_ARCHIVE_BYTES or sha256(ARCHIVE) != SOURCE_ARCHIVE_SHA256:
        hold("REVIEWED_SOURCE_ARCHIVE_SHA_MISMATCH")
    with tarfile.open(ARCHIVE, "r:") as tar:
        members = tar.getmembers()
        if len(members) != 65:
            hold("REVIEWED_SOURCE_ARCHIVE_MEMBER_COUNT")
        for item in members:
            name = PurePosixPath(item.name)
            if (name.is_absolute() or ".." in name.parts
                    or not (item.isfile() or item.isdir())
                    or not (item.name in ("services", "services/identity")
                            and item.isdir()
                            or item.name.startswith("services/identity/"))):
                hold("REVIEWED_SOURCE_ARCHIVE_UNSAFE_MEMBER")
        expected = {
            "services/identity/requirements.txt": REQUIREMENTS_SHA256,
            "services/identity/omnilyzer-identity.service": OLD_UNIT_SHA256,
            "services/identity/config/urls.py":
                "7640a6251e8263187e26e58b7fa472c3f667c56aa2884f8fd1671f05e817db97",
            "services/identity/identity_bff/formative.py":
                "c3c39f499b9f9126982930ffeb4ee3bf7591716a56b622d1dba9155e51bd7a5c",
            "services/identity/tests/test_canonical_public_host.py":
                "f4cb56320de1b3cb360dfd0a96e7811143c5dad871121ac4cb31fefc2fdc5461",
            "services/identity/config/settings.py":
                "732b0f05db064b60330d28adaf6d94d220f07a885c1a0baf96c272a7a3cf90d0",
            "services/identity/identity_bff/views.py":
                "f75f67b669c5dd6f9c8eccdd7897cd6189ac2ef6b6642d8c1afc40471c4b4b21",
            "services/identity/identity_bff/oidc.py":
                "0a37989b4e8d6e77d16f0a27b85be9515eea37001c305d7bd3cb46f140a6a698",
        }
        for name, digest in expected.items():
            f = tar.extractfile(name)
            if f is None or hashlib.sha256(f.read()).hexdigest() != digest:
                hold("EXACT_GIT_SOURCE_FILE_SHA_MISMATCH")
    return members


def snapshot_reviewed_archive(destination):
    """Pin exact user-staged source bytes inside a private root-owned directory.

    The user-owned archive may change between initial preflight and staging.
    Never extract from that mutable pathname: read a single no-follow regular
    source file descriptor, copy bounded bytes, and verify the private copy's
    complete approved digest before opening it as TAR.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(ARCHIVE, flags), "rb") as source:
        meta = os.fstat(source.fileno())
        expected_uid = pwd.getpwnam("trusthansen").pw_uid
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != expected_uid
                or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o400
                or meta.st_size != SOURCE_ARCHIVE_BYTES):
            hold("REVIEWED_ARCHIVE_SOURCE_FD_CHANGED")
        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        checksum = hashlib.sha256()
        count = 0
        with os.fdopen(os.open(destination, out_flags, 0o600), "wb") as target:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                count += len(chunk)
                if count > SOURCE_ARCHIVE_BYTES:
                    hold("REVIEWED_SOURCE_ARCHIVE_SHA_MISMATCH")
                checksum.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    if count != SOURCE_ARCHIVE_BYTES or checksum.hexdigest() != SOURCE_ARCHIVE_SHA256:
        hold("REVIEWED_SOURCE_ARCHIVE_SHA_MISMATCH")
    return destination


def proposed_unit(original):
    """Derive exactly four reviewed immutable release-path substitutions."""
    before = OLD_SHA.encode("ascii")
    if hashlib.sha256(original).hexdigest() != OLD_UNIT_SHA256:
        hold("CURRENT_UNIT_SOURCE_MISMATCH")
    if original.count(before) != 4:
        hold("EXPECTED_FOUR_IMMUTABLE_UNIT_PINS")
    result = original.replace(before, NEW_SHA.encode("ascii"))
    if hashlib.sha256(result).hexdigest() != NEW_UNIT_SHA256:
        hold("REVIEWED_UNIT_DERIVATION_SHA_MISMATCH")
    return result


def validate_live_before_upgrade(*, require_vhost=True):
    """Prove the old private GTM BFF is still the selected live release."""
    if socket.gethostname().split(".")[0] != "truexmainserver":
        hold("WRONG_PRODUCTION_HOST")
    if not CURRENT.is_symlink() or CURRENT.resolve() != OLD:
        hold("OLD_LIVE_RELEASE_CHANGED")
    if OLD.is_symlink() or not OLD.is_dir():
        hold("OLD_IMMUTABLE_RELEASE_INVALID")
    valid_regular(UNIT, uid=0, mode=0o644)
    if sha256(UNIT) != OLD_UNIT_SHA256:
        hold("LIVE_SERVICE_UNIT_SHA_CHANGED")
    if (OLD / "services/identity/requirements.txt").is_file() is False:
        hold("OLD_PINNED_REQUIREMENTS_MISSING")
    if sha256(OLD / "services/identity/requirements.txt") != REQUIREMENTS_SHA256:
        hold("DEPENDENCIES_CHANGED")
    if service_active(SERVICE) != "active" or systemd("UnitFileState") != "enabled":
        hold("OLD_BFF_MUST_BE_ACTIVE_AND_BOOT_ENABLED")
    if systemd("WorkingDirectory") != str(OLD / "services/identity"):
        hold("OLD_BFF_LOADED_CWD_CHANGED")
    if systemd("NeedDaemonReload") != "no" or systemd("DropInPaths"):
        hold("SYSTEMD_DRIFT")
    if service_active(NATIVE) != "active":
        hold("NATIVE_NOT_ACTIVE")
    if (not NATIVE_CURRENT.is_symlink()
            or NATIVE_CURRENT.resolve() != NATIVE_APPROVED
            or systemd("WorkingDirectory", NATIVE) != str(NATIVE_APPROVED / "backend")):
        hold("NATIVE_REVIEWED_IMMUTABLE_RUNTIME_DRIFT")
    if service_active("nginx.service") != "active":
        hold("NGINX_NOT_ACTIVE")
    bindings = re.findall(r"\b(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]):18740\b",
                          command(["/usr/bin/ss", "-lntH"]))
    if bindings != ["127.0.0.1:18740"]:
        hold("BFF_MUST_BIND_LOOPBACK_ONLY")
    if require_vhost and sha256(VHOST) != OLD_VHOST_SHA256:
        hold("PRIVATE_NGINX_VHOST_NOT_CURRENT_APPROVED_PRESTATE")
    return int(systemd("MainPID")), int(systemd("MainPID", NATIVE))


def root_operator():
    """Validate exact privileged operator path without root from user home."""
    if os.geteuid() != 0:
        hold("ROOT_REQUIRED")
    here = Path(__file__).absolute()
    if here != OPERATOR:
        hold("ROOT_OPERATOR_MUST_USE_FIXED_PATH")
    valid_regular(here, uid=0, mode=0o500)
    parent = RECEIPTS.parent
    if parent.is_symlink() or not parent.is_dir():
        hold("PRIVATE_IDENTITY_CUSTODY_DIR_MISSING")
    meta = parent.lstat()
    if meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o700:
        hold("PRIVATE_IDENTITY_CUSTODY_DIR_UNSAFE")


def explicit_go():
    """Require a separately stated, source-specific Product Owner runtime GO."""
    if (os.environ.get("M01_OWNER_GO_SCOPE") != GO_SCOPE
            or os.environ.get("M01_OWNER_GO_SOURCE_SHA") != NEW_SHA
            or os.environ.get("M01_OWNER_GO_ARCHIVE_SHA256") != SOURCE_ARCHIVE_SHA256):
        hold("EXPLICIT_BFF_RUNTIME_OWNER_GO_MISSING")


def write_exclusive(path, value, *, mode=0o600):
    """Create a durable root-private receipt without replacing any earlier one."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as file:
            file.write(value)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(descriptor)


def normalize_source_directories(root, members):
    """Make only reviewed non-secret source paths traversable by service UID."""
    for item in members:
        if item.isdir():
            p = root / item.name
            if p.is_symlink() or not p.is_dir():
                hold("EXTRACTED_DIRECTORY_CHANGED")
            p.chmod(0o755)


def rewrite_console_scripts(venv):
    """Reuse accepted installer logic to relocate signed old entrypoint shebangs."""
    old_python = (str(OLD / ".venv/bin/python")).encode()
    new_python = (str(NEW / ".venv/bin/python")).encode()
    for f in (venv / "bin").iterdir():
        if not f.is_file() or f.is_symlink():
            continue
        content = f.read_bytes()
        first, sep, rest = content.partition(b"\n")
        if first == b"#!" + old_python:
            f.write_bytes(b"#!" + new_python + sep + rest)
            f.chmod(stat.S_IMODE(f.stat().st_mode) | stat.S_IXUSR | stat.S_IXGRP)
    if not (venv / "bin/gunicorn").read_bytes().startswith(b"#!" + new_python + b"\n"):
        hold("GUNICORN_NOT_RELOCATED_TO_NEW_IMMUTABLE_RELEASE")


def verify_packages():
    """Reuse old root-owned pinned offline venv only for IDENTICAL requirements."""
    code = ("import sys\nfrom pathlib import Path\n"
            "from importlib.metadata import version\n"
            "for line in Path(sys.argv[1]).read_text().splitlines():\n"
            " if not line or line.startswith('#'): continue\n"
            " name,pinned=line.split('==',1)\n"
            " if version(name.split('[',1)[0])!=pinned: "
            "raise SystemExit('PIN_MISMATCH')\n")
    command([str(NEW / ".venv/bin/python"), "-I", "-B", "-c",
             code, str(NEW / "services/identity/requirements.txt")], timeout=30)
    actual = command([str(NEW / ".venv/bin/python"), "-m", "gunicorn", "--version"])
    if "24.1.1" not in actual:
        hold("GUNICORN_PIN_CHANGED")


def stage_new_release():
    """Stage an immutable root-owned copy WITHOUT touching live BFF or unit."""
    root_operator()
    explicit_go()
    members = validate_archive()
    old_pid, native_pid = validate_live_before_upgrade()
    if NEW.exists() or NEW.is_symlink() or RECEIPTS.exists():
        hold("ONE_TIME_STAGE_ALREADY_EXISTS")
    temp = Path(tempfile.mkdtemp(prefix=".m01-def92-", dir=RELEASES))
    published = False
    try:
        # The initial validated user path is mutable. Extract ONLY the
        # byte-identical, digest-verified copy within this root-owned 0700 dir.
        private_archive = snapshot_reviewed_archive(temp / ".m01-pinned-source.tar")
        with tarfile.open(private_archive, "r:") as tf:
            tf.extractall(temp, filter="data")
        private_archive.unlink()
        normalize_source_directories(temp, members)
        shutil.copytree(OLD / ".venv", temp / ".venv", symlinks=True)
        # The new venv must be relocated against its final immutable path.
        rewrite_console_scripts(temp / ".venv")
        template = (temp / "services/identity/omnilyzer-identity.service").read_bytes()
        generated = proposed_unit(template)
        candidate = temp / "m01-reviewed-upgrade.service"
        candidate.write_bytes(generated)
        candidate.chmod(0o644)
        temp.chmod(0o755)
        temp.rename(NEW)
        published = True
        verify_packages()
        command(["/usr/sbin/runuser", "-u", "omnilyzer-identity", "--",
                 "/usr/bin/test", "-r",
                 str(NEW / "services/identity/config/wsgi.py")])
        command(["/usr/bin/systemd-analyze", "verify",
                 str(NEW / "m01-reviewed-upgrade.service")], timeout=30)
        if service_active(SERVICE) != "active" or int(systemd("MainPID")) != old_pid:
            hold("OLD_BFF_CHANGED_DURING_INACTIVE_STAGE")
        if int(systemd("MainPID", NATIVE)) != native_pid:
            hold("NATIVE_CHANGED_DURING_INACTIVE_STAGE")
        RECEIPTS.mkdir(mode=0o700)
        write_exclusive(RECEIPTS / "staged.json", json.dumps({
            "source_commit": NEW_SHA, "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "unit_sha256": NEW_UNIT_SHA256, "old_release": OLD_SHA,
            "runtime_dependencies_unchanged": True,
            "status": "STAGED_ONLY_NO_SERVICE_SWITCH",
        }, sort_keys=True).encode())
        print("M01_NEW_IMMUTABLE_BFF_STAGED_NO_SERVICE_OR_NGINX_CHANGE_PASS")
    except BaseException:
        # Only a failed, unselected, receipt-free stage can be removed.
        # Never clean an already-approved version or a live process.
        if (published and NEW.is_dir() and not NEW.is_symlink()
                and not RECEIPTS.exists()
                and CURRENT.resolve() == OLD):
            shutil.rmtree(NEW)
        raise
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def staged_proof():
    """Check private receipt, immutable source/venv, and non-live new release."""
    if not RECEIPTS.is_dir() or RECEIPTS.is_symlink():
        hold("PROTECTED_STAGE_RECEIPT_MISSING")
    statinfo = RECEIPTS.lstat()
    if statinfo.st_uid != 0 or stat.S_IMODE(statinfo.st_mode) != 0o700:
        hold("ROOT_RECEIPT_OWNERSHIP_CHANGED")
    valid_regular(RECEIPTS / "staged.json", uid=0, mode=0o600)
    saved = json.loads((RECEIPTS / "staged.json").read_text())
    if (saved.get("source_commit") != NEW_SHA
            or saved.get("source_archive_sha256") != SOURCE_ARCHIVE_SHA256
            or saved.get("unit_sha256") != NEW_UNIT_SHA256
            or saved.get("status") != "STAGED_ONLY_NO_SERVICE_SWITCH"):
        hold("STAGED_RECEIPT_NOT_SOURCE_PINNED")
    if NEW.is_symlink() or not NEW.is_dir():
        hold("STAGED_RELEASE_MISSING")
    expected_staged = {
        "requirements.txt": REQUIREMENTS_SHA256,
        "config/settings.py": "732b0f05db064b60330d28adaf6d94d220f07a885c1a0baf96c272a7a3cf90d0",
        "config/urls.py": "7640a6251e8263187e26e58b7fa472c3f667c56aa2884f8fd1671f05e817db97",
        "identity_bff/views.py": "f75f67b669c5dd6f9c8eccdd7897cd6189ac2ef6b6642d8c1afc40471c4b4b21",
        "identity_bff/oidc.py": "0a37989b4e8d6e77d16f0a27b85be9515eea37001c305d7bd3cb46f140a6a698",
        "identity_bff/formative.py": "c3c39f499b9f9126982930ffeb4ee3bf7591716a56b622d1dba9155e51bd7a5c",
    }
    if (any(sha256(NEW / "services/identity" / name) != digest
            for name, digest in expected_staged.items())
            or sha256(NEW / "m01-reviewed-upgrade.service") != NEW_UNIT_SHA256):
        hold("STAGED_RUNTIME_SOURCE_OR_UNIT_DRIFT")
    verify_packages()


def replace_unit(content):
    """Atomically replace only the reviewed systemd unit, never edit in place."""
    descriptor, name = tempfile.mkstemp(prefix=".m01-def92-unit-", dir=UNIT.parent)
    p = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        p.chmod(0o644)
        os.replace(p, UNIT)
    finally:
        p.unlink(missing_ok=True)


def replace_current(target):
    """Atomically select an immutable release, preserving a rollback target."""
    tmp = CURRENT.parent / ".m01-def92-next"
    if tmp.exists() or tmp.is_symlink():
        hold("CURRENT_SWITCH_TEMPORARY_PATH_OCCUPIED")
    tmp.symlink_to(target)
    try:
        os.replace(tmp, CURRENT)
    finally:
        tmp.unlink(missing_ok=True)


def private_http_ready(target=NEW, *, attempts=25):
    """Prove the selected old/new private loopback HTTP, never a remote proxy."""
    with tempfile.TemporaryDirectory(prefix="m01-def92-http-") as d:
        body = str(Path(d) / "body.json")
        header = str(Path(d) / "headers")
        for _ in range(attempts):
            if service_active(SERVICE) != "active":
                hold("PRIVATE_BFF_STOPPED_BEFORE_READINESS")
            if CURRENT.resolve() == target:
                pid = int(systemd("MainPID"))
                try:
                    uid = Path(f"/proc/{pid}").stat().st_uid
                    cwd = Path(f"/proc/{pid}/cwd").resolve()
                except OSError:
                    uid, cwd = -1, Path("/")
                bind = re.findall(r"\b(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]):18740\b",
                                  command(["/usr/bin/ss", "-lntH"]))
                if uid == 994 and cwd == target / "services/identity" and bind == ["127.0.0.1:18740"]:
                    result = command([
                        "/usr/bin/curl", "--noproxy", "*", "--insecure",
                        "--silent", "--show-error", "--connect-timeout", "2",
                        "--max-time", "4",
                        "--resolve", "app.sumlaude.com:443:127.0.0.1",
                        "--dump-header", header, "--output", body,
                        "--write-out", "%{http_code}",
                        "https://app.sumlaude.com/auth/session",
                    ], timeout=8, check=False)
                    if result.returncode == 0 and result.stdout == "200":
                        if json.loads(Path(body).read_text()) != {"authenticated": False}:
                            hold("PRIVATE_BFF_ANONYMOUS_SESSION_BODY_CHANGED")
                        if "set-cookie: __host-sumlaude_session=" in Path(header).read_text().lower():
                            hold("PRIVATE_BFF_ANONYMOUS_PRODUCT_COOKIE_PRESENT")
                        return pid
            time.sleep(1)
    hold("PRIVATE_BFF_IMMUTABLE_DIRECT_ORIGIN_READINESS_TIMEOUT")


def apply_once():
    """Switch live BFF once after explicit GO; roll back ACTIVE old on failure."""
    root_operator()
    explicit_go()
    staged_proof()
    old_pid, native_pid = validate_live_before_upgrade()
    private_http_ready(OLD, attempts=2)
    if any((RECEIPTS / x).exists() for x in
           ("apply-started", "applied.json", "rollback.json")):
        hold("ONE_SHOT_APPLY_ALREADY_ATTEMPTED_NO_REPLAY")
    previous_unit = UNIT.read_bytes()
    old_link = os.readlink(CURRENT)
    write_exclusive(RECEIPTS / "previous-unit", previous_unit)
    write_exclusive(RECEIPTS / "previous-current-target", old_link.encode())
    write_exclusive(RECEIPTS / "apply-started", b"ONE_SHOT_MUTATION_START\n")
    created_go_marker = False
    started_mutation = False
    # An interrupted root upgrade must restore the previously ACTIVE BFF.
    # SIGKILL/power loss is inherently ambiguous: preserve receipts/no replay.
    prior_term = signal.getsignal(signal.SIGTERM)
    prior_int = signal.getsignal(signal.SIGINT)

    def abort_signal(signum, _frame):
        """Translate normal termination to the same controlled rollback path."""
        raise UpgradeHold("UPGRADE_OPERATOR_INTERRUPTED")

    signal.signal(signal.SIGTERM, abort_signal)
    signal.signal(signal.SIGINT, abort_signal)
    try:
        started_mutation = True
        command(["/usr/bin/systemctl", "stop", SERVICE], timeout=45)
        replace_unit((NEW / "m01-reviewed-upgrade.service").read_bytes())
        replace_current(NEW)
        if GO_MARKER.is_symlink():
            hold("GO_MARKER_UNSAFE_SYMLINK")
        if GO_MARKER.exists():
            valid_regular(GO_MARKER, uid=0, mode=0o600)
        else:
            write_exclusive(GO_MARKER, b"reviewed-canonical-bff-def92-owner-go\n")
            created_go_marker = True
        command(["/usr/bin/systemctl", "daemon-reload"])
        if (systemd("WorkingDirectory") != str(NEW / "services/identity")
                or systemd("NeedDaemonReload") != "no"
                or systemd("UnitFileState") != "enabled"
                or sha256(UNIT) != NEW_UNIT_SHA256):
            hold("NEW_SYSTEMD_UNIT_NOT_LOADED_EXACT")
        command(["/usr/bin/systemctl", "start", SERVICE], timeout=50)
        pid = private_http_ready(NEW)
        if sha256(VHOST) != OLD_VHOST_SHA256:
            hold("NGINX_PRIVATE_VHOST_CHANGED_DURING_BFF_UPGRADE")
        if int(systemd("MainPID", NATIVE)) != native_pid:
            hold("NATIVE_PID_CHANGED_DURING_BFF_UPGRADE")
        if CURRENT.resolve() != NEW or service_active(SERVICE) != "active":
            hold("NEW_RUNTIME_CHANGED_AFTER_VERIFIED_START")
        write_exclusive(RECEIPTS / "applied.json", json.dumps({
            "status": "CANONICAL_BFF_DEF92_ACTIVE_DIRECT_ORIGIN_PASS",
            "old_release": OLD_SHA, "new_release": NEW_SHA,
            "old_pid": old_pid, "new_pid": pid,
            "unit_sha256": NEW_UNIT_SHA256,
            "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "native_pid_preserved": True,
            "nginx_unchanged": True,
            "learner_features_unchanged": True,
        }, sort_keys=True).encode())
        print("M01_BFF_DEF92_IMMUTABLE_ACTIVE_UPGRADE_AND_DIRECT_HTTPS_PASS")
    except BaseException:
        # Ignore a second ordinary termination only while recovering the
        # existing active BFF. SIGKILL cannot be controlled; receipts remain.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        # Section: Only fail-closed after the old running process has stopped.
        # No SQL/data restoration is ever part of a BFF code rollback.
        if started_mutation:
            try:
                command(["/usr/bin/systemctl", "stop", SERVICE],
                        timeout=45, check=False)
                replace_unit(previous_unit)
                replace_current(Path(old_link))
                command(["/usr/bin/systemctl", "daemon-reload"])
                command(["/usr/bin/systemctl", "start", SERVICE], timeout=50)
                if (service_active(SERVICE) != "active"
                        or CURRENT.resolve() != OLD
                        or sha256(UNIT) != OLD_UNIT_SHA256):
                    hold("ROLLBACK_OLD_ACTIVE_BFF_NOT_RESTORED")
                private_http_ready(OLD, attempts=8)
                if created_go_marker:
                    GO_MARKER.unlink()
                write_exclusive(RECEIPTS / "rollback.json", json.dumps({
                    "status": "OLD_ACTIVE_BFF_RESTORED_NEW_RELEASE_NOT_SELECTED",
                    "old_release": OLD_SHA, "new_release": NEW_SHA,
                }, sort_keys=True).encode())
                print("M01_BFF_DEF92_AUTO_ROLLBACK_OLD_ACTIVE_PASS",
                      file=sys.stderr)
            except BaseException:
                print("M01_BFF_DEF92_ROLLBACK_UNCERTAIN_HOLD_NO_REPLAY",
                      file=sys.stderr)
        raise
    finally:
        signal.signal(signal.SIGTERM, prior_term)
        signal.signal(signal.SIGINT, prior_int)


def verify_installed():
    """Read-only inspect the exact already-applied live version and receipt."""
    root_operator()
    staged_proof()
    valid_regular(RECEIPTS / "applied.json", uid=0, mode=0o600)
    receipt = json.loads((RECEIPTS / "applied.json").read_text())
    if (receipt.get("status") != "CANONICAL_BFF_DEF92_ACTIVE_DIRECT_ORIGIN_PASS"
            or receipt.get("unit_sha256") != NEW_UNIT_SHA256
            or CURRENT.resolve() != NEW
            or sha256(UNIT) != NEW_UNIT_SHA256
            or systemd("WorkingDirectory") != str(NEW / "services/identity")
            or service_active(SERVICE) != "active"):
        hold("POST_APPLY_RUNTIME_OR_RECEIPT_CHANGED")
    private_http_ready()
    print("M01_BFF_DEF92_PRIVATE_RUNTIME_INDEPENDENT_VERIFY_PASS")


def main():
    """Dispatch only isolated source-read, root-stage, root-apply or verify."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("preflight", "stage", "apply", "verify"))
    args = p.parse_args()
    if args.action == "preflight":
        validate_archive()
        validate_live_before_upgrade()
        print("M01_BFF_DEF92_SOURCE_PRECHECK_PASS_NO_PROD_WRITE")
    elif args.action == "stage":
        stage_new_release()
    elif args.action == "apply":
        apply_once()
    else:
        verify_installed()


if __name__ == "__main__":
    try:
        main()
    except (UpgradeHold, OSError, ValueError, tarfile.TarError,
            json.JSONDecodeError) as exc:
        print(str(exc) if isinstance(exc, UpgradeHold)
              else "M01_ACTIVE_BFF_HOLD UNEXPECTED_FAILURE_"
                   + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

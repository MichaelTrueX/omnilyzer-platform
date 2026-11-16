"""File: deployment/analytics_prod_rootless_bootstrap.py
Purpose: One-time pinned rootless Docker prerequisite on truexmainserver.
Related: AGENTS.md, deployment/direct_dev_prod_preflight.py,
         docs/operations/analytics-prod-first-install.md.
No PROD application image, DB mutation, Nginx change, or release authorization.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.request

HOST = "truexmainserver"
USER = "omnilyzer-analytics"
HOME = Path("/var/lib/omnilyzer/analytics")
SUBID_START, SUBID_COUNT = 231072, 65536
SUBID_END = SUBID_START + SUBID_COUNT - 1
DOCKER_FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
VENDOR_SHA256 = "200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488"
APPARMOR_SHA256 = "a6a1a760d88312275d64f195e6b2f51627e8cabfdf4e355262c86f0578c66d80"
PACKAGES = (
    "containerd.io=2.3.6-1~ubuntu.24.04~noble",
    "docker-ce=5:29.8.1-1~ubuntu.24.04~noble",
    "docker-ce-cli=5:29.8.1-1~ubuntu.24.04~noble",
    "docker-ce-rootless-extras=5:29.8.1-1~ubuntu.24.04~noble",
    "docker-compose-plugin=5.5.1-1~ubuntu.24.04~noble",
    "uidmap=1:4.13+dfsg1-4ubuntu3.2",
    "slirp4netns=1.2.1-1build2",
)
ROOTFUL_UNITS = ("docker.service", "docker.socket", "containerd.service")
KEY = Path("/etc/apt/keyrings/omnilyzer-docker.asc")
SOURCE = Path("/etc/apt/sources.list.d/omnilyzer-docker.sources")
APPARMOR = Path("/etc/apparmor.d/rootlesskit")
UNIT = Path("/etc/systemd/user/omnilyzer-analytics-docker.service")
WANTS = Path("/etc/systemd/user/default.target.wants/omnilyzer-analytics-docker.service")
CONFIG = Path("/etc/omnilyzer/analytics/docker/daemon.json")
MARKER = Path("/var/lib/omnilyzer/analytics-bootstrap-v1.json")
SOURCE_TEXT = (
    "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\n"
    "Suites: noble\nComponents: stable\nArchitectures: amd64\n"
    "Signed-By: /etc/apt/keyrings/omnilyzer-docker.asc\n"
)
UNIT_TEXT = """# File: /etc/systemd/user/omnilyzer-analytics-docker.service
# Purpose: Dedicated non-root Analytics Docker daemon. No TCP listener.
# Related: deployment/analytics_prod_rootless_bootstrap.py.
[Unit]
Description=Omnilyzer Analytics PROD rootless Docker
Requires=dbus.socket
After=dbus.socket
ConditionUser=omnilyzer-analytics

[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/bin/dockerd-rootless.sh --host=unix://%t/docker.sock --data-root=/var/lib/omnilyzer/analytics/docker-data --exec-root=%t/docker-exec --pidfile=%t/docker.pid --config-file=/etc/omnilyzer/analytics/docker/daemon.json --storage-driver=overlay2 --group=0
Restart=on-failure
RestartSec=5s
TimeoutStartSec=90s
TimeoutStopSec=30s
KillMode=mixed
Delegate=yes
UMask=0077
Environment=HOME=/var/lib/omnilyzer/analytics
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS=--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns"

[Install]
WantedBy=default.target
"""
RUN_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
    "LANG": "C", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive",
    "APT_LISTCHANGES_FRONTEND": "none", "NEEDRESTART_MODE": "l",
}


def run(*argv: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run fixed argv without shell interpolation or inherited environment."""
    result = subprocess.run(
        argv, env=RUN_ENV, stdin=subprocess.DEVNULL, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} exit={result.returncode}: {result.stderr[-1500:]}")
    return result


def subid_conflicts(path: Path) -> list[str]:
    """Collect every collision with the dedicated Analytics subordinate range."""
    errors: list[str] = []
    for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        fields = line.split(":")
        try:
            if len(fields) != 3:
                raise ValueError("invalid fields")
            start, count = int(fields[1]), int(fields[2])
            if start < 0 or count <= 0:
                raise ValueError("invalid range")
        except ValueError:
            errors.append(f"{path.name} line {number}: invalid mapping")
            continue
        if start <= SUBID_END and SUBID_START <= start + count - 1:
            errors.append(f"{path.name} line {number}: overlapping mapping")
    return errors


def host_id_conflicts() -> list[str]:
    """Reject subordinate IDs already used by actual host users or groups."""
    errors: list[str] = []
    for account in pwd.getpwall():
        if SUBID_START <= account.pw_uid <= SUBID_END:
            errors.append(f"host UID overlap: {account.pw_name}")
        if SUBID_START <= account.pw_gid <= SUBID_END:
            errors.append(f"host primary GID overlap: {account.pw_name}")
    for group in grp.getgrall():
        if SUBID_START <= group.gr_gid <= SUBID_END:
            errors.append(f"host GID overlap: {group.gr_name}")
    return errors


def valid_docker_key_listing(listing: str) -> bool:
    """Accept one pinned primary Docker signing key, with optional subkeys."""
    lines = listing.splitlines()
    primary = [line for line in lines if line.startswith("pub:")]
    fingerprints = [
        line.split(":")[9] for line in lines
        if line.startswith("fpr:") and len(line.split(":")) > 9
    ]
    return len(primary) == 1 and bool(fingerprints) and fingerprints[0] == DOCKER_FINGERPRINT


def preflight() -> None:
    """Report independent mismatches together before any privileged mutation."""
    errors: list[str] = []
    if socket.gethostname().split(".")[0] != HOST:
        errors.append("wrong host")
    if platform.machine() != "x86_64":
        errors.append("unsupported architecture")
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        errors.append("unsupported operating system")
    try:
        pwd.getpwnam(USER)
        errors.append("service user exists; no automatic retry")
    except KeyError:
        pass
    for path in (KEY, SOURCE, UNIT, WANTS, CONFIG, MARKER, HOME):
        if os.path.lexists(path):
            errors.append(f"pre-existing managed path: {path}")
    for parent in (UNIT.parent, WANTS.parent):
        if os.path.lexists(parent):
            found = os.lstat(parent)
            if (not stat.S_ISDIR(found.st_mode) or found.st_uid != 0
                    or found.st_gid != 0 or stat.S_IMODE(found.st_mode) != 0o755):
                errors.append(f"unsafe root-owned systemd directory: {parent}")
    # PROD already has the exact DEV-approved rootlesskit AppArmor profile.
    # Reuse it without overwriting unrelated security configuration.
    try:
        profile = os.lstat(APPARMOR)
        if (not stat.S_ISREG(profile.st_mode) or profile.st_uid != 0
                or profile.st_gid != 0 or stat.S_IMODE(profile.st_mode) != 0o644
                or profile.st_nlink != 1
                or hashlib.sha256(APPARMOR.read_bytes()).hexdigest() != APPARMOR_SHA256):
            errors.append("existing rootlesskit AppArmor profile differs")
    except OSError:
        errors.append("approved rootlesskit AppArmor profile missing")
    for binary in ("/usr/bin/docker", "/usr/bin/dockerd", "/usr/bin/rootlesskit"):
        if os.path.lexists(binary):
            errors.append(f"existing container runtime: {binary}")
    if os.path.lexists("/var/run/docker.sock"):
        errors.append("existing rootful Docker socket")
    for unit in ROOTFUL_UNITS:
        active = run("/usr/bin/systemctl", "is-active", unit, check=False)
        if active.stdout.strip() not in {"inactive", "unknown"}:
            errors.append(f"rootful unit state differs: {unit}")
        enabled = run("/usr/bin/systemctl", "is-enabled", unit, check=False)
        if enabled.stdout.strip() not in {"not-found", "disabled", ""}:
            errors.append(f"existing rootful unit configuration: {unit}")
    for path in (Path("/etc/subuid"), Path("/etc/subgid")):
        try:
            errors.extend(subid_conflicts(path))
        except (OSError, UnicodeError):
            errors.append(f"cannot inspect {path}")
    errors.extend(host_id_conflicts())
    for port in (3141, 3142):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                errors.append(f"private port {port} occupied")
    available_kb = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            available_kb = int(line.split()[1])
    if available_kb < 1024 * 1024:
        errors.append("less than 1 GiB available memory")
    if shutil.disk_usage("/").free < 12 * 1024**3:
        errors.append("less than 12 GiB available disk")
    if errors:
        for error in errors:
            print(f"PROD_ROOTLESS_PREFLIGHT_FAIL {error}", file=sys.stderr)
        raise RuntimeError(f"preflight rejected {len(errors)} condition(s)")
    print("PROD_ROOTLESS_FIRST_INSTALL_PREFLIGHT_PASS")


def write_new(path: Path, content: bytes, mode: int) -> None:
    """Create a new file exclusively without following symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        # Enforce the reviewed mode independently of the caller's umask
        # for apt, systemd, daemon configuration and the private marker.
        os.fchmod(stream.fileno(), mode)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def user_command(uid: int, *command: str) -> subprocess.CompletedProcess[str]:
    """Run systemd or Docker only as the dedicated unprivileged service user."""
    return run(
        "/usr/sbin/runuser", "-u", USER, "--", "/usr/bin/env",
        f"HOME={HOME}", f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        f"DOCKER_HOST=unix:///run/user/{uid}/docker.sock",
        *command, timeout=90,
    )


def install() -> None:
    """Install pinned rootless prerequisites, never a production application."""
    if os.geteuid() != 0:
        raise RuntimeError("root required for --apply")
    preflight()
    # Public apt/systemd parent directories must remain traversable by the
    # service user. The temporary directory is independently mode 0700.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="analytics-prod-docker-", dir="/var/tmp") as temp:
        key_file = Path(temp) / "docker.asc"
        with urllib.request.urlopen(
            "https://download.docker.com/linux/ubuntu/gpg", timeout=20
        ) as response:
            key_data = response.read(100001)
        if len(key_data) > 100000:
            raise RuntimeError("Docker signing key too large")
        key_file.write_bytes(key_data)
        key_result = run("/usr/bin/gpg", "--batch", "--show-keys", "--with-colons", str(key_file))
        if not valid_docker_key_listing(key_result.stdout):
            raise RuntimeError("Docker signing-key bundle differs from one pinned primary key")
        # Prevent vendor post-install scripts from starting rootful services.
        run("/usr/bin/systemctl", "mask", "--now", *ROOTFUL_UNITS)
        write_new(KEY, key_data, 0o644)
        write_new(SOURCE, SOURCE_TEXT.encode("ascii"), 0o644)
        run("/usr/bin/apt-get", "update", timeout=180)
        run(
            "/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confold", *PACKAGES, timeout=600,
        )
    for spec in PACKAGES:
        name, version = spec.split("=", 1)
        found = run("/usr/bin/dpkg-query", "-W", "-f=${Version}", name).stdout.strip()
        if found != version:
            raise RuntimeError(f"installed package differs: {name}")
    vendor = Path("/usr/bin/dockerd-rootless.sh")
    if hashlib.sha256(vendor.read_bytes()).hexdigest() != VENDOR_SHA256:
        raise RuntimeError("rootless Docker vendor script differs from DEV")
    # The exact approved root-owned profile was verified by preflight.
    run("/usr/sbin/apparmor_parser", "-r", str(APPARMOR))
    Path("/var/lib/omnilyzer").mkdir(mode=0o755, exist_ok=True)
    run(
        "/usr/sbin/useradd", "--system", "--no-create-home", "--user-group",
        "--home-dir", str(HOME), "--shell", "/usr/sbin/nologin", USER,
    )
    run(
        "/usr/sbin/usermod", "--add-subuids", f"{SUBID_START}-{SUBID_END}",
        "--add-subgids", f"{SUBID_START}-{SUBID_END}", USER,
    )
    account = pwd.getpwnam(USER)
    for path in (Path("/etc/subuid"), Path("/etc/subgid")):
        lines = path.read_text(encoding="ascii").splitlines()
        mappings = [line for line in lines if line.startswith(f"{USER}:")]
        if mappings != [f"{USER}:{SUBID_START}:{SUBID_COUNT}"]:
            raise RuntimeError(f"service user subordinate IDs differ: {path}")
    finish_service_install(account)



def finish_service_install(account: pwd.struct_passwd) -> None:
    """Finish only the post-user creation stage, without packages or useradd."""
    # Prevent persistent user-unit overrides under ~/.config or ~/.local.
    # The vendor rootless launcher only requires HOME to exist; all daemon
    # writes use the explicit data-root and XDG_RUNTIME_DIR paths.
    HOME.mkdir(mode=0o755, exist_ok=True)
    os.chown(HOME, 0, 0)
    data = HOME / "docker-data"
    data.mkdir(mode=0o700)
    os.chown(data, account.pw_uid, account.pw_gid)
    CONFIG.parent.mkdir(parents=True, mode=0o755)
    write_new(CONFIG, b'{"features":{"containerd-snapshotter":false}}\n', 0o644)
    # The user manager reads this unit from the root-owned global user-unit
    # directory, not from the service account's writable home directory.
    write_new(UNIT, UNIT_TEXT.encode("utf-8"), 0o644)
    WANTS.parent.mkdir(mode=0o755, exist_ok=True)
    WANTS.symlink_to("../omnilyzer-analytics-docker.service")
    run("/usr/bin/loginctl", "enable-linger", USER)
    run("/usr/bin/systemctl", "start", f"user@{account.pw_uid}.service")
    user_command(account.pw_uid, "/usr/bin/systemctl", "--user", "daemon-reload")
    user_command(account.pw_uid, "/usr/bin/systemctl", "--user", "start", "omnilyzer-analytics-docker.service")
    result = user_command(
        account.pw_uid, "/usr/bin/docker", "info",
        "--format", "{{json .SecurityOptions}}",
    )
    security = json.loads(result.stdout)
    if not any("rootless" in item for item in security):
        raise RuntimeError("Docker runtime did not prove rootless mode")
    for unit in ROOTFUL_UNITS:
        state = run("/usr/bin/systemctl", "is-active", unit, check=False).stdout.strip()
        if state not in {"inactive", "unknown"}:
            raise RuntimeError(f"rootful unit unexpectedly active: {unit}")
    if os.path.lexists("/var/run/docker.sock"):
        raise RuntimeError("unexpected rootful Docker socket")
    write_new(
        MARKER,
        (json.dumps({
            "version": 1, "user": USER, "uid": account.pw_uid,
            "rootless": True, "prod_application_installed": False,
        }, sort_keys=True) + "\n").encode("ascii"),
        0o600,
    )
    print(f"PROD_ROOTLESS_BOOTSTRAP_PASS uid={account.pw_uid} public_routes=unchanged app=not-installed")



# This recovery is valid only for the specific consumed 16 Nov first-install run.
ORIGINAL_INSTALLER = Path("/usr/local/sbin/omnilyzer-analytics-prod-bootstrap")
ORIGINAL_INSTALLER_SHA256 = "e0d596ba51222d3aa293bfec508dfc58ebdf55714607959e8d38aedd20d0bdd8"
PARTIAL_APT_KEY_SHA256 = "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
PARTIAL_APT_SOURCE_SHA256 = "9899af3a25fe17e73f325b0f8a2802511517be377c0ca9476e50bd61ddeb8903"
PARTIAL_UID, PARTIAL_GID = 990, 982


def check_consumed_partial_install() -> pwd.struct_passwd:
    """Fail closed unless the already consumed installer stopped at user creation."""
    if os.geteuid() != 0:
        raise RuntimeError("partial-state inspection requires root")
    errors: list[str] = []
    if socket.gethostname().split(".")[0] != HOST:
        errors.append("wrong host")
    if platform.machine() != "x86_64":
        errors.append("wrong architecture")
    try:
        account = pwd.getpwnam(USER)
        group = grp.getgrnam(USER)
        if (account.pw_uid, account.pw_gid, account.pw_dir, account.pw_shell) != (
                PARTIAL_UID, PARTIAL_GID, str(HOME), "/usr/sbin/nologin"):
            errors.append("service account identity mismatch")
        if group.gr_gid != PARTIAL_GID or group.gr_mem:
            errors.append("service group mismatch")
    except KeyError:
        account = None
        errors.append("expected service identity is absent")

    # Verify immutable root custody, unchanged package/repository trust and
    # original consumed first-install source before touching any new state.
    for path, digest, mode in (
        (ORIGINAL_INSTALLER, ORIGINAL_INSTALLER_SHA256, 0o500),
        (KEY, PARTIAL_APT_KEY_SHA256, 0o644),
        (SOURCE, PARTIAL_APT_SOURCE_SHA256, 0o644),
        (APPARMOR, APPARMOR_SHA256, 0o644),
    ):
        try:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != mode
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                errors.append(f"root-owned source differs: {path}")
        except OSError:
            errors.append(f"root-owned source missing: {path}")
    for spec in PACKAGES:
        name, version = spec.split("=", 1)
        found = run("/usr/bin/dpkg-query", "-W", "-f=" + chr(36) + "{Version}", name, check=False)
        if found.returncode or found.stdout.strip() != version:
            errors.append(f"package differs: {name}")
    audit = run("/usr/bin/dpkg", "--audit", check=False)
    if audit.returncode or audit.stdout.strip():
        errors.append("dpkg has incomplete package state")
    try:
        if hashlib.sha256(Path("/usr/bin/dockerd-rootless.sh").read_bytes()).hexdigest() != VENDOR_SHA256:
            errors.append("Docker rootless launcher differs")
    except OSError:
        errors.append("Docker rootless launcher missing")
    for unit in ROOTFUL_UNITS:
        enabled = run("/usr/bin/systemctl", "is-enabled", unit, check=False)
        active = run("/usr/bin/systemctl", "is-active", unit, check=False)
        if enabled.stdout.strip() != "masked" or active.stdout.strip() != "inactive":
            errors.append(f"rootful service unexpected state: {unit}")
    if os.path.lexists("/var/run/docker.sock"):
        errors.append("rootful Docker socket unexpectedly present")

    # Absolutely no post-user stage may have started. A subsequent partial
    # failure is a new HOLD, not permission to replay this continuation.
    for path in (HOME / "docker-data", CONFIG, UNIT, WANTS, MARKER):
        if os.path.lexists(path):
            errors.append(f"post-user setup already started: {path}")
    try:
        info = os.lstat(HOME)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755
                or any(HOME.iterdir())):
            errors.append("service HOME is not the original empty root-owned directory")
    except OSError:
        errors.append("partial service HOME missing")
    for parent in (Path("/var/lib/omnilyzer"), UNIT.parent):
        try:
            info = os.lstat(parent)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755):
                errors.append(f"unsafe parent: {parent}")
        except OSError:
            errors.append(f"missing parent: {parent}")
    for subid in (Path("/etc/subuid"), Path("/etc/subgid")):
        try:
            lines = subid.read_text(encoding="ascii").splitlines()
            ours = [line for line in lines if line.startswith(f"{USER}:")]
            if ours != [f"{USER}:{SUBID_START}:{SUBID_COUNT}"]:
                errors.append(f"subordinate ID mismatch: {subid}")
            for line in lines:
                if line.startswith(f"{USER}:"):
                    continue
                entries = line.split(":")
                if len(entries) != 3:
                    errors.append(f"invalid subordinate ID entry: {subid}")
                    continue
                try:
                    low, count = int(entries[1]), int(entries[2])
                    if count <= 0 or (low <= SUBID_END and low + count - 1 >= SUBID_START):
                        errors.append(f"external subordinate ID collision: {subid}")
                except ValueError:
                    errors.append(f"malformed subordinate ID: {subid}")
        except OSError:
            errors.append(f"cannot read subordinate IDs: {subid}")
    errors.extend(host_id_conflicts())
    manager = run("/usr/bin/systemctl", "is-active", f"user@{PARTIAL_UID}.service", check=False)
    if manager.stdout.strip() not in ("inactive", "unknown"):
        errors.append("service user manager already active")
    if os.path.lexists(Path("/var/lib/systemd/linger") / USER):
        errors.append("service user lingering already enabled")
    for port in (3141, 3142):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                errors.append(f"private port occupied: {port}")

    if errors:
        for error in errors:
            print(f"PROD_ROOTLESS_PARTIAL_RECOVERY_HOLD {error}", file=sys.stderr)
        raise RuntimeError(f"partial-state preflight rejected {len(errors)} mismatch(es)")
    if account is None:
        raise RuntimeError("missing account despite passed preflight")
    print(f"PROD_ROOTLESS_PARTIAL_RECOVERY_PREFLIGHT_PASS uid={PARTIAL_UID}")
    return account


def resume_after_user_created() -> None:
    """Continue only the exact unfinished post-user stage, not the root installer."""
    account = check_consumed_partial_install()
    os.umask(0o022)
    finish_service_install(account)



def main() -> int:
    """Offer read-only qualification or one explicit root-only installation."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--check-partial", action="store_true")
    mode.add_argument("--resume-after-user", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            preflight()
        elif args.apply:
            install()
        elif args.check_partial:
            check_consumed_partial_install()
        else:
            resume_after_user_created()
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"PROD_ROOTLESS_HOLD_NO_AUTOMATIC_RETRY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""File: deployment/analytics_prod_rootless_bootstrap.py
Purpose: One-time pinned rootless Docker prerequisite on truexmainserver.
Related: AGENTS.md, deployment/direct_dev_prod_preflight.py,
         docs/operations/analytics-prod-first-install.md.
No PROD application image, DB mutation, Nginx change, or release authorization.
"""
from __future__ import annotations

import argparse
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
UNIT = HOME / ".config/systemd/user/docker.service"
CONFIG = Path("/etc/omnilyzer/analytics/docker/daemon.json")
MARKER = Path("/var/lib/omnilyzer/analytics-bootstrap-v1.json")
SOURCE_TEXT = (
    "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\n"
    "Suites: noble\nComponents: stable\nArchitectures: amd64\n"
    "Signed-By: /etc/apt/keyrings/omnilyzer-docker.asc\n"
)
UNIT_TEXT = """# File: /var/lib/omnilyzer/analytics/.config/systemd/user/docker.service
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
    for path in (KEY, SOURCE, UNIT, CONFIG, MARKER, HOME):
        if os.path.lexists(path):
            errors.append(f"pre-existing managed path: {path}")
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
        fingerprints = [
            line.split(":")[9] for line in key_result.stdout.splitlines()
            if line.startswith("fpr:")
        ]
        if not fingerprints or fingerprints[0] != DOCKER_FINGERPRINT:
            raise RuntimeError("Docker signing-key fingerprint mismatch")
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
        "/usr/sbin/useradd", "--system", "--create-home", "--user-group",
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
    HOME.chmod(0o700)
    HOME.chown(account.pw_uid, account.pw_gid)
    data = HOME / "docker-data"
    data.mkdir(mode=0o700)
    data.chown(account.pw_uid, account.pw_gid)
    CONFIG.parent.mkdir(parents=True, mode=0o755)
    write_new(CONFIG, b'{"features":{"containerd-snapshotter":false}}\n', 0o644)
    UNIT.parent.mkdir(parents=True, mode=0o755)
    write_new(UNIT, UNIT_TEXT.encode("utf-8"), 0o644)
    # Keep the user unit and its enablement root-owned; the service user
    # can start the daemon but cannot rewrite its startup configuration.
    wants = UNIT.parent / "default.target.wants"
    wants.mkdir(mode=0o755)
    (wants / "docker.service").symlink_to("../docker.service")
    run("/usr/bin/loginctl", "enable-linger", USER)
    run("/usr/bin/systemctl", "start", f"user@{account.pw_uid}.service")
    user_command(account.pw_uid, "/usr/bin/systemctl", "--user", "daemon-reload")
    user_command(account.pw_uid, "/usr/bin/systemctl", "--user", "start", "docker.service")
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


def main() -> int:
    """Offer read-only qualification or one explicit root-only installation."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        preflight() if args.check else install()
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"PROD_ROOTLESS_HOLD_NO_AUTOMATIC_RETRY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

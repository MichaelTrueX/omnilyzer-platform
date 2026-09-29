"""Closed executor-owned launch of Docker's pinned vendor rootless bootstrap.

Install this file root-owned at the unit's fixed ExecStart path. The package
script, rather than this launcher, owns RootlessKit and namespace setup.
"""

from __future__ import annotations

import errno
import hashlib
import os
import socket
import stat
import sys


UID = GID = 991
RUNTIME = "/run/user/991"
HOME = "/var/lib/omnilyzer/deployment/rootless-home"
DATA = "/var/lib/omnilyzer/deployment/rootless-docker-data"
CONFIG = "/etc/omnilyzer/deployment/rootless-docker/daemon.json"
VENDOR_SCRIPT = "/usr/bin/dockerd-rootless.sh"
VENDOR_SCRIPT_SHA256 = "200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488"
ROOTLESSKIT_STATE = "/run/user/991/dockerd-rootless"
CONTAINERD_ROOTLESS_STATE = "/run/user/991/containerd-rootless"
SOCKET = "unix:///run/user/991/docker.sock"
EXEC_ROOT = "/run/user/991/docker-exec"
PID_FILE = "/run/user/991/docker.pid"
DAEMON_CONFIG_BYTES = b'{"features":{"containerd-snapshotter":false}}\n'
ROOTLESSKIT_FLAGS = "--subid-source=static --slirp4netns-binary=/usr/bin/slirp4netns"


def _directory(path: str, uid: int, gid: int, mode: int) -> None:
    found = os.lstat(path)
    if (not stat.S_ISDIR(found.st_mode) or found.st_uid != uid
            or found.st_gid != gid or stat.S_IMODE(found.st_mode) != mode):
        raise RuntimeError("rootless Docker resource authority differs")


def _file(path: str, uid: int, gid: int, mode: int) -> None:
    found = os.lstat(path)
    if (not stat.S_ISREG(found.st_mode) or found.st_nlink != 1
            or found.st_uid != uid or found.st_gid != gid
            or stat.S_IMODE(found.st_mode) != mode):
        raise RuntimeError("rootless Docker resource authority differs")


def _rootlesskit_state() -> None:
    try:
        found = os.lstat(ROOTLESSKIT_STATE)
    except FileNotFoundError:
        return
    if (not stat.S_ISDIR(found.st_mode) or found.st_uid != UID
            or found.st_gid != GID or stat.S_IMODE(found.st_mode) != 0o700):
        raise RuntimeError("rootless Docker state authority differs")
    # RootlessKit owns its lock and stale-state cleanup. Never remove it here.


def _socket_identity(found: os.stat_result) -> None:
    if (not stat.S_ISSOCK(found.st_mode) or found.st_uid != UID
            or found.st_gid != GID or stat.S_IMODE(found.st_mode) != 0o660
            or found.st_nlink != 1):
        raise RuntimeError("rootless Docker socket authority differs")


def _check_daemon_socket() -> None:
    try:
        found = os.lstat(RUNTIME + "/docker.sock")
    except FileNotFoundError:
        return
    _socket_identity(found)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.5)
            probe.connect(RUNTIME + "/docker.sock")
    except OSError as exc:
        if exc.errno != errno.ECONNREFUSED:
            raise RuntimeError("rootless Docker socket status is ambiguous") from None
        # Possibly stale, or a daemon has not entered listen() yet. Do not
        # unlink: RootlessKit's vendor lock must decide concurrency first.
        return
    else:
        raise RuntimeError("rootless Docker socket has a live owner")


def main() -> None:
    if len(sys.argv) != 1:
        raise RuntimeError("rootless Docker launcher accepts no arguments")
    groups = os.getgroups()
    if (os.geteuid() != UID or os.getegid() != GID
            or len(groups) != len(set(groups))
            or set(groups) not in ({992}, {991, 992})):
        raise RuntimeError("rootless Docker principal differs")
    _directory(RUNTIME, UID, GID, 0o700)  # Verify logind's runtime; never create it.
    _directory(HOME, UID, GID, 0o700)
    _directory(DATA, UID, GID, 0o700)
    _directory("/etc/omnilyzer/deployment/rootless-docker", 0, 0, 0o755)
    _file(CONFIG, 0, 0, 0o644)
    with open(CONFIG, "rb") as source:
        if source.read() != DAEMON_CONFIG_BYTES:
            raise RuntimeError("rootless Docker daemon configuration differs")
    _file(VENDOR_SCRIPT, 0, 0, 0o755)
    with open(VENDOR_SCRIPT, "rb") as source:
        if hashlib.sha256(source.read()).hexdigest() != VENDOR_SCRIPT_SHA256:
            raise RuntimeError("rootless Docker vendor bootstrap differs")
    # The vendor script searches PATH for docker-rootlesskit before rootlesskit.
    # Reject a higher-priority executable rather than accept another bootstrap.
    if any(os.path.lexists(path) for path in (
        "/usr/sbin/docker-rootlesskit", "/usr/bin/docker-rootlesskit",
        "/bin/docker-rootlesskit", "/usr/sbin/rootlesskit",
    )):
        raise RuntimeError("rootless Docker binary selection differs")
    _file("/usr/bin/rootlesskit", 0, 0, 0o755)
    _file("/usr/bin/dockerd", 0, 0, 0o755)
    _file("/usr/bin/slirp4netns", 0, 0, 0o755)
    _rootlesskit_state()
    _check_daemon_socket()
    if os.path.lexists(CONTAINERD_ROOTLESS_STATE):
        raise RuntimeError("separate rootless containerd state conflicts")
    if os.environ.get("NOTIFY_SOCKET") != "/run/user/991/systemd/notify":
        raise RuntimeError("rootless Docker user-manager notification differs")
    environment = {
        "HOME": HOME,
        "XDG_RUNTIME_DIR": RUNTIME,
        "PATH": "/usr/bin:/usr/sbin:/bin",
        "LANG": "C.UTF-8",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/991/bus",
        "NOTIFY_SOCKET": "/run/user/991/systemd/notify",
        "DOCKERD": "/usr/bin/dockerd",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": ROOTLESSKIT_STATE,
        "CONTAINERD_ROOTLESS_ROOTLESSKIT_STATE_DIR": CONTAINERD_ROOTLESS_STATE,
        "DOCKERD_ROOTLESS_ROOTLESSKIT_NET": "slirp4netns",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_MTU": "65520",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER": "builtin",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX": "auto",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP": "auto",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK": "true",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS": "true",
        "DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS": ROOTLESSKIT_FLAGS,
    }
    os.execve(VENDOR_SCRIPT, (
        VENDOR_SCRIPT, "--host=" + SOCKET, "--data-root=" + DATA,
        "--exec-root=" + EXEC_ROOT, "--pidfile=" + PID_FILE,
        "--config-file=" + CONFIG, "--exec-opt=native.cgroupdriver=systemd",
        "--storage-driver=overlay2", "--group=0",
    ), environment)


if __name__ == "__main__":
    main()

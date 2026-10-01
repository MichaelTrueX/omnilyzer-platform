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
import uuid


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
SOCKET_MODE = 0o1660
DATA_INITIAL_MODE = 0o700
DATA_MANAGED_MODE = 0o710
DATA_MANAGED_ENTRIES = (
    ("buildkit", "directory", 0o711),
    ("containerd", "directory", 0o700),
    ("containers", "directory", 0o710),
    ("engine-id", "file", 0o600),
    ("image", "directory", 0o700),
    ("network", "directory", 0o750),
    ("overlay2", "directory", 0o710),
    ("plugins", "directory", 0o700),
    ("runtimes", "directory", 0o700),
    ("swarm", "directory", 0o700),
    ("tmp", "directory", 0o700),
    ("volumes", "directory", 0o701),
)
ENGINE_ID_SIZE = 36


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


def _data_root() -> None:
    named = os.lstat(DATA)
    if (not stat.S_ISDIR(named.st_mode) or named.st_uid != UID
            or named.st_gid != GID):
        raise RuntimeError("rootless Docker data-root authority differs")

    mode = stat.S_IMODE(named.st_mode)
    if mode not in {DATA_INITIAL_MODE, DATA_MANAGED_MODE}:
        raise RuntimeError("rootless Docker data-root authority differs")

    descriptor = os.open(
        DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_uid != UID or opened.st_gid != GID
                or stat.S_IMODE(opened.st_mode) != mode):
            raise RuntimeError("rootless Docker data-root authority differs")

        names = frozenset(os.listdir(descriptor))
        if mode == DATA_INITIAL_MODE:
            if names or frozenset(os.listdir(descriptor)):
                raise RuntimeError("rootless Docker initial data root is not empty")
            final = os.fstat(descriptor)
            if (
                (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
                or final.st_uid != UID
                or final.st_gid != GID
                or stat.S_IMODE(final.st_mode) != DATA_INITIAL_MODE
            ):
                raise RuntimeError("rootless Docker data-root authority differs")
            return

        expected = {name: (kind, item_mode)
                    for name, kind, item_mode in DATA_MANAGED_ENTRIES}
        if names != frozenset(expected):
            raise RuntimeError("rootless Docker managed data root differs")

        for name, (kind, item_mode) in expected.items():
            child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (child.st_uid != UID or child.st_gid != GID
                    or stat.S_IMODE(child.st_mode) != item_mode):
                raise RuntimeError("rootless Docker managed data root differs")
            if kind == "directory":
                if not stat.S_ISDIR(child.st_mode):
                    raise RuntimeError("rootless Docker managed data root differs")
            elif kind == "file":
                if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                    raise RuntimeError("rootless Docker managed data root differs")
            else:
                raise RuntimeError("rootless Docker managed data root differs")

            if name == "engine-id":
                if child.st_size != ENGINE_ID_SIZE:
                    raise RuntimeError("rootless Docker engine identity differs")
                file_descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                try:
                    data = os.read(file_descriptor, ENGINE_ID_SIZE + 1)
                    if len(data) != ENGINE_ID_SIZE:
                        raise RuntimeError("rootless Docker engine identity differs")
                    try:
                        text = data.decode("ascii")
                        parsed = uuid.UUID(text)
                    except (UnicodeDecodeError, ValueError):
                        raise RuntimeError("rootless Docker engine identity differs") from None
                    if str(parsed) != text:
                        raise RuntimeError("rootless Docker engine identity differs")
                finally:
                    os.close(file_descriptor)

        if frozenset(os.listdir(descriptor)) != frozenset(expected):
            raise RuntimeError("rootless Docker managed data root differs")
        final = os.fstat(descriptor)
        if ((final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
                or final.st_uid != UID or final.st_gid != GID
                or stat.S_IMODE(final.st_mode) != mode):
            raise RuntimeError("rootless Docker data-root authority differs")
    finally:
        os.close(descriptor)


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
            or found.st_gid != GID or stat.S_IMODE(found.st_mode) != SOCKET_MODE
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
    _data_root()
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

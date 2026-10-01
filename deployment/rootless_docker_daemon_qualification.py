"""deployment/rootless_docker_daemon_qualification.py - C33F proof.

Purpose:
- independently qualify the running UID-991 rootless Docker daemon after C33E;
- re-prove the immutable package/account/systemd authority while allowing the
  exact reviewed rootless runtime;
- prove exact user-unit state, RootlessKit authority, dockerd argv, Unix socket
  identity, Docker engine configuration and empty pre-workload inventory;
- keep the user unit disabled and broker/executor/deployment inactive.

C33F is fully read-only and does not import the C33E mutator.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import socket
import stat
import subprocess
import uuid

from . import rootless_docker_user_manager_qualification as userq
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
)


__all__ = (
    "RootlessDockerDaemonQualificationError",
    "RootlessDockerDaemonEvidence",
    "qualify_rootless_docker_daemon",
)

_ERROR = "rootless Docker daemon qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_DOCKER = AUTHORITY.docker_cli
_TIMEOUT = 5.0
_DOCKER_TIMEOUT = 15.0
_OUTPUT_LIMIT = 1024 * 1024
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_DEPLOYMENT_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.service",
    "omnilyzer-deployment-executor.socket",
)
_USER_UNIT_ENABLE_LINK = (
    "/etc/systemd/user/default.target.wants/" + _USER_UNIT
)
_EXPECTED_DOCKERD_ARGV = (
    AUTHORITY.dockerd,
    "--host=unix://" + AUTHORITY.daemon_socket,
    "--data-root=" + AUTHORITY.data_root,
    "--exec-root=" + AUTHORITY.exec_root,
    "--pidfile=" + AUTHORITY.pid_file,
    "--config-file=" + AUTHORITY.daemon_config,
    "--exec-opt=native.cgroupdriver=systemd",
    "--storage-driver=overlay2",
    "--group=0",
)
_REQUIRED_ROOTLESSKIT_TOKENS = frozenset(
    {
        "--state-dir=" + AUTHORITY.rootlesskit_state,
        "--net=slirp4netns",
        "--mtu=65520",
        "--port-driver=builtin",
        "--slirp4netns-sandbox=auto",
        "--slirp4netns-seccomp=auto",
        "--disable-host-loopback",
        "--copy-up=/etc",
        "--copy-up=/run",
        "--propagation=rslave",
        "--detach-netns",
        "--subid-source=static",
        "--slirp4netns-binary=/usr/bin/slirp4netns",
        AUTHORITY.vendor_rootless_script,
    }
)
_DOCKER_INFO_KEYS = frozenset(
    {
        "ServerVersion",
        "Driver",
        "DockerRootDir",
        "CgroupDriver",
        "CgroupVersion",
        "SecurityOptions",
        "Containers",
        "ContainersRunning",
        "ContainersPaused",
        "ContainersStopped",
        "Images",
        "LiveRestoreEnabled",
        "Swarm",
    }
)


class RootlessDockerDaemonQualificationError(Exception):
    """One fixed external failure for the C33F read-only boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerDaemonEvidence:
    """Exact daemon evidence observed twice without mutation."""

    application_reviewed_commit: str
    expected_workflow_sha: str
    user_unit_state: tuple[str, str, str, str]
    user_unit_fragment: str
    user_unit_main_pid: int
    rootlesskit_pid: int
    rootlesskit_argv: tuple[str, ...]
    dockerd_pid: int
    dockerd_argv: tuple[str, ...]
    daemon_socket: str
    socket_uid: int
    socket_gid: int
    socket_mode: int
    rootlesskit_state: tuple[str, int, int, int]
    server_version: str
    storage_driver: str
    docker_root_dir: str
    cgroup_driver: str
    cgroup_version: str
    security_options: tuple[str, ...]
    containers: tuple[int, int, int, int]
    images: int
    linger_mode: int
    runtime_directory: tuple[str, int, int, int]
    user_manager_control_group: str
    delegate_controllers: tuple[str, ...]
    subuid_records: tuple[tuple[str, int, int], ...]
    subgid_records: tuple[tuple[str, int, int], ...]
    directories: tuple[tuple[str, int, int, int], ...]
    assets: tuple[tuple[str, str, int, int, int], ...]
    packages: tuple[tuple[str, str, str], ...]
    host_dependencies: tuple[tuple[str, str, str], ...]
    masked_units: tuple[str, ...]
    critical_executables: tuple[tuple[str, str, int, str], ...]
    cgroup_controllers: tuple[str, ...]
    executor_dropins: tuple[str, ...]
    user_manager_dropins: tuple[str, ...]
    bundle: RootlessDockerPackageBundleEvidence

    def __post_init__(self) -> None:
        expected_packages = tuple(
            (
                payload.package,
                next(
                    item.apt_version
                    for item in (
                        *INSTALLATION_AUTHORITY.packages,
                        *INSTALLATION_AUTHORITY.supplemental_packages,
                    )
                    if item.name == payload.package
                ),
                "amd64",
            )
            for payload in INSTALLATION_AUTHORITY.payloads
        )
        expected_assets = tuple(
            (destination, digest, uid, gid, mode)
            for _source, destination, digest, uid, gid, mode
            in AUTHORITY.installed_assets
        )
        expected_subid = (
            AUTHORITY.executor_user,
            AUTHORITY.subuid_start,
            AUTHORITY.subordinate_count,
        )
        if (
            self.application_reviewed_commit != userq.staticq.TARGET_REVIEWED_COMMIT
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.user_unit_state != ("loaded", "active", "running", "disabled")
            or self.user_unit_fragment != AUTHORITY.user_unit
            or type(self.user_unit_main_pid) is not int
            or self.user_unit_main_pid <= 1
            or self.rootlesskit_pid != self.user_unit_main_pid
            or type(self.rootlesskit_pid) is not int
            or self.rootlesskit_pid <= 1
            or not _REQUIRED_ROOTLESSKIT_TOKENS.issubset(
                frozenset(self.rootlesskit_argv)
            )
            or type(self.dockerd_pid) is not int
            or self.dockerd_pid <= 1
            or self.dockerd_argv != _EXPECTED_DOCKERD_ARGV
            or self.daemon_socket != AUTHORITY.daemon_socket
            or (self.socket_uid, self.socket_gid, self.socket_mode)
            != (
                AUTHORITY.executor_uid,
                AUTHORITY.executor_gid,
                AUTHORITY.daemon_socket_mode,
            )
            or self.rootlesskit_state
            != (
                AUTHORITY.rootlesskit_state,
                AUTHORITY.executor_uid,
                AUTHORITY.executor_gid,
                AUTHORITY.rootlesskit_state_mode,
            )
            or self.server_version != AUTHORITY.engine_version
            or self.storage_driver != "overlay2"
            or self.docker_root_dir != AUTHORITY.data_root
            or self.cgroup_driver != "systemd"
            or self.cgroup_version != "2"
            or "name=rootless" not in self.security_options
            or "name=cgroupns" not in self.security_options
            or self.containers != (0, 0, 0, 0)
            or self.images != 0
            or self.linger_mode not in {0o600, 0o644}
            or self.runtime_directory
            != (AUTHORITY.runtime_directory, AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o700)
            or self.user_manager_control_group
            != "/user.slice/user-991.slice/user@991.service"
            or self.delegate_controllers != ("cpu", "memory", "pids")
            or self.subuid_records != self.subgid_records
            or tuple(
                item for item in self.subuid_records
                if item[0] == AUTHORITY.executor_user
            ) != (expected_subid,)
            or tuple(
                item for item in self.subuid_records if item[0] == "omnigpt"
            ) != (("omnigpt", 427680, 65536),)
            or self.directories != AUTHORITY.post_daemon_provisioned_directories
            or self.assets != expected_assets
            or self.packages != expected_packages
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or type(self.host_dependencies) is not tuple
            or len(self.host_dependencies) != len(INSTALLATION_AUTHORITY.host_dependencies)
            or any(
                observed[0] != requirement.package
                or observed[2] != requirement.architecture
                or type(observed[1]) is not str
                or not observed[1]
                or any(
                    char not in userq.staticq.preinstall._VERSION_CHARS
                    for char in observed[1]
                )
                for observed, requirement in zip(
                    self.host_dependencies,
                    INSTALLATION_AUTHORITY.host_dependencies,
                    strict=True,
                )
            )
            or type(self.critical_executables) is not tuple
            or len(self.critical_executables)
            != len(userq.staticq.postinstall._REQUIRED_EXECUTABLES)
            or tuple(
                (package, path, mode)
                for package, path, mode, _sha256 in self.critical_executables
            )
            != tuple(
                (
                    package,
                    path,
                    userq.staticq.postinstall._EXECUTABLE_MODES[path],
                )
                for package, path in userq.staticq.postinstall._REQUIRED_EXECUTABLES
            )
            or any(
                type(sha256) is not str
                or len(sha256) != 64
                or any(c not in "0123456789abcdef" for c in sha256)
                for _package, _path, _mode, sha256 in self.critical_executables
            )
            or next(
                sha256
                for _package, path, _mode, sha256 in self.critical_executables
                if path == AUTHORITY.vendor_rootless_script
            ) != AUTHORITY.vendor_rootless_script_sha256
            or not {"cpu", "memory", "pids"}.issubset(
                frozenset(self.cgroup_controllers)
            )
            or self.executor_dropins != (AUTHORITY.executor_socket_dropin,)
            or self.user_manager_dropins
            != userq.staticq._expected_user_manager_dropins()
            or type(self.bundle) is not RootlessDockerPackageBundleEvidence
            or self.bundle.staging_directory != INSTALLATION_AUTHORITY.staging_directory
            or tuple(item.sha256 for item in self.bundle.files)
            != tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads)
        ):
            raise ValueError(_ERROR)
        RootlessDockerPackageBundleEvidence.__post_init__(self.bundle)


def _root_identity() -> tuple[int, int, int, int]:
    return userq._root_identity()


def _read_user_systemctl(property_name: str) -> str:
    if property_name not in {
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "MainPID",
        "FragmentPath",
    }:
        raise OSError
    result = subprocess.run(
        (
            _SYSTEMCTL,
            "--user",
            "--machine=omnilyzer-executor@.host",
            "show",
            "--property=" + property_name,
            "--value",
            _USER_UNIT,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
        timeout=_TIMEOUT,
        check=False,
    )
    if (
        result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\n" in result.stdout[:-1]
    ):
        raise OSError
    return result.stdout[:-1].decode("ascii")


def _canonical_user_unit_fragment(fragment: str) -> str:
    if fragment != AUTHORITY.user_unit_fragment_alias:
        raise OSError
    parent = os.lstat(AUTHORITY.user_unit_fragment_alias_parent)
    if (
        not stat.S_ISLNK(parent.st_mode)
        or (parent.st_uid, parent.st_gid) != (0, 0)
        or os.readlink(AUTHORITY.user_unit_fragment_alias_parent)
        != AUTHORITY.user_unit_fragment_alias_target
    ):
        raise OSError
    try:
        alias = os.stat(AUTHORITY.user_unit_fragment_alias, follow_symlinks=True)
        reviewed = os.stat(AUTHORITY.user_unit, follow_symlinks=True)
    except OSError:
        raise OSError from None
    if (
        not stat.S_ISREG(alias.st_mode)
        or not stat.S_ISREG(reviewed.st_mode)
        or (alias.st_uid, alias.st_gid) != (0, 0)
        or (reviewed.st_uid, reviewed.st_gid) != (0, 0)
        or stat.S_IMODE(alias.st_mode) != 0o644
        or stat.S_IMODE(reviewed.st_mode) != 0o644
        or (alias.st_dev, alias.st_ino) != (reviewed.st_dev, reviewed.st_ino)
    ):
        raise OSError
    return AUTHORITY.user_unit


def _user_unit_evidence() -> tuple[tuple[str, str, str, str], str, int]:
    state = (
        _read_user_systemctl("LoadState"),
        _read_user_systemctl("ActiveState"),
        _read_user_systemctl("SubState"),
        _read_user_systemctl("UnitFileState"),
    )
    fragment = _canonical_user_unit_fragment(
        _read_user_systemctl("FragmentPath")
    )
    try:
        main_pid = int(_read_user_systemctl("MainPID"))
    except ValueError:
        raise OSError from None
    if (
        state != ("loaded", "active", "running", "disabled")
        or fragment != AUTHORITY.user_unit
        or main_pid <= 1
        or os.path.lexists(_USER_UNIT_ENABLE_LINK)
    ):
        raise OSError
    return state, fragment, main_pid


def _read_proc_file(path: str, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode):
            raise OSError
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise OSError
        return bytes(data)
    finally:
        os.close(descriptor)


def _proc_uid(pid: int) -> int:
    try:
        text = _read_proc_file(f"/proc/{pid}/status", 256 * 1024).decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) != 5:
                raise OSError
            values = tuple(int(item) for item in fields[1:])
            if len(set(values)) != 1:
                raise OSError
            return values[0]
    raise OSError


def _proc_cmdline(pid: int) -> tuple[str, ...]:
    data = _read_proc_file(f"/proc/{pid}/cmdline", 256 * 1024)
    if not data or not data.endswith(b"\0"):
        raise OSError
    try:
        parts = tuple(item.decode("utf-8") for item in data[:-1].split(b"\0"))
    except UnicodeDecodeError:
        raise OSError from None
    if not parts or any(not item for item in parts):
        raise OSError
    return parts


def _proc_dir_uid(pid: int) -> int:
    if type(pid) is not int or pid <= 1:
        raise OSError
    value = os.stat(f"/proc/{pid}", follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode):
        raise OSError
    return value.st_uid


def _proc_comm(pid: int) -> str:
    if type(pid) is not int or pid <= 1:
        raise OSError
    data = _read_proc_file(f"/proc/{pid}/comm", 64)
    if (
        not data.endswith(b"\n")
        or b"\r" in data
        or b"\n" in data[:-1]
    ):
        raise OSError
    try:
        name = data[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    if not name:
        raise OSError
    return name


def _pids(name: str) -> tuple[int, ...]:
    if name not in {"rootlesskit", "dockerd", "containerd", "slirp4netns"}:
        raise OSError

    observed = []
    try:
        entries = tuple(os.scandir("/proc"))
    except OSError:
        raise OSError from None

    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            pid = int(entry.name)
        except ValueError:
            continue
        if pid <= 1:
            continue
        try:
            directory_uid = _proc_dir_uid(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if directory_uid != AUTHORITY.executor_uid:
            continue

        try:
            comm = _proc_comm(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            # A UID-991 candidate that still exists but cannot be inspected is
            # security-relevant and must fail closed.
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if comm != name:
            continue
        if _proc_uid(pid) != AUTHORITY.executor_uid:
            raise OSError
        observed.append(pid)

    pids = tuple(sorted(observed))
    if not pids or len(set(pids)) != len(pids):
        raise OSError
    return pids


def _process_evidence(main_pid: int) -> tuple[
    int,
    tuple[str, ...],
    int,
    tuple[str, ...],
]:
    rootlesskit_pids = _pids("rootlesskit")
    if rootlesskit_pids != (main_pid,):
        raise OSError
    rootlesskit_argv = _proc_cmdline(main_pid)
    if not _REQUIRED_ROOTLESSKIT_TOKENS.issubset(frozenset(rootlesskit_argv)):
        raise OSError

    dockerd_pids = _pids("dockerd")
    if len(dockerd_pids) != 1:
        raise OSError
    dockerd_pid = dockerd_pids[0]
    dockerd_argv = _proc_cmdline(dockerd_pid)
    if dockerd_argv != _EXPECTED_DOCKERD_ARGV:
        raise OSError

    containerd_pids = _pids("containerd")
    if len(containerd_pids) != 1:
        raise OSError
    _pids("slirp4netns")

    return main_pid, rootlesskit_argv, dockerd_pid, dockerd_argv


def _socket_evidence() -> tuple[str, int, int, int]:
    value = os.lstat(AUTHORITY.daemon_socket)
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_nlink != 1
        or (value.st_uid, value.st_gid)
        != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
        or stat.S_IMODE(value.st_mode) != AUTHORITY.daemon_socket_mode
    ):
        raise OSError
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(1.0)
        probe.connect(AUTHORITY.daemon_socket)
    finally:
        probe.close()
    return (
        AUTHORITY.daemon_socket,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )


def _rootlesskit_state_evidence() -> tuple[str, int, int, int]:
    value = os.lstat(AUTHORITY.rootlesskit_state)
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid)
        != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
        or stat.S_IMODE(value.st_mode) != AUTHORITY.rootlesskit_state_mode
        or os.path.lexists(AUTHORITY.containerd_rootless_state)
    ):
        raise OSError
    return (
        AUTHORITY.rootlesskit_state,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
    )


def _runtime_artifacts_exact() -> None:
    checks = (
        (AUTHORITY.pid_file, stat.S_IFREG, AUTHORITY.pid_file_mode),
        (AUTHORITY.exec_root, stat.S_IFDIR, AUTHORITY.exec_root_mode),
    )
    for path, kind, mode in checks:
        value = os.lstat(path)
        if (
            stat.S_IFMT(value.st_mode) != kind
            or (value.st_uid, value.st_gid)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
            or stat.S_IMODE(value.st_mode) != mode
        ):
            raise OSError


def _docker_info_evidence() -> tuple[
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
    tuple[int, int, int, int],
    int,
]:
    result = subprocess.run(
        (
            _DOCKER,
            "--config",
            "/etc/omnilyzer/deployment/docker-client",
            "--host",
            "unix://" + AUTHORITY.daemon_socket,
            "info",
            "--format",
            "json",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"},
        shell=False,
        timeout=_DOCKER_TIMEOUT,
        check=False,
    )
    if (
        result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OSError from None
    if type(value) is not dict or not _DOCKER_INFO_KEYS.issubset(value):
        raise OSError
    swarm = value["Swarm"]
    security = value["SecurityOptions"]
    numeric = (
        value["Containers"],
        value["ContainersRunning"],
        value["ContainersPaused"],
        value["ContainersStopped"],
        value["Images"],
    )
    if (
        type(swarm) is not dict
        or swarm.get("LocalNodeState") != "inactive"
        or type(security) is not list
        or any(type(item) is not str for item in security)
        or any(type(item) is not int or item < 0 for item in numeric)
        or value["LiveRestoreEnabled"] is not False
    ):
        raise OSError
    evidence = (
        value["ServerVersion"],
        value["Driver"],
        value["DockerRootDir"],
        value["CgroupDriver"],
        str(value["CgroupVersion"]),
        tuple(sorted(security)),
        tuple(numeric[:4]),
        numeric[4],
    )
    if (
        evidence[0] != AUTHORITY.engine_version
        or evidence[1] != "overlay2"
        or evidence[2] != AUTHORITY.data_root
        or evidence[3] != "systemd"
        or evidence[4] != "2"
        or "name=rootless" not in evidence[5]
        or "name=cgroupns" not in evidence[5]
        or evidence[6] != (0, 0, 0, 0)
        or evidence[7] != 0
    ):
        raise OSError
    return evidence


def _require_rootful_masks() -> None:
    postinstall = userq.staticq.postinstall
    preinstall = userq.staticq.preinstall
    for unit, path in zip(
        INSTALLATION_AUTHORITY.rootful_units,
        postinstall._ROOTFUL_MASK_PATHS,
        strict=True,
    ):
        value = os.lstat(path)
        if (
            not stat.S_ISLNK(value.st_mode)
            or (value.st_uid, value.st_gid) != (0, 0)
            or os.readlink(path) != "/dev/null"
            or preinstall._systemctl_value(unit, "LoadState") != "masked"
            or preinstall._systemctl_value(unit, "UnitFileState") != "masked"
            or preinstall._systemctl_value(unit, "ActiveState") != "inactive"
        ):
            raise OSError


def _package_host():
    identity = _root_identity()
    staticq = userq.staticq
    postinstall = staticq.postinstall
    preinstall = staticq.preinstall
    migrated = staticq.qualify_successor_host_migration()
    if (
        migrated.phase != "complete"
        or migrated.next_operation != "complete"
        or migrated.application_sha256 != staticq._EXPECTED_APPLICATION_SHA256
        or migrated.executor_reviewed_commit != staticq.TARGET_REVIEWED_COMMIT
        or migrated.broker_reviewed_commit != staticq.TARGET_REVIEWED_COMMIT
    ):
        raise OSError
    supplementary = preinstall._require_executor_identity()
    dependencies = tuple(
        preinstall._require_host_dependency(item)
        for item in INSTALLATION_AUTHORITY.host_dependencies
    )
    packages = tuple(
        postinstall._require_package(item)
        for item in INSTALLATION_AUTHORITY.payloads
    )
    postinstall._require_conflicts_absent()
    _require_rootful_masks()
    controllers = preinstall._require_kernel_prerequisites()
    postinstall._require_no_shadowing()
    executables = postinstall._require_critical_executables()
    bundle = staticq.qualify_rootless_docker_package_bundle()
    for path in (
        "/var/run/docker.sock",
        AUTHORITY.socket_directory,
        INSTALLATION_AUTHORITY.policy_rc_d_path,
        INSTALLATION_AUTHORITY.staging_directory + ".incoming",
    ):
        if os.path.lexists(path):
            raise OSError
    if _root_identity() != identity:
        raise OSError
    return (
        migrated.expected_workflow_sha,
        supplementary,
        dependencies,
        packages,
        controllers,
        executables,
        bundle,
    )


def _require_post_daemon_data_root() -> tuple[str, int, int, int]:
    path = AUTHORITY.data_root
    expected_uid = AUTHORITY.executor_uid
    expected_gid = AUTHORITY.executor_gid
    expected_mode = next(
        mode for item_path, _uid, _gid, mode
        in AUTHORITY.post_daemon_provisioned_directories
        if item_path == path
    )
    expected_entries = {
        name: (kind, mode)
        for name, kind, mode in AUTHORITY.post_daemon_data_root_entries
    }

    named = os.lstat(path)
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_uid, named.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(named.st_mode) != expected_mode
    ):
        raise OSError

    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or (opened.st_uid, opened.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(opened.st_mode) != expected_mode
        ):
            raise OSError
        if frozenset(os.listdir(descriptor)) != frozenset(expected_entries):
            raise OSError

        for name, (kind, mode) in expected_entries.items():
            child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (child.st_uid, child.st_gid) != (expected_uid, expected_gid):
                raise OSError
            if kind == "directory":
                if not stat.S_ISDIR(child.st_mode):
                    raise OSError
            elif kind == "file":
                if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                    raise OSError
            else:
                raise OSError
            if stat.S_IMODE(child.st_mode) != mode:
                raise OSError

            if name == "engine-id":
                if child.st_size != AUTHORITY.post_daemon_engine_id_size:
                    raise OSError
                file_descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                try:
                    data = os.read(file_descriptor, AUTHORITY.post_daemon_engine_id_size + 1)
                    if len(data) != AUTHORITY.post_daemon_engine_id_size:
                        raise OSError
                    try:
                        text = data.decode("ascii")
                        parsed = uuid.UUID(text)
                    except (UnicodeDecodeError, ValueError):
                        raise OSError from None
                    if str(parsed) != text:
                        raise OSError
                finally:
                    os.close(file_descriptor)

        if frozenset(os.listdir(descriptor)) != frozenset(expected_entries):
            raise OSError
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (final.st_uid, final.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(final.st_mode) != expected_mode
        ):
            raise OSError
    finally:
        os.close(descriptor)
    return path, expected_uid, expected_gid, expected_mode


def _require_post_daemon_static_assets() -> tuple[
    tuple[tuple[str, int, int, int], ...],
    tuple[tuple[str, str, int, int, int], ...],
]:
    directories = []
    for path, uid, gid, mode in AUTHORITY.post_daemon_provisioned_directories:
        if path == AUTHORITY.data_root:
            directories.append(_require_post_daemon_data_root())
        else:
            directories.append(
                userq.staticq._require_directory(
                    path,
                    uid,
                    gid,
                    mode,
                    userq.staticq._EXPECTED_DIRECTORY_CHILDREN[path],
                )
            )
    assets = tuple(
        userq.staticq._require_file(destination, digest, uid, gid, mode)
        for _source, destination, digest, uid, gid, mode
        in AUTHORITY.installed_assets
    )
    return tuple(directories), assets


def _user_manager_evidence() -> tuple[int, tuple[str, int, int, int], str, tuple[str, ...]]:
    linger_mode = userq._linger_evidence()
    runtime = userq._runtime_evidence()
    if (
        userq._read_systemctl("user@991.service", "LoadState") != "loaded"
        or userq._read_systemctl("user@991.service", "ActiveState") != "active"
        or userq._read_systemctl("user-runtime-dir@991.service", "LoadState") != "loaded"
        or userq._read_systemctl("user-runtime-dir@991.service", "ActiveState") != "active"
        or userq._read_loginctl("RuntimePath") != AUTHORITY.runtime_directory
    ):
        raise OSError
    control_group = userq._read_systemctl("user@991.service", "ControlGroup")
    if (
        control_group != "/user.slice/user-991.slice/user@991.service"
        or userq._read_systemctl("user@991.service", "Delegate") != "yes"
    ):
        raise OSError
    controllers = tuple(
        sorted(
            userq._read_systemctl(
                "user@991.service", "DelegateControllers"
            ).split()
        )
    )
    if controllers != ("cpu", "memory", "pids"):
        raise OSError
    cgroup = "/sys/fs/cgroup" + control_group
    if not stat.S_ISDIR(os.lstat(cgroup).st_mode):
        raise OSError
    available = userq._read_cgroup_tokens(cgroup + "/cgroup.controllers")
    delegated = userq._read_cgroup_tokens(cgroup + "/cgroup.subtree_control")
    if not {"cpu", "memory", "pids"}.issubset(available | delegated):
        raise OSError
    return linger_mode, runtime, control_group, controllers


def _qualify_once_with_user_unit(user_unit_evidence) -> RootlessDockerDaemonEvidence:
    identity = _root_identity()
    package_host = _package_host()
    subuid, subgid = userq.staticq._require_subids()
    directories, assets = _require_post_daemon_static_assets()
    userq.staticq._require_user_manager_template_dropins()

    executor_dropins = tuple(
        userq.staticq._read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_dropins = tuple(
        userq.staticq._read_systemctl("user@991.service", "DropInPaths").split()
    )
    if (
        executor_dropins != (AUTHORITY.executor_socket_dropin,)
        or user_dropins != userq.staticq._expected_user_manager_dropins()
    ):
        raise OSError
    for unit in _DEPLOYMENT_UNITS:
        if userq._read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError

    state, fragment, main_pid = user_unit_evidence()
    rootlesskit_pid, rootlesskit_argv, dockerd_pid, dockerd_argv = (
        _process_evidence(main_pid)
    )
    socket_evidence = _socket_evidence()
    rootlesskit_state = _rootlesskit_state_evidence()
    _runtime_artifacts_exact()
    info = _docker_info_evidence()
    linger_mode, runtime, control_group, delegates = _user_manager_evidence()

    if _root_identity() != identity:
        raise OSError

    return RootlessDockerDaemonEvidence(
        application_reviewed_commit=userq.staticq.TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=package_host[0],
        user_unit_state=state,
        user_unit_fragment=fragment,
        user_unit_main_pid=main_pid,
        rootlesskit_pid=rootlesskit_pid,
        rootlesskit_argv=rootlesskit_argv,
        dockerd_pid=dockerd_pid,
        dockerd_argv=dockerd_argv,
        daemon_socket=socket_evidence[0],
        socket_uid=socket_evidence[1],
        socket_gid=socket_evidence[2],
        socket_mode=socket_evidence[3],
        rootlesskit_state=rootlesskit_state,
        server_version=info[0],
        storage_driver=info[1],
        docker_root_dir=info[2],
        cgroup_driver=info[3],
        cgroup_version=info[4],
        security_options=info[5],
        containers=info[6],
        images=info[7],
        linger_mode=linger_mode,
        runtime_directory=runtime,
        user_manager_control_group=control_group,
        delegate_controllers=delegates,
        subuid_records=subuid,
        subgid_records=subgid,
        directories=directories,
        assets=assets,
        packages=package_host[3],
        host_dependencies=package_host[2],
        masked_units=INSTALLATION_AUTHORITY.rootful_units,
        critical_executables=package_host[5],
        cgroup_controllers=package_host[4],
        executor_dropins=executor_dropins,
        user_manager_dropins=user_dropins,
        bundle=package_host[6],
    )


def _qualify_once() -> RootlessDockerDaemonEvidence:
    return _qualify_once_with_user_unit(_user_unit_evidence)


def qualify_rootless_docker_daemon() -> RootlessDockerDaemonEvidence:
    """Require two identical independent observations of the running daemon."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerDaemonQualificationError(_ERROR) from None

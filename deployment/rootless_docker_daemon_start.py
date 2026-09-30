"""deployment/rootless_docker_daemon_start.py - C33E rootless daemon start.

Purpose:
- consume the independently qualified C33D user-manager state;
- start only the reviewed rootless Docker user service for UID 991;
- keep that user service disabled so reboot persistence remains a later review;
- require the exact private Unix socket and rootless Docker server identity;
- keep broker, executor, projected socket and deployment inactive.

C33E never enables a unit and never starts broker/executor/deployment services.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import socket
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_user_manager_qualification as userq
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY


__all__ = (
    "RootlessDockerDaemonStartError",
    "RootlessDockerDaemonStartEvidence",
    "start_rootless_docker_daemon",
)

_ERROR = "rootless Docker daemon start is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_DOCKER = AUTHORITY.docker_cli
_TIMEOUT = 30.0
_DOCKER_TIMEOUT = 15.0
_OUTPUT_LIMIT = 1024 * 1024
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_DEPLOYMENT_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.service",
    "omnilyzer-deployment-executor.socket",
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


class RootlessDockerDaemonStartError(Exception):
    """One fixed external failure for the privileged C33E boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerDaemonStartEvidence:
    """Exact C33E daemon-start evidence."""

    operation: str
    expected_workflow_sha: str
    user_unit_state: tuple[str, str, str, str]
    daemon_socket: str
    socket_uid: int
    socket_gid: int
    socket_mode: int
    dockerd_pid: int
    dockerd_argv: tuple[str, ...]
    server_version: str
    storage_driver: str
    docker_root_dir: str
    cgroup_driver: str
    cgroup_version: str
    security_options: tuple[str, ...]
    containers: tuple[int, int, int, int]
    images: int

    def __post_init__(self) -> None:
        if (
            self.operation not in {"started", "already-started"}
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.user_unit_state != ("loaded", "active", "running", "disabled")
            or self.daemon_socket != AUTHORITY.daemon_socket
            or (self.socket_uid, self.socket_gid, self.socket_mode)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o660)
            or type(self.dockerd_pid) is not int
            or self.dockerd_pid <= 1
            or self.dockerd_argv != _EXPECTED_DOCKERD_ARGV
            or self.server_version != AUTHORITY.engine_version
            or self.storage_driver != "overlay2"
            or self.docker_root_dir != AUTHORITY.data_root
            or self.cgroup_driver != "systemd"
            or self.cgroup_version != "2"
            or "name=rootless" not in self.security_options
            or "name=cgroupns" not in self.security_options
            or self.containers != (0, 0, 0, 0)
            or self.images != 0
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    return userq._root_identity()


def _run(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    if argv != (
        _SYSTEMCTL,
        "--user",
        "--machine=omnilyzer-executor@.host",
        "start",
        _USER_UNIT,
    ):
        raise OSError
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"},
        shell=False,
        timeout=_TIMEOUT,
        check=False,
    )
    if (
        type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or len(result.stderr) > _OUTPUT_LIMIT
    ):
        raise OSError
    return result


def _read_user_systemctl(property_name: str) -> str:
    if property_name not in {
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
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
        timeout=5.0,
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


def _user_unit_state() -> tuple[str, str, str, str]:
    return (
        _read_user_systemctl("LoadState"),
        _read_user_systemctl("ActiveState"),
        _read_user_systemctl("SubState"),
        _read_user_systemctl("UnitFileState"),
    )


def _socket_evidence() -> tuple[str, int, int, int]:
    value = os.lstat(AUTHORITY.daemon_socket)
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_nlink != 1
        or (value.st_uid, value.st_gid)
        != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
        or stat.S_IMODE(value.st_mode) != 0o660
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


def _docker_info() -> dict[str, object]:
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
    return value


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
    value = _docker_info()
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
        or type(value["LiveRestoreEnabled"]) is not bool
        or value["LiveRestoreEnabled"]
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
    data = _read_proc_file(f"/proc/{pid}/status", 256 * 1024)
    try:
        text = data.decode("ascii")
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


def _dockerd_evidence() -> tuple[int, tuple[str, ...]]:
    result = userq.staticq.preinstall._run((userq.staticq.preinstall._PGREP, "-x", "dockerd"))
    if result.returncode != 0 or not result.stdout.endswith(b"\n"):
        raise OSError
    try:
        pids = tuple(
            int(line) for line in result.stdout.decode("ascii").strip().splitlines()
        )
    except (UnicodeDecodeError, ValueError):
        raise OSError from None
    if len(pids) != 1:
        raise OSError
    pid = pids[0]
    if _proc_uid(pid) != AUTHORITY.executor_uid:
        raise OSError
    argv = _proc_cmdline(pid)
    if argv != _EXPECTED_DOCKERD_ARGV:
        raise OSError
    return pid, argv


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


def _package_host_allow_daemon():
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
        AUTHORITY.containerd_rootless_state,
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


def _static_evidence_after_start():
    package_host = _package_host_allow_daemon()
    subuid, subgid = userq.staticq._require_subids()
    directories, assets = userq.staticq._require_static_assets()
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
    delegates = tuple(
        sorted(userq._read_systemctl("user@991.service", "DelegateControllers").split())
    )
    if (
        control_group != "/user.slice/user-991.slice/user@991.service"
        or userq._read_systemctl("user@991.service", "Delegate") != "yes"
        or delegates != ("cpu", "memory", "pids")
    ):
        raise OSError
    return (
        package_host,
        subuid,
        subgid,
        directories,
        assets,
        linger_mode,
        runtime,
        executor_dropins,
        user_dropins,
        control_group,
        delegates,
    )


def _ready_evidence(operation: str) -> RootlessDockerDaemonStartEvidence:
    state = _user_unit_state()
    if state != ("loaded", "active", "running", "disabled"):
        raise OSError
    socket_evidence = _socket_evidence()
    info = _docker_info_evidence()
    pid, argv = _dockerd_evidence()
    if os.path.lexists(
        "/etc/systemd/user/default.target.wants/" + _USER_UNIT
    ):
        raise OSError
    return RootlessDockerDaemonStartEvidence(
        operation=operation,
        expected_workflow_sha=_package_host_allow_daemon()[0],
        user_unit_state=state,
        daemon_socket=socket_evidence[0],
        socket_uid=socket_evidence[1],
        socket_gid=socket_evidence[2],
        socket_mode=socket_evidence[3],
        dockerd_pid=pid,
        dockerd_argv=argv,
        server_version=info[0],
        storage_driver=info[1],
        docker_root_dir=info[2],
        cgroup_driver=info[3],
        cgroup_version=info[4],
        security_options=info[5],
        containers=info[6],
        images=info[7],
    )


def _start_under_lock() -> RootlessDockerDaemonStartEvidence:
    identity = _root_identity()
    state = _user_unit_state()

    if state == ("loaded", "inactive", "dead", "disabled"):
        before = userq.qualify_rootless_docker_user_manager()
        result = _run(
            (
                _SYSTEMCTL,
                "--user",
                "--machine=omnilyzer-executor@.host",
                "start",
                _USER_UNIT,
            )
        )
        if result.returncode != 0:
            raise OSError
        operation = "started"
    elif state == ("loaded", "active", "running", "disabled"):
        before = None
        operation = "already-started"
    else:
        raise OSError

    after_static = _static_evidence_after_start()
    result = _ready_evidence(operation)

    if before is not None:
        package_host = after_static[0]
        if (
            before.expected_workflow_sha != package_host[0]
            or before.subuid_records != after_static[1]
            or before.subgid_records != after_static[2]
            or before.directories != after_static[3]
            or before.assets != after_static[4]
            or before.linger_mode != after_static[5]
            or (
                before.runtime_directory,
                before.runtime_uid,
                before.runtime_gid,
                before.runtime_mode,
            )
            != after_static[6]
            or before.packages != package_host[3]
            or before.host_dependencies != package_host[2]
            or before.critical_executables != package_host[5]
            or before.cgroup_controllers != package_host[4]
            or before.bundle != package_host[6]
            or before.executor_dropins != after_static[7]
            or before.user_manager_dropins != after_static[8]
            or before.user_manager_control_group != after_static[9]
            or before.delegate_controllers != after_static[10]
        ):
            raise OSError

    if result.expected_workflow_sha != after_static[0][0] or _root_identity() != identity:
        raise OSError
    return result


def start_rootless_docker_daemon() -> RootlessDockerDaemonStartEvidence:
    """Start only the reviewed rootless Docker user service under the shared lock."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _start_under_lock()
    except _CONTROL as error:
        control = error
    except Exception:
        failure = True
    finally:
        if lock is not None:
            try:
                orchestration._release_process_lock(lock)
            except _CONTROL as error:
                control = control or error
            except Exception:
                failure = True
    if control is not None:
        raise control
    if failure or result is None:
        raise RootlessDockerDaemonStartError(_ERROR) from None
    return result

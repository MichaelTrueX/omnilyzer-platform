"""deployment/rootless_docker_user_manager_bootstrap.py - C33C user manager bootstrap.

Purpose:
- consume the independently qualified C33A static bootstrap state;
- enable linger only for omnilyzer-executor;
- start only user@991.service so logind/systemd creates /run/user/991;
- verify exact runtime-directory ownership/mode and cgroup delegation;
- keep rootless Docker, executor, broker and deployment inactive.

C33C does not start, enable or invoke Docker. It does not start any user unit.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import subprocess

from . import dev_host_provisioning_orchestration as orchestration
from . import rootless_docker_static_bootstrap_qualification as staticq
from .rootless_docker_authority import AUTHORITY


__all__ = (
    "RootlessDockerUserManagerBootstrapError",
    "RootlessDockerUserManagerBootstrapEvidence",
    "bootstrap_rootless_docker_user_manager",
)

_ERROR = "rootless Docker user-manager bootstrap is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_LOGINCTL = "/usr/bin/loginctl"
_SYSTEMCTL = "/usr/bin/systemctl"
_TIMEOUT = 30.0
_OUTPUT_LIMIT = 256 * 1024
_LINGER_PATH = "/var/lib/systemd/linger/omnilyzer-executor"
_RUNTIME = AUTHORITY.runtime_directory
_USER_MANAGER = "user@991.service"
_USER_RUNTIME = "user-runtime-dir@991.service"
_DEPLOYMENT_UNITS = (
    "omnilyzer-deployment-broker.service",
    "omnilyzer-deployment-executor.service",
    "omnilyzer-deployment-executor.socket",
)
_USER_UNIT_ENABLE_LINK = (
    "/etc/systemd/user/default.target.wants/"
    "omnilyzer-task014-rootless-docker.service"
)


class RootlessDockerUserManagerBootstrapError(Exception):
    """One fixed external failure for the privileged C33C boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerUserManagerBootstrapEvidence:
    """Exact result of the C33C user-manager transition."""

    operation: str
    expected_workflow_sha: str
    linger_path: str
    runtime_directory: str
    runtime_uid: int
    runtime_gid: int
    runtime_mode: int
    user_manager: str
    user_manager_control_group: str
    delegate_controllers: tuple[str, ...]
    static_subuid: tuple[str, int, int]
    static_subgid: tuple[str, int, int]

    def __post_init__(self) -> None:
        expected_subid = (
            AUTHORITY.executor_user,
            AUTHORITY.subuid_start,
            AUTHORITY.subordinate_count,
        )
        if (
            self.operation not in {"bootstrapped", "resumed", "already-bootstrapped"}
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.linger_path != _LINGER_PATH
            or self.runtime_directory != _RUNTIME
            or (self.runtime_uid, self.runtime_gid, self.runtime_mode)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o700)
            or self.user_manager != _USER_MANAGER
            or self.user_manager_control_group
            != "/user.slice/user-991.slice/user@991.service"
            or self.delegate_controllers != ("cpu", "memory", "pids")
            or self.static_subuid != expected_subid
            or self.static_subgid != expected_subid
        ):
            raise ValueError(_ERROR)


def _root_identity() -> tuple[int, int, int, int]:
    return staticq._root_identity()


def _run(argv: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    """Run only the two reviewed mutating command shapes."""

    if argv == (_LOGINCTL, "enable-linger", AUTHORITY.executor_user):
        pass
    elif argv == (_SYSTEMCTL, "start", _USER_MANAGER):
        pass
    else:
        raise OSError

    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/root",
        },
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


def _read_systemctl(unit: str, property_name: str) -> str:
    if (
        unit not in (*_DEPLOYMENT_UNITS, _USER_MANAGER, _USER_RUNTIME)
        or property_name
        not in {
            "LoadState",
            "ActiveState",
            "UnitFileState",
            "ControlGroup",
            "Delegate",
            "DelegateControllers",
            "DropInPaths",
        }
    ):
        raise OSError
    result = subprocess.run(
        (
            _SYSTEMCTL,
            "show",
            "--property=" + property_name,
            "--value",
            unit,
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


def _read_loginctl(property_name: str) -> str:
    if property_name not in {"Linger", "RuntimePath", "UID", "Name"}:
        raise OSError
    result = subprocess.run(
        (
            _LOGINCTL,
            "show-user",
            AUTHORITY.executor_user,
            "--property=" + property_name,
            "--value",
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


def _linger_state() -> str:
    try:
        value = os.lstat(_LINGER_PATH)
    except FileNotFoundError:
        return "absent"
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or (value.st_uid, value.st_gid) != (0, 0)
        or stat.S_IMODE(value.st_mode) not in {0o600, 0o644}
        or value.st_size != 0
    ):
        raise OSError
    if (
        _read_loginctl("Linger") != "yes"
        or _read_loginctl("UID") != str(AUTHORITY.executor_uid)
        or _read_loginctl("Name") != AUTHORITY.executor_user
    ):
        raise OSError
    return "exact"


def _runtime_state() -> str:
    try:
        value = os.lstat(_RUNTIME)
    except FileNotFoundError:
        return "absent"
    if (
        not stat.S_ISDIR(value.st_mode)
        or (value.st_uid, value.st_gid)
        != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise OSError
    descriptor = os.open(
        _RUNTIME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_ino != value.st_ino
            or opened.st_dev != value.st_dev
            or (opened.st_uid, opened.st_gid)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise OSError
    finally:
        os.close(descriptor)
    return "exact"


def _require_rootless_inactive() -> None:
    postinstall = staticq.postinstall
    preinstall = staticq.preinstall
    for unit, path in zip(
        postinstall.INSTALLATION_AUTHORITY.rootful_units,
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
    for name in ("dockerd", "containerd"):
        result = preinstall._run((preinstall._PGREP, "-x", name))
        if result.returncode != 1 or result.stdout != b"":
            raise OSError
    if os.path.lexists(_USER_UNIT_ENABLE_LINK):
        raise OSError
    for path in (
        "/var/run/docker.sock",
        AUTHORITY.daemon_socket,
        AUTHORITY.socket_directory + "/docker.sock",
        AUTHORITY.pid_file,
        postinstall.INSTALLATION_AUTHORITY.policy_rc_d_path,
        postinstall.INSTALLATION_AUTHORITY.staging_directory + ".incoming",
    ):
        if os.path.lexists(path):
            raise OSError


def _read_user_systemctl(property_name: str) -> str:
    if property_name not in {"LoadState", "ActiveState", "UnitFileState"}:
        raise OSError
    result = subprocess.run(
        (
            _SYSTEMCTL,
            "--user",
            "--machine=omnilyzer-executor@.host",
            "show",
            "--property=" + property_name,
            "--value",
            "omnilyzer-task014-rootless-docker.service",
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


def _read_cgroup_tokens(path: str) -> frozenset[str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_size > 64 * 1024:
            raise OSError
        data = bytearray()
        while len(data) <= 64 * 1024:
            chunk = os.read(descriptor, min(4096, 64 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 64 * 1024:
            raise OSError
        try:
            text = bytes(data).decode("ascii").strip()
        except UnicodeDecodeError:
            raise OSError from None
        return frozenset(token.removeprefix("+") for token in text.split())
    finally:
        os.close(descriptor)


def _package_host_allow_user_runtime():
    identity = _root_identity()
    postinstall = staticq.postinstall
    preinstall = staticq.preinstall
    install = postinstall.INSTALLATION_AUTHORITY
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
        preinstall._require_host_dependency(item) for item in install.host_dependencies
    )
    packages = tuple(
        postinstall._require_package(item) for item in install.payloads
    )
    postinstall._require_conflicts_absent()
    _require_rootless_inactive()
    controllers = preinstall._require_kernel_prerequisites()
    postinstall._require_no_shadowing()
    executables = postinstall._require_critical_executables()
    bundle = staticq.qualify_rootless_docker_package_bundle()
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


def _static_state():
    identity = _root_identity()
    package_host = _package_host_allow_user_runtime()
    subuid, subgid = staticq._require_subids()
    directories, assets = staticq._require_static_assets()
    staticq._require_user_manager_template_dropins()
    executor_paths = tuple(
        staticq._read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_paths = tuple(
        staticq._read_systemctl(_USER_MANAGER, "DropInPaths").split()
    )
    if (
        executor_paths != (AUTHORITY.executor_socket_dropin,)
        or user_paths != staticq._expected_user_manager_dropins()
    ):
        raise OSError
    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError
    _require_rootless_inactive()
    if _root_identity() != identity:
        raise OSError
    return package_host, subuid, subgid, directories, assets


def _phase() -> tuple[str, str, str]:
    linger = _linger_state()
    runtime = _runtime_state()
    manager = _read_systemctl(_USER_MANAGER, "ActiveState")

    if linger == "absent" and runtime == "absent" and manager == "inactive":
        return "initial", linger, runtime
    if linger == "exact" and runtime == "absent" and manager == "inactive":
        return "resume", linger, runtime
    if linger == "exact" and runtime == "exact" and manager == "active":
        return "complete", linger, runtime
    raise OSError


def _require_complete_user_manager() -> tuple[str, tuple[str, ...]]:
    if _linger_state() != "exact" or _runtime_state() != "exact":
        raise OSError
    if (
        _read_systemctl(_USER_MANAGER, "LoadState") != "loaded"
        or _read_systemctl(_USER_MANAGER, "ActiveState") != "active"
        or _read_systemctl(_USER_RUNTIME, "LoadState") != "loaded"
        or _read_systemctl(_USER_RUNTIME, "ActiveState") != "active"
        or _read_loginctl("RuntimePath") != _RUNTIME
    ):
        raise OSError

    control_group = _read_systemctl(_USER_MANAGER, "ControlGroup")
    if control_group != "/user.slice/user-991.slice/user@991.service":
        raise OSError
    if _read_systemctl(_USER_MANAGER, "Delegate") != "yes":
        raise OSError
    controllers = tuple(
        sorted(_read_systemctl(_USER_MANAGER, "DelegateControllers").split())
    )
    if controllers != ("cpu", "memory", "pids"):
        raise OSError

    cgroup = "/sys/fs/cgroup" + control_group
    value = os.lstat(cgroup)
    if not stat.S_ISDIR(value.st_mode):
        raise OSError
    available = _read_cgroup_tokens(cgroup + "/cgroup.controllers")
    delegated = _read_cgroup_tokens(cgroup + "/cgroup.subtree_control")
    if not {"cpu", "memory", "pids"}.issubset(available | delegated):
        raise OSError

    _require_rootless_inactive()
    if (
        _read_user_systemctl("LoadState") != "loaded"
        or _read_user_systemctl("ActiveState") != "inactive"
        or _read_user_systemctl("UnitFileState") != "disabled"
    ):
        raise OSError
    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError
    return control_group, controllers


def _bootstrap_under_lock() -> RootlessDockerUserManagerBootstrapEvidence:
    identity = _root_identity()
    phase, _linger, _runtime = _phase()

    if phase == "initial":
        before = staticq.qualify_rootless_docker_static_bootstrap()
        static_before = (
            before.expected_workflow_sha,
            before.subuid_records,
            before.subgid_records,
            before.directories,
            before.assets,
            before.packages,
            before.host_dependencies,
            before.critical_executables,
            before.cgroup_controllers,
            before.executor_dropins,
            before.user_manager_dropins,
            before.bundle,
        )
    else:
        static_before = _static_state()

    if phase == "initial":
        result = _run((_LOGINCTL, "enable-linger", AUTHORITY.executor_user))
        if result.returncode != 0 or _linger_state() != "exact":
            raise OSError

    if phase != "complete":
        _require_rootless_inactive()
        result = _run((_SYSTEMCTL, "start", _USER_MANAGER))
        if result.returncode != 0:
            raise OSError

    control_group, controllers = _require_complete_user_manager()
    static_after = _static_state()

    if phase == "initial":
        expected_after = (
            static_after[0][0],
            static_after[1],
            static_after[2],
            static_after[3],
            static_after[4],
            static_after[0][3],
            static_after[0][2],
            static_after[0][5],
            static_after[0][4],
            (AUTHORITY.executor_socket_dropin,),
            staticq._expected_user_manager_dropins(),
            static_after[0][6],
        )
        if expected_after != static_before:
            raise OSError
    elif static_after != static_before:
        raise OSError

    if _root_identity() != identity:
        raise OSError

    expected_subid = (
        AUTHORITY.executor_user,
        AUTHORITY.subuid_start,
        AUTHORITY.subordinate_count,
    )
    return RootlessDockerUserManagerBootstrapEvidence(
        operation=(
            "already-bootstrapped"
            if phase == "complete"
            else "bootstrapped"
            if phase == "initial"
            else "resumed"
        ),
        expected_workflow_sha=static_after[0][0],
        linger_path=_LINGER_PATH,
        runtime_directory=_RUNTIME,
        runtime_uid=AUTHORITY.executor_uid,
        runtime_gid=AUTHORITY.executor_gid,
        runtime_mode=0o700,
        user_manager=_USER_MANAGER,
        user_manager_control_group=control_group,
        delegate_controllers=controllers,
        static_subuid=expected_subid,
        static_subgid=expected_subid,
    )


def bootstrap_rootless_docker_user_manager() -> RootlessDockerUserManagerBootstrapEvidence:
    """Enable linger and start only the reviewed UID-991 user manager."""

    lock = None
    result = None
    failure = False
    control = None
    try:
        _root_identity()
        lock = orchestration._acquire_process_lock()
        result = _bootstrap_under_lock()
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
        raise RootlessDockerUserManagerBootstrapError(_ERROR) from None
    return result

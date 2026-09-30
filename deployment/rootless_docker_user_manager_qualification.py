"""deployment/rootless_docker_user_manager_qualification.py - C33D proof.

Purpose:
- independently qualify the UID-991 linger/user-manager state created by C33C;
- re-prove the static rootless host/package authority while allowing only the
  systemd-owned /run/user/991 runtime to exist;
- prove exact linger, runtime-directory ownership/mode, user-manager cgroup
  delegation, and rootless Docker user-unit inactivity;
- remain fully read-only and independent from the C33C mutating module.

C33D performs no filesystem, account, systemd, Docker, network, or deployment
mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import subprocess

from . import rootless_docker_static_bootstrap_qualification as staticq
from .rootless_docker_authority import AUTHORITY
from .rootless_docker_installation_authority import INSTALLATION_AUTHORITY
from .rootless_docker_package_bundle_qualification import (
    RootlessDockerPackageBundleEvidence,
)


__all__ = (
    "RootlessDockerUserManagerQualificationError",
    "RootlessDockerUserManagerEvidence",
    "qualify_rootless_docker_user_manager",
)

_ERROR = "rootless Docker user-manager qualification is unavailable"
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_LOGINCTL = "/usr/bin/loginctl"
_SYSTEMCTL = "/usr/bin/systemctl"
_TIMEOUT = 5.0
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
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"
_USER_UNIT_ENABLE_LINK = (
    "/etc/systemd/user/default.target.wants/"
    "omnilyzer-task014-rootless-docker.service"
)


class RootlessDockerUserManagerQualificationError(Exception):
    """One fixed external failure for the C33D read-only boundary."""


@dataclass(frozen=True, slots=True)
class RootlessDockerUserManagerEvidence:
    """Exact user-manager evidence observed twice without mutation."""

    application_reviewed_commit: str
    expected_workflow_sha: str
    linger_path: str
    linger_mode: int
    runtime_directory: str
    runtime_uid: int
    runtime_gid: int
    runtime_mode: int
    user_manager: str
    user_manager_control_group: str
    delegate_controllers: tuple[str, ...]
    rootless_user_unit: str
    rootless_user_unit_state: tuple[str, str, str]
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
        expected_subid = (
            AUTHORITY.executor_user,
            AUTHORITY.subuid_start,
            AUTHORITY.subordinate_count,
        )
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
        if (
            self.application_reviewed_commit != staticq.TARGET_REVIEWED_COMMIT
            or type(self.expected_workflow_sha) is not str
            or len(self.expected_workflow_sha) != 40
            or self.expected_workflow_sha == "0" * 40
            or any(c not in "0123456789abcdef" for c in self.expected_workflow_sha)
            or self.linger_path != _LINGER_PATH
            or self.linger_mode not in {0o600, 0o644}
            or self.runtime_directory != _RUNTIME
            or (self.runtime_uid, self.runtime_gid, self.runtime_mode)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o700)
            or self.user_manager != _USER_MANAGER
            or self.user_manager_control_group
            != "/user.slice/user-991.slice/user@991.service"
            or self.delegate_controllers != ("cpu", "memory", "pids")
            or self.rootless_user_unit != _USER_UNIT
            or self.rootless_user_unit_state != ("loaded", "inactive", "disabled")
            or self.subuid_records != self.subgid_records
            or tuple(
                item for item in self.subuid_records
                if item[0] == AUTHORITY.executor_user
            ) != (expected_subid,)
            or tuple(
                item for item in self.subuid_records if item[0] == "omnigpt"
            ) != (("omnigpt", 427680, 65536),)
            or self.directories != AUTHORITY.provisioned_directories
            or self.assets != expected_assets
            or self.packages != expected_packages
            or self.masked_units != INSTALLATION_AUTHORITY.rootful_units
            or type(self.host_dependencies) is not tuple
            or len(self.host_dependencies)
            != len(INSTALLATION_AUTHORITY.host_dependencies)
            or any(
                observed[0] != requirement.package
                or observed[2] != requirement.architecture
                or type(observed[1]) is not str
                or not observed[1]
                or any(
                    char not in staticq.preinstall._VERSION_CHARS
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
            != len(staticq.postinstall._REQUIRED_EXECUTABLES)
            or tuple(
                (package, path, mode)
                for package, path, mode, _sha256 in self.critical_executables
            )
            != tuple(
                (
                    package,
                    path,
                    staticq.postinstall._EXECUTABLE_MODES[path],
                )
                for package, path in staticq.postinstall._REQUIRED_EXECUTABLES
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
            != staticq._expected_user_manager_dropins()
            or type(self.bundle) is not RootlessDockerPackageBundleEvidence
            or self.bundle.staging_directory
            != INSTALLATION_AUTHORITY.staging_directory
            or tuple(item.sha256 for item in self.bundle.files)
            != tuple(item.sha256 for item in INSTALLATION_AUTHORITY.payloads)
        ):
            raise ValueError(_ERROR)
        RootlessDockerPackageBundleEvidence.__post_init__(self.bundle)


def _root_identity() -> tuple[int, int, int, int]:
    return staticq._root_identity()


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


def _linger_evidence() -> int:
    value = os.lstat(_LINGER_PATH)
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or (value.st_uid, value.st_gid) != (0, 0)
        or mode not in {0o600, 0o644}
        or value.st_size != 0
        or _read_loginctl("Linger") != "yes"
        or _read_loginctl("UID") != str(AUTHORITY.executor_uid)
        or _read_loginctl("Name") != AUTHORITY.executor_user
    ):
        raise OSError
    return mode


def _runtime_evidence() -> tuple[str, int, int, int]:
    named = os.lstat(_RUNTIME)
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_uid, named.st_gid)
        != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
        or stat.S_IMODE(named.st_mode) != 0o700
    ):
        raise OSError
    descriptor = os.open(
        _RUNTIME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_ino != named.st_ino
            or opened.st_dev != named.st_dev
            or (opened.st_uid, opened.st_gid)
            != (AUTHORITY.executor_uid, AUTHORITY.executor_gid)
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise OSError
    finally:
        os.close(descriptor)
    return _RUNTIME, AUTHORITY.executor_uid, AUTHORITY.executor_gid, 0o700


def _require_rootless_inactive() -> None:
    postinstall = staticq.postinstall
    preinstall = staticq.preinstall
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
        INSTALLATION_AUTHORITY.policy_rc_d_path,
        INSTALLATION_AUTHORITY.staging_directory + ".incoming",
    ):
        if os.path.lexists(path):
            raise OSError


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


def _package_host():
    identity = _root_identity()
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


def _require_user_manager() -> tuple[str, tuple[str, ...]]:
    if (
        _read_systemctl(_USER_MANAGER, "LoadState") != "loaded"
        or _read_systemctl(_USER_MANAGER, "ActiveState") != "active"
        or _read_systemctl(_USER_RUNTIME, "LoadState") != "loaded"
        or _read_systemctl(_USER_RUNTIME, "ActiveState") != "active"
        or _read_loginctl("RuntimePath") != _RUNTIME
    ):
        raise OSError
    control_group = _read_systemctl(_USER_MANAGER, "ControlGroup")
    if (
        control_group != "/user.slice/user-991.slice/user@991.service"
        or _read_systemctl(_USER_MANAGER, "Delegate") != "yes"
    ):
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

    user_state = (
        _read_user_systemctl("LoadState"),
        _read_user_systemctl("ActiveState"),
        _read_user_systemctl("UnitFileState"),
    )
    if user_state != ("loaded", "inactive", "disabled"):
        raise OSError
    return control_group, controllers


def _qualify_once() -> RootlessDockerUserManagerEvidence:
    identity = _root_identity()
    package_host = _package_host()
    subuid, subgid = staticq._require_subids()
    directories, assets = staticq._require_static_assets()
    staticq._require_user_manager_template_dropins()

    executor_dropins = tuple(
        staticq._read_systemctl(
            "omnilyzer-deployment-executor.service", "DropInPaths"
        ).split()
    )
    user_dropins = tuple(
        staticq._read_systemctl(_USER_MANAGER, "DropInPaths").split()
    )
    if (
        executor_dropins != (AUTHORITY.executor_socket_dropin,)
        or user_dropins != staticq._expected_user_manager_dropins()
    ):
        raise OSError

    for unit in _DEPLOYMENT_UNITS:
        if _read_systemctl(unit, "ActiveState") != "inactive":
            raise OSError

    linger_mode = _linger_evidence()
    runtime = _runtime_evidence()
    control_group, controllers = _require_user_manager()
    _require_rootless_inactive()

    if _root_identity() != identity:
        raise OSError

    return RootlessDockerUserManagerEvidence(
        application_reviewed_commit=staticq.TARGET_REVIEWED_COMMIT,
        expected_workflow_sha=package_host[0],
        linger_path=_LINGER_PATH,
        linger_mode=linger_mode,
        runtime_directory=runtime[0],
        runtime_uid=runtime[1],
        runtime_gid=runtime[2],
        runtime_mode=runtime[3],
        user_manager=_USER_MANAGER,
        user_manager_control_group=control_group,
        delegate_controllers=controllers,
        rootless_user_unit=_USER_UNIT,
        rootless_user_unit_state=(
            _read_user_systemctl("LoadState"),
            _read_user_systemctl("ActiveState"),
            _read_user_systemctl("UnitFileState"),
        ),
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


def qualify_rootless_docker_user_manager() -> RootlessDockerUserManagerEvidence:
    """Require two identical independent C33C user-manager observations."""

    try:
        first = _qualify_once()
        second = _qualify_once()
        if second != first:
            raise OSError
        return first
    except _CONTROL:
        raise
    except Exception:
        raise RootlessDockerUserManagerQualificationError(_ERROR) from None

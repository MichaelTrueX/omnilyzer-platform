"""C33Q read-only preflight for fresh UID-991 user-manager recovery.

C33Q proves that replacing user@991.service is safe to attempt later, without
performing the replacement. It is intentionally post-persistence-aware:
persistent install authority comes from C33O, while the current live manager is
still expected to expose cached UnitFileState=disabled.

The future mutation is pinned to one exact system-manager command:
    /usr/bin/systemctl restart user@991.service
This module never executes that command.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import Callable

from . import rootless_docker_daemon_qualification as c33f
from . import rootless_docker_persistence_enablement as persistence
from .rootless_docker_authority import AUTHORITY


__all__ = (
    "RootlessDockerFreshManagerPreflightCheck",
    "RootlessDockerFreshManagerPreflightEvidence",
    "RootlessDockerFreshManagerSnapshot",
    "preflight_rootless_docker_fresh_manager",
    "snapshot_rootless_docker_fresh_manager_candidate",
)

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_SYSTEMCTL = "/usr/bin/systemctl"
_LOGINCTL = "/usr/bin/loginctl"
_TIMEOUT = 5.0
_OUTPUT_LIMIT = 256 * 1024
_USER_MANAGER = "user@991.service"
_USER_RUNTIME = "user-runtime-dir@991.service"
_RESTART_COMMAND = (_SYSTEMCTL, "restart", _USER_MANAGER)
_CGROUP_ROOT = "/user.slice/user-991.slice/user@991.service"
_USER_UNIT = "omnilyzer-task014-rootless-docker.service"


@dataclass(frozen=True, slots=True)
class RootlessDockerFreshManagerPreflightCheck:
    name: str
    passed: bool
    error_type: str | None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or type(self.passed) is not bool
            or (self.passed and self.error_type is not None)
            or (
                not self.passed
                and (type(self.error_type) is not str or not self.error_type)
            )
        ):
            raise ValueError("invalid fresh-manager preflight check")


@dataclass(frozen=True, slots=True)
class RootlessDockerFreshManagerSnapshot:
    persistent_state: str
    live_user_unit_state: tuple[str, str, str, str]
    user_manager_state: tuple[str, str, str, str]
    user_manager_pid: int
    user_runtime_state: tuple[str, str, str]
    linger_state: tuple[str, str, str, str, str, str, str]
    rootlesskit_pid: int
    dockerd_pid: int
    containerd_pid: int
    slirp4netns_pid: int
    containers: tuple[int, int, int, int]
    images: int

    def __post_init__(self) -> None:
        if (
            self.persistent_state != "enabled"
            or self.live_user_unit_state
            != ("loaded", "active", "running", "disabled")
            or self.user_manager_state
            != ("loaded", "active", "running", "static")
            or type(self.user_manager_pid) is not int
            or self.user_manager_pid <= 1
            or self.user_runtime_state != ("loaded", "active", "exited")
            or self.linger_state
            != (
                "yes",
                AUTHORITY.runtime_directory,
                str(AUTHORITY.executor_uid),
                AUTHORITY.executor_user,
                "lingering",
                "",
                "",
            )
            or any(
                type(pid) is not int or pid <= 1
                for pid in (
                    self.rootlesskit_pid,
                    self.dockerd_pid,
                    self.containerd_pid,
                    self.slirp4netns_pid,
                )
            )
            or len(
                {
                    self.user_manager_pid,
                    self.rootlesskit_pid,
                    self.dockerd_pid,
                    self.containerd_pid,
                    self.slirp4netns_pid,
                }
            )
            != 5
            or self.containers != (0, 0, 0, 0)
            or self.images != 0
        ):
            raise ValueError("invalid fresh-manager snapshot")


@dataclass(frozen=True, slots=True)
class RootlessDockerFreshManagerPreflightEvidence:
    checks: tuple[RootlessDockerFreshManagerPreflightCheck, ...]

    def __post_init__(self) -> None:
        if (
            type(self.checks) is not tuple
            or not self.checks
            or any(
                type(item) is not RootlessDockerFreshManagerPreflightCheck
                for item in self.checks
            )
            or len({item.name for item in self.checks}) != len(self.checks)
        ):
            raise ValueError("invalid fresh-manager preflight evidence")

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.checks)

    @property
    def failures(self) -> tuple[RootlessDockerFreshManagerPreflightCheck, ...]:
        return tuple(item for item in self.checks if not item.passed)


def _evaluate(
    name: str,
    function: Callable[[], object],
) -> RootlessDockerFreshManagerPreflightCheck:
    try:
        function()
        return RootlessDockerFreshManagerPreflightCheck(name, True, None)
    except _CONTROL:
        raise
    except Exception as error:
        return RootlessDockerFreshManagerPreflightCheck(
            name,
            False,
            type(error).__name__,
        )


def _run_one_line(argv: tuple[str, ...]) -> str:
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
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
        result.returncode != 0
        or type(result.stdout) is not bytes
        or len(result.stdout) > _OUTPUT_LIMIT
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\n" in result.stdout[:-1]
    ):
        raise OSError
    try:
        return result.stdout[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None


def _system_value(unit: str, property_name: str) -> str:
    if (
        unit not in {_USER_MANAGER, _USER_RUNTIME}
        or property_name
        not in {
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "MainPID",
            "ControlGroup",
            "Delegate",
            "DelegateControllers",
        }
    ):
        raise OSError
    return _run_one_line(
        (
            _SYSTEMCTL,
            "show",
            "--property=" + property_name,
            "--value",
            unit,
        )
    )


def _login_value(property_name: str) -> str:
    if property_name not in {
        "Linger",
        "RuntimePath",
        "UID",
        "Name",
        "State",
        "Sessions",
        "Display",
    }:
        raise OSError
    return _run_one_line(
        (
            _LOGINCTL,
            "show-user",
            AUTHORITY.executor_user,
            "--property=" + property_name,
            "--value",
        )
    )


def _user_manager_state() -> tuple[
    tuple[str, str, str, str],
    int,
    tuple[str, str, str],
]:
    manager = (
        _system_value(_USER_MANAGER, "LoadState"),
        _system_value(_USER_MANAGER, "ActiveState"),
        _system_value(_USER_MANAGER, "SubState"),
        _system_value(_USER_MANAGER, "UnitFileState"),
    )
    try:
        manager_pid = int(_system_value(_USER_MANAGER, "MainPID"))
    except ValueError:
        raise OSError from None
    runtime = (
        _system_value(_USER_RUNTIME, "LoadState"),
        _system_value(_USER_RUNTIME, "ActiveState"),
        _system_value(_USER_RUNTIME, "SubState"),
    )
    if (
        manager != ("loaded", "active", "running", "static")
        or manager_pid <= 1
        or runtime != ("loaded", "active", "exited")
        or _system_value(_USER_MANAGER, "ControlGroup") != _CGROUP_ROOT
        or _system_value(_USER_MANAGER, "Delegate") != "yes"
        or tuple(
            sorted(_system_value(_USER_MANAGER, "DelegateControllers").split())
        )
        != ("cpu", "memory", "pids")
    ):
        raise OSError
    return manager, manager_pid, runtime


def _linger_state() -> tuple[str, str, str, str, str, str, str]:
    value = (
        _login_value("Linger"),
        _login_value("RuntimePath"),
        _login_value("UID"),
        _login_value("Name"),
        _login_value("State"),
        _login_value("Sessions"),
        _login_value("Display"),
    )
    if value != (
        "yes",
        AUTHORITY.runtime_directory,
        str(AUTHORITY.executor_uid),
        AUTHORITY.executor_user,
        "lingering",
        "",
        "",
    ):
        raise OSError
    return value


def _single_pid(name: str) -> int:
    values = c33f._pids(name)
    if len(values) != 1:
        raise OSError
    return values[0]


def _snapshot() -> RootlessDockerFreshManagerSnapshot:
    qualified = persistence.qualify_rootless_docker_persistence()
    manager, manager_pid, runtime = _user_manager_state()
    linger = _linger_state()

    containerd_pid = _single_pid("containerd")
    slirp4netns_pid = _single_pid("slirp4netns")

    return RootlessDockerFreshManagerSnapshot(
        persistent_state=qualified.persistent_state,
        live_user_unit_state=qualified.daemon.user_unit_state,
        user_manager_state=manager,
        user_manager_pid=manager_pid,
        user_runtime_state=runtime,
        linger_state=linger,
        rootlesskit_pid=qualified.daemon.rootlesskit_pid,
        dockerd_pid=qualified.daemon.dockerd_pid,
        containerd_pid=containerd_pid,
        slirp4netns_pid=slirp4netns_pid,
        containers=qualified.daemon.containers,
        images=qualified.daemon.images,
    )


def snapshot_rootless_docker_fresh_manager_candidate() -> (
    RootlessDockerFreshManagerSnapshot
):
    """Capture the exact current post-persistence recovery candidate state."""

    first = _snapshot()
    second = _snapshot()
    if second != first:
        raise OSError
    return first


def _read_cgroup(pid: int) -> str:
    data = c33f._read_proc_file(f"/proc/{pid}/cgroup", 64 * 1024)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise OSError from None
    lines = tuple(text.splitlines())
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise OSError
    path = lines[0][3:]
    if not path:
        raise OSError
    return path


def _uid_process_cgroup_boundary() -> tuple[tuple[int, str], ...]:
    snapshot = snapshot_rootless_docker_fresh_manager_candidate()
    observed: list[tuple[int, str]] = []
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
            uid = c33f._proc_dir_uid(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if uid != AUTHORITY.executor_uid:
            continue
        try:
            path = _read_cgroup(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            if not os.path.exists(f"/proc/{pid}"):
                continue
            raise
        if path != _CGROUP_ROOT and not path.startswith(_CGROUP_ROOT + "/"):
            raise OSError
        observed.append((pid, path))

    result = tuple(sorted(observed))
    required = {
        snapshot.user_manager_pid,
        snapshot.rootlesskit_pid,
        snapshot.dockerd_pid,
        snapshot.containerd_pid,
        snapshot.slirp4netns_pid,
    }
    if not result or not required.issubset({pid for pid, _path in result}):
        raise OSError
    return result


def _boot_activation_contract() -> tuple[str, ...]:
    source = Path(AUTHORITY.user_unit).read_text(encoding="utf-8")
    lines = tuple(source.splitlines())
    required = (
        "ConditionUser=omnilyzer-executor",
        "ExecStart=/usr/bin/python3 -I -B /opt/omnilyzer/deployment/rootless-docker/launch.py",
        "Restart=always",
        "WantedBy=default.target",
    )
    if any(lines.count(item) != 1 for item in required):
        raise OSError
    if tuple(item for item in lines if item.startswith("WantedBy=")) != (
        "WantedBy=default.target",
    ):
        raise OSError
    persistence._enable_link_evidence()
    if persistence._global_enable_evidence() != "enabled":
        raise OSError
    return required


def _restart_command_contract() -> tuple[str, str, str]:
    if _RESTART_COMMAND != (
        "/usr/bin/systemctl",
        "restart",
        "user@991.service",
    ):
        raise OSError
    return _RESTART_COMMAND


def _component_checks() -> tuple[tuple[str, Callable[[], object]], ...]:
    return (
        ("stable_candidate_snapshot", snapshot_rootless_docker_fresh_manager_candidate),
        ("uid_process_cgroup_boundary", _uid_process_cgroup_boundary),
        ("boot_activation_contract", _boot_activation_contract),
        ("restart_command_contract", _restart_command_contract),
    )


def preflight_rootless_docker_fresh_manager() -> (
    RootlessDockerFreshManagerPreflightEvidence
):
    """Run all fresh-manager prerequisites without any mutation."""

    return RootlessDockerFreshManagerPreflightEvidence(
        tuple(_evaluate(name, function) for name, function in _component_checks())
    )
